#!/usr/bin/env python3
"""Universal BIOS installer for retrogaming platforms.

Self-contained script using only Python stdlib. Downloads missing BIOS files
from the retrobios repository and places them in the correct location for
the detected emulator platform.

Usage:
    python install.py
    python install.py --platform retroarch --dest ~/custom/bios
    python install.py --check
    python install.py --list-platforms
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import platform
import re
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath

BASE_URL = os.environ.get(
    "RETROBIOS_BASE_URL",
    "https://raw.githubusercontent.com/Abdess/retrobios/main",
)
MANIFEST_URL = f"{BASE_URL}/install/{{platform}}.json"
TARGETS_URL = f"{BASE_URL}/install/targets/{{platform}}.json"
RAW_FILE_URL = f"{BASE_URL}/{{path}}"
RELEASE_URL = (
    "https://github.com/Abdess/retrobios/releases/download/large-files/{asset}"
)
MAX_RETRIES = 3

# Platforms with a manifest in install/. Manifest URLs are case sensitive,
# so user input is normalized against this list before any fetch.
AVAILABLE_PLATFORMS = (
    "retroarch", "batocera", "recalbox", "retrobat", "emudeck",
    "lakka", "retrodeck", "rocknix", "romm", "bizhawk", "misterfpga",
)

# Fallback BIOS destination per platform when --platform is forced
# but auto-detection finds nothing on the machine.
DEFAULT_DESTS = {
    "batocera": Path("/userdata/bios"),
    "recalbox": Path("/recalbox/share/bios"),
    "lakka": Path("/storage/system"),
    "retrodeck": Path.home() / "retrodeck",
    "emudeck": Path.home() / "Emulation" / "bios",
    "rocknix": Path("/storage/roms/bios"),
    "misterfpga": Path("/media/fat/games"),
}


def detect_os() -> str:
    """Return normalized OS identifier."""
    system = platform.system().lower()
    if system == "linux":
        proc_version = Path("/proc/version")
        if proc_version.exists():
            try:
                content = proc_version.read_text(encoding="utf-8", errors="replace")
                if "microsoft" in content.lower():
                    return "wsl"
            except OSError:
                pass
        return "linux"
    if system == "darwin":
        return "darwin"
    if system == "windows":
        return "windows"
    return system


def _parse_os_release() -> dict[str, str]:
    """Parse /etc/os-release KEY=value format."""
    result: dict[str, str] = {}
    path = Path("/etc/os-release")
    if not path.exists():
        return result
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if "=" not in line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            value = value.strip('"').strip("'")
            result[key] = value
    except OSError:
        pass
    return result


def _expand_retroarch_path(value: str, app_dir: Path) -> Path:
    """Expand the notations RetroArch writes into its config values.

    fill_pathname_expand_special (libretro-common/file/file_path.c) maps a
    leading '~' to the home directory and a leading ':' to the application
    directory, dropping the two leading characters in both cases.
    """
    if value[:1] == "~":
        return Path(str(Path.home())) / value[2:]
    if value[:1] == ":":
        return app_dir / value[2:]
    return Path(os.path.expandvars(os.path.expanduser(value)))


def _parse_retroarch_system_dir(
    cfg_path: Path, app_dir: Path | None = None
) -> Path | None:
    """Parse system_directory from retroarch.cfg.

    app_dir is RetroArch's application directory, used to expand ':' values.
    It defaults to the directory holding the config, which is where a portable
    install keeps both.
    """
    if not cfg_path.exists():
        return None
    app_dir = app_dir or cfg_path.parent
    try:
        for line in cfg_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith("system_directory"):
                _, _, value = line.partition("=")
                value = value.strip().strip('"').strip("'")
                if not value or value == "default":
                    return app_dir / "system"
                return _expand_retroarch_path(value, app_dir)
    except OSError:
        pass
    return None


def _shell_unquote(value: str) -> str:
    """Resolve a shell right-hand side into its effective string value.

    Handles concatenated quoted/unquoted segments the way bash does
    (e.g. "/run/media/deck/EmuSD"/Emulation), expands variables in
    double-quoted and unquoted segments, and stops at unquoted
    whitespace or a comment.
    """
    parts: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        c = value[i]
        if c == '"':
            end = value.find('"', i + 1)
            if end == -1:
                parts.append(os.path.expandvars(value[i + 1:]))
                break
            parts.append(os.path.expandvars(value[i + 1:end]))
            i = end + 1
        elif c == "'":
            end = value.find("'", i + 1)
            if end == -1:
                parts.append(value[i + 1:])
                break
            parts.append(value[i + 1:end])
            i = end + 1
        elif c.isspace() or c == "#":
            break
        else:
            end = i
            while end < n and value[end] not in "\"'#" and not value[end].isspace():
                end += 1
            parts.append(os.path.expandvars(value[i:end]))
            i = end
    return os.path.expanduser("".join(parts))


def _parse_bash_var(path: Path, key: str) -> str | None:
    """Extract the effective value of key= from a bash/shell file."""
    if not path.exists():
        return None
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith(f"{key}="):
                _, _, value = line.partition("=")
                return _shell_unquote(value)
    except OSError:
        pass
    return None


def _parse_json_path(path: Path, *keys: str) -> str | None:
    """Extract a nested string value from a JSON file."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        for key in keys:
            data = data[key]
        return data if isinstance(data, str) and data else None
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return None


def _parse_ps1_var(path: Path, key: str) -> str | None:
    """Extract value of $key= or key= from a PowerShell file."""
    if not path.exists():
        return None
    normalized = key.lstrip("$")
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            check = line.lstrip("$")
            if check.startswith(f"{normalized}="):
                _, _, value = check.partition("=")
                return value.strip('"').strip("'")
    except OSError:
        pass
    return None


def _detect_embedded() -> list[tuple[str, Path]]:
    """Check for embedded Linux retrogaming OSes."""
    found: list[tuple[str, Path]] = []
    os_release = _parse_os_release()
    os_id = os_release.get("ID", "").lower()

    if os_id == "rocknix":
        found.append(("rocknix", Path("/storage/roms/bios")))
        return found

    # MiSTer keeps the SD card at /media/fat with the main binary at its root
    # (Main_MiSTer file_io.cpp:1150-1156), and cores read from games/
    # (file_io.h:168)
    if Path("/media/fat/MiSTer").exists():
        found.append(("misterfpga", Path("/media/fat/games")))
        return found

    if Path("/etc/knulli-release").exists():
        found.append(("batocera", Path("/userdata/bios")))
        return found

    if os_id == "lakka":
        found.append(("lakka", Path("/storage/system")))
        return found

    if Path("/etc/batocera-version").exists():
        found.append(("batocera", Path("/userdata/bios")))
        return found

    if (
        Path("/recalbox/recalbox.version").exists()
        or Path("/usr/bin/recalbox-settings").exists()
    ):
        found.append(("recalbox", Path("/recalbox/share/bios")))
        return found

    if Path("/opt/muos").exists() or Path("/mnt/mmc/MUOS/").exists():
        found.append(("retroarch", Path("/mnt/mmc/MUOS/bios")))
        return found

    if Path("/home/ark").exists() and Path("/opt/system").exists():
        found.append(("retroarch", Path("/roms/bios")))
        return found

    if Path("/mnt/vendor/bin/dmenu.bin").exists():
        found.append(("retroarch", Path("/mnt/mmc/bios")))
        return found

    return found


def _lnk_target(lnk_path: Path, exe_name: str) -> Path | None:
    """Read the target path of a Windows shortcut.

    Shortcuts embed the target as a plain local path; scanning for it avoids
    parsing the whole .lnk structure for the one field that matters here.
    """
    try:
        if lnk_path.stat().st_size > 64 * 1024:
            return None
        blob = lnk_path.read_bytes()
    except OSError:
        return None
    pattern = re.compile(
        rb"[A-Za-z]:\\[ -~]{0,260}?" + re.escape(exe_name.encode()), re.IGNORECASE
    )
    match = pattern.search(blob)
    if not match:
        return None
    return Path(match.group().decode("ascii", "replace").replace("\\", "/"))


def launchbox_root(os_type: str) -> Path | None:
    """Locate the LaunchBox installation directory.

    LaunchBox installs wherever the user points its installer and writes no
    uninstall registry key, so the Start menu shortcut is the only record of
    that choice. Everything else falls back to the default location.
    """
    if os_type not in ("windows", "wsl"):
        return None
    candidates: list[Path] = []
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        lnk = (
            Path(appdata)
            / "Microsoft"
            / "Windows"
            / "Start Menu"
            / "Programs"
            / "LaunchBox"
            / "LaunchBox.lnk"
        )
        if lnk.exists():
            target = _lnk_target(lnk, "LaunchBox.exe")
            if target:
                # The shortcut points at Core/LaunchBox.exe
                candidates.append(target.parent.parent)
                candidates.append(target.parent)
    userprofile = os.environ.get("USERPROFILE", "")
    if userprofile:
        candidates.append(Path(userprofile) / "LaunchBox")
    for root in candidates:
        if (root / "Data" / "Emulators.xml").exists():
            return root
    return None


def launchbox_emulators(emulators_xml: Path) -> dict[str, Path]:
    """Map each emulator LaunchBox knows about to its installation directory.

    LaunchBox stores its emulator list in Data/Emulators.xml; ApplicationPath
    is either absolute or relative to the LaunchBox root directory. Keys are
    the lowercase executable names.
    """
    found: dict[str, Path] = {}
    if not emulators_xml.exists():
        return found
    try:
        if emulators_xml.stat().st_size > 10 * 1024 * 1024:
            return found
        raw = emulators_xml.read_text(encoding="utf-8", errors="replace")
        # ElementTree expands internal entities; LaunchBox writes no doctype
        if "<!DOCTYPE" in raw.upper():
            return found
        tree = ET.ElementTree(ET.fromstring(raw))
    except (ET.ParseError, OSError):
        return found
    lb_root = emulators_xml.parent.parent
    for emu in tree.getroot().iter("Emulator"):
        app_path = (emu.findtext("ApplicationPath") or "").replace("\\", "/")
        if not app_path:
            continue
        exe = Path(app_path)
        if not exe.is_absolute():
            exe = lb_root / exe
        if exe.parent.is_dir():
            found.setdefault(exe.name.lower(), exe.parent)
    return found


def _launchbox_retroarch_system_dir(emulators_xml: Path) -> Path | None:
    """Resolve the system dir of a RetroArch referenced by LaunchBox.

    Mirrors the plugin's UpdateSystemPath: read system_directory from the
    retroarch.cfg sitting next to the executable, else assume system/.
    """
    emu_dir = launchbox_emulators(emulators_xml).get("retroarch.exe")
    if emu_dir is None:
        return None
    system_dir = _parse_retroarch_system_dir(emu_dir / "retroarch.cfg", emu_dir)
    return system_dir or emu_dir / "system"


def _pcsx2_bios_dir(emu_dir: Path) -> Path:
    """Resolve the BIOS folder of a PCSX2 installed under LaunchBox.

    EmuFolders (pcsx2/Pcsx2Config.cpp) enters portable mode when portable.ini
    or portable.txt sits next to the executable, and then takes the data root
    from the contents of portable.txt, relative to the executable. Otherwise
    the data root is Documents/PCSX2. Bios defaults to "bios" below it and the
    Bios key of PCSX2.ini overrides that.
    """
    documents = Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Documents"
    portable_txt = emu_dir / "portable.txt"
    portable = (emu_dir / "portable.ini").exists() or portable_txt.exists()
    if portable:
        subpath = ""
        try:
            subpath = portable_txt.read_text(
                encoding="utf-8", errors="replace"
            ).strip()
        except OSError:
            pass
        data_root = emu_dir / subpath if subpath else emu_dir
    else:
        data_root = documents / "PCSX2"
    ini = data_root / "inis" / "PCSX2.ini"
    try:
        for line in ini.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("Bios = "):
                value = line[len("Bios = "):].strip()
                candidate = Path(value)
                return candidate if candidate.is_absolute() else data_root / value
    except OSError:
        pass
    return data_root / "bios"


def _xemu_bios_dir(emu_dir: Path) -> Path:
    """Resolve the BIOS folder of a xemu managed by LaunchBox.

    Follows the plugin: xemu.toml next to the executable else the roaming
    copy, with bootrom_path and flashrom_path naming a file whose directory
    holds the images. Both default to bios/ under the executable.
    """
    appdata = os.environ.get("APPDATA", "")
    toml = emu_dir / "xemu.toml"
    if not toml.exists() and appdata:
        toml = Path(appdata) / "xemu" / "xemu" / "xemu.toml"
    if toml.exists():
        try:
            for line in toml.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith(("bootrom_path", "flashrom_path")):
                    parts = line.split("'")
                    if len(parts) > 1 and Path(parts[1]).exists():
                        return Path(parts[1]).parent
        except OSError:
            pass
    return emu_dir / "bios"


def launchbox_bios_dirs(root: Path) -> dict[str, Path]:
    """Map emulator ids to the BIOS directory LaunchBox expects for them.

    Only emulators whose destination LaunchBox itself computes are listed;
    the rest keep the default locations declared in the manifest.
    """
    emulators = launchbox_emulators(root / "Data" / "Emulators.xml")
    dirs: dict[str, Path] = {}
    emu_dir = emulators.get("pcsx2.exe")
    if emu_dir:
        dirs["pcsx2"] = _pcsx2_bios_dir(emu_dir)
    emu_dir = emulators.get("xemu.exe")
    if emu_dir:
        dirs["xemu"] = _xemu_bios_dir(emu_dir)
    emu_dir = emulators.get("dolphin.exe")
    if emu_dir and (emu_dir / "portable.txt").exists():
        # portable.txt beside the executable moves the user directory to
        # User (SetUserDirectory in Source/Core/UICommon/UICommon.cpp,
        # PORTABLE_USER_DIR in Source/Core/Common/CommonPaths.h)
        dirs["dolphin"] = emu_dir / "User"
    return dirs


def detect_frontends(os_type: str, home: Path | None = None) -> list[str]:
    """Detect frontends that reference emulators without owning a BIOS dir.

    ES-DE resolves its application data directory to $ESDE_APPDATA_DIR or
    <home>/ES-DE (es-core FileSystemUtil.cpp getAppDataDirectory).
    """
    home = home or Path.home()
    frontends: list[str] = []
    esde_env = os.environ.get("ESDE_APPDATA_DIR", "")
    if (esde_env and Path(esde_env).is_dir()) or (home / "ES-DE").is_dir():
        frontends.append("esde")
    if launchbox_root(os_type) is not None:
        frontends.append("launchbox")
    return frontends


def detect_platforms(os_type: str) -> list[tuple[str, Path]]:
    """Detect installed emulator platforms and their BIOS directories."""
    found: list[tuple[str, Path]] = []

    if os_type in ("linux", "wsl"):
        found.extend(_detect_embedded())

        # EmuDeck (Linux/SteamOS)
        home = Path.home()
        emudeck_settings = home / ".config" / "EmuDeck" / "settings.sh"
        if emudeck_settings.exists():
            emu_path = _parse_bash_var(emudeck_settings, "emulationPath")
            if emu_path:
                bios_dir = Path(emu_path) / "bios"
                found.append(("emudeck", bios_dir))

        # RetroDECK: retrodeck.json since the cfg-to-json migration, which
        # renames the old retrodeck.cfg to retrodeck.bak (global.sh:149-153)
        retrodeck_conf_dir = home / ".var" / "app" / "net.retrodeck.retrodeck" / "config" / "retrodeck"
        retrodeck_json = retrodeck_conf_dir / "retrodeck.json"
        retrodeck_cfg = retrodeck_conf_dir / "retrodeck.cfg"
        if retrodeck_json.exists():
            rd_home = _parse_json_path(retrodeck_json, "paths", "rd_home_path")
            found.append(("retrodeck", Path(rd_home) if rd_home else home / "retrodeck"))
        elif retrodeck_cfg.exists():
            rd_home = _parse_bash_var(retrodeck_cfg, "rdhome")
            found.append(("retrodeck", Path(rd_home) if rd_home else home / "retrodeck"))

        # RetroArch Flatpak
        flatpak_cfg = home / ".var" / "app" / "org.libretro.RetroArch" / "config" / "retroarch" / "retroarch.cfg"
        ra_dir = _parse_retroarch_system_dir(flatpak_cfg)
        if ra_dir:
            found.append(("retroarch", ra_dir))

        # RetroArch Snap
        snap_cfg = home / "snap" / "retroarch" / "current" / ".config" / "retroarch" / "retroarch.cfg"
        ra_dir = _parse_retroarch_system_dir(snap_cfg)
        if ra_dir:
            found.append(("retroarch", ra_dir))

        # RetroArch native
        native_cfg = home / ".config" / "retroarch" / "retroarch.cfg"
        ra_dir = _parse_retroarch_system_dir(native_cfg)
        if ra_dir:
            found.append(("retroarch", ra_dir))

    if os_type == "darwin":
        home = Path.home()
        mac_cfg = home / "Library" / "Application Support" / "RetroArch" / "retroarch.cfg"
        ra_dir = _parse_retroarch_system_dir(mac_cfg)
        if ra_dir:
            found.append(("retroarch", ra_dir))

    if os_type in ("windows", "wsl"):
        # EmuDeck Windows
        home = Path.home()
        emudeck_ps1 = Path(os.environ.get("APPDATA", "")) / "EmuDeck" / "settings.ps1"
        if emudeck_ps1.exists():
            emu_path = _parse_ps1_var(emudeck_ps1, "$emulationPath")
            if emu_path:
                found.append(("emudeck", Path(emu_path) / "bios"))

        # RetroArch Windows
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            win_cfg = Path(appdata) / "RetroArch" / "retroarch.cfg"
            ra_dir = _parse_retroarch_system_dir(win_cfg)
            if ra_dir:
                found.append(("retroarch", ra_dir))

        # Portable RetroArch referenced by LaunchBox
        lb_root = launchbox_root(os_type)
        if lb_root and not any(name == "retroarch" for name, _ in found):
            system_dir = _launchbox_retroarch_system_dir(
                lb_root / "Data" / "Emulators.xml"
            )
            if system_dir:
                found.append(("retroarch", system_dir))

    return found


def normalize_platform(name: str) -> str:
    """Return the canonical platform id for user-supplied input."""
    plat = name.strip().lower()
    if plat not in AVAILABLE_PLATFORMS:
        print(f"Unknown platform '{name}'. Available platforms:", file=sys.stderr)
        for p in AVAILABLE_PLATFORMS:
            print(f"  {p}", file=sys.stderr)
        sys.exit(1)
    return plat


def fetch_manifest(plat: str) -> dict:
    """Download platform manifest JSON."""
    url = MANIFEST_URL.format(platform=plat)
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        print(f"  Failed to fetch manifest for {plat}: {exc}", file=sys.stderr)
        sys.exit(1)


def fetch_targets(plat: str) -> dict:
    """Download target core list. Returns empty dict on 404."""
    url = TARGETS_URL.format(platform=plat)
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}
        print(f"  Warning: failed to fetch targets for {plat}: {exc}", file=sys.stderr)
        return {}
    except (urllib.error.URLError, OSError):
        return {}


def _filter_by_target(
    files: list[dict], target_cores: list[str]
) -> list[dict]:
    """Keep files where cores is None or overlaps with target_cores."""
    result: list[dict] = []
    target_set = set(target_cores)
    for f in files:
        cores = f.get("cores")
        if cores is None or any(c in target_set for c in cores):
            result.append(f)
    return result


def _sha1_file(path: Path) -> str:
    """Compute SHA1 of a file."""
    h = hashlib.sha1()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def check_local(
    files: list[dict], bios_path: Path
) -> tuple[list[dict], list[dict], list[dict]]:
    """Check which files exist locally and have correct hashes.

    Returns (to_download, up_to_date, mismatched).
    """
    to_download: list[dict] = []
    up_to_date: list[dict] = []
    mismatched: list[dict] = []

    for f in files:
        dest = bios_path / f["dest"]
        if not dest.exists():
            to_download.append(f)
            continue
        expected_sha1 = f.get("sha1", "")
        if not expected_sha1:
            up_to_date.append(f)
            continue
        actual = _sha1_file(dest)
        if actual == expected_sha1:
            up_to_date.append(f)
        else:
            mismatched.append(f)

    return to_download, up_to_date, mismatched


def _download_one(
    f: dict, bios_path: Path, verbose: bool = False
) -> tuple[str, bool]:
    """Download a single file. Returns (dest, success)."""
    dest = bios_path / f["dest"]
    dest.parent.mkdir(parents=True, exist_ok=True)

    if f.get("release_asset"):
        url = RELEASE_URL.format(asset=urllib.parse.quote(f["release_asset"], safe="/"))
    else:
        url = RAW_FILE_URL.format(path=urllib.parse.quote(f["repo_path"], safe="/"))

    tmp_path = dest.with_suffix(dest.suffix + ".tmp")

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                with open(tmp_path, "wb") as out:
                    shutil.copyfileobj(resp, out)

            expected_sha1 = f.get("sha1", "")
            if expected_sha1:
                actual = _sha1_file(tmp_path)
                if actual != expected_sha1:
                    if verbose:
                        print(f"    SHA1 mismatch on attempt {attempt}", file=sys.stderr)
                    tmp_path.unlink(missing_ok=True)
                    continue

            tmp_path.rename(dest)
            return f["dest"], True

        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            if verbose:
                print(f"    Attempt {attempt} failed: {exc}", file=sys.stderr)
            tmp_path.unlink(missing_ok=True)

    return f["dest"], False


def download_files(
    files: list[dict], bios_path: Path, jobs: int = 8, verbose: bool = False
) -> list[str]:
    """Download files in parallel. Returns list of failed file names."""
    failed: list[str] = []
    total = len(files)

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        future_map = {
            pool.submit(_download_one, f, bios_path, verbose): f
            for f in files
        }
        done_count = 0
        for future in concurrent.futures.as_completed(future_map):
            done_count += 1
            dest, success = future.result()
            status = "ok" if success else "FAILED"
            print(f"  [{done_count}/{total}] {dest} {status}")
            if not success:
                failed.append(dest)

    return failed


def do_standalone_copies(
    manifest: dict, bios_path: Path, os_type: str,
    extra_dirs: dict[str, Path] | None = None,
) -> tuple[int, int]:
    """Copy BIOS files to standalone emulator directories.

    Supports:
    - file: single file copy
    - pattern: glob match (e.g. "scph*.bin")
    - note: informational message when detect path exists
    - WSL fallback to linux targets

    extra_dirs maps the emulator id of an entry to a root that replaces the
    default per-OS locations, for setups such as LaunchBox that keep their
    emulators outside them. The layout below the root is the same.

    Returns (copied_count, skipped_count).
    """
    from fnmatch import fnmatch

    copies = manifest.get("standalone_copies", [])
    if not copies:
        return 0, 0

    copied = 0
    skipped = 0

    for entry in copies:
        # Note entries: print message if emulator detected
        if "note" in entry:
            detect_paths = entry.get("detect", {}).get(os_type, [])
            if not detect_paths and os_type == "wsl":
                detect_paths = entry.get("detect", {}).get("linux", [])
            for dp in detect_paths:
                expanded = Path(os.path.expandvars(os.path.expanduser(dp)))
                if expanded.is_dir():
                    print(f"  {entry['note']}")
                    break
            continue

        # Resolve source files
        if "pattern" in entry:
            sources = [
                f for f in bios_path.rglob("*")
                if fnmatch(f.name, entry["pattern"]) and f.is_file()
            ]
        else:
            src = bios_path / entry["file"]
            sources = [src] if src.exists() else []

        if not sources:
            continue

        # Resolve target directories with WSL fallback
        targets = entry.get("targets", {}).get(os_type, [])
        if not targets and os_type == "wsl":
            targets = entry.get("targets", {}).get("linux", [])

        target_dirs = [
            Path(os.path.expandvars(os.path.expanduser(t))) for t in targets
        ]
        extra_root = (extra_dirs or {}).get(entry.get("emulator", ""))
        if extra_root is not None:
            subdir = PurePosixPath(entry.get("file", "")).parent
            extra = extra_root if str(subdir) == "." else extra_root / subdir
            if extra not in target_dirs:
                target_dirs.append(extra)

        for target_dir in target_dirs:
            if not target_dir.is_dir():
                skipped += len(sources)
                continue
            for src in sources:
                dest = target_dir / src.name
                try:
                    shutil.copy2(src, dest)
                    copied += 1
                except OSError:
                    skipped += 1

    return copied, skipped


def format_size(n: int) -> str:
    """Human-readable file size."""
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.1f} GB"


def _prompt_platform_choice(
    platforms: list[tuple[str, Path]],
) -> list[tuple[str, Path]]:
    """Prompt user to choose among detected platforms."""
    print("\nInstall for:")
    for i, (name, path) in enumerate(platforms, 1):
        print(f"  {i}) {name.capitalize()} ({path})")
    if len(platforms) > 1:
        print(f"  {len(platforms) + 1}) All")
    print()

    while True:
        try:
            choice = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if not choice:
            continue
        try:
            idx = int(choice)
        except ValueError:
            continue
        if 1 <= idx <= len(platforms):
            return [platforms[idx - 1]]
        if idx == len(platforms) + 1 and len(platforms) > 1:
            return platforms

    return platforms


def main() -> None:
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="Download missing BIOS files for retrogaming emulators.",
    )
    parser.add_argument(
        "--platform",
        help="target platform (retroarch, batocera, emudeck, ...)",
    )
    parser.add_argument(
        "--dest",
        type=Path,
        help="override BIOS destination directory",
    )
    parser.add_argument(
        "--target",
        help="hardware target for core filtering (switch, rpi4, ...)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="check existing files without downloading",
    )
    parser.add_argument(
        "--list-platforms",
        action="store_true",
        help="list detected platforms and exit",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="list available targets for a platform and exit",
    )
    parser.add_argument(
        "--jobs", "-j",
        type=int,
        default=8,
        help="parallel download threads (default: 8)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="verbose output",
    )

    args = parser.parse_args()
    print("RetroBIOS\n")

    os_type = detect_os()

    # Early exit for listing
    if args.list_platforms:
        print("Available platforms:")
        for p in AVAILABLE_PLATFORMS:
            print(f"  {p}")
        detected = detect_platforms(os_type)
        if detected:
            print("\nDetected on this system:")
            for name, path in detected:
                print(f"  {name}: {path}")
        return

    # Platform detection or override
    if args.platform:
        args.platform = normalize_platform(args.platform)
    if args.platform and args.dest:
        platforms = [(args.platform, args.dest)]
    elif args.platform:
        print("Detecting platform...")
        detected = detect_platforms(os_type)
        matched = [(n, p) for n, p in detected if n == args.platform]
        if matched:
            platforms = matched
        else:
            default_dest = DEFAULT_DESTS.get(args.platform, Path.home() / "bios")
            print(
                f"  Platform '{args.platform}' not detected, "
                f"using default path: {default_dest}"
            )
            platforms = [(args.platform, default_dest)]
    elif args.dest:
        print(f"  Using destination: {args.dest}")
        platforms = [("retroarch", args.dest)]
    else:
        print("Detecting platform...")
        frontends = detect_frontends(os_type)
        if "esde" in frontends:
            print("  Found ES-DE (BIOS files go to each emulator, not to ES-DE itself)")
        if "launchbox" in frontends:
            print("  Found LaunchBox")
        platforms = detect_platforms(os_type)
        if not platforms:
            print("  No supported platform detected.")
            print("  Use --platform and --dest to specify manually.")
            sys.exit(1)
        for name, path in platforms:
            print(f"  Found {name.capitalize()} at {path}")

    if len(platforms) > 1 and not args.list_targets and sys.stdin.isatty():
        platforms = _prompt_platform_choice(platforms)

    total_downloaded = 0
    total_up_to_date = 0
    total_errors = 0

    for plat_name, bios_path in platforms:
        print(f"\nFetching file index for {plat_name}...")
        manifest = fetch_manifest(plat_name)
        files = manifest.get("files", [])

        if args.list_targets:
            targets = fetch_targets(plat_name)
            if not targets:
                print(f"  No targets available for {plat_name}")
            else:
                for t in sorted(targets.keys()):
                    cores = targets[t].get("cores", [])
                    print(f"  {t} ({len(cores)} cores)")
            continue

        # Target filtering
        if args.target:
            targets = fetch_targets(plat_name)
            target_info = targets.get(args.target)
            if not target_info:
                print(f"  Warning: target '{args.target}' not found for {plat_name}")
            else:
                target_cores = target_info.get("cores", [])
                before = len(files)
                files = _filter_by_target(files, target_cores)
                print(f"  Filtered {before} -> {len(files)} files for target {args.target}")

        total_size = sum(f.get("size", 0) for f in files)
        print(f"  {len(files)} files ({format_size(total_size)})")

        print("\nChecking existing files...")
        to_download, up_to_date, mismatched = check_local(files, bios_path)
        present = len(up_to_date) + len(mismatched)
        print(
            f"  {present}/{len(files)} present "
            f"({len(up_to_date)} verified, {len(mismatched)} wrong hash)"
        )

        # Mismatched files need re-download
        to_download.extend(mismatched)

        if args.check:
            if to_download:
                print(f"\n  {len(to_download)} files need downloading.")
            else:
                print("\n  All files up to date.")
            continue

        if to_download:
            dl_size = sum(f.get("size", 0) for f in to_download)
            print(f"\nDownloading {len(to_download)} files ({format_size(dl_size)})...")
            bios_path.mkdir(parents=True, exist_ok=True)
            failed = download_files(
                to_download, bios_path, jobs=args.jobs, verbose=args.verbose
            )
            total_downloaded += len(to_download) - len(failed)
            total_errors += len(failed)
        else:
            print("\n  All files up to date.")

        total_up_to_date += len(up_to_date)

        # Standalone copies
        if manifest.get("standalone_copies") and not args.check:
            print("\nStandalone emulators:")
            lb_root = launchbox_root(os_type)
            extra_dirs = launchbox_bios_dirs(lb_root) if lb_root else None
            copied, skipped = do_standalone_copies(
                manifest, bios_path, os_type, extra_dirs
            )
            if copied or skipped:
                print(f"  {copied} copied, {skipped} skipped (dir not found)")

    if not args.check and not args.list_targets:
        print(
            f"\nDone. {total_downloaded} downloaded, "
            f"{total_up_to_date} up to date, {total_errors} errors."
        )


if __name__ == "__main__":
    main()
