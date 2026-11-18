"""The operating system, the board and the RetroArch folders it keeps."""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

from installer.constants import CARD_MARKER
from installer.embedded import (
    _EMBEDDED_RULES,
    _OsRule,
    _mounted_cards,
    card_platform,
    display_name,
    setup_bios_folder,
    shown_path,
)
from installer.events import EVENTS
from installer.paths import _MOVED_FOLDERS
from installer.probe import (
    _DETECTION_REFUSED,
    _SETUP_SEARCH,
    _WSL,
    _exists,
    _host_path,
    _is_dir,
    _is_file,
    _note_refused,
    refused_words,
)
from installer.text import _CONTROLS, screen_text


def _os_default_dests(os_type: str) -> dict[str, Path]:
    """Where a platform keeps its BIOS on this OS, when it is not detected.

    The same folders the platform's detection looks for: a platform named on
    the command line but not found must not land in ~/bios, which none of
    them reads.
    """
    if os_type == "windows":
        return {
            # RetroArch's system directory defaults to <exe folder>\system
            # (platform_win32.c), and its installer to C:\RetroArch-Win64.
            "retroarch": _host_path("C:/RetroArch-Win64/system"),
            # RetroBat's installer defaults to C:\RetroBat (installer.iss).
            "retrobat": _host_path("C:/RetroBat/bios"),
            # EmuDeck's Windows edition: C:\Emulation when its settings name
            # no folder (emudeck-we functions/all.ps1:12-14).
            "emudeck": _host_path("C:/Emulation/bios"),
        }
    if os_type == "wsl":
        # RetroArch may be the Linux one inside the distribution, while RetroBat
        # only exists on the Windows side, reached through /mnt/c.
        return {
            "retroarch": _unix_retroarch_base() / "system",
            "retrobat": _host_path("C:/RetroBat/bios"),
        }
    if os_type == "darwin":
        return {"retroarch": _macos_retroarch_base() / "system"}
    return {
        "retroarch": _unix_retroarch_base() / "system",
    }


# The three RetroArch packages published for Android, newest ABI first.
ANDROID_RETROARCH_PACKAGES = (
    "com.retroarch.aarch64",
    "com.retroarch",
    "com.retroarch.ra32",
)
# Where Android keeps each app's private data.
ANDROID_APP_DATA = Path("/data/data")


def _is_android() -> bool:
    """Android reports itself as Linux, so the runtime is named instead.

    Termux inherits the two variables the Android runtime exports, and
    /system/build.prop covers a shell that was started without them.
    """
    if os.environ.get("ANDROID_ROOT") and os.environ.get("ANDROID_DATA"):
        return True
    return Path("/system/build.prop").exists()


def detect_os() -> str:
    """Return normalized OS identifier.

    RETROBIOS_OS names the platform outright (linux, wsl, windows, darwin,
    android), for a run that has to behave like another host: the PowerShell
    wrapper tests drive a Windows layout on a Linux runner.
    """
    forced = os.environ.get("RETROBIOS_OS", "").strip().lower()
    if forced in ("linux", "wsl", "windows", "darwin", "android"):
        return forced
    system = platform.system().lower()
    if system == "linux":
        if _is_android():
            return "android"
        proc_version = Path("/proc/version")
        if _exists(proc_version):
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
    path = _on_device("/etc/os-release")
    if not _exists(path):
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


_WINDOWS_VARIABLES = ("USERPROFILE", "APPDATA", "LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)")


def _wsl_dest(args: argparse.Namespace) -> None:
    """Every path option as WSL opens it: the screen names a card D:, and
    D:\\ given to --dest was refused as a folder that does not exist, then
    E:\\ given to --from once --dest took it."""
    for name in ("dest", "save_dir", "cores_dir"):
        if getattr(args, name, None) is not None:
            setattr(args, name, _host_path(str(getattr(args, name))))
    for name in ("from", "from_pack"):
        if getattr(args, name, None):
            setattr(args, name, [_host_path(str(path)) for path in getattr(args, name)])


def _enter_wsl() -> None:
    """Read Windows paths through drvfs, and the Windows variables detection
    needs, which WSL does not pass to Linux (only those named in WSLENV)."""
    _WSL["active"] = True
    for variable in _WINDOWS_VARIABLES:
        if os.environ.get(variable):
            continue
        try:
            # No stdin: cmd.exe inherited the terminal and swallowed the
            # answer typed at the first prompt.
            result = subprocess.run(
                ["cmd.exe", "/c", f"echo %{variable}%"],
                capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL,
                cwd="/mnt/c" if Path("/mnt/c").is_dir() else None, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            # The others would wait as long: detection is told the Windows
            # side was not searched, never that nothing is there.
            _windows_unasked("cmd.exe", exc)
            return
        value = result.stdout.strip()
        if value and not value.startswith("%"):
            os.environ[variable] = str(_host_path(value))


def _windows_unasked(tool: str, exc: Exception) -> None:
    """Keep why a Windows program run from WSL gave no answer: an interop
    slow to start or turned off hid every Windows setup, and the run said
    none was installed."""
    if isinstance(exc, subprocess.TimeoutExpired):
        why = f"{tool} did not answer in {exc.timeout:g} s"
    else:
        why = f"{tool} could not run: {getattr(exc, 'strerror', None) or exc}"
    _WSL["unasked"] = _WSL["unasked"] or why


def _expand_retroarch_path(value: str, app_dir: Path, home: Path | None = None) -> Path:
    """Expand the notations RetroArch writes into its config values.

    fill_pathname_expand_special (libretro-common/file/file_path.c) maps a
    leading '~' to the home directory and a leading ':' to the application
    directory, dropping the two leading characters in both cases.
    """
    if value[:1] == "~":
        return (home or Path(str(Path.home()))) / value[2:]
    if value[:1] == ":":
        return app_dir / value[2:]
    return _host_path(os.path.expandvars(os.path.expanduser(value)))


def _retroarch_cfg_dir(
    cfg_path: Path, key: str, app_dir: Path, default: str, home: Path | None = None
) -> Path | None:
    """A directory setting of retroarch.cfg, as RetroArch expands it.

    A value left empty or at `default` is the directory RetroArch falls back
    on, `default` under app_dir. None when the config is unreadable or does
    not set the key. A config this user cannot read is said once, like a
    closed folder: a retroarch.cfg a `sudo retroarch` left to root hid the
    setup without a word.
    """
    try:
        lines = cfg_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        _note_refused(cfg_path, exc)
        return None
    for line in lines:
        line = line.strip()
        name, sep, value = line.partition("=")
        if sep and name.strip() == key:
            value = value.strip().strip('"').strip("'")
            if not value or value == "default":
                return app_dir / default
            return _expand_retroarch_path(value, app_dir, home)
    return None


def _steam_libraries() -> list[Path]:
    """Every Steam library, the default one first.

    Steam lists the others in steamapps/libraryfolders.vdf, each as a
    "path" line. A RetroArch installed on D:/SteamLibrary was not found
    when only Program Files was searched. The client's own folder is the
    SteamPath value it writes under HKCU\\Software\\Valve\\Steam, read the
    same way by Playnite (PlayniteExtensions 886468f6,
    source/Libraries/SteamLibrary/Steam.cs:34-38): a client installed in
    D:\\Steam hid every library.
    """
    roots: list[Path] = []
    steam_path = _read_registry("HKCU\\Software\\Valve\\Steam", "SteamPath")
    candidates = [_host_path(steam_path.replace("/", "\\"))] if steam_path else []
    for var in ("ProgramFiles(x86)", "ProgramFiles"):
        base = os.environ.get(var, "")
        if base:
            candidates.append(Path(base) / "Steam")
    for candidate in candidates:
        if candidate not in roots and _is_dir(candidate):
            roots.append(candidate)
    libraries = list(roots)
    for root in roots:
        vdf = root / "steamapps" / "libraryfolders.vdf"
        try:
            text = vdf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for raw in re.findall(r'"path"\s+"([^"]+)"', text):
            library = Path(raw.replace("\\\\", "\\"))
            if library not in libraries:
                libraries.append(library)
    return libraries


def _scoop_root(variable: str, parent: str) -> str:
    """%variable%, else %parent%\\scoop, else nothing."""
    folder = os.environ.get(parent)
    return os.environ.get(variable) or (str(Path(folder) / "scoop") if folder else "")


def _windows_retroarch_dirs() -> list[Path]:
    """Folders holding retroarch.exe where its installers put it.

    C:/RetroArch-Win64 by default, C:/RetroArch for 32-bit builds, the same
    names under Program Files, every Steam library, the Emulators folder of
    an installed ES-DE (es_find_rules.xml lists all of them), and a Scoop
    install, user or global.
    """
    candidates = [_host_path("C:/RetroArch-Win64"), _host_path("C:/RetroArch")]
    for var in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(var, "")
        if root:
            candidates += [Path(root) / "RetroArch-Win64", Path(root) / "RetroArch"]
            candidates += [
                Path(root) / "ES-DE" / "Emulators" / name
                for name in ("RetroArch-Win64", "RetroArch")
            ]
    candidates += [
        library / "steamapps" / "common" / "RetroArch" for library in _steam_libraries()
    ]
    # Scoop's Extras bucket: <root>\apps\retroarch\current, the root being
    # %SCOOP% or ~\scoop for a user install, %SCOOP_GLOBAL% or
    # %ProgramData%\scoop for a global one. Its system folder is persisted
    # through a junction, so the folder beside retroarch.exe is the real one.
    scoop_roots = [_scoop_root("SCOOP", "USERPROFILE"), _scoop_root("SCOOP_GLOBAL", "ProgramData")]
    candidates += [
        Path(root) / "apps" / "retroarch" / "current" for root in scoop_roots if root
    ]
    return [folder for folder in candidates if _is_file(folder / "retroarch.exe")]


def _macos_retroarch_base() -> Path:
    """Where RetroArch on macOS keeps its system folder by default:
    ~/Documents/RetroArch, or Application Support/RetroArch for a portable
    install. The Steam build is always portable (platform_darwin.m, `#if
    HAVE_STEAM portable = YES`), with no portable.txt to say so: its
    bundle under Steam's library, and no other RetroArch.app, mark it."""
    support = Path.home() / "Library" / "Application Support" / "RetroArch"
    if _is_file(support / "portable.txt"):
        return support
    steam = (
        Path.home() / "Library" / "Application Support" / "Steam" / "steamapps"
        / "common" / "RetroArch" / "RetroArch.app"
    )
    if _is_dir(steam) and not _is_dir(Path("/Applications/RetroArch.app")):
        return support
    return Path.home() / "Documents" / "RetroArch"


def _retroarch_appimage_dirs(home: Path) -> list[Path]:
    """The system folder of each RetroArch AppImage kept with a portable
    folder, up to two folders below home.

    The buildbot's Linux build unpacks RetroArch-Linux-x86_64.AppImage beside
    RetroArch-Linux-x86_64.AppImage.home/.config/retroarch. The AppImage
    runtime sets HOME to <AppImage>.home and XDG_CONFIG_HOME to
    <AppImage>.config when those folders exist (type2-runtime fedfad51,
    src/runtime/runtime.c:1449-1462), so this RetroArch never reads
    ~/.config/retroarch. The archive holds no retroarch.cfg: until the first
    run writes one, the system folder is the base folder's (frontend_unix_get_env
    in platform_unix.c).
    """
    images: list[Path] = []
    for depth in ("", "*/", "*/*/"):
        for suffix in (".home", ".config"):
            try:
                hits = sorted(home.glob(f"{depth}*.AppImage{suffix}"))
            except OSError:
                continue
            for hit in hits:
                image = hit.with_name(hit.name[:-len(suffix)])
                if image not in images and _is_file(image):
                    images.append(image)
    dirs: list[Path] = []
    for image in images:
        portable_home = image.with_name(image.name + ".home")
        portable_config = image.with_name(image.name + ".config")
        if _is_dir(portable_config):
            base = portable_config / "retroarch"
        elif _is_dir(portable_home) and "XDG_CONFIG_HOME" not in os.environ:
            base = portable_home / ".config" / "retroarch"
        else:
            continue
        tilde = portable_home if _is_dir(portable_home) else home
        system = _parse_retroarch_system_dir(base / "retroarch.cfg", base, tilde)
        if system is None and _is_dir(base):
            system = base / "system"
        if system is not None and system not in dirs:
            dirs.append(system)
    return dirs


def _unix_retroarch_base() -> Path:
    """RetroArch's base folder on Linux: $XDG_CONFIG_HOME/retroarch when the
    variable is set, else ~/.config/retroarch (fill_pathname_application_data
    in file_path_special.c, frontend_unix_get_env in platform_unix.c). The
    code tests only that the variable exists, so an empty one counts."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg is not None:
        return Path(xdg) / "retroarch"
    return Path.home() / ".config" / "retroarch"


# System directory -> the retroarch.cfg it was read from and the directory
# ':' expands to there, for finding the cores of the same installation.
_RETROARCH_CONFIGS: dict[Path, tuple[Path, Path]] = {}


def _parse_retroarch_system_dir(
    cfg_path: Path, app_dir: Path | None = None, home: Path | None = None
) -> Path | None:
    """Parse system_directory from retroarch.cfg.

    app_dir is RetroArch's application directory, used to expand ':' values.
    It defaults to the directory holding the config, which is where a portable
    install keeps both. home is what '~' means to that RetroArch, the user's
    home when not given.
    """
    if not _exists(cfg_path):
        return None
    app_dir = app_dir or cfg_path.parent
    system_dir = _retroarch_cfg_dir(cfg_path, "system_directory", app_dir, "system", home)
    if system_dir is not None:
        _RETROARCH_CONFIGS.setdefault(system_dir, (cfg_path, app_dir))
    return system_dir


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
    if not _exists(path):
        return None
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith(f"{key}="):
                _, _, value = line.partition("=")
                return _shell_unquote(value)
    except OSError as exc:
        # A settings.sh a sudo EmuDeck run left to root hid the setup.
        _note_refused(path, exc)
    return None


# Where an embedded system names the board it was built for, in the words
# of our target lists: batocera-system.mk writes BATOCERA_SYSTEM_ARCH,
# recalbox-system.mk RECALBOX_SYSTEM_PLATFORM, ROCKNIX's scripts/image puts
# HW_DEVICE in os-release (RK3326, our rk3326). Lakka's scripts/image writes
# LIBREELEC_DEVICE when the image is built for a device (RPi4) and always
# LIBREELEC_PROJECT (Generic): the first one set is the board. KNULLI moves
# /usr/share/batocera to /usr/share/knulli (knulli-linux 57afa662,
# board/scripts/post-build-script.sh:264-278) and writes KNULLI_SYSTEM_ARCH
# to knulli.arch (package/system/knulli-system/knulli-system.mk:98-99).
# AmberELEC's scripts/image writes COREELEC_DEVICE (a21975bf, line 168), the
# DEVICE its Makefile builds (RG351P). EmuELEC's writes the same line (v4.8,
# line 189), the DEVICE of the release image (OdroidGoAdvance).
_BOARD_SOURCES: dict[str, tuple[str, str]] = {
    "amberelec": ("os_release", "COREELEC_DEVICE"),
    "emuelec": ("os_release", "COREELEC_DEVICE"),
    "batocera": ("file", "/usr/share/batocera/batocera.arch"),
    "recalbox": ("file", "/recalbox/recalbox.arch"),
    "rocknix": ("os_release", "HW_DEVICE"),
    "lakka": ("os_release", "LIBREELEC_DEVICE|LIBREELEC_PROJECT"),
    "knulli": ("file", "/usr/share/knulli/knulli.arch"),
    "retropie": ("retropie", ""),
}

# The board a system's own name stands for, where the two differ: the
# target lists are named for the board files (configs/knulli-rk3566.board),
# and the arch file for the TARGET flag the board sets. knulli-rk3566.board
# sets BR2_PACKAGE_BATOCERA_TARGET_RK3568, which knulli-system.mk:22-23
# (20260511) writes as rk3568. batocera-zen3.board sets TARGET_ZEN3, which
# batocera-system.mk:56-57 (batocera-43.1) writes as x86-64-v3.
_BOARD_NAMES: dict[str, dict[str, str]] = {
    "batocera": {"x86-64-v3": "zen3"},
    "knulli": {"rk3568": "rk3566"},
}


# The board a card names on a partition a computer reads. Batocera writes
# its image's board to boot/batocera.board on the BATOCERA boot partition,
# the FAT one beside SHARE (batocera-43.1, board/batocera/scripts/
# post-image-script.sh:60), and reads it there itself (package/batocera/
# core/batocera-scripts/scripts/batocera-info). batocera.arch is inside the
# image, out of a computer's reach. KNULLI writes boot/knulli.board the same
# way (knulli-linux 20260511, board/scripts/post-image-script.sh:66). Both
# write the image's name, which the target list maps to its board.
_CARD_BOARD_FILES: dict[str, str] = {"batocera": "boot/batocera.board",
                                     "knulli": "boot/knulli.board"}


def card_board(platform: str) -> str | None:
    """The board the card mounted here names, None where no card or two
    cards of different boards do: a card is most often prepared on a
    computer, where the system's own board file does not exist."""
    where = _CARD_BOARD_FILES.get(platform)
    if where is None:
        return None
    boards: set[str] = set()
    for mount in _mounted_cards():
        try:
            value = (mount / where).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if value.strip() and not _CONTROLS.search(value.strip()):
            boards.add(value.strip().lower())
    return boards.pop() if len(boards) == 1 else None


def detect_board(platform: str) -> str | None:
    """The board this system was built for, or None where it names none."""
    kind, where = _BOARD_SOURCES.get(platform, ("", ""))
    if kind == "file":
        try:
            value = Path(where).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    elif kind == "os_release":
        release = _parse_os_release()
        value = next((release[key] for key in where.split("|") if release.get(key)), "")
    elif kind == "retropie":
        value = _retropie_board() or ""
    else:
        return None
    board = value.strip().lower()
    # A board no TARGET line names is written "unknown" (KNULLI's r16).
    if board == "unknown":
        return None
    return _BOARD_NAMES.get(platform, {}).get(board, board) or None


# RetroPie names its board as get_platform does (RetroPie-Setup f5ebfba6,
# scriptmodules/system.sh:396-424 and 425-513): a Pi by the BCM Hardware
# line of /proc/cpuinfo or raspberrypi in its device tree, its model by the
# CPU field (bits 12-15) of a revision code with bit 23 set, rpi1 without
# it. With neither a Hardware line nor a device tree, the machine: x86_64.
# Read only where RetroPie is installed (rootdir /opt/retropie,
# retropie_packages.sh:17): a computer preparing a Pi's card is no Pi.
_RPI_MODELS = {0: "rpi1", 1: "rpi2", 2: "rpi3", 3: "rpi4", 4: "rpi5"}


def _retropie_board() -> str | None:
    """The target RetroPie's own reading of this machine names, or None."""
    if not _is_dir(_on_device("/opt/retropie")):
        return None
    try:
        cpuinfo = _on_device("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        cpuinfo = ""
    fields = {key.strip(): value.strip() for key, sep, value in
              (line.partition(":") for line in cpuinfo.splitlines()) if sep}
    tree = _on_device("/proc/device-tree/compatible")
    try:
        compatible = tree.read_bytes().decode("ascii", errors="replace")
    except OSError:
        compatible = None
    hardware = fields.get("Hardware", "")
    if hardware.startswith("BCM") or (not hardware and compatible is not None
                                      and "raspberrypi" in compatible):
        try:
            revision = int(fields.get("Revision", ""), 16)
        except ValueError:
            return None
        if not (revision >> 23) & 1:
            return "rpi1"
        return _RPI_MODELS.get((revision >> 12) & 15)
    if hardware or compatible is not None:
        return None
    return "x86_64" if platform.machine() == "x86_64" else None


def _parse_json_path(path: Path, *keys: str) -> str | None:
    """Extract a nested string value from a JSON file."""
    if not _exists(path):
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
    if not _exists(path):
        return None
    normalized = key.lstrip("$")
    try:
        raw = path.read_bytes()
        # Windows PowerShell's Out-File writes UTF-16, Set-Content -Encoding
        # UTF8 a byte order mark: EmuDeck's settings.ps1 passes through both.
        encoding = "utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
        for line in raw.decode(encoding, errors="replace").splitlines():
            line = line.strip()
            check = line.lstrip("$")
            if check.startswith(f"{normalized}="):
                _, _, value = check.partition("=")
                return value.strip('"').strip("'")
    except OSError as exc:
        _note_refused(path, exc)
    return None


# The root the embedded rules read under: "/" on a device, a folder holding a
# copy of one in the tests.
_SYSTEM_ROOT = Path("/")


def _on_device(path: str) -> Path:
    """A path of the running system, read under _SYSTEM_ROOT."""
    if _SYSTEM_ROOT == Path("/"):
        return Path(path)
    return _SYSTEM_ROOT / path.lstrip("/")


# Why a system found here gets no folder: said once per run.
_NO_FOLDER = {
    "TrimUI": "its firmware publishes no source naming the folder its RetroArch reads",
    "MinUI": f"its card names no release in {CARD_MARKER}, which tells MinUI, NextUI "
             "and MyMinUI apart. Name the card's root and the one it runs: "
             "--platform minui (or nextui, myminui) --dest /mnt/SDCARD",
}
# A system found by its card, with the end of the path that proves it: the
# card root is what comes before.
_CARD_SYSTEMS = {"MinUI": "/.system/res"}

# (platform, BIOS folder) -> the name the system found there gives itself.
_DETECTED_OS: dict[tuple[str, Path], str] = {}


# A version as a list or a system writes it: v1.22.2, 43.1, 8.3.1.1.
_VERSION_TEXT = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,39}")
# What generate_pack.py wrote as every list's version until it recorded the
# platform's own: not a version, so a list holding it names none.
_NO_LIST_VERSION = "1.0"
# What the platform's own check does, not a verdict on it: it compares the
# files with the list of its own version, and no run proved them working.
_MD5_CHECK = ("{name}'s own BIOS check reads the list of the version it runs, and "
              "may show some files as not matching it.")


def _version_line(path: Path) -> str:
    """The first line of a small version file, "" when it cannot be read."""
    if not _is_file(path):
        return ""
    try:
        with path.open("rb") as fh:
            head = fh.read(4096)
    except OSError:
        return ""
    lines = head.decode("utf-8", errors="replace").strip().splitlines()
    return lines[0].strip() if lines else ""


def _batocera_version(_bios_path: Path) -> str:
    # batocera-system.mk:9,100-102 (batocera-43.1): the version, then the
    # date and time of the build.
    words = _version_line(_on_device("/usr/share/batocera/batocera.version")).split()
    return words[0] if words else ""


def _recalbox_version(_bios_path: Path) -> str:
    # Dockerfile:31 (recalbox 10.1.1) writes RECALBOX_VERSION, which
    # .gitlab-ci.yml:723 sets to the release tag, or for a build of a branch
    # to its date and name. A build from a working tree says "development"
    # (projects/configgen/configgen/challenge/RuleScript.py:64). Only a
    # release is a version a list is built for.
    text = _version_line(_on_device("/recalbox/recalbox.version"))
    return text if re.fullmatch(r"\d+(?:\.\d+)+", text) else ""


def _retrobat_version(bios_path: Path) -> str:
    # <RetroBat>/system/version.info, which es-update writes and es-checkversion
    # reads (emulatorlauncher 48cdc616, es-update/RetrobatVersion.cs:66-92).
    # The 8.3.1 installer holds "8.3.1.1-stable-win64".
    text = _version_line(bios_path.parent / "system" / "version.info")
    head = text.split("-", 1)[0]
    return head if re.fullmatch(r"\d+(?:\.\d+)+", head) else ""


def _os_release_version(key: str, value: str) -> Callable[[Path], str]:
    """VERSION_ID from os-release, on the system that names itself so."""
    def read(_bios_path: Path) -> str:
        release = _parse_os_release()
        if release.get(key, "").lower() != value:
            return ""
        return release.get("VERSION_ID", "")
    return read


def _same_release(installed: str, listed: str) -> bool:
    return installed == listed


def _retrobat_release(installed: str, listed: str) -> bool:
    # The release tagged 8.3.1 ships 8.3.1.1: a fourth number is a build of
    # the tagged version.
    return installed == listed or installed.startswith(listed + ".")


class _VersionSource(NamedTuple):
    """Where a system states the version it runs, and what a different one means."""

    read: Callable[[Path], str]
    meaning: str
    same: Callable[[str, str], bool] = _same_release
    # Written by the list (v6.1) and not by the system (6.1).
    prefix: str = ""


# The systems whose version a file states, read without running anything.
# RetroArch writes its version in no file: its lists come from core info
# files the online updater replaces, so its version is not compared. KNULLI
# writes its codename (knulli-system.mk:9,100-102, "scarab") and ROCKNIX the
# date of the build (scripts/image:82), not the release their lists name.
# AmberELEC's list names a prerelease tag, and how that tag maps to the
# VERSION its image writes is not established.
_VERSION_SOURCES: dict[str, _VersionSource] = {
    "batocera": _VersionSource(_batocera_version, _MD5_CHECK),
    "recalbox": _VersionSource(_recalbox_version, _MD5_CHECK),
    "retrobat": _VersionSource(_retrobat_version, _MD5_CHECK, _retrobat_release),
    # scripts/image:159-164 (Lakka-LibreELEC v6.1) writes VERSION_ID from
    # OS_VERSION, "6.1" in distributions/Lakka/version, and ID=lakka.
    "lakka": _VersionSource(
        _os_release_version("ID", "lakka"),
        "Lakka checks only that a file is there, so this matters only where a core "
        "of the version it runs reads a file this list does not name.", prefix="v"),
    # scripts/image:172-177 (EmuELEC v4.8): VERSION_ID from OS_VERSION, 4.8 in
    # distributions/EmuELEC/version, and NAME=EmuELEC.
    "emuelec": _VersionSource(_os_release_version("NAME", "emuelec"), _MD5_CHECK),
}


def version_note(plat: str, bios_path: Path, manifest: dict) -> tuple[str, str, str] | None:
    """(list version, installed version, sentence) when the system here runs
    another version than the one the list was built for, else None: an
    unknown version on either side says nothing."""
    source = _VERSION_SOURCES.get(plat)
    listed = manifest.get("version")
    if (source is None or not isinstance(listed, str) or listed == _NO_LIST_VERSION
            or not _VERSION_TEXT.fullmatch(listed)):
        return None
    installed = source.read(bios_path)
    if not _VERSION_TEXT.fullmatch(installed):
        return None
    compared = listed[len(source.prefix):] if listed.startswith(source.prefix) else listed
    if source.same(installed, compared):
        return None
    name = display_name(plat, manifest)
    return listed, installed, (
        f"This list was built for {name} {listed}, this machine runs {installed}. "
        + source.meaning.format(name=name))


def _rule_matches(rule: _OsRule, release: dict[str, str]) -> bool:
    if rule.method == "os_release":
        # Any of the KEY=value pairs, the value compared without case.
        return any(
            release.get(key) == value.lower()
            for key, _, value in (pair.partition("=") for pair in rule.values)
        )
    if rule.method == "file_matches":
        path, pattern = rule.values
        try:
            text = _on_device(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        return re.search(pattern, text, re.IGNORECASE | re.MULTILINE) is not None
    return all(_exists(_on_device(value)) for value in rule.values)


def _config_files(pattern: str) -> list[tuple[Path, Path]]:
    """(file to read, its folder as the system sees it) for a config rule."""
    device = pattern.replace("$HOME", str(Path.home()), 1)
    folder, _, name = device.rpartition("/")
    if "*" not in name:
        return [(_on_device(device), Path(folder))]
    try:
        return [(path, Path(folder)) for path in sorted(_on_device(folder).glob(name))
                if _is_file(path)]
    except OSError:
        return []


def _os_system_dir(rules: list[_OsRule]) -> Path | None:
    """The folder a system's RetroArch reads: the system_directory of its
    first config that sets one, else the folder its build defaults to.

    The config also records where the cores of that installation are.
    """
    for rule in rules:
        home = Path(rule.home) if rule.home else None
        for pattern in rule.configs:
            for path, folder in _config_files(pattern):
                system_dir = _parse_retroarch_system_dir(path, folder, home)
                if system_dir is not None:
                    seen = _on_device(str(system_dir))
                    _RETROARCH_CONFIGS.setdefault(seen, _RETROARCH_CONFIGS[system_dir])
                    return seen
    bios = next((rule.bios for rule in rules if rule.bios), None)
    return _on_device(bios) if bios else None


def _detect_embedded() -> list[tuple[str, Path]]:
    """The embedded system this is, by what its own build writes.

    A system built on another matches both: the derivative is meant. Two
    unrelated systems matching are both returned, and os_conflict() names
    them, so that no folder is chosen between them in silence.
    """
    release = {k: v.lower() for k, v in _parse_os_release().items()}
    matched = [rule for rule in _EMBEDDED_RULES if _rule_matches(rule, release)]
    bases = {rule.base for rule in matched if rule.base}
    found: list[tuple[str, Path]] = []
    for name in dict.fromkeys(rule.name for rule in matched):
        if name in bases:
            continue
        rules = [rule for rule in matched if rule.name == name]
        plat = rules[0].manifest
        folder = _os_system_dir(rules) if plat else None
        if name in _CARD_SYSTEMS:
            marker = next(value for rule in rules for value in rule.values
                          if value.endswith(_CARD_SYSTEMS[name]))
            root = _on_device(marker[:-len(_CARD_SYSTEMS[name])])
            plat = card_platform(root) or ""
            if plat:
                folder, name = root, display_name(plat)
        if folder is None:
            reason = _NO_FOLDER.get(
                name, "nothing on it names the folder its RetroArch reads")
            closing = "" if name in _CARD_SYSTEMS else " Name the folder with --dest."
            print(f"{name} found here, but {reason}.{closing}", file=sys.stderr)
            continue
        _DETECTED_OS[(plat, folder)] = name
        found.append((plat, folder))
    return found


def detected_os(plat: str, path: Path) -> str:
    """The name of the system detection found this folder on, or ""."""
    return _DETECTED_OS.get((plat, path), "")


# A card read from a computer can name a system it cannot tell from
# another: dArkOS writes ArkOS's EASYROMS tree (finishing_touches.sh:420-
# 481, daecf488) and replaced it on 30 December 2025, so an EASYROMS card is
# either one. The detection keeps ArkOS's name, as its rules and lists are
# keyed. On the device itself the boot splash title tells them apart.
_CARD_TITLES = {"ArkOS": "dArkOS or ArkOS"}
# The folders whose system was named from a card read on a computer.
_FROM_CARD: set[tuple[str, Path]] = set()


def card_title(name: str) -> str:
    """The system a card's own files name, as a computer reading it can tell."""
    return _CARD_TITLES.get(name, name)


def detected_shown(plat: str, path: Path) -> str:
    """detected_os as the screen says it: a card read on a computer by the
    name its files allow."""
    name = detected_os(plat, path)
    return card_title(name) if (plat, path) in _FROM_CARD else name


def os_conflict(platforms: list[tuple[str, Path]]) -> list[str]:
    """The systems among these when there are two or more: a machine runs one."""
    names = list(dict.fromkeys(filter(None, (detected_os(n, p) for n, p in platforms))))
    return names if len(names) > 1 else []


def _system_lines() -> list[str]:
    """Each embedded system detection knows, with the files it gets."""
    lines = []
    for name in dict.fromkeys(rule.name for rule in _EMBEDDED_RULES):
        plat = next(rule.manifest for rule in _EMBEDDED_RULES if rule.name == name)
        if name in _CARD_SYSTEMS:
            lines.append(f"{name}: minui, nextui or myminui, as the card's {CARD_MARKER} "
                         "names it (from a computer: --dest <card root>)")
        elif plat:
            lines.append(f"{name}: {plat}")
        else:
            lines.append(f"{name}: not installed to, {_NO_FOLDER[name]} (use --dest)")
    return lines


def found_label(plat: str, path: Path) -> str:
    """How a detected folder is announced: the system's own name, and the
    platform whose files it gets when that is another name."""
    name = detected_shown(plat, path)
    shown = display_name(plat)
    moved = "".join(f", {folder}/ at {place}"
                    for folder, place in sorted(_MOVED_FOLDERS.get(path, {}).items())
                    if folder in ("bios", "roms"))
    folder = shown_path(setup_bios_folder(plat, path))
    if not name or name == shown:
        return f"{shown} at {folder}{moved}"
    return f"{name} at {folder} ({shown} files){moved}"


def _note_windows_unasked() -> None:
    """Say once, as a folder detection could not look in, that Windows did
    not answer: its drives are then searched without its folders."""
    why = _WSL["unasked"]
    if (not why or not getattr(_SETUP_SEARCH, "active", False)
            or getattr(_SETUP_SEARCH, "quiet", False)):
        return
    refused = (Path(_WSL["root"]), why)
    if refused in _DETECTION_REFUSED:
        return
    _DETECTION_REFUSED.append(refused)
    words = refused_words(*refused)
    EVENTS.emit("unsearched", folder=str(refused[0]), reason=why, message=words)
    print(f"  {screen_text(words)}", file=sys.stderr)


def _winreg_value(key: str, value: str) -> str | None:
    """A string value of the Windows registry, read natively."""
    if sys.platform != "win32":
        return None
    import winreg

    hive, _, subkey = key.partition("\\")
    roots = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    try:
        with winreg.OpenKey(roots[hive], subkey) as handle:
            data, _kind = winreg.QueryValueEx(handle, value)
    except (OSError, KeyError):
        return None
    return data.strip() if isinstance(data, str) and data.strip() else None


def _read_registry(key: str, value: str) -> str | None:
    """A string value of the Windows registry, read natively or, under WSL,
    through reg.exe. None when the key, the value or the means is missing."""
    if os.name == "nt":
        return _winreg_value(key, value)
    if not _WSL["active"]:
        return None
    try:
        result = subprocess.run(
            ["reg.exe", "query", key, "/v", value],
            capture_output=True, text=True, errors="replace", timeout=10,
            stdin=subprocess.DEVNULL, cwd="/mnt/c" if Path("/mnt/c").is_dir() else None,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        _windows_unasked("reg.exe", exc)
        _note_windows_unasked()
        return None
    match = re.search(
        rf"^\s*{re.escape(value)}\s+REG_(?:EXPAND_)?SZ\s+(.+?)\s*$", result.stdout, re.M
    )
    return match.group(1) if match else None
