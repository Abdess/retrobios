"""LaunchBox on Windows: where it lives, the emulators it lists and their BIOS folders."""
from __future__ import annotations

import contextlib
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from installer.config_values import _parse_retroarch_system_dir
from installer.host_fs import _exists, _is_dir


def _lnk_target(lnk_path: Path, exe_name: str) -> Path | None:
    """Read the target path of a Windows shortcut.

    Shortcuts embed the target as a plain local path. Scanning for it avoids
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
        if _exists(lnk):
            target = _lnk_target(lnk, "LaunchBox.exe")
            if target:
                # The shortcut points at Core/LaunchBox.exe
                candidates.append(target.parent.parent)
                candidates.append(target.parent)
    userprofile = os.environ.get("USERPROFILE", "")
    if userprofile:
        candidates.append(Path(userprofile) / "LaunchBox")
    for root in candidates:
        if _exists(root / "Data" / "Emulators.xml"):
            return root
    return None


def launchbox_emulators(emulators_xml: Path) -> dict[str, Path]:
    """Map each emulator LaunchBox knows about to its installation directory.

    LaunchBox stores its emulator list in Data/Emulators.xml. ApplicationPath
    is either absolute or relative to the LaunchBox root directory. Keys are
    the lowercase executable names.
    """
    found: dict[str, Path] = {}
    if not _exists(emulators_xml):
        return found
    try:
        if emulators_xml.stat().st_size > 10 * 1024 * 1024:
            return found
        raw = emulators_xml.read_text(encoding="utf-8", errors="replace")
        # ElementTree expands internal entities, and LaunchBox writes no doctype
        if "<!DOCTYPE" in raw.upper():
            return found
        root = ET.fromstring(raw)
    except (ET.ParseError, OSError):
        return found
    lb_root = emulators_xml.parent.parent
    for emu in root.iter("Emulator"):
        app_path = (emu.findtext("ApplicationPath") or "").replace("\\", "/")
        if not app_path:
            continue
        exe = Path(app_path)
        if not exe.is_absolute():
            exe = lb_root / exe
        if _is_dir(exe.parent):
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
    portable = _exists(emu_dir / "portable.ini") or _exists(portable_txt)
    if portable:
        subpath = ""
        with contextlib.suppress(OSError):
            subpath = portable_txt.read_text(
                encoding="utf-8", errors="replace"
            ).strip()
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
    if not _exists(toml) and appdata:
        toml = Path(appdata) / "xemu" / "xemu" / "xemu.toml"
    if _exists(toml):
        try:
            for line in toml.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith(("bootrom_path", "flashrom_path")):
                    parts = line.split("'")
                    if len(parts) > 1 and _exists(Path(parts[1])):
                        return Path(parts[1]).parent
        except OSError:
            pass
    return emu_dir / "bios"


def launchbox_bios_dirs(root: Path) -> dict[str, Path]:
    """Map emulator ids to the BIOS directory LaunchBox expects for them.

    Only emulators whose destination LaunchBox itself computes are listed.
    The rest keep the default locations declared in the manifest.
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
    if emu_dir and _exists(emu_dir / "portable.txt"):
        # portable.txt beside the executable moves the user directory to
        # User (SetUserDirectory in Source/Core/UICommon/UICommon.cpp,
        # PORTABLE_USER_DIR in Source/Core/Common/CommonPaths.h)
        dirs["dolphin"] = emu_dir / "User"
    return dirs
