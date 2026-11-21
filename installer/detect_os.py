"""The operating system this runs on and the embedded system it is, WSL and the registry read."""
from __future__ import annotations

import argparse
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from installer.cards import card_platform, setup_bios_folder
from installer.config_values import _RETROARCH_CONFIGS, _parse_retroarch_system_dir
from installer.detection_notes import echo_detection, note_detection
from installer.embedded import CARD_MARKER, _EMBEDDED_RULES, _NO_FOLDER
from installer.events import EVENTS
from installer.host_fs import (
    _DETECTION_REFUSED,
    _SETUP_SEARCH,
    _WSL,
    _exists,
    _host_path,
    _is_dir,
    _is_file,
    refused_words,
)
from installer.paths import _MOVED_FOLDERS, shown_path
from installer.platforms import display_name
from installer.text import screen_text

if TYPE_CHECKING:
    from installer.embedded import _OsRule


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


def _unix_retroarch_base() -> Path:
    """RetroArch's base folder on Linux: $XDG_CONFIG_HOME/retroarch when the
    variable is set, else ~/.config/retroarch (fill_pathname_application_data
    in file_path_special.c, frontend_unix_get_env in platform_unix.c). The
    code tests only that the variable exists, so an empty one counts."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg is not None:
        return Path(xdg) / "retroarch"
    return Path.home() / ".config" / "retroarch"


# The root the embedded rules read under: "/" on a device, a folder holding a
# copy of one in the tests.
_SYSTEM_ROOT = Path("/")


def _on_device(path: str) -> Path:
    """A path of the running system, read under _SYSTEM_ROOT."""
    if _SYSTEM_ROOT == Path("/"):
        return Path(path)
    return _SYSTEM_ROOT / path.lstrip("/")


# A system found by its card, with the end of the path that proves it: the
# card root is what comes before.
_CARD_SYSTEMS = {"MinUI": "/.system/res"}

# (platform, BIOS folder) -> the name the system found there gives itself.
_DETECTED_OS: dict[tuple[str, Path], str] = {}


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
            note_detection(f"{name} found here, but {reason}.{closing}")
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
    echo_detection(f"  {screen_text(words)}")


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


def _os_name() -> str:
    """The OS's own name, from os-release, else the kernel's."""
    release = _parse_os_release()
    return release.get("PRETTY_NAME") or release.get("NAME") or platform.system()
