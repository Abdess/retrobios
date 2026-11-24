"""Frontends and emulators found on this machine, by path, executable, registry and setup."""
from __future__ import annotations

import functools
import os
import re
from collections.abc import Callable
from pathlib import Path

from installer.config_values import (
    _CONFIGS_READ,
    _parse_bash_var,
    _parse_json_path,
    _parse_ps1_var,
    _parse_retroarch_system_dir,
    _retroarch_cfg_dir,
)
from installer.detection_notes import note_detection
from installer.detect_os import (
    _detect_embedded,
    _macos_retroarch_base,
    _note_windows_unasked,
    _read_registry,
    _unix_retroarch_base,
)
from installer.host_fs import _SETUP_SEARCH, _exists, _host_path, _is_dir, _is_file, _note_refused
from installer.paths import MOVED, RETRODECK_CONFIG, shown_path
from installer.platforms import display_name
from installer.text import _CONTROLS
from installer.detect_android import _detect_android, android_unreachable_folders
from installer.detect_launchbox import (
    _launchbox_retroarch_system_dir,
    launchbox_emulators,
    launchbox_root,
)


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


# The platforms whose configuration names a folder with a control character.
_UNNAMEABLE: list[str] = []


def _detection_guarded(detect: Callable[..., list]) -> Callable[..., list]:
    """Detection whose probes treat a folder this user cannot open as
    absent, and say so once.

    Each probe goes through _exists, _is_dir or _is_file, which records the
    refusal. A probe that still raises PermissionError (a glob on a Python
    whose pathlib lets it through) is the last net: the call finds nothing
    and says why, where HOME kept across `su` without `-` once ended the
    run on a traceback.
    """
    @functools.wraps(detect)
    def guarded(*args: object, **kwargs: object) -> list:
        outer = getattr(_SETUP_SEARCH, "active", False)
        _SETUP_SEARCH.active = True
        try:
            return detect(*args, **kwargs)
        except PermissionError as exc:
            _note_refused(Path(str(exc.filename or "")), exc)
            return []
        finally:
            _SETUP_SEARCH.active = outer
    return guarded


@_detection_guarded
def detect_frontends(os_type: str, home: Path | None = None) -> list[str]:
    """Detect frontends that reference emulators without owning a BIOS dir.

    ES-DE resolves its application data directory to $ESDE_APPDATA_DIR or
    <home>/ES-DE (es-core FileSystemUtil.cpp getAppDataDirectory).
    """
    home = home or Path.home()
    frontends: list[str] = []
    esde_env = os.environ.get("ESDE_APPDATA_DIR", "")
    if (esde_env and _is_dir(Path(esde_env))) or _is_dir(home / "ES-DE"):
        frontends.append("esde")
    if launchbox_root(os_type) is not None:
        frontends.append("launchbox")
    return frontends


# The registry's path_exists rules (platforms/_registry.yml install.detect),
# one row each: (os, platform, path, BIOS directory when it is not the path).
# The manifests publish them too, but detection runs before any manifest is
# fetched. A test holds this table equal to the registry. Without it a Linux
# home holding RetroPie/BIOS or .config/BizHawk/Firmware detected nothing.
_PATH_RULES: tuple[tuple[str, str, str, str | None], ...] = (
    ("windows", "retrobat", "C:\\RetroBat\\bios", None),
    ("windows", "retrobat", "%USERPROFILE%\\RetroBat\\bios", None),
    ("linux", "emudeck", "$HOME/Emulation/bios", None),
    ("darwin", "emudeck", "$HOME/Emulation/bios", None),
    ("linux", "retrodeck", "$HOME/.var/app/net.retrodeck.retrodeck", "$HOME/retrodeck"),
    ("linux", "romm", "/romm/library/bios", None),
    # A library laid out as {platform}/bios has no library/bios: RomM's
    # config folder is the evidence (config_manager.py:264-265).
    ("linux", "romm", "/romm/config/config.yml", "/romm/library/bios"),
    ("linux", "retropie", "$HOME/RetroPie/BIOS", None),
    ("windows", "bizhawk", "%USERPROFILE%\\BizHawk\\Firmware", None),
    ("linux", "misterfpga", "/media/fat/MiSTer", "/media/fat/games"),
)


def _rule_path(template: str) -> Path:
    """A rule's path on this machine: $HOME or %USERPROFILE%, then the rest."""
    bases = (
        ("$HOME", Path.home()),
        ("%USERPROFILE%", Path(os.environ.get("USERPROFILE") or Path.home())),
    )
    for variable, base in bases:
        if template.startswith(variable):
            rest = [part for part in re.split(r"[\\/]", template[len(variable):]) if part]
            return base.joinpath(*rest)
    return _host_path(template)


# The registry's executable rules: (os, platform, glob under $HOME or
# %USERPROFILE%, folder beside the executable that holds the BIOS). BizHawk is
# a portable archive reading <EmuHawk folder>/Firmware (PathExtensions.cs
# DataDirectoryPath), wherever it was extracted. ~/.config/BizHawk/Firmware,
# the old guess, is a folder no build reads.
_EXE_RULES: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    ("linux", "bizhawk", ("$HOME/BizHawk*/EmuHawkMono.sh", "$HOME/*/BizHawk*/EmuHawkMono.sh"),
     "Firmware"),
    ("windows", "bizhawk", ("%USERPROFILE%\\BizHawk*\\EmuHawk.exe",
                            "%USERPROFILE%\\*\\BizHawk*\\EmuHawk.exe"), "Firmware"),
)


def _detect_by_executable(os_type: str, found: list[tuple[str, Path]]) -> None:
    """Add a portable install found by its executable, the newest first."""
    systems = ("linux", "windows") if os_type == "wsl" else (os_type,)
    for rule_os, platform_name, patterns, subdir in _EXE_RULES:
        if rule_os not in systems or any(name == platform_name for name, _ in found):
            continue
        hits: list[Path] = []
        for pattern in patterns:
            base, _, rest = pattern.partition("/" if "/" in pattern else "\\")
            glob = "/".join(part for part in re.split(r"[\\/]", rest) if part)
            try:
                hits.extend(path for path in _rule_path(base).glob(glob) if _is_file(path))
            except OSError:
                continue
        if hits:
            newest = max(hits, key=lambda path: path.stat().st_mtime)
            found.append((platform_name, newest.parent / subdir))


# The registry's registry rules: (os, platform, key, value, BIOS folder under
# the folder the value names). RetroBat.exe writes its own folder there on
# every start (retrobat-executable 702da66a, RetroBat/RetroBat/Program.cs:57
# and 99, RegistryTools.cs:15-50), wherever it was installed. The path rules
# only knew C:\RetroBat and the profile folder.
_REGISTRY_RULES: tuple[tuple[str, str, str, str, str], ...] = (
    ("windows", "retrobat", "HKCU\\SOFTWARE\\RetroBat", "LatestKnownInstallPath", "bios"),
)


def _detect_by_registry(os_type: str, found: list[tuple[str, Path]]) -> None:
    """Add a platform whose own program names its folder in the registry.

    A folder since moved or removed is passed over, so the path rules still
    get their turn.
    """
    systems = ("windows",) if os_type in ("windows", "wsl") else ()
    for rule_os, platform_name, key, value, subdir in _REGISTRY_RULES:
        if rule_os not in systems or any(name == platform_name for name, _ in found):
            continue
        folder = _read_registry(key, value)
        if not folder:
            continue
        base = _host_path(folder.rstrip("\\/") or folder)
        if _is_dir(base):
            found.append((platform_name, base / subdir))


def _detect_by_path(os_type: str, found: list[tuple[str, Path]]) -> None:
    """Add what a registry path rule finds, for a platform not found yet."""
    systems = ("linux", "windows") if os_type == "wsl" else (os_type,)
    for rule_os, platform_name, path, bios in _PATH_RULES:
        if rule_os not in systems or any(name == platform_name for name, _ in found):
            continue
        if _exists(_rule_path(path)):
            found.append((platform_name, _rule_path(bios or path)))


def _detect_emudeck_unix(found: list[tuple[str, Path]]) -> None:
    """Add EmuDeck on Linux or macOS."""
    # EmuDeck on Linux and macOS: functions/all.sh:3-4 and 24 (EmuDeck
    # dddb3022) reads $emudeckFolder/settings.sh on both, and vars.sh:2
    # sets emudeckFolder to $HOME/.config/EmuDeck.
    emudeck_settings = Path.home() / ".config" / "EmuDeck" / "settings.sh"
    if _exists(emudeck_settings):
        emu_path = _parse_bash_var(emudeck_settings, "emulationPath")
        if emu_path:
            found.append(("emudeck", Path(emu_path) / "bios"))


def _detect_retrodeck(home: Path, found: list[tuple[str, Path]]) -> None:
    """Add RetroDECK's home folder."""
    retrodeck_conf_dir = home / RETRODECK_CONFIG
    retrodeck_json = retrodeck_conf_dir / "retrodeck.json"
    retrodeck_cfg = retrodeck_conf_dir / "retrodeck.cfg"
    if _exists(retrodeck_json):
        rd_home = _parse_json_path(retrodeck_json, "paths", "rd_home_path")
        if not rd_home:
            # A home moved to an SD card lives only in this file: the
            # default is a guess, and the user is told so.
            note_detection(
                f"Warning: could not read paths.rd_home_path from "
                f"{retrodeck_json}: assuming {home / 'retrodeck'}",
            )
        rd_root = Path(rd_home) if rd_home else home / "retrodeck"
        MOVED.record(rd_root, retrodeck_json)
        found.append(("retrodeck", rd_root))
    elif _exists(retrodeck_cfg):
        rd_home = _parse_bash_var(retrodeck_cfg, "rdhome")
        found.append(("retrodeck", Path(rd_home) if rd_home else home / "retrodeck"))


def _detect_linux_retroarch(home: Path, found: list[tuple[str, Path]]) -> None:
    """Add RetroArch's Linux builds: Flatpak, Snap, native and AppImage."""
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

    # RetroArch native: the config under its base folder, then
    # ~/.retroarch.cfg when that one is missing (open_default_config_file
    # in configuration.c). Either way the system folder defaults to the
    # base folder's.
    native_base = _unix_retroarch_base()
    for native_cfg in (native_base / "retroarch.cfg", home / ".retroarch.cfg"):
        ra_dir = _parse_retroarch_system_dir(native_cfg, native_base)
        if ra_dir:
            found.append(("retroarch", ra_dir))
            break

    found.extend(("retroarch", ra_dir) for ra_dir in _retroarch_appimage_dirs(home))


def _detect_darwin_retroarch(found: list[tuple[str, Path]]) -> None:
    """Add RetroArch on macOS."""
    # open_default_config_file reads <Application Support>/RetroArch/config
    # (configuration.c). A value left at default is the documents folder,
    # or Application Support itself for a portable install
    # (platform_darwin.m). The config beside it is where older builds
    # kept it.
    support = Path.home() / "Library" / "Application Support" / "RetroArch"
    for mac_cfg in (support / "config" / "retroarch.cfg", support / "retroarch.cfg"):
        ra_dir = _parse_retroarch_system_dir(mac_cfg, _macos_retroarch_base())
        if ra_dir:
            found.append(("retroarch", ra_dir))
            break


def _detect_windows_retroarch(found: list[tuple[str, Path]]) -> None:
    """Add EmuDeck and RetroArch on Windows: installed, Steam, then UWP."""
    emudeck = _emudeck_windows_bios()
    if emudeck is not None:
        found.append(("emudeck", emudeck))

    # RetroArch Windows: open_default_config_file reads retroarch.cfg
    # beside the exe, then under %APPDATA%\RetroArch, and a value left at
    # default is <exe folder>\system (configuration.c, platform_win32.c).
    appdata = os.environ.get("APPDATA", "")
    appdata_cfg = Path(appdata) / "RetroArch" / "retroarch.cfg" if appdata else None
    exe_dirs = _windows_retroarch_dirs()
    for exe_dir in exe_dirs:
        ra_dir = _parse_retroarch_system_dir(exe_dir / "retroarch.cfg", exe_dir)
        if ra_dir is None and appdata_cfg is not None:
            ra_dir = _parse_retroarch_system_dir(appdata_cfg, exe_dir)
        found.append(("retroarch", ra_dir or exe_dir / "system"))
        break
    if not exe_dirs and appdata_cfg is not None:
        ra_dir = _parse_retroarch_system_dir(appdata_cfg)
        if ra_dir:
            found.append(("retroarch", ra_dir))

    # RetroArch from Steam: a portable install in a Steam library
    for library in _steam_libraries():
        steam_cfg = library / "steamapps" / "common" / "RetroArch" / "retroarch.cfg"
        ra_dir = _parse_retroarch_system_dir(steam_cfg)
        if ra_dir and not any(name == "retroarch" for name, _ in found):
            found.append(("retroarch", ra_dir))
            break

    # The UWP/MSIX package (sideloaded, or Xbox in dev mode)
    if not any(name == "retroarch" for name, _ in found):
        uwp = _retroarch_uwp_system_dir()
        if uwp is not None:
            found.append(("retroarch", uwp))


def _detect_windows_launchbox(os_type: str, found: list[tuple[str, Path]]) -> None:
    """Add RetroArch and BizHawk as LaunchBox references them."""
    # Portable RetroArch referenced by LaunchBox
    lb_root = launchbox_root(os_type)
    if lb_root and not any(name == "retroarch" for name, _ in found):
        system_dir = _launchbox_retroarch_system_dir(
            lb_root / "Data" / "Emulators.xml"
        )
        if system_dir:
            found.append(("retroarch", system_dir))
    # BizHawk is a portable archive reading <EmuHawk folder>\Firmware
    # (PathExtensions.cs DataDirectoryPath, PathEntryCollection "Firmware").
    if lb_root and not any(name == "bizhawk" for name, _ in found):
        emu_dir = launchbox_emulators(lb_root / "Data" / "Emulators.xml").get("emuhawk.exe")
        if emu_dir is not None:
            found.append(("bizhawk", emu_dir / "Firmware"))


def _without_unnameable(found: list[tuple[str, Path]]) -> list[tuple[str, Path]]:
    """found once each, less a folder named with a control character."""
    # An embedded system's config read again as the home folder's one (HOME is
    # /storage on the ELEC family) is the same folder.
    kept = []
    for name, path in dict.fromkeys(found):
        if _CONTROLS.search(str(path)):
            # A config naming a folder with a control character: printed,
            # the name is a terminal command, and the folder one nobody can
            # type. Its default is then no answer: the
            # setup reads the folder named.
            if name not in _UNNAMEABLE:
                _UNNAMEABLE.append(name)
            note_detection(f"  {display_name(name)}: the folder its configuration names "
                           f"holds a control character ({shown_path(path)}). Name its BIOS "
                           "folder with --dest.")
            continue
        kept.append((name, path))
    return kept


@_detection_guarded
def detect_platforms(os_type: str) -> list[tuple[str, Path]]:
    """Detect installed emulator platforms and their BIOS directories."""
    if not _CONFIGS_READ:
        _CONFIGS_READ.append(True)
    found: list[tuple[str, Path]] = []
    if os_type == "wsl":
        _note_windows_unasked()

    if os_type == "android":
        found.extend(_detect_android())
        for line in android_unreachable_folders():
            note_detection(line)

    if os_type in ("linux", "wsl"):
        found.extend(_detect_embedded())

    if os_type in ("linux", "wsl", "darwin"):
        _detect_emudeck_unix(found)

    if os_type in ("linux", "wsl"):
        home = Path.home()
        _detect_retrodeck(home, found)
        _detect_linux_retroarch(home, found)

    if os_type == "darwin":
        _detect_darwin_retroarch(found)

    if os_type in ("windows", "wsl"):
        _detect_windows_retroarch(found)
        _detect_windows_launchbox(os_type, found)

    if os_type in ("linux", "wsl", "darwin"):
        bizhawk = _bizhawk_unix_firmware()
        if bizhawk is not None and not any(name == "bizhawk" for name, _ in found):
            found.append(("bizhawk", bizhawk))

    _detect_by_executable(os_type, found)
    _detect_by_registry(os_type, found)
    _detect_by_path(os_type, found)
    return _without_unnameable(found)


def _emudeck_windows_bios() -> Path | None:
    """The BIOS folder of EmuDeck's Windows edition, as its scripts find it.

    functions/all.ps1:4-14 (emudeck-we 037460ef) loads
    %APPDATA%\\EmuDeck\\settings.ps1, else %USERPROFILE%\\EmuDeck\\settings.ps1,
    and takes C:\\Emulation when neither sets $emulationPath. A network
    install sets it through a drive mapped to $VolName in that session
    (JSONtoPS1.ps1:166-172), which is the share itself here.
    """
    candidates = [Path(os.environ[var]) / "EmuDeck" / "settings.ps1"
                  for var in ("APPDATA", "USERPROFILE") if os.environ.get(var)]
    settings = next((path for path in candidates if _is_file(path)), None)
    if settings is None:
        return None
    emu_path = _parse_ps1_var(settings, "$emulationPath")
    if emu_path and ("$" in emu_path or "+" in emu_path):
        share = _parse_ps1_var(settings, "$VolName")
        emu_path = f"{share.rstrip(chr(92))}\\Emulation" if share else None
    return _host_path(emu_path or "C:\\Emulation") / "bios"


# Identity Name in pkg/msvc-uwp/RetroArch-msvcUWP/Package.appxmanifest.
RETROARCH_UWP_ID = "1e4cf179-f3c2-404f-b9f3-cb2070a5aad8"


def _retroarch_uwp_system_dir() -> Path | None:
    """System directory of the RetroArch UWP package, if one is installed.

    The package writes into its LocalState folder: uwp_main.cpp makes it the
    home directory, configuration.c reads retroarch.cfg there, and
    platform_uwp.c defaults the system directory to ~\\system. A `~` in the
    config is therefore LocalState, not the user's profile.
    """
    local = os.environ.get("LOCALAPPDATA", "").strip()
    if not local:
        return None
    states = sorted(Path(local, "Packages").glob(f"{RETROARCH_UWP_ID}_*/LocalState"))
    if not states:
        return None
    state = states[0]
    return (_retroarch_cfg_dir(state / "retroarch.cfg", "system_directory", state, "system",
                               home=state)
            or state / "system")


def _bizhawk_unix_firmware() -> Path | None:
    """BizHawk's Firmware folder on Unix, where its data home says.

    PathExtensions.cs reads $BIZHAWK_DATA_HOME before the executable's
    folder, and the Nix package sets it to
    $XDG_DATA_HOME/emuhawk-monort-<version> (Dist/launch-scripts.nix).
    """
    data_home = os.environ.get("BIZHAWK_DATA_HOME", "").strip()
    if data_home and _is_dir(Path(data_home)):
        return Path(data_home) / "Firmware"
    xdg = os.environ.get("XDG_DATA_HOME", "").strip() or str(Path.home() / ".local" / "share")
    homes = sorted((home for home in Path(xdg).glob("emuhawk-monort-*") if _is_dir(home)),
                   key=lambda home: home.stat().st_mtime)
    return homes[-1] / "Firmware" if homes else None
