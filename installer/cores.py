"""Libretro cores installed, their info files, and the names people type for platforms and systems."""
from __future__ import annotations

import errno
import os
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import NoReturn

from installer.constants import AVAILABLE_PLATFORMS
from installer.detect_os import _NO_FOLDER, _retroarch_cfg_dir
from installer.embedded import _EMBEDDED_RULES, _name_key, display_name, shown_path
from installer.events import EVENTS
from installer.local_files import _retroarch_config_for
from installer.probe import _exists, _is_dir, _is_file

# A libretro core as RetroArch loads it: <name>_libretro.so|dll|dylib, and
# <name>_libretro_android.so on Android.
_CORE_FILE_RE = re.compile(
    r"^(?P<name>.+?)_libretro(?:_android)?\.(?:so|dll|dylib)$", re.IGNORECASE
)
CORE_PLATFORMS = ("retroarch", "lakka", "retropie")
# Where these systems install cores whatever retroarch.cfg says: RetroPie
# gives each package its own folder, Lakka keeps the image's cores and the
# ones the online updater fetches apart.
_FIXED_CORE_DIRS = {
    "retropie": (Path("/opt/retropie/libretrocores"),),
    "lakka": (Path("/usr/lib/libretro"), Path("/storage/cores"), Path("/tmp/cores")),
}


def core_dirs(plat: str, bios_path: Path) -> list[Path]:
    """The directories the RetroArch writing to bios_path loads cores from.

    The config detection read for this system directory names them in
    libretro_directory, read here when the run was given --dest, as the
    interface's runs all are. Without one, a retroarch.cfg beside the system
    directory is the portable layout. Unset, the setting is cores/ under
    RetroArch's own directory.
    """
    found = _retroarch_config_for(bios_path)
    if found is None and _is_file(bios_path.parent / "retroarch.cfg"):
        found = (bios_path.parent / "retroarch.cfg", bios_path.parent)
    dirs: list[Path] = []
    if found is not None:
        cfg, app_dir = found
        dirs.append(
            _retroarch_cfg_dir(cfg, "libretro_directory", app_dir, "cores")
            or app_dir / "cores"
        )
    dirs.extend(_FIXED_CORE_DIRS.get(plat, ()))
    return list(dict.fromkeys(dirs))


def keeps_case(directory: Path) -> bool:
    """Whether names differing only by case are distinct files there.

    Probed on the nearest existing directory, since the filesystem decides,
    not the operating system: an ext4 drive mounted on macOS keeps case and
    a casefolded ext4 directory folds it. Unprobeable: the system's default.
    """
    probe_dir = directory
    while not _is_dir(probe_dir) and probe_dir != probe_dir.parent:
        probe_dir = probe_dir.parent
    try:
        handle, name = tempfile.mkstemp(prefix=".retrobios-case-", dir=str(probe_dir))
    except OSError:
        return sys.platform not in ("win32", "darwin")
    os.close(handle)
    try:
        twin = os.path.join(os.path.dirname(name), os.path.basename(name).upper())
        return not os.path.exists(twin)
    finally:
        os.unlink(name)


def fold_case_twins(files: list[dict]) -> tuple[list[dict], list[str]]:
    """One file per name where the directory folds case, the others named.

    The first in manifest order stays, as the pack's own order places it.
    """
    kept: list[dict] = []
    seen: set[str] = set()
    folded: list[str] = []
    for entry in files:
        key = str(entry.get("dest", "")).casefold()
        if key in seen:
            folded.append(str(entry.get("dest", "")))
            continue
        seen.add(key)
        kept.append(entry)
    return kept, folded


# The characters FAT and exFAT refuse in a name, as Windows does on any drive
# (Linux 7475ea8b, fs/fat/namei_vfat.c:201-207 and fs/exfat/nls.c:396-403;
# "Naming Files, Paths, and Namespaces" in the Win32 documentation). The
# slash, the backslash and the controls never reach a destination
# (_safe_relative_path). RetroDECK names three files zxs:48.rom,
# zxs:if1-2.rom and snes:st018.data.rom (its retroarch component manifest):
# on an exFAT card each write failed, on every run.
FAT_REFUSED = re.compile(r'[<>:"|?*]')
FAT_REFUSED_SHOWN = '< > : " | ? *'


def holds_fat_refused_names(directory: Path) -> bool:
    """Whether a name holding a colon can be created there.

    Probed on the nearest existing directory, as keeps_case is: an ext4
    card on a Steam Deck holds one, an exFAT card refuses it with EINVAL.
    Windows refuses it on every drive. A probe refused for another cause
    (a folder this user cannot write) decides nothing.
    """
    if os.name == "nt":
        return False
    probe_dir = directory
    while not _is_dir(probe_dir) and probe_dir != probe_dir.parent:
        probe_dir = probe_dir.parent
    try:
        handle, name = tempfile.mkstemp(prefix=".retrobios-name-", suffix=":",
                                        dir=str(probe_dir))
    except OSError as exc:
        return exc.errno != errno.EINVAL
    os.close(handle)
    os.unlink(name)
    return True


def split_fat_refused(files: list[dict]) -> tuple[list[dict], list[str]]:
    """The entries whose destination a FAT, exFAT or Windows folder can
    hold, and the destinations it cannot."""
    kept = [entry for entry in files if not FAT_REFUSED.search(str(entry.get("dest", "")))]
    refused = [str(entry.get("dest", "")) for entry in files
               if FAT_REFUSED.search(str(entry.get("dest", "")))]
    return kept, refused


# Android's media scanner marks a folder holding a .nomedia file hidden, and
# every folder below it (MediaProvider a183e2b9, FileUtils.java:1587-1629
# isDirectoryHidden, ModernMediaScanner.java:845-846 and 1017-1020). Without
# one, the samples, overlays and videos of a BIOS folder in shared storage
# showed in the phone's gallery and music apps. RetroArch writes none
# (libretro-common/file/file_path_io.c:194 only skips one).
NOMEDIA = ".nomedia"


def hide_from_media_scanner(folder: Path) -> bool:
    """Leave an empty .nomedia in folder, True when this call wrote it."""
    marker = folder / NOMEDIA
    if not _is_dir(folder) or _exists(marker):
        return False
    try:
        marker.touch()
    except OSError as exc:
        print(f"  {NOMEDIA} not written in {shown_path(folder)}: {exc.strerror}",
              file=sys.stderr)
        return False
    return True


def installed_cores(dirs: list[Path]) -> list[str]:
    """The cores present in these directories, by the name the buildbot uses.

    A folder inside is looked into once, which is how RetroPie installs
    each package. An unreadable directory holds nothing that can be seen.
    """
    names: set[str] = set()
    for directory in dirs:
        try:
            children = list(directory.iterdir())
        except OSError:
            continue
        for child in children:
            candidates = [child]
            if child.is_dir():
                try:
                    candidates = list(child.iterdir())
                except OSError:
                    continue
            for path in candidates:
                match = _CORE_FILE_RE.match(path.name)
                if match and path.is_file():
                    names.add(match.group("name"))
    return sorted(names)


def info_dirs(plat: str, bios_path: Path, searched: list[Path]) -> list[Path]:
    """The directories RetroArch reads core .info files from.

    libretro_info_path in retroarch.cfg, info/ beside RetroArch by default,
    then the cores folders: Linux builds and Lakka keep each .info beside
    its core.
    """
    found = _retroarch_config_for(bios_path)
    if found is None and _is_file(bios_path.parent / "retroarch.cfg"):
        found = (bios_path.parent / "retroarch.cfg", bios_path.parent)
    dirs: list[Path] = []
    if found is not None:
        cfg, app_dir = found
        dirs.append(_retroarch_cfg_dir(cfg, "libretro_info_path", app_dir, "info")
                    or app_dir / "info")
    dirs.extend(searched)
    return list(dict.fromkeys(dirs))


_INFO_FIRMWARE_RE = re.compile(r'^\s*firmware\d+_path\s*=\s*"?([^"\r\n]*?)"?\s*$')


def info_firmware(dirs: list[Path], core: str) -> list[str] | None:
    """The firmware paths a core's .info declares, None without a .info.

    RetroArch reads firmware<N>_path, relative to the system directory
    (core_info.c), and so does this.
    """
    for directory in dirs:
        info = directory / f"{core}_libretro.info"
        try:
            text = info.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        paths = (m.group(1).strip().replace("\\", "/")
                 for m in map(_INFO_FIRMWARE_RE.match, text.splitlines()) if m)
        return list(dict.fromkeys(p for p in paths if p))
    return None


def known_core_names(manifest: dict) -> set[str]:
    """Every core name a file list answers for: profiles and their other names."""
    names: set[str] = set()
    for profile, aliases in (manifest.get("core_names") or {}).items():
        names.add(profile)
        names.update(aliases)
    for cores in (manifest.get("system_cores") or {}).values():
        names.update(cores)
    for entry in [*manifest.get("files", []), *manifest.get("omitted_files", [])]:
        names.update(entry.get("cores") or [])
        for alternative in entry.get("alternatives", []):
            names.update(alternative.get("cores") or [])
    return names


def unknown_cores(manifest: dict, names: list[str]) -> list[str]:
    """The installed cores the file list has no profile for, in name order."""
    known = known_core_names(manifest)
    return sorted(name for name in names if name not in known)


# A list this short is printed whole rather than pointed at.
SHORT_LIST = 12


# Names people type for a system, each with its id. Only ever suggested:
# --system gba, psx and ps1 were refused with no hint on RetroArch, whose
# list names no system that way, and taking one in silence could install
# another console than the one meant.
SYSTEM_SHORT_NAMES = {
    **dict.fromkeys(("psx", "ps1", "ps", "playstation1"), "sony-playstation"),
    "ps2": "sony-playstation-2", "ps3": "sony-playstation-3", "psp": "sony-psp",
    **dict.fromkeys(("vita", "psvita"), "sony-playstation-vita"),
    "gb": "nintendo-gb", "gbc": "nintendo-gbc", "gba": "nintendo-gba",
    **dict.fromkeys(("nes", "famicom", "fc"), "nintendo-nes"), "fds": "nintendo-fds",
    **dict.fromkeys(("snes", "sfc", "superfamicom"), "nintendo-snes"),
    "n64": "nintendo-64", "n64dd": "nintendo-64dd", "sgb": "nintendo-sgb",
    **dict.fromkeys(("nds", "ds"), "nintendo-ds"), "dsi": "nintendo-dsi",
    "3ds": "nintendo-3ds", "wiiu": "nintendo-wii-u", "switch": "nintendo-switch",
    **dict.fromkeys(("gc", "ngc", "gcn", "gamecube"), "nintendo-gamecube"),
    "pokemini": "nintendo-pokemon-mini",
    **dict.fromkeys(("md", "gen", "genesis", "megadrive"), "sega-mega-drive"),
    **dict.fromkeys(("scd", "segacd", "megacd"), "sega-mega-cd"),
    "32x": "sega-32x", **dict.fromkeys(("sms", "mastersystem"), "sega-master-system"),
    **dict.fromkeys(("gg", "gamegear"), "sega-game-gear"),
    **dict.fromkeys(("ss", "saturn"), "sega-saturn"),
    **dict.fromkeys(("dc", "dreamcast"), "sega-dreamcast"),
    **dict.fromkeys(("naomi", "atomiswave"), "sega-dreamcast-arcade"),
    **dict.fromkeys(("pce", "tg16", "turbografx", "turbografx16", "pcengine",
                     "supergrafx"), "nec-pc-engine"),
    **dict.fromkeys(("pcecd", "tgcd", "turbografxcd"), "nec-pc-engine-cd"),
    "pcfx": "nec-pc-fx",
    **dict.fromkeys(("neogeo", "mvs", "aes"), "snk-neogeo"),
    **dict.fromkeys(("neocd", "neogeocd"), "snk-neogeo-cd"),
    **dict.fromkeys(("msx", "msx2"), "microsoft-msx"),
    "c64": "commodore-c64", "c128": "commodore-c128",
    **dict.fromkeys(("amiga", "cd32"), "commodore-amiga"),
    "x68k": "sharp-x68000", **dict.fromkeys(("jag", "jaguar"), "atari-jaguar"),
    **dict.fromkeys(("st", "atarist"), "atari-st"), "a800": "atari-400-800",
    **dict.fromkeys(("coleco", "colecovision"), "coleco-colecovision"),
    **dict.fromkeys(("intv", "intellivision"), "mattel-intellivision"),
    "o2": "magnavox-odyssey2", "channelf": "fairchild-channel-f",
    **dict.fromkeys(("zx", "spectrum", "zxspectrum"), "sinclair-zx-spectrum"),
    "cpc": "amstrad-cpc", "bbc": "acorn-bbc-micro", "apple2": "apple-ii",
}

# A system some lists file under another id, by the file that stands for it.
# The Neo Geo card offers --system snk-neogeo, and RetroArch's list keeps
# neogeo.zip under arcade: the run suggests arcade, never takes it.
SYSTEM_KEY_FILES = {"snk-neogeo": "neogeo.zip"}


def key_file_holders(files: list[dict], omitted: list[dict]) -> dict[str, list[str]]:
    """The systems a list files each SYSTEM_KEY_FILES file under, for the
    systems the list does not name itself."""
    entries = files + omitted
    known = {system for entry in entries for system in entry_systems(entry)}
    holders: dict[str, list[str]] = {}
    for system, name in SYSTEM_KEY_FILES.items():
        if system in known:
            continue
        held = sorted({
            holder for entry in entries
            if PurePosixPath(str(entry.get("dest", ""))).name.lower() == name
            for holder in entry_systems(entry)
        })
        if held:
            holders[system] = held
    return holders


def did_you_mean(
    typed: list[str], known: list[str], listing: str,
    aliases: dict[str, str] | None = None, inside_from: int = 4,
    meant: dict[str, list[str]] | None = None,
) -> str:
    """The closest known names to what was typed, and the option listing them all.

    A typo was answered with every name the platform has, up to 400 on one
    line, with no hint that playstation is sony-playstation. An alias close
    to what was typed suggests the name it stands for. A name holding what
    was typed, inside_from letters or more, is suggested too. meant gives,
    by the letters and digits of a typed name, the names it stands for
    here, suggested instead of the close ones.
    """
    import difflib

    by_key: dict[str, str] = {}
    for name in known:
        by_key.setdefault(_name_key(name), name)
    for alias, name in (aliases or {}).items():
        by_key.setdefault(_name_key(alias), name)
    close: list[str] = []
    for word in typed:
        key = _name_key(word)
        if not key:
            continue
        if meant and key in meant:
            close += [name for name in meant[key] if name not in close]
            continue
        matches = difflib.get_close_matches(key, list(by_key), n=3, cutoff=0.6)
        if len(key) >= inside_from:
            matches += sorted(k for k in by_key if key in k and k not in matches)
        for k in matches:
            # Two aliases of one system (psx, ps1) name it once.
            if by_key[k] not in close:
                close.append(by_key[k])
    if close:
        return f"Close matches: {', '.join(close[:3])}. {listing} lists all {len(known)}."
    if len(known) <= SHORT_LIST:
        return f"Known: {', '.join(known)}."
    return f"{listing} lists all {len(known)}."


def refuse_name(platform: str, *lines: str) -> NoReturn:
    """End the run on a name it cannot use (a platform, target, system, core
    or emulator), refused before any download.

    The reason went to stderr only: a reader of --events got start, then
    end with code 1, and could not tell a typo from a failed download. Code
    2, as for an option argparse refuses: 1 also means --check found files
    to fetch, and a script reading it reran the install on a typo forever.
    """
    message = " ".join(line.strip() for line in lines)
    if message.startswith("Error: "):
        message = message[len("Error: "):]
    EVENTS.emit("error", stage="option", reason="unknown", platform=platform,
                message=message)
    for line in lines:
        print(line, file=sys.stderr)
    sys.exit(2)


# Frontends and systems that keep no BIOS folder of their own: each
# emulator they start reads its own, which a run without --platform finds.
# --platform es-de was "Unknown platform", the answer left unsaid.
_NO_BIOS_FOLDER = ("ES-DE", "LaunchBox", "Android")


def normalize_platform(name: str, say: bool = True) -> str:
    """Return the canonical platform id for user-supplied input.

    The site writes MiSTer FPGA and RetroArch: letters and digits decide,
    as they do for verify.py and generate_pack.py. say is False where the
    name is read again later, which says it once.
    """
    key = _name_key(name)
    for plat in AVAILABLE_PLATFORMS:
        if key and key in (_name_key(plat), _name_key(display_name(plat))):
            return plat
    # --list-platforms prints `muOS: retroarch`, and --platform muos was
    # refused: a system named there stands for the list it gets.
    for rule in _EMBEDDED_RULES:
        if key and rule.manifest and key == _name_key(rule.name):
            if say:
                print(f"  {rule.name} gets the {display_name(rule.manifest)} file list: "
                      f"--platform {rule.manifest}.")
            return rule.manifest
    for frontend in _NO_BIOS_FOLDER:
        if key and key == _name_key(frontend):
            refuse_name(name.strip(), f"{frontend} has no BIOS folder of its own: run again "
                        "without --platform, and the installer fills the folder of each "
                        "emulator it finds here.")
    # --list-platforms prints TrimUI with why it gets no folder, and naming
    # it answered "Unknown platform".
    for rule in _EMBEDDED_RULES:
        if key and not rule.manifest and key == _name_key(rule.name):
            refuse_name(name.strip(), f"{rule.name} is not installed to: "
                        f"{_NO_FOLDER.get(rule.name, 'no source names its BIOS folder')}.",
                        "  Name that folder: --platform retroarch "
                        "--dest FOLDER")
    # Every name --list-platforms prints, so that spruce suggests spruceOS
    # and the count is the one the listing shows.
    known = list(AVAILABLE_PLATFORMS) + list(dict.fromkeys(
        rule.name for rule in _EMBEDDED_RULES
        if _name_key(rule.name) not in {_name_key(plat) for plat in AVAILABLE_PLATFORMS}
    )) + list(_NO_BIOS_FOLDER)
    refuse_name(name.strip(), f"Unknown platform '{name.strip()}'. "
                + did_you_mean([name], known, "--list-platforms"))


def entry_systems(entry: dict) -> list[str]:
    """The platform systems a file or an omission belongs to.

    An omission's `system` is spelled the way its profile spells it. Only
    `systems` names the platform's own, the ones --system accepts.
    """
    return list(entry.get("systems") or [])
