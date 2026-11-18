"""Libretro cores installed here, the firmware their info files declare, and --cores-dir."""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from installer.config_values import _retroarch_cfg_dir
from installer.events import EVENTS
from installer.frontend_folders import _retroarch_config_for
from installer.host_fs import _is_file, closed_folder
from installer.invocation import _INVOCATION
from installer.local_check import closed_folder_words
from installer.platforms import display_name
from installer.text import _plural, screen_text

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


def _check_cores_dir(folder: Path) -> None:
    """Refuse a --cores-dir that cannot be listed, saying why: a typo
    (core/ for cores/) or a closed folder read as an empty one, and the
    run said "none in" and asked for the --cores-dir it was given."""
    try:
        with os.scandir(folder):
            return
    except FileNotFoundError:
        why = "does not exist"
    except NotADirectoryError:
        why = "is not a folder"
    except PermissionError as exc:
        closed = closed_folder(folder)
        why = (f"cannot be opened by this user ({exc.strerror or exc})"
               if closed is None or closed[0] == folder
               else f"cannot be opened: {closed_folder_words(folder, closed)}")
    except OSError as exc:
        why = f"could not be read ({exc.strerror or exc})"
    print(f"Error: --cores-dir {screen_text(str(folder))} {why}.", file=sys.stderr)
    print("  Name the folder RetroArch loads cores from (libretro_directory in "
          "retroarch.cfg, cores/ beside RetroArch by default).", file=sys.stderr)
    sys.exit(1)


def _unprofiled_cores_firmware(
    plat: str, bios_path: Path, manifest: dict, found: list[str], searched: list[Path],
) -> list[str]:
    """What the installed cores the list has no profile for declare, each said.

    Such a core reads systems the list cannot name, and narrowing to the
    installed cores dropped its BIOS without a word (issue 87, parallel_dc
    before its profile). Its .info is what RetroArch itself checks, so the
    files it declares are kept. A core without one is named.
    """
    unknown = unknown_cores(manifest, found)
    if not unknown:
        return []
    dirs = info_dirs(plat, bios_path, searched)
    dests: list[str] = []
    for core in unknown:
        declared = info_firmware(dirs, core)
        if declared is None:
            message = (f"{core}: a core this list does not know, with no .info to read: "
                       "its files may be missing. Run without --installed-cores "
                       "to install every file.")
        else:
            message = (f"{core}: a core this list does not know, "
                       f"{_plural(len(declared), 'file')} its .info declares kept")
        print(f"  {message}")
        EVENTS.emit("unknown_core", platform=plat, core=core,
                    info=declared is not None, dests=declared or [], message=message)
        dests.extend(declared or [])
    return dests


def _no_core_found(plat: str, bios_path: Path, searched: list[Path]) -> None:
    """Refuse --installed-cores with no core, and say how to point at them.

    With no retroarch.cfg naming the folder as its system_directory, and
    none beside it, nothing names the cores folder: the run stopped on "no
    known directory" with no way forward.
    """
    where = (f"none in {', '.join(map(str, searched))}" if searched
             else f"no retroarch.cfg was found for {bios_path} to name their folder")
    print(f"Error: no installed core found for {display_name(plat)}: {where}.",
          file=sys.stderr)
    print("  Name the folder RetroArch loads cores from (libretro_directory in "
          "retroarch.cfg, cores/ beside RetroArch by default):", file=sys.stderr)
    command = _INVOCATION.command(plat, bios_path, without=("--installed-cores", "--cores-dir"))
    print(f"    {command} --cores-dir <cores folder>", file=sys.stderr)
    print("  Or run it without --installed-cores to install every file.", file=sys.stderr)
    sys.exit(1)
