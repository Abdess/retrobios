"""Where each entry of a file list lands, kept under its BIOS folder, and how a path is shown."""
from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import NamedTuple

from installer.host_fs import _WSL
from installer.text import _CONTROLS, screen_text


def _path_characters(value: object, field: str, colons: bool = True) -> str:
    """The character rules every manifest-controlled relative path meets.

    No backslash, control character, empty segment, trailing slash or drive
    prefix, and at most 1024 characters: on Windows a backslash or a C:
    segment leaves the folder the path is joined to. A segment that Windows
    reads as a drive (C:x, any segment of one letter and a colon in front)
    or that ends with a colon is refused wherever it stands, since a later
    segment is joined as a drive-relative path. ``colons`` keeps a colon
    inside a name: RetroDECK's ares reads bios/snes:st018.data.rom on Linux.
    A Windows host refuses it all the same, as an alternate data stream of
    the file before the colon.
    """
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ValueError(f"invalid {field}")
    if (
        "\\" in value
        or _CONTROLS.search(value)
        or "//" in value
        or value.endswith("/")
        or re.match(r"^[A-Za-z]:", value)
    ):
        # A control character is refused with NUL: a pack's member named
        # x<ESC>]0;PWN<BEL>.bin set the window title in the progress line,
        # and the file was written under that name.
        raise ValueError(f"unsafe {field}: {value!r}")
    for part in value.split("/"):
        if ":" not in part:
            continue
        if (
            PureWindowsPath(part).drive or part.endswith(":")
            or not colons or os.name == "nt"
        ):
            raise ValueError(f"unsafe {field}: {value!r}")
    return value


def _safe_relative_path(value: object, field: str, colons: bool = True) -> PurePosixPath:
    """Validate a manifest-controlled relative POSIX path."""
    path = PurePosixPath(_path_characters(value, field, colons))
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"unsafe {field}: {value!r}")
    return path


# The most folders a roms root climbs from the BIOS folder: two, as the rom
# folders files of MinUI, NextUI, MyMinUI (../../Roms) and muOS (../../ROMS)
# record it (platforms/romfolders/*.yml, roms_root.from_bios).
MAX_ROMS_UPS = 2


def _roms_relation(value: object, field: str) -> tuple[int, PurePosixPath]:
    """A roms root relative to the BIOS folder: (folders up, names down).

    "." is the BIOS folder itself. Any other value climbs one to
    MAX_ROMS_UPS folders, then names plain folders: nothing climbs again
    once it went down, and nothing goes down without climbing first.
    """
    if value == ".":
        return 0, PurePosixPath()
    path = PurePosixPath(_path_characters(value, field, colons=False))
    parts = path.parts
    ups = next((i for i, part in enumerate(parts) if part != ".."), len(parts))
    names = parts[ups:]
    if (
        path.is_absolute() or not 1 <= ups <= MAX_ROMS_UPS
        or any(part in ("", ".", "..") for part in names)
    ):
        raise ValueError(f"unsafe {field}: {value!r}")
    return ups, PurePosixPath(*names)


# The roots a list places files below by their place relative to the BIOS
# folder: the roms root (ROCKNIX's /storage/roms) and the frontend's
# configs folder (Batocera's /userdata/system/configs).
RELATIVE_ROOTS = ("roms", "configs")


def _relative_root(bios_path: Path, from_bios: str, root: str = "roms") -> Path | None:
    """A relative root of a BIOS folder, on the host's own path type.

    The BIOS folder's ancestor at the depth the relation climbs, then the
    named folders below it. None when the joined and normalized path is
    anything else.
    """
    ups, names = _roms_relation(from_bios, f"{root}_directory.from_bios")
    if ups > len(bios_path.parents):
        return None
    ancestor = bios_path if not ups else bios_path.parents[ups - 1]
    expected = ancestor.joinpath(*names.parts)
    joined = Path(os.path.normpath(bios_path.joinpath(*PurePosixPath(from_bios).parts)))
    if joined != Path(os.path.normpath(expected)) or not _lexically_under(joined, ancestor):
        return None
    return expected


def _lexically_under(candidate: Path, root: Path) -> bool:
    """Whether a path built from checked parts stays below *root*."""
    try:
        Path(os.path.normpath(candidate)).relative_to(Path(os.path.normpath(root)))
    except ValueError:
        return False
    return True


def _within(candidate: Path, root: Path) -> bool:
    """Whether *candidate* stays under *root* once both are resolved."""
    try:
        (root / candidate.name).resolve().relative_to(root)
    except (OSError, ValueError):
        return False
    return True


def _safe_target_dir(value: object, field: str) -> str:
    """Validate a manifest-controlled standalone-copy directory.

    These name emulator install directories, so unlike a BIOS destination they
    are legitimately absolute and outside the BIOS tree. What they must never
    do is climb: a '..' anywhere turns "copy next to the emulator" into "write
    wherever the manifest likes".
    """
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError(f"invalid {field}")
    if _CONTROLS.search(value):
        raise ValueError(f"unsafe {field}: {value!r}")
    parts = re.split(r"[\\/]", value)
    if any(part == ".." for part in parts):
        raise ValueError(f"unsafe {field}: {value!r}")
    return value


# RetroDECK's settings folder below the home folder: retrodeck.json since the
# cfg-to-json migration, which renames the old retrodeck.cfg to retrodeck.bak
# (global.sh:149-153).
RETRODECK_CONFIG = Path(".var") / "app" / "net.retrodeck.retrodeck" / "config" / "retrodeck"


def _retrodeck_paths(retrodeck_json: Path) -> dict | None:
    """The paths table of retrodeck.json, None when it cannot be read."""
    try:
        paths = json.loads(retrodeck_json.read_text(encoding="utf-8", errors="replace"))["paths"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return paths if isinstance(paths, dict) else None


def _moved_in(root: Path, paths: dict) -> dict[str, Path]:
    """Each RetroDECK folder that is no longer <home>/<name>."""
    moved = {}
    for key, value in paths.items():
        name = key[:-len("_path")] if key.endswith("_path") else ""
        if name and name != "rd_home" and isinstance(value, str) and value.strip():
            place = Path(value.strip())
            if place != root / name:
                moved[name] = place
    return moved


class MovedFolders:
    """A platform whose folders move one by one: root -> {folder under the
    root: where it is now}.

    RetroDECK's per-folder move (RetroDECK 7786a849,
    functions/api_data_processing.sh:913-935) records each new place in
    retrodeck.json paths.<folder>_path (config/retrodeck/retrodeck.json:3-23),
    and its manifest places files under bios/ and roms/ of the home folder.
    A root is looked up on first use, so a run given --dest that never
    detects places files where a detecting run does; detection only fills
    the cache ahead.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_root: dict[Path, dict[str, Path]] = {}

    def reset(self) -> None:
        with self._lock:
            self._by_root.clear()

    def record(self, root: Path, retrodeck_json: Path) -> None:
        """root's moved folders, as retrodeck_json lists them."""
        paths = _retrodeck_paths(retrodeck_json)
        with self._lock:
            self._by_root[root] = _moved_in(root, paths) if paths is not None else {}

    def of(self, root: Path) -> dict[str, Path]:
        """root's moved folders: none unless root is RetroDECK's home folder."""
        with self._lock:
            known = self._by_root.get(root)
        if known is not None:
            return known
        moved = self._look_up(root)
        with self._lock:
            return self._by_root.setdefault(root, moved)

    @staticmethod
    def _look_up(root: Path) -> dict[str, Path]:
        home = Path.home()
        paths = _retrodeck_paths(home / RETRODECK_CONFIG / "retrodeck.json")
        if paths is None:
            return {}
        rd_home = paths.get("rd_home_path")
        rd_root = Path(rd_home) if isinstance(rd_home, str) and rd_home else home / "retrodeck"
        if os.path.abspath(rd_root) != os.path.abspath(root):
            return {}
        return _moved_in(root, paths)


MOVED = MovedFolders()


# Resolved folder -> the same folder as the run names it: /sdcard is a link
# to /storage/emulated/0 on Android, and one result named the BIOS folder
# /sdcard/RetroArch/system and its backup in /storage/emulated/0/RetroArch.
_SPELLED: dict[Path, Path] = {}


def _note_spelling(root: Path) -> Path:
    """root resolved, its own spelling recorded for every path shown below
    the link it goes through (spelled)."""
    given, resolved = Path(os.path.abspath(root)), root.resolve()
    named, real = given, resolved
    while named.name == real.name and named != named.parent and real != real.parent:
        named, real = named.parent, real.parent
    if named != real:
        try:
            if Path(os.path.realpath(named)) == real:
                _SPELLED[real] = named
        except (OSError, ValueError):
            pass
    return resolved


def spelled(path: Path | str) -> Path:
    """path in the form the run names its folders: below a link the BIOS
    folder was named through, the link's name (_note_spelling)."""
    path = Path(path)
    for real in sorted(_SPELLED, key=lambda each: len(each.parts), reverse=True):
        if path == real or real in path.parents:
            return _SPELLED[real] / path.relative_to(real)
    return path


def _destination_path(root: Path, value: object) -> Path:
    """Place a manifest destination below *root*.

    The manifest cannot climb: _safe_relative_path refuses absolute paths,
    drive letters and '..'. Symbolic links met under the root are the
    user's own layout and are followed. EmuDeck links bios/shadps4/sys_modules
    into shadPS4's data directory, and the file has to land where the
    emulator reads it.
    """
    relative = _safe_relative_path(value, "dest")
    moved = MOVED.of(root)
    if len(relative.parts) > 1 and relative.parts[0] in moved:
        return moved[relative.parts[0]].resolve() / Path(*relative.parts[1:])
    return _note_spelling(root) / Path(*relative.parts)


class SavePlace(NamedTuple):
    """The save directory a frontend's config names, whether it hands each
    core a folder of its own below it (RetroArch's sort_savefiles_enable,
    runloop.c runloop_path_set_redirect), and whether the file list's dests
    hold that folder (its save_directory.by_core)."""

    directory: Path
    by_core: bool
    listed_by_core: bool = True


# BIOS folder -> where the files read below its frontend's save directory go,
# set once the save directory is known (save_directory_for).
_SAVE_DIRS: dict[Path, SavePlace] = {}
# (BIOS folder, root) -> the platform's roms or configs folder, set by
# place_relative_entries.
_RELATIVE_DIRS: dict[tuple[Path, str], Path] = {}
# (BIOS folder, emulator key) -> the emulator folder, set by
# place_emulator_entries.
_EMULATOR_DIRS: dict[tuple[Path, str], Path] = {}


def _entry_place(root: Path, entry: dict) -> tuple[Path, object]:
    """The folder an entry's dest is relative to, and the dest.

    An entry with root: save is relative to the save directory the frontend
    hands the core, below the BIOS folder's frontend save directory and the
    core's own folder where the frontend sorts saves by core. Any other is
    relative to the BIOS folder.
    """
    if entry.get("root") in RELATIVE_ROOTS:
        folder = _RELATIVE_DIRS.get((root, entry["root"]))
        if folder is None:
            raise ValueError(f"no {entry['root']} folder known for {entry.get('dest')}")
        return folder, entry.get("dest")
    if entry.get("root") == "emulators":
        key, _, rest = str(entry.get("dest")).partition("/")
        folder = _EMULATOR_DIRS.get((root, key))
        if folder is None:
            raise ValueError(f"no emulator folder known for {entry.get('dest')}")
        return folder, rest
    if entry.get("root") != "save":
        return root, entry.get("dest")
    place = _SAVE_DIRS.get(root)
    if place is None:
        raise ValueError(f"no save directory known for {entry.get('dest')}")
    dest = entry.get("dest")
    folder = entry.get("core_folder")
    # No core_folder: the core reads the same place whether the frontend
    # sorts saves by core or not (an empty library_name, or Cemu adding its
    # own folder only where the directory is not named after it).
    if folder and isinstance(dest, str) and place.by_core != place.listed_by_core:
        if place.listed_by_core:
            dest = dest.split("/", 1)[1] if "/" in dest else dest
        else:
            dest = f"{folder}/{dest}"
    return place.directory, dest


def _entry_path(root: Path, entry: dict) -> Path:
    """Where an entry is written, as _entry_place places it."""
    return _destination_path(*_entry_place(root, entry))


def _entry_key(entry: dict) -> str:
    """What tells one entry of the list from another: its dest, below the
    BIOS folder, below the save directory or in an emulator's own folder.
    KNULLI lists its own fbneo/hiscore.dat in the BIOS tree and FB Alpha
    2012's below the save directory, two files under one dest. NUL never
    appears in a dest."""
    dest = str(entry.get("dest"))
    root = entry.get("root")
    if root == "emulator":
        # A path in one emulator's own folder: two emulators read two files.
        return f"emulator\0{','.join(entry.get('cores') or [])}\0{dest}"
    return f"{root}\0{dest}" if root in ("save", "emulators", *RELATIVE_ROOTS) else dest


def shown_path(path: Path | str) -> str:
    """A path as the person names it: under WSL, /mnt/d/BIOS is D:\\BIOS, the
    drive the card row calls D:."""
    text = str(spelled(path)) if os.path.isabs(str(path)) else str(path)
    root = _WSL["root"].rstrip("/") + "/"
    match = (re.match(rf"^{re.escape(root)}([a-z])(?:/(.*))?$", text)
             if _WSL["active"] else None)
    if match:
        text = f"{match.group(1).upper()}:\\" + (match.group(2) or "").replace("/", "\\")
    # A folder's name comes from whoever named it: a card's label, a
    # retroarch.cfg, a pack. Printed raw, a control character in it is a
    # terminal command.
    return screen_text(text)
