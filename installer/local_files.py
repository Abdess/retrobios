"""Digests of the files in place, the RetroArch configuration and where saves go."""
from __future__ import annotations

import concurrent.futures
import contextlib
import errno
import hashlib
import io
import os
import re
import stat
import sys
import time
from pathlib import Path, PurePosixPath
from typing import IO

from installer.detect_frontends import _android_cfg_value, detect_platforms
from installer.detect_os import _RETROARCH_CONFIGS, _retroarch_cfg_dir, detect_os
from installer.embedded import shown_path
from installer.events import EVENTS
from installer.invocation import _INVOCATION
from installer.paths import (
    RELATIVE_ROOTS,
    _EMULATOR_DIRS,
    _RELATIVE_DIRS,
    _SAVE_DIRS,
    SavePlace,
    _entry_path,
    _lexically_under,
    _note_spelling,
    _relative_root,
    _safe_relative_path,
    spelled,
)
from installer.probe import _SETUP_SEARCH, _held, _is_dir
from installer.terminal import EVENT_PROGRESS_INTERVAL, Terminal, detail
from installer.text import _plural


def _digest_file(path: Path, algorithms: tuple[str, ...]) -> dict[str, str]:
    """Compute several digests of a file in a single read.

    Checking a 3 GB collection against both a SHA-1 and a SHA-256 used to walk
    every file twice, single threaded. Hashing is cheap next to the I/O, so
    the read is what has to happen once.
    """
    with open(path, "rb") as fh:
        return _digest_handle(fh, algorithms)


def _digest_handle(fh: IO[bytes], algorithms: tuple[str, ...]) -> dict[str, str]:
    """Digests of an open file, read from its start."""
    hashers = {name: hashlib.new(name) for name in algorithms}
    fh.seek(0)
    for chunk in iter(lambda: fh.read(1024 * 1024), b""):
        for hasher in hashers.values():
            hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def _sha1_file(path: Path) -> str:
    """Compute SHA1 of a file."""
    return _digest_file(path, ("sha1",))["sha1"]


def _sha256_file(path: Path) -> str:
    """Compute SHA256 of a file."""
    return _digest_file(path, ("sha256",))["sha256"]


def _cfg_true(value: str | None) -> bool:
    return (value or "").strip().lower() == "true"


_CONFIGS_READ: list[bool] = []


def _retroarch_config_for(bios_path: Path) -> tuple[Path, Path] | None:
    """The retroarch.cfg whose system_directory is bios_path, and the
    folder ':' expands to there.

    A run given --dest detects nothing, so the configs are read here, once
    and silently, the first time a save directory or the cores folder is
    asked for: the interface names every folder with --dest, and its runs
    sent Azahar's keys.txt to a guessed folder where line mode read
    savefile_directory, and found no core where line mode found them.
    """
    found = _retroarch_config_at(bios_path)
    if found is not None or _CONFIGS_READ:
        return found
    _CONFIGS_READ.append(True)
    # Silent, the unsearched event too: this run searched for no setup, and
    # the event came after detect, the line it stands for never shown.
    _SETUP_SEARCH.quiet = True
    try:
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            detect_platforms(_INVOCATION.os_type or detect_os())
    finally:
        _SETUP_SEARCH.quiet = False
    return _retroarch_config_at(bios_path)


def _folder_key(path: Path) -> str:
    """The folder as the system names it: absolute, links followed, and
    case folded where the system's default filesystem folds it."""
    real = os.path.realpath(path)
    return real.casefold() if sys.platform in ("win32", "darwin") else real


def _retroarch_config_at(bios_path: Path) -> tuple[Path, Path] | None:
    """The config detection read for bios_path, however the folder is
    written: --dest relative, through a link, or in another case. The
    configs are keyed by the folder as each retroarch.cfg writes it."""
    found = _RETROARCH_CONFIGS.get(bios_path)
    if found is not None or not _RETROARCH_CONFIGS:
        return found
    wanted = _folder_key(bios_path)
    for system_dir, config in _RETROARCH_CONFIGS.items():
        if _folder_key(system_dir) == wanted:
            return config
    # A drive whose filesystem folds case where the system's default does
    # not (or the reverse): the filesystem answers for folders that exist.
    for system_dir, config in _RETROARCH_CONFIGS.items():
        try:
            if os.path.samefile(system_dir, bios_path):
                return config
        except (OSError, ValueError):
            continue
    return None


def save_directory_for(
    bios_path: Path, manifest: dict, override: Path | None = None,
) -> SavePlace | str:
    """The save directory the platform's frontend hands its cores, or why
    this run cannot tell.

    A RetroArch found by its retroarch.cfg answers from it: savefile_directory
    as RetroArch expands it, a value left at default or naming no folder
    being saves/ beside the config (configuration.c config_load_file keeps
    the default unless path_is_directory), and sort_savefiles_enable, true by
    default (config.def.h:1099). savefiles_in_content_dir and
    sort_savefiles_by_content_enable put the directory beside each game: no
    single place then. Without a config, the BIOS folder standing at its
    default name puts the save directory beside it, as the pack lays them out,
    and a list whose dests start above the BIOS folder (RetroDECK) puts it
    in the folder the run installs to. ``override`` (--save-dir) names the directory itself. A launcher that
    writes the save directory at each launch, one folder per system
    (by_system: Batocera, RetroBat), is not read from any retroarch.cfg:
    the one on disk holds the last launch's system.
    """
    layout = manifest.get("save_directory")
    if not layout:
        return "the file list names no save directory for this platform"
    folder = layout["folder"]
    listed = bool(layout["by_core"])
    by_core = listed
    found = None if layout.get("by_system") else _retroarch_config_for(bios_path)
    if found is not None:
        cfg_path, app_dir = found
        for key in ("savefiles_in_content_dir", "sort_savefiles_by_content_enable"):
            if _cfg_true(_android_cfg_value(cfg_path, key)):
                return (f"RetroArch keeps saves beside each game ({key} in {cfg_path}): "
                        "name the folder with --save-dir")
        sort = _android_cfg_value(cfg_path, "sort_savefiles_enable")
        if sort is not None:
            by_core = _cfg_true(sort)
        if override is not None:
            return SavePlace(override, by_core, listed)
        directory = _retroarch_cfg_dir(cfg_path, "savefile_directory", app_dir, folder)
        if directory is None or not _is_dir(directory):
            directory = app_dir / folder
        return SavePlace(directory, by_core, listed)
    if override is not None:
        return SavePlace(override, by_core, listed)
    base = manifest.get("base_destination") or ""
    if base and bios_path.name == base:
        return SavePlace(bios_path.parent / folder, by_core, listed)
    if not base:
        # The dests start below the folder holding the BIOS folder
        # (RetroDECK's ~/retrodeck holds bios/ and saves/).
        return SavePlace(bios_path / folder, by_core, listed)
    # The wording of the run's end, said before the menu too: two wordings
    # of one fact in one run, the first printing /mnt/e under WSL.
    return "its place is not known. Name it with --save-dir"


def place_save_entries(
    files: list[dict], bios_path: Path, manifest: dict, override: Path | None,
    display: str, say: bool = True,
) -> tuple[list[dict], list[dict]]:
    """Find the save directory for the entries read below it.

    Returns the files to install and, when the save directory is unknown,
    the entries left out as omissions, said once with the reason. Without
    say nothing is printed or sent: the run says it (say_saves) once a
    choice of systems has kept the files it counts.
    """
    saved = [entry for entry in files if entry.get("root") == "save"]
    if not saved:
        return files, []
    place = save_directory_for(bios_path, manifest, override)
    if isinstance(place, SavePlace):
        _SAVE_DIRS[bios_path] = place
        # Named through the link the BIOS folder was named through.
        _note_spelling(bios_path)
        where = str(spelled(place.directory))
        if (manifest.get("save_directory") or {}).get("by_system"):
            where += f"{os.sep}<system>"
        if place.by_core:
            where += f"{os.sep}<core>"
        _SAVE_WHERE[bios_path] = where
        if say:
            print(f"  {saves_line(display, len(saved), where)}")
            EVENTS.emit("saves", platform=str(manifest.get("platform", "")),
                        files=len(saved), folder=where)
        return files, []
    _SAVE_WHY[bios_path] = place
    if say:
        print(f"  {_plural(len(saved), 'file')} read from {display}'s save directory "
              f"left out: {place}.")
    kept = [entry for entry in files if entry.get("root") != "save"]
    unplaced = [
        {"dest": entry["dest"], "name": PurePosixPath(entry["dest"]).name,
         "system": "", "systems": list(entry.get("systems") or []), "required": False,
         "reason": "no_save_directory", "frontend": display,
         "cores": entry.get("cores"), "root": "save",
         **({"core_folder": entry["core_folder"]} if entry.get("core_folder") else {})}
        for entry in saved
    ]
    return kept, unplaced


def place_relative_entries(
    files: list[dict], bios_path: Path, manifest: dict, display: str, say: bool = True,
) -> tuple[list[dict], list[dict]]:
    """Find the roms and configs folders for the entries read below them.

    The list gives each root relative to the BIOS folder, as the OS's own
    source places them (ROCKNIX's /storage/roms holds bios/, Batocera's
    configs folder is ../system/configs): a BIOS folder of the platform's
    name puts the root there. Any other is a folder this run cannot relate
    to the root, and the entries are left out with the reason.
    """
    unplaced: list[dict] = []
    for root in RELATIVE_ROOTS:
        below = [entry for entry in files if entry.get("root") == root]
        if not below:
            continue
        layout = manifest.get(f"{root}_directory") or {}
        folder = (
            _relative_root(bios_path, layout["from_bios"], root)
            if layout and bios_path.name == layout.get("bios_folder") else None
        )
        if folder is not None:
            _RELATIVE_DIRS[(bios_path, root)] = folder
            continue
        if say:
            print(f"  {_plural(len(below), 'file')} read from {display}'s {root} folder left "
                  f"out: {bios_path} is not its {layout.get('bios_folder') or 'BIOS'} folder.")
        files = [entry for entry in files if entry.get("root") != root]
        unplaced += [
            {"dest": entry["dest"], "name": PurePosixPath(entry["dest"]).name,
             "system": "", "systems": list(entry.get("systems") or []), "required": False,
             "reason": f"no_{root}_directory", "cores": entry.get("cores"), "root": root}
            for entry in below
        ]
    return files, unplaced


def _config_keys(path: Path) -> set[str]:
    """The keys an emulatorLauncher-style key=value file sets, lowercased."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    return {
        line.split("=", 1)[0].strip().lower()
        for line in text.splitlines() if "=" in line and line.split("=", 1)[1].strip()
    }


def place_emulator_entries(
    files: list[dict], bios_path: Path, manifest: dict, display: str, say: bool = True,
) -> tuple[list[dict], list[dict]]:
    """Find the emulator folder each entry a launcher runs from one goes to.

    The platform keeps its BIOS folder beside its own folder holding the
    launcher config (RetroBat's bios beside emulationstation): a BIOS
    folder of that name whose parent holds the config is the platform's.
    A key the config sets moves the folder somewhere this run does not
    follow, so its files are left out. Otherwise the folder is the first of
    the searched places that exists, the default one when none does, as the
    launcher searches them.
    """
    inside = [entry for entry in files if entry.get("root") == "emulators"]
    if not inside:
        return files, []
    layout = manifest.get("emulators_directory") or {}
    home = bios_path.parent
    config = (
        home.joinpath(*_safe_relative_path(
            layout["config"], "emulators_directory.config", colons=False).parts)
        if layout else None
    )
    if config is not None and bios_path.name == layout.get("bios_folder") and config.is_file():
        moved = _config_keys(config)
        matches = True
    else:
        moved, matches = set(), False
    kept: list[dict] = []
    unplaced: list[dict] = []
    for entry in files:
        if entry.get("root") != "emulators":
            kept.append(entry)
            continue
        key = _safe_relative_path(str(entry["dest"]), "emulators dest", colons=False).parts[0]
        places = [
            home.joinpath(*_safe_relative_path(
                t.replace("{key}", key), "emulators place", colons=False).parts)
            for t in layout.get("searched") or []
        ]
        default = home.joinpath(
            *_safe_relative_path(layout.get("default", "").replace("{key}", key),
                                 "emulators default", colons=False).parts
        ) if matches else None
        if (matches and key.lower() not in moved and default is not None
                and all(_lexically_under(place, home) for place in [*places, default])):
            found = next((place for place in places if _is_dir(place)), None)
            _EMULATOR_DIRS[(bios_path, key)] = found or default
            kept.append(entry)
            continue
        unplaced.append({
            "dest": entry["dest"], "name": PurePosixPath(entry["dest"]).name,
            "system": "", "systems": list(entry.get("systems") or []), "required": False,
            "reason": "no_emulators_directory", "cores": entry.get("cores"),
            "root": "emulators",
        })
    if unplaced and say:
        why = (f"{config} sets their folder" if matches
               else f"{bios_path} is not the {layout.get('bios_folder') or 'BIOS'} folder "
                    f"beside {layout.get('config') or 'its config'}")
        print(f"  {_plural(len(unplaced), 'file')} read from {display}'s emulator folders "
              f"left out: {why}.")
    return kept, unplaced


# Per BIOS folder, where its save files go in words, or why that is not
# known: read by the lines that count them once a choice is made.
_SAVE_WHERE: dict[Path, str] = {}
_SAVE_WHY: dict[Path, str] = {}


def say_saves(plat: str, files: list[dict], omitted: list[dict], bios_path: Path,
              display: str, printed: bool) -> None:
    """The save directory lines and the saves event, over the files the
    run installs once narrowed: --system sony-playstation said 106 files
    went to the save directory, none of them a PlayStation file. printed
    is the menu having said them already."""
    saved = sum(1 for entry in files if entry.get("root") == "save")
    where = _SAVE_WHERE.get(bios_path)
    if saved and where is not None:
        if not printed:
            print(f"  {saves_line(display, saved, where)}")
        EVENTS.emit("saves", platform=plat, files=saved, folder=where)
    if printed:
        return
    for line in save_lines([], omitted, bios_path, display):
        detail(f"  {line}")


# The digests the line menu's head read of the files in place, by path and
# by what stat says of the file, kept for the check that follows Enter: the
# head named a wrong copy of the right size in place,
# and a card read twice is read at the speed of its reader. Emptied once
# that check has read them (head_reads_done).
_HEAD_READS: dict[tuple, dict[str, str]] = {}


def _stat_key(path: Path) -> tuple | None:
    """What tells a file apart from the same path rewritten: None for none."""
    try:
        info = path.stat()
    except OSError:
        return None
    return (str(path), info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino)


def _read_digests(path: Path, algorithms: tuple[str, ...], remember: bool = False) -> dict:
    """_digest_file, answered from what the head read when the file is the
    same one, and remembered for the check when remember is set."""
    key = _stat_key(path)
    known = _HEAD_READS.get((key, algorithms)) if key is not None else None
    if known is not None:
        return known
    digests = _digest_file(path, algorithms)
    if remember and key is not None:
        _HEAD_READS[(key, algorithms)] = digests
    return digests


def head_reads_done() -> None:
    """The check after the head has read what it holds: nothing more is
    answered from it, a file the run writes being read again."""
    _HEAD_READS.clear()


def _classify_local(entry: dict, dest: Path, remember: bool = False) -> str:
    """Return 'up_to_date' or 'mismatched' for a file already on disk.
    remember keeps what was read for the check after the line menu."""
    expected = {
        name: entry.get(name, "").lower()
        for name in ("sha256", "sha1")
        if entry.get(name)
    }
    try:
        is_file = dest.is_file()
    except OSError:
        # A folder above it this user cannot enter: what sits there is not
        # known to be the right file.
        return "mismatched"
    if not is_file:
        # A folder at the file's place: --check says so, an install fails
        # on that file alone.
        return "mismatched"
    if not expected:
        return "up_to_date"
    try:
        actual = _read_digests(dest, tuple(expected), remember)
    except OSError:
        # Unreadable (no permission, a read error on a failing card): its
        # contents are not known to be the right ones.
        return "mismatched"
    if all(actual[name] == value for name, value in expected.items()):
        return "up_to_date"
    return "mismatched"


def closed_folder_words(dest: Path, closed: tuple[Path, str]) -> str:
    folder, why = closed
    return f"this user cannot open {folder} ({why}), which holds {dest}"


def unreachable_words(exc: OSError) -> str:
    """Why the place of a file could not be looked at, in words."""
    return (f"could not be read ({exc.strerror or exc}): this user may not "
            f"have access to its folder")


def check_local(
    files: list[dict], bios_path: Path, jobs: int = 8,
    term: "Terminal | None" = None,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Check which files exist locally and have correct hashes.

    Returns (to_download, up_to_date, mismatched). With a terminal, a count
    moves while the files are read: 3.9 GB on an SD card went by in minutes
    of silence, read as a hung run and stopped with Ctrl+C.
    """
    to_download: list[dict] = []
    present: list[tuple[dict, Path]] = []

    for f in files:
        dest = _entry_path(bios_path, f)
        if _held(dest):
            present.append((f, dest))
        else:
            to_download.append(f)

    up_to_date: list[dict] = []
    mismatched: list[dict] = []
    if present:
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            verdicts = pool.map(
                lambda item: (item[0], _classify_local(item[0], item[1])), present
            )
            shown = term if term is not None and term.live and not term.quiet else None
            last = evented = 0.0
            for done, (entry, verdict) in enumerate(verdicts, 1):
                if verdict == "up_to_date":
                    up_to_date.append(entry)
                else:
                    mismatched.append(entry)
                now = time.monotonic()
                # The program driving the installer gets the count the
                # terminal gets: a screen with a bare timer over 6 GB on an
                # SD card read as hung.
                if EVENTS.on and (now - evented >= EVENT_PROGRESS_INTERVAL
                                  or done == len(present)):
                    evented = now
                    EVENTS.emit("checking", files_done=done, files_total=len(present))
                if shown is not None and (now - last >= 0.1 or done == len(present)):
                    last = now
                    print(f"\r  read {done}/{len(present)}", end="", file=shown.stream,
                          flush=True)
            if shown is not None:
                print("\r\033[K", end="", file=shown.stream, flush=True)

    return to_download, up_to_date, mismatched


# Where a file in place that this run replaces is kept: a folder beside the
# one written to, never inside it. Several emulators find their BIOS by
# content, not by name: DuckStation, SwanStation and Rustation read every
# file of the BIOS folder, BizHawk walks its firmware folder recursively. A
# kept copy anywhere under that folder could be taken for the BIOS.
BACKUP_DIR = "retrobios-backup"
# Written into every run folder the installer creates. --restore only accepts
# a folder holding it, so a folder someone else placed (a shared BIOS folder
# on a network share) is never copied over the user's files.
BACKUP_MARKER = ".retrobios-backup"


def _check_holder(holder: Path) -> os.stat_result:
    """Refuse a backup holder the user's files must not go into.

    A link would send them wherever it points. On a system with user ids, a
    folder another user owns was not made by this user's runs, and its owner
    could read or swap what is moved in. A storage that keeps no owner per
    file gives every file one owner: Android's shared storage shows a folder
    Termux has just made as another user's, as does a FAT card. A holder
    owned like the folder it sits in is that storage's owner, not someone
    else's folder. Returns what was checked, so the caller can confirm the
    same folder is still there once it has written into it.
    """
    info = os.lstat(holder)
    if not stat.S_ISDIR(info.st_mode):
        raise OSError(errno.ELOOP, f"{holder} is a link or not a folder")
    getuid = getattr(os, "getuid", None)
    if (getuid is not None and info.st_uid != getuid()
            and info.st_uid != os.lstat(holder.parent).st_uid):
        raise OSError(errno.EPERM, f"{holder} belongs to another user")
    return info


def _same_folder(path: Path, checked: os.stat_result) -> bool:
    """Whether path is still the folder checked, not a link swapped in since."""
    now = os.lstat(path)
    return (stat.S_ISDIR(now.st_mode)
            and (now.st_dev, now.st_ino) == (checked.st_dev, checked.st_ino))


_SAVE_SPLITS = {(True, True): "a folder per system, then one per core, under",
                (True, False): "a folder per system under",
                (False, True): "a folder per core under"}


def save_where_words(where: str) -> tuple[str, str]:
    """(words, folder) for where the saves event says files go: the folder
    without the <system> and <core> it ends with, and those said in words.
    "go to: /sdcard/RetroArch/saves/<core>" read as a folder named <core>."""
    parts = re.split(r"[\\/]", where)
    by_core = bool(parts) and parts[-1] == "<core>"
    if by_core:
        parts = parts[:-1]
    by_system = bool(parts) and parts[-1] == "<system>"
    if by_system:
        parts = parts[:-1]
    folder = where[:len(os.sep.join(parts))] if (by_core or by_system) else where
    return _SAVE_SPLITS.get((by_system, by_core), ""), folder


def saves_line(display: str, count: int, where: str) -> str:
    """Where the files read from the frontend's save directory go."""
    words, folder = save_where_words(where)
    return (f"{_plural(count, 'file')} read from {display}'s save directory "
            f"{'goes' if count == 1 else 'go'} to {words + ' ' if words else ''}"
            f"{shown_path(folder)}")


def unplaced_line(display: str, count: int, remedy: str) -> str:
    """The files read from an unknown save directory, left out."""
    return (f"{_plural(count, 'file')} read from {display}'s save directory left out: "
            f"its place is not known. {remedy}")


def save_lines(files: list[dict], omitted: list[dict], bios_path: Path | None,
               display: str) -> list[str]:
    """The save directory lines of a plan, over the files a choice keeps:
    106 were said to go there for a --system sony-playstation that kept
    none of them, and ROCKNIX's 44 left out were said only at the end, as
    "the frontend's"."""
    lines = []
    count = sum(1 for entry in files if entry.get("root") == "save")
    where = _SAVE_WHERE.get(bios_path) if bios_path is not None else None
    if count and where is not None:
        lines.append(saves_line(display, count, where))
    left = sum(1 for entry in omitted if entry.get("reason") == "no_save_directory")
    if left:
        why = _SAVE_WHY.get(bios_path) if bios_path is not None else None
        lines.append(f"{_plural(left, 'file')} read from {display}'s save directory left "
                     f"out: {why}." if why else
                     unplaced_line(display, left, "Name it with --save-dir."))
    return lines
