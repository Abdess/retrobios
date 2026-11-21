"""The folders a frontend names besides its BIOS folder: saves, roms, configs and emulators."""
from __future__ import annotations

import contextlib
import io
import os
import re
import sys
from pathlib import Path, PurePosixPath

from installer.config_values import (
    _RETROARCH_CONFIGS,
    _cfg_true,
    _config_keys,
    _retroarch_cfg_dir,
    _retroarch_cfg_value,
)
from installer.console import detail
from installer.detect_frontends import detect_platforms
from installer.detect_os import detect_os
from installer.events import EVENTS
from installer.host_fs import _SETUP_SEARCH, _is_dir
from installer.invocation import _INVOCATION
from installer.paths import (
    RELATIVE_ROOTS,
    _EMULATOR_DIRS,
    _RELATIVE_DIRS,
    _SAVE_DIRS,
    SavePlace,
    _lexically_under,
    _note_spelling,
    _relative_root,
    _safe_relative_path,
    shown_path,
    spelled,
)
from installer.text import _plural

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
            if _cfg_true(_retroarch_cfg_value(cfg_path, key)):
                return (f"RetroArch keeps saves beside each game ({key} in {cfg_path}): "
                        "name the folder with --save-dir")
        sort = _retroarch_cfg_value(cfg_path, "sort_savefiles_enable")
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
    display: str,
) -> tuple[list[dict], list[dict]]:
    """Find the save directory for the entries read below it.

    Returns the files to install and, when the save directory is unknown,
    the entries left out as omissions. Nothing is printed or sent: the run
    says it (say_saves) once a choice of systems has kept the files it
    counts.
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
        return files, []
    _SAVE_WHY[bios_path] = place
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
    files: list[dict], bios_path: Path, manifest: dict,
) -> tuple[list[dict], list[dict]]:
    """Find the roms and configs folders for the entries read below them.

    The list gives each root relative to the BIOS folder, as the OS's own
    source places them (ROCKNIX's /storage/roms holds bios/, Batocera's
    configs folder is ../system/configs): a BIOS folder of the platform's
    name puts the root there. Any other is a folder this run cannot relate
    to the root, and the entries are left out, the reason kept for
    say_unplaced.
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
        _UNPLACED_WHY[(bios_path, root)] = (
            f"{bios_path} is not its {layout.get('bios_folder') or 'BIOS'} folder")
        files = [entry for entry in files if entry.get("root") != root]
        unplaced += [
            {"dest": entry["dest"], "name": PurePosixPath(entry["dest"]).name,
             "system": "", "systems": list(entry.get("systems") or []), "required": False,
             "reason": f"no_{root}_directory", "cores": entry.get("cores"), "root": root}
            for entry in below
        ]
    return files, unplaced


def place_emulator_entries(
    files: list[dict], bios_path: Path, manifest: dict,
) -> tuple[list[dict], list[dict]]:
    """Find the emulator folder each entry a launcher runs from one goes to.

    The platform keeps its BIOS folder beside its own folder holding the
    launcher config (RetroBat's bios beside emulationstation): a BIOS
    folder of that name whose parent holds the config is the platform's.
    A key the config sets moves the folder somewhere this run does not
    follow, so its files are left out, the reason kept for say_unplaced.
    Otherwise the folder is the first of the searched places that exists,
    the default one when none does, as the launcher searches them.
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
    if unplaced:
        _UNPLACED_WHY[(bios_path, "emulators")] = (
            f"{config} sets their folder" if matches
            else f"{bios_path} is not the {layout.get('bios_folder') or 'BIOS'} folder "
                 f"beside {layout.get('config') or 'its config'}")
    return kept, unplaced


# Per BIOS folder and root, why the files read below a roms, configs or
# emulators folder are left out: said once a choice keeps the ones counted.
_UNPLACED_WHY: dict[tuple[Path, str], str] = {}
_UNPLACED_FOLDERS = {"roms": "roms folder", "configs": "configs folder",
                     "emulators": "emulator folders"}


def say_unplaced(omitted: list[dict], bios_path: Path, display: str) -> None:
    """The roms, configs and emulator folder lines, over the entries a
    narrowed run still counts: --system panasonic-3do said 1918 files read
    from EmuDeck's roms folder were left out, 6 of them the 3DO's."""
    for root, folder in _UNPLACED_FOLDERS.items():
        left = sum(1 for entry in omitted if entry.get("reason") == f"no_{root}_directory")
        why = _UNPLACED_WHY.get((bios_path, root))
        if left and why is not None:
            print(f"  {_plural(left, 'file')} read from {display}'s {folder} left out: {why}.")


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
