"""The first passes over a setup's file list: names, options, board, target, cores, emulators, saves."""

from __future__ import annotations

import argparse
import io
import json
import os
import stat
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from installer.choices import (
    _narrow_to_emulators,
    _older_list_advice,
    _standalone_builds,
    emulator_names,
    trim_recorded,
)
from installer.console import detail
from installer.cores import _unprofiled_cores_firmware
from installer.destination import _unknown_target
from installer.device import card_board, detect_board, version_note
from installer.events import EVENTS
from installer.fetch_plan import FetchPlan
from installer.filesystems import (
    FAT_REFUSED,
    FAT_REFUSED_SHOWN,
    fold_case_twins,
    holds_fat_refused_names,
    keeps_case,
    split_fat_refused,
)
from installer.frontend_folders import (
    place_emulator_entries,
    place_relative_entries,
    place_save_entries,
)
from installer.install_record import by_record, drop_recorded
from installer.lists import (
    ListFailure,
    fetch_manifest,
    fetch_targets,
    load_targets,
    local_targets,
    targets_failure_lines,
)
from installer.narrowing import (
    board_target,
    designated_cores,
    find_by_hash,
    narrow_to_cores,
    truth_lists,
)
from installer.offline import LOCAL
from installer.paths import shown_path
from installer.plan_words import unlisted_saves_words
from installer.platforms import PLATFORM_NAMES, display_name
from installer.refusal import Refusal
from installer.tally import keep_declared, leave_out_game_data, tally
from installer.text import _plural, screen_text

if TYPE_CHECKING:
    from installer.folder_index import FolderIndex, LocalCopy
    from installer.game_folders import GamesPlan
    from installer.local_copies import Unreadable
    from installer.run_setups import _InstallRun


def _print_emulators(plat: str, manifest: dict, files: list[dict], omitted: list[dict]) -> None:
    """What --emulator accepts for a platform, one name per line."""
    names = emulator_names(manifest, files, omitted)
    if not names:
        print(f"  {plat} records no emulators")
        return
    width = min(max(len(name) for name in names), 40)
    for name in sorted(names):
        profile = names[name]
        print(f"  {name:<{width}}  {'' if profile == name else 'same as ' + profile}".rstrip())


FIND_SCHEMA = 1
# What a match of --find --json carries, every key in this order, null
# where the list records none.
FIND_FIELDS = ("dest", "root", "sha1", "sha256", "md5", "crc32", "size", "systems", "cores")


def _found_files(args: argparse.Namespace, plat: str,
                 files: list[dict]) -> tuple[list[dict], list[dict]]:
    """--find: the file of the list with the hash given, the run narrowed to
    it, or with --json the matches printed and nothing installed.

    One content found at several destinations installs at each. A hash two
    contents share (a crc32) is ambiguous: named, never chosen. A kind the
    list does not record (md5, crc32) is said as such, never as unknown.
    """
    value = args.find.strip().lower()
    kind, matches, recorded = find_by_hash(files, value)
    contents = {match.get("sha1") or match.get("sha256") for match in matches}
    result = ("found" if len(contents) == 1 else "ambiguous" if contents
              else "unknown" if recorded else "unrecorded")
    if args.json:
        record = {"schema": FIND_SCHEMA, "platform": plat, "hash": value, "kind": kind,
                  "result": result,
                  "matches": [{field: match.get(field) for field in FIND_FIELDS}
                              for match in matches]}
        print(json.dumps(record), file=args.json_out, flush=True)
        if result != "found":
            args.find_failed = True
        return [], []
    lines = {
        "unrecorded": [f"Error: the {plat} file list records no {kind}: --find reads "
                       "sha1 and sha256 in every list."],
        "unknown": [f"Error: no file of the {plat} list has the {kind} {value}."],
        "ambiguous": [f"Error: {len(contents)} files of the {plat} list have the "
                      f"{kind} {value}: give their sha1 instead.",
                      *(f"  {match['dest']}  {match.get('sha1', '')}" for match in matches)],
    }.get(result)
    if lines is not None:
        # 4: the hash was read and the list holds no one file for it, neither
        # a failure (1) nor an option refused (2).
        raise Refusal("option", "unknown", plat, *lines, code=4,
                      message=lines[0][len("Error: "):])
    for match in matches:
        print(f"  {value} is {match['dest']}")
    return matches, []


def _output_kind(stream: TextIO) -> str:
    """"pipe" or "file" for what stream writes to, "" when neither is known.
    `| tee log.txt` shows every line, `> log.txt` none of them."""
    try:
        mode = os.fstat(stream.fileno()).st_mode
    except (OSError, ValueError, AttributeError, io.UnsupportedOperation):
        return ""
    if stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):
        return "pipe"
    return "file" if stat.S_ISREG(mode) else ""


class _PlatformPass:
    """One setup of the run: its file list as each stage narrows it, then
    what the check found in its folder."""

    def __init__(self, plat_name: str, bios_path: Path, manifest: dict) -> None:
        self.plat_name = plat_name
        self.bios_path = bios_path
        self.manifest = manifest
        self.files: list[dict] = manifest.get("files", [])
        self.omitted_files: list[dict] = manifest.get("omitted_files", [])
        self.variants: list[dict] = []
        self.case_kept = False
        self.game_data_cut = 0
        self.target: str | None = None
        # The cores whose order decides a slot: the board's, else every core.
        self.slot_reach: set[str] | None = None
        self.found_cores: list[str] = []
        self.display = ""
        self.unplaced: list[dict] = []
        self.menu = False
        self.games_plan: GamesPlan | None = None
        self.games_applied = False
        self.core_choices: set[str] = set()
        self.selection: tuple[list[str], list[str], list[str]] | None = None
        # What declining the size question points back at, when it was asked.
        self.smaller = ""
        # g at the menu: whether it left the game data out.
        self.cut: list[bool] | None = None
        self.run_counts = tally([])
        self.narrowed = False
        self.data_dirs: list[dict] = []
        self.head_data = 0
        self.record_files: list[dict] = []
        self.to_download: list[dict] = []
        self.up_to_date: list[dict] = []
        # The entries this run put in place, each checked as it landed.
        self.landed: list[dict] = []
        self.mismatched: list[dict] = []
        self.data_states: list[tuple[dict, tuple[Path, dict[str, dict], int]]] = []
        self.trees_missing = 0
        self.bios_index: FolderIndex | None = None
        self.copies: dict[int, LocalCopy] = {}
        self.unread: list[Unreadable] = []
        self.plan = FetchPlan([], [], [], 0, 0)
        self.hint: list[str] = []
        self.space_checked = False


def _pass_files(run: _InstallRun, plat_name: str, bios_path: Path) -> _PlatformPass:
    """The setup's file list read, narrowed to what --source truth keeps."""
    if bios_path not in run.installed_paths:
        run.installed_paths.append(bios_path)
    if LOCAL.manifest is not None:
        detail(f"\nReading the file index for {plat_name} from {LOCAL.manifest}...")
    elif LOCAL.pack is not None:
        detail(f"\nReading the file index for {plat_name} from {LOCAL.pack.name}...")
    else:
        detail(f"\nFetching file index for {plat_name}...")
    manifest = fetch_manifest(plat_name)
    run.categorized = run.categorized or bool(manifest.get("categorized"))
    p = _PlatformPass(plat_name, bios_path, manifest)
    if run.args.source == "truth":
        if manifest.get("truth_files") is None:
            raise Refusal("option", "not_recorded", plat_name,
                          f"Error: the {plat_name} file list does not say what the emulator "
                          "profiles prove is read, which --source truth needs.",
                          _older_list_advice(plat_name))
        before = len(p.files)
        p.files, p.omitted_files = truth_lists(manifest, p.files, p.omitted_files)
        detail(f"  What the emulator profiles prove is read: {before} to "
               f"{len(p.files)} files (--source truth)")
    return p


def _pass_case_and_names(run: _InstallRun, p: _PlatformPass) -> None:
    """The case variants kept or folded, and the names the drive refuses left out."""
    bios_path, manifest, files = p.bios_path, p.manifest, p.files
    variants = manifest.get("case_variants", [])
    case_kept = keeps_case(bios_path)
    if variants and case_kept:
        # The list is folded for Windows and macOS, but here bios.col and
        # BIOS.col are two files that two cores open.
        files = files + [{**variant, "case_variant": True} for variant in variants]
    elif run.packing:
        # A ZIP keeps both spellings, whatever drive it is written to:
        # the device installing it folds them.
        files = files + [{**variant, "case_variant": True} for variant in variants]
        case_kept = True
    p.variants, p.case_kept = variants, case_kept
    if not case_kept:
        files, folded = fold_case_twins(files)
        if folded:
            # Batocera's share opened over SMB, an exFAT card: the second
            # spelling overwrote the first, and every --check found one
            # of them wrong and fetched it again.
            shown = ", ".join(folded[:3]) + (" ..." if len(folded) > 3 else "")
            detail(
                f"  {_plural(len(folded), 'file')} left out: {bios_path} does not keep "
                f"case and holds another file under the same name ({shown})"
            )
    if not run.packing and any(FAT_REFUSED.search(str(entry.get("dest", "")))
                               for entry in files) \
            and not holds_fat_refused_names(bios_path):
        files, refused = split_fat_refused(files)
        shown = ", ".join(refused[:3]) + (" ..." if len(refused) > 3 else "")
        detail(
            f"  {_plural(len(refused), 'file')} left out: the file system of "
            f"{shown_path(bios_path)} cannot hold a name with any of "
            f"{FAT_REFUSED_SHOWN} ({screen_text(shown)})"
        )
    p.files = files


def _pass_options(run: _InstallRun, p: _PlatformPass) -> bool:
    """--find, --no-game-data, --declared-only and --list-targets. True when
    the setup is done with."""
    args, plat_name = run.args, p.plat_name
    if args.find:
        # Among the case variants kept here too: bios.col is one file.
        p.files, p.omitted_files = _found_files(args, plat_name, p.files)
        if args.json:
            return True
    if args.no_game_data and not p.manifest.get("categorized") and by_record(args):
        drop_recorded(args, plat_name, "--no-game-data", "the list marks no game data")
    if args.no_game_data and not p.manifest.get("categorized"):
        # Without the field nothing is marked, and the run would
        # install the game data it was asked to leave out.
        raise Refusal("option", "not_recorded", plat_name,
                      f"Error: the {plat_name} file list records no file category, "
                      "which --no-game-data needs.", _older_list_advice(plat_name))

    if args.declared_only:
        before = len(p.files)
        p.files, p.omitted_files = keep_declared(p.files, p.omitted_files)
        detail(f"  The platform's own list: {before} to {len(p.files)} files "
               "(--declared-only)")

    if args.list_targets:
        targets = needed_targets(plat_name)
        if not targets:
            print(f"  No targets available for {plat_name}")
        else:
            for t in sorted(targets.keys()):
                cores = targets[t].get("cores")
                label = "no core list" if cores is None else f"{len(cores)} cores"
                print(f"  {t} ({label})")
        return True
    return False


def _pass_board(run: _InstallRun, p: _PlatformPass) -> str | None:
    """The board the setup narrows to: --target, else the one the device or
    the card mounted here names."""
    args, plat_name = run.args, p.plat_name
    target = args.target
    if (target or args.every_board or run.packing or run.chosen_by_flag
            or (LOCAL.offline and local_targets(plat_name) is None)):
        return target
    board = detect_board(plat_name)
    where = "detected"
    if not board and args.dest is not None:
        board, where = card_board(plat_name), "found on the card"
    if not board:
        return target
    known = fetch_targets(plat_name) or {}
    image, board = board, board_target(board, known) or board
    if board in known:
        target = board
        named = board if image == board else f"{board} ({image})"
        words = f"Board {named} {where} (--every-board installs all boards)"
    else:
        words = (f"Board {board} {where} has no "
                 f"{PLATFORM_NAMES.get(plat_name, plat_name)} core list: "
                 "installing the files of every board")
    detail(f"  {words}")
    EVENTS.emit("board", platform=plat_name, board=board,
                applied=target == board, message=words)
    return target


def _pass_target(run: _InstallRun, p: _PlatformPass) -> None:
    """The files narrowed to the cores of the board."""
    # Target filtering. With no --target, a system that names its board
    # narrows to it: a Batocera RPi4 took 8.6 GiB where its board needs
    # 5.5. Read from the device itself, else from the card mounted here:
    # a card prepared on a computer took every board's files, and the
    # full-screen interface, which always gives --dest, never applied one.
    p.target = target = _pass_board(run, p)
    if target:
        _pass_target_cores(run, p, target)


def needed_targets(plat: str) -> dict:
    """The board list a run cannot go on without, its failure the run's refusal."""
    try:
        return load_targets(plat)
    except ListFailure as stopped:
        # A list the run would carry on without stops this one all the same:
        # it said why on stderr and ended with code 1, no error event sent.
        problem = stopped.problem
        raise Refusal("targets", problem.code, problem.plat,
                      *targets_failure_lines(problem), code=problem.fatal or 1) from None


def _pass_target_cores(run: _InstallRun, p: _PlatformPass, target: str) -> None:
    """The files narrowed to the cores the board's list names."""
    targets = run.target_lists.get(p.plat_name)
    if targets is None:
        targets = needed_targets(p.plat_name)
    target_info = targets.get(target)
    if target_info is None:
        # Carrying on would install every file, which is the opposite
        # of what a filter was asked for: a 4 GB download instead of
        # the subset the target needs. Refuse rather than ignore.
        _unknown_target(target, p.plat_name, targets)
    elif target_info.get("cores") is None:
        detail(
            f"  Target '{target}' publishes no core list: "
            "installing every file"
        )
    else:
        before = len(p.files)
        p.files, p.omitted_files = narrow_to_cores(
            p.manifest, target_info["cores"], p.files, p.omitted_files,
            target=target,
        )
        p.slot_reach = designated_cores(p.manifest, target_info["cores"], target)
        detail(f"  Filtered {before} to {len(p.files)} files for target {target}")


def _pass_installed_cores(run: _InstallRun, p: _PlatformPass) -> None:
    """The files narrowed to the cores installed, with --installed-cores."""
    args, plat_name, bios_path, manifest = run.args, p.plat_name, p.bios_path, p.manifest
    found_cores = run.cores_found.get((plat_name, bios_path), [])
    if "system_cores" not in manifest:
        found_cores = []
    elif found_cores:
        detail(f"  {_plural(len(found_cores), 'core')} installed")
    p.found_cores = found_cores
    if args.installed_cores and "system_cores" not in manifest and by_record(args):
        drop_recorded(args, plat_name, "--installed-cores",
                      "the list does not say which cores read which systems")
    if not args.installed_cores:
        return
    if "system_cores" not in manifest:
        raise Refusal("option", "not_recorded", plat_name,
                      f"Error: the {plat_name} file list does not say which cores "
                      "read which systems, which --installed-cores needs.",
                      _older_list_advice(plat_name))
    before = len(p.files)
    info_dests = _unprofiled_cores_firmware(
        plat_name, bios_path, manifest, found_cores,
        run.cores_searched.get((plat_name, bios_path), []),
    )
    p.files, p.omitted_files = narrow_to_cores(
        manifest, found_cores, p.files, p.omitted_files, info_dests
    )
    detail(f"  Narrowed {before} to {len(p.files)} files to the installed cores")
    # A slot is ranked by the cores installed, as a pack built for them.
    found_reach = designated_cores(manifest, found_cores)
    p.slot_reach = found_reach if p.slot_reach is None else p.slot_reach & found_reach


def _pass_emulators(run: _InstallRun, p: _PlatformPass) -> bool:
    """--list-emulators, or the files narrowed to --emulator. True when the
    setup is done with."""
    args = run.args
    if args.list_emulators:
        _print_emulators(p.plat_name, p.manifest, *(
            leave_out_game_data(p.files, p.omitted_files)[:2] if args.no_game_data
            else (p.files, p.omitted_files)))
        return True

    if args.emulator and by_record(args):
        for part in trim_recorded({"--emulator": list(args.emulator)}, p.plat_name,
                                  p.manifest, p.files, p.omitted_files):
            drop_recorded(args, p.plat_name, part.flag, part.why, part.keep)
    if args.emulator:
        names = emulator_names(p.manifest, p.files, p.omitted_files)
        before = len(p.files)
        chosen, p.files, p.omitted_files = _narrow_to_emulators(
            args.emulator, p.manifest, p.plat_name, p.files, p.omitted_files
        )
        detail(f"  Narrowed {before} to {len(p.files)} files to {', '.join(chosen)}")
        if args.standalone:
            p.files, p.omitted_files = _standalone_builds(
                args.emulator, names, p.manifest, p.plat_name, p.files, p.omitted_files)
    return False


def _pass_version_and_saves(run: _InstallRun, p: _PlatformPass) -> None:
    """The list's version said, and the files read from save and emulator
    folders placed."""
    plat_name, bios_path, manifest = p.plat_name, p.bios_path, p.manifest
    # Said before the install and again with the result.
    note = None if run.listing or run.packing else version_note(plat_name, bios_path, manifest)
    if note is not None:
        print(f"  {note[2]}")
        run.version_notes.append(note[2])
        EVENTS.emit("version", platform=plat_name, list_version=note[0],
                    installed_version=note[1], message=note[2])

    # Before the menu: it offered 23 files, then 22 were checked, the
    # one read from an unknown save directory left out. Said once the
    # choice is made, over the files it keeps (say_saves, say_unplaced).
    p.display = display = display_name(plat_name, manifest)
    if not run.packing:
        # A pack keeps every root's files: the device installing it
        # places them.
        files, unplaced = place_save_entries(
            p.files, bios_path, manifest, run.args.save_dir, display)
        files, beyond = place_relative_entries(files, bios_path, manifest)
        p.files, elsewhere = place_emulator_entries(files, bios_path, manifest)
        p.unplaced = [*unplaced, *beyond, *elsewhere]
    if not manifest.get("save_directory") and not run.packing:
        # Its own list leaves these files out: naming the folder with
        # --save-dir installs none of them, and was advised in a loop.
        why = unlisted_saves_words(display)
        p.unplaced = [_unlisted_save(entry, why) for entry in p.unplaced]
        p.omitted_files = [_unlisted_save(entry, why) for entry in p.omitted_files]


def _unlisted_save(entry: dict, why: str) -> dict:
    """entry, when read from a save directory the list names no place for,
    with why in words and no remedy."""
    if entry.get("reason") != "no_save_directory":
        return entry
    return {**entry, "why": why, "remedy": ""}
