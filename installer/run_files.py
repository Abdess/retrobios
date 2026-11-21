"""One setup's file list, narrowed pass by pass by every option and choice."""
from __future__ import annotations

import argparse
import io
import json
import os
import stat
import sys
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from installer.choices import (
    GAMES_REQUIRED_WORDS,
    GamesChoice,
    _narrow_to_emulators,
    _older_list_advice,
    _recorded_emulators,
    _requested_narrowing,
    _standalone_builds,
    available_choices,
    emulator_names,
    records_selection,
)
from installer.console import OUTPUT, detail
from installer.cores import _unprofiled_cores_firmware
from installer.datadirs import select_data_directories
from installer.destination import _unknown_target
from installer.detect_os import detected_shown
from installer.device import card_board, detect_board, version_note
from installer.events import EVENTS
from installer.filesystems import (
    FAT_REFUSED,
    FAT_REFUSED_SHOWN,
    fold_case_twins,
    holds_fat_refused_names,
    keeps_case,
    split_fat_refused,
)
from installer.frontend_folders import (
    _SAVE_WHY,
    place_emulator_entries,
    place_relative_entries,
    place_save_entries,
    say_saves,
)
from installer.games import fallback_lines, read_games
from installer.install_record import _RECORD_TAKEN, by_record, drop_recorded, record_menu_words
from installer.invocation import _INVOCATION
from installer.line_menu import MenuContext, _prompt_custom_selection
from installer.lists import fetch_manifest, fetch_targets, local_targets
from installer.manifest import GAME_DATA
from installer.narrowing import (
    _chosen,
    _filter_by_target,
    board_target,
    designated_cores,
    find_by_hash,
    narrow,
    narrow_to_cores,
    one_per_slot,
    truth_lists,
)
from installer.offline import LOCAL
from installer.pack import _pack_refused, pack_path
from installer.paths import shown_path
from installer.plan_words import (
    INSTALLED_ONLY,
    _core_sized,
    _system_sized,
    choosable_systems,
    chosen_flags,
    chosen_systems,
    emptied_words,
    game_data_only,
    game_data_only_words,
    unlisted_saves_words,
)
from installer.platforms import PLATFORM_NAMES, display_name, system_title
from installer.tally import (
    _bytes,
    _left_out_lines,
    keep_declared,
    kinds_definition,
    leave_out_game_data,
    not_installable_words,
    parts_words,
    tally,
)
from installer.text import _plural, format_size, screen_text

if TYPE_CHECKING:
    from installer.from_folders import FolderIndex, LocalCopy, Unreadable
    from installer.games import GamesPlan
    from installer.run_setups import _InstallRun


def _system_label(name: str, manifest: dict | None) -> str:
    """A system id with the names the platform gives it: nintendo-gba (gba)."""
    names = ((manifest or {}).get("system_names") or {}).get(name)
    return f"{name} ({', '.join(names)})" if names else name


def _print_choices(
    plat: str, files: list[dict], omitted: list[dict], systems: bool,
    manifest: dict | None = None,
) -> None:
    """What --system or --core accepts for a platform, with what each holds."""
    choices = available_choices(files, omitted)
    names = choices["systems"] if systems else choices["cores"]
    if not names:
        print(f"  {plat} records no {'systems' if systems else 'cores'}")
        return
    labels = {name: _system_label(name, manifest) if systems else name for name in names}
    width = min(max(len(label) for label in labels.values()), 40)
    for name in names:
        held = (
            [f for f in files if _chosen(f, {name})]
            if systems
            else _filter_by_target([f for f in files if f.get("cores") is not None], [name])
        )
        print(f"  {labels[name]:<{width}}  "
              f"{_system_sized(held) if systems else _core_sized(held)}")


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
        EVENTS.emit("error", stage="option", reason="unknown", platform=plat,
                    message=lines[0][len("Error: "):])
        for line in lines:
            print(line, file=sys.stderr)
        # 4: the hash was read and the list holds no one file for it, neither
        # a failure (1) nor an option refused (2).
        sys.exit(4)
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
        self.mismatched: list[dict] = []
        self.data_states: list[tuple[dict, tuple[Path, dict[str, dict], int]]] = []
        self.trees_missing = 0
        self.bios_index: FolderIndex | None = None
        self.copies: dict[int, LocalCopy] = {}
        self.unread: list[Unreadable] = []
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
            print(f"Error: the {plat_name} file list does not say what the emulator "
                  "profiles prove is read, which --source truth needs.", file=sys.stderr)
            print(_older_list_advice(plat_name), file=sys.stderr)
            sys.exit(1)
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
        print(f"Error: the {plat_name} file list records no file category, "
              "which --no-game-data needs.", file=sys.stderr)
        print(_older_list_advice(plat_name), file=sys.stderr)
        sys.exit(1)

    if args.declared_only:
        before = len(p.files)
        p.files, p.omitted_files = keep_declared(p.files, p.omitted_files)
        detail(f"  The platform's own list: {before} to {len(p.files)} files "
               "(--declared-only)")

    if args.list_targets:
        targets = fetch_targets(plat_name)
        if targets is None:
            sys.exit(1)
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


def _pass_target_cores(run: _InstallRun, p: _PlatformPass, target: str) -> None:
    """The files narrowed to the cores the board's list names."""
    targets = run.target_lists.get(p.plat_name)
    if targets is None:
        targets = fetch_targets(p.plat_name)
    if targets is None:
        sys.exit(1)
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
        print(
            f"Error: the {plat_name} file list does not say which cores "
            "read which systems, which --installed-cores needs.",
            file=sys.stderr,
        )
        print(_older_list_advice(plat_name), file=sys.stderr)
        sys.exit(1)
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
        _recorded_emulators(args, p.plat_name, p.manifest, p.files, p.omitted_files)
    if args.emulator:
        names = emulator_names(p.manifest, p.files, p.omitted_files)
        p.files, p.omitted_files = _narrow_to_emulators(
            args.emulator, p.manifest, p.plat_name, p.files, p.omitted_files
        )
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
    # choice is made, over the files it keeps (say_saves).
    p.display = display = display_name(plat_name, manifest)
    if not run.packing:
        # A pack keeps every root's files: the device installing it
        # places them.
        files, unplaced = place_save_entries(
            p.files, bios_path, manifest, run.args.save_dir, display, say=False)
        files, beyond = place_relative_entries(
            files, bios_path, manifest, display, say=not run.listing)
        p.files, elsewhere = place_emulator_entries(
            files, bios_path, manifest, display, say=not run.listing)
        p.unplaced = [*unplaced, *beyond, *elsewhere]
    if not manifest.get("save_directory") and not run.packing:
        # Its own list leaves these files out: naming the folder with
        # --save-dir installs none of them, and was advised in a loop.
        _SAVE_WHY[bios_path] = unlisted_saves_words(display)


def _pass_games(run: _InstallRun, p: _PlatformPass) -> None:
    """The games of the card read, and the files narrowed to what they need
    where no menu chooses."""
    args = run.args
    # The games of the card, read before the choices: where it holds
    # some, what they need is the menu's first choice, and --for-games
    # narrows the list here, before the systems are counted.
    p.menu = will_ask = (run.interactive and not args.check and not run.listing
                         and not run.chosen_by_flag and not args.one_per_slot)
    # A run that asks nothing takes the plan's first choice: the games of
    # the card. `--yes` alone installed 6.4 GB on a dArkOS card holding
    # two games, while the screen offers what they need first. Not for a
    # run given its list (the screen's own runs, the choice already
    # made), nor one narrowed by name.
    unasked = (not run.interactive and not args.check and not run.listing and not run.packing
               and not getattr(args, "all_files", False)
               and LOCAL.manifest is None and LOCAL.pack is None
               and not (args.installed_cores or args.no_game_data or args.system
                        or args.core or args.region or args.emulator or args.declared_only
                        or args.one_per_slot or run.chosen_by_flag))
    if args.for_games is not None or unasked or (will_ask and not (
            args.installed_cores or args.no_game_data or LOCAL.pack is not None)):
        p.games_plan = read_games(args, p.plat_name, p.bios_path, p.manifest, run.term,
                                  run.os_type)
    games_plan = p.games_plan
    # Given with --system, --core or --region, the games narrow first and
    # those choose among what they keep, as the screen's ticks do.
    if games_plan is not None and (not will_ask or args.system or args.core or args.region
                                   or args.emulator or args.declared_only):
        p.files, p.omitted_files = games_plan.apply(p.files, p.omitted_files,
                                                    args.required_only)
        p.unplaced = games_plan.apply([], p.unplaced, args.required_only)[1]
        p.games_applied = True
        detail(f"  For the games: {_plural(len(p.files), 'file')} of the list"
               + (f", {GAMES_REQUIRED_WORDS}" if args.required_only else ""))
        if args.for_games is None:
            detail("  The card holds games, so only what they need is installed. "
                   "--all-files installs the whole list.")
        run.version_notes += [line.strip() for line in fallback_lines(games_plan)]


def _pass_menu_answer(
    run: _InstallRun, p: _PlatformPass,
    answer: tuple[list[str], list[str], list[str]] | str | GamesChoice | None,
    given: tuple[list[str], list[str], list[str]] | GamesChoice | None,
    whole_installed: tuple[list[dict], list[dict]] | None,
    kept_record: bool, record_options_kept: list[tuple[str, str | None]] | None,
) -> tuple[list[str], list[str], list[str]] | None:
    """The menu's answer applied: the systems, cores and regions it chose,
    None for every file."""
    plat_name = p.plat_name
    selection = answer
    if selection == INSTALLED_ONLY and whole_installed is not None:
        p.files, p.omitted_files = whole_installed
        _INVOCATION.chosen[plat_name] = chosen_flags(INSTALLED_ONLY)
        selection = None
    elif isinstance(selection, GamesChoice):
        p.files, p.omitted_files = selection.apply(p.files, p.omitted_files)
        p.unplaced = selection.apply([], p.unplaced)[1]
        p.games_applied = True
        run.version_notes += [line.strip() for line in fallback_lines(selection.plan)]
        if selection != given:
            _INVOCATION.chosen[plat_name] = chosen_flags(selection)
        else:
            _INVOCATION.chosen.pop(plat_name, None)
        selection = None
    elif selection is not None and selection != given:
        _INVOCATION.chosen[plat_name] = chosen_flags(selection)
    elif selection is None and isinstance(given, GamesChoice):
        # Everything, where --for-games was given: the command
        # without it makes the same choice.
        _INVOCATION.chosen[plat_name] = []
    else:
        _INVOCATION.chosen.pop(plat_name, None)
    if kept_record and record_options_kept is not None:
        # Enter on the recorded choice: still the record's options.
        _INVOCATION.chosen[plat_name] = record_options_kept
    elif selection is None and plat_name in _RECORD_TAKEN and not p.games_applied:
        # e: every file, the recorded narrowing given up.
        run.args.system = run.args.core = run.args.region = None
    return selection if isinstance(selection, tuple) else None


def _pass_menu(run: _InstallRun, p: _PlatformPass, bare: list[dict], bare_omitted: list[dict],
               given: tuple[list[str], list[str], list[str]] | GamesChoice | None,
               ) -> tuple[list[str], list[str], list[str]] | None:
    """The line menu asked and its answer applied."""
    args, plat_name, bios_path, manifest = run.args, p.plat_name, p.bios_path, p.manifest
    files, omitted_files = p.files, p.omitted_files
    whole_installed = (
        narrow_to_cores(manifest, p.found_cores, files, omitted_files)
        if p.found_cores and not args.installed_cores else None
    )
    installed = (whole_installed if whole_installed is None or not args.no_game_data
                 else leave_out_game_data(*whole_installed)[:2])
    listed = len(manifest.get("files", [])) + len(p.variants if p.case_kept else [])

    # g, the plan's game data row: offered where the list marks its
    # game data and --no-game-data did not already leave it out.
    p.cut = cut = ([False] if manifest.get("categorized") and not args.no_game_data
                   and any(entry.get("category") == GAME_DATA for entry in files) else None)

    def command_for(choice: object, plat: str = plat_name,
                    folder: Path = bios_path) -> str:
        # The choice made at the questions, every other option of the
        # run kept: --dest, --from-pack and --manifest were dropped.
        _INVOCATION.chosen[plat] = (
            (chosen_flags(choice) if choice is not None else [])
            + ([("--no-game-data", None)] if cut and cut[0] else []))
        return _INVOCATION.command(plat, folder)

    # The record's options, which the menu's commands overwrite.
    record_options_kept = _INVOCATION.chosen.get(plat_name)
    answer = _prompt_custom_selection(
        MenuContext(
            plat_name, bare, bare_omitted + p.unplaced, installed,
            detected_shown(plat_name, bios_path) or p.display,
            manifest.get("data_directories") or [], bios_path, manifest,
            bool(p.target or args.installed_cores or args.declared_only
                 or len(files) + p.game_data_cut + len(p.unplaced) != listed)),
        dry_run=args.dry_run, choosable=records_selection(files), given=given,
        command=command_for, cut=cut,
        note=" ".join(filter(None, [
            record_menu_words(_RECORD_TAKEN.get(plat_name)),
            game_data_only_words([system_title(system, manifest) for system in
                                  game_data_only(given[0] if isinstance(given, tuple)
                                                 else [], files)])
            if args.no_game_data else ""])),
        played=None if p.games_applied else p.games_plan,
    )
    # Its head named the BIOS folder: the result does not again.
    OUTPUT.where_said = True
    kept_record = plat_name in _RECORD_TAKEN and answer is not None and (
        answer is given or answer == given)
    if answer is None and LOCAL.pack is not None:
        p.smaller = "  Nothing copied."
    elif answer is None:
        smaller = ("  Nothing downloaded. To install less, run the same command "
                   "again and type c at the first question to choose systems")
        if installed is not None:
            smaller += (f", or i for only what the installed cores read "
                        f"({format_size(_bytes(installed[0]))})")
        p.smaller = smaller + "."
    return _pass_menu_answer(run, p, answer, given, whole_installed, kept_record,
                             record_options_kept)


def _pass_choice(run: _InstallRun, p: _PlatformPass) -> None:
    """The systems, cores and regions chosen, by the options or at the menu."""
    args, plat_name, manifest = run.args, p.plat_name, p.manifest
    files, omitted_files = p.files, p.omitted_files
    # --no-game-data leaves the game data out once the list is narrowed
    # to the choice: taken out first, its line named the 5099 game data
    # files of every system under a run for the PlayStation alone
    # What is chosen among is the list without it.
    bare, bare_omitted = (leave_out_game_data(files, omitted_files)[:2]
                          if args.no_game_data else (files, omitted_files))

    # What --core resolves against, for advice that names one.
    p.core_choices = set(available_choices(bare, bare_omitted)["cores"])
    # A system named that holds only game data is a choice, said empty
    # below: refused as unknown, it was named "not a system".
    selection = _requested_narrowing(args, plat_name, files, omitted_files, manifest)
    # What the systems are counted out of, on the plan and in Choose
    # systems: the screen reads it from this event.
    EVENTS.emit("choices", platform=plat_name, systems=choosable_systems(
        bare, bare_omitted, *(selection[1:] if selection else ())))
    kept_dests = {entry.get("dest") for entry in files}
    EVENTS.emit("set_aside", platform=plat_name, dests=[
        entry.get("dest") for entry in manifest.get("files") or []
        if entry.get("dest") not in kept_dests])
    given: tuple[list[str], list[str], list[str]] | GamesChoice | None = selection
    if p.games_plan is not None and not p.games_applied and args.for_games is not None:
        given = GamesChoice(p.games_plan, args.required_only)
    p.selection = _pass_menu(run, p, bare, bare_omitted, given) if p.menu else selection


def _pass_narrow(run: _InstallRun, p: _PlatformPass) -> None:
    """The files narrowed to the choice, to one per slot and without game data."""
    args, plat_name, selection = run.args, p.plat_name, p.selection
    if selection is not None:
        before = len(p.files)
        p.files, p.omitted_files = narrow(p.files, p.omitted_files, *selection)
        p.unplaced = narrow([], p.unplaced, *selection)[1]
        if len(p.files) != before and not p.menu:
            # Enter for every system narrows nothing: "Narrowed 23 to 23".
            # The menu counted the choice again before Enter.
            detail(f"  Narrowed {before} to {len(p.files)} files")
    if args.one_per_slot:
        if not p.manifest.get("slot_fields"):
            print(f"Error: the {plat_name} file list does not say which files a "
                  "slot holds, which --one-per-slot needs.", file=sys.stderr)
            print(_older_list_advice(plat_name), file=sys.stderr)
            sys.exit(1)
        before = len(p.files)
        p.files, p.omitted_files = one_per_slot(p.files, p.omitted_files, p.slot_reach)
        detail(f"  One BIOS per console and region: {before} to {len(p.files)} files")
    if (p.cut and p.cut[0]) or args.no_game_data:
        # Left out at g or by --no-game-data, from what the choice kept:
        # g offered the game data of the systems chosen, and the line
        # below counted the whole list's.
        before = len(p.files)
        p.files, p.omitted_files, left_out = leave_out_game_data(p.files, p.omitted_files)
        p.game_data_cut = before - len(p.files)
        run.left_out_seen.extend(left_out)
        if not args.no_game_data:
            _INVOCATION.chosen[plat_name] = (_INVOCATION.chosen.get(plat_name, [])
                                             + [("--no-game-data", None)])
        for line in _left_out_lines(left_out, args.verbose):
            detail(line)


def _pass_unplaced(run: _InstallRun, p: _PlatformPass) -> bool:
    """The files no folder holds counted, the save folders said, and
    --list-systems or --list-cores. True when the setup is done with."""
    args = run.args
    if p.unplaced:
        run.total_omitted += len(p.unplaced)
        run.omitted_seen.extend(p.unplaced)
    if not run.packing:
        say_saves(p.plat_name, p.files, p.omitted_files + p.unplaced, p.bios_path, p.display,
                  p.menu)

    if args.list_systems or args.list_cores:
        _print_choices(p.plat_name, p.files, p.omitted_files, args.list_systems, p.manifest)
        return True
    return False


def _pass_head(run: _InstallRun, p: _PlatformPass) -> None:
    """The files counted, the data trees kept, and the head of a run
    without a menu."""
    args, manifest, files, game_data_cut = run.args, p.manifest, p.files, p.game_data_cut
    # The count every later line of the platform divides: the files
    # checked, planned, offered and installed are these.
    p.run_counts = run_counts = tally(files)
    # Whether the list was narrowed: the data trees kept are then those
    # of the files kept. Computed once, for the head and the run, which
    # must count the same trees.
    p.narrowed = narrowed = bool(
        p.target or args.system or args.core or args.region or args.installed_cores
        or args.one_per_slot or args.standalone or run.chosen_by_flag
        or args.declared_only or len(files) + game_data_cut + len(p.unplaced)
        != len(manifest.get("files", [])) + len(p.variants if p.case_kept else [])
        or p.games_applied
    )
    # --find installs the file found, no tree beside it.
    p.data_dirs = data_dirs = [] if args.find else select_data_directories(
        manifest, files, narrowed, bool(args.required_only),
        p.games_plan if p.games_applied else None, chosen_systems(p.selection))
    # The kinds as the plan and the menu head say them (parts_words),
    # the data files of the folders kept among them: this head said
    # BIOS files and game data beside a plan of three kinds, neither
    # defined. One total above them, the data files
    # in it.
    p.head_data = head_data = sum(len(entry.get("files") or {}) for entry in data_dirs)
    head_bytes = sum(meta.get("size", 0) for entry in data_dirs
                     for meta in (entry.get("files") or {}).values())
    if not p.menu:
        # An answered menu said these lines right above: the run head
        # repeated them under it.
        detail(f"  {_plural(run_counts.files + head_data, 'file')} "
               f"({format_size(run_counts.size + head_bytes)})")
        categorized_list = bool(manifest.get("categorized"))
        kinds = run_counts if categorized_list else tally(
            {"size": entry.get("size")} for entry in files)
        parts = parts_words(kinds, head_data, head_bytes, game_data_cut)
        if parts:
            detail(f"    {parts}.")
        defined = kinds_definition(
            categorized_list and bool(run_counts.games or game_data_cut), bool(head_data))
        if defined:
            detail(f"    {defined}")


def _pass_empty_and_omitted(run: _InstallRun, p: _PlatformPass) -> bool:
    """A choice that keeps no file said, and the files the list cannot
    install counted. True when the setup is done with."""
    selection, manifest = p.selection, p.manifest
    # A choice that keeps no file says so where "All files up to date"
    # was said of it.
    empty_choice = "" if p.run_counts.files or not (selection or p.game_data_cut) else (
        emptied_words([system_title(name, manifest) for name in
                       (selection[0] if selection else [])], bool(p.game_data_cut)))
    if empty_choice:
        print(f"  {empty_choice}")
        if run.packing:
            sys.exit(_pack_refused(p.plat_name, pack_path(run.args.pack, p.plat_name, p.narrowed),
                                   "the choice keeps no file to put in a pack", 2))
        if not EVENTS.on:
            return True
    omitted_files = p.omitted_files
    if omitted_files:
        required_omitted = sum(
            1 for entry in omitted_files if entry.get("required", True)
        )
        reasons: dict[str, int] = {}
        for entry in omitted_files:
            reason = entry.get("reason", "unknown")
            reasons[reason] = reasons.get(reason, 0) + 1
        detail(f"  {not_installable_words(len(omitted_files), required_omitted, reasons)}")
        run.total_omitted += len(omitted_files)
        # Named for the end of the run: ROCKNIX's own list leaves them out,
        # and the end said "the frontend's save directory".
        run.omitted_seen.extend({**entry, "frontend": p.display,
                                 "save_why": unlisted_saves_words(p.display)}
                                if entry.get("reason") == "no_save_directory"
                                and not entry.get("frontend") else entry
                                for entry in omitted_files)
    return False


def _select_setup_files(run: _InstallRun, plat_name: str,
                        bios_path: Path) -> _PlatformPass | None:
    """The setup's file list narrowed by every option and choice. None when
    the setup is done with."""
    p = _pass_files(run, plat_name, bios_path)
    _pass_case_and_names(run, p)
    if _pass_options(run, p):
        return None
    _pass_target(run, p)
    _pass_installed_cores(run, p)
    if _pass_emulators(run, p):
        return None
    _pass_version_and_saves(run, p)
    _pass_games(run, p)
    _pass_choice(run, p)
    _pass_narrow(run, p)
    if _pass_unplaced(run, p):
        return None
    _pass_head(run, p)
    if _pass_empty_and_omitted(run, p):
        return None
    return p
