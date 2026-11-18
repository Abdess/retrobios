"""One install run, platform by platform, pass by pass."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import NoReturn, TextIO

from installer.app import CardApp, app_refusal, finish_app
from installer.cards import (
    _check_cores_dir,
    _missing_dest,
    _no_core_found,
    _platform_for_dest,
    _refuse_closed,
    _refuse_file,
    _several_found,
    _unknown_target,
    _unprofiled_cores_firmware,
    card_dest,
    card_install_dest,
)
from installer.choices import (
    _narrow_to_emulators,
    _older_list_advice,
    _recorded_emulators,
    _requested_narrowing,
    _standalone_builds,
    parse_romm_firmware,
    romm_firmware_layout,
    romm_relayout,
)
from installer.constants import AVAILABLE_PLATFORMS, GAME_DATA, PLATFORM_NAMES, TARGET_PLATFORMS
from installer.cores import (
    CORE_PLATFORMS,
    FAT_REFUSED,
    FAT_REFUSED_SHOWN,
    NOMEDIA,
    _NO_BIOS_FOLDER,
    core_dirs,
    fold_case_twins,
    hide_from_media_scanner,
    holds_fat_refused_names,
    installed_cores,
    keeps_case,
    normalize_platform,
    split_fat_refused,
)
from installer.datadirs import (
    data_directory_state,
    data_fetch_bytes,
    data_space_bytes,
    install_data_directory,
    select_data_directories,
)
from installer.detect_frontends import detect_frontends, detect_platforms, launchbox_bios_dirs, launchbox_root
from installer.detect_os import (
    _enter_wsl,
    _system_lines,
    _wsl_dest,
    card_board,
    detect_board,
    detect_os,
    detected_os,
    detected_shown,
    found_label,
    version_note,
)
from installer.embedded import _SHARE_FOLDERS, card_bound, display_name, shown_path
from installer.events import EVENTS, _event_mode
from installer.from_folders import (
    CheckHeld,
    FolderIndex,
    LocalCopy,
    Unreadable,
    _bytes,
    _open_local_sources,
    bios_folder_index,
    bulk_hint,
    check_lines,
    copy_plan_lines,
    emit_copies,
    emit_unreadable,
    plan_local_copies,
    sources_line,
    unreadable_copies,
    unreadable_lines,
)
from installer.games import GamesPlan, fallback_lines, read_games
from installer.invocation import _INVOCATION, Invocation, installer_id
from installer.line_ui import (
    GAMES_REQUIRED_WORDS,
    INSTALLED_ONLY,
    GamesChoice,
    MenuContext,
    _default_set_aside,
    _is_terminal,
    _manual_usage_hint,
    _print_choices,
    _print_emulators,
    _prompt_custom_selection,
    _prompt_manual_platform,
    _prompt_platform_choice,
    ask_platform_folder,
    choosable_systems,
    chosen_flags,
    chosen_systems,
    emptied_words,
    emulator_names,
    fold_line,
    game_data_only,
    game_data_only_words,
    share_words,
    unlisted_saves_words,
)
from installer.local_files import (
    _SAVE_WHY,
    _retroarch_config_at,
    check_local,
    head_reads_done,
    place_emulator_entries,
    place_relative_entries,
    place_save_entries,
    say_saves,
)
from installer.manifest import board_target
from installer.narrowing import (
    available_choices,
    designated_cores,
    find_by_hash,
    narrow,
    narrow_to_cores,
    one_per_slot,
    records_selection,
    truth_lists,
)
from installer.network import fetch_manifest, fetch_targets, local_targets
from installer.offline import LOCAL, offline_named
from installer.outcome import (
    CONFIRM_FROM_BYTES,
    DRIVE_FULL,
    EVERYTHING_IN_PLACE,
    ROMM_SCAN_WORDS,
    OfflineReason,
    OutcomeDetails,
    _absent_required,
    _check_fetch_line,
    _needed_lines,
    _offline_only,
    _report_outcome,
    _write_advice,
    needed_absent_words,
    not_installable_words,
    on_its_card,
)
from installer.pack import (
    _pack_refused,
    pack_holds_trees,
    pack_lacks,
    pack_lacks_words,
    pack_path,
    run_pack,
    split_pack_lines,
)
from installer.pack_source import NOT_IN_PACK, NOT_KEPT, NOT_WRITABLE, _folder_writable, pack_name_platforms
from installer.paths import _entry_path
from installer.plan import _check_free_space, _confirm, _print_plan, download_files
from installer.platform_choice import _line_setups, drive_example
from installer.record import (
    KEPT,
    _RECORD_TAKEN,
    apply_record,
    by_record,
    choice_given,
    drop_recorded,
    games_folder_kept,
    plan_kept,
    record_argv,
    record_day,
    record_file,
    record_menu_words,
    record_paths,
    setup_record,
    system_title,
    write_record,
)
from installer.setups import PORTABLE_ONLY, _default_dest, found_setups
from installer.standalone import _install_standalone_folders, do_standalone_copies, standalone_folders_here
from installer.tally import (
    CheckTally,
    _emit_check,
    _left_out_events,
    _left_out_lines,
    _os_name,
    _skipped,
    keep_declared,
    kinds_definition,
    leave_out_game_data,
    parts_words,
    tally,
)
from installer.terminal import OUTPUT, Progress, Terminal, detail
from installer.text import _plural, agree, format_size, screen_text

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


class _InstallRun:
    """What the stages of one run share: its options, the setups it installs
    for and the totals its end reads."""

    def __init__(self, args: argparse.Namespace, term: Terminal, os_type: str,
                 interactive: bool, listing: bool, packing: bool) -> None:
        self.args = args
        self.term = term
        self.os_type = os_type
        self.interactive = interactive
        self.listing = listing
        self.packing = packing
        # Options that choose the files themselves: no question chooses again,
        # and no board or game of the card narrows what they chose.
        self.chosen_by_flag = bool(args.find) or args.source == "truth"
        self.platforms: list[tuple[str, Path]] = []
        # A destination taken from the default table, the platform not being
        # found here, is only a guess.
        self.assumed_dests: set[Path] = set()
        # What detection found, with the screen's labels, and whether the setups
        # found are offered as its Where to install? screen offers them: always when
        # detection chose, and when a file list named the platform.
        self.setups: list = []
        self.mounted: set = set()
        self.offer = False
        self.app_cards: list[CardApp] = []
        self.target_lists: dict[str, dict] = {}
        self.cores_found: dict[tuple[str, Path], list[str]] = {}
        self.cores_searched: dict[tuple[str, Path], list[Path]] = {}
        self.total_downloaded = 0
        self.total_up_to_date = 0
        self.total_errors = 0
        self.total_omitted = 0
        self.omitted_seen: list[dict] = []
        self.left_out_seen: list[dict] = []
        self.version_notes: list[str] = []
        self.total_interrupted = False
        self.total_bytes = 0
        self.total_seconds = 0.0
        self.total_declined = 0
        # Files --offline left out at a terminal: missing, never "as answered".
        self.total_offline = 0
        # Of those, the wrong copies left in place: the result names them apart
        # from the files still missing, as --check does.
        self.total_wrong_left = 0
        # The BIOS list's files it left out, wrong copies aside: the result
        # counts them by kind.
        self.offline_left: list[dict] = []
        self.check_pending = 0
        self.total_verified = 0
        self.files_pending = 0
        self.failures: list[tuple[str, str]] = []
        self.installed_paths: list[Path] = []
        self.bulk_lines: list[str] = []
        # The entries installed and the data tree files: the end line counts
        # BIOS files and game data among them, the data files apart.
        self.landed: list[dict] = []
        self.data_landed = 0
        self.categorized = False
        # The BIOS folders read for misplaced files, one per platform.
        self.bios_indexes: list[FolderIndex] = []


def _start_install(args: argparse.Namespace, real_stdout: TextIO) -> _InstallRun:
    """The run's options completed, its terminal and its local sources opened."""
    KEPT.reset()
    # A namespace built by a caller that predates --for-games has neither.
    args.for_games = getattr(args, "for_games", None)
    args.required_only = getattr(args, "required_only", False)
    for name, default in (("one_per_slot", False), ("standalone", False), ("source", "full"),
                          ("find", None), ("json", False)):
        setattr(args, name, getattr(args, name, default))
    term = Terminal(real_stdout, quiet=args.quiet)
    interactive = sys.stdin.isatty() and not args.no_input and not args.quiet
    listing = (args.list_targets or args.list_systems or args.list_cores
               or args.list_emulators)
    if interactive and not _is_terminal(real_stdout):
        # A question goes to stdout: sent to a file, it waited on an answer
        # to a prompt nobody could see.
        interactive = False
        if not listing and not args.check:
            kind = _output_kind(real_stdout)
            where = f"Output goes to a {kind}" if kind else "Output is not a terminal"
            undo = "the pipe" if kind == "pipe" else "the redirection"
            print(f"{where}, so nothing is asked. Add --no-input to say so, or run it "
                  f"without {undo} to answer.", file=sys.stderr)
    OUTPUT.verbose = bool(getattr(args, "verbose", False))
    OUTPUT.where_said = False
    detail(f"{term.bold('RetroBIOS')} {term.dim(installer_id())}\n")

    os_type = detect_os()
    if os_type == "wsl":
        _enter_wsl()
        _wsl_dest(args)
    _open_local_sources(args)
    # --pack: the files go into a ZIP for another device, no folder of this
    # machine is read or written, and nothing is asked.
    packing = getattr(args, "pack", None) is not None
    if packing:
        interactive = False
        if args.platform is None:
            spelled = pack_name_platforms(Path(os.path.expanduser(str(args.pack))).name)
            if len(spelled) != 1:
                print("Error: name the platform the pack is for with --platform.",
                      file=sys.stderr)
                sys.exit(2)
            args.platform = spelled[0]
    return _InstallRun(args, term, os_type, interactive, listing, packing)


def _print_platform_list(os_type: str) -> None:
    """--list-platforms: the file lists, the systems and the setups found here."""
    print("Available platforms:")
    for p in AVAILABLE_PLATFORMS:
        print(f"  {p}")
    print("\nSystems recognized by their own files, and the file list each gets "
          "(--platform takes either name):")
    for line in _system_lines():
        print(f"  {line}")
    print("\nNo BIOS folder of their own, each emulator reading its own (run without "
          "--platform):")
    print(f"  {', '.join(_NO_BIOS_FOLDER)}")
    detected = detect_platforms(os_type)
    if detected:
        print("\nDetected on this system:")
        for name, path in detected:
            system = detected_os(name, path)
            print(f"  {name}: {path}" + (f" ({system})" if system else ""))
    else:
        print("\nDetected on this system: none")


def _named_by_list_only(run: _InstallRun) -> NoReturn:
    """Stop a run without questions whose file list named a setup not found here."""
    args = run.args
    # The list names the files, not the setup they are for: a
    # RetroArch list serves a computer and a dozen handheld cards.
    # Without questions nothing found here stops, as without a list,
    # where --yes filled this computer's default folder.
    # Said as the stop without a list is said, and of the pack where
    # a pack was named: "the file list" was one the user never gave.
    source = ("the pack" if LOCAL.pack is not None and LOCAL.manifest is None
              else "the file list")
    message = (f"No supported platform detected: {display_name(args.platform)} was "
               f"not found here, and {source} does not say where it goes")
    EVENTS.emit("error", stage="detect", reason="not_found", platform=args.platform,
                message=message)
    print(f"  {message}.", file=sys.stderr)
    hint = Invocation()
    hint.os_type, hint.options = run.os_type, _INVOCATION.options
    example = _default_dest(run.os_type, args.platform)
    # The run's own way of answering, kept: a script copying the
    # example stopped at a question.
    answered = "".join(f" {flag}" for flag, on in (
        ("--yes", args.yes), ("--no-input", args.no_input)) if on)
    print("  Name its folder with --dest, for example:\n    "
          + hint.command(args.platform, example if example is not None
                         else "<its BIOS folder>") + answered, file=sys.stderr)
    sys.exit(1)


def _named_setup_default(run: _InstallRun) -> list[tuple[str, Path]]:
    """A named platform not found here, nothing asked: its default folder,
    or the run stops on how to name one."""
    args = run.args
    if getattr(args, "platform_from_list", False):
        _named_by_list_only(run)
    if args.platform in PORTABLE_ONLY:
        # A portable emulator reads the folder beside its executable:
        # any default would be a folder it never opens.
        EVENTS.emit("error", stage="detect", reason="not_found", platform=args.platform,
                    message=f"Platform '{args.platform}' not found. "
                    f"{PORTABLE_ONLY[args.platform]}")
        print(
            f"  Platform '{args.platform}' not found. {PORTABLE_ONLY[args.platform]} "
            f"Name it with --dest, for example: --platform {args.platform} "
            f"--dest '<BizHawk folder>{os.sep}Firmware'",
            file=sys.stderr,
        )
        sys.exit(1)
    if args.platform in _SHARE_FOLDERS:
        # Its own folder exists on the Batocera machine alone, which
        # detection would have found: here /userdata/bios was taken, and
        # the run ended on "Cannot create" with no event saying why.
        message = (f"Platform '{args.platform}' not found here. "
                   f"{share_words(args.platform)}")
        EVENTS.emit("error", stage="detect", reason="not_found", platform=args.platform,
                    message=message)
        example = drive_example(run.os_type, "SHARE", "bios", args.platform)
        print(f"  {message} Name it with --dest, for example: --platform "
              f"{args.platform} --dest {example}", file=sys.stderr)
        sys.exit(1)
    default_dest = _default_dest(run.os_type, args.platform)
    if default_dest is None:
        where = ("where this user can look, and its default folder may not be "
                 "the one it reads" if _default_set_aside(run.os_type, args.platform)
                 else "and no folder on this system is one it reads")
        message = f"Platform '{args.platform}' not found {where}"
        EVENTS.emit("error", stage="detect", reason="not_found",
                    platform=args.platform, message=message)
        print(
            f"  {message}. Name it with --dest, for example: "
            f"--platform {args.platform} --dest <its BIOS folder>",
            file=sys.stderr,
        )
        sys.exit(1)
    print(
        f"  Platform '{args.platform}' not detected, "
        f"using default path: {default_dest}"
    )
    run.assumed_dests.add(default_dest)
    return [(args.platform, default_dest)]


def _detect_named_setup(run: _InstallRun, named: str) -> list[tuple[str, Path]]:
    """The setups of the platform named with --platform and no --dest."""
    args, os_type, interactive = run.args, run.os_type, run.interactive
    detail("Looking for setups here...")
    if not run.listing:
        # The cards mounted here too, as the screen finds them, with or
        # without questions: a pack's RetroArch list went to this
        # computer's folder past the Onion card it was downloaded for,
        # and --yes did so after the screen had found the card.
        run.setups, run.mounted = found_setups(os_type)
        detected = [(name, path) for name, path, _label in run.setups]
    else:
        detected = detect_platforms(os_type)
    bound = card_bound(named, args.platform)
    # A system that runs from its card is found only on the device:
    # Onion named on a PC matched the PC's own RetroArch.
    matched = [(n, p) for n, p in detected if n == args.platform
               and (bound is None or detected_os(n, p) == bound[0])]
    if matched:
        run.offer = getattr(args, "platform_from_list", False)
        for name, path in matched:
            detail(fold_line(f"  Found {found_label(name, path)}"))
        return matched
    if run.listing:
        # A listing reads the manifest and writes nothing: no folder is
        # needed, and asking BizHawk's for one refused a question asked
        # before downloading BizHawk.
        return [(args.platform, _default_dest(os_type, args.platform) or Path.cwd())]
    if bound is not None:
        # Its files go on its SD card, which is never this machine's
        # own folder.
        return [(args.platform, card_install_dest(
            named, args.platform, interactive,
            not (args.check or args.dry_run or args.yes)))]
    if interactive and getattr(args, "platform_from_list", False) and len(
            _line_setups(run.setups, run.mounted, os_type)) > 1:
        # A list or a pack that card setups read too: they are offered,
        # RetroArch first, as the screen offers them. Its folder question
        # alone left ArkOS, muOS and JELOS out of reach.
        print(f"  {display_name(args.platform)} was not found here.")
        return _prompt_manual_platform(
            os_type, not (args.check or args.dry_run or args.yes), True,
            f"Which setup is the {display_name(args.platform)} list for?", run.setups,
            run.mounted)
    if interactive:
        # Asked as the screen asks, never taken: the default folder was
        # filled with a card mounted in the reader, and with nothing
        # found here, without a question.
        print(f"  {display_name(args.platform)} was not found here.")
        return [(args.platform, ask_platform_folder(
            os_type, args.platform, not (args.check or args.dry_run or args.yes)))]
    return _named_setup_default(run)


def _nothing_detected(run: _InstallRun) -> bool:
    """No setup found and none named: the standalone folders, a question or
    a stop. True when the run is over."""
    args, os_type = run.args, run.os_type
    # The screen's words where a person answers: "platform" was said
    # nowhere else.
    print("  Nothing was found here." if run.interactive and not run.listing
          else "  No supported platform detected.")
    EVENTS.emit("detect", os=os_type, os_name=_os_name(), platforms=[])
    # Standalone emulators read their BIOS from folders of their own,
    # which the file lists name: an ES-DE user with DuckStation and
    # PCSX2 was sent to RetroArch's folder, which nothing here reads.
    narrowing = (args.system or args.core or args.emulator or args.region
                 or args.target or args.installed_cores or args.declared_only)
    if not run.listing and not narrowing and _install_standalone_folders(
        args, os_type, run.term, run.interactive
    ):
        return True
    if not run.interactive or run.listing:
        asked = next((flag for flag, on in (
            ("--list-systems", args.list_systems), ("--list-cores", args.list_cores),
            ("--list-emulators", args.list_emulators),
            ("--list-targets", args.list_targets),
        ) if on), "")
        for line in _manual_usage_hint(os_type, asked):
            print(line)
        sys.exit(1)
    # A folder typed, or a card's root, is checked there.
    # Said once, by the detection line above: "Nothing was found
    # here." came twice, and after "A card is in the reader"
    run.platforms = _prompt_manual_platform(
        os_type, not (args.check or args.dry_run or args.yes), check_typed=True,
        title="Which setup?")
    run.offer = False
    return False


def _detect_any_setup(run: _InstallRun) -> bool:
    """The setups found here, no platform and no folder named. True when
    the run is over."""
    detail("Looking for setups here...")
    frontends = detect_frontends(run.os_type)
    if "esde" in frontends:
        detail("  Found ES-DE (BIOS files go to each emulator, not to ES-DE itself)")
    if "launchbox" in frontends:
        detail("  Found LaunchBox")
    if not run.listing:
        # A card mounted here is found as the screen finds it, in every
        # mode: line mode said "No supported platform detected" beside
        # an Onion card, and --yes filled this computer's folder.
        run.setups, run.mounted = found_setups(run.os_type)
        run.platforms = [(name, path) for name, path, _label in run.setups]
        run.offer = run.interactive
    else:
        run.platforms = detect_platforms(run.os_type)
    if not run.platforms:
        return _nothing_detected(run)
    for name, path in run.platforms:
        detail(fold_line(f"  Found {found_label(name, path)}"))
    return False


def _detect_setups(run: _InstallRun) -> bool:
    """The setups the run is for, detected or named. True when the run is over."""
    args = run.args
    # Platform detection or override.
    named = args.platform or ""
    if args.platform:
        args.platform = normalize_platform(args.platform, say=args.verbose)
    if args.dest:
        plat, args.dest = card_dest(named, args.platform or "", args.dest)
        args.platform = plat or args.platform
    if run.packing:
        # Where the pack goes stands for the folder: nothing is read there.
        run.platforms = [(args.platform, pack_path(args.pack, args.platform, False).parent)]
    elif args.platform and args.dest:
        run.platforms = [(args.platform, args.dest)]
    elif args.platform:
        run.platforms = _detect_named_setup(run, named)
    elif args.dest:
        detail(f"  Using destination: {args.dest}")
        plat, args.dest = _platform_for_dest(run.os_type, args.dest,
                                             run.interactive and not run.listing)
        run.platforms = [(plat, args.dest)]
    else:
        return _detect_any_setup(run)
    return False


def _choose_setups(run: _InstallRun) -> None:
    """The setups found narrowed to the one a person chooses, or the run
    stops on what to name."""
    args = run.args
    if len(run.platforms) > 1 and not run.interactive and not run.listing:
        # A run without questions installs for one setup, the one a person
        # would have chosen: --yes beside two setups filled both, 14 GB in
        # two folders, where its help says it stops on what to name.
        _several_found(run.platforms, run.setups)
    if run.platforms and not run.packing:
        EVENTS.emit("detect", os=run.os_type, os_name=_os_name(), platforms=[
            {"platform": name, "name": display_name(name), "bios_dir": str(path)}
            for name, path in run.platforms
        ])

    if (len(run.platforms) > 1 or run.offer) and not run.listing and run.interactive:
        # --check installs nothing, and "Install for:" said it would.
        ask = not (args.check or args.dry_run or args.yes)
        run.platforms = _prompt_platform_choice(
            run.platforms, "Check:" if args.check else "Install for:",
            {(name, path): label for name, path, label in run.setups},
            lambda: _prompt_manual_platform(run.os_type, ask, True, "Which setup?",
                                            run.setups, run.mounted))
    # --add-app names a card for each folder, or the run stops here.
    run.app_cards = app_refusal(args, run.platforms)


def _remember_install(args: argparse.Namespace, plat: str, folder: Path, manifest: dict,
                      written: list[dict], games: bool) -> None:
    """Record what this install placed in folder and the choice it made,
    games being the card's games applied with no --for-games."""
    if not written and setup_record(plat, folder)[0] is None:
        # Nothing of ours is there to record, and no choice to keep.
        return
    # A games folder is kept only where the next run reads it from a
    # record (games_folder_kept): elsewhere the card's own games are.
    options = [(flag, value if flag != "--for-games" or not value
                else os.path.abspath(value)
                if games_folder_kept(os.path.abspath(value), folder) else None)
               for flag, value in _INVOCATION.flags(plat)]
    if games:
        options += [("--for-games", None),
                    *([("--required-only", None)] if args.required_only else [])]
    choice = record_argv(options)
    path, setup, problem = write_record(folder, plat, manifest, choice, written)
    if problem:
        detail(f"  {problem}.")
    count = len(setup["files"])
    EVENTS.emit("record", platform=plat, folder=str(folder),
                path=str(path or record_paths(folder)[0]),
                status="not_written" if problem else "written", choice=choice,
                date=setup["written"], files=count,
                message=f"{problem}." if problem else
                f"Recorded {_plural(count, 'file')} and this choice in {path}.")


def _check_run_target(run: _InstallRun) -> None:
    """--target checked for every platform, before anything is written."""
    args, platforms = run.args, run.platforms
    # --target is checked for every platform before anything is written, as
    # --installed-cores is below: EmuDeck installed 3.2 GB and only then was
    # steamos refused for RetroArch, with no summary of what had landed.
    if args.target and by_record(args) and len(platforms) == 1:
        # The screen's runs carry the record's options as typed ones.
        plat = platforms[0][0]
        if LOCAL.offline and local_targets(plat) is None and plat in TARGET_PLATFORMS:
            drop_recorded(args, plat, "--target", "the board list needs the internet")
        else:
            with contextlib.redirect_stderr(io.StringIO()):
                known = fetch_targets(plat)
            if known is None or args.target not in known:
                drop_recorded(args, plat, "--target", "the board list does not name it"
                              if known is not None else "the board list could not be read")
    if args.target:
        for plat_name, _bios_path in platforms:
            targets = fetch_targets(plat_name)
            if targets is None:
                sys.exit(1)
            run.target_lists[plat_name] = targets
            if args.target not in targets:
                _unknown_target(args.target, plat_name, targets, *(
                    ["  Nothing was installed. Name one platform with "
                     "--platform to install it alone."] if len(platforms) > 1 else []))


def _check_run_romm(run: _InstallRun) -> None:
    """--romm-firmware applied or refused, never ignored."""
    args = run.args
    if args.romm_firmware is None:
        return
    # Applied or refused, never ignored.
    if not any(name == "romm" for name, _path in run.platforms):
        print("Error: --romm-firmware applies to RomM, which this run does not "
              "install for.", file=sys.stderr)
        sys.exit(1)
    try:
        parse_romm_firmware(args.romm_firmware)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def _check_run_cores(run: _InstallRun) -> None:
    """The cores installed for each setup, read before anything is written."""
    args = run.args
    # Every check --installed-cores makes before anything is written: a
    # refusal for the second platform must not follow an install of the first.
    for plat_name, bios_path in [] if run.packing else run.platforms:
        if plat_name in CORE_PLATFORMS:
            if args.cores_dir:
                _check_cores_dir(args.cores_dir)
            searched = [args.cores_dir] if args.cores_dir else core_dirs(plat_name, bios_path)
            run.cores_found[(plat_name, bios_path)] = installed_cores(searched)
            run.cores_searched[(plat_name, bios_path)] = searched
        elif args.installed_cores and by_record(args):
            drop_recorded(args, plat_name, "--installed-cores",
                          f"{plat_name} ships its cores with the system")
        elif args.installed_cores:
            print(
                f"Error: {plat_name} ships its cores with the system. "
                f"--installed-cores applies to {', '.join(CORE_PLATFORMS)}",
                file=sys.stderr,
            )
            sys.exit(1)
        if args.installed_cores and not run.cores_found[(plat_name, bios_path)]:
            if by_record(args):
                drop_recorded(args, plat_name, "--installed-cores", "no core is installed")
            else:
                _no_core_found(plat_name, bios_path, searched)


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


def _pass_romm_layout(run: _InstallRun, p: _PlatformPass) -> None:
    """RomM's firmware laid out under its library, as --romm-firmware says."""
    bios_path = p.bios_path
    try:
        layout = romm_firmware_layout(bios_path, run.args.romm_firmware)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    if layout is not None:
        p.files, library = romm_relayout(p.files, bios_path, *layout)
        if library != bios_path:
            run.installed_paths[run.installed_paths.index(bios_path)] = library
            detail(f"  Firmware laid out as {'/'.join(layout[0] + ('{platform}',) + layout[1])} "
                   f"under {library}")
            p.bios_path = library


def _drop_stale_parts(bios_path: Path, entries: list[dict]) -> None:
    """Remove the partial copy left beside each file now in place."""
    for entry in entries:
        try:
            stale = _entry_path(bios_path, entry)
        except ValueError:
            continue
        stale = stale.parent / f".{stale.name}.part"
        if stale.is_file():
            stale.unlink()


def _pass_check_existing(run: _InstallRun, p: _PlatformPass) -> None:
    """The setup's folder checked, and where each missing file comes from."""
    args, bios_path, files = run.args, p.bios_path, p.files
    detail("\nChecking existing files...")
    to_download, up_to_date, mismatched = check_local(
        files, bios_path, jobs=args.jobs, term=run.term
    )
    present = len(up_to_date) + len(mismatched)
    # The screen's words: "0/22 present (0 verified, 0 wrong hash)"
    # beside its "0 in place, 22 missing, 0 wrong copies". The data files
    # the head counts are among them, as the screen counts them.
    wrong = len(mismatched)
    # Each data tree read and hashed once in the run: the count here,
    # the check, the events, the plan and the install read this.
    p.data_states = data_states = [(entry, data_directory_state(entry, bios_path))
                                   for entry in p.data_dirs]
    head_reads_done()
    p.trees_missing = trees_missing = sum(len(state[1]) for _entry, state in data_states)
    trees_held = p.head_data - trees_missing
    detail(f"  {len(up_to_date) + trees_held} in place, "
           f"{p.run_counts.files - present + trees_missing} missing, "
           f"{_plural(wrong, 'wrong copy')}")

    # A partial copy left by an interrupted run is useless once the file
    # is in place: it goes.
    _drop_stale_parts(bios_path, up_to_date)

    # Mismatched files need re-download
    to_download.extend(mismatched)
    p.to_download, p.up_to_date, p.mismatched = to_download, up_to_date, mismatched
    # The files this machine already holds: misplaced in the BIOS folder
    # (bios/bios/, a pack extracted into a folder of its own, a name in
    # capitals, still zipped), or in a folder named with --from.
    p.bios_index = bios_index = (bios_folder_index(bios_path, files, up_to_date)
                                 if to_download else None)
    if bios_index is not None:
        run.bios_indexes.append(bios_index)
    p.copies = copies = plan_local_copies(to_download, bios_path, bios_index, LOCAL.folders)
    p.unread = unread = unreadable_copies(to_download, copies, LOCAL.folders)
    selection = p.selection
    p.hint = [] if LOCAL.pack is not None else bulk_hint(
        to_download, p.manifest,
        systems_chosen=bool(selection and selection[0]),
        cores_chosen=bool((selection and selection[1]) or args.emulator
                          or args.installed_cores or p.target),
        accepted=p.core_choices,
    )

    if EVENTS.on:
        _emit_check(
            p.plat_name, p.manifest, bios_path,
            CheckTally(files, up_to_date, mismatched,
                       sum(len(state[1]) for _entry, state in data_states),
                       len(p.omitted_files),
                       sum(data_fetch_bytes(entry, state[1]) for entry, state in data_states)),
            chosen=selection[0] if selection else None,
        )
        emit_copies(p.plat_name, to_download, copies, bios_index, bios_path, files)
        emit_unreadable(p.plat_name, unread)
    run.total_verified += len(up_to_date)


def _pass_check_missing(run: _InstallRun, p: _PlatformPass) -> None:
    """--check: the files not in place named, and how to get them."""
    args, bios_path = run.args, p.bios_path
    to_download, mismatched, copies = p.to_download, p.mismatched, p.copies
    # Named, not only counted: a user looking for the one bad
    # BIOS learned "1 files need downloading" and nothing else.
    # A wrong hash comes first and always in full: listed after
    # 8000 missing files, it hid behind "... and 8059 more".
    wrong = {id(entry) for entry in mismatched}
    missing = [entry for entry in to_download if id(entry) not in wrong]
    # A pack extracted from some of its parts: the part is named
    # before the hundreds of files it holds.
    for line in split_pack_lines(bios_path):
        print(line)
    offline = _offline_only()
    # What the pack lacks is said before the count, as the
    # screen says it.
    lacking = pack_lacks([f for f in to_download if id(f) not in copies])
    if lacking:
        print(f"\n  {pack_lacks_words(len(lacking), len(to_download) - len(copies))}")
    # One total with the count above it, the data files among
    # them as the screen counts them: "0 in place, 10805 missing"
    # stood over "8164 files to download".
    # The count and the folder by default, each file with
    # --verbose: 20 paths hid the line saying what to do.
    print(f"\n  {_plural(len(to_download) + p.trees_missing, 'file')} "
          + ("not in place." if offline or LOCAL.pack is not None
             else "to download."))
    for line in check_lines(missing, mismatched, p.files, p.manifest, bios_path,
                            args.verbose, CheckHeld(p.up_to_date, p.bios_index, copies)):
        print(line)
    for line in unreadable_lines(p.unread, args.verbose):
        print(line)
    print(f"  BIOS folder: {shown_path(bios_path)}")
    # The data files need the internet too: offline, "8164 files
    # need the internet" stood under "10805 files not in place".
    trees_fetched = p.trees_missing if LOCAL.pack is None else 0
    print(_check_fetch_line(len(to_download) - len(copies) + trees_fetched,
                            "the BIOS folder", len(lacking), bool(mismatched)))
    run.check_pending += len(to_download)


def _pass_check_report(run: _InstallRun, p: _PlatformPass) -> None:
    """--check: what the setup's folder holds and lacks."""
    args, plat_name, bios_path = run.args, p.plat_name, p.bios_path
    if p.to_download:
        _pass_check_missing(run, p)
    elif p.trees_missing:
        # The screen's headline: "Everything is in place." stood
        # above "0/169 data files present" and exit code 1.
        print(f"\n  {_plural(p.trees_missing, 'data file')} to fetch")
    else:
        print(f"\n  {EVERYTHING_IN_PLACE}")
        print(f"  BIOS folder: {shown_path(bios_path)}")
    if plat_name in _RECORD_TAKEN:
        # The files counted are the recorded choice's, not the list's.
        print(f"  {record_menu_words(_RECORD_TAKEN[plat_name])} "
              "--all-files checks every file.")
    absent = _absent_required(p.omitted_files, bios_path)
    # The collection cannot supply these, so they leave the exit
    # code alone, but a user asking why a game will not start needs
    # their count, and with --verbose their names, and which system
    # and emulator each one is for.
    if absent and not OUTPUT.verbose:
        print(f"  {needed_absent_words(len(absent), '--verbose')}")
    for line in _needed_lines(
        absent, "Not in the collection and absent here, needed to start an emulator",
        every=args.verbose,
    ):
        detail(line)
    for entry, (_root, needed, present) in p.data_states:
        if needed:
            detail(f"  {entry['ref']}: {present}/{len(entry['files'])} data files "
                   f"present, {len(needed)} to fetch")
            run.check_pending += len(needed)


def _pass_dry_run(run: _InstallRun, p: _PlatformPass) -> None:
    """--dry-run: the plan of what an install would write."""
    args, bios_path, to_download, copies = run.args, p.bios_path, p.to_download, p.copies
    run.files_pending += len(to_download)
    trees = [(entry, state[1]) for entry, state in p.data_states]
    # A data file in place with other contents is kept like a BIOS file.
    kept = plan_kept(p.mismatched + [
        {"dest": f"{entry['dest']}/{rel}" if entry.get("dest") else rel}
        for entry, needed in trees for rel in needed
    ], bios_path)
    planned = [f for f in to_download if id(f) not in copies]
    # Said before the plan promises a count and a size, as an
    # install says it: the dry run promised 23 files where the pack
    # held 20.
    lacking = {id(f) for f in pack_lacks(planned)}
    if lacking:
        print(f"\n  {pack_lacks_words(len(lacking), len(planned))}")
    _print_plan([f for f in planned if id(f) not in lacking], bios_path, run.term,
                trees, kept, copy_plan_lines(to_download, copies, p.bios_index,
                                             bios_path, p.files, args.verbose, True),
                verbose=args.verbose, manifest=p.manifest)
    if p.plat_name in _RECORD_TAKEN:
        print(f"  {record_menu_words(_RECORD_TAKEN[p.plat_name])} "
              "--all-files lists every file.")
    for line in unreadable_lines(p.unread, args.verbose):
        print(line)
    for line in p.hint:
        print(line)


def _pass_offline_left(run: _InstallRun, p: _PlatformPass, fetched: list[dict]) -> None:
    """--offline: the files to fetch counted missing, the copies kept to do."""
    # The screen offers no Install for these: the question asked
    # to download 6.6 GB that --offline never fetches. With --yes,
    # the screen's own install, each one was "downloading", then
    # FAILED, and the summary listed it pending and failed at once.
    # Counted, never said here: the summary says it once.
    # Not done: the summary counts them as missing.
    run.files_pending += len(fetched)
    run.total_offline += len(fetched)
    wrong_ids = {id(entry) for entry in p.mismatched}
    run.total_wrong_left += sum(1 for f in fetched if id(f) in wrong_ids)
    run.offline_left += [f for f in fetched if id(f) not in wrong_ids]
    p.to_download = [f for f in p.to_download if id(f) in p.copies]


def _pass_declined(run: _InstallRun, p: _PlatformPass, fetch_size: int) -> bool:
    """The size question, where one is asked. True when it was declined."""
    args = run.args
    if (
        run.interactive
        and not args.yes
        and fetch_size >= CONFIRM_FROM_BYTES
        and not _confirm(
            f"\nCopy {format_size(fetch_size)} from the pack to "
            f"{shown_path(p.bios_path)}? [Y/n] " if LOCAL.pack is not None
            else f"\nDownload {format_size(fetch_size)} to "
            f"{shown_path(p.bios_path)}? [Y/n] "
        )
    ):
        # A beginner who just passed the c entry was sent to a
        # 91-line --help.
        print(p.smaller or "  Nothing downloaded. --system, --core and --region "
              "install less (see --help).")
        run.total_up_to_date += len(p.up_to_date)
        run.total_declined += len(p.to_download)
        run.files_pending += len(p.to_download)
        return True
    return False


def _pass_copy_line(run: _InstallRun, p: _PlatformPass, fetched: list[dict],
                    lacking: set[int], dl_size: int) -> None:
    """The copies from this machine planned, and the line that opens them."""
    copies, bios_index = p.copies, p.bios_index
    detail()
    for line in copy_plan_lines(p.to_download, copies, bios_index, p.bios_path,
                                p.files, run.args.verbose, False):
        detail(line)
    held = len(fetched) - len(lacking)
    rest = (f" and {'copying' if LOCAL.pack is not None else 'downloading'} "
            f"{held}" if held else "")
    where = f" from {LOCAL.pack.name}" if fetched and LOCAL.pack is not None else ""
    # Named by the folder they come from, as the line above
    # names it: "found on this machine" followed "from E:\".
    sources = list(dict.fromkeys(copy.index.label for copy in copies.values()))
    named = ", ".join(screen_text(shown_path(label)) for label in sources)
    origin = (f"from {named}" if all(
        copy.index is not bios_index for copy in copies.values())
        else "found on this machine")
    # The size beside what it weighs: after "and downloading
    # 19" it read as theirs alone.
    sized = f" ({format_size(dl_size)})"
    detail(f"\nCopying {_plural(len(copies), 'file')}{'' if rest else sized} "
           f"{origin}{rest}{where}{sized if rest else ''}...")


def _pass_download_head(run: _InstallRun, p: _PlatformPass, fetched: list[dict],
                        lacking: set[int], dl_size: int) -> None:
    """The lines an install opens on: what comes, from where, to where."""
    args, plat_name, bios_path = run.args, p.plat_name, p.bios_path
    if not p.menu:
        # What happens and where, the two lines a run without questions
        # opens on: the menu's head said them where it was asked.
        coming = len(p.to_download) - len(lacking) + p.trees_missing
        weight = dl_size + sum(data_fetch_bytes(entry, state[1])
                               for entry, state in p.data_states)
        taken = _RECORD_TAKEN.get(plat_name)
        print(f"\nInstalling {_plural(coming, 'file')} ({format_size(weight)}) for "
              f"{detected_shown(plat_name, bios_path) or p.display}"
              + (", what the games need" if p.games_applied else "")
              + (f", same choice as on {record_day(taken)}" if taken else "") + ".")
        print(f"BIOS folder: {shown_path(bios_path)}")
        OUTPUT.where_said = True
    if p.unread:
        # A file of the user's that could not be read is said in
        # every mode: it was expected to be copied.
        print()
        for line in unreadable_lines(p.unread, args.verbose):
            print(line)
    if p.copies:
        _pass_copy_line(run, p, fetched, lacking, dl_size)
    elif LOCAL.pack is not None:
        # The files the pack holds: "Copying 23 files (85.0 KB)" sat
        # beside the size of 20.
        detail(f"\nCopying {_plural(len(p.to_download) - len(lacking), 'file')} "
               f"({format_size(dl_size)}) from {LOCAL.pack.name}...")
    else:
        detail(f"\nDownloading {len(p.to_download)} files ({format_size(dl_size)})...")
    detail("  Press Ctrl+C to stop. Running the same command again "
           "carries on from here.")


def _pass_make_folder(run: _InstallRun, p: _PlatformPass, dl_size: int) -> bool:
    """The space checked and the BIOS folder made. True when it was created."""
    args, plat_name, bios_path = run.args, p.plat_name, p.bios_path
    # Checked before the folder is created: a run stopped for space
    # left an empty BIOS folder behind. The data trees count too,
    # written after the files on the same drive.
    _check_free_space(bios_path, dl_size + data_space_bytes(p.data_states), plat_name,
                      1 if run.total_downloaded else 2, on_its_card(plat_name, bios_path))
    p.space_checked = True
    created = not bios_path.exists()
    try:
        bios_path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        sys.stdout.flush()
        # Said to a script too: the run ended on code 2 with no error
        # and no summary, what was installed before it unsaid.
        EVENTS.emit("error", stage="dest", reason="not_writable", platform=plat_name,
                    message=f"{bios_path} cannot be created: {exc.strerror}")
        EVENTS.emit(
            "summary", mode=_event_mode(args), installed=run.total_downloaded,
            up_to_date=run.total_up_to_date, pending=run.files_pending + len(p.to_download),
            failed=[{"dest": dest, "reason": str(reason)} for dest, reason in run.failures],
            skipped=_skipped(run.omitted_seen), left_out=_left_out_events(run.left_out_seen),
            kept=KEPT.summary(), interrupted=False,
        )
        print(f"\nCannot create {bios_path}.", file=sys.stderr)
        print(f"  {exc.strerror}.", file=sys.stderr)
        print(_write_advice(bios_path, bios_path in run.assumed_dests, plat_name),
              file=sys.stderr)
        # The documented code for a folder that cannot be written,
        # as when it exists read-only. 1 once an earlier platform
        # of the run installed something.
        sys.exit(1 if run.total_downloaded else 2)
    if created:
        detail(f"  Created {shown_path(bios_path)}")
    return created


def _pass_fetch(run: _InstallRun, p: _PlatformPass, dl_size: int, created: bool) -> bool:
    """The files downloaded or copied and counted. True when interrupted."""
    args, plat_name, bios_path, to_download = run.args, p.plat_name, p.bios_path, p.to_download
    progress = Progress(len(to_download), dl_size, run.term)
    failed, interrupted = download_files(
        to_download, bios_path, jobs=args.jobs, verbose=args.verbose,
        term=run.term, progress=progress, copies=p.copies,
    )
    if created and not progress.installed:
        # Created for files none of which came: not left behind empty.
        try:
            bios_path.rmdir()
        except OSError as exc:
            if args.verbose:
                print(f"  {shown_path(bios_path)} stays: {exc.strerror}",
                      file=sys.stderr)
    run.bulk_lines += p.hint
    if plat_name == "romm" and progress.installed:
        run.bulk_lines.append(ROMM_SCAN_WORDS)
    run.total_downloaded += progress.installed
    # The end line tells BIOS files from game data, as the menu
    # counted them, over the files that landed: matched by the end
    # of a failed path, a.bin was dropped when x/a.bin failed.
    run.landed.extend(progress.landed)
    p.record_files += [record_file(entry, "copy" if id(entry) in p.copies
                                   else "pack" if LOCAL.pack is not None else "download")
                       for entry in progress.landed]
    run.files_pending += len(to_download) - progress.installed if interrupted \
        else len(failed)
    run.total_errors += len(failed)
    run.failures.extend(failed)
    run.total_bytes += progress.transferred()
    run.total_seconds += progress.elapsed()
    if interrupted:
        run.total_interrupted = True
        _remember_install(args, plat_name, bios_path, p.manifest, p.record_files,
                          p.games_applied and args.for_games is None)
    return interrupted


def _pass_download(run: _InstallRun, p: _PlatformPass) -> str:
    """The missing files installed: "go" carries on with the setup, "next"
    moves to the next one, "stop" ends the run."""
    fetched = [f for f in p.to_download if id(f) not in p.copies]
    if _offline_only() and fetched:
        _pass_offline_left(run, p, fetched)
        fetched = []
    # What the pack does not hold is said before a size is promised:
    # a pack older than the list gave "Copy 6.6 GB" and 8358 files
    # failed. They are still tried, and fail as
    # not in the pack, the size and the question leaving them out.
    lacking = {id(f) for f in pack_lacks(fetched)}
    if lacking:
        print(f"\n  {pack_lacks_words(len(lacking), len(fetched))}")
    if lacking and len(lacking) == len(p.to_download) and not pack_holds_trees(p.data_dirs):
        # Nothing here can come from the pack: no "Copying 0 files", no
        # folder made, each file failed as not in it.
        run.failures.extend((f["dest"], NOT_IN_PACK) for f in p.to_download)
        run.total_errors += len(p.to_download)
        run.files_pending += len(p.to_download)
        run.total_up_to_date += len(p.up_to_date)
        return "next"
    dl_size = sum(f.get("size", 0) for f in p.to_download if id(f) not in lacking)
    fetch_size = _bytes([f for f in fetched if id(f) not in lacking])
    if not p.to_download:
        run.total_up_to_date += len(p.up_to_date)
        if _offline_only():
            for _entry, (_root, needed, present) in p.data_states:
                run.total_up_to_date += present
                run.total_offline += len(needed)
                run.files_pending += len(needed)
        return "next"
    if _pass_declined(run, p, fetch_size):
        return "next"
    EVENTS.emit("download", platform=p.plat_name, files=len(p.to_download), bytes=dl_size)
    _pass_download_head(run, p, fetched, lacking, dl_size)
    created = _pass_make_folder(run, p, dl_size)
    return "stop" if _pass_fetch(run, p, dl_size, created) else "go"


def _pass_install_tree(run: _InstallRun, p: _PlatformPass, entry: dict,
                       state: tuple[Path, dict[str, dict], int]) -> None:
    """One data tree fetched or copied, and its line."""
    # Its archive is drawn as the BIOS files were, and counted
    # in the bytes and time the run ends on: 82 MB came in
    # silence and the end said 310.5 KB.
    fetching = bool(state[1]) and LOCAL.pack is None
    progress = Progress(len(state[1]), 0, run.term, events=False) if fetching else None
    try:
        counts = install_data_directory(entry, p.bios_path, state, progress)
    finally:
        if progress is not None:
            progress.finish()
            run.total_bytes += progress.transferred()
            run.total_seconds += progress.elapsed()
    run.total_downloaded += counts["installed"]
    run.data_landed += counts["installed"]
    p.record_files += [record_file(item, "pack" if LOCAL.pack is not None
                                   else "download", "data")
                       for item in counts.get("written", [])]
    run.total_up_to_date += counts["present"]
    if isinstance(counts["error"], OfflineReason):
        # Left out as the BIOS files above are: counted missing,
        # not as one failure per tree.
        detail(f"  {entry['ref']}: {counts['present']} already in place, "
               f"{agree(counts['absent'], 'needs', 'need')} the internet "
               f"({offline_named()})")
        run.total_offline += counts["absent"]
        run.files_pending += counts["absent"]
        return
    if not counts["error"]:
        # An archive that could not be read leaves every file
        # absent: "no longer in the source (the pack has them)"
        # said so of 218 files no source was asked for.
        line = f"  {entry['ref']}: {counts['installed']} installed, " \
               f"{counts['present']} already in place"
        if counts["changed"] or counts["absent"]:
            # From a pack, the pack is the source that lacks them.
            line += (f", {counts['changed'] + counts['absent']} not in "
                     f"{LOCAL.pack.name}" if LOCAL.pack is not None else
                     f", {counts['changed'] + counts['absent']} no longer in "
                     "the source (the pack has them)")
        detail(line)
    _pass_tree_failures(run, p, entry, counts)


def _pass_tree_failures(run: _InstallRun, p: _PlatformPass, entry: dict, counts: dict) -> None:
    """The failures of one data tree counted, and said where they are not."""
    if counts["error"] in (NOT_WRITABLE, DRIVE_FULL):
        if counts["error"] == DRIVE_FULL:
            print(f"  {entry['ref']}: {DRIVE_FULL} ({shown_path(p.bios_path)})",
                  file=sys.stderr)
        run.failures.append((entry["ref"], counts["error"]))
        run.total_errors += 1
    elif counts["error"]:
        print(f"  {entry['ref']}: could not read "
              f"{LOCAL.pack.name if LOCAL.pack is not None else entry['url']}: "
              f"{counts['error']}", file=sys.stderr)
        run.failures.append((entry["ref"], counts["error"]))
        run.total_errors += 1
    for rel, reason in counts["not_kept"]:
        where = f"{entry['dest']}/{rel}" if entry.get("dest") else rel
        run.failures.append((where, f"{NOT_KEPT} ({reason})"))
        run.total_errors += 1


def _pass_data_trees(run: _InstallRun, p: _PlatformPass) -> None:
    """The data trees the setup keeps, each one its folder can hold."""
    # A tree whose folder this user cannot write is not fetched: the
    # BIOS files above already said the cause and its remedy, and
    # each archive was named as unreadable.
    writable = []
    for entry, state in p.data_states:
        if state[1] and not _folder_writable(state[0]):
            run.failures.append((entry["ref"], NOT_WRITABLE))
            run.total_errors += 1
        else:
            writable.append((entry, state))
    if writable and not p.space_checked:
        # With every BIOS file in place, the trees alone: checked
        # before the first archive is written.
        _check_free_space(p.bios_path, data_space_bytes(writable), p.plat_name,
                          1 if run.total_downloaded else 2,
                          on_its_card(p.plat_name, p.bios_path))
    if writable:
        detail("\nData directories:")
    for entry, state in writable:
        _pass_install_tree(run, p, entry, state)


def _pass_standalone(run: _InstallRun, p: _PlatformPass) -> None:
    """The copies for standalone emulators, or the folders found that would take them."""
    args, manifest, os_type = run.args, p.manifest, run.os_type
    if (
        manifest.get("standalone_copies")
        and not args.check
        and args.standalone_copies
    ):
        print("\nStandalone emulators:")
        lb_root = launchbox_root(os_type)
        extra_dirs = launchbox_bios_dirs(lb_root) if lb_root else None
        copied, skipped, copy_failed = do_standalone_copies(
            manifest, p.bios_path, os_type, extra_dirs, run.failures
        )
        if copied or skipped or copy_failed:
            print(
                f"  {copied} copied, {skipped} skipped (folder not found or closed), "
                f"{copy_failed} failed"
            )
        run.total_errors += copy_failed
    elif manifest.get("standalone_copies") and not args.check:
        # Said only where it concerns this machine: "skipped" printed on
        # every run read as an incident, and named no emulator.
        lb_root = launchbox_root(os_type)
        folders = standalone_folders_here(
            manifest, os_type, launchbox_bios_dirs(lb_root) if lb_root else None
        )
        if folders:
            detail("\nStandalone emulator folders found here:")
            for folder in folders:
                detail(f"  {folder}")
            detail("  --standalone-copies also copies the BIOS files and keys "
                   "they read into them.")


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


def _apply_setup_files(run: _InstallRun, p: _PlatformPass) -> bool:
    """The setup's files packed, checked, planned or installed. True when
    the run stops there."""
    args = run.args
    if run.packing:
        sys.exit(run_pack(args, p.plat_name, p.manifest, p.files, p.omitted_files, p.data_dirs,
                          p.narrowed, run.term))

    if p.plat_name == "romm":
        _pass_romm_layout(run, p)

    _pass_check_existing(run, p)
    if args.check:
        _pass_check_report(run, p)
        return False
    if args.dry_run:
        _pass_dry_run(run, p)
        return False

    if p.to_download:
        step = _pass_download(run, p)
        if step != "go":
            return step == "stop"
    elif len(run.platforms) > 1:
        # One setup's run ends on "Done. Everything is in place.": said
        # here too, it came twice.
        print(f"\n  {EVERYTHING_IN_PLACE}")

    run.total_up_to_date += len(p.up_to_date)

    # Data trees the pack carries beside the files: Dolphin's Sys,
    # PPSSPP's assets. Fetched from their source archive, each file
    # checked against the hash the list records.
    if p.data_dirs and not run.total_interrupted:
        _pass_data_trees(run, p)

    _remember_install(args, p.plat_name, p.bios_path, p.manifest, p.record_files,
                      p.games_applied and args.for_games is None)

    if run.os_type == "android" and not args.check and hide_from_media_scanner(p.bios_path):
        detail(f"  Added {NOMEDIA} to {shown_path(p.bios_path)}: the gallery and music "
               "apps leave its images, sounds and videos out")

    # Standalone copies
    _pass_standalone(run, p)
    return False


def _install_setup(run: _InstallRun, plat_name: str, bios_path: Path) -> bool:
    """One setup of the run. True when the run stops there."""
    p = _select_setup_files(run, plat_name, bios_path)
    return p is not None and _apply_setup_files(run, p)


def _finish_install(run: _InstallRun, real_stdout: TextIO) -> None:
    """The run's summary event, its exit code and its result."""
    args, platforms = run.args, run.platforms
    sys.stdout = real_stdout
    if args.find and getattr(args, "json", False):
        # The matches are the answer: nothing was installed.
        sys.exit(4 if getattr(args, "find_failed", False) else 0)
    if not run.listing:
        EVENTS.emit(
            "summary", mode=_event_mode(args), installed=run.total_downloaded,
            up_to_date=run.total_verified if args.check or args.dry_run else run.total_up_to_date,
            pending=run.check_pending if args.check else run.files_pending,
            failed=[{"dest": dest, "reason": str(reason)} for dest, reason in run.failures],
            skipped=_skipped(run.omitted_seen), left_out=_left_out_events(run.left_out_seen),
            kept=KEPT.summary(), interrupted=run.total_interrupted,
        )
    # A check scripted as `--check && launch` reads the exit code only. Its
    # own code, 3: with 1, a check that found files missing could not be
    # told from a check that never ran (a list refused, a --from missing).
    if args.check and run.check_pending:
        sys.exit(3)
    if not args.check and not run.listing and not args.dry_run:
        _report_outcome(
            run.installed_paths,
            run.total_downloaded,
            run.total_up_to_date,
            run.total_errors,
            run.total_omitted,
            run.total_interrupted,
            details=OutcomeDetails(
                failures=run.failures,
                transferred=run.total_bytes,
                seconds=run.total_seconds,
                declined=run.total_declined,
                assumed=run.assumed_dests,
                omitted_entries=run.omitted_seen,
                platform_of={path: plat for plat, path in platforms},
                hints=run.bulk_lines,
                kinds=((tally(run.landed), run.data_landed) if run.categorized else None),
                same_choice=(_INVOCATION.command(*platforms[0])
                             if run.interactive and len(platforms) == 1 else ""),
                sources=_run_sources(run.bios_indexes, run.total_downloaded,
                                     run.total_offline - run.total_wrong_left,
                                     run.total_wrong_left, run.total_errors),
                offline=run.total_offline,
                notes=run.version_notes,
                missing=tally(run.offline_left) if run.categorized else None,
            ),
            term=run.term,
        )
        finish_app(args, platforms, run.app_cards, run.interactive and not run.total_declined)


def _install(args: argparse.Namespace, real_stdout: TextIO) -> None:
    """One run of the installer, once the options are read."""
    run = _start_install(args, real_stdout)

    # Early exit for listing
    if args.list_platforms:
        _print_platform_list(run.os_type)
        return

    if _detect_setups(run):
        return
    _choose_setups(run)

    if args.dest is not None and not run.listing:
        _missing_dest(args.dest, run.interactive and not (args.check or args.dry_run or args.yes))
    elif not run.listing and not run.packing:
        # A system_directory under /root read from retroarch.cfg, run without
        # sudo: the case probe raised PermissionError before any line.
        for name, path in run.platforms:
            found_in = _retroarch_config_at(path)
            named = (f"used by default, since {display_name(name)} was not found"
                     if path in run.assumed_dests
                     else f"{found_in[0]} names" if found_in else "detected here")
            # One setup by now: two found without questions stopped above.
            _refuse_closed(path, f"{named} (name another with --dest)")
            _refuse_file(path, f"{named} (name another with --dest)")

    # The choice the folder's record keeps is the plan's first choice, taken
    # as its options would be: before the checks of --target and
    # --installed-cores, which it may hold. Never where the command line
    # chose, nor for a run over several setups.
    _RECORD_TAKEN.clear()

    if len(run.platforms) == 1 and not run.listing and not run.packing \
            and not choice_given(args):
        apply_record(args, *run.platforms[0])

    _check_run_target(run)
    _check_run_romm(run)
    _check_run_cores(run)

    for plat_name, bios_path in run.platforms:
        if _install_setup(run, plat_name, bios_path):
            break

    _finish_install(run, real_stdout)


def _run_sources(bios_indexes: list[FolderIndex], installed: int, missing: int,
                 wrong: int = 0, failed: int = 0) -> str:
    """The end line saying which folder gave how many of the files: missing
    the files left out, wrong the wrong copies left in place, failed the
    files the run could not write or fetch."""
    folders = [(index.label, index.copied) for index in LOCAL.folders]
    fixed = sum(index.fixed for index in bios_indexes)
    shared = sum(index.copied for index in bios_indexes)
    fetched = installed - fixed - shared - sum(count for _label, count in folders)
    return sources_line(folders, fixed, max(fetched, 0), missing,
                        "copied from the pack" if LOCAL.pack is not None else "downloaded",
                        shared, wrong, failed)


TUI_MIN_ROWS = 12
# Text stops growing past this width: on a 200-column window a row and its
# size sat a whole screen apart.
TUI_MAX_WIDTH = 100
# An arrow key arrives as Esc and two more characters, Esc alone as itself:
# past this wait an Esc with nothing after it is the key.
TUI_ESC_WAIT = 0.04
TUI_FRAME = 0.1
# Set for a child run handed the interface's own copy of the file list.
TUI_LIST_ENV = "RETROBIOS_TUI_LIST"
# Set for a child run whose choice options are the install record's, kept
# on the screen: a part of them that cannot apply is left out, as line mode
# leaves it out of a record it reads, never refused.
TUI_RECORD_ENV = "RETROBIOS_TUI_RECORDED"
_PASTE_START = "\x1b[200~"
_PASTE_END = "\x1b[201~"
# Turned on by the interface, so a pasted path arrives as one piece and its
# newline does not submit it half typed.
_SCREEN_ON = "\x1b[?1049h\x1b[?25l\x1b[?2004h\x1b[2J"
# The mouse modes are turned off on every way out, turned on or not: a
# shell left with them on reads each click as a line of garbage.
_SCREEN_OFF = "\x1b[?1006l\x1b[?1000l\x1b[?2004l\x1b[0m\x1b[?25h\x1b[?1049l"
# Presses and releases (1000), reported in SGR form (1006): a column past
# 223 does not fit the legacy form's byte. Never 1003 (every motion): a
# touch screen has no hover, and nothing here depends on one.
_MOUSE_ON = "\x1b[?1000h\x1b[?1006h"
_MOUSE_OFF = "\x1b[?1006l\x1b[?1000l"
TUI_MOUSE_ENV = "RETROBIOS_NO_MOUSE"
# How a line is drawn without colour: the screen's title and a headline
# bold, the row in focus reversed, the bar and secondary text dim.
_STYLES = {"title": "\x1b[1m", "head": "\x1b[1m", "focus": "\x1b[7m", "dim": "\x1b[2m",
           "hint": "\x1b[2m"}
# The role each style is drawn in with colour (tui_paint).
_COLOUR_BASES = {"title": "strong", "head": "strong", "focus": "selected", "dim": "muted",
                 "hint": "muted", "refusal": "failure"}
# A count or a size on a headline: "4 files to download, 1.0 MB".
_KEY_NUMBER = re.compile(r"(?<![=\w.])\d[\d,.]*(?: (?:B|KB|MB|GB|TB)\b)?")
_PROGRESS_BAR = re.compile(r"^ *\[(#*)(-*)\]")
_FOLDER_LABEL = "BIOS folder: "
