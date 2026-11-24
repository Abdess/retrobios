"""A run's options completed, and the setups it installs: named, detected or chosen."""
from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn, TextIO

from installer.cards import _SHARE_FOLDERS, card_bound
from installer.console import OUTPUT, _is_terminal, detail, fold_line
from installer.cores import CORE_PLATFORMS, _check_cores_dir, _no_core_found, core_dirs, installed_cores
from installer.destination import _platform_for_dest, _several_found, _unknown_target, card_dest, card_install_dest
from installer.detect_frontends import detect_frontends, detect_platforms
from installer.detect_os import _enter_wsl, _os_name, _system_lines, _wsl_dest, detect_os, detected_os, found_label
from installer.events import EVENTS
from installer.from_folders import _open_local_sources
from installer.games import games_folder_refusal
from installer.handheld_app import app_refusal
from installer.install_record import by_record, drop_recorded
from installer.invocation import _INVOCATION, Invocation, installer_id
from installer.line_folder import (
    _default_set_aside,
    _manual_usage_hint,
    _prompt_manual_platform,
    _prompt_platform_choice,
    ask_platform_folder,
    share_words,
)
from installer.lists import ListFailure, load_targets
from installer.offline import LOCAL
from installer.pack import pack_path
from installer.pack_source import pack_name_platforms
from installer.paths import MOVED
from installer.platforms import AVAILABLE_PLATFORMS, _NO_BIOS_FOLDER, display_name, normalize_platform
from installer.refusal import Refusal
from installer.safe_replace import KEPT
from installer.setup_passes import _output_kind, needed_targets
from installer.setups import PORTABLE_ONLY, _default_dest, _line_setups, drive_example, found_setups
from installer.standalone import _install_standalone_folders
from installer.terminal import Terminal

if TYPE_CHECKING:
    from installer.folder_index import FolderIndex
    from installer.handheld_app import CardApp


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
        # No setup found, the standalone emulator folders filled instead:
        # the run still ends on its summary, exit code and result.
        self.standalone_only = False
        # A step about to write was reached: a refusal from then on still
        # ends on the summary of what the run installed before it.
        self.writing = False

    @contextmanager
    def writes(self, pending: int) -> Iterator[None]:
        """The checks before a step writes, pending the files it would
        write, counted as still to install when a refusal stops it."""
        self.writing = True
        try:
            yield
        except Refusal:
            self.files_pending += pending
            raise


def _start_install(args: argparse.Namespace, real_stdout: TextIO) -> _InstallRun:
    """The run's options completed, its terminal and its local sources opened."""
    KEPT.reset()
    MOVED.reset()
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
    refusal = games_folder_refusal(args.for_games, args.platform or "")
    if refusal is not None:
        raise refusal
    # --pack: the files go into a ZIP for another device, no folder of this
    # machine is read or written, and nothing is asked.
    packing = getattr(args, "pack", None) is not None
    if packing:
        interactive = False
        if args.platform is None:
            spelled = pack_name_platforms(Path(os.path.expanduser(str(args.pack))).name)
            if len(spelled) != 1:
                raise Refusal("pack", "no_platform", "",
                              "Error: name the platform the pack is for with --platform.",
                              code=2)
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
    hint = Invocation()
    hint.os_type, hint.options = run.os_type, _INVOCATION.options
    example = _default_dest(run.os_type, args.platform)
    # The run's own way of answering, kept: a script copying the
    # example stopped at a question.
    answered = "".join(f" {flag}" for flag, on in (
        ("--yes", args.yes), ("--no-input", args.no_input)) if on)
    raise Refusal("detect", "not_found", args.platform, f"  {message}.",
                  "  Name its folder with --dest, for example:\n    "
                  + hint.command(args.platform, example if example is not None
                                 else "<its BIOS folder>") + answered,
                  message=message)


def _named_setup_default(run: _InstallRun) -> list[tuple[str, Path]]:
    """A named platform not found here, nothing asked: its default folder,
    or the run stops on how to name one."""
    args = run.args
    if getattr(args, "platform_from_list", False):
        _named_by_list_only(run)
    if args.platform in PORTABLE_ONLY:
        # A portable emulator reads the folder beside its executable:
        # any default would be a folder it never opens.
        raise Refusal(
            "detect", "not_found", args.platform,
            f"  Platform '{args.platform}' not found. {PORTABLE_ONLY[args.platform]} "
            f"Name it with --dest, for example: --platform {args.platform} "
            f"--dest '<BizHawk folder>{os.sep}Firmware'",
            message=f"Platform '{args.platform}' not found. {PORTABLE_ONLY[args.platform]}")
    if args.platform in _SHARE_FOLDERS:
        # Its own folder exists on the Batocera machine alone, which
        # detection would have found: here /userdata/bios was taken, and
        # the run ended on "Cannot create" with no event saying why.
        message = (f"Platform '{args.platform}' not found here. "
                   f"{share_words(args.platform)}")
        example = drive_example(run.os_type, "SHARE", "bios", args.platform)
        raise Refusal("detect", "not_found", args.platform,
                      f"  {message} Name it with --dest, for example: --platform "
                      f"{args.platform} --dest {example}", message=message)
    default_dest = _default_dest(run.os_type, args.platform)
    if default_dest is None:
        where = ("where this user can look, and its default folder may not be "
                 "the one it reads" if _default_set_aside(run.os_type, args.platform)
                 else "and no folder on this system is one it reads")
        message = f"Platform '{args.platform}' not found {where}"
        raise Refusal("detect", "not_found", args.platform,
                      f"  {message}. Name it with --dest, for example: "
                      f"--platform {args.platform} --dest <its BIOS folder>",
                      message=message)
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
    a stop. True when no setup is left to install (run.standalone_only
    then says the run still ends on its result)."""
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
    if not run.listing and not narrowing and _install_standalone_folders(run):
        run.standalone_only = True
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


def _check_run_target(run: _InstallRun) -> None:
    """--target checked for every platform, before anything is written."""
    args, platforms = run.args, run.platforms
    # --target is checked for every platform before anything is written, as
    # --installed-cores is below: EmuDeck installed 3.2 GB and only then was
    # steamos refused for RetroArch, with no summary of what had landed.
    if args.target and by_record(args) and len(platforms) == 1:
        # The screen's runs carry the record's options as typed ones.
        plat = platforms[0][0]
        try:
            known = load_targets(plat)
        except ListFailure as stopped:
            drop_recorded(args, plat, "--target", "the board list needs the internet"
                          if stopped.problem.code == "offline"
                          else "the board list could not be read")
        else:
            if args.target not in known:
                drop_recorded(args, plat, "--target", "the board list does not name it")
    if args.target:
        for plat_name, _bios_path in platforms:
            targets = needed_targets(plat_name)
            run.target_lists[plat_name] = targets
            if args.target not in targets:
                _unknown_target(args.target, plat_name, targets, *(
                    ["  Nothing was installed. Name one platform with "
                     "--platform to install it alone."] if len(platforms) > 1 else []))


def _check_run_cores(run: _InstallRun) -> None:
    """The cores installed for each setup, read before anything is written."""
    args = run.args
    # Every check --installed-cores makes before anything is written: a
    # refusal for the second platform must not follow an install of the first.
    for plat_name, bios_path in [] if run.packing else run.platforms:
        if plat_name in CORE_PLATFORMS:
            if args.cores_dir:
                _check_cores_dir(args.cores_dir, plat_name)
            searched = [args.cores_dir] if args.cores_dir else core_dirs(plat_name, bios_path)
            run.cores_found[(plat_name, bios_path)] = installed_cores(searched)
            run.cores_searched[(plat_name, bios_path)] = searched
        elif args.installed_cores and by_record(args):
            drop_recorded(args, plat_name, "--installed-cores",
                          f"{plat_name} ships its cores with the system")
        elif args.installed_cores:
            raise Refusal("option", "not_applicable", plat_name,
                          f"Error: {plat_name} ships its cores with the system. "
                          f"--installed-cores applies to {', '.join(CORE_PLATFORMS)}")
        if args.installed_cores and not run.cores_found[(plat_name, bios_path)]:
            if by_record(args):
                drop_recorded(args, plat_name, "--installed-cores", "no core is installed")
            else:
                _no_core_found(plat_name, bios_path, searched)
