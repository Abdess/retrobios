"""main: the options read, the action chosen and the run started."""
from __future__ import annotations

import argparse
import io
import os
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

from installer.arguments import PACK_NAME_END, build_parser
from installer.combinations import combination_refusals, given_options
from installer.console import OUTPUT, fold_line
from installer.detect_os import detect_os
from installer.events import EVENTS, EVENT_SCHEMA, _event_exit_code, _event_mode
from installer.from_folders import _open_local_sources
from installer.handheld_app import app_not_added
from installer.host_fs import _is_dir, _writing
from installer.install_record import restore_kept
from installer.invocation import (
    LISTING_FLAGS,
    OFFLINE_VARIABLE,
    _INVOCATION,
    installer_id,
    listings_given,
    offline_requested,
)
from installer.narrowing import FIND_KINDS
from installer.network import _RAW_ERRORS, install_bounded_opener
from installer.offline import LOCAL, OFFLINE_FLAG_VALUE, offline_named
from installer.platforms import AVAILABLE_PLATFORMS, TARGET_PLATFORMS, _name_key, display_name, refuse_name
from installer.refusal import Refusal
from installer.regions import resolve_regions
from installer.remote import remote_from_env, remote_in_use
from installer.backups import run_backups, run_delete_backup
from installer.removal import run_removal
from installer.run import _install
from installer.tui_routes import (
    TUI_LIST_ENV,
    TUI_RECORD_ENV,
    line_mode_reason,
    plain_requested,
    tui_blocker,
    tui_obstacle,
)
from installer.tui_session import run_tui


def _check_expert(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """--one-per-slot, --standalone, --source truth and --find, applied or
    refused, never ignored (combination_refusals)."""
    refusals = combination_refusals(given_options(args))
    if refusals:
        parser.error(refusals[0])
    if args.find:
        # Each would be skipped by a run that installs one file or prints it.
        for flag, given in (("--pack", getattr(args, "pack", None) is not None),
                            ("--add-app", args.add_app),
                            ("--standalone-copies", args.standalone_copies),
                            ("--romm-firmware", args.romm_firmware is not None),
                            ("--from", bool(getattr(args, "from")))):
            if given:
                parser.error(f"--find picks one file by its hash, which {flag} does not apply to")
    if args.find is not None:
        value = args.find.strip()
        if len(value) not in FIND_KINDS or not re.fullmatch(r"[0-9a-fA-F]+", value):
            kinds = ", ".join(f"{kind} ({length} digits)" for length, kind in FIND_KINDS.items())
            parser.error(f"--find takes a hash in hexadecimal: {kinds}")


def say_raw_errors(verbose: bool) -> None:
    """Each run says errors from its own options: a run with --verbose before
    it in the same process left every later message with its raw cause."""
    if verbose:
        _RAW_ERRORS.set()
    else:
        _RAW_ERRORS.clear()


def _main_settle(args: argparse.Namespace) -> None:
    """Options that set others, and the record of the command."""
    say_raw_errors(args.verbose)
    if args.cores_dir:
        args.installed_cores = True
    if args.yes:
        # Asked at a terminal, --yes still waited at Install for: and at
        # the menu. Yes to every question is no question.
        args.no_input = True
    _INVOCATION.record(args)
    if os.environ.get(TUI_RECORD_ENV):
        args.from_record = True
    if os.environ.get(TUI_LIST_ENV):
        # The full screen's own copy of the list, deleted when it closes: a
        # command naming it fails once the screen is gone.
        _INVOCATION.options = [option for option in _INVOCATION.options
                               if option[0] != "--manifest"]


def _main_check_values(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Refuse values out of range and options that ask for two things."""
    if not 1 <= args.jobs <= 32:
        parser.error("--jobs must be between 1 and 32")
    if args.region:
        try:
            resolve_regions(args.region)
        except ValueError as exc:
            parser.error(str(exc))
    for option, values in (("--system", args.system), ("--core", args.core)):
        if values is not None and not any(
            token.strip() for value in values for token in value.split(",")
        ):
            parser.error(f"{option} needs at least one name")
    if args.quiet and (
        args.check or args.dry_run or listings_given(args)
    ):
        parser.error("--quiet applies to an install, not to --check, --dry-run or a listing")
    if args.tui and args.plain:
        parser.error("--tui and --plain ask for two different interfaces")
    if args.all_files and args.for_games is not None:
        parser.error("--all-files and --for-games ask for two different lists")
    if args.required_only and args.for_games is None:
        parser.error("--required-only applies to --for-games: the list alone does not "
                     "say which files a game cannot start without")
    if args.for_games is not None and listings_given(args):
        parser.error("--for-games narrows an install, not a listing")


def _main_check_listings(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Refuse two listings, or a listing with an option it does not read."""
    # Applied or refused, never ignored: a run prints one list, and the
    # narrowing options apply to --list-systems and --list-cores only, past
    # --target and --installed-cores, which --list-emulators also reads.
    listings = listings_given(args)
    if len(listings) > 1:
        parser.error(f"{listings[0]} and {listings[1]} each print a list: run them "
                     "one at a time")
    if listings and listings[0] in ("--list-platforms", "--list-targets",
                                    "--list-emulators"):
        unread: tuple[tuple[str, object], ...] = (
            ("--system", args.system), ("--core", args.core),
            ("--region", args.region), ("--emulator", args.emulator))
        if listings[0] != "--list-emulators":
            unread += (("--target", args.target), ("--every-board", args.every_board),
                       ("--installed-cores", args.installed_cores))
        if listings[0] == "--list-platforms":
            unread += (("--platform", args.platform),)
        given = next((flag for flag, value in unread if value), "")
        if given:
            parser.error(f"{listings[0]} prints the whole list, which {given} "
                         "does not narrow")


def _main_check_declared_only(parser: argparse.ArgumentParser,
                              args: argparse.Namespace) -> None:
    """Refuse --declared-only with an option it leaves without effect."""
    if args.declared_only:
        # Applied or refused, never ignored.
        for given, reason in (
            (args.tui, "the full-screen interface has no choice for --declared-only"),
            (args.list_platforms or args.list_targets,
             "--declared-only narrows a file list, not --list-platforms or --list-targets"),
            (args.core or args.list_cores,
             "--declared-only leaves out the files cores load, which --core and "
             "--list-cores choose among"),
            (args.list_emulators,
             "--list-emulators names emulators, and --declared-only narrows files"),
            (args.standalone_copies,
             "--standalone-copies copies into standalone emulators' folders, outside "
             "the platform's own list that --declared-only keeps"),
        ):
            if given:
                parser.error(reason)


def _main_check_add_app(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Refuse --add-app where the run writes or downloads nothing."""
    if args.add_app:
        # Applied or refused, never ignored.
        for given, reason in (
            (args.check or args.dry_run,
             "--add-app writes the RetroBIOS app on the card, which --check and "
             "--dry-run do not"),
            (listings_given(args),
             "--add-app writes the RetroBIOS app on the card, which a listing does not"),
            (args.from_pack, "--add-app downloads the RetroBIOS app, and --from-pack "
             "makes no network request"),
            (args.offline or offline_requested(), "--add-app downloads the RetroBIOS "
             "app, which --offline does not"),
        ):
            if given:
                parser.error(reason)


def _main_check_offline(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Record --offline, and refuse --target where no core list can be read."""
    if args.offline and not offline_requested():
        # The runs the full-screen interface starts read it from here, and
        # the words name the option given. A variable already set keeps its
        # value: dropping --offline alone would leave the run offline.
        os.environ[OFFLINE_VARIABLE] = OFFLINE_FLAG_VALUE
    named = next((plat for plat in AVAILABLE_PLATFORMS if args.platform and _name_key(
        args.platform) in (_name_key(plat), _name_key(display_name(plat)))), "")
    if offline_requested() and args.target and named and named not in TARGET_PLATFORMS:
        refuse_name(named, f"Error: {display_name(named)} has no hardware targets: run "
                    "again without --target.")
    if (offline_requested() and (args.target or args.list_targets)
            and not (args.manifest or args.from_pack)
            and not (named and named not in TARGET_PLATFORMS)):
        # No list can be at hand: a pack carries one, and so can the folder
        # of a --manifest (targets/<platform>.json).
        parser.error(f"--target needs a core list, which {offline_named()} does not fetch: "
                     "give --from-pack, or --manifest with targets/<platform>.json beside it")


def _main_check_sources(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Refuse a source of files given with a listing that reads none."""
    if getattr(args, "from") and listings_given(args):
        parser.error("--from copies files into the BIOS folder, which a listing "
                     "does not write")
    if (args.from_pack or args.manifest) and args.list_platforms:
        # --list-targets reads its boards from them, where --target does.
        parser.error("--from-pack and --manifest give a file list, which --list-platforms "
                     "does not read")
    if args.no_game_data and (args.list_platforms or args.list_targets):
        parser.error("--no-game-data narrows a file list, not --list-platforms "
                     "or --list-targets")


def _main_run_events(args: argparse.Namespace) -> None:
    """Run with --events, the run framed by start and end."""
    # The events own stdout. The text a person reads goes to stderr, so a
    # program never has to tell one from the other.
    args.no_input = True
    EVENTS.open(sys.stdout)
    sys.stdout = sys.stderr
    EVENTS.emit("start", schema=EVENT_SCHEMA, installer=installer_id(),
                mode=_event_mode(args))
    try:
        _run(args)
    except SystemExit as exc:
        EVENTS.emit("end", code=_event_exit_code(exc.code))
        raise
    except KeyboardInterrupt:
        EVENTS.emit("end", code=130)
        raise
    EVENTS.emit("end", code=0)


def _main_dispatch(args: argparse.Namespace) -> None:
    """Open the full screen, or run line by line, with events or JSON."""
    # The screens have no choice for --declared-only: the questions ask the
    # rest, and the run keeps the platform's own list.
    # Nor for --source truth and --find, which choose the files themselves.
    lined = args.declared_only or args.source == "truth" or bool(args.find)
    obstacle = None if args.tui else tui_obstacle(args)
    if args.tui or not (plain_requested(args) or lined or obstacle):
        sys.exit(run_tui(args))
    if not (plain_requested(args) or lined):
        # The questions came line by line with no word of why: the page
        # says a smaller window says so, and a TERM
        # unset or dumb said nothing.
        said = line_mode_reason(obstacle)
        if said:
            print(fold_line(said))
    if args.events:
        _main_run_events(args)
        return
    if args.json:
        # The matches own stdout, the text a person reads goes to stderr.
        args.no_input = True
        args.json_out = sys.stdout
        sys.stdout = sys.stderr
        try:
            _run(args)
        finally:
            sys.stdout = args.json_out
        return
    _run(args)


def main() -> None:
    """Entry point: the remote resolved once, then the run."""
    try:
        remote = remote_from_env()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    with remote_in_use(remote):
        try:
            _main_run()
        except Refusal as refusal:
            # Raised outside an install, which reports its own: the full
            # screen's start, an action and the sources opened before it.
            refusal.report()
            raise


def _main_run() -> None:
    _INVOCATION.os_type = detect_os()
    parser = build_parser()
    args = parser.parse_args()
    _main_settle(args)
    _main_check_values(parser, args)
    _main_check_listings(parser, args)
    _main_check_declared_only(parser, args)
    _check_expert(parser, args)
    if args.tui:
        reason = tui_blocker(args)
        if reason:
            # The reason alone: fourteen lines of usage hid it.
            print(f"{parser.prog}: error: --tui cannot open the full-screen interface "
                  f"here: {reason}", file=sys.stderr)
            sys.exit(2)
    _check_actions(parser, args)
    _check_pack(parser, args)
    if args.restore is not None:
        _run_action(args, lambda given: restore_kept(given.restore, given.dry_run))
    if args.delete_backup is not None:
        _run_action(args, run_delete_backup)
    if args.every_board and args.target:
        parser.error("--every-board installs every board, and --target names one")
    _main_check_add_app(parser, args)
    _main_check_offline(parser, args)
    install_bounded_opener()
    if args.remove or args.backups:
        _run_action(args, _with_local_sources(run_removal if args.remove else run_backups))
    _main_check_sources(parser, args)
    _main_dispatch(args)


# What each action reads beside its own option: anything else given with
# it is refused, never ignored. dest and platform name the BIOS folder.
_ACTION_TAKES = {
    "restore": ("dry_run", "events", "yes", "no_input", "verbose"),
    "delete_backup": ("dry_run", "events", "yes", "no_input", "verbose"),
    "backups": ("platform", "dest", "events", "no_input", "verbose"),
    "remove": ("platform", "dest", "system", "core", "emulator", "file", "backup",
               "misplaced", "dry_run", "events", "yes", "no_input", "verbose", "manifest", "from_pack",
               "offline"),
}
# Options that are a choice of their own, never refused for being given.
_ACTION_FREE = ("jobs", "plain", "from_record")


def _check_actions(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Refuse an action given with an option it does not read, two actions,
    or --file, --backup and --misplaced without --remove."""
    actions = [name for name in _ACTION_TAKES if getattr(args, name)]
    if len(actions) > 1:
        parser.error(f"--{actions[0].replace('_', '-')} and --{actions[1].replace('_', '-')} "
                     "are two actions: run them one at a time")
    if not actions:
        for name in ("file", "backup", "misplaced"):
            if getattr(args, name):
                parser.error(f"--{name} applies to --remove")
        return
    action = actions[0]
    defaults = build_parser().parse_args([])
    given = [name for name, value in vars(args).items()
             if name != action and name not in _ACTION_TAKES[action]
             and name not in _ACTION_FREE and value != getattr(defaults, name, value)]
    if given:
        parser.error(f"--{action.replace('_', '-')} takes no "
                     f"--{given[0].replace('_', '-')}")
    if action == "remove":
        narrowed = [flag for flag, value in (("--system", args.system), ("--core", args.core),
                                             ("--emulator", args.emulator),
                                             ("--file", args.file)) if value]
        if len(narrowed) > 1:
            parser.error(f"--remove takes one of --system, --core, --emulator or --file, "
                         f"not {narrowed[0]} and {narrowed[1]}")
        if args.misplaced and (narrowed or args.backup):
            # The copies are the user's, so no backup note can give them
            # back to a setup, and no system or core names them.
            parser.error(f"--remove --misplaced takes no {(narrowed or ['--backup'])[0]}")


def _check_pack(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Refuse --split without --pack, and --pack with an option that reads
    or writes a BIOS folder: applied or refused, never ignored."""
    pack = getattr(args, "pack", None)
    if getattr(args, "split", None) is not None and pack is None:
        parser.error("--split applies to --pack")
    if pack is None:
        return
    for flag, given in (
        ("--check", args.check), ("--dest", args.dest),
        ("--installed-cores", args.installed_cores), ("--cores-dir", args.cores_dir),
        ("--save-dir", args.save_dir), ("--standalone-copies", args.standalone_copies),
        ("--add-app", args.add_app), ("--romm-firmware", args.romm_firmware is not None),
        ("--tui", args.tui),
        *((flag, getattr(args, attr)) for flag, attr in LISTING_FLAGS),
    ):
        if given:
            parser.error(f"--pack writes a pack ZIP, and {flag} reads or writes the "
                         "BIOS folder of this machine")
    if args.for_games is True:
        parser.error("--for-games with --pack needs its FOLDER: no card is read for a pack")
    name = Path(os.path.expanduser(str(pack))).name
    if not (_is_dir(Path(os.path.expanduser(str(pack))))
            or str(pack).endswith(("/", os.sep)) or name.endswith(PACK_NAME_END)):
        parser.error(f"--pack names a folder, or a file whose name ends with "
                     f"{PACK_NAME_END} (--from-pack and the parts of a pack read that "
                     f"name): {name}")


def _with_local_sources(action: Callable[[argparse.Namespace], int],
                        ) -> Callable[[argparse.Namespace], int]:
    """action, the list and the pack it was given opened first. Opened
    before the action, they said the list's platform on stdout ahead of
    start, the first line of --events no JSON."""
    def opened(args: argparse.Namespace) -> int:
        _open_local_sources(args)
        return action(args)
    return opened


def _run_action(args: argparse.Namespace,
                action: Callable[[argparse.Namespace], int]) -> NoReturn:
    """Run an action and exit with its code, its events framed by start and
    end with --events."""
    if not args.events:
        sys.exit(action(args))
    args.no_input = True
    EVENTS.open(sys.stdout)
    sys.stdout = sys.stderr
    EVENTS.emit("start", schema=EVENT_SCHEMA, installer=installer_id(),
                mode=_event_mode(args))
    try:
        code = action(args)
    except SystemExit as exc:
        if isinstance(exc, Refusal):
            exc.report()
        EVENTS.emit("end", code=_event_exit_code(exc.code))
        raise
    except KeyboardInterrupt:
        EVENTS.emit("end", code=130)
        raise
    EVENTS.emit("end", code=code)
    sys.exit(code)


def _run(args: argparse.Namespace) -> None:
    """The run, its text quiet or not, the archives it read closed after."""
    try:
        _run_text(args)
    except SystemExit as exc:
        if exc.code not in (0, None):
            app_not_added()
        raise
    except KeyboardInterrupt:
        app_not_added()
        raise
    finally:
        LOCAL.close_indexes()
        # A caller running the installer in its own process gets the next
        # run's text as quiet as any first run.
        OUTPUT.verbose = OUTPUT.where_said = False


def _run_text(args: argparse.Namespace) -> None:
    if not args.quiet:
        _install(args, sys.stdout)
        return
    # Quiet: what a run prints is kept, and shown on stderr if the run fails,
    # so an error printed on stdout is never lost.
    captured = io.StringIO()
    real_stdout = sys.stdout
    sys.stdout = captured
    try:
        _install(args, real_stdout)
    except SystemExit as exc:
        if sys.stdout is captured:
            sys.stdout = real_stdout
            if exc.code not in (0, None):
                sys.stderr.write(captured.getvalue())
        raise
    finally:
        if sys.stdout is captured:
            sys.stdout = real_stdout


def _line_buffered_stdout() -> None:
    """Flush stdout line by line, as stderr is.

    Piped to a log (`| tee install.log`), stdout was block-buffered while
    errors went out at once: the log opened on "Could not fetch the file
    list" before the banner and the step that produced it.
    """
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        try:
            reconfigure(line_buffering=True)
        except (ValueError, OSError):
            # A stream that cannot be reconfigured keeps its own buffering:
            # the order of a log is cosmetic, the run goes on.
            return


if __name__ == "__main__":
    _line_buffered_stdout()
    # A reader that stops early (`install.py --list | head`) ends the run
    # quietly instead of on a BrokenPipeError traceback.
    try:
        main()
        sys.stdout.flush()
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(141)
    except KeyboardInterrupt:
        # Outside the download phase (fetching the file list, checking the
        # files present, rebuilding data directories): nothing is half
        # written there, and a socket traceback read as a crash. Stopped at
        # a question, nothing has started, and there is nothing to carry on.
        if _writing.is_set():
            print("\nStopped. Run the same command again to carry on from here. "
                  "Nothing is lost.")
        else:
            print("\nStopped. Nothing was installed.")
        sys.exit(130)
