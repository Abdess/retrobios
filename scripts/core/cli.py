"""Running a command-line entry point: exit status, signals, input errors, name hints."""

from __future__ import annotations

import argparse
import os
import signal
import sys
from collections.abc import Callable
from pathlib import Path

from core.artifacts import ArtifactDirectoryMissing, ArtifactLockBusy
from core.paths import BIOS_DIR, DB_FILE, EMULATORS_DIR, PLATFORMS_DIR


# Every build script imports this module. verify.py, slots.py, validate_pr.py
# and cross_reference.py started under 3.8 and stopped halfway on a
# str.removeprefix AttributeError, which named no version.
if sys.version_info < (3, 9):
    sys.exit(
        f"{Path(sys.argv[0]).name} needs Python 3.9 or newer, "
        f"this is {sys.version.split()[0]}"
    )


def require_directory(path: str, flag: str = "--bios-dir") -> None:
    """Stop on a folder that does not exist.

    identity --strict, dedup, auto_fetch, romset_recipes and generate_pack
    read a mistyped --bios-dir as an empty collection and passed: 0
    conflicts, 0 duplicates, a pack of nothing.
    """
    if not os.path.isdir(path):
        raise SystemExit(f"ERROR: {flag} {path} is not a directory")


class InputMissing(FileNotFoundError):
    """An input a command was pointed at does not exist. run_cli prints the
    message on one line instead of a stack trace."""


class SourceUnreadable(ValueError):
    """A profile or platform file that is not valid YAML. Not an InputMissing:
    the callers that skip a platform whose file is absent must not skip one
    whose file is damaged. run_cli prints the message on one line."""


# A list this short is printed whole rather than pointed at.
SHORT_LIST = 12


def suggest_names(
    typed: list[str],
    available: list[str],
    listing_flag: str,
    listed: int | None = None,
) -> str:
    """The closest known names to what was typed, and how to see them all.

    The hints showed the first ten or twenty names of the alphabet behind a
    "..." whatever was typed: sony-playstaton listed 3do to apple-iie.
    `listed` is how many entries the listing shows when `available` also
    holds aliases of them.
    """
    import difflib

    total = len(available) if listed is None else listed
    close = sorted({m for name in typed
                    for m in difflib.get_close_matches(name, available, n=3, cutoff=0.6)})
    if close:
        return f"Close matches: {', '.join(close)}. {listing_flag} lists all {total}."
    if len(available) <= SHORT_LIST:
        return f"Known: {', '.join(available)}."
    return f"{listing_flag} lists all {total}."


REPO_INPUTS = {
    "db": ("--db", DB_FILE, "database file to read"),
    "platforms": ("--platforms-dir", PLATFORMS_DIR, "platform YAML directory"),
    "emulators": ("--emulators-dir", EMULATORS_DIR, "emulator profile directory"),
    "bios": ("--bios-dir", BIOS_DIR, "BIOS collection directory"),
}


def add_repo_inputs(parser: argparse.ArgumentParser, *inputs: str) -> None:
    """Declare the repository inputs a command reads, in the order given:
    any of "db", "platforms", "emulators", "bios"."""
    for key in inputs:
        flag, default, text = REPO_INPUTS[key]
        parser.add_argument(flag, default=default, help=f"{text} (default: %(default)s)")


def add_emulator_selection(parser: argparse.ArgumentParser) -> None:
    """The --emulator and --system modes that verify and generate_pack share."""
    parser.add_argument("--emulator", "-e", help="Emulator profile name(s), comma-separated")
    parser.add_argument("--system", "-s", help="System ID(s), comma-separated")
    parser.add_argument("--standalone", action="store_true", help="Use standalone mode")
    parser.add_argument("--list-emulators", action="store_true", help="List available emulators")
    parser.add_argument("--list-systems", action="store_true", help="List available systems")


def _exit_on_signal(signum: int, _frame: object) -> None:
    sys.exit(128 + signum)


def run_cli(main: Callable[[], int | None]) -> None:
    """Run a command-line entry point to its exit status.

    A reader that stops early (`verify.py --all | head`) closed the pipe
    and the next write died on a BrokenPipeError traceback. Output nobody
    reads any more ends the run quietly, with the status a shell gives a
    writer whose reader left.

    SIGTERM (timeout, kill) and SIGHUP (a closed terminal) end the process
    without unwinding by default: a pack build left its multi-GB hidden
    .partial behind. Raised as SystemExit, they run the cleanup a failed
    write runs, and the status stays the one a shell gives the signal.
    """
    for name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _exit_on_signal)
    # Redirected, stdout is block-buffered and stderr is not: the --strict
    # verdict landed on the first line of the log, before the report it
    # closes. Line buffering keeps the two in the order they were written.
    # A stream a caller swapped in (a test's StringIO) has nothing to set.
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(line_buffering=True)
    try:
        code = main()
        sys.stdout.flush()
    except (InputMissing, SourceUnreadable, ArtifactLockBusy,
            ArtifactDirectoryMissing) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(141)
    sys.exit(code)
