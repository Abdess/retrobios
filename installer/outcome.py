"""How a run ends: failures, remedies and the next step, on the screen and in events."""
from __future__ import annotations

import errno
import http.client
import os
import socket
import sys
import urllib.error
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple, NoReturn

from installer.cards import _mounted_cards
from installer.console import OUTPUT, SAID_FAILED
from installer.destination import on_its_card
from installer.detect_os import detected_os
from installer.failure_causes import (
    Failure,
    connection_only,
    failed_lines,
    failure_records,
    failure_remedies,
    retry_helps,
    retry_words,
    split_offline,
)
from installer.host_fs import _held
from installer.invocation import _INVOCATION
from installer.offline import LOCAL, _offline_only, offline_named, offline_undo
from installer.paths import shown_path
from installer.platforms import display_name
from installer.romm import ROMM_SCAN_WORDS
from installer.safe_replace import BACKUP_DIR, KEPT, _kept_lines
from installer.tally import _omission_lines, installed_words, needed_absent_words
from installer.text import _plural, agree, format_duration, format_size, screen_text

if TYPE_CHECKING:
    from installer.invocation import Invocation
    from installer.tally import Tally
    from installer.terminal import Terminal


def _locations(paths: list[Path]) -> str:
    """Where the run wrote, naming every destination when it served several."""
    return ", ".join(shown_path(p) for p in paths) if paths else "nowhere"


# What a run says when every file is in place, on the screen and in line
# mode: the site's "How to check" quotes it (scripts/generate_site.py).
EVERYTHING_IN_PLACE = "Every file on the list is in place."


def _on_read_only_mount(path: Path) -> bool:
    """Whether the file system holding path, or the folder it would go in,
    is mounted read-only (a card Linux remounts read-only after an error)."""
    if not hasattr(os, "statvfs"):
        return False
    probe = path
    while not _held(probe) and probe.parent != probe:
        probe = probe.parent
    try:
        return bool(os.statvfs(probe).f_flag & os.ST_RDONLY)
    except OSError:
        return False


def read_only_words(path: Path) -> str:
    """The remedy for a folder on a read-only file system, in one sentence
    that the plan, the result and line mode all say: root cannot write it
    either, and the plan offered sudo for it."""
    place = path.absolute()
    card = any(mount == place or mount in place.parents for mount in _mounted_cards())
    return (f"The {'card' if card else 'drive'} is read-only: unlock it or mount it "
            "read-write, then run again.")


# What Termux needs to write shared storage, said by the plan, the result
# and line mode alike.
TERMUX_STORAGE_WORDS = ("Run termux-setup-storage once and allow the storage permission "
                        "Android asks for, then run it again.")


def write_remedy(path: Path, plat: str, hint: Invocation, commands: bool = True) -> list[str]:
    """What the screens say a user can do about a folder they cannot write:
    the read-only remedy, or the same choice run as an administrator, the
    command carrying every option of the run (hint). The sudo line dropped
    --from-pack and --manifest, and stopped at the file list with
    --offline. commands is False where no command can be typed (a pad)."""
    if _on_read_only_mount(path):
        return [read_only_words(path)]
    if hint.os_type == "android":
        # Termux has no sudo: its shared storage is reached once Android
        # gives it the storage permission.
        return [TERMUX_STORAGE_WORDS]
    if not commands:
        return []
    if hint.os_type == "windows":
        return ["Or run the installer as an administrator."]
    # sudo changes the home folder, and with it what is detected: the folder
    # is named so root writes here.
    return ["Or run it as root, this folder named: "
            + hint.command(plat, path, elevated=True)]


def _write_advice(path: Path, assumed: bool, plat: str = "",
                  hint: Invocation | None = None) -> str:
    """What to do about a folder this run could not write, the command
    built by hint (the run's own invocation by default).

    sudo fixes a root-owned BIOS folder on the console itself. On another
    machine it would create that folder on the wrong disk: a platform named
    but not found here is a card or share mounted elsewhere, named by --dest.
    Windows has no sudo, and Termux reaches shared storage once
    termux-setup-storage has run. A read-only mount refuses root as well,
    so sudo is never offered for it.
    """
    hint = hint or _INVOCATION
    if _on_read_only_mount(path):
        again = f"\n    {hint.command(plat, path)}" if plat else ""
        return (f"  {read_only_words(path)} {path} is on a file system mounted "
                "read-only, which no user can write, sudo included (a card or drive "
                "the system switched to read-only after an error needs a check "
                f"first: fsck, or chkdsk on Windows).{again}")
    if assumed:
        return (f"  {path} is where the platform keeps its BIOS on its own system, "
                "and it was not found here. If this machine prepares its card or "
                "share, run it again with --dest pointing at that folder:\n"
                f"    {hint.command(plat, '<that folder>')}")
    if plat and hint.os_type == "windows":
        return ("  This user cannot write there. Run it again from a PowerShell window "
                "opened as administrator:\n"
                f"    {hint.command(plat, path)}\n"
                "  Or choose another folder with --dest.")
    if plat and hint.os_type == "android":
        return (f"  This user cannot write there. {TERMUX_STORAGE_WORDS}\n"
                f"    {hint.command(plat, path)}\n"
                "  Or choose another folder with --dest.")
    if plat:
        # sudo resets HOME to root's on Debian, Ubuntu, Arch and SteamOS:
        # the same command detected nothing there, fell back to a folder
        # under /root and reported success.
        return ("  This user cannot write there. Run it again with sudo, naming the "
                "folder so root does not look in its own home:\n"
                f"    {hint.command(plat, path, elevated=True)}\n"
                "  Or choose another folder with --dest.")
    if hint.os_type == "windows":
        return ("  This user cannot write there: run the same command from a PowerShell "
                "window opened as administrator, or choose another folder with --dest.")
    return ("  This user cannot write there: run the same command with sudo, "
            "or choose another folder with --dest.")


def _transfer_failure(exc: BaseException) -> bool:
    """Whether a download error came from the connection, not the disk."""
    # urlopen raises URLError for the name lookup, the connection and TLS.
    # A cut read surfaces as a timeout (socket.timeout is no TimeoutError
    # before 3.10), a reset, an SSL error or a size that does not add up.
    ssl_error = getattr(sys.modules.get("ssl"), "SSLError", ())
    if isinstance(exc, (urllib.error.URLError, http.client.HTTPException, ValueError,
                        ConnectionError, TimeoutError, socket.timeout)):
        return True
    if ssl_error and isinstance(exc, ssl_error):
        return True
    return isinstance(exc, OSError) and exc.errno in (
        errno.ECONNRESET, errno.ECONNREFUSED, errno.ECONNABORTED, errno.ETIMEDOUT,
        errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETDOWN, errno.EPIPE,
    )


def _status_print(term: Terminal | None) -> Callable[..., None]:
    """print, with the status words of what it prints in their roles when
    term paints (Terminal.status)."""
    if term is None or not term.colour:
        return print

    def say(*parts: object, **kwargs: Any) -> None:
        print(*(term.status(str(part)) for part in parts), **kwargs)
    return say


class _Ending(NamedTuple):
    """What every ending of a run reads, worked out by _report_outcome."""

    say: Callable[..., None]
    paths: list[Path]
    downloaded: int
    up_to_date: int
    errors: int
    omitted: int
    offline: int
    failures: list[Failure]
    sources: str
    kept: list[str]
    advice: list[str]
    same_lines: list[str]
    installed_kinds: str
    omitted_entries: list[dict]
    unplaced: int
    platform_of: dict[Path, str]
    hints: list[str]
    same_choice: str
    missing: Tally | None


def _say_failures(say: Callable[..., None], failures: list[Failure]) -> None:
    """The failed files the progress has not named, as the screen lists them."""
    # A failure the progress already named on its FAILED line is not named
    # again: line mode listed each one twice.
    for line in failed_lines(failures, SAID_FAILED):
        say(line)


def _failure_advice(
    paths: list[Path], failures: list[Failure], assumed: set[Path] | None,
    platform_of: dict[Path, str] | None,
) -> list[str]:
    """What to do about the causes of the failed files, one line each."""
    refused = any(record.kind == "not_writable" for record in failures
                  if not Path(record.dest).is_absolute())
    advice = [
        _write_advice(path, path in (assumed or set()), (platform_of or {}).get(path, ""))
        for path in paths
    ] if refused else []
    advice += [_write_advice(folder, False) for folder in sorted({
        Path(record.dest).parent for record in failures
        if Path(record.dest).is_absolute() and record.kind == "not_writable"
    })]
    return advice + failure_remedies(failures, _locations(paths))


def _kept_and_unplaced(omitted_entries: list[dict], notes: list[str] | None,
                       ) -> tuple[list[str], int]:
    """The lines every ending repeats, and the count of files left out for
    an unknown save directory."""
    # Left out for an unknown save directory, said with that reason in
    # every ending: "the collection does not hold it" blamed the collection.
    unplaced = [entry for entry in omitted_entries
                if entry.get("reason") == "no_save_directory"]
    kept = _kept_lines() + ([
        f"{_plural(len(unplaced), 'file')} read from "
        f"{unplaced[0].get('frontend') or 'the frontend'}'s save directory left out: "
        + (f"{unplaced[0]['save_why']}." if unplaced[0].get("save_why")
           else f"its place is not known. {LINE_SAVE_REMEDY}")] if unplaced else [])
    kept += list(notes or [])
    return kept, len(unplaced)


def _end_offline(end: _Ending) -> NoReturn:
    """End a run --offline left files out of."""
    say, paths, downloaded, errors, offline = (
        end.say, end.paths, end.downloaded, end.errors, end.offline)
    sources = end.sources
    remedy = _offline_remedy()
    if not downloaded and not errors:
        say(f"\nNothing installed: {agree(offline, 'file needs', 'files need')} "
            "the internet, which "
            f"{offline_named()} does not use.")
        say(f"  {remedy}")
        for line in end.kept:
            say(line)
        if end.up_to_date:
            say(f"{_plural(end.up_to_date, 'file')} already in place at "
                f"{_locations(paths)}.")
        for line in end.same_lines:
            say(line)
        sys.exit(2)
    failed = f", {errors} failed" if errors else ""
    if downloaded and sources:
        # One count, the remedy under it, as the screen's result: the
        # count came twice, "installed" then "copied". The failed files are
        # in it.
        say(f"\nFinished with files missing. {sources}")
        sources = ""
    elif downloaded:
        say(f"\nFinished with files missing. {_plural(downloaded, 'file')} installed, "
            f"{offline} not fetched ({offline_named()}){failed}.")
    else:
        # Nothing written: "Finished with files missing. 0 files installed"
        # read as a part done.
        say(f"\nNothing installed: {_plural(offline, 'file')} not fetched "
            f"({offline_named()}){failed}.")
    if sources:
        say(f"  {sources}")
    if end.installed_kinds:
        say(end.installed_kinds)
    missing = end.missing
    if missing is not None and missing.bios and missing.games:
        # The kinds still missing, as the screen's result says them,
        # before the remedy: "They are not in OLD" followed the files
        # installed.
        say(f"  Still missing: {installed_words(missing.bios, missing.games)}.")
    # Under the files it is about: after the save-directory line, "They"
    # read as that one file.
    say(f"  {remedy}")
    say(f"BIOS folder: {_locations(paths)}")
    for line in end.kept + end.advice + end.same_lines:
        say(line)
    sys.exit(1 if downloaded else 2)


def _end_nothing_installed(end: _Ending) -> NoReturn:
    """End a run whose every file failed."""
    say, paths, failures = end.say, end.paths, end.failures
    say(f"\nNothing was installed. {_plural(end.errors, 'file')} failed.")
    if connection_only(failures):
        # The folder was never the problem: naming it as the place being
        # written to sent people looking at their disk.
        say(f"BIOS folder: {_locations(paths)}")
    elif retry_words(failures):
        # Nothing was written: every file is one the pack lacks.
        say(f"BIOS folder: {_locations(paths)}")
    else:
        say(f"BIOS folder that was being written to: {_locations(paths)}")
    for line in end.kept + end.advice:
        say(line)
    say(retry_words(failures) or "Run the same command again once that is resolved. "
        "Files already installed are kept.")
    for line in end.same_lines:
        say(line)
    sys.exit(2)


def _end_with_errors(end: _Ending) -> NoReturn:
    """End a run that installed files and failed others."""
    say, failures = end.say, end.failures
    # One count: "42 files installed, 2 files failed." over "38 files
    # copied from E:\, 4 downloaded, 2 still missing." said it twice,
    # the failed files as missing ones.
    say(f"\nFinished with errors. {end.sources}" if end.sources else
        f"\nFinished with errors. {_plural(end.downloaded, 'file')} installed, "
        f"{_plural(end.errors, 'file')} failed.")
    if end.installed_kinds:
        say(end.installed_kinds)
    say(f"BIOS folder: {_locations(end.paths)}")
    for line in end.kept + end.advice:
        say(line)
    retry = retry_words(failures)
    if retry:
        say(retry)
    elif retry_helps(failures):
        say("Run the same command again to retry only those.")
    for line in end.same_lines:
        say(line)
    sys.exit(1)


def _say_left_out(end: _Ending) -> None:
    """The files a run that ended well did not install, and the hints after them."""
    say, paths = end.say, end.paths
    skipped = [entry for entry in end.omitted_entries
               if entry.get("reason") != "no_save_directory"]
    if end.omitted > end.unplaced and OUTPUT.verbose:
        for line in _omission_lines(end.omitted - end.unplaced, skipped,
                                    Path(paths[0]) if len(paths) == 1 else None):
            say(line)
    elif end.omitted > end.unplaced and any(entry.get("required") for entry in skipped):
        # A file an emulator cannot start without is no detail: counted.
        say(needed_absent_words(sum(1 for entry in skipped if entry.get("required")),
                                "--verbose"))
    # RomM's scan is the step after the install: the other hints say how to
    # install less, a detail.
    for line in end.hints:
        if OUTPUT.verbose or line == ROMM_SCAN_WORDS:
            say(line)


def _end_done(end: _Ending) -> None:
    """End a run that installed every file it could."""
    say, paths, downloaded, up_to_date = end.say, end.paths, end.downloaded, end.up_to_date
    sources = end.sources
    # No zero count, the screen's words: "Done. 0 files installed, 22
    # files already up to date" beside its "Everything is in place"
    in_place = f" {_plural(up_to_date, 'file')} already in place." if up_to_date else ""
    if not downloaded:
        say(f"\nDone. {EVERYTHING_IN_PLACE}")
    elif sources and "," not in sources and not KEPT.summary():
        # Every file from one place: "22 files installed." over "22 files
        # copied from packx." said one count twice.
        say(f"\nDone. {sources}{in_place}")
        sources = ""
    else:
        say(f"\nDone. {_plural(downloaded, 'file')} installed.{in_place}")
    if sources:
        say(f"  {sources}")
    if end.installed_kinds:
        say(end.installed_kinds)
    if OUTPUT.verbose or not OUTPUT.where_said:
        say(f"BIOS folder: {_locations(paths)}")
    for line in end.kept:
        say(line)
    _say_left_out(end)
    if end.same_choice and OUTPUT.verbose:
        # After the questions, as the screen's result ends: "the same
        # command" was one that asked them.
        for line in end.same_lines:
            say(line)
        say("To check this later, run that command with --check.")
    elif OUTPUT.verbose:
        say("To check this later, run the same command with --check.")
    say(next_step_words(end.platform_of, paths))


class OutcomeDetails(NamedTuple):
    """What a run's end says besides its counts (_report_outcome)."""

    failures: list[tuple[str, str]] | None = None
    transferred: int = 0
    seconds: float = 0.0
    declined: int = 0
    assumed: set[Path] | None = None
    omitted_entries: list[dict] | None = None
    platform_of: dict[Path, str] | None = None
    hints: list[str] | None = None
    sources: str = ""
    offline: int = 0
    kinds: tuple[Tally, int] | None = None
    same_choice: str = ""
    notes: list[str] | None = None
    missing: Tally | None = None


def _report_outcome(
    paths: list[Path],
    downloaded: int,
    up_to_date: int,
    errors: int,
    omitted: int,
    interrupted: bool,
    *,
    details: OutcomeDetails | None = None,
    term: Terminal | None = None,
) -> None:
    """Close the run on what happened, and leave with a status that says so.
    kinds is the count of the files installed (tally) and of the data
    tree files, given for a list marking its game data, said apart. notes
    are lines every ending repeats (a list built for another version).
    missing is the count of the files --offline left out, by kind, given as
    kinds is.

    A run that installed nothing used to end on the word Done and a zero exit,
    which reads as success to a person and to a script alike. offline counts
    the files --offline left out at a terminal, kept apart from a "no" to
    the size question: counted with it, 14,696 files missing ended on Done
    and exit 0 once 4 came from this machine. They end the run as files
    that failed do, 1 when some were installed and 2 when none were, the
    codes the full screen's run gives. term paints the status words.
    """
    d = details or OutcomeDetails()
    failures, transferred, seconds, declined = d.failures, d.transferred, d.seconds, d.declined
    offline, same_choice, notes = d.offline, d.same_choice, d.notes
    say = _status_print(term)
    # The command making the same choice ends every result the screen ends
    # with it: "Finished with files missing" gave none.
    same_lines = ([f"Same choice without questions: {screen_text(same_choice)}"]
                  if same_choice and OUTPUT.verbose else [])
    # A file --offline left out is not a failure, whether the run asked or
    # not: without questions it was "14698 files failed", and "Run the same
    # command again to retry only those", which cannot fetch them.
    records, left = split_offline(failure_records(failures or []))
    if left:
        errors = max(0, errors - len(left))
        offline += len(left)
    if transferred and seconds > 0 and OUTPUT.verbose:
        verb = "copied from the pack" if LOCAL.pack is not None else "downloaded"
        say(f"\n{format_size(transferred)} {verb} in "
            f"{format_duration(seconds)} ({format_size(int(transferred / seconds))}/s).")
    _say_failures(say, records)
    if declined and not downloaded and not errors and not interrupted and not offline:
        say(f"\nNothing installed: {_plural(declined, 'file')} not downloaded, as answered.")
        if up_to_date:
            say(f"{_plural(up_to_date, 'file')} already in place at {_locations(paths)}.")
        for note in notes or []:
            say(note)
        return
    kept, unplaced = _kept_and_unplaced(d.omitted_entries or [], notes)
    if interrupted:
        say(f"\nStopped. {_plural(downloaded, 'file')} installed.")
        for line in kept:
            say(line)
        say("Run the same command again to carry on from here. Nothing is lost.")
        sys.exit(130)

    # A standalone copy fails by absolute path, in an emulator's folder
    # rather than the BIOS folder: that folder is where the write went.
    elsewhere = sorted({Path(record.dest).parent for record in records
                        if Path(record.dest).is_absolute()})
    advice = _failure_advice(paths, records, d.assumed, d.platform_of)
    paths = paths + [folder for folder in elsewhere if folder not in paths]

    # The kinds installed, on every end that installed some, under where
    # they came from: as the screen's result says them.
    installed_kinds = (f"  Installed: {installed_words(d.kinds[0].bios, d.kinds[0].games, d.kinds[1])}."
                       if d.kinds and d.kinds[0].files and downloaded and OUTPUT.verbose else "")
    end = _Ending(
        say=say, paths=paths, downloaded=downloaded, up_to_date=up_to_date, errors=errors,
        omitted=omitted, offline=offline, failures=records, sources=d.sources, kept=kept,
        advice=advice, same_lines=same_lines, installed_kinds=installed_kinds,
        omitted_entries=d.omitted_entries or [], unplaced=unplaced,
        platform_of=d.platform_of or {}, hints=d.hints or [], same_choice=same_choice,
        missing=d.missing,
    )
    if offline:
        _end_offline(end)
    if errors and not downloaded:
        _end_nothing_installed(end)
    if errors:
        _end_with_errors(end)
    _end_done(end)


NEXT_ON_CARD = "Next: put the card back in the device and start a game."
# On the device detection found the installer running on (KNULLI, Batocera):
# that system is already started.
NEXT_ON_DEVICE = "Next: start a game."


def next_step_words(platform_of: dict[Path, str], paths: list[Path]) -> str:
    """The step after an install that ended well: a card goes back in its
    device, a setup on this machine is started."""
    setups = [(platform_of.get(path, ""), path) for path in paths]
    if setups and all(plat and on_its_card(plat, path) for plat, path in setups):
        return NEXT_ON_CARD
    if setups and all(plat and detected_os(plat, path) for plat, path in setups):
        return NEXT_ON_DEVICE
    names = list(dict.fromkeys(display_name(plat) for plat, path in setups if plat))
    if len(names) == 1:
        return f"Next: start {names[0]} and play."
    return "Next: start your emulators and play."


def _offline_remedy(folders: list[str] | None = None, named: bool = False) -> str:
    """Where files --offline does not fetch can still come from: the
    folders --from named (folders, on the screen) are not suggested again.
    One wording for line mode, a run without questions, --check and the
    screen. named: the line before already says what the folders lack."""
    labels = (folders if folders is not None
              else [index.label for index in LOCAL.folders])
    if labels and named:
        return f"Run the installer again with a pack (--from-pack) or {offline_undo()}."
    if labels:
        names = ", ".join(screen_text(shown_path(label)) for label in labels)
        return (f"They are not in {names}: run the installer again with a pack "
                f"(--from-pack) or {offline_undo()}.")
    return ("Copy them from an old card or a folder (--from), or run the installer "
            f"again with a pack (--from-pack) or {offline_undo()}.")


def _check_fetch_line(fetch: int, beside: str, lacking: int = 0, wrong: bool = False) -> str:
    """What --check says a run without it does with the files not in place:
    offline, those it cannot fetch are said so, not "run it to fetch them".
    With a pack, those it holds are copied and those it lacks are said lacking
    (lacking): "fetch them" was said with a pack and no network."""
    if LOCAL.pack is not None:
        held = fetch - lacking
        if not held:
            return (f"  {LOCAL.pack.name} holds none of them: a newer pack, or a run "
                    "without --from-pack, installs them.")
        return (f"  Run the same command without --check to copy {held} of them from "
                f"{LOCAL.pack.name}. A wrong copy is replaced, and the one in "
                f"place kept in {BACKUP_DIR} beside {beside}.")
    if _offline_only():
        if not fetch:
            return "  Run the same command without --check to copy them into place."
        return (f"  {agree(fetch, 'file needs', 'files need')} the "
                f"internet, which {offline_named()} does not use. {_offline_remedy()}")
    # What becomes of a wrong copy is said where there is one.
    return ("  Run the same command without --check to fetch them."
            + (f"\n  A wrong copy is replaced, and the one in place kept in {BACKUP_DIR} "
               f"beside {beside}." if OUTPUT.verbose or wrong else ""))


# The definitions in a few words, for a help with no room for the sentences.
_SHORT_DEFINITIONS = (
    ("Game data:", "Game data: what a game reads, of no use to other cores."),
    ("Data files:", "Data files: an emulator's own data folder."),
)


LINE_SAVE_REMEDY = "Name it with --save-dir next time."
