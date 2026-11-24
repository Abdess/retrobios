"""The download pass of a setup: what offline leaves, the question, the folder, the fetch."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from installer.console import OUTPUT, Progress, _confirm, detail
from installer.destination import on_its_card
from installer.detect_os import detected_shown
from installer.download import download_files
from installer.events import EVENTS
from installer.install_record import (
    _RECORD_TAKEN,
    games_folder_kept,
    record_argv,
    record_day,
    record_file,
    record_paths,
    setup_record,
    write_record,
)
from installer.invocation import _INVOCATION
from installer.local_copies import copy_plan_lines, unreadable_lines
from installer.offline import LOCAL, _offline_only
from installer.outcome import _write_advice
from installer.pack_source import NOT_IN_PACK, pack_lacks_words
from installer.paths import shown_path
from installer.plan import CONFIRM_FROM_BYTES, _check_free_space
from installer.refusal import Refusal
from installer.romm import ROMM_SCAN_WORDS
from installer.space import bytes_written
from installer.tally import _bytes
from installer.text import _plural, format_size, screen_text

if TYPE_CHECKING:
    from installer.setup_passes import _PlatformPass
    from installer.run_setups import _InstallRun


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
        coming = len(p.to_download) - len(lacking) + p.plan.data_files
        weight = dl_size + p.plan.data_bytes
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


def _pass_make_folder(run: _InstallRun, p: _PlatformPass, written: int) -> bool:
    """The space checked and the BIOS folder made. True when it was created."""
    plat_name, bios_path = p.plat_name, p.bios_path
    with run.writes(len(p.to_download)):
        # Checked before the folder is created: a run stopped for space
        # left an empty BIOS folder behind. The data trees count too,
        # written after the files on the same drive.
        _check_free_space(bios_path, written, plat_name,
                          1 if run.total_downloaded else 2, on_its_card(plat_name, bios_path))
        p.space_checked = True
        created = not bios_path.exists()
        try:
            bios_path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            sys.stdout.flush()
            # The documented code for a folder that cannot be written,
            # as when it exists read-only. 1 once an earlier platform
            # of the run installed something.
            raise Refusal(
                "dest", "not_writable", plat_name,
                f"\nCannot create {bios_path}.", f"  {exc.strerror}.",
                _write_advice(bios_path, bios_path in run.assumed_dests, plat_name),
                code=1 if run.total_downloaded else 2,
                message=f"{bios_path} cannot be created: {exc.strerror}",
            ) from None
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
    p.landed += progress.landed
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
    plan = p.plan
    fetched = plan.fetched
    if _offline_only() and fetched:
        _pass_offline_left(run, p, fetched)
        fetched = []
    # What the pack does not hold is said before a size is promised:
    # a pack older than the list gave "Copy 6.6 GB" and 8358 files
    # failed. They are still tried, and fail as
    # not in the pack, the size and the question leaving them out.
    # Offline there is no pack, so nothing is lacking.
    lacking = {id(f) for f in plan.lacking}
    if lacking:
        print(f"\n  {pack_lacks_words(len(lacking), len(fetched))}")
    if lacking and len(lacking) == len(p.to_download) and not plan.data_files:
        # Nothing here can come from the pack: no "Copying 0 files", no
        # folder made, each file failed as not in it.
        run.failures.extend((f["dest"], NOT_IN_PACK) for f in p.to_download)
        run.total_errors += len(p.to_download)
        run.files_pending += len(p.to_download)
        run.total_up_to_date += len(p.up_to_date)
        return "next"
    coming = plan.without_lacking(p.to_download)
    dl_size = _bytes(coming)
    fetch_size = _bytes(plan.without_lacking(fetched))
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
    created = _pass_make_folder(run, p, bytes_written(coming, p.data_states))
    return "stop" if _pass_fetch(run, p, dl_size, created) else "go"
