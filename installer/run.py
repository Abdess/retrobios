"""One install run: each setup's files checked, planned or installed, then its record and summary."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from installer.console import OUTPUT, Progress, _confirm, detail
from installer.datadirs import data_directory_state, data_fetch_bytes, install_data_directory
from installer.destination import _missing_dest, _refuse_closed, _refuse_file, on_its_card
from installer.detect_frontends import launchbox_bios_dirs, launchbox_root
from installer.detect_os import detected_shown
from installer.diagnosis import CheckHeld, bios_folder_index, check_lines
from installer.download import download_files
from installer.events import EVENTS, _event_mode
from installer.filesystems import NOMEDIA, hide_from_media_scanner
from installer.from_folders import (
    copy_plan_lines,
    emit_copies,
    emit_unreadable,
    plan_local_copies,
    sources_line,
    unreadable_copies,
    unreadable_lines,
)
from installer.frontend_folders import _retroarch_config_at
from installer.handheld_app import finish_app
from installer.host_fs import DRIVE_FULL, NOT_WRITABLE, _folder_writable
from installer.install_record import (
    _RECORD_TAKEN,
    apply_record,
    choice_given,
    games_folder_kept,
    record_argv,
    record_day,
    record_file,
    record_menu_words,
    record_paths,
    setup_record,
    write_record,
)
from installer.invocation import _INVOCATION
from installer.local_check import check_local, head_reads_done
from installer.offline import LOCAL, _offline_only, offline_named
from installer.outcome import (
    EVERYTHING_IN_PLACE,
    OfflineReason,
    OutcomeDetails,
    _check_fetch_line,
    _report_outcome,
    _write_advice,
)
from installer.pack import run_pack, split_pack_lines
from installer.pack_source import NOT_IN_PACK, pack_holds_trees, pack_lacks, pack_lacks_words
from installer.paths import _entry_path, shown_path
from installer.plan import CONFIRM_FROM_BYTES, _check_free_space, _print_plan, bulk_hint
from installer.platforms import display_name
from installer.romm import ROMM_SCAN_WORDS, _check_run_romm, _pass_romm_layout
from installer.run_files import _select_setup_files
from installer.run_setups import (
    _check_run_cores,
    _check_run_target,
    _choose_setups,
    _detect_setups,
    _print_platform_list,
    _start_install,
)
from installer.safe_replace import KEPT, NOT_KEPT, plan_kept
from installer.space import bytes_written
from installer.standalone import do_standalone_copies, standalone_folders_here
from installer.tally import (
    CheckTally,
    _absent_required,
    _bytes,
    _emit_check,
    _left_out_events,
    _needed_lines,
    _skipped,
    needed_absent_words,
    tally,
)
from installer.text import _plural, agree, format_size, screen_text

if TYPE_CHECKING:
    from installer.from_folders import FolderIndex
    from installer.run_files import _PlatformPass
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
        # What the run would write, as _pass_download holds it against the
        # free space: the screen's plan warns on this number.
        lacking = {id(f) for f in pack_lacks([f for f in to_download if id(f) not in copies])}
        _emit_check(
            p.plat_name, p.manifest, bios_path,
            CheckTally(files, up_to_date, mismatched,
                       sum(len(state[1]) for _entry, state in data_states),
                       len(p.omitted_files),
                       sum(data_fetch_bytes(entry, state[1]) for entry, state in data_states),
                       bytes_written([f for f in to_download if id(f) not in lacking],
                                     data_states)),
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


def _pass_make_folder(run: _InstallRun, p: _PlatformPass, written: int) -> bool:
    """The space checked and the BIOS folder made. True when it was created."""
    args, plat_name, bios_path = run.args, p.plat_name, p.bios_path
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
    coming = [f for f in p.to_download if id(f) not in lacking]
    dl_size = _bytes(coming)
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
    created = _pass_make_folder(run, p, bytes_written(coming, p.data_states))
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
        if counts["updated"]:
            # A rolling source moved on since the list: its bytes landed.
            line += f", {counts['updated']} newer than the pack's (as {entry['url']} serves them)"
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
        _check_free_space(p.bios_path, bytes_written([], writable), p.plat_name,
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
