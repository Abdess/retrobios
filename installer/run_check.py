"""The passes that read a setup: files in place, files missing, and what a dry run would do."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from installer.console import OUTPUT, detail
from installer.datadirs import data_directory_state, data_fetch_bytes
from installer.diagnosis import CheckHeld, bios_folder_index, check_lines
from installer.events import EVENTS
from installer.fetch_plan import emit_fetch_plan, fetch_plan
from installer.install_record import _RECORD_TAKEN, record_menu_words
from installer.local_check import check_local, head_reads_done
from installer.local_copies import (
    copy_plan_lines,
    emit_copies,
    emit_unreadable,
    plan_local_copies,
    unreadable_copies,
    unreadable_lines,
)
from installer.offline import LOCAL, _offline_only
from installer.outcome import EVERYTHING_IN_PLACE, _check_fetch_line
from installer.pack_parts import split_pack_lines
from installer.pack_source import pack_lacks_words
from installer.paths import _entry_path, shown_path
from installer.plan import _print_plan, bulk_hint
from installer.safe_replace import plan_kept
from installer.space import bytes_written
from installer.tally import (
    CheckTally,
    _absent_required,
    _emit_check,
    _needed_lines,
    needed_absent_words,
)
from installer.text import _plural

if TYPE_CHECKING:
    from installer.run_files import _PlatformPass
    from installer.run_setups import _InstallRun


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
    p.plan = plan = fetch_plan(to_download, copies, data_states)
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
        _emit_check(
            p.plat_name, p.manifest, bios_path,
            CheckTally(files, up_to_date, mismatched,
                       sum(len(state[1]) for _entry, state in data_states),
                       len(p.omitted_files),
                       sum(data_fetch_bytes(entry, state[1]) for entry, state in data_states),
                       bytes_written(plan.without_lacking(to_download), data_states)),
            chosen=selection[0] if selection else None,
        )
        emit_fetch_plan(p.plat_name, plan)
        emit_copies(p.plat_name, to_download, copies, bios_index, bios_path, files)
        emit_unreadable(p.plat_name, unread)
    run.total_verified += len(up_to_date)


def _pass_check_missing(run: _InstallRun, p: _PlatformPass) -> None:
    """--check: the files not in place named, and how to get them."""
    args, bios_path = run.args, p.bios_path
    to_download, mismatched, copies, plan = p.to_download, p.mismatched, p.copies, p.plan
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
    if plan.lacking:
        print(f"\n  {pack_lacks_words(len(plan.lacking), len(plan.fetched))}")
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
    print(_check_fetch_line(len(plan.fetched) + plan.data_files,
                            "the BIOS folder", len(plan.lacking), bool(mismatched)))
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
    plan = p.plan
    # Said before the plan promises a count and a size, as an
    # install says it: the dry run promised 23 files where the pack
    # held 20.
    if plan.lacking:
        print(f"\n  {pack_lacks_words(len(plan.lacking), len(plan.fetched))}")
    _print_plan(plan.coming, bios_path, run.term,
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
