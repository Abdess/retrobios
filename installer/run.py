"""One install run: each setup applied, its trees and standalone copies, then its record and summary."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from installer.console import Progress, detail
from installer.datadirs import install_data_directory
from installer.destination import _missing_dest, _refuse_closed, _refuse_file, on_its_card
from installer.detect_launchbox import launchbox_bios_dirs, launchbox_root
from installer.events import EVENTS, _event_mode
from installer.failure_causes import OfflineReason, failure_events
from installer.filesystems import NOMEDIA, hide_from_media_scanner
from installer.from_folders import sources_line
from installer.frontend_folders import _retroarch_config_at
from installer.handheld_app import finish_app
from installer.host_fs import DRIVE_FULL, NOT_WRITABLE, _folder_writable
from installer.install_record import (
    _RECORD_TAKEN,
    apply_record,
    choice_given,
    record_file,
)
from installer.invocation import _INVOCATION
from installer.offline import LOCAL, offline_named
from installer.outcome import (
    EVERYTHING_IN_PLACE,
    OutcomeDetails,
    _report_outcome,
)
from installer.pack import run_pack
from installer.paths import shown_path
from installer.plan import _check_free_space
from installer.platforms import display_name
from installer.refusal import Refusal
from installer.romm import _check_run_romm, _pass_romm_layout
from installer.run_check import _pass_check_existing, _pass_check_report, _pass_dry_run
from installer.run_download import _pass_download, _remember_install
from installer.run_files import _select_setup_files
from installer.run_setups import (
    _check_run_cores,
    _check_run_target,
    _choose_setups,
    _detect_setups,
    _print_platform_list,
    _start_install,
)
from installer.safe_replace import KEPT, NOT_KEPT
from installer.space import bytes_written
from installer.standalone import do_standalone_copies, preview_standalone, standalone_folders_here, standalone_plan
from installer.tally import (
    _left_out_events,
    _skipped,
    tally,
)
from installer.text import agree

if TYPE_CHECKING:
    from installer.folder_index import FolderIndex
    from installer.setup_passes import _PlatformPass
    from installer.run_setups import _InstallRun


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
        with run.writes(sum(len(state[1]) for _entry, state in writable)):
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
        # The files this run checked in place or put there, never others
        # the folder holds.
        copied, skipped, copy_failed = do_standalone_copies(
            manifest, p.bios_path, os_type, extra_dirs, run.failures,
            p.up_to_date + p.landed,
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


def _pass_standalone_preview(run: _InstallRun, p: _PlatformPass) -> None:
    """--check or --dry-run with --standalone-copies: the emulator folders
    found here, what each holds and lacks or would receive, as a run with
    no platform says them."""
    if not (p.manifest.get("standalone_copies") and run.args.standalone_copies):
        return
    lb_root = launchbox_root(run.os_type)
    plan = standalone_plan([{**p.manifest, "files": p.files}], run.os_type,
                           launchbox_bios_dirs(lb_root) if lb_root else None)
    if not plan:
        return
    print("\nStandalone emulators:")
    pending, _in_place = preview_standalone(plan, run.args, run.term)
    if run.args.check:
        run.check_pending += pending
    else:
        run.files_pending += pending


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
        _pass_standalone_preview(run, p)
        return False
    if args.dry_run:
        _pass_dry_run(run, p)
        _pass_standalone_preview(run, p)
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


def _emit_summary(run: _InstallRun) -> None:
    """The failures and summary events of what the run did, at its end or
    where a refusal stopped it."""
    args = run.args
    if run.failures:
        EVENTS.emit("failures", failed=failure_events(run.failures))
    EVENTS.emit(
        "summary", mode=_event_mode(args), installed=run.total_downloaded,
        up_to_date=run.total_verified if args.check or args.dry_run else run.total_up_to_date,
        pending=run.check_pending if args.check else run.files_pending,
        failed=[{"dest": dest, "reason": str(reason)} for dest, reason in run.failures],
        skipped=_skipped(run.omitted_seen), left_out=_left_out_events(run.left_out_seen),
        kept=KEPT.summary(), interrupted=run.total_interrupted,
    )


def _finish_install(run: _InstallRun, real_stdout: TextIO) -> None:
    """The run's summary event, its exit code and its result."""
    args, platforms = run.args, run.platforms
    sys.stdout = real_stdout
    if args.find and getattr(args, "json", False):
        # The matches are the answer: nothing was installed.
        sys.exit(4 if getattr(args, "find_failed", False) else 0)
    if not run.listing:
        _emit_summary(run)
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
    """One run of the installer, once the options are read, a refusal
    reported where it ends the run: its error event before end, its lines
    before what the unwinding run says."""
    run = None
    try:
        run = _start_install(args, real_stdout)
        _install_run(run, real_stdout)
    except Refusal as refusal:
        refusal.report()
        # A stop once a step began writing reports what the run installed
        # before it, whatever stopped it.
        if run is not None and run.writing and not run.listing:
            _emit_summary(run)
        raise


def _install_run(run: _InstallRun, real_stdout: TextIO) -> None:
    args = run.args

    # Early exit for listing
    if args.list_platforms:
        _print_platform_list(run.os_type)
        return

    if _detect_setups(run):
        if run.standalone_only:
            _finish_install(run, real_stdout)
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
