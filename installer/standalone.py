"""Standalone emulators: their folders and the copies a launcher makes."""
from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from installer.console import Progress, _confirm
from installer.detect_launchbox import launchbox_bios_dirs, launchbox_root
from installer.download import download_files
from installer.host_fs import NOT_WRITABLE, _closed_to_this_user, _exists, _is_dir, _replace_with_copy, _write_refused
from installer.invocation import offline_requested
from installer.lists import fetch_manifest
from installer.local_check import check_local, unreachable_words
from installer.outcome import EVERYTHING_IN_PLACE, _check_fetch_line
from installer.paths import _destination_path, _within
from installer.plan import _check_free_space, _print_plan
from installer.plan_words import _sized
from installer.safe_replace import KEPT, NOT_KEPT, _NotKept, plan_kept

if TYPE_CHECKING:
    from installer.run_setups import _InstallRun
    from installer.terminal import Terminal


def _copy_targets(
    entry: dict, os_type: str, extra_dirs: dict[str, Path] | None = None,
) -> list[Path]:
    """The emulator folders a standalone copy entry names on this OS.

    WSL falls back to the Linux ones, and extra_dirs adds the folder a
    frontend such as LaunchBox keeps the emulator in.
    """
    targets = entry.get("targets", {}).get(os_type, [])
    if not targets and os_type == "wsl":
        targets = entry.get("targets", {}).get("linux", [])
    target_dirs = [Path(os.path.expandvars(os.path.expanduser(t))) for t in targets]
    extra_root = (extra_dirs or {}).get(entry.get("emulator", ""))
    if extra_root is not None:
        subdir = PurePosixPath(entry.get("file", "")).parent
        extra = extra_root if str(subdir) == "." else extra_root / subdir
        if extra not in target_dirs:
            target_dirs.append(extra)
    return target_dirs


def standalone_folders_here(
    manifest: dict, os_type: str, extra_dirs: dict[str, Path] | None = None,
) -> list[Path]:
    """The emulator folders of the manifest's standalone copies that exist
    on this machine: the ones --standalone-copies would write to."""
    found: list[Path] = []
    for entry in manifest.get("standalone_copies", []):
        if "note" in entry:
            continue
        for folder in _copy_targets(entry, os_type, extra_dirs):
            if folder not in found and _is_dir(folder):
                found.append(folder)
    return found


# The file lists a machine with standalone emulators and no platform is
# served from: EmuDeck's holds the Switch keys, RetroArch's the PPSSPP atlas
# and the Flycast flash, and each copy entry names its folders.
STANDALONE_SOURCES = ("emudeck", "retroarch")


def copy_sources(manifest: dict) -> list[tuple[dict, list[tuple[dict, str]]]]:
    """Each standalone copy entry of the manifest, with the entries of its
    file list it carries and the name each takes in the emulator folder.

    The one reading of a copy entry: a pattern matches the names the list
    gives, never whatever lies in the BIOS folder (a user's own
    scph9999.bin went to DuckStation). `source` is where this list puts the
    file that `file` names as the registry does for every platform: read
    there, it was missing wherever the pack places it elsewhere.
    """
    from fnmatch import fnmatch

    files = manifest.get("files", [])
    by_dest = {entry["dest"]: entry for entry in files}
    carried: list[tuple[dict, list[tuple[dict, str]]]] = []
    for copy in manifest.get("standalone_copies", []):
        if "note" in copy:
            continue
        if "pattern" in copy:
            sources = [entry for entry in files
                       if fnmatch(PurePosixPath(entry["dest"]).name, copy["pattern"])]
        else:
            held = by_dest.get(copy.get("source") or copy["file"])
            sources = [held] if held else []
        # `as`: the name the emulator reads, when it is not the
        # platform's (melonDS's dsisd.bin, xemu's eeprom.bin).
        carried.append((copy, [(entry, copy.get("as") or PurePosixPath(entry["dest"]).name)
                               for entry in sources]))
    return carried


def standalone_plan(
    manifests: list[dict], os_type: str, extra_dirs: dict[str, Path] | None = None,
) -> list[tuple[Path, list[dict]]]:
    """What each emulator folder found here receives, by its own file name.

    The standalone copies of the manifests (copy_sources), each entry named
    as the emulator reads it. A run with no platform fetches them from the
    lists: an ES-DE user with DuckStation and PCSX2 and no RetroArch had no
    tree to copy from. The first list that holds a name for a folder
    serves it.
    """
    plan: dict[Path, dict[str, dict]] = {}
    for manifest in manifests:
        for copy, sources in copy_sources(manifest):
            for folder in _copy_targets(copy, os_type, extra_dirs):
                if not sources or not _is_dir(folder):
                    continue
                chosen = plan.setdefault(folder, {})
                for entry, name in sources:
                    chosen.setdefault(name, {**entry, "dest": name})
    return [(folder, list(entries.values())) for folder, entries in plan.items() if entries]


def _check_standalone_folder(to_download: list[dict], mismatched: list[dict],
                             verbose: bool) -> None:
    """What --check says of one standalone emulator folder."""
    for entry in mismatched:
        print(f"    wrong copy: {entry['dest']}")
    wrong = {id(entry) for entry in mismatched}
    missing = [entry for entry in to_download if id(entry) not in wrong]
    for entry in missing[:10] if not verbose else missing:
        print(f"    missing: {entry['dest']}")
    if not verbose and len(missing) > 10:
        print(f"    ... and {len(missing) - 10} more missing (--verbose lists them all)")
    if not to_download:
        print(f"  {EVERYTHING_IN_PLACE}")


def preview_standalone(plan: list[tuple[Path, list[dict]]], args: argparse.Namespace,
                       term: Terminal) -> tuple[int, int]:
    """--check or --dry-run over the emulator folders of a standalone plan:
    what each holds and lacks, or what a run would write. The count of the
    files not in place, and of those in place."""
    pending = in_place = 0
    for folder, entries in plan:
        print(f"\n{folder}:")
        to_download, up_to_date, mismatched = check_local(entries, folder, jobs=args.jobs)
        to_download.extend(mismatched)
        if args.check:
            _check_standalone_folder(to_download, mismatched, args.verbose)
        else:
            _print_plan(to_download, folder, term, kept=plan_kept(mismatched, folder),
                        verbose=args.verbose)
        pending += len(to_download)
        in_place += len(up_to_date)
    return pending, in_place


def _install_standalone_folders(run: _InstallRun) -> bool:
    """Fill the standalone emulator folders found here, with no platform,
    their counts kept in the run's totals: the run ends as every run does.

    False when this machine has none, the run then going on to the platform
    question or hint.
    """
    args, os_type, term = run.args, run.os_type, run.term
    if offline_requested():
        # Their folders are named by file lists this run cannot fetch: the
        # first refusal ended an --offline run that asked nothing of EmuDeck
        # on "No file list for emudeck".
        return False
    manifests = [fetch_manifest(plat) for plat in STANDALONE_SOURCES]
    lb_root = launchbox_root(os_type)
    plan = standalone_plan(manifests, os_type,
                           launchbox_bios_dirs(lb_root) if lb_root else None)
    if not plan:
        return False
    print("  Found standalone emulator folders:")
    for folder, entries in plan:
        print(f"    {folder}  {_sized(entries)}")
    if run.interactive and not (args.check or args.dry_run or args.yes) and not _confirm(
        "\nInstall the BIOS files these emulators read into their folders? [Y/n] "
    ):
        return False
    run.installed_paths = [folder for folder, _entries in plan]
    if args.check or args.dry_run:
        pending, in_place = preview_standalone(plan, args, term)
        if args.check:
            run.check_pending += pending
            run.total_verified += in_place
            if pending:
                print("\n" + _check_fetch_line(pending, "its folder"))
        else:
            run.files_pending += pending
        return True
    for folder, entries in plan:
        print(f"\n{folder}:")
        to_download, up_to_date, mismatched = check_local(entries, folder, jobs=args.jobs)
        to_download.extend(mismatched)
        run.total_up_to_date += len(up_to_date)
        if not to_download:
            print(f"  {EVERYTHING_IN_PLACE}")
            continue
        size = sum(entry.get("size", 0) for entry in to_download)
        with run.writes(len(to_download)):
            _check_free_space(folder, size, code=1 if run.total_downloaded else 2)
        progress = Progress(len(to_download), size, term)
        failed, interrupted = download_files(
            to_download, folder, jobs=args.jobs, verbose=args.verbose,
            term=term, progress=progress,
        )
        run.total_downloaded += progress.installed
        run.total_errors += len(failed)
        run.failures.extend((str(folder / dest), reason) for dest, reason in failed)
        run.total_bytes += progress.transferred()
        run.total_seconds += progress.elapsed()
        if interrupted:
            run.total_interrupted = True
            break
    return True


def _print_standalone_note(entry: dict, os_type: str) -> None:
    """A note entry's message, said when its emulator is found here."""
    detect_paths = entry.get("detect", {}).get(os_type, [])
    if not detect_paths and os_type == "wsl":
        detect_paths = entry.get("detect", {}).get("linux", [])
    for dp in detect_paths:
        expanded = Path(os.path.expandvars(os.path.expanduser(dp)))
        if _is_dir(expanded):
            print(f"  {entry['note']}")
            break


def _copy_standalone_file(src: Path, dest: Path, resolved_dir: Path,
                          failures: list[tuple[str, str]] | None) -> bool:
    """Copy one file into an emulator folder, False when it was refused."""
    linked = dest.is_symlink()
    # A crafted source name would climb out of the directory.
    if not linked and not _within(dest, resolved_dir):
        print(f"  ERROR: {dest}: {OUTSIDE_TARGET}")
        if failures is not None:
            failures.append((str(dest), OUTSIDE_TARGET))
        return False
    try:
        KEPT.keep(resolved_dir, PurePosixPath(dest.name), dest, {}, src)
    except _NotKept as exc:
        print(f"  ERROR: {dest}: {NOT_KEPT} ({exc})")
        if failures is not None:
            failures.append((str(dest), f"{NOT_KEPT} ({exc})"))
        return False
    try:
        if linked:
            # Writing through a link already at the name would
            # leave the folder the user opted into. The link
            # itself gives way to the file.
            _replace_with_copy(src, dest)
            print(f"  {dest}: link replaced by the file")
        else:
            shutil.copy2(src, dest)
    except OSError as exc:
        print(f"  ERROR: {dest}: {exc.strerror or exc}")
        if failures is not None:
            reason = NOT_WRITABLE if _write_refused(exc) else str(
                exc.strerror or exc)
            failures.append((str(dest), reason))
        return False
    return True


def do_standalone_copies(
    manifest: dict, bios_path: Path, os_type: str,
    extra_dirs: dict[str, Path] | None = None,
    failures: list[tuple[str, str]] | None = None,
    verified: list[dict] | None = None,
) -> tuple[int, int, int]:
    """Copy BIOS files to standalone emulator directories.

    Each copy entry carries what copy_sources names, the entries of the
    file list, read in bios_path: verified holds the entries this run found
    or put there with their hashes, and no other is copied. Without it,
    every entry of the list present in bios_path. A note entry prints its
    message when its emulator is found here, and WSL falls back to the
    Linux folders.

    extra_dirs maps the emulator id of an entry to a root that replaces the
    default per-OS locations, for setups such as LaunchBox that keep their
    emulators outside them. The layout below the root is the same.

    Returns (copied, skipped, failed): skipped is a target directory that
    does not exist, failed a copy the system refused (permission, disk
    full, read-only mount) or a name leading out of the folder, which used
    to be counted as "dir not found". A link already at a file's name is
    replaced by the file, never written through.
    Each failure is also appended to failures, by absolute path, for the
    summary to name.
    """
    copies = manifest.get("standalone_copies", [])
    if not copies:
        return 0, 0, 0
    carried = {id(copy): sources for copy, sources in copy_sources(manifest)}
    held = None if verified is None else {entry["dest"] for entry in verified}

    copied = 0
    skipped = 0
    failed = 0

    for entry in copies:
        if "note" in entry:
            _print_standalone_note(entry, os_type)
            continue

        sources = [(src, name) for src, name in (
            (_destination_path(bios_path, item["dest"]), name)
            for item, name in carried[id(entry)]
            if held is None or item["dest"] in held) if _exists(src)]
        if not sources:
            continue

        for target_dir in _copy_targets(entry, os_type, extra_dirs):
            closed = _closed_to_this_user(target_dir)
            if closed is not None:
                # Android 11 and later keep each app's Android/data folder
                # to that app, there or not: Termux cannot copy Dolphin's
                # IPL.bin there, and cannot tell whether Dolphin is installed.
                print(f"  {target_dir}: {unreachable_words(closed)}, not copied")
                skipped += len(sources)
                continue
            if not _is_dir(target_dir):
                skipped += len(sources)
                continue
            resolved_dir = target_dir.resolve()
            for src, name in sources:
                dest = target_dir / name
                if _copy_standalone_file(src, dest, resolved_dir, failures):
                    copied += 1
                else:
                    failed += 1

    return copied, skipped, failed


OUTSIDE_TARGET = "name leads outside the emulator folder"
