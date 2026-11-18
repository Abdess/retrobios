"""The plan shown before a download, and the download of every file."""
from __future__ import annotations

import concurrent.futures
import shutil
import sys
from collections.abc import Collection
from pathlib import Path

from installer.constants import _stop, _writing
from installer.cores import entry_systems
from installer.datadirs import data_fetch_bytes
from installer.download import _download_one
from installer.embedded import shown_path
from installer.events import EVENTS
from installer.from_folders import LocalCopy, _bytes
from installer.invocation import _INVOCATION
from installer.line_ui import _sized
from installer.offline import LOCAL, offline_named, offline_undo
from installer.outcome import (
    EVERYTHING_IN_PLACE,
    PLAN_FILES_PER_SYSTEM,
    PLAN_FRAME_LINES,
    PLAN_GROUP_TITLES,
    PLAN_LARGEST_SYSTEMS,
    _REFUSALS,
    _offline_only,
)
from installer.pack_source import NOT_WRITABLE, _folder_writable
from installer.probe import _exists
from installer.prompt import _ask
from installer.record import OTHER_TITLE, system_title
from installer.tally import parts_words, tally
from installer.terminal import Progress, Terminal, terminal_size
from installer.text import _plural, cell_width, format_size


def _confirm(prompt: str) -> bool:
    """Yes unless the answer refuses: n, no, or one of the quit words."""
    answer = _ask(prompt).strip().lower()
    return not (answer.startswith("n") or answer in _REFUSALS)


def _plan_by_system(
    to_download: list[dict], verbose: bool, manifest: dict | None,
) -> tuple[dict[str, list[dict]], dict[str, str]]:
    """The files of a plan by system, and the title each system is listed by."""
    by_system: dict[str, list[dict]] = {}
    titles: dict[str, str] = {}
    for entry in to_download:
        names = [system_title(name, manifest) for name in entry_systems(entry)]
        system = ", ".join(names) or OTHER_TITLE
        by_system.setdefault(system, []).append(entry)
        # Batocera's group of systems sharing MAME's device ROMs was one line
        # of 732 characters, ten rows on an 80-column terminal.
        titles[system] = (system if verbose or len(names) <= PLAN_GROUP_TITLES
                          else f"{', '.join(names[:2])} and {len(names) - 2} more systems")
    return by_system, titles


def _plan_listing(
    by_system: dict[str, list[dict]], titles: dict[str, str], term: Terminal, verbose: bool,
) -> list[tuple[str, str]]:
    """Each system of a plan and its files."""
    shown = None if verbose else PLAN_FILES_PER_SYSTEM
    # (line, its text without styles), the second measuring the rows it takes.
    listing: list[tuple[str, str]] = []
    for system in sorted(by_system):
        entries = sorted(by_system[system], key=lambda e: e["dest"])
        listing.append((f"  {term.bold(titles[system])}  {_sized(entries)}",
                        f"  {titles[system]}  {_sized(entries)}"))
        listing += [(f"    {entry['dest']}  {term.dim(format_size(entry.get('size', 0)))}",
                     f"    {entry['dest']}  {format_size(entry.get('size', 0))}")
                    for entry in entries[:shown]]
        if shown is not None and len(entries) > shown:
            more = f"    ... and {len(entries) - shown} more"
            listing.append((more, more))
    return listing


def _print_largest_systems(
    to_download: list[dict], by_system: dict[str, list[dict]], titles: dict[str, str],
    term: Terminal,
) -> None:
    """The largest systems of a plan taller than the screen."""
    largest = sorted(by_system, key=lambda s: (-_bytes(by_system[s]), s))
    # A file several systems share is a group of its own: "88 systems"
    # were 66 systems, as the full screen counts them, and 22 groups.
    systems = {name for entry in to_download for name in entry_systems(entry)}
    groups = (f"{_plural(len(systems), 'system')} in {len(largest)} groups"
              if systems and len(systems) != len(largest)
              else _plural(len(largest), 'system'))
    print(f"  {groups}, the largest first:")
    for system in largest[:PLAN_LARGEST_SYSTEMS]:
        print(f"  {term.bold(titles[system])}  {_sized(by_system[system])}")
    if len(largest) > PLAN_LARGEST_SYSTEMS:
        # Counted as the line above counts: the groups, when it names them.
        unit = "group" if "groups" in groups else "system"
        more = len(largest) - PLAN_LARGEST_SYSTEMS
        print(f"  ... and {more} more {unit}{'s' if more > 1 else ''}: --verbose lists "
              "every system and its files.")


def _print_plan(
    to_download: list[dict], bios_path: Path, term: Terminal,
    trees: Collection[tuple[dict, dict[str, dict]]] = (),
    kept: dict[Path, list[int]] | None = None,
    copied: Collection[str] = (),
    verbose: bool = False,
    manifest: dict | None = None,
) -> None:
    """What a real run would fetch: the totals first, then by system, each
    by the title the list and the screen give it, and nothing written.

    The data trees count in the total and come before the closing line:
    printed after it, they left 2636 RetroArch files out of the figure a
    user plans an SD card from. A listing taller than the screen pushed the
    total out of sight (599 lines for RetroArch): it gives way to the
    largest systems, and --verbose lists every file.
    """
    counts = tally(to_download)
    filled = [(entry, needed) for entry, needed in trees if needed]
    tree_counts = tally(meta for _entry, needed in filled for meta in needed.values())
    tree_files = tree_counts.files
    # One count for the plan, the screen's: "8252
    # files, and 2636 data files" read as two kinds of one thing. The kinds
    # follow, adding up to it.
    total = counts.files + tree_files
    tree_bytes = sum(data_fetch_bytes(entry, needed) for entry, needed in filled)
    parts = ([f"{_plural(total, 'file')} ({format_size(counts.size + tree_bytes)})"]
             if total else [])
    split = parts_words(counts if (manifest or {}).get("categorized")
                        else tally({"size": e.get("size")} for e in to_download),
                        tree_files, tree_bytes)
    if split and filled:
        split += f", the data files extracted from {_plural(len(filled), 'archive')}"
    # A pack is copied from, not downloaded: "Would download 23 files" was
    # said of a run that makes no network request.
    verb = "copy" if LOCAL.pack is not None else "download"
    if not parts and not copied:
        print(f"\n  {EVERYTHING_IN_PLACE} A real run would {verb} nothing.")
        return
    if parts and _offline_only():
        # --offline fetches none of them: "Would download" promised a
        # transfer the run never makes, where the screen says "need the
        # internet".
        one = total == 1
        print(f"\n{' and '.join(parts)} {'needs' if one else 'need'} the internet, which "
              f"{offline_named()} does not use. Run {offline_undo()}, and they would go "
              f"to {shown_path(bios_path)}:")
    elif parts:
        source = " from the pack" if LOCAL.pack is not None else ""
        print(f"\nWould {verb} {' and '.join(parts)}{source} to {shown_path(bios_path)}:")
    if parts and split:
        print(f"  {split}.")
    for line in copied:
        print(line)
    if not parts:
        print(f"\n  Nothing to {verb}.")
    by_system, titles = _plan_by_system(to_download, verbose, manifest)
    listing = _plan_listing(by_system, titles, term, verbose)
    columns, screen = terminal_size()
    # A line wider than the terminal wraps: counted as one, the total the
    # listing must leave in view scrolled out of sight.
    rows = sum(-(-max(1, cell_width(plain)) // max(1, columns)) for _line, plain in listing)
    if verbose or rows + len(filled) + PLAN_FRAME_LINES <= screen:
        for line, _plain in listing:
            print(line)
    else:
        _print_largest_systems(to_download, by_system, titles, term)
    for entry, needed in filled:
        source = LOCAL.pack.name if LOCAL.pack is not None else entry["url"]
        fetched = data_fetch_bytes(entry, needed)
        archive = ("" if fetched == sum(meta.get("size", 0) for meta in needed.values())
                   else f" (a {format_size(fetched)} archive)")
        print(f"  {term.bold(entry['ref'] + ' data')}  {_sized(list(needed.values()))}, "
              f"from {source}{archive}")
    for folder, (count, size) in sorted((kept or {}).items()):
        print(f"\n  Would keep {_plural(count, 'file')} already there ({format_size(size)}), "
              f"whose contents differ, in {folder}")
    print("\n  Nothing was written. Run without --dry-run to install.")


def _check_free_space(bios_path: Path, needed: int, plat: str = "", code: int = 2,
                      card: bool = False) -> None:
    """Stop before writing when the volume cannot hold the download.

    Reported against the nearest existing ancestor, since the destination
    may not exist yet. The run ends with code: 2 when nothing was installed,
    the status a script reads as "nothing installed", 1 after an earlier
    platform of the run installed files.
    """
    probe = bios_path
    while not _exists(probe) and probe != probe.parent:
        probe = probe.parent
    try:
        free = shutil.disk_usage(probe).free
    except OSError:
        return
    if free >= needed:
        return
    print(f"\nNot enough space on the drive holding {bios_path}.", file=sys.stderr)
    print(f"  Needed: {format_size(needed)}. Free: {format_size(free)}.",
          file=sys.stderr)
    if card:
        # Its system reads this card alone: another drive, with RetroArch's
        # list, was offered for an Onion card.
        print(f"  Free up {format_size(needed - free)} on the card, then run it again: "
              "its system reads its BIOS files there only.", file=sys.stderr)
        sys.exit(code)
    if not plat:
        print(f"  Free up {format_size(needed - free)}, or use --dest to install "
              "to another drive.", file=sys.stderr)
        sys.exit(code)
    # --dest alone used to mean RetroArch's list: the platform is named, so
    # a Batocera install moved to a USB drive stays Batocera's.
    print(f"  Free up {format_size(needed - free)}, or install to another drive:\n"
          f"    {_INVOCATION.command(plat, '<folder on another drive>')}",
          file=sys.stderr)
    sys.exit(code)


def download_files(
    files: list[dict], bios_path: Path, jobs: int = 8, verbose: bool = False,
    term: Terminal | None = None, progress: Progress | None = None,
    copies: dict[int, LocalCopy] | None = None,
) -> tuple[list[tuple[str, str]], bool]:
    """Download files in parallel.

    Returns the destinations that failed, each with its reason, and whether
    the run was interrupted. progress.installed counts the files written.
    Every future is submitted up front, so a bare KeyboardInterrupt would
    let the pool drain the queue in full: the stop flag is what makes Ctrl+C
    end the run rather than only stop the reporting.
    """
    failed: list[tuple[str, str]] = []
    interrupted = False
    _stop.clear()
    _writing.set()
    term = term or Terminal()
    if progress is None:
        progress = Progress(len(files), sum(f.get("size", 0) for f in files), term)

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        future_map = {
            pool.submit(_download_one, f, bios_path, verbose, progress,
                        (copies or {}).get(id(f))): f
            for f in files
        }
        refused = False
        refused_events = 0
        try:
            for future in concurrent.futures.as_completed(future_map):
                dest, success, reason = future.result()
                if refused:
                    # The folder they all go in refused the first: each
                    # would fail alike, counted without a line of its own,
                    # though a program reading the events still gets one.
                    if not success:
                        failed.append((dest, NOT_WRITABLE))
                        refused_events += 1
                        EVENTS.emit(
                            "downloaded", dest=dest, ok=False, reason=NOT_WRITABLE,
                            size=future_map[future].get("size", 0),
                            files_done=progress.files + refused_events,
                            files_total=progress.total_files, bytes_done=progress.bytes,
                            bytes_total=progress.expected_bytes,
                        )
                    continue
                if _stop.is_set():
                    continue
                progress.done(dest, success, reason)
                EVENTS.emit(
                    "downloaded", dest=dest, ok=success, reason=reason,
                    size=future_map[future].get("size", 0), files_done=progress.files,
                    files_total=progress.total_files, bytes_done=progress.bytes,
                    bytes_total=progress.expected_bytes,
                )
                if not success:
                    failed.append((dest, reason))
                    if reason == NOT_WRITABLE and not _folder_writable(bios_path):
                        # A read-only card or share: hundreds of identical
                        # FAILED lines buried the one cause and its advice.
                        refused = True
                        _stop.set()
        except KeyboardInterrupt:
            interrupted = True
            _stop.set()
            progress.finish()
            print("\n  Stopping. Files already installed are kept.")
    # The pool has run every future by now: a file that landed after Ctrl+C
    # is on disk and counts.
    progress.landed = [
        entry for future, entry in future_map.items()
        if not future.cancelled() and future.exception() is None and future.result()[1]
    ]
    progress.installed = len(progress.landed)
    progress.finish()
    progress.emit_transfer()
    return failed, interrupted
