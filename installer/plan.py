"""The plan shown before a download: what comes, its size and the space it needs."""
from __future__ import annotations

from collections.abc import Collection
from pathlib import Path
from typing import TYPE_CHECKING

from installer.datadirs import data_fetch_bytes
from installer.events import EVENTS
from installer.invocation import _INVOCATION
from installer.narrowing import _filter_by_target
from installer.offline import LOCAL, _offline_only, offline_named, offline_undo
from installer.outcome import EVERYTHING_IN_PLACE
from installer.paths import shown_path
from installer.plan_words import _sized
from installer.platforms import OTHER_TITLE, entry_systems, system_title
from installer.refusal import Refusal
from installer.space import space_shortfall
from installer.tally import _bytes, parts_words, tally
from installer.terminal import terminal_size
from installer.text import _plural, cell_width, format_size

if TYPE_CHECKING:
    from installer.terminal import Terminal

# Below this a download is small enough that narrowing it is not worth a line.
BULK_HINT_FROM = 100 * 1024 * 1024


def bulk_hint(
    to_download: list[dict], manifest: dict, systems_chosen: bool, cores_chosen: bool,
    accepted: Collection[str] = (),
) -> list[str]:
    """Name what pulls most of a download, when narrowing saves over half of it.

    `--system 3do` fetched 349 MB for RetroArch, and `--core opera` 12.5 MB:
    the arcade cores that also read 3DO pulled the rest, and nothing said so.
    accepted holds the names --core takes. Drawn from every core of the
    system, the advice named ares, which loads no file of its own, and
    `--core ares` was then refused.
    """
    total = _bytes(to_download)
    if total < BULK_HINT_FROM:
        return []
    systems = {s for entry in to_download for s in entry_systems(entry)}
    if not cores_chosen and len(systems) == 1:
        system = next(iter(systems))
        candidates = [core for core in (manifest.get("system_cores") or {}).get(system) or []
                      if core in accepted]
        by_core: dict[str, int] = {}
        for entry in to_download:
            for core in entry.get("cores") or []:
                by_core[core] = by_core.get(core, 0) + entry.get("size", 0)
        kept = {core: _bytes(_filter_by_target(to_download, [core])) for core in candidates}
        if by_core and kept:
            heavy = max(sorted(by_core), key=lambda core: by_core[core])
            light = min(sorted(kept), key=lambda core: kept[core])
            saved = total - kept[light]
            if saved * 2 > total:
                return [
                    f"  {heavy} pulls {format_size(by_core[heavy])} of this "
                    f"{format_size(total)} download for {system}. --core {light} "
                    f"keeps {format_size(kept[light])} of it and saves "
                    f"{format_size(saved)} ({saved * 100 // total}%)."
                ]
    if not systems_chosen and len(systems) > 1:
        alone: dict[str, int] = {}
        for entry in to_download:
            own = entry_systems(entry)
            if len(own) == 1:
                alone[own[0]] = alone.get(own[0], 0) + entry.get("size", 0)
        if alone:
            heavy = max(sorted(alone), key=lambda system: alone[system])
            if alone[heavy] * 2 > total:
                return [
                    f"  {heavy} pulls {format_size(alone[heavy])} of this "
                    f"{format_size(total)} download. --system naming the systems "
                    f"played leaves it out and saves {format_size(alone[heavy])} "
                    f"({alone[heavy] * 100 // total}%), --list-systems names them."
                ]
    return []


# Asked before, in an interactive run: past this size a download is worth a
# second thought, and --system, --core or --region can make it smaller.
CONFIRM_FROM_BYTES = 1024 * 1024 * 1024

# A --dry-run plan: file names per system, the systems shown when the
# listing is taller than the screen, and the lines around the listing.
PLAN_FILES_PER_SYSTEM = 8
PLAN_LARGEST_SYSTEMS = 10
PLAN_FRAME_LINES = 6
# Past this many systems a group sharing files is named by its first two.
PLAN_GROUP_TITLES = 3


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
        print(f"  ... and {_plural(more, 'more ' + unit)}: --verbose lists "
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
    shortfall = space_shortfall(bios_path, needed)
    if shortfall is None:
        return
    free = shortfall[1]
    EVENTS.emit("no_space", platform=plat, folder=str(bios_path), bytes_needed=needed,
                bytes_free=free)
    lines = [f"\nNot enough space on the drive holding {bios_path}.",
             f"  Needed: {format_size(needed)}. Free: {format_size(free)}."]
    if card:
        # Its system reads this card alone: another drive, with RetroArch's
        # list, was offered for an Onion card.
        lines.append(f"  Free up {format_size(needed - free)} on the card, then run it "
                     "again: its system reads its BIOS files there only.")
    elif not plat:
        lines.append(f"  Free up {format_size(needed - free)}, or use --dest to install "
                     "to another drive.")
    else:
        # --dest alone used to mean RetroArch's list: the platform is named, so
        # a Batocera install moved to a USB drive stays Batocera's.
        lines.append(f"  Free up {format_size(needed - free)}, or install to another "
                     f"drive:\n    {_INVOCATION.command(plat, '<folder on another drive>')}")
    raise Refusal("space", "drive_full", plat, *lines, code=code,
                  message=f"Not enough space on the drive holding {bios_path}: "
                          f"{format_size(needed)} needed, {format_size(free)} free.")
