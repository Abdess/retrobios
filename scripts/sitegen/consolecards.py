"""The cards of one console, ranked and grouped by section and region."""

from __future__ import annotations

import re
from typing import TypeVar

from core.text import series
from model.collection import profiles_on_disk
from model.composition import GAME_DATA_TOPS
from model.guides import INSTALL_PS1, INSTALL_SH
from model.profiles import entry_system_ids
from packs.consumers import FileConsumers
from sitegen.cards import emulator_display, romset_releases, system_file_card


# A manufacturer page above this much Markdown becomes a summary with one
# page per console, and a console above it is cut into parts. Measured as
# MkDocs Markdown, a page renders to up to 1.8 times its size in HTML with
# its structured data: at 500 KB the Sony page was 849 KB, and every page
# stays under 600 KB from 300 KB. game-engines was one 10.5 MB page that
# took 21 s of main-thread work on a phone.
SYSTEM_PAGE_BUDGET = 300_000
# Manufacturers whose every console gets a page of its own, whatever its
# size. A section shares its page's search fields with its neighbours, and
# a digit is on too many pages to weigh: "playstation 3 bios" found the
# PlayStation page before the Sony page that held the PlayStation 3, and
# "gba bios" landed on mGBA's page, the Game Boy Advance being a section of
# the Nintendo page.
CONSOLE_PAGES = frozenset({"Nintendo", "Sony"})
# What the sections kept on a manufacturer's summary may weigh once
# rendered, estimated from their Markdown. Fitted on the Nintendo, Sega and
# Commodore summaries: highlighted install commands grow about eleven times
# since each carries its setup's name, cards 1.7 times. The page budget is
# 600 KB of HTML, and the frame around the content (head, navigation,
# footer) is about 45 KB.
CARD_HTML_RATIO = 1.7
INSTALL_HTML_RATIO = 11
SYSTEM_SUMMARY_HTML = 500_000
# The ratio was fitted while each command named the raw.githubusercontent.com
# bootstrap, 66 characters (67 for PowerShell). A box is weighed with its
# address at that length, so the shorter site address moves no console off
# or onto a summary and no card changes address.
FITTED_ADDRESS_CHARS = {INSTALL_PS1: 67, INSTALL_SH: 66}


def install_box_weight(lines: list[str]) -> int:
    weight = 0
    for line in lines:
        weight += len(line) + 1
        for address, fitted in FITTED_ADDRESS_CHARS.items():
            found = line.count(address)
            line = line.replace(address, "")
            weight += found * (fitted - len(address))
    return weight


# A system card: whether it is a variant, its lines, its sha1.
Card = tuple[bool, list[str], str]
Item = TypeVar("Item")


def _reading_entries(sha1: str, consumers: FileConsumers) -> list[dict]:
    """The profile entries that read a file, one per emulator."""
    files_of = getattr(consumers, "emulator_files", {})
    entries = []
    for emulator, index in getattr(consumers, "emulator_entries", {}).get(sha1, {}).items():
        files = files_of.get(emulator) or []
        if 0 <= index < len(files) and isinstance(files[index], dict):
            entries.append(files[index])
    return entries


NO_PRIORITY = 1 << 30


def card_rank(f: dict, consumers: FileConsumers, start: dict[str, int] | None = None) -> tuple:
    """Where a file's card sits in its console: the files the section's
    start line names first, in its order (``start``, sha1 -> place), then
    the files an emulator requires, then by the emulators' search order
    (smallest first), then a required file by how many emulators read it,
    then by how many setups list the file, then by name.

    By byte order the PlayStation section opened on LibPS.exe and
    PSX_DTLH2000.bin, capitals first, and scph5501.bin was 28th. Without
    the reader count the Neo Geo section opened on aes.zip, which geolith
    alone reads. Without the start line's order, "first below" named
    neogeo.zip over a section opening on sfix.sfix.
    """
    sha1 = str(f.get("sha1", ""))
    entries = _reading_entries(sha1, consumers)
    priorities = [e["priority"] for e in entries if isinstance(e.get("priority"), int)]
    required = any(e.get("required", True) for e in entries)
    return (
        (start or {}).get(sha1, NO_PRIORITY),
        not required,
        min(priorities, default=NO_PRIORITY),
        -len(entries) if required else 0,
        -len(consumers.platforms.get(sha1, ())),
        f["name"].casefold(), f["name"], f.get("path", ""),
    )


def _by_name(f: dict) -> tuple:
    return f["name"].casefold(), f["name"], f.get("path", "")


def console_cards(
    manufacturer: str,
    files: list[dict],
    consumers: FileConsumers,
    anchored: set[str],
    by_name: bool = False,
    start: list[str] | None = None,
) -> list[Card]:
    """Each card of one console, primaries then variants, with whether it
    is a variant. ``start`` is the sha1s the start line names, whose cards
    come first in its order. ``by_name`` orders the rest by name alone,
    for a console cut into parts named by their first and last file: the
    PlayStation 2 opened on cheats_ni.zip, its BIOS far below."""
    searchable = manufacturer not in GAME_DATA_TOPS
    place = {sha1: index for index, sha1 in enumerate(start or [])}

    def order(f: dict) -> tuple:
        if by_name:
            return (place.get(str(f.get("sha1", "")), NO_PRIORITY), *_by_name(f))
        return card_rank(f, consumers, place)
    # Another revision of a MAME or FBNeo set is another release's set, its
    # Romset line saying which: it sits open beside the set of its name.
    # Twelve neogeo.zip were on five pages, the SNK ones closed under
    # Variants.
    romsets = romset_releases()
    beside = [f for f in files if "/.variants/" in f["path"] and f["name"] in romsets]
    main_files = [f for f in files if "/.variants/" not in f["path"]]
    variant_files = [f for f in files if "/.variants/" in f["path"] and f not in beside]
    # Sets of one name side by side, the first ranked leading.
    ranked = sorted(main_files, key=order)
    by_set: dict[str, list[dict]] = {}
    for f in [*ranked, *sorted(beside, key=order)]:
        if f["name"] in romsets:
            by_set.setdefault(f["name"], []).append(f)
    ordered: list[dict] = []
    for f in ranked:
        if f["name"] not in romsets:
            ordered.append(f)
        elif by_set.get(f["name"]):
            ordered.extend(by_set.pop(f["name"]))
    ordered.extend(f for files in by_set.values() for f in files)
    cards = [(False, system_file_card(f, consumers, anchored, searchable), str(f.get("sha1", "")))
             for f in ordered]
    cards += [(True, system_file_card(v, consumers, anchored, searchable), str(v.get("sha1", "")))
              for v in sorted(variant_files, key=order)]
    return cards


# A "Start with" line names this many files at most: Game Engines'
# TheXTech requires 2,014.
START_WITH_NAMES = 6


def region_order() -> dict[str, int]:
    """The regions a start line lists, the territories first. A file read
    for every region is a region-free stand-in for the BIOS of each one:
    the PlayStation section opened on psxonpsp660.bin, which one emulator
    requires among the BIOS it accepts, above the scph files most read."""
    from model.region import REGION_TREE, WORLD

    ordered = []
    for parent, members in REGION_TREE.items():
        ordered += [parent, *sorted(members)]
    ordered.append(WORLD)
    return {region: index for index, region in enumerate(ordered)}


def reading_pairs(sha1: str, consumers: FileConsumers) -> list[tuple[str, dict]]:
    """The profile entries that read a file, each with its emulator."""
    files_of = getattr(consumers, "emulator_files", {})
    pairs = []
    for emulator, index in sorted(getattr(consumers, "emulator_entries", {}).get(sha1, {}).items()):
        files = files_of.get(emulator) or []
        if 0 <= index < len(files) and isinstance(files[index], dict):
            pairs.append((emulator, files[index]))
    return pairs


def entry_systems(emulator: str, entry: dict) -> list[str]:
    """The systems an entry is read for: its own `system:` or `systems:`
    (a MAME device set several systems load), else its profile's only one."""
    if entry.get("system") or entry.get("systems"):
        return entry_system_ids(entry, {})
    systems = (profiles_on_disk().get(emulator) or {}).get("systems") or []
    return [str(systems[0])] if len(systems) == 1 else []


# id(consumers) -> (consumers, section -> the entries whose system leads there).
_SECTION_ENTRIES: dict[int, tuple[object, dict[tuple[str, str], list]]] = {}


def entries_by_section(consumers: FileConsumers) -> dict[tuple[str, str], list]:
    """Each console section with the (sha1, emulator, entry, system) whose
    system leads to it, read once per build."""
    from sitegen.render import system_section

    cached = _SECTION_ENTRIES.get(id(consumers))
    if cached is not None and cached[0] is consumers:
        return cached[1]
    sections: dict[str, tuple[str, str] | None] = {}
    index: dict[tuple[str, str], list] = {}
    for sha1 in sorted(getattr(consumers, "emulator_entries", {})):
        for emulator, entry in reading_pairs(sha1, consumers):
            for sys_id in entry_systems(emulator, entry):
                if sys_id not in sections:
                    sections[sys_id] = system_section(sys_id)
                place = sections[sys_id]
                if place is not None:
                    index.setdefault(place, []).append((sha1, emulator, entry, sys_id))
    _SECTION_ENTRIES.clear()
    _SECTION_ENTRIES[id(consumers)] = (consumers, index)
    return index


def setup_name(f: dict, consumers: FileConsumers, pairs: list[tuple[str, dict]]) -> str:
    """The name most setups give a file, else most emulators: the collection
    keeps BizHawk's GBA_bios.rom where eight setups write gba_bios.bin."""
    counts: dict[str, int] = {}
    destinations = getattr(consumers, "platform_destinations", {}).get(str(f.get("sha1", "")), {})
    for dests in destinations.values():
        for base in {d.replace("\\", "/").rsplit("/", 1)[-1] for d in dests if d}:
            counts[base] = counts.get(base, 0) + 1
    if not counts:
        for _emulator, entry in pairs:
            if entry.get("name"):
                name = str(entry["name"])
                counts[name] = counts.get(name, 0) + 1
    if not counts:
        return f["name"]
    most = max(counts.values())
    top = sorted((n for n, c in counts.items() if c == most), key=lambda n: (n.casefold(), n))
    return f["name"] if f["name"] in top else top[0]


def without_files(emulators: list[str]) -> str:
    """Who runs without the files: every emulator reading one, up to three
    by name, more counted, as their order would rank nothing."""
    names = sorted({emulator_display(e) for e in emulators}, key=str.casefold)
    if len(names) > 3:
        return f": none of its {len(names)} emulators requires one"
    return " with " + series(names, "or")


def visible_name(name: str) -> str:
    """The file name a start line shows, out of its code span and link."""
    match = re.match(r"\[?`([^`]*)`", name)
    return match[1] if match else name


def add_name(names: list[str], name: str) -> None:
    """A name once per line: two copies of sfcbox.zip read as one file."""
    if all(visible_name(n) != visible_name(name) for n in names):
        names.append(name)
