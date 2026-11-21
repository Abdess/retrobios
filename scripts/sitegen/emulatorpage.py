"""Each emulator's page: intro, files, data directories and parts."""

from __future__ import annotations

import html
import re
import urllib.parse
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from core.hashing import parse_hash_list
from core.sizes import size_text
from model.systemnames import system_name
from model.profiles import is_emulator
from packs.crossref import FileConsumers
from sitegen import entries as siteentries, markup, measurements as sitemeasurements
from sitegen.cards import ROMSET_FAQ, emulator_file_anchors
from sitegen.config import REPO_URL, date_line, yaml
from sitegen.decorate import DEMOTED_WEIGHT, SEARCH_WEIGHT
from sitegen.descriptions import said_as_list
from sitegen.emulatorcards import (
    CardLayout,
    DATA_MEMBERS,
    build_rows,
    entry_label,
    file_badges,
    named_example,
    named_system_link,
    region_words,
    render_emulator_file,
    render_metadata_rows,
    any_name_bios,
    emulator_romset,
    version_markdown,
)
from sitegen.emulatorsindex import CLS_LABEL_ONE
from sitegen.fields import render_platform_details, render_structured_blocks, search_excluded
from sitegen.home import next_block
from sitegen.install import (
    install_block,
    platform_display,
    comes_with_app,
    data_folder_block,
    data_root_words,
    standalone_place,
)
from sitegen.lookup import data_directory_origin, data_tree_pages
from sitegen.render import (
    admonition_body,
    code_span,
    count_text,
    escape_tags,
    card_page,
    record_emulator_cards,
)
from sitegen.sources import source_ref_markdown, link_prose_citations, revision_markdown
from sitegen.startwith import card_runs
from sitegen.structured import emulator_file_aliases


def _distinct_spellings(names: list) -> list[str]:
    """Names as a reader tells them apart: one per spelling, ignoring case.

    DuckStation's cores list `Duckstation` for EmuELEC, whose launch name is
    spelled so, and the page read "duckstation, Duckstation". The profile
    keeps both, the core lookup being case-sensitive.
    """
    seen: dict[str, str] = {}
    for name in map(str, names):
        seen.setdefault(name.casefold(), name)
    return list(seen.values())


def availability_check(
    db: dict, data_names: set[str] | None, owner: str = "",
) -> Callable[[dict], bool]:
    """A predicate answering whether the collection holds a file.

    It answers the way cross_reference does. A page that called a file
    missing while the gap report called it held would describe a
    different collection on two pages of the same site.
    """
    from packs.crossref import entry_source

    by_name = db.get("indexes", {}).get("by_name", {})
    by_name_lower = {k.lower(): k for k in by_name}
    by_path_suffix = db.get("indexes", {}).get("by_path_suffix", {})

    index = {
        "by_name": by_name,
        "by_name_lower": by_name_lower,
        "by_path_suffix": by_path_suffix,
        "by_md5": db.get("indexes", {}).get("by_md5", {}),
        "by_sha256": db.get("indexes", {}).get("by_sha256", {}),
        "by_crc32": db.get("indexes", {}).get("by_crc32", {}),
        "db_files": db.get("files", {}),
        "data_names": data_names,
    }

    def _file_available(f: dict) -> bool:
        """Check if a file is available using the same resolution as cross_reference."""
        # cross_reference sets these aside before resolving: the file found
        # under the name belongs to another game or release.
        if not f.get("name") or f.get("unsourceable"):
            return False
        return entry_source({**f, "source_profile": owner} if owner else f, index) is not None

    return _file_available


def _emulator_slots(files: list[dict]) -> list[list[dict]]:
    """The entries of each slot, as verify --emulator and the gaps page
    count them, leaving out the slots the app ships."""
    from packs.crossref import slot_key

    slots: dict[tuple, list[dict]] = {}
    for f in files:
        slots.setdefault(slot_key(f), []).append(f)
    return [group for group in slots.values() if not all(comes_with_app(f) for f in group)]


def _set_names(value: object) -> list[str]:
    """The sets an entry belongs to: group takes a name, a list or a map."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, dict)):
        return [str(name) for name in value]
    return []


def _requirements(files: list[dict], groups: dict | None) -> list[list[dict]]:
    """Each thing the emulator needs: the members of a required set, any one
    of which fills it (DuckStation's ps-bios, 105 images), or a required
    file of its own. load_emulator_profiles marks every member of a
    required set required, so counted per file DuckStation read "105
    required" for one BIOS."""
    required_sets = {name for name, spec in (groups or {}).items()
                     if isinstance(spec, dict) and spec.get("required")}
    sets: dict[str, list[dict]] = {}
    alone: list[list[dict]] = []
    for f in files:
        if f.get("required") is not True or comes_with_app(f):
            continue
        names = [name for name in _set_names(f.get("group")) if name in required_sets]
        if names:
            for name in names:
                sets.setdefault(name, []).append(f)
        else:
            alone.append([f])
    return [*sets.values(), *alone]


def _regional_set(requirements: list[list[dict]]) -> list[dict]:
    """The one requirement, a set whose members the code picks by the game's
    region, or [] when there is no such single choice."""
    if len(requirements) != 1 or len(requirements[0]) < 2:
        return []
    members = requirements[0]
    if not all(f.get("region") for f in members):
        return []
    return members if len({region_words(f["region"]) for f in members}) >= 2 else []


def _emulator_file_summary(files: list[dict], groups: dict | None = None) -> list[str]:
    """What the emulator reads, above its file table, and its categories.

    Counted by slot, as verify --emulator and the gaps page count: raze
    lists every GRP its code accepts under one name, and holding one fills
    the slot. Counted per entry, the page announced 46 missing where 12
    slots are empty. The files the app ships are counted apart: NetherSX2
    said "4 required" for one BIOS and three fonts in its package. A
    required set counts once (`groups`).
    """
    slots = _emulator_slots(files)
    shipped = sum(1 for f in files if comes_with_app(f))
    requirements = _requirements(files, groups)
    in_sets = {id(f) for members in requirements for f in members}
    req_slots = sum(1 for group in slots if any(id(f) in in_sets for f in group))
    req_count = len(requirements)
    optional = len(slots) - req_slots
    hle_count = sum(1 for group in slots if any(f.get("hle_fallback") for f in group))

    # Sentences, one number format: the line read "1,563 files | 164
    # required, 1399 optional | 1563 in repo".
    total = f"**{count_text(len(slots), 'file')}**"
    if sum(len(group) for group in slots) != len(slots):
        total += f" ({sum(len(group) for group in slots):,} accepted versions)"
    line = f"{total}: {req_count:,} required, {optional:,} optional."
    if any(len(members) > 1 for members in requirements):
        line += " Any one file of a required set fills it."
    regional = _regional_set(requirements) or (
        [f for members in requirements for f in members]
        if _regional_choice([f for members in requirements for f in members]) else [])
    if regional:
        # DuckStation takes the BIOS of the game's region: "3 required"
        # read as "get all three".
        line = f"{total}. One of {len(regional):,} is required, for the games' region."
        if optional:
            line += f" {optional:,} {'is' if optional == 1 else 'are'} optional."
    if hle_count:
        line += f" {hle_count:,} {'has' if hle_count == 1 else 'have'} an HLE fallback."
    if shipped:
        line += f" {count_text(shipped, 'more file')} {'comes' if shipped == 1 else 'come'} with the app."
    lines = [line, ""]

    categories = [f.get("category", "bios") for f in files]
    if "game_data" in categories or "bios_zip" in categories:
        cats = [
            f"{categories.count(key):,} {label}"
            for key, label in (
                ("bios", "BIOS"), ("bios_zip", "BIOS ZIPs"), ("game_data", "game data")
            )
            if categories.count(key)
        ]
        lines.extend([f"By kind: {said_as_list(cats)}.", ""])
    return lines


def _emulator_held_line(files: list[dict], available: Callable[[dict], bool]) -> list[str]:
    """What this collection holds of them, one quiet line under the table:
    a reader comes for what the emulator needs, the project's counts after."""
    slots = _emulator_slots(files)
    if not slots:
        return []
    in_repo = sum(1 for group in slots if any(available(f) for f in group))
    unsourceable = sum(
        1 for group in slots
        if not any(available(f) for f in group) and all(f.get("unsourceable") for f in group)
    )
    held = [f"{in_repo:,} in repo", f"{len(slots) - in_repo - unsourceable:,} missing"]
    if unsourceable:
        held.append(f"{unsourceable:,} unsourceable")
    return [f"<p><small>In this collection: {said_as_list(held)}.</small></p>", ""]


DATA_REVISIONS: dict[str, dict] = {}
# Emulator -> the platforms that run it, as resolve_platform_cores answers.
EMULATOR_SETUPS: dict[str, list[str]] = {}
# The measurement index items of each emulator, for the proof lines of its page.
MEASUREMENT_ITEMS: dict[str, list[dict]] = {}
# The emulator pages that list each data directory, by ref.
DATA_READERS: dict[str, list[tuple[str, str]]] = {}


def _data_member_table(members: dict[str, dict], names: list[str], anchors: set[str]) -> list[str]:
    """A data directory's files with their size and sha1, each sha1 an
    anchor the first time the page lists it (``anchors``, the page's ids)."""
    table = ["| File | Size | SHA1 |", "|------|-----:|------|"]
    for member in names:
        info = members[member]
        sha1 = str(info.get("sha1", ""))
        # One id per page: two members can hold the same bytes (every empty
        # file), and Dolphin's trees share Sys.
        anchor = f"sha1-{sha1[:12]}"
        span = "" if anchor in anchors else f'<span id="{anchor}"></span>'
        anchors.add(anchor)
        table.append(f"| {span}{code_span(member)} | {size_text(int(info.get('size', 0)))} | {code_span(sha1)} |")
    return table


def _data_tree_page(ref: str, entry: dict, pages: list[tuple[str, list[str]]],
                    index: int) -> str:
    """One page of a large data directory's file list."""
    stem, names = pages[index]
    members = DATA_MEMBERS.get(ref) or {}
    part = f" (part {index + 1} of {len(pages)})" if len(pages) > 1 else ""
    read_by = said_as_list([f"[{escape_tags(display)}]({key}.md#data-directories)"
                             for key, display in DATA_READERS.get(ref, [])])
    # A file list out of the search: "dolphin" found three parts of the
    # dolphin-sys tree, on their title, before the Dolphin page.
    front: dict = {"level": "reference", "search": "exclude"}
    # The reader the tree is named after (dolphin for dolphin-sys), else
    # the first by name.
    readers = DATA_READERS.get(ref) or []
    owner = max(readers, default=None,
                key=lambda reader: len(reader[0]) if ref.startswith(f"{reader[0]}-") else 0)
    if owner:
        head = _part_front_matter(
            (owner[1], f"{owner[0]}.md"),
            [(f"The {ref} data directory, part {n}", f"{other}.md")
             for n, (other, _names) in enumerate(pages, 1)], index, front)
    else:
        head = ["---", yaml.safe_dump(front, sort_keys=False, allow_unicode=True).rstrip("\n"),
                "---", ""]
    lines = [
        *head,
        f"# The {ref} data directory{part}", "",
        f"{entry.get('description') or 'A data directory'}: "
        f"{count_text(len(members), 'file')}, as the packs ship them."
        + (f" Read by {read_by}." if read_by else ""), "",
    ]
    if len(pages) > 1:
        lines.extend([", ".join(f"[part {i}]({other}.md)" if other != stem else f"part {i}"
                                for i, (other, _names) in enumerate(pages, 1)), ""])
    lines.extend(search_excluded(_data_member_table(members, names, set())))
    lines.extend(["", date_line()])
    return "\n".join(lines) + "\n"


# An emulator page lists at most this many file cards: MAME's 1,564 made a
# 3 MB page. Past it, the cards go to pages of their own and the emulator's
# page keeps a table of every entry, each row holding the card's old
# anchor. A count, not a size: system cards link to these cards and are
# written before them. At 400 a part of MAME's cards was 805 KB of HTML.
EMULATOR_CARDS_PER_PAGE = 220
# The most cards a part of a split page holds. Each card is a table row
# since sitegen/entries.py, about five elements and 60 bytes more: at 220 a
# part, MAME's first was 612 KB and 9,777 elements.
EMULATOR_CARDS_PER_PART = 180
# The words a part's rows may show, every card closed. A count of cards
# held while the rows did not grow: once 888 of MAME's entries named
# their system, each row said "for <system>" and the first part showed
# 1,931 words for 1,180 before. The frame of a part (headings, filter
# boxes, the links to the other parts, the footer) shows 100 to 170 more,
# and tests/test_site_entry_tables.py holds a part under 1,693: about a
# tenth is left as margin.
EMULATOR_PART_WORDS = 1_350


# The headings an emulator's cards go under, in page order: what it needs
# first. DuckStation's three required BIOS were cards 12 to 14 under one
# heading, and MAME opened on 25 floppy sound samples.
CARD_SECTIONS = (("required", "Required"), ("optional", "Optional"), ("game_data", "Game data"),
                 ("with_app", "Comes with the app"))
_SECTION_RANK = {key: rank for rank, (key, _title) in enumerate(CARD_SECTIONS)}


def _card_section(f: dict) -> str:
    if comes_with_app(f):
        return "with_app"
    if f.get("category") == "game_data":
        return "game_data"
    return "required" if f.get("required") else "optional"


def _display_order(files: list) -> list[int]:
    """Entry indexes in page order: required, optional, then game data,
    each in profile order."""
    return sorted(range(len(files)), key=lambda i: _SECTION_RANK[_card_section(files[i])])


def _html_words(fragment: str) -> int:
    """The words a browser shows for an HTML fragment, each tag a break."""
    return len(html.unescape(re.sub(r"<[^>]*>", " ", fragment)).split())


def _entry_row_words(files: list[dict], profile: dict,
                     available: Callable[[dict], bool]) -> list[int]:
    """The words each entry's row shows with its card closed: its title
    and its cells, an empty cell written "-" in a column another row of
    its section fills. A part's table drops a column its own rows leave
    empty: counted over the whole section, a row never shows more."""
    cells = [_entry_cells(f, profile, available) for f in files]
    filled: dict[str, set[int]] = {}
    for f, row in zip(files, cells):
        filled.setdefault(_card_section(f), set()).update(
            column for column, cell in enumerate(row) if cell)
    return [_html_words(entry_label(f, profile)) + sum(
                _html_words(cell) or column in filled[_card_section(f)]
                for column, cell in enumerate(row))
            for f, row in zip(files, cells)]


def emulator_parts(name: str, files: list, profile: dict | None = None,
                   available: Callable[[dict], bool] | None = None,
                   ) -> list[tuple[str, list[int]]]:
    """The pages an emulator's cards go to, with the entries each holds,
    or none when they fit on the emulator's page. In page order, at most
    EMULATOR_PART_WORDS shown and EMULATOR_CARDS_PER_PART entries a part,
    the parts balanced by words. ``available`` is the page's own test of
    a held file, the status a row shows: without it every row is weighed
    "in repo", the longest status."""
    if len(files) <= EMULATOR_CARDS_PER_PAGE:
        return []
    profile = profile if profile is not None else {"files": files}
    order = _display_order(files)
    words = _entry_row_words(files, profile, available or (lambda _f: True))
    sizes = [words[i] for i in order]
    ceiling = max(EMULATOR_PART_WORDS, max(sizes))
    count = max(len(card_runs(order, ceiling, sizes)), -(-len(files) // EMULATOR_CARDS_PER_PART))
    while True:
        # The fewest words a part can hold for the parts to be ``count``:
        # cut at the ceiling, the last part took what the others left.
        share = min(-(-sum(sizes) // count), ceiling)
        runs = card_runs(order, share, sizes)
        while len(runs) > count:
            share = min(share + max(1, share // 50), ceiling)
            runs = card_runs(order, share, sizes)
        if max(len(run) for run in runs) <= EMULATOR_CARDS_PER_PART:
            return [(f"{name}-files-{index}", run) for index, run in enumerate(runs, 1)]
        count += 1


# From this many entries an emulator page lists them as one table, each
# row opening to its card (sitegen/entries.py). Below it the page is one
# screen of open cards. A summary table above folded cards listed every
# file twice: PCSX-ReARMed's seven, once in the table and once in a closed
# "7 files" block. A split emulator's card pages always use the table.
EMULATOR_TABLE_MIN = 6
ENTRY_HEADS = ["File", "Contents", "Status", "Hash"]
# The end of the badge file_badges writes for an entry of each section.
_SECTION_BADGE = {"required": ">required</span>", "optional": ">optional</span>",
                  "with_app": ">comes with the app</span>"}


def _entry_rows(files: list[dict], cards: list[list[str]], profile: dict,
                available: Callable[[dict], bool]) -> list[siteentries.Row]:
    """Each entry as a table row: its card's title and body, the number of
    members an archive holds, its badges and its hash."""
    rows = []
    for f, card in zip(files, cards):
        title, body = siteentries.card_title_and_body(card)
        rows.append(siteentries.Row(title, body, _entry_cells(f, profile, available)))
    return rows


def _entry_cells(f: dict, profile: dict, available: Callable[[dict], bool]) -> list[str]:
    """An entry's cells beside its title: the members an archive holds,
    its badges and its hash."""
    many = len(profile.get("systems") or []) > 1
    for_system = system_name(str(f["system"])) if f.get("system") and many else ""
    contents = f.get("contents") or []
    badges = file_badges(f, available(f), for_system)
    # The first badge says whether the entry is needed: under Required,
    # Optional or Comes with the app it repeats the section heading.
    # One element and two words fewer on each of MAME's 1,563 rows.
    if badges and badges[0].endswith(_SECTION_BADGE.get(_card_section(f), "\0")):
        badges = badges[1:]
    return [f"{len(contents):,}" if contents else "", " ".join(badges), _hash_short(f)]


def _entries_table(files: list[dict], group: list[int], rows: list[siteentries.Row]) -> list[str]:
    """The rows of ``group``, one section's entries, as one table."""
    key = _card_section(files[group[0]])
    heading = dict(CARD_SECTIONS)[key]
    return siteentries.entry_table([rows[i] for i in group], ENTRY_HEADS,
                                   f"rb-entry-filter-{key.replace('_', '-')}", heading,
                                   # The badges hide themselves from the search
                                   # but for the archive's name ("in pgm.zip"),
                                   # how a ZIP name finds the cores reading it.
                                   searched=frozenset({"Status"}))


def _sectioned(files: list, indexes: list[int],
               render: Callable[[list[int]], list[str]]) -> list[str]:
    """Each section's heading, then ``render`` of its entries among ``indexes``."""
    lines: list[str] = []
    for key, title in CARD_SECTIONS:
        group = [i for i in indexes if _card_section(files[i]) == key]
        if group:
            lines.extend([f"## {title}", "", *render(group)])
    return lines


def _hash_short(f: dict) -> str:
    """The shortest way to tell two dumps apart in a table: the first 12
    characters of an md5, crc32 or sha1, the whole value in its title."""
    for field in ("md5", "crc32", "sha1"):
        values = parse_hash_list(f.get(field))
        if values:
            full = html.escape(values[0])
            # Kept on one line: the label above the value doubled each row.
            return f'{field.upper()}\u00a0<code title="{full}">{full[:12]}</code>'
    return ""


def _summary_table(files: list[dict], indexes: list[int], cell: Callable[[int, str], str],
                   multi_system: bool = False) -> list[str]:
    """The table of an emulator's entries, one row each, ``cell`` writing
    the linked name of entry i from its shown path.

    A column every row leaves empty is not written: AetherSX2's Region
    column held "-" on every row and pushed Required off a phone screen.
    Nor is Required when every row gives the same answer, which the
    section heading or the count above already says: in MAME's index it
    turned 1,564 rows into label and value pairs on a phone.
    """
    rows = []
    for i in indexes:
        f = files[i]
        needed = "with the app" if comes_with_app(f) else "yes" if f.get("required") else "no"
        if needed == "yes" and multi_system and f.get("system"):
            needed = f"for {system_name(str(f['system']))}"
        rows.append((cell(i, str(f.get("path") or f.get("name", ""))),
                     region_words(f.get("region"), 3), needed, _hash_short(f)))
    keep = [0] + [column for column in (1, 3) if any(row[column] for row in rows)]
    if len({row[2] for row in rows}) > 1:
        keep.append(2)
    keep.sort()
    heads = ("File", "Region", "Required", "Hash")
    return [
        "| " + " | ".join(heads[c] for c in keep) + " |",
        "|" + "|".join("------" for _c in keep) + "|",
        *("| " + " | ".join(row[c] or "-" for c in keep) + " |" for row in rows),
    ]


def plan_emulator_pages(profiles: dict,
                        available: Callable[[dict], bool] | None = None) -> None:
    """Record which page holds each emulator card, before any page links one.
    ``available`` is the test the pages use for a held file."""
    stems = set()
    for name, profile in sorted(profiles.items()):
        if not is_emulator(profile):
            continue
        files = profile.get("files") or []
        anchors = emulator_file_anchors(files)
        for stem, entries in emulator_parts(name, files, profile, available):
            stems.add(stem)
            record_emulator_cards(name, stem, [anchors[i] for i in entries])
    clash = stems & set(profiles)
    if clash:
        raise RuntimeError(f"an emulator's card page takes a profile's address: {sorted(clash)}")


def generate_emulator_page(
    name: str,
    profile: dict,
    db: dict,
    consumers: FileConsumers | None = None,
    data_names: set[str] | None = None,
    data_registry: dict | None = None,
    data_dirs: list[dict] | None = None,
) -> str:
    """One emulator's page. ``data_dirs`` defaults to the profile's own."""
    return emulator_pages(
        name, profile, db, consumers, data_names, data_registry, data_dirs)[name]


def _collection_card_href(entry: dict, consumers: FileConsumers | None, owner: str) -> str:
    """The collection card of the copy that answers an emulator entry, or ""."""
    if consumers is None:
        return ""
    sha1 = consumers.sha1_of(entry, entry.get("path") or "", owner=owner)
    held = consumers.path_of(sha1) if sha1 else ""
    if not held.startswith("bios/"):
        return ""
    return f"../systems/{urllib.parse.quote(card_page(held, sha1))}.md#sha1-{sha1[:12]}"


def _any_name_folder(profile: dict, entry: dict) -> str:
    """Where the one BIOS goes, as the profile states it, or ""."""
    folder = str(profile.get("bios_directory") or "")
    if not folder:
        path = str(entry.get("path") or "")
        folder = path.rsplit("/", 1)[0] + "/" if "/" in path else ""
    if not folder:
        return ""
    if profile.get("type") == "standalone":
        # A bare `bios/` is a folder inside the app's own data folder.
        own = ("[the app's data folder](#data-folder)" if profile.get("data_root")
               else "the app's own data folder")
        return f"the {code_span(folder.strip('/'))} folder inside {own}"
    return f"{code_span(folder)}, inside the BIOS folder"


def _any_name_steps(emu_name: str, profile: dict, entry: dict, href: str,
                    name: str = "") -> str:
    """The intro of an emulator that takes one BIOS of any name: get one,
    put it in its folder, any name works.

    An app whose profile names its data folder gets that folder, one tab
    per system it runs on: AetherSX2's step said "inside the app's own
    data folder" while the profile cites Android/data/xyz.aethersx2.android.
    """
    system = system_name((profile.get("systems") or [""])[0])
    example = str(entry.get("name") or "")
    if named_example(example) and href:
        get = f"Download [{code_span(example)}]({href})."
    else:
        get = f"Get one from the {named_system_link(profile['systems'][0], '../')} files."
    steps = [get]
    folders: list[str] = []
    if profile.get("type") == "standalone" and standalone_place(name, profile, entry):
        steps.append("Put it in this folder:")
        folders = ['<div id="data-folder" class="rb-anchor"></div>', "",
                   *data_folder_block(name, profile, [entry])]
    else:
        folder = _any_name_folder(profile, entry)
        if folder:
            steps.append(f"Put it in {folder}.")
        folders = _data_folder_intro(name, profile)
    reader = "The app" if profile.get("type") == "standalone" else "The emulator"
    return "\n".join([
        f"{emu_name} needs one {system} BIOS file, any region.",
        "",
        *(f"{number}. {step}" for number, step in enumerate(steps, 1)),
        "",
        *folders,
        *([""] if folders and folders[-1] else []),
        f"Any file name works. {reader} reads what the file holds.",
    ])


def _data_folder_intro(name: str, profile: dict) -> list[str]:
    """Where the app keeps its files, under the intro of a profile that
    names its data folder and takes more than one BIOS of any name."""
    if not profile.get("data_root"):
        return []
    files = [f for f in profile.get("files") or [] if isinstance(f, dict)]
    placed = [f for f in files if standalone_place(name, profile, f)]
    subject = ("The app" if profile.get("type") == "standalone"
               else "Run on its own, the app")
    lead = (f"{subject} reads its files from this folder:" if placed
            else f"{subject} keeps its data in this folder:")
    return ['<div id="data-folder" class="rb-anchor"></div>', "", lead, "",
            *data_folder_block(name, profile, files)]


def _emulator_intro(emu_name: str, profile: dict, href: str = "", name: str = "") -> str:
    """What the emulator needs, in plain words, from fields every profile has.

    The page opened on a twelve-row table: "Type", "Version", "Checked by".
    DuckStation needs one PlayStation BIOS of any name, and the reader had
    to infer it from the "Files found by" row. ``href`` links the
    collection's copy of the one BIOS an emulator takes under any name,
    and ``name`` is the profile's key.
    """
    entry = any_name_bios(profile)
    if entry is not None:
        return _any_name_steps(emu_name, profile, entry, href, name)
    names: list[str] = []
    for sys_id in profile.get("systems") or []:
        label = system_name(sys_id)
        if label not in names:
            names.append(label)
    # What the app installs itself is no file for the reader to get.
    files = [f for f in profile.get("files") or [] if isinstance(f, dict) and not comes_with_app(f)]
    requirements = _requirements(files, profile.get("groups"))
    required = [f for members in requirements for f in members]
    sentences = []
    if names:
        shown = names if len(names) <= 4 else names[:3] + [f"{len(names) - 3} more systems"]
        sentences.append(f"{emu_name} emulates {said_as_list(shown)}.")
    regional = _regional_set(requirements)
    by_region = "" if regional else _regional_choice(required)
    others = len(files) - len(required)
    if regional:
        # DuckStation needs one BIOS of the game's region and accepts 105
        # images: every member of its ps-bios set is marked required, and
        # the page said "105 of them required".
        sentences.append(
            f"It needs one BIOS for the game's region, among the {len(regional):,} it accepts.")
        if others:
            sentences.append(
                f"The {count_text(others, 'other file')} {'is' if others == 1 else 'are'} optional.")
    elif by_region:
        # Three required BIOS of three regions: the page said "3 of them
        # required" and read as "get all of these".
        sentences.append(f"It picks the BIOS for the game's region: {by_region}.")
        if others:
            sentences.append(
                f"The {count_text(others, 'other file')} {'is' if others == 1 else 'are'} optional.")
    elif files:
        sentences.append(
            f"It reads {count_text(len(files), 'file')}, {len(requirements):,} of them required: "
            "without a required file it does not start games."
            if requirements else
            f"It reads {count_text(len(files), 'file')}, none of them required: it starts "
            "games without them."
        )
        if any(len(members) > 1 for members in requirements):
            sentences.append("Any one file of a required set fills it.")
    if required and len(names) > 1:
        sentences.append("A required file is needed only by the machines that use it.")
        if profile.get("found_by") == "content":
            sentences.append("It recognises a file by its contents, so any file name works.")
        if any(f.get("source_ref") for f in files):
            sentences.append("Each file below cites the line of source code that reads it.")
    folder = _data_folder_intro(name, profile) if name else []
    return "\n".join([" ".join(sentences), "", *folder]).strip("\n")


def _regional_choice(required: list[dict], most: int = 6) -> str:
    """The required files as one choice by region, or "" when they are not one.

    Only when every required entry carries a region: and they name at least
    two: region: is the territory the code selects the file for, so the
    reader needs the one of the game's region.
    """
    if not required or len(required) > most or not all(f.get("region") for f in required):
        return ""
    if len({region_words(f["region"]) for f in required}) < 2:
        return ""
    choices = [f"{f.get('name', '')} ({region_words(f['region'], 3)})" for f in required]
    return ", ".join(choices[:-1]) + f" or {choices[-1]}"


def _alias_page(name: str, profile: dict) -> str:
    """The page of a core that uses another one's firmware."""
    parent = profile.get("alias_of", profile.get("bios_identical_to", "unknown"))
    return (
        f"# {name}\n\n"
        f"This core uses the same firmware as **{parent}**.\n\n"
        f"See [{parent}]({parent}.md) for details.\n"
    )


def _linked_value(value: str) -> str:
    """A value linked to itself when it is a URL."""
    return f"[{value}]({value})" if value.startswith("http") else value


def _source_rows(profile: dict) -> list[str]:
    """The meta card rows naming where the code lives."""
    rows = []
    source_raw = profile.get("source", "")
    source = str(source_raw) if not isinstance(source_raw, dict) else ""
    # A key set to null says there is none (the project is its own upstream,
    # it publishes no version), and an absent key says nobody wrote it down. The
    # page printed `None` for the first, which read as the second.
    upstream_raw = profile.get("upstream", "")
    upstream_none = "upstream" in profile and upstream_raw is None
    upstream = str(upstream_raw) if isinstance(upstream_raw, str) else ""
    if isinstance(source_raw, dict):
        named = [f"[{k}]({v})" if isinstance(v, str) and v.startswith("http") else f"{k}: {v}"
                 for k, v in source_raw.items()]
        rows.append(f"| Source | {', '.join(named)} |")
    elif source:
        rows.append(f"| Source | {_linked_value(source)} |")
    if isinstance(upstream_raw, dict):
        links = [f"[{k}]({v})" if isinstance(v, str) and v.startswith("http") else f"{k}: {v}"
                 for k, v in upstream_raw.items()]
        rows.append(f"| Upstream | {', '.join(links)} |")
    elif upstream_none:
        rows.append("| Upstream | none: the source is the project itself |")
    elif upstream and upstream != source:
        rows.append(f"| Upstream | {_linked_value(upstream)} |")
    gone = profile.get("upstream_gone")
    if gone:
        # The links above answer 451 or reach a domain someone else now
        # owns: said beside them, with the date the profile observed it.
        rows.append(f"| Source status | gone: {escape_tags(str(gone))} |")
    mirror = profile.get("source_mirror")
    if mirror:
        rows.append(f"| Mirror | [{mirror}]({mirror}) |" if str(mirror).startswith("http")
                    else f"| Mirror | {mirror} |")
    return rows


def _emulator_meta_rows(name: str, profile: dict) -> list[str]:
    """The rows of the "About this profile" card, after its header."""
    rows = [f"| Type | {profile.get('type', 'unknown')} |"]
    classification = profile.get("core_classification", "")
    if classification:
        cls_display = CLS_LABEL_ONE.get(classification, classification)
        rows.append(f"| Classification | {cls_display} |")
    rows.extend(_source_rows(profile))
    rows.append(f"| Version | {version_markdown(profile)} |")
    revision = revision_markdown(profile)
    if revision:
        rows.append(f"| Revision | {revision} |")
    rows.extend(build_rows(profile))
    setups = EMULATOR_SETUPS.get(name)
    if setups:
        # The file cards name the setups whose own list holds a file: the
        # ones that run the emulator and pack its files were said nowhere.
        # Said once here: a line on each card put MAME's parts and four
        # other pages over their element budget. Out of the search: setup
        # names on 530 pages ranked the data page first for "batocera folder".
        rows.append(f"| Run by | <span {markup.search_exclude()}>" + ", ".join(
            f"[{platform_display(p)}](../platforms/{p}.md)" for p in setups) + "</span> |")
    rows.append(f"| Profiled | {profile.get('profiled_date', 'unknown')} |")
    # The YAML is the reusable document this site renders, and the JSON is the
    # same profile for a program.
    rows.append(
        f"| Profile | [YAML]({REPO_URL}/blob/main/emulators/{name}.yml), "
        f"[JSON](../api/v1/emulators/{name}.json) |"
    )
    cores = profile.get("cores", [name])
    if cores:
        rows.append(f"| Cores | {', '.join(_distinct_spellings(cores))} |")
    systems = profile.get("systems", [])
    if systems:
        sys_links = list(dict.fromkeys(named_system_link(s, "../") for s in systems))
        rows.append(f"| Systems | {', '.join(sys_links)} |")
    author = profile.get("author", "")
    if author:
        rows.append(f"| Author | {author} |")
    based_on = profile.get("based_on", "")
    if based_on:
        rows.append(f"| Based on | {based_on} |")
    rows.extend(render_metadata_rows(profile))
    return rows


@dataclass(frozen=True)
class _EmulatorSources:
    """What an emulator page reads besides its profile."""

    db: dict
    consumers: FileConsumers | None
    data_names: set[str] | None


def _emulator_files_section(
    name: str, emu_name: str, profile: dict, sources: _EmulatorSources,
) -> tuple[list[str], dict[str, str]]:
    """The Files section, and the pages its cards went to."""
    files = profile.get("files", [])
    systems = profile.get("systems", [])
    consumers = sources.consumers
    part_pages: dict[str, str] = {}
    lines: list[str] = []
    _file_available = availability_check(sources.db, sources.data_names, name)

    lines.extend(["## Files", ""])
    lines.extend(_emulator_file_summary(files, profile.get("groups")))
    held = _emulator_held_line(files, _file_available)

    anchors = emulator_file_anchors(files)
    aliases = emulator_file_aliases(files, anchors)
    parts = emulator_parts(name, files, profile, _file_available)
    data_href = f"{name}.md#data-folder" if parts else "#data-folder"
    table_form = markup.starlight() and (bool(parts) or len(files) >= EMULATOR_TABLE_MIN)
    cards = [
        render_emulator_file(f, profile, consumers, files, _file_available, anchor, name,
                              CardLayout(alias, data_href, badges_apart=table_form))
        for f, anchor, alias in zip(files, anchors, aliases)
    ]
    rows = (_entry_rows(files, cards, profile, _file_available) if table_form else [])
    if not parts and table_form:
        lines.extend(held)
        lines.extend(_sectioned(files, _display_order(files),
                                lambda group: _entries_table(files, group, rows)))
    elif not parts:
        lines.extend(held)
        lines.extend(_sectioned(files, _display_order(files),
                                lambda group: [line for i in group for line in cards[i]]))
    else:
        lines.extend(_card_index(emu_name, files, anchors, aliases, parts,
                                 len(systems or []) > 1))
        lines.extend(held)
        for number, (stem, entries) in enumerate(parts, 1):
            part_pages[stem] = _emulator_part_page(
                name, emu_name, number, parts, [cards[i] for i in entries],
                [files[i] for i in entries],
                [rows[i] for i in entries] if table_form else None)
    return lines, part_pages


def _data_directory_lines(
    dd: dict, profile: dict, data_registry: dict | None, member_anchors: set[str],
) -> tuple[list[str], dict[str, str]]:
    """One data directory: what it holds, where it comes from, which build
    reads it, and the pages its member list went to."""
    lines: list[str] = []
    part_pages: dict[str, str] = {}
    ref = dd.get("ref", "")
    dest = dd.get("destination", "")
    entry = (data_registry or {}).get(ref, {})
    # An empty destination wrote "``", which opened a code span
    # running to the next one and hid a link from the MDX pass.
    line = f"- `{ref}` > `{dest}`" if dest else f"- `{ref}`"
    if entry.get("description"):
        line += f": {entry['description']}"
    lines.append(line)
    lines.extend(f"    - {line}" for line in data_directory_origin(
        entry, DATA_REVISIONS.get(ref) or {}))
    if dd.get("mode"):
        lines.append(f"    - Read by the {dd['mode']} build only")
    if dd.get("bundled"):
        lines.append("    - Installed with the emulator, so packs leave it out")
    if dd.get("source_ref"):
        lines.append(f"    - Source: {source_ref_markdown(profile, dd['source_ref'])}")
    members = DATA_MEMBERS.get(ref) or {}
    tree_pages = data_tree_pages(ref, members)
    if tree_pages:
        where = (f"[a page of their own]({tree_pages[0][0]}.md)" if len(tree_pages) == 1
                 else "pages of their own: " + ", ".join(
                     f"[part {i}]({stem}.md)" for i, (stem, _names) in enumerate(tree_pages, 1)))
        lines.append(f"    - {count_text(len(members), 'file')}, listed on {where}")
        for index, (stem, _names) in enumerate(tree_pages):
            part_pages[stem] = _data_tree_page(ref, entry, tree_pages, index)
    elif members:
        table = _data_member_table(members, sorted(members), member_anchors)
        lines.append("")
        lines.extend(markup.details(
            "info", f"{count_text(len(members), 'file')}, as the packs ship them",
            table, indent="    "))
    return lines, part_pages


def _data_directories_section(
    profile: dict, data_dirs: list[dict], data_registry: dict | None,
) -> tuple[list[str], dict[str, str]]:
    """The Data directories section, and the pages its member lists went to."""
    # The member tables are a file list with hashes: out of the search,
    # dolphin, primehack and ishiiruka each put 210 KB of it there.
    trees: list[str] = []
    part_pages: dict[str, str] = {}
    member_anchors: set[str] = set()
    # Each tree with what it holds, where it comes from, which build reads
    # it and the code that does: these trees put thousands of files in
    # the packs, and the page said only `dolphin-sys` > `Sys`.
    for dd in data_dirs:
        lines, pages = _data_directory_lines(dd, profile, data_registry, member_anchors)
        trees.extend(lines)
        part_pages.update(pages)
    trees.append("")
    # The member tables are the lookup's.
    return ["## Data directories", "", *search_excluded(trees)], part_pages


def emulator_pages(
    name: str,
    profile: dict,
    db: dict,
    consumers: FileConsumers | None = None,
    data_names: set[str] | None = None,
    data_registry: dict | None = None,
    data_dirs: list[dict] | None = None,
) -> dict[str, str]:
    """An emulator's page by stem under emulators/, and the pages its cards
    went to when there are more than EMULATOR_CARDS_PER_PAGE."""
    if profile.get("type") == "alias":
        return {name: _alias_page(name, profile)}

    emu_name = profile.get("emulator", name)
    files = profile.get("files", [])
    notes_raw = profile.get("notes", profile.get("note", ""))
    notes = (
        str(notes_raw).strip() if notes_raw and not isinstance(notes_raw, dict) else ""
    )
    exclusion = profile.get("exclusion_note", "")
    if data_dirs is None:
        data_dirs = profile.get("data_directories", [])

    part_pages: dict[str, str] = {}
    one_bios = any_name_bios(profile)
    intro = _emulator_intro(emu_name, profile, _collection_card_href(
        one_bios, consumers, name) if one_bios else "", name)
    romset = emulator_romset(profile)
    lines = [
        f"# {emu_name}",
        "",
        *([intro, ""] if intro else []),
    ]
    if romset:
        # The commonest arcade failure is a set from another MAME version,
        # and its answer sat on a Reference page no arcade page linked.
        # FinalBurn profiles list the members of their archives, not the
        # archives, and MAME 2003-Plus none at all: the line went missing
        # on both.
        lines.extend([f"Its BIOS and game sets must come from the {romset} romset. "
                      f"[Which version each core reads]({ROMSET_FAQ}).", ""])
    card = [
        markup.block_open("div", 'class="rb-meta-card"'),
        "",
        "| Detail | Value |",
        "|---|---|",
        *_emulator_meta_rows(name, profile),
        "",
        "</div>",
        "",
    ]
    # Reference for the few who check a revision: stacked on a phone, the
    # card took two screens above the files.
    lines.extend(markup.details("note", "About this profile", card))

    lines.extend(install_block(name, profile))

    lines.extend(render_platform_details(profile))

    if notes:
        body = admonition_body(data_root_words(link_prose_citations(profile, notes))
                                ).replace("\n    ", "\n")
        lines.extend(markup.details("note", "Technical notes", body.split("\n")))

    if not files:
        lines.append("No BIOS or firmware files required.")
        if exclusion:
            lines.append("")
            lines.extend(markup.aside("info", "Why no files", [escape_tags(str(exclusion))])[:-1])
    else:
        section, pages = _emulator_files_section(
            name, emu_name, profile, _EmulatorSources(db, consumers, data_names))
        lines.extend(section)
        part_pages.update(pages)

    lines.extend(sitemeasurements.proof_section(MEASUREMENT_ITEMS.get(name, [])))

    blocks = render_structured_blocks(profile)
    if blocks:
        lines.extend(["## Profile data", "", *blocks])

    if data_dirs:
        section, pages = _data_directories_section(profile, data_dirs, data_registry)
        lines.extend(section)
        part_pages.update(pages)

    lines.extend(next_block([
        "[Get the files](../which-pack.md), for the setup in use",
        "[Every system](../systems/index.md), and the files each one needs",
        "[When a game does not start](../wiki/troubleshooting.md)",
    ]))
    lines.extend(["", date_line()])
    return {name: "\n".join(lines) + "\n", **part_pages}


def _card_index(
    emu_name: str, files: list[dict], anchors: list[str], aliases: list[str],
    parts: Sequence[tuple[str, Sequence[int]]], multi_system: bool = False,
) -> list[str]:
    """Every entry of a split emulator page, one row each, linked to its card.

    Each row holds the ids the card had on this page, so a link cited
    before the split lands on the row, and site.js follows it to the card.
    """
    page_of = {index: stem for stem, entries in parts for index in entries}

    def cell(i: int, shown: str) -> str:
        # The id sits on the link itself, one element fewer per row: MAME's
        # 1,564 rows put 13,300 elements on its page.
        href = markup.site_href(f"emulators/{page_of[i]}/#{anchors[i]}")
        alias = f'<span id="{aliases[i]}"></span>' if aliases[i] else ""
        return (f'{alias}<a id="{anchors[i]}" href="{href}">'
                f"<code>{html.escape(shown, quote=False)}</code></a>")

    def table(group: list[int]) -> list[str]:
        return [
            markup.block_open("section", f'class="rb-card-index" {markup.search_exclude()}'),
            "", *_summary_table(files, group, cell, multi_system), "", "</section>", "",
        ]

    return [
        f"{emu_name} reads more files than one page holds: each entry below "
        f"links to its card, on {count_text(len(parts), 'page')}: "
        + ", ".join(f"[{number}]({stem}.md)" for number, (stem, _e) in enumerate(parts, 1))
        + ".",
        "",
        *_sectioned(files, _display_order(files), table),
    ]


def _part_front_matter(parent: tuple[str, str], siblings: list[tuple[str, str]],
                       index: int, front: dict | None = None) -> list[str]:
    """The front matter of part ``index`` of ``siblings`` ((label, link)
    each): the page it belongs to, its neighbours and the part weight.

    MAME's eight card pages had no parent, so the crumbs skipped MAME, and
    `prev: false`, so part 5 reached part 6 only through a sentence.
    The first part's previous page is the parent, the last part has no next.
    """
    data = dict(front or {})
    data["parent"] = {"label": parent[0], "link": parent[1]}
    before = siblings[index - 1] if index > 0 else parent
    data["prev"] = {"label": before[0], "link": before[1]}
    data["next"] = ({"label": siblings[index + 1][0], "link": siblings[index + 1][1]}
                    if index + 1 < len(siblings) else False)
    data["searchWeight"] = SEARCH_WEIGHT.get("part", DEMOTED_WEIGHT)
    return ["---", yaml.safe_dump(data, sort_keys=False, allow_unicode=True).rstrip("\n"),
            "---", ""]


def _emulator_part_page(
    name: str, emu_name: str, number: int, parts: Sequence[tuple[str, Sequence[int]]],
    cards: list[list[str]], files: list[dict], rows: list[siteentries.Row] | None = None,
) -> str:
    """One page of a split emulator's cards: with ``rows``, one table row
    each, the card under its name."""
    if rows is not None:
        def render(group: list[int]) -> list[str]:
            return _entries_table(files, group, rows)
    else:
        def render(group: list[int]) -> list[str]:
            return [line for i in group for line in cards[i]]
    first = str(files[0].get("path") or files[0].get("name", ""))
    last = str(files[-1].get("path") or files[-1].get("name", ""))
    others = ", ".join(
        f"[{n}]({stem}.md)" for n, (stem, _e) in enumerate(parts, 1) if n != number)
    lines = [
        *_part_front_matter((emu_name, f"{name}.md"),
                            [(f"{emu_name} files, part {n}", f"{stem}.md")
                             for n, (stem, _e) in enumerate(parts, 1)], number - 1),
        f"# {emu_name} files, part {number} of {len(parts)}",
        "",
        # The crumbs end on the emulator, read from parent:.
        f"This part holds {count_text(len(files), 'entry', 'entries')}, "
        f"{code_span(first)} to {code_span(last)}. The other parts: {others}.",
        "",
        *_sectioned(files, list(range(len(files))), render),
    ]
    lines.extend(next_block([f"[{emu_name}]({name}.md), the profile and every entry"]))
    lines.extend(["", date_line()])
    return "\n".join(lines) + "\n"
