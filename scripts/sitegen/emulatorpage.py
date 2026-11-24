"""Each emulator's page: intro, files, data directories and parts."""

from __future__ import annotations

import html
import re
import urllib.parse
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from core.hashing import parse_hash_list
from sitegen.runsections import system_name
from model.profiles import is_emulator
from packs.consumers import FileConsumers
from packs.supplemental import SupplementalIndex
from sitegen import entries as siteentries, markup, measurements as sitemeasurements
from sitegen.cards import ROMSET_FAQ, emulator_file_anchors
from sitegen.config import REPO_URL, date_line
from sitegen.emulatorcards import (
    CardLayout,
    CardSources,
    build_rows,
    entry_label,
    named_system_link,
    render_emulator_file,
    any_name_bios,
)
from sitegen.filebadges import file_badges, region_words
from sitegen.emulatormetadata import render_metadata_rows, emulator_romset, version_markdown
from sitegen.emulatorsindex import CLS_LABEL_ONE
from sitegen.fields import render_platform_details, render_structured_blocks
from sitegen.home import next_block
from sitegen.install import (
    install_block,
    platform_display,
    comes_with_app,
    data_root_words,
)
from sitegen.pageregistry import PageRegistry
from sitegen.render import admonition_body, card_anchor, code_span, count_text, escape_tags
from sitegen.runlinks import card_page, record_emulator_cards
from sitegen.sources import link_prose_citations, revision_markdown
from sitegen.parts import even_runs, part_front_matter, weighted_runs
from sitegen.structured import emulator_file_aliases
from sitegen.emulatordata import data_directories_section
from sitegen.emulatorintro import emulator_file_summary, emulator_held_line, emulator_intro


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
    db: dict, data_names: SupplementalIndex | None, owner: str = "",
) -> Callable[[dict], bool]:
    """A predicate answering whether the collection holds a file.

    It answers the way cross_reference does. A page that called a file
    missing while the gap report called it held would describe a
    different collection on two pages of the same site.
    """
    from packs.crossref import entry_index, entry_source

    index = entry_index(db, data_names)

    def _file_available(f: dict) -> bool:
        """Check if a file is available using the same resolution as cross_reference."""
        # cross_reference sets these aside before resolving: the file found
        # under the name belongs to another game or release.
        if not f.get("name") or f.get("unsourceable"):
            return False
        return entry_source({**f, "source_profile": owner} if owner else f, index) is not None

    return _file_available


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
    count = max(len(weighted_runs(order, ceiling, sizes)), -(-len(files) // EMULATOR_CARDS_PER_PART))
    while True:
        # The fewest words a part can hold for the parts to be ``count``:
        # cut at the ceiling, the last part took what the others left.
        runs = even_runs(order, sizes, count, ceiling)
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
    data_names: SupplementalIndex | None = None,
    data_registry: dict | None = None,
    data_dirs: list[dict] | None = None,
    registry: PageRegistry | None = None,
) -> str:
    """One emulator's page. ``data_dirs`` defaults to the profile's own."""
    return emulator_pages(
        name, profile, db, consumers, data_names, data_registry, data_dirs, registry)[name]


def _collection_card_href(entry: dict, consumers: FileConsumers | None, owner: str) -> str:
    """The collection card of the copy that answers an emulator entry, or ""."""
    if consumers is None:
        return ""
    sha1 = consumers.sha1_of(entry, entry.get("path") or "", owner=owner)
    held = consumers.path_of(sha1) if sha1 else ""
    if not held.startswith("bios/"):
        return ""
    return f"../systems/{urllib.parse.quote(card_page(held, sha1))}.md#{card_anchor(sha1)}"


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


def _emulator_meta_rows(name: str, profile: dict, setups: list[str] | None) -> list[str]:
    """The rows of the "About this profile" card, after its header.
    ``setups`` are the platforms that run the emulator."""
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
    data_names: SupplementalIndex | None
    data_members: dict[str, dict[str, dict]]


def _emulator_files_section(
    name: str, emu_name: str, profile: dict, sources: _EmulatorSources,
) -> tuple[list[str], dict[str, str]]:
    """The Files section, and the pages its cards went to."""
    files = profile.get("files", [])
    systems = profile.get("systems", [])
    cards_from = (CardSources(sources.consumers, sources.data_members)
                  if sources.consumers else None)
    part_pages: dict[str, str] = {}
    lines: list[str] = []
    _file_available = availability_check(sources.db, sources.data_names, name)

    lines.extend(["## Files", ""])
    lines.extend(emulator_file_summary(files, profile.get("groups")))
    held = emulator_held_line(files, _file_available)

    anchors = emulator_file_anchors(files)
    aliases = emulator_file_aliases(files, anchors)
    parts = emulator_parts(name, files, profile, _file_available)
    data_href = f"{name}.md#data-folder" if parts else "#data-folder"
    table_form = markup.starlight() and (bool(parts) or len(files) >= EMULATOR_TABLE_MIN)
    cards = [
        render_emulator_file(f, profile, cards_from, files, _file_available, anchor, name,
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


def emulator_pages(
    name: str,
    profile: dict,
    db: dict,
    consumers: FileConsumers | None = None,
    data_names: SupplementalIndex | None = None,
    data_registry: dict | None = None,
    data_dirs: list[dict] | None = None,
    registry: PageRegistry | None = None,
) -> dict[str, str]:
    """An emulator's page by stem under emulators/, and the pages its cards
    went to when there are more than EMULATOR_CARDS_PER_PAGE. ``registry``
    is what the build recorded about its pages."""
    registry = registry or PageRegistry()
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
    intro = emulator_intro(emu_name, profile, _collection_card_href(
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
        *_emulator_meta_rows(name, profile, registry.emulator_setups.get(name)),
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
            name, emu_name, profile,
            _EmulatorSources(db, consumers, data_names, registry.data_members))
        lines.extend(section)
        part_pages.update(pages)

    lines.extend(sitemeasurements.proof_section(registry.measurement_items.get(name, [])))

    blocks = render_structured_blocks(profile)
    if blocks:
        lines.extend(["## Profile data", "", *blocks])

    if data_dirs:
        section, pages = data_directories_section(profile, data_dirs, data_registry, registry)
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
        *part_front_matter((emu_name, f"{name}.md"),
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
