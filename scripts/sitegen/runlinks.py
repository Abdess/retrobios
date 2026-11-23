"""Where one run's pages put systems, consoles, cards and boards."""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field

from core.paths import REPO_ROOT
from model import siteinputs
from model.collection import card_moves
from model.systemnames import (
    SYSTEM_PARENTS,
    ensure_console_sections,
    section_without_boards,
    sections_generation,
    system_name,
)
from sitegen import markup
from sitegen.arcadeboards import ArcadeBoards, read_arcade_boards
from sitegen.render import SYSTEM_ICON_BASE, board_slug, console_anchor, console_icon_name

# Local copies of the upstream icons, named as upstream names them.
ICON_DIR = REPO_ROOT / "docs_assets" / "system-icons"


@dataclass
class LinkTables:
    """The answers one run gives to where a page is.

    ``system_pages``: the system ids the collection's folders place
    (sitegen.places), by the folder each is placed in. ``console_pages``:
    (slug, console) -> its page stems under systems/ when a manufacturer page
    too large for one is cut, and ``card_pages`` (slug, console, sha1) -> the
    stem holding that card. ``board_sections``: boards whose section the
    system pages wrote. ``emulator_card_pages``: (emulator, anchor) -> the
    emulators/ stem a card moved to. ``icons``: icon name -> whether the site
    holds a copy. ``arcade``: the boards elected, with the sections_generation
    they were elected under. ``aliases``: page_aliases() built from the rest,
    with the sections_generation it read, dropped whenever a table it reads
    changes.
    """

    system_pages: dict[str, tuple[str, str]] = field(default_factory=dict)
    console_pages: dict[tuple[str, str], list[str]] = field(default_factory=dict)
    card_pages: dict[tuple[str, str, str], str] = field(default_factory=dict)
    board_sections: set[str] = field(default_factory=set)
    emulator_card_pages: dict[tuple[str, str], str] = field(default_factory=dict)
    icons: dict[str, bool] = field(default_factory=dict)
    arcade: tuple[int, ArcadeBoards] | None = None
    aliases: tuple[int, dict[str, list[str]]] | None = None


_current = [LinkTables()]


def current() -> LinkTables:
    return _current[0]


def use(tables: LinkTables) -> None:
    """Install a run's tables, the previous run's forgotten."""
    _current[0] = tables


def prime_system_icons(names: set[str]) -> int:
    """Record which system icons the site holds a copy of, and return how
    many of ``names`` have none.

    The icons are copied once into ``docs_assets/system-icons/`` by
    ``scripts/fetch_site_images.py``: the build reads that folder and never
    the network. A system without a copy gets no icon, because a heading
    with a broken image reads worse than a heading without one.
    """
    held = {path.stem for path in ICON_DIR.glob("*.png")}
    current().icons.update({name: name in held for name in names})
    return sum(1 for name in names if name not in held)


def system_icon_markdown(manufacturer: str, console_name: str) -> str:
    """Icon image for a system heading, empty when the site holds none.

    The link names the upstream file: ``sitegen.pageprep.localize_images``
    points it at the local copy, whose source is recorded beside it.
    """
    name = console_icon_name(manufacturer, console_name)
    if not current().icons.get(name):
        return ""
    url = f"{SYSTEM_ICON_BASE}/{urllib.parse.quote(name)}.png"
    return markup.image(console_name, url, width="24") + " "


def set_system_page_map(mapping: dict[str, tuple[str, str]]) -> None:
    """Install the run's placed system ids, replacing the previous table."""
    tables = current()
    tables.system_pages = dict(mapping)
    tables.aliases = None


def reset_console_pages() -> None:
    """Forget where the system pages put consoles, cards and boards."""
    tables = current()
    tables.console_pages.clear()
    tables.card_pages.clear()
    tables.board_sections.clear()
    tables.aliases = None


def record_console_pages(
    slug: str, console: str, stems: list[str], sha1s: list[list[str]]
) -> None:
    """Where a split manufacturer page put one console: its page stems, in
    order, and the sha1 of each card on each of them."""
    tables = current()
    tables.console_pages[(slug, console)] = list(stems)
    for stem, part in zip(stems, sha1s):
        for sha1 in part:
            tables.card_pages.setdefault((slug, console, sha1), stem)
    tables.aliases = None


def split_system_stems() -> set[str]:
    """Every page stem of a console moved to a page of its own."""
    return {stem for stems in current().console_pages.values() for stem in stems}


def console_href(slug: str, console: str, prefix: str = "") -> str:
    """Where a console's files are: its own page, or its section of the
    manufacturer's page (also where a console cut into parts lists them).
    An arcade board's section is the page of its own name, no heading
    repeating its title."""
    tables = current()
    if slug == "arcade" and tables.board_sections:
        board = _board_ids_by_name().get(console.casefold())
        if board in tables.board_sections:
            return f"{prefix}systems/arcade-{urllib.parse.quote(board_slug(board))}.md"
    stems = tables.console_pages.get((slug, console))
    if stems and len(stems) == 1:
        return f"{prefix}systems/{urllib.parse.quote(stems[0])}.md"
    return f"{prefix}systems/{urllib.parse.quote(slug)}.md#{console_anchor(slug, console)}"


def card_page(path: str, sha1: str) -> str:
    """The systems/ page stem holding the card of the copy at ``path``
    (bios/<Manufacturer>/<Console>/...). A board's set is on the board's
    page whatever folder holds the copy."""
    tables = current()
    parts = path.split("/")
    slug = parts[1].lower().replace(" ", "-")
    console = parts[2] if len(parts) > 2 else ""
    if tables.board_sections:
        board = arcade_board(sha1)
        if board in tables.board_sections:
            return f"arcade-{board_slug(board)}"
    slug, console = card_moves.get((slug, console, str(sha1)), (slug, console))
    return tables.card_pages.get((slug, console, sha1), slug)


def record_emulator_cards(emulator: str, stem: str, anchors: list[str]) -> None:
    """Emulator cards moved off a page too long for one, to ``stem``."""
    for anchor in anchors:
        current().emulator_card_pages[(emulator, anchor)] = stem


def emulator_card_page(emulator: str, anchor: str) -> str:
    """The emulators/ page stem holding a card: the emulator's own page, or
    the page its cards went to."""
    return current().emulator_card_pages.get((emulator, anchor), emulator)


# A system id that names a family of arcade boards -> the board its link
# leads to. RetroArch's sega-dreamcast-arcade lists the NAOMI, NAOMI 2 and
# Atomiswave BIOS: the NAOMI page comes first, the Dreamcast section links
# the others.
BOARD_PARENTS: dict[str, str] = {
    "sega-dreamcast-arcade": "sega-naomi",
}


def system_section(sys_id: str) -> tuple[str, str] | None:
    """The console section a system id leads to, as (manufacturer slug,
    console): its own section, else the parent SYSTEM_PARENTS names, else
    the arcade board it names once record_board_section() wrote it
    (``("arcade", <board name>)``, which console_href turns into
    ``systems/arcade-<board slug>.md#<board slug>``), else the one section
    whose heading reads system_name(). The folder a system's files sit in
    is no answer by itself: Emerson's Arcadia 2001 led to the Saturn and
    Sega's NAOMI to the Dreamcast.

    A heading under Arcade counts when it reads the name exactly (Namco
    System 246). One under Other never does, its headings name programs."""
    sections = current().board_sections
    if sys_id in BOARD_PARENTS and sections:
        board = _board_of_id(BOARD_PARENTS[sys_id])
        if board in sections:
            return "arcade", system_name(board)
    section = section_without_boards(sys_id)
    if (not sections or sys_id in SYSTEM_PARENTS
            or (section is not None and section[0] != "arcade")):
        return section
    board = _board_of_id(sys_id)
    if board in sections:
        return "arcade", system_name(board)
    return section


def system_link(sys_id: str, prefix: str = "") -> str:
    """A system id linked to the section named after it, or the bare id."""
    section = system_section(sys_id)
    if section:
        slug, console = section
        return f"[{sys_id}]({console_href(slug, console, prefix)})"
    return sys_id


def link_coverage(ids: set[str]) -> tuple[int, int]:
    """How many of ``ids`` lead to a section, and how many there are."""
    return sum(1 for sys_id in ids if system_section(sys_id)), len(ids)


def use_arcade_boards(boards: ArcadeBoards) -> None:
    """Install the boards elected for the sections installed now. Without
    it, or once the sections change, they are read from the site inputs on
    first use."""
    ensure_console_sections()
    tables = current()
    tables.arcade = (sections_generation[0], boards)
    tables.aliases = None


def _boards() -> ArcadeBoards:
    ensure_console_sections()
    tables = current()
    held = tables.arcade
    if held is not None and held[0] == sections_generation[0]:
        return held[1]
    boards = read_arcade_boards()
    tables.arcade = (sections_generation[0], boards)
    return boards


def archive_machine(sha1: str) -> tuple[str, str] | None:
    """The (manufacturer, console) section of the machine an archive is
    the set of, when a profile declares it for one machine only: the Neo
    Geo's neogeo.zip, the MZ-2000's mz2000.zip. Read from the same
    ``category: bios_zip`` entries as arcade_board(), never the folder."""
    places = _boards().archive_machines.get(str(sha1), frozenset())
    return next(iter(places)) if len(places) == 1 else None


def _board_ids_by_name() -> Mapping[str, str]:
    return _boards().board_names


def _board_of_id(sys_id: str) -> str | None:
    """The board an id names, by its display name: naomi2 and sega-naomi2
    are one board."""
    try:
        name = system_name(sys_id)
    except KeyError:
        return None
    return _board_ids_by_name().get(name.casefold())


def arcade_board(sha1: str) -> str | None:
    """The system id an arcade archive is the BIOS of, or None.

    Read from the profiles' ``system``/``systems`` and ``contents:``,
    never from the folder. An archive several boards share as often (a
    device ROM), or one a machine with its own section names (neogeo.zip
    for the Neo Geo, cd32.zip for the CD32), has no board. Every id of a
    board's name returns the same id, the first in sort order."""
    return _boards().archive_boards.get(str(sha1))


def record_board_section(board: str) -> None:
    """Mark a board's section as written, at systems/arcade-<board_slug>/
    under the heading <board_slug>. From then on system_section() leads
    every id of the board there, and card_page() sends its Arcade cards
    there. The system pages call it for each board they give a section,
    before any other page links one. A link waits for its section: before
    the Arcade pages were grouped by board, 8,606 links on 141 pages led to
    pages nobody wrote and the build stopped."""
    canonical = _board_of_id(str(board))
    if canonical is None:
        raise KeyError(f"{board!r} is not an arcade board")
    tables = current()
    tables.board_sections.add(canonical)
    tables.aliases = None


def arcade_boards() -> dict[str, str]:
    """Every board, by board id -> display name."""
    return {board: system_name(board) for board in sorted(set(_boards().board_names.values()))}


# platforms folder -> system id -> the names its platform files give it.
_search_aliases: dict[str, dict[str, list[str]]] = {}
# A native name as a person types it: no space, no comma. RetroArch's
# native names are No-Intro titles ("Sony - PlayStation") and stay out.
_ALIAS_SHAPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]*")


def _read_search_aliases(platforms_dir: str) -> dict[str, list[str]]:
    from model.registry import list_registered_platforms
    from model.platforms import load_platform_config
    from model.systems import platform_system_names

    index: dict[str, set[str]] = {}
    for platform in list_registered_platforms(platforms_dir):
        config = load_platform_config(platform, platforms_dir)
        names = platform_system_names(config, list(config.get("systems", {})))
        for owner, spelled in names.items():
            index.setdefault(owner, set()).update(
                name for name in spelled if _ALIAS_SHAPE.fullmatch(name)
            )
    # Search ignores case: one spelling per word, the lower-case one
    # when a platform writes it (psx, not PSX).
    aliases: dict[str, list[str]] = {}
    for owner, names in index.items():
        spellings: dict[str, str] = {}
        for name in sorted(names, key=lambda n: (n != n.lower(), n)):
            spellings.setdefault(name.casefold(), name)
        if spellings:
            aliases[owner] = sorted(spellings.values(), key=str.casefold)
    return aliases


def system_search_aliases(sys_id: str) -> list[str]:
    """The native system ids the platform YAMLs file ``sys_id`` under
    (psx, dreamcast, gba), sorted, for search. Read from each platform's
    own entries by common.platform_system_names, never typed by hand, in
    the platforms folder the site inputs name."""
    platforms_dir = str(siteinputs.current().platforms)
    if platforms_dir not in _search_aliases:
        _search_aliases[platforms_dir] = _read_search_aliases(platforms_dir)
    return list(_search_aliases[platforms_dir].get(str(sys_id), []))


def page_aliases(rel: str) -> list[str]:
    """The names the platforms file the consoles of a system page under
    (psx, dreamcast, gba), from system_search_aliases(): "psx bios" finds
    the PlayStation page though the page never says psx. Built from the
    run's tables, again once one of them changes."""
    tables = current()
    if not tables.system_pages:
        return []
    ensure_console_sections()
    if tables.aliases is None or tables.aliases[0] != sections_generation[0]:
        by_page: dict[str, set[str]] = {}
        for sys_id in list(tables.system_pages):
            section = system_section(sys_id)
            names = system_search_aliases(sys_id)
            if not section or not names:
                continue
            target = console_href(*section).partition("#")[0]
            by_page.setdefault(urllib.parse.unquote(target), set()).update(names)
        tables.aliases = (sections_generation[0], {
            page: sorted(names, key=str.casefold) for page, names in by_page.items()})
    return list(tables.aliases[1].get(rel, []))
