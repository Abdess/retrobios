"""Small renderings shared by every page."""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Callable, Mapping

from model import siteinputs
from sitegen import markup
from sitegen.arcadeboards import ArcadeBoards, read_arcade_boards
from core.paths import REPO_ROOT
from core.text import count_text as count_text
from model.collection import card_moves, manufacturer_slug
from model.systemnames import (
    SYSTEM_PARENTS,
    console_anchors,
    ensure_console_sections,
    section_without_boards,
    sections_generation,
    system_name,
)


WIKI_SRC_DIR = "wiki"  # manually maintained wiki sources
SYSTEM_ICON_BASE = "https://raw.githubusercontent.com/libretro/retroarch-assets/master/xmb/systematic/png"
# Local copies of the upstream icons, named as upstream names them.
ICON_DIR = REPO_ROOT / "docs_assets" / "system-icons"

# Icon names the site holds a copy of. A name mapped to False has none.
_icon_available: dict[str, bool] = {}

_CODE_SPAN = re.compile(r"(`+).+?\1", re.S)


def code_span(value: object) -> str:
    """A value as an inline code span it cannot leave.

    Markdown shows HTML inside a code span as text, so the one way out is a
    backtick in the value closing the span early. Data from a profile, a
    platform file or a file name is not ours to trust that far.
    """
    return "`" + str(value).replace("`", "'") + "`"


# A hash shown short, in a card, a platform row or an emulator table: as long
# as the card's own address (sha1-<12 hex>), one length across the site.
SHORT_HASH = 12
# A file card's permanent id: published, linked from outside, and read back
# by the site's lookup (model/retired.py keeps a retired one answering).
CARD_ANCHOR = re.compile(rf"sha1-[0-9a-f]{{{SHORT_HASH}}}")


def card_anchor(sha1: str) -> str:
    """The id of the card a file's sha1 heads: sha1-<first 12 hex>."""
    return f"sha1-{sha1[:SHORT_HASH]}"


def escape_tags(text: str) -> str:
    """Show a placeholder such as ``<system_dir>`` as it was written.

    Profile prose names paths with angle brackets. Passed through as HTML
    they are unknown tags and vanish from the page, and ``<title id>`` opens
    a title element that swallows everything after it. Code spans keep their
    brackets, and an autolink stays a link.
    """
    def outside(chunk: str) -> str:
        return re.sub(r"<(?!https?://|mailto:)", "&lt;", chunk)

    out: list[str] = []
    position = 0
    for match in _CODE_SPAN.finditer(text):
        out.append(outside(text[position:match.start()]))
        out.append(match.group(0))
        position = match.end()
    out.append(outside(text[position:]))
    return "".join(out)


def admonition_body(text: str) -> str:
    """Indent prose without turning source tokens such as ``#if`` into H1s."""
    escaped = re.sub(r"(?m)^(\s*)#", r"\1\\#", escape_tags(text))
    return escaped.replace("\n", "\n    ")

def console_icon_name(manufacturer: str, console_name: str) -> str:
    return f"{manufacturer} - {console_name}".replace("/", " ")

def _icon_url(icon_name: str) -> str:
    return f"{SYSTEM_ICON_BASE}/{urllib.parse.quote(icon_name)}.png"

def prime_system_icons(names: set[str]) -> None:
    """Record which system icons the site holds a copy of.

    The icons are copied once into ``docs_assets/system-icons/`` by
    ``scripts/fetch_site_images.py``: the build reads that folder and never
    the network. A system without a copy gets no icon, because a heading
    with a broken image reads worse than a heading without one.
    """
    held = {path.stem for path in ICON_DIR.glob("*.png")}
    _icon_available.update({name: name in held for name in names})
    missing = sum(1 for name in names if name not in held)
    if missing:
        print(f"  {missing} systems have no icon in {ICON_DIR.relative_to(ICON_DIR.parents[1])}")

def system_icon_markdown(manufacturer: str, console_name: str) -> str:
    """Icon image for a system heading, empty when the site holds none.

    The link names the upstream file: ``sitegen.pageprep.localize_images``
    points it at the local copy, whose source is recorded beside it.
    """
    name = console_icon_name(manufacturer, console_name)
    if not _icon_available.get(name):
        return ""
    return markup.image(console_name, _icon_url(name), width="24") + " "

# The system ids the collection's folders place (sitegen.places), by the
# folder each is placed in. Read as the run's set of system ids: a link, an
# install command and a card's maker go where system_section() says.
system_page_map: dict[str, tuple[str, str]] = {}

def slugify_anchor(text: str) -> str:
    """Slugify text for MkDocs anchor compatibility."""
    import re

    slug = text.lower()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s]+", "-", slug)
    slug = slug.strip("-")
    return slug

def set_system_page_map(mapping: dict[str, tuple[str, str]]) -> None:
    """Install the run's placed system ids, replacing the previous table."""
    system_page_map.clear()
    system_page_map.update(mapping)


# A manufacturer page too large for one page is a summary, each console on
# pages of its own: (slug, console) -> its page stems under systems/, and
# (slug, console, sha1) -> the stem holding that card. A console of a page
# kept whole has no entry, its section is on the manufacturer's page.
_console_pages: dict[tuple[str, str], list[str]] = {}
_card_pages: dict[tuple[str, str, str], str] = {}


def reset_console_pages() -> None:
    """Forget where the system pages put consoles, cards and boards."""
    _console_pages.clear()
    _card_pages.clear()
    _board_sections.clear()


def record_console_pages(
    slug: str, console: str, stems: list[str], sha1s: list[list[str]]
) -> None:
    """Where a split manufacturer page put one console: its page stems, in
    order, and the sha1 of each card on each of them."""
    _console_pages[(slug, console)] = list(stems)
    for stem, part in zip(stems, sha1s):
        for sha1 in part:
            _card_pages.setdefault((slug, console, sha1), stem)


def split_system_stems() -> set[str]:
    """Every page stem of a console moved to a page of its own."""
    return {stem for stems in _console_pages.values() for stem in stems}


def console_anchor(manufacturer: str, console: str) -> str:
    """The id of a console's heading on its manufacturer's page."""
    from core.anchors import toc_slug

    key = (manufacturer_slug(manufacturer), console)
    return console_anchors.get(key) or toc_slug(console)


def console_href(slug: str, console: str, prefix: str = "") -> str:
    """Where a console's files are: its own page, or its section of the
    manufacturer's page (also where a console cut into parts lists them).
    An arcade board's section is the page of its own name, no heading
    repeating its title."""
    if slug == "arcade" and _board_sections:
        board = _board_ids_by_name().get(console.casefold())
        if board in _board_sections:
            return f"{prefix}systems/arcade-{urllib.parse.quote(board_slug(board))}.md"
    stems = _console_pages.get((slug, console))
    if stems and len(stems) == 1:
        return f"{prefix}systems/{urllib.parse.quote(stems[0])}.md"
    return f"{prefix}systems/{urllib.parse.quote(slug)}.md#{console_anchor(slug, console)}"


def card_page(path: str, sha1: str) -> str:
    """The systems/ page stem holding the card of the copy at ``path``
    (bios/<Manufacturer>/<Console>/...). A board's set is on the board's
    page whatever folder holds the copy."""
    parts = path.split("/")
    slug = parts[1].lower().replace(" ", "-")
    console = parts[2] if len(parts) > 2 else ""
    if _board_sections:
        board = arcade_board(sha1)
        if board in _board_sections:
            return f"arcade-{board_slug(board)}"
    slug, console = card_moves.get((slug, console, str(sha1)), (slug, console))
    return _card_pages.get((slug, console, sha1), slug)


# Emulator cards moved off a page too long for one: (emulator, anchor) ->
# the page stem under emulators/ that holds the card.
_emulator_card_pages: dict[tuple[str, str], str] = {}


def record_emulator_cards(emulator: str, stem: str, anchors: list[str]) -> None:
    for anchor in anchors:
        _emulator_card_pages[(emulator, anchor)] = stem


def emulator_card_page(emulator: str, anchor: str) -> str:
    """The emulators/ page stem holding a card: the emulator's own page, or
    the page its cards went to."""
    return _emulator_card_pages.get((emulator, anchor), emulator)


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
    if sys_id in BOARD_PARENTS and _board_sections:
        board = _board_of_id(BOARD_PARENTS[sys_id])
        if board in _board_sections:
            return "arcade", system_name(board)
    section = section_without_boards(sys_id)
    if (not _board_sections or sys_id in SYSTEM_PARENTS
            or (section is not None and section[0] != "arcade")):
        return section
    board = _board_of_id(sys_id)
    if board in _board_sections:
        return "arcade", system_name(board)
    return section


def _system_link(sys_id: str, prefix: str = "") -> str:
    """A system id linked to the section named after it, or the bare id."""
    section = system_section(sys_id)
    if section:
        slug, console = section
        return f"[{sys_id}]({console_href(slug, console, prefix)})"
    return sys_id


# The arcade boards elected (sitegen.arcadeboards) for the sections
# installed, with the sections_generation they were elected under.
_arcade: list[tuple[int, ArcadeBoards] | None] = [None]


def use_arcade_boards(boards: ArcadeBoards) -> None:
    """Install the boards elected for the sections installed now. Without
    it, or once the sections change, they are read from the site inputs on
    first use."""
    ensure_console_sections()
    _arcade[0] = (sections_generation[0], boards)


def _boards() -> ArcadeBoards:
    ensure_console_sections()
    held = _arcade[0]
    if held is not None and held[0] == sections_generation[0]:
        return held[1]
    boards = read_arcade_boards()
    _arcade[0] = (sections_generation[0], boards)
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


def board_slug(sys_id: str) -> str:
    """The slug of a board's section: its page is systems/arcade-<slug>/
    and its heading's id is <slug>. Read from the board's display name,
    so every id of one board gives one slug."""
    from core.anchors import toc_slug

    return toc_slug(system_name(str(sys_id)))


# Boards whose section the system pages wrote. A link waits for its
# section: before the Arcade pages were grouped by board, 8,606 links on
# 141 pages led to pages nobody wrote and the build stopped.
_board_sections: set[str] = set()


def record_board_section(board: str) -> None:
    """Mark a board's section as written, at systems/arcade-<board_slug>/
    under the heading <board_slug>. From then on system_section() leads
    every id of the board there, and card_page() sends its Arcade cards
    there. The system pages call it for each board they give a section,
    before any other page links one."""
    canonical = _board_of_id(str(board))
    if canonical is None:
        raise KeyError(f"{board!r} is not an arcade board")
    _board_sections.add(canonical)


def arcade_boards() -> dict[str, str]:
    """Every board, by board id -> display name."""
    return {board: system_name(board) for board in sorted(set(_boards().board_names.values()))}


def scalar_text(key: object, value: object) -> str:
    """A scalar of a structured block. A source reference reads as code."""
    if isinstance(value, bool):
        text = "yes" if value else "no"
    elif value is None:
        text = "none"
    else:
        # One line: a folded note's second line started at column 0 and
        # left the admonition it was written in. Never cut: 34 notes lost
        # their end, and a cut citation links to another line.
        text = " ".join(str(value).split())
    return f"`{text}`" if key == "source_ref" else text


def _field_label(key: object) -> str:
    """A YAML key as the page shows it: words, not an identifier."""
    return str(key).replace("_", " ")


FieldText = Callable[[object, object], str]


def render_yaml_value(
    lines: list[str], val: object, indent: int = 4,
    field_text: FieldText = scalar_text,
) -> None:
    """Render any YAML value as a nested markdown list.

    Every level is a list item and its children a sublist four spaces in.
    A key written as a paragraph with its children indented below it read as
    an indented code block: the clownmdemu page showed the raw asterisks.
    ``field_text`` renders each scalar, so a page can link a source_ref.
    """
    pad = " " * indent
    if isinstance(val, dict):
        for k, v in val.items():
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}- **{_field_label(k)}:**")
                lines.append("")
                render_yaml_value(lines, v, indent + 4, field_text)
            else:
                lines.append(f"{pad}- **{_field_label(k)}:** {field_text(k, v)}")
        lines.append("")
    elif isinstance(val, list):
        for item in val:
            if isinstance(item, dict):
                # Scalars on the item's line, lists and maps as its children:
                # cemu's firmware titles lost the files each title carries.
                scalars = {ik: iv for ik, iv in item.items()
                           if not (isinstance(iv, (dict, list)) and iv)}
                nested = {ik: iv for ik, iv in item.items() if ik not in scalars}
                parts = [f"{_field_label(ik)}: {field_text(ik, iv)}"
                         for ik, iv in scalars.items()]
                lines.append(f"{pad}- {', '.join(parts)}".rstrip())
                if nested:
                    lines.append("")
                    render_yaml_value(lines, nested, indent + 4, field_text)
            else:
                lines.append(f"{pad}- {field_text(None, item)}")
        lines.append("")
    elif isinstance(val, str) and "\n" in val:
        lines.extend(f"{pad}{line}" for line in val.split("\n"))
    else:
        lines.append(f"{pad}{field_text(None, val)}")


def _platform_link(name: str, display: str, prefix: str = "") -> str:
    """Generate a markdown link to a platform page."""
    return f"[{display}]({prefix}platforms/{name}.md)"

def emulator_link(name: str, prefix: str = "") -> str:
    """Generate a markdown link to an emulator page."""
    return f"[{name}]({prefix}emulators/{name}.md)"

def percent_text(n: int, total: int) -> str:
    if total == 0:
        return "0%"
    return f"{n / total * 100:.1f}%"

def by_mode(value: str | dict, mode: str) -> str:
    """Read a profile field that may be keyed by build mode."""
    if isinstance(value, dict):
        return str(value.get(mode) or "") if mode else ""
    return str(value or "")


# A system id that names a family of arcade boards -> the board its link
# leads to. RetroArch's sega-dreamcast-arcade lists the NAOMI, NAOMI 2 and
# Atomiswave BIOS: the NAOMI page comes first, the Dreamcast section links
# the others.
BOARD_PARENTS: dict[str, str] = {
    "sega-dreamcast-arcade": "sega-naomi",
}


def system_ids(profiles: dict[str, dict], platforms: list[dict]) -> set[str]:
    """Every system id a page can name: the platforms' and the profiles'."""
    ids = {str(sys_id) for config in platforms for sys_id in config.get("systems", {})}
    for profile in profiles.values():
        ids.update(str(sys_id) for sys_id in profile.get("systems") or [])
        for entry in profile.get("files") or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("system"):
                ids.add(str(entry["system"]))
            ids.update(str(sys_id) for sys_id in entry.get("systems") or [])
    return ids


def link_coverage(ids: set[str]) -> tuple[int, int]:
    """How many of ``ids`` lead to a section, and how many there are."""
    return sum(1 for sys_id in ids if system_section(sys_id)), len(ids)


# A system id -> the names the platforms' own files give it, built once.
_search_aliases: dict[str, list[str]] = {}
_search_aliases_built = [False]
# A native name as a person types it: no space, no comma. RetroArch's
# native names are No-Intro titles ("Sony - PlayStation") and stay out.
_ALIAS_SHAPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]*")


def system_search_aliases(sys_id: str) -> list[str]:
    """The native system ids the platform YAMLs file ``sys_id`` under
    (psx, dreamcast, gba), sorted, for search. Read from each platform's
    own entries by common.platform_system_names, never typed by hand."""
    if not _search_aliases_built[0]:
        from model.registry import list_registered_platforms
        from model.platforms import load_platform_config
        from model.systems import platform_system_names

        platforms_dir = str(siteinputs.current().platforms)
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
        _search_aliases.clear()
        for owner, names in index.items():
            spellings: dict[str, str] = {}
            for name in sorted(names, key=lambda n: (n != n.lower(), n)):
                spellings.setdefault(name.casefold(), name)
            if spellings:
                _search_aliases[owner] = sorted(spellings.values(), key=str.casefold)
        _search_aliases_built[0] = True
    return list(_search_aliases.get(str(sys_id), []))
