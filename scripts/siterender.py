"""Small renderings shared by every page."""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Callable
from pathlib import Path

import siteinputs
import sitemarkup as markup


WIKI_SRC_DIR = "wiki"  # manually maintained wiki sources
SYSTEM_ICON_BASE = "https://raw.githubusercontent.com/libretro/retroarch-assets/master/xmb/systematic/png"
# Local copies of the upstream icons, named as upstream names them.
ICON_DIR = Path(__file__).resolve().parent.parent / "docs_assets" / "system-icons"

# Icon names the site holds a copy of. A name mapped to False has none.
_icon_available: dict[str, bool] = {}

_CODE_SPAN = re.compile(r"(`+).+?\1", re.S)


def _code(value: object) -> str:
    """A value as an inline code span it cannot leave.

    Markdown shows HTML inside a code span as text, so the one way out is a
    backtick in the value closing the span early. Data from a profile, a
    platform file or a file name is not ours to trust that far.
    """
    return "`" + str(value).replace("`", "'") + "`"


def _count(number: int, noun: str, plural: str = "") -> str:
    """A count and its noun, singular for one: the site printed "1 files" 234 times."""
    return f"{number:,} {noun if number == 1 else plural or noun + 's'}"


def _escape_tags(text: str) -> str:
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


def _admonition_body(text: str) -> str:
    """Indent prose without turning source tokens such as ``#if`` into H1s."""
    escaped = re.sub(r"(?m)^(\s*)#", r"\1\\#", _escape_tags(text))
    return escaped.replace("\n", "\n    ")

def _icon_name(manufacturer: str, console_name: str) -> str:
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

    The link names the upstream file: ``sitediagrams.localize_images``
    points it at the local copy, whose source is recorded beside it.
    """
    name = _icon_name(manufacturer, console_name)
    if not _icon_available.get(name):
        return ""
    return markup.image(console_name, _icon_url(name), width="24") + " "

# Global index: maps system_id -> (manufacturer_slug, console_name) for cross-linking
_system_page_map: dict[str, tuple[str, str]] = {}

def _slugify_anchor(text: str) -> str:
    """Slugify text for MkDocs anchor compatibility."""
    import re

    slug = text.lower()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s]+", "-", slug)
    slug = slug.strip("-")
    return slug

_norm_page_map: dict[str, tuple[str, str] | None] = {}


def set_system_page_map(mapping: dict[str, tuple[str, str]]) -> None:
    """Install the system id -> page table every link on the site reads.

    The table replaces the previous one, and the index of other spellings is
    derived from it here. Kept anywhere else, it outlived a table of the same
    size and linked to the pages of the previous one.
    """
    from common import _norm_system_id

    _system_page_map.clear()
    _system_page_map.update(mapping)
    _norm_page_map.clear()
    for known, page in _system_page_map.items():
        key = _norm_system_id(known)
        if _norm_page_map.get(key, page) != page:
            _norm_page_map[key] = None
        else:
            _norm_page_map[key] = page


def _page_by_norm(sys_id: str) -> tuple[str, str] | None:
    """The page an id leads to under another spelling of the same system.

    Emulator cards name sega-megadrive or sinclair-zxspectrum, the pages are
    keyed by the platforms' spellings: 2,431 of 4,195 cards had no link. A
    spelling two pages share leads nowhere rather than to either.
    """
    from common import _norm_system_id

    return _norm_page_map.get(_norm_system_id(sys_id))


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


# (manufacturer slug, console) -> the id of the console's heading. Two
# folders spelled alike (Sega's "Mega CD" and "Mega-CD") share a slug, and
# the second heading took "mega-cd_1" while every link said "mega-cd".
_console_anchors: dict[tuple[str, str], str] = {}


def _manufacturer_slug(manufacturer: str) -> str:
    return manufacturer.lower().replace(" ", "-")


def console_anchor(manufacturer: str, console: str) -> str:
    """The id of a console's heading on its manufacturer's page."""
    from sitestarlight import toc_slug

    key = (_manufacturer_slug(manufacturer), console)
    return _console_anchors.get(key) or toc_slug(console)


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


# (manufacturer slug, folder, sha1) -> the (manufacturer slug, console) a
# copy's card went to when the system pages file it outside its folder:
# ScummVM's engine data under Other/ScummVM, neogeo.zip under Arcade.
_card_moves: dict[tuple[str, str, str], tuple[str, str]] = {}


def record_card_move(manufacturer: str, folder: str, sha1: str,
                     to_manufacturer: str, to_console: str) -> None:
    """Mark that the card of the copy under bios/<manufacturer>/<folder>/
    sits in the section (to_manufacturer, to_console)."""
    _card_moves[(_manufacturer_slug(manufacturer), folder, str(sha1))] = (
        _manufacturer_slug(to_manufacturer), to_console)


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
    slug, console = _card_moves.get((slug, console, str(sha1)), (slug, console))
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
    section = _section_without_boards(sys_id)
    if (not _board_sections or sys_id in SYSTEM_PARENTS
            or (section is not None and section[0] != "arcade")):
        return section
    board = _board_of_id(sys_id)
    if board in _board_sections:
        return "arcade", system_name(board)
    return section


def _section_without_boards(sys_id: str) -> tuple[str, str] | None:
    """system_section before arcade boards: what the folders and the
    reviewed parents give."""
    own = _own_section(sys_id)
    if own is not None:
        return _manufacturer_slug(own[0]), own[1]
    parent = SYSTEM_PARENTS.get(sys_id)
    if parent is not None and parent in _section_pairs:
        return _manufacturer_slug(parent[0]), parent[1]
    try:
        name = system_name(sys_id)
    except KeyError:
        return None
    places = _sections_by_name.get(name.casefold(), set())
    if len(places) != 1:
        return None
    mfr, console = next(iter(places))
    if mfr in _NAMELESS_TOPS or (
        mfr in _PROGRAM_TOPS and console.casefold() in _program_names
    ):
        return None
    return _manufacturer_slug(mfr), console


def _system_link(sys_id: str, prefix: str = "") -> str:
    """A system id linked to the section named after it, or the bare id."""
    section = system_section(sys_id)
    if section:
        slug, console = section
        return f"[{sys_id}]({console_href(slug, console, prefix)})"
    return sys_id


# Arcade boards. A board is a system id that a profile entry with
# ``category: bios_zip`` names, through its ``system:``/``systems:`` or the
# profile's single system, whose archive the collection holds, and that has
# no section under a machine's maker. The archive is found by its name and,
# where the entry lists ``contents:``, kept only when it holds one of those
# CRC32s: maclc3.zip names a MAME set and an unrelated 189 MB file. The
# folder a copy sits in decides nothing.
_arcade_source: list[tuple[dict, dict] | None] = [None]
# sha1 -> the board id the archive is the BIOS of.
_archive_boards: dict[str, str] = {}
# Casefolded board name -> the board id that stands for it.
_board_names: dict[str, str] = {}
# sha1 -> the (manufacturer, console) sections of the machines whose own
# set the archive is: neogeo.zip for the Neo Geo, mz2000.zip for the MZ.
_archive_machines: dict[str, set[tuple[str, str]]] = {}
_boards_built = [False]


def set_arcade_boards(profiles: dict[str, dict], db: dict) -> None:
    """Install the profiles and database the arcade boards are read from.
    Without it they are read from the repository on first use."""
    _arcade_source[0] = (profiles, db)
    _boards_built[0] = False


def _owner_ids(entry: dict, systems: list[str]) -> set[str]:
    """The system ids a profile entry is declared for."""
    owners = {str(entry["system"])} if entry.get("system") else set()
    owners.update(str(sys_id) for sys_id in entry.get("systems") or [])
    if not owners and len(systems) == 1:
        owners = set(systems)
    return owners


# _board_role for an id whose archive is its machine's: a section under the
# machine's maker, or a reviewed parent outside Arcade.
_MACHINE = "\0machine"


def _board_role(sys_id: str) -> str | None:
    """A board's name, _MACHINE for an id that names a machine with a
    section of its own, None for an id that names neither (the generic
    arcade id, an id with no name)."""
    parent = SYSTEM_PARENTS.get(sys_id)
    if parent is not None:
        return None if parent[0] == "Arcade" else _MACHINE
    section = _section_without_boards(sys_id)
    if section is not None and section[0] != "arcade":
        return _MACHINE
    try:
        return system_name(sys_id)
    except KeyError:
        return None


def _in_arcade(sha1: str, db: dict) -> bool:
    """Whether a copy of the content sits under bios/Arcade/."""
    entry = db.get("files", {}).get(sha1) or {}
    if str(entry.get("path", "")).startswith("bios/Arcade/"):
        return True
    return sha1 in _arcade_suffix_sha1s(db)


_suffix_cache: list[tuple[dict, frozenset[str]] | None] = [None]


def _arcade_suffix_sha1s(db: dict) -> frozenset[str]:
    # Holding the database itself, never id(db): a database freed and
    # replaced at the same address answered with the first one's set.
    cached = _suffix_cache[0]
    if cached is not None and cached[0] is db:
        return cached[1]
    found = frozenset(
        sha1s[0]
        for tail, sha1s in db.get("indexes", {}).get("by_path_suffix", {}).items()
        if tail.startswith("Arcade/") and len(sha1s) == 1
    )
    _suffix_cache[0] = (db, found)
    return found


def _build_boards() -> None:
    if _boards_built[0]:
        return
    from ziptools import zip_member_crcs

    _ensure_console_sections()
    if _arcade_source[0] is None:
        import json

        from common import load_emulator_profiles

        inputs = siteinputs.current()
        database = inputs.db
        if not database.exists():
            _archive_boards.clear()
            _board_names.clear()
            _boards_built[0] = True
            return
        with open(database, encoding="utf-8") as handle:
            db = json.load(handle)
        profiles = load_emulator_profiles(str(inputs.emulators), skip_aliases=False)
        _arcade_source[0] = (profiles, db)
    profiles, db = _arcade_source[0]
    files = db.get("files", {})
    by_name = db.get("indexes", {}).get("by_name", {})

    # sha1 -> board name -> the profiles naming it. None: a machine's own.
    votes: dict[str, dict[str, set[str]] | None] = {}
    _archive_machines.clear()
    ids_by_name: dict[str, set[str]] = {}
    for key in sorted(profiles):
        profile = profiles[key]
        if profile.get("role") == "test":
            continue
        systems = [str(sys_id) for sys_id in profile.get("systems") or []]
        for entry in profile.get("files") or []:
            if not isinstance(entry, dict) or entry.get("category") != "bios_zip":
                continue
            owners = _owner_ids(entry, systems)
            if not owners:
                continue
            crcs = {
                str(member["crc32"]).lower()
                for member in entry.get("contents") or []
                if isinstance(member, dict) and member.get("crc32")
            }
            names = {str(entry.get("name", ""))}
            names.update(str(alias) for alias in entry.get("aliases") or [])
            archives: set[str] = set()
            for name in names:
                found = by_name.get(name.rsplit("/", 1)[-1]) or []
                for sha1 in [found] if isinstance(found, str) else found:
                    if sha1 not in files:
                        continue
                    if crcs:
                        held = zip_member_crcs(str(_REPO_ROOT / files[sha1]["path"]))
                        # An archive the build cannot read keeps its name.
                        if held and not held & crcs:
                            continue
                    archives.add(sha1)
            for owner in owners:
                role = _board_role(owner)
                if role == _MACHINE:
                    # The profile's only system stands for an entry that names
                    # none: MAME's printer and expansion sets in a Dragon
                    # profile. Only an entry naming the machine moves its set,
                    # and only when every machine it names has that section:
                    # epson_fx80.zip, which sixteen machines load, has none.
                    declared = entry.get("system") or entry.get("systems")
                    places = {_machine_section(o) for o in owners
                              if _board_role(o) == _MACHINE} if declared else {None}
                    section = next(iter(places)) if len(places) == 1 else None
                    for sha1 in archives:
                        votes[sha1] = None
                        _archive_machines.setdefault(sha1, set()).add(section)
                    continue
                if role is None:
                    continue
                ids_by_name.setdefault(role.casefold(), set()).add(owner)
                for sha1 in archives:
                    ballot = votes.setdefault(sha1, {})
                    if ballot is not None:
                        ballot.setdefault(role.casefold(), set()).add(key)

    _archive_boards.clear()
    _board_names.clear()
    for sha1, ballot in votes.items():
        if not ballot:
            continue
        ranked = sorted(ballot.items(), key=lambda item: (-len(item[1]), item[0]))
        # Two boards named as often: a device ROM several boards share.
        if len(ranked) > 1 and len(ranked[0][1]) == len(ranked[1][1]):
            continue
        name = ranked[0][0]
        board = sorted(ids_by_name[name])[0]
        _archive_boards[sha1] = board
        if _in_arcade(sha1, db):
            _board_names[name] = board
    # A board none of whose archives sits under Arcade has no section there.
    for sha1, board in list(_archive_boards.items()):
        if system_name(board).casefold() not in _board_names:
            del _archive_boards[sha1]
    _boards_built[0] = True


def _machine_section(sys_id: str) -> tuple[str, str] | None:
    """The (manufacturer, console) section SYSTEM_PARENTS files a machine
    id under, outside Arcade. Only a reviewed parent moves an archive out
    of the folder holding it: an id with a section of its own keeps its
    archives where the collection files them."""
    parent = SYSTEM_PARENTS.get(sys_id)
    if parent is None or parent[0] == "Arcade" or parent not in _section_pairs:
        return None
    return parent


def archive_machine(sha1: str) -> tuple[str, str] | None:
    """The (manufacturer, console) section of the machine an archive is
    the set of, when a profile declares it for one machine only: the Neo
    Geo's neogeo.zip, the MZ-2000's mz2000.zip. Read from the same
    ``category: bios_zip`` entries as arcade_board(), never the folder."""
    _build_boards()
    places = _archive_machines.get(str(sha1), set())
    return next(iter(places)) if len(places) == 1 else None


def _board_ids_by_name() -> dict[str, str]:
    _build_boards()
    return _board_names


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
    _build_boards()
    return _archive_boards.get(str(sha1))


def board_slug(sys_id: str) -> str:
    """The slug of a board's section: its page is systems/arcade-<slug>/
    and its heading's id is <slug>. Read from the board's display name,
    so every id of one board gives one slug."""
    from sitestarlight import toc_slug

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
    _build_boards()
    return {board: system_name(board) for board in sorted(set(_board_names.values()))}


def _field_text(key: object, value: object) -> str:
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


def _render_yaml_value(
    lines: list[str], val: object, indent: int = 4,
    field_text: FieldText = _field_text,
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
                _render_yaml_value(lines, v, indent + 4, field_text)
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
                    _render_yaml_value(lines, nested, indent + 4, field_text)
            else:
                lines.append(f"{pad}- {field_text(None, item)}")
        lines.append("")
    elif isinstance(val, str) and "\n" in val:
        for line in val.split("\n"):
            lines.append(f"{pad}{line}")
    else:
        lines.append(f"{pad}{field_text(None, val)}")


def _platform_link(name: str, display: str, prefix: str = "") -> str:
    """Generate a markdown link to a platform page."""
    return f"[{display}]({prefix}platforms/{name}.md)"

def _emulator_link(name: str, prefix: str = "") -> str:
    """Generate a markdown link to an emulator page."""
    return f"[{name}]({prefix}emulators/{name}.md)"

def _fmt_size(size: int) -> str:
    if size >= 1024 * 1024 * 1024:
        return f"{size / (1024**3):.1f} GB"
    if size >= 1024 * 1024:
        return f"{size / (1024**2):.1f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"

def _pct(n: int, total: int) -> str:
    if total == 0:
        return "0%"
    return f"{n / total * 100:.1f}%"

def _by_mode(value: str | dict, mode: str) -> str:
    """Read a profile field that may be keyed by build mode."""
    if isinstance(value, dict):
        return str(value.get(mode) or "") if mode else ""
    return str(value or "")


# System display names. A system is named by the heading of the console
# section that is its own: the folder its id spells, under the maker the id
# names when two makers file a console of that name. The page a system's
# files were voted onto is not its section and never names it. That vote
# called nintendo-gba "Nintendo Game Boy" and camplynx "Arcade". A system
# with no section of its own is named in SYSTEM_NAMES, and a system in
# neither stops the build.

# Folders that file copies by the emulator or board that loads them. Their
# headings name a program, not a system.
_PROGRAM_TOPS = frozenset({"Other", "Arcade"})
# Of those, the top whose headings never name a system, even read whole.
# An Arcade heading can (Namco System 246), an Other one cannot.
_NAMELESS_TOPS = frozenset({"Other"})

# A section whose folder is a short name the code reads, headed with the
# program's name instead (bios/Arcade/fba2012 holds FB Alpha 2012's samples).
SECTION_LABELS: dict[tuple[str, str], str] = {
    ("Arcade", "fba2012"): "FB Alpha 2012",
}

# Every (manufacturer, console) section the system pages carry.
_section_pairs: set[tuple[str, str]] = set()
# Normalized id -> the console sections spelled that way.
_console_sections: dict[str, set[tuple[str, str]]] = {}
# A console section by the name its heading reads (Bandai WonderSwan).
_sections_by_name: dict[str, set[tuple[str, str]]] = {}
# Emulator and engine names. A heading spelled like one (Game Engines >
# Solarus, ZC > ZC210) files that program's copies and names no system.
_program_names: set[str] = set()


def program_names(profiles: dict[str, dict]) -> set[str]:
    """Every name an emulator profile goes by: its key, its emulator and
    display names."""
    names = {str(key) for key in profiles}
    for profile in profiles.values():
        names.update(
            str(profile[field]) for field in ("emulator", "display_name")
            if profile.get(field)
        )
    return names


def set_console_sections(
    sections: dict[str, dict] | set[tuple[str, str]],
    programs: set[str] | frozenset[str] = frozenset(),
) -> None:
    """Install the console sections the system pages carry.

    ``sections`` maps each manufacturer to its consoles, as the system pages
    group them, or is a set of (manufacturer, console) pairs. ``programs``
    are the emulator names, which never name a system.
    """
    from common import _norm_system_id

    pairs = (
        {(mfr, console) for mfr, consoles in sections.items() for console in consoles}
        if isinstance(sections, dict) else set(sections)
    )
    # A reviewed parent under a maker the pages carry is a section even with
    # no folder of its own: the Atom's sets sit under bios/Arcade, and the
    # system pages file them under Acorn (generate_site.arcade_board_sections).
    makers = {mfr for mfr, _console in pairs}
    pairs |= {parent for parent in SYSTEM_PARENTS.values()
              if parent[0] in makers and parent[0] not in _PROGRAM_TOPS}
    from sitestarlight import _unique, toc_slug

    _console_sections.clear()
    _sections_by_name.clear()
    _console_anchors.clear()
    _section_pairs.clear()
    _section_pairs.update(pairs)
    by_maker: dict[str, list[str]] = {}
    for mfr, console in pairs:
        by_maker.setdefault(mfr, []).append(console)
        for name in {_heading_name(mfr, console).casefold(), console.casefold()}:
            _sections_by_name.setdefault(name, set()).add((mfr, console))
    # In the order the page lists them, after the page title's own id.
    for mfr, consoles in by_maker.items():
        used = {toc_slug(mfr)}
        for console in sorted(consoles):
            _console_anchors[(_manufacturer_slug(mfr), console)] = _unique(toc_slug(console), used)
    for mfr, console in pairs:
        spelled = console.lower().replace(" ", "-")
        slug = mfr.lower().replace(" ", "-")
        for key in {_norm_system_id(f"{slug}-{spelled}"), _norm_system_id(spelled)}:
            _console_sections.setdefault(key, set()).add((mfr, console))
    _program_names.clear()
    _program_names.update(name.casefold() for name in programs)
    _sections_installed[0] = True
    # Which ids are boards depends on which have a section elsewhere.
    _boards_built[0] = False


_sections_installed = [False]
_REPO_ROOT = Path(__file__).resolve().parent.parent


def _ensure_console_sections() -> None:
    """Read the sections from the repository when no generator installed
    them, so a page rendered on its own names systems as the site does."""
    if _sections_installed[0]:
        return
    import json

    from common import load_emulator_profiles
    from sitecollection import _group_by_manufacturer

    inputs = siteinputs.current()
    with open(inputs.db, encoding="utf-8") as handle:
        db = json.load(handle)
    profiles = load_emulator_profiles(str(inputs.emulators), skip_aliases=False)
    set_console_sections(_group_by_manufacturer(db), program_names(profiles))


def _own_section(sys_id: str) -> tuple[str, str] | None:
    """The console section that is this id's own, or None.

    Of two sections spelled alike (Atari and Camputers both file a Lynx),
    the one under the maker the id names is kept. Two left is no answer,
    and neither is a section that files a program's copies.
    """
    from common import _norm_system_id

    _ensure_console_sections()
    places = _console_sections.get(_norm_system_id(sys_id), set())
    if len(places) > 1:
        places = {
            (mfr, console) for mfr, console in places
            if sys_id.lower().startswith(mfr.lower().replace(" ", "-") + "-")
        }
    if len(places) != 1:
        return None
    mfr, console = next(iter(places))
    # A folder under a program's top, named like its own page (Dinothawr) or
    # like an emulator holds a program's files, not a system's.
    if (
        mfr in _PROGRAM_TOPS
        or console.casefold() == mfr.casefold()
        or _heading_name(mfr, console).casefold() in _program_names
    ):
        return None
    return mfr, console


def _heading_name(mfr: str, console: str) -> str:
    """A console heading read out of its page: the maker in front, unless
    the heading already starts with it or the page is a game publisher's."""
    from common import GAME_DATA_TOPS

    if mfr in GAME_DATA_TOPS:
        return SECTION_LABELS.get((mfr, console), console)
    if console.casefold().startswith(mfr.split()[0].casefold()):
        return console
    return f"{mfr} {console}"


def system_name(sys_id: str) -> str:
    """The display name of a system id, the only one a page prints."""
    sys_id = str(sys_id)
    section = _own_section(sys_id)
    if section is not None:
        return _heading_name(*section)
    name = SYSTEM_NAMES.get(sys_id)
    if name is None:
        raise KeyError(
            f"system {sys_id!r} has no console section of its own and no "
            "entry in siterender.SYSTEM_NAMES"
        )
    return name


# Systems without a console section of their own.
SYSTEM_NAMES: dict[str, str] = {
    "2ship": "The Legend of Zelda: Majora's Mask",
    "aarch64": "ARM 64-bit (AArch64)",
    "acclaim-zn1": "Acclaim ZN-1",
    "adrift": "ADRIFT",
    "advsys": "AdvSys",
    "ags": "Adventure Game Studio games",
    "agt": "Adventure Game Toolkit",
    "alan": "Alan",
    "alg-laserdisc": "American Laser Games laserdisc",
    "allied-leisure-pinball": "Allied Leisure pinball",
    "alpha": "DEC Alpha",
    "andamiro-pumpitup": "Andamiro Pump It Up",
    "apf-m1000": "APF M-1000",
    "apfm1000": "APF M-1000",
    "apple-iie": "Apple IIe",
    "apple-ios": "Apple iOS",
    "apple2": "Apple II",
    "arcade": "Arcade games",
    "arcade-laserdisc": "Laserdisc arcade games",
    "arcadia-systems": "Arcadia Systems Multi Select",
    "arduboy": "Arduboy",
    "aristocrat-mk5": "Aristocrat MK5",
    "aristocrat-mk6": "Aristocrat MK6",
    "aristocrat-mk7": "Aristocrat MK7",
    "arm": "ARM",
    "atari-falcon": "Atari Falcon",
    "atari-jaguarcd": "Atari Jaguar CD",
    "atari-ste": "Atari STE",
    "atari-system1": "Atari System 1",
    "atari-tt": "Atari TT",
    "atari-zn1": "Atari ZN-1",
    "atlus-zn1": "Atlus ZN-1",
    "bandai-playdia": "Bandai Playdia",
    "bandai-wswan": "Bandai WonderSwan",
    "bandai-wswanc": "Bandai WonderSwan Color",
    "barcrest-mpu4": "Barcrest MPU4",
    "bbc-master-128": "Acorn BBC Master 128",
    "bbc-master-compact": "Acorn BBC Master Compact",
    "bbc-master-et": "Acorn BBC Master ET",
    "bbc-micro-b": "Acorn BBC Micro Model B",
    "bbc-micro-bplus": "Acorn BBC Micro Model B+",
    "bbk-longman-4980": "BBK Longman A4980",
    "bbk-longman-4988": "BBK Longman A4988",
    "bennugd": "BennuGD games",
    "bermuda-syndrome": "Bermuda Syndrome game",
    "brezzasoft-crystal": "BrezzaSoft Crystal System",
    "bshift": "Half-Life: Blue Shift",
    "caesar3": "Caesar III",
    "cambridge-z88": "Cambridge Computer Z88",
    "camplynx": "Camputers Lynx",
    "capcom-cps1": "Capcom CPS-1",
    "capcom-cps2": "Capcom CPS-2",
    "capcom-cps3": "Capcom CPS-3",
    "capcom-zn1": "Capcom ZN-1",
    "capcom-zn2": "Capcom ZN-2",
    "casio-pv1000": "Casio PV-1000",
    "catacomb-3d": "Catacomb 3-D",
    "catacomb-adventure": "Catacomb Adventure Series",
    "cave-cv1000": "Cave CV1000",
    "cave-story": "Cave Story",
    "cavestory": "Cave Story",
    "celeste-classic": "Celeste Classic",
    "century-cvs": "Century CVS",
    "ces-galaxy-games": "CES Galaxy Games",
    "cgenie": "EACA Colour Genie",
    "chex": "Chex Quest",
    "chip8": "CHIP-8",
    "coco3": "Tandy Color Computer 3",
    "commanderx16": "Commander X16",
    "commodore-c64-supercpu": "Commodore 64 with SuperCPU",
    "commodore-cd32": "Commodore Amiga CD32",
    "commodore-cdtv": "Commodore CDTV",
    "commodore-cubo": "CD Express Cubo CD32",
    "coolbar": "Coolbar feature phones",
    "cstrike": "Counter-Strike",
    "ctf": "Quake II: Capture the Flag",
    "czero": "Counter-Strike: Condition Zero",
    "czeror": "Counter-Strike: Condition Zero Deleted Scenes",
    "dark-forces": "Star Wars: Dark Forces",
    "dark-forces-ii": "Star Wars Jedi Knight: Dark Forces II",
    "deco-cassette": "Data East DECO Cassette System",
    "descent2": "Descent II",
    "dingoo-a320": "Dingoo A320",
    "dinothawr": "Dinothawr game",
    "discrete-arcade": "Discrete logic arcade games",
    "dmc": "Deathmatch Classic",
    "doom3-bfg": "Doom 3: BFG Edition",
    "dos": "MS-DOS",
    "dragon32": "Dragon 32",
    "dragon64": "Dragon 64",
    "droidworks": "Star Wars: DroidWorks",
    "duke-nukem-2": "Duke Nukem II",
    "duke3d": "Duke Nukem 3D",
    "dusklight": "The Legend of Zelda: Twilight Princess",
    "efo-cedar-magnet": "EFO Cedar Magnet System",
    "eighting-zn1": "Eighting ZN-1",
    "elektor-tv-games-computer": "Elektor TV Games Computer",
    "emerson-arcadia-2001": "Emerson Arcadia 2001",
    "enemy-territory-quake-wars": "Enemy Territory: Quake Wars",
    "enemyterritory": "Wolfenstein: Enemy Territory",
    "enterprise-128": "Enterprise 128",
    "enterprise-64": "Enterprise 64",
    "entex-advision": "Entex Adventure Vision",
    "epoch-scv": "Epoch Super Cassette Vision",
    "epochcv": "Epoch Cassette Vision",
    "eternal-computer": "Eternal Software Initiative computer",
    "exelvision-exl100": "Exelvision EXL 100",
    "exhumed": "PowerSlave",
    "exidy-maxaflex": "Exidy Max-A-Flex",
    "fallout": "Fallout",
    "famicom": "Nintendo Famicom",
    "flash": "Adobe Flash",
    "flashback": "Flashback",
    "fm77av": "Fujitsu FM77AV",
    "fpinball": "Future Pinball tables",
    "fruitmachine": "Fruit machines",
    "fury": "Ion Fury game",
    "gaelco-powervr": "Gaelco PowerVR boards",
    "galaksija": "Galaksija computer",
    "game": "Picross puzzle (libretro sample)",
    "gamecom": "Tiger Game.com",
    "gamemaker": "GameMaker games",
    "gameplan-mpu1": "Game Plan MPU-1",
    "gamepock": "Epoch Game Pocket Computer",
    "gametank": "GameTank console",
    "gearbox": "Half-Life: Opposing Force",
    "ghostship": "Super Mario 64",
    "glulx": "Glulx",
    "gottlieb-system1": "Gottlieb System 1",
    "half-life-2": "Half-Life 2",
    "handheld-electronic": "Nintendo Game & Watch",
    "heart-of-darkness": "Heart of Darkness",
    "heretic": "Heretic",
    "heroes-of-might-and-magic-2": "Heroes of Might and Magic II",
    "hexen": "Hexen",
    "hexen2": "Hexen II",
    "hppa": "HP PA-RISC",
    "hugo": "Hugo",
    "hyper-neogeo64": "SNK Hyper Neo Geo 64",
    "ibm-at": "IBM PC/AT",
    "ibm-pcjr": "IBM PCjr",
    "ibm-ps1": "IBM PS/1",
    "ibm-xt": "IBM PC XT",
    "icarus-starship-command-simulator": "Icarus Starship Command Simulator",
    "igs-pgm": "IGS PolyGame Master",
    "imax-macs": "I'Max MACS",
    "interact": "Interact Home Computer",
    "interton-vc4000": "Interton VC 4000",
    "itech-eagle": "Incredible Technologies Eagle",
    "jacl": "JACL",
    "jedi-academy": "Star Wars Jedi Knight: Jedi Academy",
    "jedi-outcast": "Star Wars Jedi Knight II: Jedi Outcast",
    "jediacademy": "Star Wars Jedi Knight: Jedi Academy",
    "jediknight2": "Star Wars Jedi Knight II: Jedi Outcast",
    "jupiter-ace": "Jupiter Cantab Jupiter Ace",
    "konami-bubble-system": "Konami Bubble System",
    "konami-bubblesystem": "Konami Bubble System",
    "konami-bubsys": "Konami Bubble System",
    "konami-endeavour": "Konami Endeavour",
    "konami-gq": "Konami GQ",
    "konami-gv": "Konami GV",
    "konami-gx": "Konami GX",
    "konami-python": "Konami Python",
    "konami-python2": "Konami Python 2",
    "konami-twinkle": "Konami Twinkle",
    "konami-viper": "Konami Viper",
    "lambda-8300": "Lambda 8300",
    "laserdisc-arcade": "Laserdisc arcade games",
    "level9": "Level 9",
    "lowresnx": "LowRes NX programs",
    "lynx": "Atari Lynx",
    "m68k": "Motorola 68000",
    "magnetic-scrolls": "Magnetic Scrolls",
    "marty": "Fujitsu FM Towns Marty",
    "mega-cd-32x": "Sega Mega-CD 32X",
    "mega-duck": "Welback Mega Duck",
    "mega-ld": "Sega Mega LD",
    "microdigital-tk85": "Microdigital TK85",
    "microsoft-msx2": "MSX2",
    "midway-mcr": "Midway MCR",
    "mips": "MIPS",
    "mips64": "MIPS64",
    "miuchiz": "Miuchiz",
    "mohaa": "Medal of Honor: Allied Assault",
    "mohaa-breakthrough": "Medal of Honor: Allied Assault Breakthrough",
    "mohaa-spearhead": "Medal of Honor: Allied Assault Spearhead",
    "msx1": "MSX",
    "msx2": "MSX2",
    "msx2+": "MSX2+",
    "msx2plus": "MSX2+",
    "msxturboR": "MSX turbo R",
    "msxturbor": "MSX turbo R",
    "mysteries-of-the-sith": "Star Wars Jedi Knight: Mysteries of the Sith",
    "myvision": "Nichibutsu My Vision",
    "mz2000": "Sharp MZ-2000",
    "mz2500": "Sharp MZ-2500",
    "mz700": "Sharp MZ-700",
    "mz800": "Sharp MZ-800",
    "mz80k": "Sharp MZ-80K",
    "nam": "NAM",
    "namco-na1": "Namco NA-1",
    "namco-nb1": "Namco NB-1",
    "namco-system11": "Namco System 11",
    "namco-system246": "Namco System 246",
    "namco-system256": "Namco System 256",
    "namco-system357": "Namco System 357",
    "namco-system573": "Konami System 573",
    "naomi2": "Sega NAOMI 2",
    "napalm": "NAPALM",
    "nec-pc-80": "NEC PC-8001",
    "nec-supergrafx": "NEC SuperGrafx",
    "neo-geo-pocket-color": "SNK Neo Geo Pocket Color",
    "neogeo64": "SNK Hyper Neo Geo 64",
    "ngp": "SNK Neo Geo Pocket",
    "ngpc": "SNK Neo Geo Pocket Color",
    "nichibutsu-hrdvd": "Nichibutsu High Rate DVD",
    "nintendo-aleck64": "Nintendo Aleck64",
    "nintendo-fds": "Nintendo Famicom Disk System",
    "nintendo-gb": "Nintendo Game Boy",
    "nintendo-gba": "Nintendo Game Boy Advance",
    "nintendo-gbc": "Nintendo Game Boy Color",
    "nintendo-nss": "Nintendo Super System",
    "nintendo-playch10": "Nintendo PlayChoice-10",
    "nintendo-sfcbox": "Nintendo Super Famicom Box",
    "nintendo-virtualboy": "Nintendo Virtual Boy",
    "nintendo-wii-arcade": "Nintendo Wii arcade boards",
    "nmk16": "NMK16",
    "oberon": "Project Oberon",
    "olivetti-pc128": "Olivetti Prodest PC 128",
    "omicron": "Omicron cartridges",
    "onscripter": "ONScripter visual novels",
    "openbor": "OpenBOR games",
    "opengoal": "Jak and Daxter",
    "oricatmos": "Oric Atmos",
    "outlaws": "Outlaws",
    "palm-os": "Palm OS",
    "pc-engine-ld": "NEC PC Engine LD-ROM2",
    "pc60": "NEC PC-6001",
    "pc80": "NEC PC-8001",
    "pce-tourvision": "TourVision",
    "pdark": "Perfect Dark",
    "pegasus": "Aamber Pegasus",
    "philips-p2000t": "Philips P2000T",
    "philips-vg5k": "Philips VG 5000",
    "picocomputer-6502": "Picocomputer 6502 programs",
    "pocket-challenge-v2": "Benesse Pocket Challenge V2",
    "powerslave": "PowerSlave",
    "ppc": "PowerPC",
    "ppc64": "PowerPC 64-bit",
    "prey": "Prey",
    "prince-of-persia": "Prince of Persia",
    "ps4": "Sony PlayStation 4",
    "pv1000": "Casio PV-1000",
    "quadrilateral-cowboy": "Quadrilateral Cowboy",
    "quake2": "Quake II",
    "quake3": "Quake III Arena",
    "quake4": "Quake 4",
    "realrtcw": "Return to Castle Wolfenstein (RealRTCW)",
    "recel-system3": "Recel System III",
    "redneck": "Redneck Rampage",
    "ricochet": "Ricochet",
    "ringo-r470": "Ringo R470",
    "riscv": "RISC-V",
    "riscv32": "RISC-V 32-bit",
    "riscv64": "RISC-V 64-bit",
    "rogue": "Quake II: Ground Zero",
    "rott": "Rise of the Triad",
    "rpgmaker": "RPG Maker games",
    "s390x": "IBM z/Architecture (s390x)",
    "sam-coupe": "MGT SAM Coupe",
    "sammy-atomiswave": "Sammy Atomiswave",
    "sammy-medal": "Sammy medal games",
    "science-of-cambridge-mk14": "Science of Cambridge MK14",
    "scott-adams": "Scott Adams adventures",
    "scott-adams-plus": "Scott Adams Plus adventures",
    "scummvm": "ScummVM games",
    "scv": "Epoch Super Cassette Vision",
    "sdlpal": "The Legend of Sword and Fairy",
    "sega-atomiswave": "Sammy Atomiswave",
    "sega-dreamcast-arcade": "Sega Dreamcast-based arcade boards",
    "sega-genesis": "Sega Genesis",
    "sega-isgsm": "Sega ISG Selection Master",
    "sega-megaplay": "Sega Mega Play",
    "sega-megatech": "Sega Mega-Tech",
    "sega-model1": "Sega Model 1",
    "sega-naomi": "Sega NAOMI",
    "sega-naomi2": "Sega NAOMI 2",
    "sega-naomigd": "Sega NAOMI GD-ROM",
    "sega-outrun": "OutRun",
    "sega-pico": "Sega Pico",
    "sega-sg1000": "Sega SG-1000",
    "sega-shootingzone": "Sega Shooting Zone",
    "sega-system-sp": "Sega System SP",
    "sega-system16b": "Sega System 16B",
    "sega-systemsp": "Sega System SP",
    "sega-vmu": "Sega Dreamcast VMU",
    "serious-sam": "Serious Sam",
    "sg-1000": "Sega SG-1000",
    "sielectronics-y2": "SiElectronics System Y2",
    "sinclair-ql": "Sinclair QL",
    "sinclair-spectrum": "Sinclair ZX Spectrum",
    "sinclair-zx-spectrum-next": "ZX Spectrum Next",
    "sinclair-zx80-81": "Sinclair ZX80 and ZX81",
    "skin-deep": "Skin Deep",
    "smbx": "Super Mario Bros. X",
    "sms": "Sega Master System",
    "snk-neogeo-aes": "SNK Neo Geo AES",
    "snk-neogeo-mvs": "SNK Neo Geo MVS",
    "snk-ngp": "SNK Neo Geo Pocket",
    "snk-ngpc": "SNK Neo Geo Pocket Color",
    "soh": "The Legend of Zelda: Ocarina of Time",
    "sonic-1-2013": "Sonic the Hedgehog (2013)",
    "sonic-2-2013": "Sonic the Hedgehog 2 (2013)",
    "sonic-mania": "Sonic Mania",
    "soniccd": "Sonic CD",
    "sony-psp": "Sony PlayStation Portable",
    "sparc": "SPARC",
    "sparc64": "SPARC64",
    "spectravideo": "Spectravideo",
    "star-control-2": "Star Control II",
    "starship": "Star Fox 64",
    "strife": "Strife",
    "sunplus-native32": "Sunplus Native32",
    "sunplus-spmp8000": "Sunplus SPMP8000",
    "super-famicom": "Nintendo Super Famicom",
    "super-kaneko-nova": "Kaneko Super Nova System",
    "super-mario-war": "Super Mario War game",
    "superacan": "Funtech Super A'Can",
    "supergrafx": "NEC SuperGrafx",
    "supergrafx-cd": "NEC SuperGrafx CD",
    "solarus": "Solarus games",
    "supertux": "SuperTux game",
    "supertuxkart": "SuperTuxKart game",
    "supracan": "Funtech Super A'Can",
    "symbian": "Symbian OS",
    "tab-silverball": "TAB Austria Silverball",
    "tads": "TADS",
    "taito-cchip": "Taito C-Chip",
    "taito-fx1": "Taito FX-1",
    "taito-gnet": "Taito G-NET",
    "taito-type-x": "Taito Type X",
    "taito-typezero": "Taito Type Zero",
    "tamagotchi-p1": "Bandai Tamagotchi P1",
    "tandy-1000": "Tandy 1000",
    "taylormade": "TaylorMade",
    "teamarena": "Quake III: Team Arena",
    "tecmo-tps": "Tecmo TPS",
    "tfc": "Team Fortress Classic",
    "the-dark-mod": "The Dark Mod",
    "thomson-mo6": "Thomson MO6",
    "thomson-to7": "Thomson TO7",
    "thomson-to770": "Thomson TO7/70",
    "thomson-to8": "Thomson TO8",
    "thomson-to8d": "Thomson TO8D",
    "thomson-to9": "Thomson TO9",
    "thomson-to9plus": "Thomson TO9+",
    "tic80": "TIC-80 cartridges",
    "tiger-game-com": "Tiger Game.com",
    "timex-tc2048": "Timex Computer 2048",
    "timex-ts1500": "Timex Sinclair 1500",
    "timex-ts2068": "Timex Sinclair 2068",
    "tomb-raider": "Tomb Raider",
    "tomb-raider-1": "Tomb Raider",
    "tomb-raider-2": "Tomb Raider II",
    "transport-tycoon-deluxe": "Transport Tycoon Deluxe",
    "tvgames": "Plug-and-play TV games",
    "tyrian": "Tyrian",
    "ur-quan-masters": "Star Control II",
    "urban-terror": "Urban Terror",
    "uzebox": "Uzebox",
    "vaporspec": "VaporSpec cartridges",
    "vc4000": "Interton VC 4000",
    "vg5k": "Philips VG 5000",
    "vgmplay": "Video game music files",
    "videobrain": "Umtech VideoBrain",
    "videosystem-zn1": "Video System ZN-1",
    "vircon32": "Vircon32 cartridges",
    "virtuality-su2000": "Virtuality SU2000",
    "vm-labs-nuon": "VM Labs Nuon",
    "vpinball": "Visual Pinball tables",
    "vtech-vsmile": "VTech V.Smile",
    "vvvvvv": "VVVVVV game",
    "watara-supervision": "Watara Supervision",
    "wonderswan-color": "Bandai WonderSwan Color",
    "ww2gi": "World War II GI",
    "x86": "x86 PC",
    "x86-64": "x86-64 PC",
    "xatrix": "Quake II: The Reckoning",
    "xrick": "Rick Dangerous",
    "ym2608": "Yamaha YM2608",
    "zc210": "Zelda Classic",
    "zeldaclassic": "Zelda Classic",
    "zn1-acclaim": "Acclaim ZN-1",
    "zn1-atlus": "Atlus ZN-1",
    "zn1-capcom": "Capcom ZN-1",
    # mame2003 files taitofx1.zip and tps.zip under these ids, its notes
    # name the boards: the Taito FX-1 and the Tecmo TPS, both ZN-1 based.
    "zn1-taito": "Taito FX-1",
    "zn1-tecmo": "Tecmo TPS",
    "zn1-video-system": "Video System ZN-1",
    "zn2-capcom": "Capcom ZN-2",
    "zx-spectrum-128": "Sinclair ZX Spectrum 128",
}


# A system id with no section of its own -> the (manufacturer, console)
# section holding its files: a model, a regional name or an add-on of the
# machine that section covers, or a game whose data that section files.
# Reviewed entry by entry against the files the profiles and platforms
# declare for the id, never decided by a vote of the folders those files
# sit in. A section that is not the machine stays out of this table even
# when it holds a copy: NAOMI's naomi2.zip filed with the Dreamcast, the
# PET's ROMs in VICE's tree under the C128, the Arcadia's under the Saturn.
SYSTEM_PARENTS: dict[str, tuple[str, str]] = {
    # Nintendo. The twin folders (DS and Nintendo DS, 64DD and Nintendo
    # 64DD) gave each name two headings and no link.
    "64dd": ("Nintendo", "Nintendo 64DD"),
    "nintendo-64dd": ("Nintendo", "Nintendo 64DD"),
    "nintendo-ds": ("Nintendo", "Nintendo DS"),
    "nintendo-dsi": ("Nintendo", "Nintendo DS"),
    "famicom": ("Nintendo", "NES"),
    "super-famicom": ("Nintendo", "SNES"),
    # Bandai: the Color boot ROMs, and those of Benesse's WonderSwan-based
    # Pocket Challenge V2, sit with the WonderSwan.
    "wonderswan-color": ("Bandai", "WonderSwan"),
    "bandai-wswanc": ("Bandai", "WonderSwan"),
    "pocket-challenge-v2": ("Bandai", "WonderSwan"),
    # SNK
    "ngpc": ("SNK", "Neo Geo Pocket"),
    "snk-ngpc": ("SNK", "Neo Geo Pocket"),
    "neo-geo-pocket-color": ("SNK", "Neo Geo Pocket"),
    "snk-neogeo-aes": ("SNK", "Neo Geo"),
    "snk-neogeo-mvs": ("SNK", "Neo Geo"),
    # Sega. The VMU is the Dreamcast's memory card, its images sit there.
    # Sega's arcade section holds the OutRun board ROMs Cannonball reads.
    "sega-genesis": ("Sega", "Mega Drive"),
    "mega-cd-32x": ("Sega", "Mega CD"),
    "sega-vmu": ("Sega", "Dreamcast"),
    "sega-outrun": ("Sega", "Arcade"),
    # NEC and Pioneer: both LaserActive packs (LD-ROM2 and Mega LD) file
    # their BIOS under the LaserActive.
    "nec-supergrafx": ("NEC", "PC Engine"),
    "supergrafx": ("NEC", "PC Engine"),
    "supergrafx-cd": ("NEC", "PC Engine CD"),
    "pc-engine-ld": ("Pioneer", "LaserActive"),
    "mega-ld": ("Pioneer", "LaserActive"),
    # Microsoft MSX generations
    "microsoft-msx2": ("Microsoft", "MSX"),
    "msx2": ("Microsoft", "MSX"),
    "msx2plus": ("Microsoft", "MSX"),
    "msx2+": ("Microsoft", "MSX"),
    "msxturboR": ("Microsoft", "MSX"),
    "msxturbor": ("Microsoft", "MSX"),
    # Sinclair: 128-0.rom and 128-1.rom, and Timex's tc2048.rom.
    "zx-spectrum-128": ("Sinclair", "ZX Spectrum"),
    "timex-tc2048": ("Sinclair", "ZX Spectrum"),
    # Acorn: os12.rom and basic2.rom for the Model B and B+, and the
    # Master Compact's bbcmc.zip.
    "bbc-micro-b": ("Acorn", "BBC Micro"),
    "bbc-micro-bplus": ("Acorn", "BBC Micro"),
    "bbc-master-compact": ("Acorn", "BBC Micro"),
    # Atari: falcon.img, ste.img and tt.img sit with the ST TOS images.
    "atari-ste": ("Atari", "ST"),
    "atari-tt": ("Atari", "ST"),
    "atari-falcon": ("Atari", "ST"),
    # Home computers filed under their family
    "apple-iie": ("Apple", "Apple II"),
    "apf-m1000": ("APF", "Imagination Machine"),
    "apfm1000": ("APF", "Imagination Machine"),
    "bbk-longman-4980": ("BBK", "A4980"),
    "bbk-longman-4988": ("BBK", "A4988"),
    "coco3": ("Tandy", "CoCo"),
    "commodore-cdtv": ("Commodore", "Amiga"),
    "dragon32": ("Dragon", "Dragon"),
    "dragon64": ("Dragon", "Dragon"),
    "enterprise-64": ("Enterprise", "64-128"),
    "enterprise-128": ("Enterprise", "64-128"),
    "fm77av": ("Fujitsu", "FM-7"),
    "gamepock": ("Epoch", "Game Pocket"),
    "ibm-pcjr": ("IBM", "PC"),
    "ibm-xt": ("IBM", "PC"),
    "marty": ("Fujitsu", "FM Towns"),
    "mz700": ("Sharp", "MZ"),
    "mz80k": ("Sharp", "MZ"),
    "mz800": ("Sharp", "MZ"),
    "oricatmos": ("Tangerine", "Oric"),
    "palm-os": ("Palm", "Palm"),
    "philips-vg5k": ("Philips", "VG5000"),
    "vg5k": ("Philips", "VG5000"),
    "videobrain": ("VideoBrain", "Family Computer"),
    # Computers whose sets sit under bios/Arcade with MAME's: the Atom has
    # no folder of its own, its section holds those sets. The MZ-2000 and
    # MZ-2500 sets join the MZ ones.
    "atom": ("Acorn", "Atom"),
    "mz2000": ("Sharp", "MZ"),
    "mz2500": ("Sharp", "MZ"),
    # Files kept at the maker's root, so each file is a heading of its own
    # on a page that is the machine's: the first one leads there.
    "galaksija": ("Galaksija", "Galaksija"),
    "vircon32": ("Vircon", "Vircon32"),
    # Games, filed with the game whose folder holds their data
    "dinothawr": ("Dinothawr", "Dinothawr"),
    "doom": ("Id Software", "Doom"),
    "ctf": ("Id Software", "Quake II"),
    "teamarena": ("Id Software", "Quake III Arena"),
    "enemyterritory": ("Id Software", "Wolfenstein Enemy Territory"),
    "gearbox": ("Valve", "Half-Life"),
    "dmc": ("Valve", "Half-Life"),
    "ricochet": ("Valve", "Half-Life"),
    "tfc": ("Valve", "Half-Life"),
    "mohaa": ("Electronic Arts", "Medal of Honor Allied Assault"),
    "mohaa-breakthrough": ("Electronic Arts", "Medal of Honor Allied Assault"),
    "mohaa-spearhead": ("Electronic Arts", "Medal of Honor Allied Assault"),
    "ur-quan-masters": ("Toys for Bob", "The Ur-Quan Masters"),
    "star-control-2": ("Toys for Bob", "The Ur-Quan Masters"),
    # Systems whose files sit in the folder of the program that reads them,
    # the only section listing them. DOS and ScummVM also read the Roland
    # MT-32 ROMs, which their own sections do not hold.
    "bbc-master-128": ("Other", "beebem"),
    "bbc-master-et": ("Other", "beebem"),
    "cave-story": ("Other", "NXEngine"),
    "dos": ("DOS", "DOSBox"),
    "scummvm": ("ScummVM", "ScummVM"),
    "sinclair-zx-spectrum-next": ("Other", "cspect"),
    "solarus": ("Game Engines", "Solarus"),
    "sunplus-spmp8000": ("Other", "spmp8000emu"),
    "tomb-raider-1": ("Game Engines", "TRX"),
    "tyrian": ("Other", "opentyrian"),
    "vm-labs-nuon": ("Other", "nuance"),
    "xrick": ("Other", "xrick"),
    "zc210": ("ZC", "ZC210"),
    # The collection's general arcade section, where naomi.zip, neogeo.zip
    # and the other board sets sit. A sound chip's set and a toy's stay in
    # the Arcade folders holding them: neither is an arcade board.
    "arcade": ("Arcade", "Arcade"),
    "miuchiz": ("Arcade", "MAME"),
    "ym2608": ("Arcade", "Arcade"),
}


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
        from common import (
            list_registered_platforms,
            load_platform_config,
            platform_system_names,
        )

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
