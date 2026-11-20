"""The system pages: each manufacturer's, its consoles and arcade boards."""

from __future__ import annotations

import dataclasses
import html
import json
import re
import urllib.parse
from dataclasses import dataclass

from model.collection import SECTION_LABELS, manufacturer_slug
from model.composition import GAME_DATA_TOPS
from packs.crossref import FileConsumers
from sitegen import markup
from sitegen.cards import icon_symbol
from sitegen.config import date_line
from sitegen.consolecards import (
    CARD_HTML_RATIO,
    CONSOLE_PAGES,
    Card,
    INSTALL_HTML_RATIO,
    SYSTEM_PAGE_BUDGET,
    SYSTEM_SUMMARY_HTML,
    console_cards,
    install_box_weight,
)
from sitegen.decorate import DEMOTED_WEIGHT, SEARCH_WEIGHT
from sitegen.fields import search_excluded
from sitegen.home import next_block
from sitegen.install import console_install_block, manifest_systems, platform_display
from sitegen.parts import character_count, even_runs, parent_front_matter, part_stems, weighted_runs
from sitegen.render import count_text, slugify_anchor, console_href, record_console_pages
from sitegen.startwith import (
    OTHER_ARCADE,
    cards_markdown,
    console_heading,
    romset_note,
    section_label,
    start_order,
    start_with,
)
from sitegen.systemsindex import folder_emulator


_NEXT_FROM_SYSTEMS = [
    "[Get the files](../which-pack.md), for the setup in use",
    "[When a game does not start](../wiki/troubleshooting.md)",
    "[Every emulator](../emulators/index.md), and the files each one reads",
]

# The arcade boards the system pages give a section, by the console key
# their section goes by (the board's name) -> the board's system id. Set by
# arcade_board_sections() before the first system page is written.
_BOARD_CONSOLES: dict[str, str] = {}


# (manufacturer, console) -> the boards whose sets left that folder's
# section for the boards' own pages. The section names them.
_BOARDS_FROM: dict[tuple[str, str], set[str]] = {}


@dataclass
class _BoardSort:
    """Where each archive goes: its board, the machine that owns it, or the
    folder it sits in."""

    boards: dict[str, list] = dataclasses.field(default_factory=dict)
    folders: dict[str, list] = dataclasses.field(default_factory=dict)
    seen: dict[str, set[str]] = dataclasses.field(default_factory=dict)
    # The sets a reviewed machine owns go to its section: neogeo.zip sat on
    # five Arcade pages, the Atom's and the MZ-2000's sets on board pages.
    machines: dict[tuple[str, str], list] = dataclasses.field(default_factory=dict)
    makers: dict[str, dict[str, list]] = dataclasses.field(default_factory=dict)

    def file_on_board(self, board: str, f: dict) -> None:
        # One card per content: a copy under Arcade and one under MAME
        # are the same file.
        if str(f.get("sha1", "")) in self.seen.setdefault(board, set()):
            return
        self.seen[board].add(str(f.get("sha1", "")))
        self.boards.setdefault(board, []).append(f)

    def arcade_folders(self, arcade: dict[str, list], by_name: dict[str, str]) -> None:
        """The folders of bios/Arcade/, each file to its board or machine."""
        from sitegen.render import arcade_board, archive_machine
        from model.collection import record_card_move

        for console in sorted(arcade):
            joined = by_name.get(console.casefold())
            for f in arcade[console]:
                sha1 = str(f.get("sha1", ""))
                board = joined or arcade_board(sha1)
                machine = None if board else archive_machine(sha1)
                if board is not None:
                    self.file_on_board(board, f)
                elif machine is not None:
                    self.machines.setdefault(machine, []).append(f)
                    record_card_move("Arcade", console, sha1, *machine)
                else:
                    self.folders.setdefault(console, []).append(f)

    def maker_folders(self, manufacturers: dict[str, dict[str, list]]) -> None:
        """A board's set filed under a machine's folder is on the board's page
        too, whatever the folder: naomi.zip under the Dreamcast was the copy
        five setups list, and the NAOMI page did not name it."""
        from sitegen.render import arcade_board, archive_machine
        from model.collection import record_card_move

        for mfr, consoles in manufacturers.items():
            if mfr == "Arcade":
                continue
            for console, files in consoles.items():
                kept = []
                for f in files:
                    sha1 = str(f.get("sha1", ""))
                    board = arcade_board(sha1)
                    machine = None if board else archive_machine(sha1)
                    if board is not None:
                        self.file_on_board(board, f)
                        _BOARDS_FROM.setdefault((mfr, console), set()).add(board)
                    elif machine is not None and machine != (mfr, console):
                        # The Atom's own set sat with the BBC Micro.
                        self.machines.setdefault(machine, []).append(f)
                        record_card_move(mfr, console, sha1, *machine)
                    else:
                        kept.append(f)
                if len(kept) != len(files):
                    self.makers.setdefault(mfr, dict(consoles))[console] = kept

    def machine_sections(self, manufacturers: dict[str, dict[str, list]]) -> None:
        """The sets a machine owns, added to its section."""
        for (mfr, console), files in sorted(self.machines.items()):
            consoles = self.makers.setdefault(mfr, dict(manufacturers.get(mfr, {})))
            held = {str(f.get("sha1", "")) for f in consoles.get(console, [])}
            consoles[console] = [*consoles.get(console, []),
                                 *(f for f in files if str(f.get("sha1", "")) not in held)]


def _installs_by_board(
    installs: dict[str, dict[str, list[tuple[str, str]]]],
) -> dict[str, dict[str, list[tuple[str, str]]]]:
    """A system's install commands, moved to its board's section."""
    from sitegen.render import system_section

    moved: dict[str, dict[str, list[tuple[str, str]]]] = {}
    for slug, consoles in installs.items():
        for console, pairs in consoles.items():
            for platform, sys_id in pairs:
                section = system_section(sys_id)
                if section and section[0] == "arcade" and section[1] in _BOARD_CONSOLES:
                    slug_to, console_to = section
                else:
                    slug_to, console_to = slug, console
                moved.setdefault(slug_to, {}).setdefault(console_to, []).append((platform, sys_id))
    return moved


def arcade_board_sections(
    manufacturers: dict[str, dict[str, list]],
    installs: dict[str, dict[str, list[tuple[str, str]]]],
) -> tuple[dict[str, dict[str, list]], dict[str, dict[str, list[tuple[str, str]]]]]:
    """The Arcade page grouped by board, and each board's install commands.

    The Arcade sections were the folders of bios/Arcade/: NAOMI, PGM and
    ZN-1 had no section, and their names stayed plain on 568 emulator
    pages. Each archive goes to the board sitegen.render.arcade_board() reads
    from the profiles, never from its folder, and a folder named after a
    board (Namco System 246) joins it, whatever maker's folder holds the
    copy. A set a reviewed machine owns (sitegen.render.archive_machine) goes
    to that machine's section. Files neither claims stay in their
    folders. Each board is recorded (sitegen.render.record_board_section) before
    any page links one, and a system's install commands follow its link to
    the board's section. Call after reset_console_pages()."""
    from sitegen.render import arcade_boards, record_board_section

    _BOARD_CONSOLES.clear()
    _BOARDS_FROM.clear()
    arcade = manufacturers.get("Arcade")
    if not arcade:
        return manufacturers, installs
    names = arcade_boards()
    by_name = {name.casefold(): board for board, name in names.items()}
    sort = _BoardSort()
    sort.arcade_folders(arcade, by_name)
    sort.maker_folders(manufacturers)
    sort.machine_sections(manufacturers)
    for board in sorted(sort.boards):
        record_board_section(board)
        _BOARD_CONSOLES[names[board]] = board
    regrouped = {**sort.folders, **{names[board]: files for board, files in sort.boards.items()}}
    makers = {mfr: {console: files for console, files in consoles.items() if files}
              for mfr, consoles in sort.makers.items()}
    return {**manufacturers, **makers, "Arcade": regrouped}, _installs_by_board(installs)


def _boards_line(manufacturer: str, console: str) -> list[str]:
    """The line of a section whose board sets went to the boards' pages:
    the Dreamcast folder holds NAOMI's and Atomiswave's."""
    from sitegen.render import arcade_boards

    boards = _BOARDS_FROM.get((manufacturer, console))
    if not boards:
        return []
    names = arcade_boards()
    links = [f"[{names[board]}]({console_href('arcade', names[board]).removeprefix('systems/')})"
             for board in sorted(boards, key=lambda b: names[b].casefold())]
    return [f"**Arcade board BIOS** on the boards' own pages: {', '.join(links)}.", ""]


def _part_name(manufacturer: str, console: str) -> str:
    """What a part's title calls the files: "Arcade files a to b"."""
    if (manufacturer, console) == OTHER_ARCADE:
        return "Arcade"
    return SECTION_LABELS.get((manufacturer, console), console)


def _system_front_matter(
    parent: tuple[str, str] | None = None,
    prev: tuple[str, str] | None = None,
    following: tuple[str, str] | None = None,
    weight: float | None = None,
    consoles: list[str] | None = None,
) -> list[str]:
    """The front matter of a system page: the page it belongs to, the
    parts before and after it (label, site path), its search weight and
    the consoles it holds, which the search reads as a field."""
    lines = parent_front_matter(parent)
    for key, link in (("prev", prev), ("next", following)):
        if link:
            lines += [f"{key}:", f"  label: {json.dumps(link[0])}", f"  link: {json.dumps(link[1])}"]
    if weight is not None:
        lines.append(f"searchWeight: {weight}")
    if consoles:
        lines += ["consoles:", *(f"  - {json.dumps(name)}" for name in consoles)]
    return ["---", *lines, "---", ""] if lines else []


def _part_weight() -> float:
    """The search weight of a part page: its cards keep their own weight."""
    return SEARCH_WEIGHT.get("part", DEMOTED_WEIGHT)


def _install_pairs(
    declared: list[tuple[str, str]], lead: str | None, consumers: FileConsumers,
) -> list[tuple[str, str]]:
    """A section's install commands: the setups whose system leads here,
    then each setup that files the section's first file under a system of
    its own (RetroArch files neogeo.zip under arcade), with that id."""
    pairs = list(declared)
    have = {platform for platform, _system in pairs}
    for platform, systems in sorted(getattr(consumers, "platform_systems", {})
                                    .get(lead or "", {}).items()):
        if platform in have:
            continue
        recorded = [s for s in sorted(systems) if s in manifest_systems(platform)]
        if recorded:
            pairs.append((platform, recorded[0]))
            have.add(platform)
    return sorted(pairs, key=lambda pair: (platform_display(pair[0]).casefold(), pair[1]))


@dataclass(frozen=True)
class _ConsoleParts:
    """A console moved to pages of its own: the pages and what each holds."""

    label: str
    stems: list[str]
    parts: list[list[Card]]
    titles: list[str]
    lead: set[str]


@dataclass
class _MakerPages:
    """What a manufacturer's pages are built from, and how each part reads."""

    manufacturer: str
    consoles: dict[str, list]
    consumers: FileConsumers
    installs: dict[str, list[tuple[str, str]]]
    budget: int
    slug: str = ""
    boards: dict[str, str] = dataclasses.field(default_factory=dict)
    json_next: str = ""
    ordered: list[str] = dataclasses.field(default_factory=list)
    starts: dict[str, list[str]] = dataclasses.field(default_factory=dict)
    intro: str = ""
    legend: list[str] = dataclasses.field(default_factory=list)
    machines: list[str] = dataclasses.field(default_factory=list)
    front: list[str] = dataclasses.field(default_factory=list)

    def __post_init__(self) -> None:
        manufacturer, consoles = self.manufacturer, self.consoles
        self.slug = manufacturer_slug(manufacturer)
        self.boards = {console: _BOARD_CONSOLES[console] for console in consoles
                       if manufacturer == "Arcade" and console in _BOARD_CONSOLES}
        self.json_next = (f"[Every hash of these files, as JSON](../api/v1/systems/"
                          f"{urllib.parse.quote(self.slug)}.json)")
        # Boards first on the Arcade page, then the folders of sets for many
        # machines. Such a folder starts nowhere: its line named konamigv.zip,
        # sys573.zip and 97 more, files of boards with lines of their own.
        boards = self.boards
        self.ordered = sorted(consoles, key=lambda c: (bool(boards) and c not in boards, c))
        self.starts = {console: [] if boards and console not in boards
                       else start_order(consoles[console], self.consumers, (manufacturer, console))
                       for console in consoles}
        # One line, then the legend closed: four paragraphs said the same on
        # every maker's page before its first console.
        self.intro = f"Every BIOS file for {manufacturer} machines, one card per file."
        self.legend = search_excluded(markup.details("note", "How to read a card", [
            "A card gives the file's fingerprints, the emulators that read it, the setups "
            "that list it and where to download it. A file can have several versions, one "
            "per region or revision: the main one comes first, the others under "
            "\"Variants\". To install the files of one console, open its \"Install\" box.",
            "",
            "**On the setup's list** names the setups whose own BIOS list has the file, by "
            "the name each gives it. **Packed for its emulators by** names the setups whose "
            "pack adds it because one of their emulators reads it.",
        ]))
        # The consoles a page answers for, a search field: machines only. An
        # emulator's folder under Other put that page first for "dolphin", and
        # a console with a page of its own is that page's to answer for.
        self.machines = [console for console in self.ordered
                         if manufacturer not in ("Other", *GAME_DATA_TOPS)
                         and (manufacturer != "Arcade" or console in boards)]
        self.front = self.consoles_front()

    def start_of(self, console: str, first_below: bool = True) -> list[str]:
        if self.boards and console not in self.boards:
            return []
        return [*start_with(self.consoles[console], self.consumers, first_below,
                             (self.manufacturer, console)),
                *_boards_line(self.manufacturer, console)]

    def cards_of(self, console: str, anchors: set[str], by_name: bool = False) -> list[Card]:
        return console_cards(self.manufacturer, self.consoles[console], self.consumers, anchors,
                              by_name, self.starts[console])

    def install_block(self, console: str) -> list[str]:
        lead = self.starts[console][0] if self.starts[console] else None
        return console_install_block(
            section_label(self.manufacturer, console),
            _install_pairs(self.installs.get(console, []), lead, self.consumers))

    def all_sections(self) -> dict[str, list[Card]]:
        anchors: set[str] = set()
        return {console: self.cards_of(console, anchors) for console in self.ordered}

    def consoles_front(self, kept: set[str] | None = None) -> list[str]:
        return _system_front_matter(consoles=[
            section_label(self.manufacturer, c) for c in self.machines
            if kept is None or c in kept])

    def head(self, front: list[str]) -> list[str]:
        """A maker's page down to its first console."""
        return [
            *front, f"# {self.manufacturer}", "", self.intro, "", *self.legend,
            *romset_note(self.consoles), *icon_symbol(),
        ]

    def whole_page(self, sections: dict[str, list[Card]]) -> str:
        lines = self.head(self.front)
        for console, cards in sections.items():
            lines.append(console_heading(self.manufacturer, console,
                                          section_label(self.manufacturer, console)))
            lines.append("")
            lines.extend(self.start_of(console))
            lines.extend(self.install_block(console))
            lines.extend(cards_markdown(cards))
            lines.append("")
        lines.extend(next_block([*_NEXT_FROM_SYSTEMS, self.json_next]))
        lines.extend(["", date_line()])
        return "\n".join(lines) + "\n"

    def cut(self, console: str, by_name: bool) -> list[list[Card]]:
        """A console's cards in parts of at most the budget, evened out."""
        # Cards are rendered again for their own page: the anchors a page
        # holds are its own.
        cards = self.cards_of(console, set(), by_name)
        with markup.using("mkdocs"):
            sizes = [character_count(card) for _variant, card, _sha1 in self.cards_of(
                console, set(), by_name)]
        parts = weighted_runs(cards, self.budget, sizes)
        if len(parts) < 2:
            return parts
        # Even parts: cut at budget, the PlayStation 2 was 137 cards
        # and 4. The same number of parts, each near the mean.
        return even_runs(cards, sizes, len(parts))

    def moved(self, weights: dict[str, int], rendered: dict[str, float]) -> set[str]:
        """Every board has a page of its own. Then the heaviest sections move
        to pages of their own until what stays on the manufacturer's page is
        half the budget: a section of one file keeps its place, and a reader
        does not open 91 pages to browse Other."""
        moved: set[str] = set(self.boards) | (
            set(self.consoles) if self.manufacturer in CONSOLE_PAGES else set())
        for console in sorted(weights, key=lambda c: (-weights[c], c)):
            if sum(w for c, w in weights.items() if c not in moved) <= self.budget // 2:
                break
            moved.add(console)
        # Then until what stays holds its estimate as it renders.
        for console in sorted(rendered, key=lambda c: (-rendered[c], c)):
            if sum(w for c, w in rendered.items() if c not in moved) <= SYSTEM_SUMMARY_HTML:
                break
            moved.add(console)
        return moved

    def part_page(self, console: str, index: int, plan: _ConsoleParts) -> str:
        """Part ``index`` of a console moved to pages of its own."""
        stems, part, label = plan.stems, plan.parts[index], plan.label
        neighbours = [(plan.titles[i], f"/systems/{stems[i]}/")
                      for i in (index - 1, index + 1) if 0 <= i < len(stems)]
        lines = [
            *_system_front_matter(
                (self.manufacturer, f"/systems/{self.slug}/"),
                prev=neighbours[0] if index > 0 else None,
                following=neighbours[-1] if index + 1 < len(stems) else None,
                weight=_part_weight() if len(stems) > 1 else None,
                consoles=[label] if index == 0 and console in self.machines else None),
            # The crumbs end on the maker's page: no line says it again.
            f"# {plan.titles[index]}", "", *icon_symbol(),
        ]
        if len(stems) > 1:
            others = ", ".join(
                f"[part {i + 1}]({other}.md)" for i, other in enumerate(stems) if i != index)
            lines.extend([f"This part holds {_part_range(part, plan.lead)}. The others: {others}.",
                          ""])
        # A board's page is its one section: its title names it, and a
        # heading of the same name said it a third time. Its cards come
        # under "Files", as every page of one console's.
        if index == 0:
            lines.extend(self.start_of(console, len(stems) == 1))
        lines.extend(self.legend)
        lines.extend(romset_note({console: self.consoles[console]}))
        lines.extend(self.install_block(console))
        lines.extend(["## Files", ""])
        lines.extend(cards_markdown(part))
        lines.append("")
        lines.extend(next_block([f"[{self.manufacturer}]({self.slug}.md), every section"]
                                 + _NEXT_FROM_SYSTEMS + [self.json_next]))
        lines.extend(["", date_line()])
        return "\n".join(lines) + "\n"

    def moved_section(self, console: str, pages: dict[str, tuple[str, dict[str, list]]]) -> list[str]:
        """A console moved to pages of its own: the lines the summary keeps
        under its heading. Its pages go into ``pages``."""
        from sitegen.render import board_slug

        manufacturer = self.manufacturer
        label = section_label(manufacturer, console)
        # One page keeps the required files first. Parts are named by their
        # first and last file, so a console cut in parts goes by name, the
        # files the start line names first.
        parts = self.cut(console, False)
        if len(parts) > 1:
            parts = self.cut(console, True)
        board = self.boards.get(console)
        base = (f"arcade-{board_slug(board)}" if board
                else f"{self.slug}-{slugify_anchor(console) or 'files'}")
        stems = part_stems(base, len(parts))
        clash = set(stems) & set(pages)
        if clash:
            raise RuntimeError(f"two system sections take one page: {sorted(clash)}")
        record_console_pages(self.slug, console, stems, [
            [sha1 for _variant, _card, sha1 in part] for part in parts
        ])
        lead = set(self.starts[console])
        # A part by the files it holds: "Arcade: Arcade, part 3 of 5" said
        # nothing a search result could use. A folder under Other goes by
        # its emulator's name: "mame files" named the folder.
        named = folder_emulator(console)[0] if manufacturer == "Other" else None
        titles = ([f"{manufacturer}: {named or label}"] if len(stems) == 1 else [
            "{} files {} to {}".format(named or _part_name(manufacturer, console),
                                       *_part_ends(part, lead))
            for part in parts])
        count = count_text(len(self.consoles[console]), "file")
        summary = list(self.start_of(console, False))
        if len(stems) == 1:
            own = "its" if len(self.consoles[console]) == 1 else "their"
            summary.append(f"{count}, on [{own} own page]({stems[0]}.md).")
        else:
            summary.append(f"{count}, on {len(stems)} pages by file name:")
            summary.append("")
            for index, (stem, part) in enumerate(zip(stems, parts)):
                summary.append(f"- [Part {index + 1}]({stem}.md): {_part_range(part, lead)}")
        summary.append("")
        plan = _ConsoleParts(label, stems, parts, titles, lead)
        for index, (stem, part) in enumerate(zip(stems, parts)):
            text = self.part_page(console, index, plan)
            held = {sha1 for _variant, _card, sha1 in part}
            pages[stem] = (text, {console: [
                f for f in self.consoles[console] if str(f.get("sha1", "")) in held]})
        return summary


def system_pages(
    manufacturer: str,
    consoles: dict[str, list],
    consumers: FileConsumers,
    installs: dict[str, list[tuple[str, str]]] | None = None,
    budget: int = SYSTEM_PAGE_BUDGET,
) -> dict[str, tuple[str, dict[str, list]]]:
    """A manufacturer's pages by stem under systems/: one page, or a summary
    and a page per console when the whole would pass ``budget``. Each page
    comes with the files whose cards it holds, by console.

    Every console keeps its heading on the summary, so a link to
    systems/<maker>/#<console> still lands, and site.js sends a card
    anchor the page no longer holds to the card's new place. The pages
    each card and console went to are recorded for every other link
    (sitegen.render.record_console_pages). An arcade board has a page of its
    own, systems/arcade-<board slug>/, under a heading of that id.
    """
    maker = _MakerPages(manufacturer, consoles, consumers, installs or {}, budget)
    slug = maker.slug

    # Sizes are those of the MkDocs Markdown the budget was set on, so the
    # pages split where they always have and no card changes address.
    with markup.using("mkdocs"):
        measured = maker.all_sections()
        measured_text = maker.whole_page(measured)
    weights = {
        console: sum(character_count(card) for _variant, card, _sha1 in cards)
        for console, cards in measured.items()
    }
    # An install box is a few lines of Markdown and about nine times that
    # once highlighted: ten of them were 295 KB of the 583 KB Nintendo
    # page, which the card weights never counted. A page is also cut when
    # its estimate as it renders passes the summary's.
    with markup.using("mkdocs"):
        boxes = {console: install_box_weight(maker.install_block(console)) for console in consoles}
    rendered = {console: CARD_HTML_RATIO * weights[console] + INSTALL_HTML_RATIO * boxes[console]
                for console in weights}
    if (not maker.boards and manufacturer not in CONSOLE_PAGES and len(measured_text) <= budget
            and sum(rendered.values()) <= SYSTEM_SUMMARY_HTML):
        text = maker.whole_page(maker.all_sections()) if markup.starlight() else measured_text
        return {slug: (text, consoles)}

    moved = maker.moved(weights, rendered)
    pages: dict[str, tuple[str, dict[str, list]]] = {}
    summary = maker.head(maker.consoles_front(set(consoles) - moved))
    summary_anchors: set[str] = set()
    for console in maker.ordered:
        label = section_label(manufacturer, console)
        summary.append(console_heading(manufacturer, console, label))
        summary.append("")
        if console not in moved:
            summary.extend(maker.start_of(console))
            summary.extend(maker.install_block(console))
            summary.extend(cards_markdown(maker.cards_of(console, summary_anchors)))
            summary.append("")
            continue
        summary.extend(maker.moved_section(console, pages))
    summary.extend(next_block([*_NEXT_FROM_SYSTEMS, maker.json_next]))
    summary.extend(["", date_line()])
    kept = {console: files for console, files in consoles.items() if console not in moved}
    return {slug: ("\n".join(summary) + "\n", kept), **pages}


def _part_ends(part: list[Card], lead: set[str] | frozenset[str] = frozenset()) -> tuple[str, str]:
    """The first and last file names of a part, as the cards show them.
    The files a start line puts first are left out when the part holds
    others: the range is the run by name that follows them."""
    named = [card for card in part if card[2] not in lead] or part
    names = []
    for _variant, card, _sha1 in named:
        # An HTML heading on the site, a Markdown one in the size yardstick.
        match = re.search(r"`([^`]*)`|<code>(.*?)</code>", card[2])
        if match is None:
            raise ValueError(f"a card heading names no file: {card[2]!r}")
        names.append(match[1] if match[1] is not None else html.unescape(match[2]))
    return names[0], names[-1]


def _part_range(part: list[Card], lead: set[str] | frozenset[str] = frozenset()) -> str:
    """The first and last file names of a part, with its count."""
    first, last = _part_ends(part, lead)
    if len(part) == 1:
        return f"`{first}`"
    return f"{count_text(len(part), 'file')}, `{first}` to `{last}`"


def generate_system_page(
    manufacturer: str,
    consoles: dict[str, list],
    consumers: FileConsumers,
    installs: dict[str, list[tuple[str, str]]] | None = None,
) -> str:
    """One manufacturer's page, a section per console.

    ``installs`` gives, per console, the (platform, system id) pairs whose
    install command the section offers. A page over the budget is the
    summary system_pages writes, its consoles on pages of their own.
    """
    return system_pages(manufacturer, consoles, consumers, installs)[manufacturer_slug(manufacturer)][0]
