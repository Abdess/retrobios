"""The console sections one site run names systems from, and their heading ids."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from core.anchors import toc_slug, unique_anchor
from model import siteinputs
from model.collection import SECTION_LABELS, Grouping, group_by_manufacturer
from model.manufacturers import manufacturer_slug
from model.systemnames import (
    ConsoleSections,
    console_sections,
    own_section_in,
    program_names,
    section_without_boards_in,
    system_name_in,
)


@dataclass(frozen=True)
class RunSections:
    """The sections a run installed, under the site inputs it read.

    ``anchors``: (manufacturer slug, console) -> the id of the console's
    heading. Two folders spelled alike (Sega's "Mega CD" and "Mega-CD")
    share a slug, and the second heading took "mega-cd_1" while every link
    said "mega-cd". ``generation`` counts the installs: what a page derives
    from the sections (the arcade boards) is stale once it moves.
    ``moves``: the cards the grouping filed outside their folder
    (model.collection.Grouping.moves).
    """

    sections: ConsoleSections
    anchors: dict[tuple[str, str], str]
    inputs: siteinputs.SiteInputs
    generation: int
    moves: Mapping[tuple[str, str, str], tuple[str, str]] = field(default_factory=dict)


_current: list[RunSections | None] = [None]
_installs = [0]


def install(
    sections: dict[str, dict] | set[tuple[str, str]],
    programs: set[str] | frozenset[str] = frozenset(),
    labels: Mapping[tuple[str, str], str] = SECTION_LABELS,
    moves: Mapping[tuple[str, str, str], tuple[str, str]] | None = None,
) -> RunSections:
    """Install the console sections the system pages carry, under the
    current site inputs, the previous ones forgotten.

    ``sections`` maps each manufacturer to its consoles, as the system pages
    group them, or is a set of (manufacturer, console) pairs. ``programs``
    are the emulator names, which never name a system. ``labels`` and
    ``moves`` are the headings and card moves of the grouping
    (install_grouping).
    """
    carried = console_sections(sections, programs, labels)
    by_maker: dict[str, list[str]] = {}
    for mfr, console in carried.pairs:
        by_maker.setdefault(mfr, []).append(console)
    anchors: dict[tuple[str, str], str] = {}
    # In the order the page lists them, after the page title's own id.
    for mfr, consoles in by_maker.items():
        used = {toc_slug(mfr)}
        for console in sorted(consoles):
            anchors[(manufacturer_slug(mfr), console)] = unique_anchor(toc_slug(console), used)
    _installs[0] += 1
    run = RunSections(carried, anchors, siteinputs.current(), _installs[0], dict(moves or {}))
    _current[0] = run
    return run


def install_grouping(grouping: Grouping, programs: set[str] | frozenset[str]) -> RunSections:
    """Install the sections of a collection's grouping, with its headings
    and card moves."""
    return install(grouping.sections, programs, grouping.labels, grouping.moves)


def reset() -> None:
    """Forget the installed sections: the next name is read from the inputs."""
    _current[0] = None


def installed() -> RunSections | None:
    """The sections installed under the current site inputs, None when
    none were, without reading anything."""
    run = _current[0]
    return run if run is not None and run.inputs == siteinputs.current() else None


def current() -> RunSections:
    """The installed sections, read from the site inputs when none were
    installed under them, so a page rendered on its own names systems as
    the site does."""
    run = installed()
    if run is not None:
        return run
    inputs = siteinputs.current()
    from model.database import load_database
    from model.profiles import load_emulator_profiles

    db = load_database(str(inputs.db))
    profiles = load_emulator_profiles(str(inputs.emulators), skip_aliases=False)
    return install_grouping(group_by_manufacturer(db), program_names(profiles))


def section_labels() -> Mapping[tuple[str, str], str]:
    """The heading each labelled section shows in place of its folder."""
    return current().sections.labels


def system_name(sys_id: str) -> str:
    """The display name of a system id, the only one a page prints
    (model.systemnames.system_name_in)."""
    return system_name_in(sys_id, current().sections)


def own_section(sys_id: str) -> tuple[str, str] | None:
    """The console section that is this id's own, or None
    (model.systemnames.own_section_in)."""
    return own_section_in(sys_id, current().sections)


def section_without_boards(sys_id: str) -> tuple[str, str] | None:
    """The console section a system id leads to before arcade boards
    (model.systemnames.section_without_boards_in)."""
    return section_without_boards_in(sys_id, current().sections)
