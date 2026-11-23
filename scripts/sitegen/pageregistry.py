"""What one site build records about its pages, for the renderers and the decorator that read it."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PageRegistry:
    """The maps a build fills as it writes pages, read by later pages and by
    the decorator. Keys are page paths relative to docs/ unless said."""

    # Structured data a page generator knows beyond its text.
    page_data: dict[str, dict] = field(default_factory=dict)
    # Emulator pages whose every file comes with the app: no "BIOS files" in
    # their title, and their description says so (DaedalusX64, ZEsarUX).
    nothing_to_fetch: set[str] = field(default_factory=set)
    # The first system, the file names, the count of required names and the
    # word for them ("BIOS" or "files") of each emulator page, for its snippet.
    emulator_snippets: dict[str, tuple[str, list[str], int, str]] = field(default_factory=dict)
    # The noun of the title of an emulator or system page (title_noun):
    # "BIOS files" when absent.
    title_nouns: dict[str, str] = field(default_factory=dict)
    # Pages that hold part of a page too long for one (a console of a split
    # manufacturer, a run of an emulator's cards): their H1 already says
    # what they are.
    part_pages: set[str] = field(default_factory=set)
    # Pages that answer a name after the page that owns it.
    search_demoted: set[str] = field(default_factory=set)
    # Data directory members by ref, then by path inside the tree.
    data_members: dict[str, dict[str, dict]] = field(default_factory=dict)
    # Data directory revisions by ref.
    data_revisions: dict[str, dict] = field(default_factory=dict)
    # The emulator pages that list each data directory, by ref.
    data_readers: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    # Emulator -> the platforms that run it, as resolve_platform_cores answers.
    emulator_setups: dict[str, list[str]] = field(default_factory=dict)
    # The measurement index items of each emulator, for the proof lines of its page.
    measurement_items: dict[str, list[dict]] = field(default_factory=dict)
