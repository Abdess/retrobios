"""The site navigation, from the wiki tabs and the generated sections."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from model.collection import _slug
from model.composition import GAME_DATA_TOPS
from model.guides import DEVICE_GROUPS, GROUP_TILES, HANDHELD_GUIDE
from model.profiles import unique_emulator_profiles
from sitegen import measurements as sitemeasurements, starlight as sitestarlight
from sitegen.config import _REPO_ROOT
from sitegen.decorate import _front_matter
from sitegen.emulatorsindex import INITIAL_DIGITS, emulator_initial
from sitegen.render import WIKI_SRC_DIR


def nav_emulators(profiles: dict) -> dict[str, dict]:
    """The emulators listed in the navigation, by key.

    A profile that emulates no system and reads no file (the libretro sample
    and test cores, games with nothing to load) answers no question about
    BIOS files. Its page stays, reachable from the overview table and the
    search, and the navigation is left to the cores people look up.
    """
    return {
        key: profile for key, profile in unique_emulator_profiles(profiles).items()
        if profile.get("systems") or profile.get("files")
    }


def _emulator_nav(profiles: dict) -> list:
    """Emulators by initial (A, B, C), one level deep. A name that does not
    open on a letter goes under "0 to 9". The route middleware draws every
    initial but the open one as a single link, so a page carries the links
    of one initial only."""
    groups: dict[str, list[tuple[str, str]]] = {}
    for key, profile in nav_emulators(profiles).items():
        display = str(profile.get("emulator", key))
        groups.setdefault(emulator_initial(display), []).append((display, f"emulators/{key}.md"))
    nav: list = ["emulators/index.md"]
    for label in sorted(groups, key=lambda g: (g != INITIAL_DIGITS, g)):
        items = sorted(groups[label], key=lambda e: e[0].casefold())
        nav.append({label: [{display: path} for display, path in items]})
    return nav


def _system_nav(manufacturers: dict) -> list:
    """Manufacturer pages, the machines apart from the arcade boards and the
    game and engine trees: an arcade page's crumb read "Consoles and
    computers"."""
    machines: list[dict] = []
    arcade: list[dict] = []
    games: list[dict] = []
    for mfr in sorted(manufacturers, key=str.casefold):
        entry = {mfr: f"systems/{_slug(mfr)}.md"}
        if mfr in GAME_DATA_TOPS:
            games.append(entry)
        else:
            (arcade if mfr == "Arcade" else machines).append(entry)
    nav: list = ["systems/index.md", {"Consoles and computers": machines}]
    if arcade:
        nav.append({"Arcade": arcade})
    if games:
        nav.append({"Game engines and PC games": games})
    return nav


def _platform_nav(coverages: dict, registry: dict) -> list:
    """Platforms by the kind of device they run on, as on the device picker."""
    nav: list = ["platforms/index.md"]
    for group, (label, _description) in DEVICE_GROUPS.items():
        members = [
            {coverages[name]["platform"]: f"platforms/{name}.md"}
            for name in sorted(coverages, key=lambda n: coverages[n]["platform"].casefold())
            if registry.get(name, {}).get("device_group") == group
        ]
        # The handheld guide sits with the group whose tile leads to it.
        members += [{HANDHELD_GUIDE.title: HANDHELD_GUIDE.path}
                    for tile in GROUP_TILES.get(group, ())
                    if HANDHELD_GUIDE and tile.link == HANDHELD_GUIDE.path]
        if members:
            nav.append({label: members})
    return nav


# The tabs in reading order, by the level their pages declare.
TABS = {
    "start": "Start here",
    "setup": "Setups",
    "explore": "Explore",
    "reference": "Reference",
    "contribute": "Contribute",
}


class NavError(ValueError):
    """A wiki page does not say where it goes in the navigation."""


def _h1(markdown: str) -> str:
    match = re.search(r"^# (.+?)(?:\s*\{[^}]*\})?\s*$", markdown, re.M)
    return match.group(1).strip() if match else ""


NavPlace = tuple[int, object, str]


def wiki_nav(wiki_dir: Path | None = None) -> dict[str, list[NavPlace]]:
    """Wiki pages by tab, each at the place its front matter gives.

    A page states `level:` (its tab), `order:` (its place in the tab, the
    smallest first) and, when the navigation names it otherwise than its
    first heading, `nav_title:`. `group:` files it under a labelled group
    of its tab. `nav: false` keeps a page out on purpose. A page that says
    neither raises, naming what to add.
    """
    wiki_dir = Path(wiki_dir) if wiki_dir else _REPO_ROOT / WIKI_SRC_DIR
    tabs: dict[str, list[NavPlace]] = {level: [] for level in TABS}
    for page in sorted(wiki_dir.glob("*.md")):
        where = f"{WIKI_SRC_DIR}/{page.name}"
        text = page.read_text(encoding="utf-8")
        meta = _front_matter(text)
        level = meta.get("level")
        if level not in TABS:
            raise NavError(
                f"{where}: front matter needs `level:`, one of {', '.join(TABS)}, "
                f"to place the page in a tab (found {level!r})"
            )
        if meta.get("nav") is False:
            continue
        order = meta.get("order")
        if not isinstance(order, int) or isinstance(order, bool):
            raise NavError(
                f"{where}: front matter needs `order:`, a whole number giving its "
                f"place in the {TABS[level]} tab, smallest first (found {order!r}), "
                "or `nav: false` to keep it out of the navigation"
            )
        path = f"{WIKI_SRC_DIR}/{page.name}"
        if page.name == "index.md":
            tabs[level].append((order, path, ""))
            continue
        title = meta.get("nav_title") or _h1(text)
        if not title:
            raise NavError(f"{where}: no `# ` heading and no `nav_title:` to name it")
        group = meta.get("group") or ""
        if not isinstance(group, str):
            raise NavError(f"{where}: `group:` names a group of the {TABS[level]} tab (found {group!r})")
        tabs[level].append((order, {str(title): path}, group))
    return tabs


def _overview_anchors(nav: list, docs: Path) -> dict[str, set[str]]:
    """The heading ids of each overview page the navigation names, where a
    group of the sidebar finds its own section."""
    def overviews(value: object) -> Iterator[str]:
        if isinstance(value, str):
            yield value
        elif isinstance(value, list):
            for entry in value:
                yield from overviews(entry)
        elif isinstance(value, dict):
            for child in value.values():
                if isinstance(child, list):
                    yield from overviews(child)

    anchors: dict[str, set[str]] = {}
    for rel in overviews(nav):
        stem = rel.rsplit(".", 1)[0]
        page = next((docs / f"{stem}{suffix}" for suffix in (".md", ".mdx")
                     if (docs / f"{stem}{suffix}").is_file()), None)
        if page:
            anchors[rel] = sitestarlight.heading_ids(page.read_text(encoding="utf-8"))
    return anchors


def _nav_target(entry: str | dict) -> str:
    return entry if isinstance(entry, str) else str(next(iter(entry.values())))


def generate_nav(
    coverages: dict,
    manufacturers: dict,
    profiles: dict,
    registry: dict | None = None,
    wiki_dir: Path | None = None,
) -> list:
    """The navigation, five tabs in reading order.

    Start here is for someone who knows nothing yet, Setups for someone
    who knows their device, Explore for one system or emulator, Reference for
    checking the work, Contribute for adding to it. Each tab opens on its
    index page.

    The generated pages hold the places below. A wiki page takes its own
    place from its front matter (wiki_nav), so a new page needs no edit here.
    A group of a tab sits at the place of its first page, its pages in their
    own order.
    """
    generated: dict[str, list[tuple]] = {
        "start": [(0, "index.md"), (20, {"Get the files": "which-pack.md"})],
        "setup": [(10 * i, item)
                  for i, item in enumerate(_platform_nav(coverages, registry or {}))],
        "explore": [
            (0, "explore.md"),
            (10, {"Systems": _system_nav(manufacturers)}),
            (20, {"Emulators": _emulator_nav(profiles)}),
        ],
        "reference": [
            # Find a file first: the one tool a reader comes to with a file in hand.
            (5, {"Find or check a file": "files/index.md"}, "Checking files"),
            (20, {"What the packs do not hold": "gaps.md"}, "Checking files"),
            (30, {"Cores by platform": "cross-reference.md"}, "Checking files"),
            (40, {"Dump provenance": "provenance.md"}, "Checking files"),
            (60, {"Data and API": "data.md"}, "Data"),
            (64, {"Data model": "wiki/data-model.md"}, "Data"),
            (68, {"Updated platform files": "exports.md"}, "Data"),
            (69, {"Measurements": sitemeasurements.EXPLORER_PAGE}, "Data"),
        ],
        "contribute": [(0, "contributing.md"), (5, {"Wanted": "wanted.md"})],
    }
    wiki = wiki_nav(wiki_dir)
    nav = []
    for level, label in TABS.items():
        places = [(place[0], place[1], place[2] if len(place) > 2 else "")
                  for place in generated[level]]
        entries = sorted(places + wiki[level], key=lambda item: item[0])
        for (first, a, _), (second, b, _) in zip(entries, entries[1:]):
            if first == second:
                raise NavError(
                    f"{label} tab: {_nav_target(a)} and {_nav_target(b)} both take "
                    f"order {first}; give one of them a free number"
                )
        items: list = []
        groups: dict[str, list] = {}
        for _order, entry, group in entries:
            if not group:
                items.append(entry)
            elif group in groups:
                groups[group].append(entry)
            else:
                groups[group] = [entry]
                items.append({group: groups[group]})
        nav.append({label: items})
    return nav
