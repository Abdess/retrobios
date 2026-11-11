"""Navigation and search.

The 404 page's sidebar read "0 1 2 3 4". A sidebar group label was a link
to its first page ("Handhelds and TV boxes" opened AmberELEC), and a crumb
linked a sibling page. Emulators sat three levels deep under "D to F / D".
Previous and next ran from Sony to Sord and from one tab into another,
and disagreed with the page's own "Next" list. The Reference tab was a flat
list of fifteen. These tests read the generator and, where it is built,
the site.

"playstation bios" found five setups' lists for the console before its own
page: the pages a setup's list moves a console to weighed 1.5, three times a
reference page. The file names a system page holds were the text of a hidden
span, so the search showed them as the excerpt. Start here looped: First
install's "Next steps" pointed back to Get your files, Is it legal? to Common
questions, and both pages had the same page as previous and next. A part
page had no crumb to the page it belongs to and nothing marked in the
sidebar. "psx" or "dc" found nothing, though every platform files the
console under that name. These tests read the generator and, where they
are built, the pages and the site.
"""
from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import re
import struct
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
import ast
from html import unescape

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site  # noqa: E402
import sitestarlight  # noqa: E402
from common import (  # noqa: E402
    list_registered_platforms,
    load_platform_config,
    load_platform_registry,
)

DIST = REPO_ROOT / "website" / "dist"
ROUTE = REPO_ROOT / "website" / "src" / "routeData.ts"
TAB_ROOTS = {"/retrobios/", "/retrobios/platforms/", "/retrobios/explore/",
             "/retrobios/wiki/", "/retrobios/contributing/"}
def _nav() -> list:
    platforms = REPO_ROOT / "platforms"
    registry = load_platform_registry(str(platforms))
    coverages = {
        key: {"platform": load_platform_config(key, str(platforms))["platform"]}
        for key in list_registered_platforms(str(platforms))
    }
    manufacturers = {"Sony": {}, "Sega": {}, "ScummVM": {}}
    profiles = {
        "duckstation": {"emulator": "DuckStation", "systems": ["sony-playstation"]},
        "dolphin": {"emulator": "Dolphin", "systems": ["nintendo-gamecube"]},
        "mame": {"emulator": "MAME", "systems": ["arcade"]},
    }
    return generate_site.generate_nav(coverages, manufacturers, profiles, registry)
def _targets(value: object) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return set().union(*(_targets(v) for v in value)) if value else set()
    return set().union(*(_targets(v) for v in value.values()))
def _present(nav: list) -> set[str]:
    return {t for t in _targets(nav) if not t.startswith("http")}

from siteguides import DEVICE_GROUPS  # noqa: E402


def _index_anchors(markdown: str) -> set[str]:
    """The heading ids a generated page carries once written."""
    _title, title_id, body = sitestarlight.split_title(markdown)
    return sitestarlight.heading_ids(sitestarlight.pin_heading_ids(body, title_id))


ANCHORS = {
    "platforms/index.md": {sitestarlight.toc_slug(label) for label, _ in DEVICE_GROUPS.values()},
    "systems/index.md": {"consoles-and-computers"},
    "emulators/index.md": _index_anchors(generate_site.generate_emulators_index({
        "duckstation": {"emulator": "DuckStation", "systems": ["sony-playstation"]},
        "dolphin": {"emulator": "Dolphin", "systems": ["nintendo-gamecube"]},
        "mame": {"emulator": "MAME", "systems": ["arcade"]},
    })),
}


class NotFoundPage(unittest.TestCase):
    def test_the_404_opens_on_the_first_tab(self):
        side = sitestarlight.sidebar(_nav(), _present(_nav()), ANCHORS)
        self.assertNotIn("/404", side["options"]["exclude"])
        self.assertIn("/404", side["options"]["topics"]["start-here"])

    def test_the_404_has_no_contents_no_index_and_no_structured_data(self):
        _target, text = sitestarlight.finalize_page(
            "404.md", "# Page not found\n\nGone.\n", level="", weight=None,
            browser_title="Page not found", description="d",
            structured={"@type": "TechArticle"}, terms={})
        front = generate_site._front_matter(text)
        self.assertIs(front["tableOfContents"], False)
        self.assertIs(front["prev"], False)
        self.assertIs(front["next"], False)
        self.assertIn({"tag": "meta", "attrs": {"name": "robots", "content": "noindex"}}, front["head"])
        self.assertNotIn("ld+json", text)


class GroupsAreGroups(unittest.TestCase):
    def setUp(self):
        nav = _nav()
        self.side = sitestarlight.sidebar(nav, _present(nav), ANCHORS)
        self.groups = self.side["groups"]

    def test_setup_groups_stay_groups_and_point_at_their_section(self):
        setup = {key: value for key, value in self.groups.items() if key.startswith("Setups/")}
        self.assertTrue(setup)
        for key, group in setup.items():
            with self.subTest(group=key):
                self.assertFalse(group["prune"])
                self.assertTrue(group["href"].startswith("/retrobios/platforms/#"), group["href"])

    def test_explore_groups_collapse_to_their_overview(self):
        explore = {key: value for key, value in self.groups.items() if key.startswith("Explore/")}
        self.assertEqual(explore["Explore/Systems"],
                         {"href": "/retrobios/systems/", "prune": True, "crumb": True})
        self.assertEqual(explore["Explore/Systems/Consoles and computers"]["href"],
                         "/retrobios/systems/#consoles-and-computers")
        self.assertEqual(explore["Explore/Emulators/D"],
                         {"href": "/retrobios/emulators/#d", "prune": True, "crumb": False})

    def test_no_group_points_at_one_of_its_own_pages(self):
        """The overview a group opens on is its own index page or a section of
        the page above it, never the first page it lists."""
        overview_pages = {sitestarlight.page_url(rel) for rel in _present(_nav())
                          if rel == "index.md" or rel.endswith("/index.md") or rel == "explore.md"}
        for key, group in self.groups.items():
            if not group["href"]:
                continue
            with self.subTest(group=key):
                self.assertTrue("#" in group["href"] or group["href"] in overview_pages, group["href"])

    def test_the_middleware_reads_the_groups_not_the_first_link(self):
        route = ROUTE.read_text(encoding="utf-8")
        self.assertNotIn("firstLink", route)
        self.assertIn("sidebar.groups", route)
        self.assertIn("sidebar.reading", route)


class EmulatorsOneLevelDeep(unittest.TestCase):
    def test_initials_hold_pages_not_groups(self):
        nav = generate_site._emulator_nav({
            "duckstation": {"emulator": "DuckStation", "systems": ["s"]},
            "dolphin": {"emulator": "Dolphin", "systems": ["s"]},
        })
        self.assertEqual(nav, ["emulators/index.md", {"D": [
            {"Dolphin": "emulators/dolphin.md"}, {"DuckStation": "emulators/duckstation.md"}]}])

    def test_every_initial_has_its_section_on_the_index(self):
        """A letter in the sidebar lands on the section of that letter."""
        from common import load_emulator_profiles

        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        anchors = _index_anchors(generate_site.generate_emulators_index(profiles))
        for group in generate_site._emulator_nav(profiles)[1:]:
            (label, _pages), = group.items()
            with self.subTest(initial=label):
                self.assertIn(sitestarlight.toc_slug(label), anchors)

    def test_every_initial_holds_pages(self):
        from common import load_emulator_profiles

        nav = generate_site._emulator_nav(load_emulator_profiles(str(REPO_ROOT / "emulators")))
        for group in nav[1:]:
            (label, pages), = group.items()
            with self.subTest(initial=label):
                self.assertTrue(all(isinstance(next(iter(p.values())), str) for p in pages))


class OneNextPerPage(unittest.TestCase):
    def setUp(self):
        nav = _nav()
        self.runs = sitestarlight.sidebar(nav, _present(nav), ANCHORS)["reading"]
        self.links = [[entry["link"] for entry in run] for run in self.runs]

    def test_start_here_runs_into_your_setup_and_stops(self):
        first = self.links[0]
        self.assertEqual(first[0], "/retrobios/")
        self.assertIn("/retrobios/platforms/", first)
        self.assertNotIn("/retrobios/explore/", first)

    def test_each_other_tab_is_read_on_its_own(self):
        starts = [run[0] for run in self.links]
        self.assertEqual(starts, ["/retrobios/", "/retrobios/explore/", "/retrobios/wiki/",
                                  "/retrobios/contributing/"])

    def test_system_emulator_and_platform_pages_are_not_in_the_reading(self):
        for link in (link for run in self.links for link in run):
            with self.subTest(link=link):
                self.assertNotRegex(link, r"^/retrobios/(systems|emulators|platforms)/[^/]+/$")

    def test_an_overview_is_named_after_what_it_opens(self):
        labels = {entry["link"]: entry["label"] for run in self.runs for entry in run}
        self.assertEqual(labels["/retrobios/platforms/"], "Setups")
        self.assertEqual(labels["/retrobios/systems/"], "Systems")
        self.assertNotIn("Overview", labels.values())

    def test_card_pages_turn_pagination_off(self):
        for rel in ("systems/sony.md", "emulators/duckstation.md", "platforms/batocera.md"):
            _target, text = sitestarlight.finalize_page(
                rel, "# T\n\nBody.\n", level="explore", weight=None, browser_title="T",
                description="d", structured={}, terms={})
            front = generate_site._front_matter(text)
            with self.subTest(page=rel):
                self.assertIs(front["prev"], False)
                self.assertIs(front["next"], False)

    def test_the_next_link_is_the_first_of_next_steps(self):
        body = ("# Troubleshooting\n\nText.\n\n## Next steps\n\n"
                "- [Common questions](faq.md)\n- [Glossary](glossary.md)\n")
        _target, text = sitestarlight.finalize_page(
            "wiki/troubleshooting.md", body, level="start", weight=None,
            browser_title="Troubleshooting", description="d", structured={}, terms={})
        front = generate_site._front_matter(text)
        self.assertEqual(front["next"], {"link": "/retrobios/wiki/faq/", "label": "Common questions"})

    def test_a_page_without_next_steps_keeps_the_reading_order(self):
        _target, text = sitestarlight.finalize_page(
            "wiki/faq.md", "# FAQ\n\nText.\n", level="start", weight=None,
            browser_title="FAQ", description="d", structured={}, terms={})
        self.assertNotIn("next", generate_site._front_matter(text))


class ReferenceGrouped(unittest.TestCase):
    def _reference(self, wiki: Path | None = None) -> list:
        nav = generate_site.generate_nav({}, {}, {}, {}, wiki)
        return next(tab["Reference"] for tab in nav if "Reference" in tab)

    def test_checking_files_opens_on_find_a_file(self):
        reference = self._reference()
        groups = {next(iter(item)): next(iter(item.values())) for item in reference
                  if isinstance(item, dict) and isinstance(next(iter(item.values())), list)}
        self.assertEqual(groups["Checking files"][0], {"Find or check a file": "files/index.md"})
        self.assertIn({"What the packs do not hold": "gaps.md"}, groups["Checking files"])
        self.assertEqual(groups["Data"][:3], [{"Data and API": "data.md"},
                                              {"Data model": "wiki/data-model.md"},
                                              {"Updated platform files": "exports.md"}])
        self.assertEqual(reference[0], "wiki/index.md")

    def test_a_wiki_page_joins_a_group_from_its_front_matter(self):
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            wiki = Path(tmp)
            (wiki / "index.md").write_text("---\nlevel: reference\norder: 0\n---\n# Reference\n")
            (wiki / "modes.md").write_text(
                "---\nlevel: reference\norder: 10\ngroup: Checking files\n---\n# How each platform checks files\n")
            reference = self._reference(wiki)
        group = next(item["Checking files"] for item in reference
                     if isinstance(item, dict) and "Checking files" in item)
        self.assertEqual(group[:2], [{"Find or check a file": "files/index.md"},
                                     {"How each platform checks files": "wiki/modes.md"}])


class Redirects(unittest.TestCase):
    def test_core_names_lead_to_their_profile(self):
        profiles = {
            "beetle_psx": {"cores": ["mednafen_psx", "beetle_psx", "Beetle PSX"]},
            "a": {"cores": ["shared"]},
            "b": {"cores": ["shared", "dolphin"]},
            "dolphin": {"cores": []},
        }
        present = {"emulators/beetle_psx.md", "emulators/a.md", "emulators/b.md",
                   "emulators/dolphin.md", "which-pack.md"}
        self.assertEqual(sitestarlight.redirects(profiles, present), {
            "/emulators/mednafen_psx/": "/emulators/beetle_psx/",
            "/wiki/getting-started/": "/which-pack/",
        })

    def test_an_alias_profile_leads_to_the_profile_it_names(self):
        # Search Console found emulators/vba_m/ gone: vba_m is an alias of vbam.
        profiles = {"vba_m": {"type": "alias", "alias_of": "vbam"}, "vbam": {"cores": []},
                    "orphan": {"type": "alias", "alias_of": "nowhere"}}
        present = {"emulators/vbam.md", "which-pack.md", "wiki/getting-started.md"}
        self.assertEqual(sitestarlight.redirects(profiles, present),
                         {"/emulators/vba_m/": "/emulators/vbam/"})

    def test_a_moved_page_redirects_only_once_its_source_is_gone(self):
        present = {"wiki/getting-started.md", "which-pack.md"}
        self.assertEqual(sitestarlight.redirects({}, present), {})

    def test_the_generator_writes_the_file(self):
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        self.assertIn('generated / "redirects.json"', source)

    def test_a_list_part_gone_with_its_rows_redirects_to_its_page(self):
        """Only platform parts were recorded: gaps-files-to-source-7, gone
        once 29 files were collected, ended on the 404 page."""
        with tempfile.TemporaryDirectory() as tmp:
            docs = Path(tmp)
            part = '---\nlevel: reference\nparent:\n  label: "Gaps"\n  link: "/gaps/"\n---\n\n# P\n'
            (docs / "gaps-files-to-source-7.md").write_text(part, encoding="utf-8")
            (docs / "gaps.md").write_text("# Gaps\n", encoding="utf-8")
            kept = {"platforms/b-atari-st.md": "platforms/b.md#atari-st"}
            published = generate_site.record_parts(
                docs, {"gaps-files-to-source-7.md", "gaps.md"}, kept)
        self.assertEqual(published, {"gaps-files-to-source-7.md": "gaps.md", **kept})
        # An emulator part names its parent with the site's base.
        self.assertEqual(generate_site._parent_page("/retrobios/emulators/amiberry/"),
                         "emulators/amiberry.md")
        self.assertEqual(generate_site._parent_page("/platforms/b/#atari-st"),
                         "platforms/b.md#atari-st")
        # The next run made six parts.
        self.assertEqual(
            sitestarlight.redirects({}, {"gaps.md", "platforms/b.md"}, published),
            {"/gaps-files-to-source-7/": "/gaps/", "/platforms/b-atari-st/": "/platforms/b/#atari-st"})


class PlatformShareCards(unittest.TestCase):
    def test_every_platform_page_shares_its_own_card(self):
        for key in list_registered_platforms(str(REPO_ROOT / "platforms")):
            with self.subTest(platform=key):
                card = REPO_ROOT / "docs_assets" / "og" / "platforms" / f"{key}.png"
                data = card.read_bytes()
                self.assertEqual(struct.unpack(">II", data[16:24]), (1200, 630))
                self.assertEqual(sitestarlight.og_image(f"platforms/{key}.md", "setup"),
                                 f"{sitestarlight.SITE_URL}assets/og/platforms/{key}.png")

    def test_other_pages_keep_their_section_card(self):
        self.assertEqual(sitestarlight.og_image("platforms/index.md", "setup"),
                         f"{sitestarlight.SITE_URL}assets/og/setup.png")
        # A manufacturer page has its own card. One
        # without a rendered card keeps its section's.
        self.assertEqual(sitestarlight.og_image("systems/sony.md", "explore"),
                         f"{sitestarlight.SITE_URL}assets/og/systems/sony.png")
        self.assertEqual(sitestarlight.og_image("systems/no-such-maker.md", "explore"),
                         f"{sitestarlight.SITE_URL}assets/og/explore.png")

    def test_an_emulator_page_shares_its_makers_card(self):
        """Every emulator page shared the generic Explore card."""
        saved = dict(sitestarlight.EMULATOR_CARDS)
        self.addCleanup(lambda: (sitestarlight.EMULATOR_CARDS.clear(),
                                 sitestarlight.EMULATOR_CARDS.update(saved)))
        sitestarlight.EMULATOR_CARDS.update({"emulators/mgba": "nintendo", "emulators/odd": "no-such-maker"})
        self.assertEqual(sitestarlight.og_image("emulators/mgba.mdx", "explore"),
                         f"{sitestarlight.SITE_URL}assets/og/systems/nintendo.png")
        self.assertEqual(sitestarlight.og_image("emulators/odd.md", "explore"),
                         f"{sitestarlight.SITE_URL}assets/og/explore.png")

    def test_a_shared_link_reads_the_search_title(self):
        """og:title was the H1, "mGBA", under a result titled "mGBA BIOS files"."""
        head = sitestarlight.page_head("emulators/mgba.md", "explore", "mGBA", "mGBA BIOS files", {})
        shared = {tag["attrs"].get("property") or tag["attrs"].get("name"): tag["attrs"]["content"]
                  for tag in head if tag.get("attrs", {}).get("content") and tag["tag"] == "meta"}
        self.assertEqual(shared["og:title"], "mGBA BIOS files")
        self.assertEqual(shared["twitter:title"], "mGBA BIOS files")
        plain = sitestarlight.page_head("wiki/faq.md", "start", "FAQ", "FAQ", {})
        self.assertFalse(any(tag.get("attrs", {}).get("property") == "og:title" for tag in plain))



# The built site


class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.where: list[str] = []
        self.sidebar: list[str] = []
        self.crumbs: list[str | None] = []
        self.pagination = False
        self._sidebar = 0
        self._crumbs = 0
        self._text: list[str] | None = None
        self._pagination = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        a = dict(attrs)
        if tag == "nav" and a.get("aria-label") == "Breadcrumb":
            self._crumbs = 1
        elif self._crumbs and tag == "a":
            self.crumbs.append(a.get("href"))
        if "sidebar-content" in (a.get("class") or ""):
            self._sidebar = 1
        elif self._sidebar and tag in ("a", "summary"):
            self._text = []
        if "pagination-links" in (a.get("class") or ""):
            self._pagination = True
        elif self._pagination and tag == "a":
            self.pagination = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "nav" and self._crumbs:
            self._crumbs = 0
        if tag == "nav" and self._pagination and not self.pagination:
            self._pagination = False
        if self._text is not None and tag in ("a", "summary"):
            self.sidebar.append(" ".join("".join(self._text).split()))
            self._text = None

    def handle_data(self, data: str) -> None:
        if self._text is not None:
            self._text.append(data)


def _read(path: Path) -> _Page:
    page = _Page()
    page.feed(path.read_text(encoding="utf-8"))
    return page


@unittest.skipUnless((DIST / "index.html").is_file(), "site not built")
class BuiltNavigation(unittest.TestCase):
    def test_the_404_sidebar_names_pages(self):
        page = _read(DIST / "404.html")
        self.assertTrue(page.sidebar)
        self.assertFalse([label for label in page.sidebar if re.fullmatch(r"\d+", label)],
                         page.sidebar)

    def test_crumbs_link_a_tab_an_overview_or_a_section(self):
        overviews = TAB_ROOTS | {"/retrobios/systems/", "/retrobios/emulators/"}
        pages = [DIST / rel for rel in (
            "platforms/batocera/index.html", "platforms/retroarch/index.html",
            "systems/sony/index.html", "emulators/duckstation/index.html",
            "wiki/verification-modes/index.html", "files/index.html")]
        for path in pages:
            if not path.is_file():
                continue
            for href in _read(path).crumbs:
                with self.subTest(page=str(path.relative_to(DIST)), href=href):
                    self.assertTrue(href in overviews or "#" in (href or ""), href)

    def test_a_setup_page_names_its_group(self):
        page = _read(DIST / "platforms" / "batocera" / "index.html")
        self.assertEqual(len(page.crumbs), 2, page.crumbs)

    def test_card_pages_have_no_previous_or_next(self):
        for rel in ("systems/sony/index.html", "emulators/duckstation/index.html",
                    "platforms/batocera/index.html"):
            with self.subTest(page=rel):
                self.assertFalse(_read(DIST / rel).pagination)
        self.assertTrue(_read(DIST / "wiki" / "faq" / "index.html").pagination)

    def test_the_redirects_file_is_written(self):
        data = json.loads((REPO_ROOT / "website" / "src" / "generated" / "redirects.json")
                          .read_text(encoding="utf-8"))
        self.assertEqual(data.get("/emulators/mednafen_psx/"), "/emulators/beetle_psx/")


SEARCH_GATE = REPO_ROOT / "website" / "tools" / "search_gate.py"
DOCS = REPO_ROOT / "website" / "src" / "content" / "docs"

CONTENT_CONFIG = REPO_ROOT / "website" / "src" / "content.config.ts"
START_HERE = [
    "/retrobios/", "/retrobios/wiki/what-are-bios-files/", "/retrobios/which-pack/",
    "/retrobios/wiki/first-install/", "/retrobios/wiki/troubleshooting/",
    "/retrobios/wiki/faq/", "/retrobios/wiki/legal/", "/retrobios/wiki/glossary/",
    "/retrobios/wiki/privacy/", "/retrobios/platforms/",
]


def _front(text: str) -> str:
    end = text.find("\n---\n", 4)
    return text[4:end] if text.startswith("---\n") and end != -1 else ""


def _moved_platform_pages() -> list[Path]:
    platforms = set(list_registered_platforms(str(REPO_ROOT / "platforms")))
    folder = DOCS / "platforms"
    if not folder.is_dir():
        return []
    # A guide page sits beside the setups (platforms/linux-handhelds) without
    # being a list moved off one of them.
    from siteguides import HANDHELD_GUIDE  # noqa: PLC0415

    guides = {Path(HANDHELD_GUIDE.path).stem} if HANDHELD_GUIDE else set()
    return [path for path in sorted(folder.glob("*.md*"))
            if path.stem not in platforms and path.stem != "index" and path.stem not in guides]


class MetaFields(unittest.TestCase):
    def test_file_names_are_an_attribute_not_text(self) -> None:
        body = ('<h3 class="rb-file-title"><code>scph5501.bin</code></h3>'
                '<h3 class="rb-file-title"><code>a,b.bin</code></h3>')
        meta = sitestarlight.file_names_meta(body)
        # Each name as its parts, each part once.
        self.assertIn('data-pagefind-meta="files:a b bin scph5501"', meta)
        self.assertRegex(meta, r"<span [^>]*hidden></span>")

    def test_a_field_escapes_its_value(self) -> None:
        meta = sitestarlight.search_field("aliases", ['a"b', "c&d"])
        self.assertIn('data-pagefind-meta="aliases:a&quot;b c&amp;d"', meta)

    def test_an_empty_field_writes_nothing(self) -> None:
        self.assertEqual(sitestarlight.search_field("aliases", []), "")
        self.assertEqual(sitestarlight.file_names_meta("<p>no card</p>"), "")

    def test_system_pages_carry_the_platforms_names(self) -> None:
        page = DOCS / "systems" / "sony-playstation.md"
        if not page.is_file():
            self.skipTest("site pages not generated")
        text = page.read_text(encoding="utf-8")
        match = re.search(r'data-pagefind-meta="aliases:([^"]*)"', text)
        self.assertIsNotNone(match, "no aliases field on the PlayStation page")
        self.assertIn("psx", unescape(match[1]).split())
        # The Dreamcast section's page: its own, or Sega's when it fits there.
        own = DOCS / "systems" / "sega-dreamcast.md"
        dreamcast = (own if own.is_file() else DOCS / "systems" / "sega.md").read_text(
            encoding="utf-8")
        self.assertRegex(dreamcast, r'data-pagefind-meta="aliases:[^"]*\bdc\b')


class SystemPartsSitUnderTheirMaker(unittest.TestCase):
    """The crumbs say where a system part sits, read from its parent: field.
    The "Part of" line under them said it again."""

    def test_every_part_names_its_maker_as_parent(self) -> None:
        pages = sorted((DOCS / "systems").glob("*.md"))
        if not pages:
            self.skipTest("site pages not generated")
        makers = {page.stem for page in pages}
        orphans = []
        for page in pages:
            text = page.read_text(encoding="utf-8")
            front = text.split("\n---\n", 1)[0]
            parent = re.search(r"^parent:\n  label: .+\n  link: /retrobios/systems/([a-z0-9-]+)/$",
                               front, re.M)
            if parent is None:
                continue
            if parent[1] not in makers:
                orphans.append(page.name)
            self.assertNotIn("\nPart of [", text, page.name)
        self.assertEqual(orphans, [])


class MovedPlatformPages(unittest.TestCase):
    def test_a_setups_list_for_one_console_is_a_reference(self) -> None:
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        block = source[source.index("for stem, page in moved.items():"):]
        block = block[: block.index("PAGE_DATA[f\"platforms/{name}.md\"]")]
        self.assertIn('SEARCH_DEMOTED.add(f"platforms/{stem}.md")', block)
        self.assertIn('level="reference"', block)
        self.assertIn('search="exclude"', block)
        self.assertIn("parent=", block)

    def test_generated_pages_weigh_as_references_and_name_their_setup(self) -> None:
        pages = _moved_platform_pages()
        if not pages:
            self.skipTest("site pages not generated")
        for path in pages:
            front = _front(path.read_text(encoding="utf-8"))
            with self.subTest(page=path.name):
                self.assertIn("\nlevel: reference\n", f"\n{front}\n")
                self.assertIn("\nsearchWeight: 0.5\n", f"\n{front}\n")
                # The title alone was indexed, and it outranked the console.
                self.assertIn("\npagefind: false\n", f"\n{front}\n")
                self.assertRegex(front, r"parent:\n  label: .+\n  link: /retrobios/platforms/[a-z0-9_-]+/\n")

    def test_parent_link_resolves_against_the_page(self) -> None:
        _target, text = sitestarlight.finalize_page(
            "platforms/retroarch-sony-playstation.md", "# RetroArch: Sony PlayStation\n\nBody.\n",
            level="reference", weight=0.5, browser_title="x", description="d",
            structured={}, terms={}, parent={"label": "RetroArch", "link": "retroarch.md"},
        )
        self.assertIn("parent:\n  label: RetroArch\n  link: /retrobios/platforms/retroarch/\n", text)

    def test_the_schema_accepts_parent(self) -> None:
        self.assertRegex(CONTENT_CONFIG.read_text(encoding="utf-8"),
                         r"parent: z\.object\(\{ label: z\.string\(\), link: z\.string\(\) \}\)")


class ArcadeGroup(unittest.TestCase):
    def test_arcade_is_not_a_console_or_computer(self) -> None:
        nav = generate_site._system_nav({"Sony": {}, "Arcade": {}, "Sega": {}})
        groups = {next(iter(entry)): entry[next(iter(entry))] for entry in nav if isinstance(entry, dict)}
        self.assertEqual(groups["Arcade"], [{"Arcade": "systems/arcade.md"}])
        self.assertNotIn({"Arcade": "systems/arcade.md"}, groups["Consoles and computers"])


class RouteMiddleware(unittest.TestCase):
    def test_next_steps_link_is_kept_only_forward(self) -> None:
        source = ROUTE.read_text(encoding="utf-8")
        self.assertIn("target <= position", source)

    def test_parent_is_a_crumb_and_marked(self) -> None:
        source = ROUTE.read_text(encoding="utf-8")
        self.assertIn("route.entry.data.parent", source)
        self.assertIn("markCurrent(route.sidebar", source)


def _gate_queries() -> dict:
    """The search gate's QUERIES, read from its source: the tool is run
    with node beside it, not imported as a package."""
    tree = ast.parse(SEARCH_GATE.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "QUERIES":
            return ast.literal_eval(node.value)
    raise AssertionError("no QUERIES in search_gate.py")


class SearchGateQueries(unittest.TestCase):
    def test_the_audits_queries_are_gated(self) -> None:
        for query in ("playstation bios", "dreamcast bios", "neo geo bios", "bios not found",
                      "offline install", "r36s", "wonderswan color", "dc bios missing",
                      "which mame version", "psx bios"):
            self.assertIn(query, _gate_queries())

    def test_prefixes_match_a_consoles_own_page(self) -> None:
        pages, _rank = _gate_queries()["playstation bios"]
        self.assertTrue(any("systems/sony-playstation/".startswith(p) for p in pages))


def _html(url: str) -> str:
    rel = url[len("/retrobios/"):]
    path = DIST / rel / "index.html"
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _pagination(text: str) -> tuple[str | None, str | None]:
    start = text.find('<nav class="pagination-links')
    if start == -1:
        return None, None
    links = text[start:text.find("</footer>", start)]
    prev = re.search(r'<a href="([^"]+)"[^>]*rel="prev"', links)
    nxt = re.search(r'<a href="([^"]+)"[^>]*rel="next"', links)
    return (prev[1] if prev else None), (nxt[1] if nxt else None)


@unittest.skipUnless((DIST / "index.html").is_file(), "site not built")
class BuiltSearchAndCrumbs(unittest.TestCase):
    def test_next_from_home_reads_start_here_once(self) -> None:
        seen, url = [], "/retrobios/"
        while url and url not in seen and len(seen) < 20:
            seen.append(url)
            url = _pagination(_html(url))[1]
        self.assertEqual(seen[: len(START_HERE)], START_HERE)
        self.assertEqual(len(seen), len(set(seen)))

    def test_no_page_has_the_same_previous_and_next(self) -> None:
        same = []
        for path in DIST.rglob("index.html"):
            prev, nxt = _pagination(path.read_text(encoding="utf-8"))
            if prev and prev == nxt:
                same.append(str(path.relative_to(DIST)))
        self.assertEqual(same, [])

    def test_search_fields_hold_no_text(self) -> None:
        texts = []
        for path in (DIST / "systems").rglob("index.html"):
            # The search fields are attributes on empty spans. The title
            # meta reads the visible h1.
            for match in re.finditer(r'<(\w+)[^>]*data-pagefind-meta="(?:files|aliases|devices|consoles|terms):'
                                     r'[^>]*>([^<]*)</\1>',
                                     path.read_text(encoding="utf-8")):
                if match[2].strip():
                    texts.append(str(path.relative_to(DIST)))
        self.assertEqual(texts, [])

    def test_a_setups_console_page_names_its_setup(self) -> None:
        text = _html("/retrobios/platforms/retroarch-sony-playstation/")
        if not text:
            self.skipTest("no RetroArch PlayStation page")
        crumbs = re.search(r'<nav[^>]*class="[^"]*rb-breadcrumbs[^"]*"[^>]*>(.*?)</nav>', text, re.S)
        self.assertIsNotNone(crumbs)
        self.assertIn('href="/retrobios/platforms/retroarch/"', crumbs[1])
        self.assertRegex(text, r'<a href="/retrobios/platforms/retroarch/"[^>]*aria-current="page"')


if __name__ == "__main__":
    unittest.main()
