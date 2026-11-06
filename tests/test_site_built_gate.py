"""The merged site, read from the built site (website/dist).

Each part of the site is checked on its own elsewhere. These checks hold
the merged site to what they fix: no sidebar label a number, no
"Next" tip, a sidebar label that is the page's own title, a card's link icon
kept out of the heading a search indexes, crumbs that lead to a tab or a
section, phone tables stacked where the reading level asks for it, and every
page under 15,000 elements and 600 KB of HTML. Items that cross pages
are held too: the platform logo beside the title, a section for every
letter of the emulators index, system links to the section of the system's
own name, dates in words and the moved getting-started page.

Skips when the site is not built.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import re
import sys
import unittest
from html import unescape
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

DIST = REPO_ROOT / "website" / "dist"
DOCS = REPO_ROOT / "website" / "src" / "content" / "docs"
SIDEBAR = REPO_ROOT / "website" / "src" / "generated" / "sidebar.json"
BASE = "/retrobios/"

PAGE_BYTES = 600_000
PAGE_ELEMENTS = 15_000
PHONE_COLUMN = 358
READER_LEVELS = {"start", "setup"}
# The size from which a table is a list scanned by column and keeps its
# scroll (website/src/plugins/rehype-stack-tables.mjs, RECORD_ROWS).
RECORD_ROWS = 20

_SCRIPT = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.S | re.I)
_ELEMENT = re.compile(r"<[a-zA-Z][a-zA-Z0-9-]*[\s/>]")
_TAGS = re.compile(r"<[^>]+>")
_TABLE = re.compile(r"<table\b(?P<attrs>[^>]*)>(?P<body>.*?)</table>", re.S)
_CURRENT = re.compile(r'<a\b[^>]*aria-current="page"[^>]*>(?P<label>.*?)</a>', re.S)
_CURRENT_HREF = re.compile(r'<a\b(?=[^>]*aria-current="page")[^>]*href="(?P<href>[^"]*)"', re.S)


def _marked_parent(html: str, url: str) -> str | None:
    """The page a part page names as its parent. The sidebar marks that page
    instead of the part, and the last crumb leads to it."""
    found = _CURRENT_HREF.search(html.split('id="starlight__sidebar"', 1)[-1])
    if found and found["href"].rstrip("/") != url.rstrip("/"):
        return found["href"]
    return None
_H1 = re.compile(r"<h1\b[^>]*>(?P<title>.*?)</h1>", re.S)
_HEADING = re.compile(r"<h(?P<level>[2-6])\b[^>]*>(?P<inner>.*?)</h(?P=level)>", re.S)
_CRUMBS = re.compile(r'<nav\b[^>]*aria-label="Breadcrumb"[^>]*>(?P<inner>.*?)</nav>', re.S)
_HREF = re.compile(r'href="(?P<href>[^"]*)"')
_TIP = re.compile(r'<aside\b[^>]*starlight-aside--tip[^>]*>.*?</aside>', re.S)


def _text(markup: str) -> str:
    return " ".join(unescape(_TAGS.sub(" ", markup)).split())


def _pages() -> list[Path]:
    return sorted(DIST.rglob("*.html"))


def _url(path: Path) -> str:
    rel = path.relative_to(DIST).as_posix()
    if rel.endswith("index.html"):
        return BASE + rel[: -len("index.html")]
    return BASE + rel


def _levels() -> dict[str, str]:
    """Page address -> the level its front matter declares."""
    levels: dict[str, str] = {}
    for source in DOCS.rglob("*.md*"):
        text = source.read_text(encoding="utf-8")
        if not text.startswith("---\n"):
            continue
        front = yaml.safe_load(text[4:text.find("\n---\n", 4)]) or {}
        stem = str(front.get("slug") or source.relative_to(DOCS).with_suffix("").as_posix())
        stem = re.sub(r"(^|/)index$", "", stem)
        levels[BASE + (stem + "/" if stem else "")] = str(front.get("level") or "")
    return levels


@unittest.skipUnless((DIST / "index.html").is_file(), "site not built")
class EveryBuiltPage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.pages = {path: path.read_text(encoding="utf-8") for path in _pages()}
        sidebar = json.loads(SIDEBAR.read_text(encoding="utf-8"))
        cls.tab_roots = {BASE + topic["link"].strip("/") + ("/" if topic["link"].strip("/") else "")
                         for topic in sidebar["topics"]}
        cls.group_pages = {group["href"] for group in sidebar["groups"].values() if group["href"]}
        cls.levels = _levels()

    def test_under_the_page_budgets(self):
        heavy, crowded = [], []
        for path, html in self.pages.items():
            size = len(html.encode("utf-8"))
            if size >= PAGE_BYTES:
                heavy.append((path.relative_to(DIST).as_posix(), size))
            elements = len(_ELEMENT.findall(_SCRIPT.sub("", html)))
            if elements >= PAGE_ELEMENTS:
                crowded.append((path.relative_to(DIST).as_posix(), elements))
        self.assertFalse(heavy, f"pages of {PAGE_BYTES:,} bytes or more")
        self.assertFalse(crowded, f"pages of {PAGE_ELEMENTS:,} elements or more")

    def test_no_sidebar_label_is_a_number(self):
        for path, html in self.pages.items():
            sidebar = html.split('id="starlight__sidebar"', 1)[-1].split("</nav>", 1)[0]
            labels = [_text(m) for m in re.findall(r"<a\b[^>]*>(.*?)</a>", sidebar, re.S)]
            numbers = [label for label in labels if re.fullmatch(r"\d+", label)]
            with self.subTest(page=path.relative_to(DIST).as_posix()):
                self.assertFalse(numbers)

    def test_no_tip_titled_next(self):
        for path, html in self.pages.items():
            for aside in _TIP.findall(html):
                title = re.search(r'class="starlight-aside__title"[^>]*>(.*?)</p>', aside, re.S)
                with self.subTest(page=path.relative_to(DIST).as_posix()):
                    self.assertNotEqual(_text(title[1]) if title else "", "Next")

    def test_the_sidebar_names_a_page_by_its_title(self):
        for path, html in self.pages.items():
            url = _url(path)
            current = _CURRENT.search(html.split('id="starlight__sidebar"', 1)[-1])
            title = _H1.search(html)
            # A tab, or a group of the sidebar, opens on its overview.
            if url in self.tab_roots or url in self.group_pages or not current or not title:
                continue
            if _marked_parent(html, url):
                continue
            with self.subTest(page=url):
                self.assertEqual(_text(current["label"]), _text(title["title"]))

    def test_a_card_link_icon_says_nothing_in_its_heading(self):
        for path, html in self.pages.items():
            for heading in _HEADING.finditer(html):
                for link in re.findall(r'<a\b[^>]*class="rb-permalink"[^>]*>(.*?)</a>',
                                       heading["inner"], re.S):
                    with self.subTest(page=path.relative_to(DIST).as_posix()):
                        self.assertEqual(_text(link), "")

    def test_every_crumb_leads_to_a_tab_or_a_section(self):
        for path, html in self.pages.items():
            crumbs = _CRUMBS.search(html)
            if not crumbs:
                continue
            parent = _marked_parent(html, _url(path))
            for href in _HREF.findall(crumbs["inner"]):
                with self.subTest(page=_url(path), href=href):
                    self.assertTrue(href in self.tab_roots or href in self.group_pages
                                    or "#" in href or href == parent, href)

    def test_phone_tables_on_reader_pages_are_stacked(self):
        """A table of three columns or more, under RECORD_ROWS rows, on a
        level 0 or 1 page is read one row at a time on a phone: it carries
        data-rb-stack. A two-column table is a list of label and value."""
        unstacked = []
        for path, html in self.pages.items():
            if self.levels.get(_url(path)) not in READER_LEVELS:
                continue
            for table in _TABLE.finditer(html):
                head = table["body"].split("</thead>", 1)[0]
                columns = head.count("<th")
                rows = table["body"].split("</thead>", 1)[-1].count("<tr")
                # A table the page fills when it runs (the file picker) is
                # not the build's.
                if not rows:
                    continue
                if columns >= 2 and rows < RECORD_ROWS and "data-rb-stack" not in table["attrs"]:
                    unstacked.append((_url(path), _text(head)[:60]))
        self.assertFalse(unstacked)

    def test_no_page_dates_itself_with_a_raw_stamp(self):
        for path, html in self.pages.items():
            with self.subTest(page=_url(path)):
                self.assertNotIn("Generated on", html)


@unittest.skipUnless((DIST / "index.html").is_file(), "site not built")
class TheIntegrationItems(unittest.TestCase):

    def test_a_platform_page_draws_its_logo_beside_the_title(self):
        from common import load_platform_registry

        registry = load_platform_registry(str(REPO_ROOT / "platforms"))
        with_logo = [key for key, entry in registry.items() if entry.get("logo")]
        self.assertTrue(with_logo)
        for key in with_logo:
            page = DIST / "platforms" / key / "index.html"
            if not page.is_file():
                continue
            html = page.read_text(encoding="utf-8")
            with self.subTest(platform=key):
                block = re.search(r'<div class="rb-title-logo[^"]*">.*?</div>', html, re.S)
                self.assertIsNotNone(block)
                self.assertRegex(block[0], r'<img\b[^>]*\bsrc="/retrobios/assets/logos/')
                self.assertNotIn("align=", html.split("<main", 1)[-1])

    def test_every_emulator_letter_lands_on_its_section(self):
        sidebar = json.loads(SIDEBAR.read_text(encoding="utf-8"))
        html = (DIST / "emulators" / "index.html").read_text(encoding="utf-8")
        ids = set(re.findall(r'\bid="([^"]+)"', html))
        letters = {key: group for key, group in sidebar["groups"].items()
                   if key.startswith("Explore/Emulators/")}
        self.assertGreater(len(letters), 20)
        for key, group in letters.items():
            with self.subTest(group=key):
                self.assertRegex(group["href"] or "", r"^/retrobios/emulators/#")
                self.assertIn(group["href"].split("#", 1)[1], ids)

    def test_system_links_reach_the_section_of_the_name(self):
        """Every link into a system page lands on an id the page holds."""
        ids: dict[str, set[str]] = {}
        for page in (DIST / "systems").glob("*/index.html"):
            ids[page.parent.name] = set(re.findall(r'\bid="([^"]+)"', page.read_text(encoding="utf-8")))
        target = re.compile(r'href="/retrobios/systems/(?P<page>[^/"#]+)/#(?P<anchor>[^"]+)"')
        for page in ("emulators/index.html", "platforms/retroarch/index.html",
                     "platforms/batocera/index.html", "systems/index.html"):
            html = (DIST / page).read_text(encoding="utf-8")
            for match in target.finditer(html):
                with self.subTest(page=page, link=match[0]):
                    self.assertIn(match["anchor"], ids.get(match["page"], set()))

    def test_getting_started_sends_to_which_pack(self):
        page = DIST / "wiki" / "getting-started" / "index.html"
        self.assertTrue(page.is_file())
        self.assertIn('url=/retrobios/which-pack/"', page.read_text(encoding="utf-8"))
        self.assertFalse((REPO_ROOT / "wiki" / "getting-started.md").exists())

    def test_existence_mode_pages_name_the_file_served(self):
        for key in ("retroarch", "lakka", "retropie"):
            page = DIST / "platforms" / key / "index.html"
            if not page.is_file():
                continue
            with self.subTest(platform=key):
                self.assertIn("Served by", page.read_text(encoding="utf-8"))


class TheRules(unittest.TestCase):
    """What the gate reads without a build."""

    def test_the_logo_reaches_the_front_matter(self):
        import sitestarlight

        _target, text = sitestarlight.finalize_page(
            "platforms/x.md", "# X\n\nBody.\n", level="setup", weight=None,
            browser_title="X", description="d", structured={}, terms={},
            logo="assets/logos/x.svg")
        self.assertIn("logo: assets/logos/x.svg", text)

    def test_a_large_data_directory_is_listed_on_pages_of_its_own(self):
        """Dolphin's Sys tree put 16,900 elements on the Dolphin page. Its
        files are found where they moved."""
        import generate_site

        members = {f"Sys/{i:05d}.ini": {"sha1": f"{i:040x}", "size": 1}
                   for i in range(generate_site.DATA_TREE_ROWS_PER_PAGE + 1)}
        pages = generate_site.data_tree_pages("dolphin-sys", members)
        self.assertEqual([stem for stem, _names in pages], ["data-dolphin-sys", "data-dolphin-sys-2"])
        self.assertEqual(generate_site.data_tree_pages("small", dict(list(members.items())[:3])), [])
        items = generate_site.file_location_items(
            {"files": {}}, {"dolphin": {"data_directories": [{"ref": "dolphin-sys"}]}},
            {"dolphin-sys": members})
        last = f"{generate_site.DATA_TREE_ROWS_PER_PAGE:040x}"
        self.assertIn({"sha1": last, "url": f"/retrobios/emulators/data-dolphin-sys-2/#sha1-{last[:12]}"}, items)

    def test_no_float_rule_for_right_aligned_images(self):
        css = (REPO_ROOT / "website" / "src" / "styles" / "retrobios.css").read_text(encoding="utf-8")
        self.assertNotIn("img[align='right']", css)
        self.assertIn(":is(h2, h3) small", css)


if __name__ == "__main__":
    unittest.main()
