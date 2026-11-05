"""Navigation and search.

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

import ast
import re
import sys
import unittest
from html import unescape
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site  # noqa: E402
import sitestarlight  # noqa: E402
from common import list_registered_platforms  # noqa: E402

SEARCH_GATE = REPO_ROOT / "website" / "tools" / "search_gate.py"
DOCS = REPO_ROOT / "website" / "src" / "content" / "docs"
DIST = REPO_ROOT / "website" / "dist"
ROUTE = REPO_ROOT / "website" / "src" / "routeData.ts"
CONTENT_CONFIG = REPO_ROOT / "website" / "src" / "content.config.ts"
START_HERE = [
    "/retrobios/", "/retrobios/wiki/what-are-bios-files/", "/retrobios/which-pack/",
    "/retrobios/wiki/first-install/", "/retrobios/wiki/troubleshooting/",
    "/retrobios/wiki/faq/", "/retrobios/wiki/legal/", "/retrobios/wiki/glossary/",
    "/retrobios/platforms/",
]


def _front(text: str) -> str:
    end = text.find("\n---\n", 4)
    return text[4:end] if text.startswith("---\n") and end != -1 else ""


def _moved_platform_pages() -> list[Path]:
    platforms = set(list_registered_platforms(str(REPO_ROOT / "platforms"), include_archived=True))
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
    start = text.find('<div class="pagination-links')
    if start == -1:
        return None, None
    links = text[start:text.find("</footer>", start)]
    prev = re.search(r'<a href="([^"]+)"[^>]*rel="prev"', links)
    nxt = re.search(r'<a href="([^"]+)"[^>]*rel="next"', links)
    return (prev[1] if prev else None), (nxt[1] if nxt else None)


@unittest.skipUnless((DIST / "index.html").is_file(), "site not built")
class BuiltSite(unittest.TestCase):
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
            # meta reads the visible h1 since round 4 item 2.4.
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
