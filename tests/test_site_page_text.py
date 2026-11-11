"""The text a page gives to whatever reads it without looking at it.

A crawler, a screen reader, an assistant, a text browser and a copy read
the words of the HTML, not the layout. The Steam Deck steps of Get the
files read three times there, once in the prose and once per drawn layout
glued letter to letter ("Open Konsole3Click Copy,the button bythe line"),
a filter box read "Filter Options41 rows" and the file picker an empty
"Setup Choose a setup". These tests read representative pages the way such
a reader does, skipping what is `hidden`, `aria-hidden`, scripts and
styles, and hold the page to one reading of each thing it says.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import re
import shutil
import subprocess
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import sitediagrams  # noqa: E402
import siteentries  # noqa: E402
import sitesteps  # noqa: E402
from siteguides import TERMINALS  # noqa: E402

WEBSITE = ROOT / "website"
DOCS = WEBSITE / "src" / "content" / "docs"
DIST = WEBSITE / "dist"
PLUGIN = WEBSITE / "src" / "plugins" / "rehype-stack-tables.mjs"
SATTERI = WEBSITE / "node_modules" / "satteri" / "dist" / "index.js"

# The pages that hold each kind: the drawn steps and the picker, the
# figures, a filter box written by the build, one by the generator above
# a file list, one above an entry table, and the stats of a setup page.
PAGES = ("which-pack", "wiki/first-install", "wiki/architecture", "wiki/what-are-bios-files",
         "wiki/installer", "platforms/retrodeck", "provenance-no-intro", "explore", "index")

BLOCKS = frozenset(
    "address article aside blockquote caption dd details dialog div dl dt fieldset figcaption "
    "figure footer form h1 h2 h3 h4 h5 h6 header hr li main nav ol option p pre section select "
    "summary table tbody td tfoot th thead tr ul".split())
VOID = frozenset("area base br col embed hr img input link meta source track wbr".split())
# What the stylesheet lays out as its own box beside the text before it:
# the markup has to space it, a reader without the stylesheet sees no box.
# A <br> breaks a line on screen only: a copy and textContent join across
# it, so it separates nothing here. link-title is the page name of
# Starlight's previous and next links.
OWN_BOX = ("rb-tile-name", "rb-tile-runs", "rb-stat-label", "rb-badge", "rb-table-filter-count",
           "link-title")


class PageText(HTMLParser):
    """The text of a page, as a reader without the stylesheet gets it: a
    block starts a line, an inline element adds nothing between words.
    Skips script, style, template, `hidden` and `aria-hidden`. A tab panel,
    hidden until its tab is picked, is read: it is content, not chrome."""

    def __init__(self, article_only: bool = False) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.stack: list[tuple[str, bool]] = []
        self.skipping = 0
        self.inside = not article_only
        self.glued: list[str] = []

    def _text_so_far(self) -> str:
        return "".join(self.parts[-4:])

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {key: value or "" for key, value in attrs}
        classes = attr.get("class", "").split()
        if not self.inside:
            self.inside = "sl-markdown-content" in classes
            return
        if self.skipping:
            if tag not in VOID:
                self.stack.append((tag, False))
            return
        if tag == "img":
            self.parts.append(attr.get("alt", ""))
            return
        if tag in BLOCKS:
            self.parts.append("\n")
        if any(name in OWN_BOX for name in classes) or (tag == "code" and self.stack
                                                         and self.stack[-1][0] == "summary"):
            before = self._text_so_far()
            if before and not before[-1].isspace():
                self.glued.append(f"{before[-20:]!r} <{tag} class={' '.join(classes)!r}>")
        if tag in VOID:
            return
        skip = (tag in ("script", "style", "template")
                or ("hidden" in attr and attr.get("role") != "tabpanel")
                or attr.get("aria-hidden") == "true")
        self.stack.append((tag, skip))
        self.skipping += skip

    def handle_endtag(self, tag: str) -> None:
        if tag in VOID or not self.inside:
            return
        while self.stack:
            name, skip = self.stack.pop()
            self.skipping -= skip
            if name == tag:
                break
        if not self.skipping and tag in BLOCKS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self.inside and not self.skipping:
            self.parts.append(data)

    @property
    def text(self) -> str:
        return re.sub(r"\n\s*", "\n", re.sub(r"[ \t]+", " ", "".join(self.parts))).strip()


def read(html: str, article_only: bool = False) -> PageText:
    reader = PageText(article_only)
    reader.feed(html)
    reader.close()
    return reader


def _letters(text: str) -> str:
    """The text without any space: the letters an SVG wrapped across text
    nodes still spell, joined or not."""
    return re.sub(r"\s+", "", text.replace("**", ""))


def _sources() -> dict[str, str]:
    found = {}
    for page in PAGES:
        for suffix in (".mdx", ".md"):
            path = DOCS / f"{page}{suffix}"
            if path.is_file():
                found[page] = path.read_text(encoding="utf-8")
    return found


def _built() -> dict[str, str]:
    found = {}
    for page in PAGES:
        path = DIST / ("index.html" if page == "index" else f"{page}/index.html")
        if path.is_file():
            found[page] = path.read_text(encoding="utf-8")
    return found


class PageReadsOnce:
    """The assertions, on generated page sources (the HTML the generators
    write, Markdown left as text) and on built pages when there are any."""

    pages: dict[str, PageText]

    def test_the_drawn_steps_are_not_read_again(self):
        checked = 0
        for name, page in self.pages.items():
            text = _letters(page.text)
            for tab, (title, steps) in sitesteps.STEPS.items():
                prose = _letters(TERMINALS[tab][1])
                with self.subTest(page=name, tab=tab):
                    self.assertLessEqual(text.count(prose), 1)
                    self.assertNotIn(_letters(title), text)
                    self.assertNotIn(_letters(sitesteps.description(tab)), text)
                    # A drawn layout repeats every caption: a caption long
                    # enough to be told apart is read at most once, by the
                    # prose when it says it.
                    for step in steps:
                        caption = _letters(step.caption)
                        if len(caption) >= 16:
                            checked += 1
                            self.assertLessEqual(text.count(caption), 1, step.caption)
        self.assertGreater(checked, 0)

    def test_a_figure_says_its_words_once(self):
        for name, page in self.pages.items():
            text = _letters(page.text)
            for image_id in sitediagrams.IMAGE_IDS:
                figure = sitediagrams.figures()[image_id]
                with self.subTest(page=name, image=image_id):
                    self.assertLessEqual(text.count(_letters(figure.desc)), 1)
                    self.assertLessEqual(text.count(_letters(figure.caption)), 1)

    def test_no_rows_counter_glued_to_a_label(self):
        for name, page in self.pages.items():
            with self.subTest(page=name):
                self.assertIsNone(re.search(r"[^\s\d,(][\d,]*\d rows\b", page.text))
                self.assertIsNone(re.search(r"(?m)^Filter \S", page.text))

    def test_no_empty_picker(self):
        for name, page in self.pages.items():
            with self.subTest(page=name):
                self.assertNotIn("Choose a setup", page.text)

    def test_what_sits_in_its_own_box_is_spaced(self):
        for name, page in self.pages.items():
            with self.subTest(page=name):
                self.assertEqual(page.glued, [])


class GeneratedPagesReadOnce(PageReadsOnce, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sources = _sources()
        if "which-pack" not in sources:
            raise unittest.SkipTest("no generated pages: run scripts/generate_site.py")
        cls.pages = {name: read(text) for name, text in sources.items()}

    def test_the_pages_hold_what_is_checked(self):
        sources = _sources()
        self.assertIn("rb-steps", sources["which-pack"])
        self.assertIn('class="rb-table-filter" hidden', sources["platforms/retrodeck"])
        self.assertIn('class="rb-table-filter" hidden', sources["provenance-no-intro"])
        self.assertIn('class="rb-figure"', sources["wiki/architecture"])


class BuiltPagesReadOnce(PageReadsOnce, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        built = _built()
        if "which-pack" not in built:
            raise unittest.SkipTest("no built site")
        cls.pages = {name: read(text, article_only=True) for name, text in built.items()}

    def test_the_build_writes_the_filter_boxes_hidden(self):
        boxes = re.findall(r'<div class="rb-table-filter"[^>]*>', _built()["wiki/installer"])
        self.assertTrue(boxes)
        for box in boxes:
            self.assertIn(" hidden", box)


class TheTwoFilterBoxesAreOne(unittest.TestCase):
    """rehype-stack-tables.mjs writes the box above a Markdown table,
    siteentries.filter_box above an HTML one: the same markup, so site.ts,
    the stylesheet and every reader meet one box."""

    def test_the_build_writes_what_the_generator_writes(self):
        node = shutil.which("node")
        if not node or not SATTERI.is_file():
            self.skipTest("no node or no website/node_modules")
        rows = "\n".join(f"| a{i} | b | c |" for i in range(22))
        script = (
            f"const {{ markdownToHtml }} = await import({json.dumps(SATTERI.as_uri())});\n"
            f"const {{ default: stackTables }} = await import({json.dumps(PLUGIN.as_uri())});\n"
            f"const md = {json.dumps(f'## Options{chr(10)}{chr(10)}| Flag | What | When |{chr(10)}|---|---|---|{chr(10)}{rows}{chr(10)}')};\n"
            "console.log(markdownToHtml(md, { hastPlugins: [stackTables()] }).html);\n"
        )
        built = subprocess.run([node, "--input-type=module", "-e", script], capture_output=True,
                               text=True, check=True, timeout=60).stdout
        box = re.search(r'<div class="rb-table-filter".*?</div>', built, re.S)
        self.assertIsNotNone(box)
        self.assertEqual(box.group(0), siteentries.filter_box(
            "rb-table-filter-1", "Options", ["Flag", "What", "When"], 22))

    def test_a_box_reads_nothing_until_wired(self):
        box = siteentries.filter_box("x", "files", ["File", "path"], 41)
        self.assertEqual(read(box).text, "")
        self.assertIn('aria-describedby="x-count"', box)
        self.assertIn('<span id="x-count"', box)
        self.assertIn("</label> <input", box)
        self.assertIn('"> <span', box)

    def test_the_script_shows_the_boxes(self):
        source = (WEBSITE / "src" / "scripts" / "site.ts").read_text(encoding="utf-8")
        self.assertIn("querySelectorAll<HTMLElement>('.rb-table-filter[hidden]')) box.hidden = false",
                      source)
        css = (WEBSITE / "src" / "styles" / "retrobios.css").read_text(encoding="utf-8")
        self.assertIn(".rb-table-filter[hidden] { visibility: hidden; }", css)


class PreviousAndNextAreSpaced(unittest.TestCase):
    """Starlight's previous and next links read "PreviousWhat the packs do
    not hold": the word and the title were split by a <br> only. The
    override (src/components/Pagination.astro) spaces them and names each
    link by its direction and its page."""

    def test_the_override_is_registered(self):
        config = (WEBSITE / "astro.config.mjs").read_text(encoding="utf-8")
        self.assertIn("Pagination: './src/components/Pagination.astro',", config)

    def test_word_and_title_are_spaced_and_named(self):
        source = (WEBSITE / "src" / "components" / "Pagination.astro").read_text(encoding="utf-8")
        for word, rel, page in (("previousWord", "prev", "prev"), ("nextWord", "next", "next")):
            with self.subTest(rel=rel):
                self.assertIn(f"{{{word}}}{{' '}}\n\t\t\t\t\t<br />", source)
                self.assertIn(f'rel="{rel}" aria-label={{`${{{word}}}: ${{{page}.label}}`}}', source)
        self.assertRegex(source, r'<nav class="pagination-links[^"]*" dir=\{dir\} aria-label=')

    def test_a_rendered_pair_reads_spaced(self):
        html = ('<div class="sl-markdown-content"></div><nav class="pagination-links">'
                '<a href="/a/" rel="prev"><span>Previous <br><span class="link-title">A</span>'
                '</span></a> <a href="/b/" rel="next"><span>Next <br>'
                '<span class="link-title">B</span></span></a></nav>')
        page = read(html, article_only=True)
        self.assertEqual(page.glued, [])
        self.assertEqual(page.text, "Previous A Next B")
        self.assertTrue(read(html.replace("Previous <br>", "Previous<br>"), article_only=True).glued)


class ThePickerWaitsForItsScript(unittest.TestCase):
    def test_hidden_until_the_setups_are_listed(self):
        source = (WEBSITE / "src" / "components" / "FilePicker.astro").read_text(encoding="utf-8")
        self.assertRegex(source, r'<div class="rb-picker" hidden ')
        listed = source.index("select.add(new Option(entry.name, entry.platform));")
        self.assertLess(listed, source.index("root.hidden = false;"))
        self.assertIn(".rb-picker[hidden] { display: block; visibility: hidden; }", source)


class DiagramsAreImages(unittest.TestCase):
    """One text source per drawing: the images are alt="", the figure says
    the words once. Each theme has its files, coloured as the page is."""

    def test_no_inline_drawing_and_no_alt(self):
        for html in [*(sitediagrams.figure_html(i) for i in sitediagrams.IMAGE_IDS),
                     *("".join(sitesteps.steps_figure(tab)) for tab in sitesteps.STEPS)]:
            with self.subTest(html=html[:60]):
                self.assertNotIn("<svg", html)
                self.assertEqual(set(re.findall(r'<img [^>]*alt="([^"]*)"', html)), {""})
                self.assertEqual(len(re.findall(r"<picture ", html)), len(sitediagrams.THEMES))

    def test_every_image_has_its_file(self):
        files = {**sitediagrams.figure_files(), **sitesteps.steps_files()}
        pages = [*(sitediagrams.figure_html(i) for i in sitediagrams.IMAGE_IDS),
                 *("".join(sitesteps.steps_figure(tab)) for tab in sitesteps.STEPS)]
        named = {url.rsplit("/", 1)[1] for html in pages
                 for url in re.findall(r'(?:src|srcset)="([^"]+)"', html)}
        self.assertEqual(named, set(files))

    def test_the_figure_says_its_desc_once(self):
        for image_id in sitediagrams.IMAGE_IDS:
            figure = sitediagrams.figures()[image_id]
            with self.subTest(image=image_id):
                text = read(sitediagrams.figure_html(image_id)).text
                self.assertEqual(text.count(figure.desc), 1)
                self.assertIn(figure.caption, text)

    def test_the_theme_colours_are_the_stylesheet_tokens(self):
        css = (WEBSITE / "src" / "styles" / "retrobios.css").read_text(encoding="utf-8")
        light_at = css.index(":root[data-theme='light'] {")
        blocks = {"dark": css[css.index(":root {"):light_at], "light": css[light_at:]}
        tokens = {"fill": "--rb-diagram-fill", "stroke": "--rb-diagram-stroke",
                  "accent": "--rb-diagram-accent", "muted": "--rb-text-secondary"}
        for theme, block in blocks.items():
            for key, token in tokens.items():
                with self.subTest(theme=theme, token=token):
                    value = re.search(rf"{token}:\s*(#[0-9a-f]+);", block).group(1)
                    self.assertEqual(sitediagrams.THEMES[theme][key], value)

    def test_a_file_carries_its_theme(self):
        for name, text in sitesteps.steps_files().items():
            theme = name.rsplit("-", 1)[1].removesuffix(".svg")
            with self.subTest(file=name):
                self.assertIn(f".rb-d-box{{fill:{sitediagrams.THEMES[theme]['fill']}", text)
                self.assertTrue(text.startswith("<svg "))


if __name__ == "__main__":
    unittest.main()
