"""Round 3, package 2: components and runtime.

Source checks always run. Checks on the built site read website/dist and
skip when no build is there. The hash functions and the table rule run
under node and skip without it.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import subprocess
import unittest
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WEBSITE = REPO_ROOT / "website"
DIST = WEBSITE / "dist"
COMPONENTS = WEBSITE / "src" / "components"
SITE_TS = WEBSITE / "src" / "scripts" / "site.ts"
CONFIG = WEBSITE / "astro.config.mjs"
PLUGIN = WEBSITE / "src" / "plugins" / "rehype-stack-tables.mjs"
UNBROKEN = WEBSITE / "src" / "plugins" / "ec-unbroken-tokens.mjs"
LOGOS = REPO_ROOT / "docs_assets" / "logos"

# Shown at 40 px in a tile and beside a setup's title: twice that for a
# sharp mark on a dense screen.
LOGO_PIXELS = 80
TAB_ROOTS = ("", "platforms", "explore", "wiki", "contributing")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _built(page: str) -> str:
    path = DIST / page / "index.html"
    if not path.is_file():
        raise unittest.SkipTest(f"no built site at {path}")
    return _read(path)


def _title_block(html: str) -> str:
    """What PageTitle draws: from the main column to the end of the h1."""
    end = html.index("</h1>", html.index('id="_top"'))
    return html[html.rfind("<main", 0, end):end]


def _tables(html: str) -> list[str]:
    return re.findall(r"<table\b.*?</table>", html, re.S)


def _headers(table: str) -> list[str]:
    head = re.search(r"<thead>(.*?)</thead>", table, re.S)
    cells = re.findall(r"<th\b[^>]*>(.*?)</th>", head.group(1), re.S) if head else []
    return [re.sub(r"<[^>]+>", "", cell).strip() for cell in cells]


def _node_module(script: str) -> str:
    node = shutil.which("node")
    if not node:
        raise unittest.SkipTest("node is missing")
    result = subprocess.run(
        [node, "--input-type=module-typescript", "-e", script],
        capture_output=True, text=True, check=True, cwd=WEBSITE,
    )
    return result.stdout


def _webp_size(data: bytes) -> tuple[int, int]:
    """Width and height from a WebP header (VP8, VP8L or VP8X)."""
    if data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise ValueError("not a WebP file")
    chunk = data[12:16]
    if chunk == b"VP8 ":
        width, height = struct.unpack("<HH", data[26:30])
        return width & 0x3FFF, height & 0x3FFF
    if chunk == b"VP8L":
        bits = int.from_bytes(data[21:25], "little")
        return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    if chunk == b"VP8X":
        return int.from_bytes(data[24:27], "little") + 1, int.from_bytes(data[27:30], "little") + 1
    raise ValueError(f"unknown WebP chunk {chunk!r}")


class TitleLogoOnAPlate(unittest.TestCase):
    """The RetroArch and Batocera marks are black: beside the title they
    vanished on the dark theme, and the image had no width (Lighthouse
    unsized-images, V3, T-F3)."""

    def test_the_component_draws_the_tile_square(self):
        title = _read(COMPONENTS / "PageTitle.astro")
        self.assertIn('width={MARK} height={MARK}', title)
        self.assertIn("const MARK = 40;", title)
        style = title[title.index(".rb-title-mark {"):]
        style = style[:style.index("}")]
        for rule in ("width: 40px;", "height: 40px;", "padding: 3px;", "border: 1px solid var(--rb-border);",
                     "border-radius: 6px;", "background: #fff;", "object-fit: contain;"):
            with self.subTest(rule=rule):
                self.assertIn(rule, style)

    def test_every_setup_page_has_a_sized_mark(self):
        index = json.loads(_read(WEBSITE / "public" / "data" / "picker" / "index.json"))
        for entry in index:
            with self.subTest(setup=entry["platform"]):
                block = _title_block(_built(f"platforms/{entry['platform']}"))
                self.assertIn('class="rb-title-mark', block)
                for image in re.findall(r"<img\b[^>]*>", block):
                    self.assertIn('width="40"', image)
                    self.assertIn('height="40"', image)

    def test_a_setup_with_no_logo_gets_its_initials(self):
        block = _title_block(_built("platforms/myminui"))
        self.assertNotIn("<img", block)
        self.assertRegex(block, r"<svg class=\"rb-title-mark[^>]*>.*?>MM</text>")


class NoLevelBadgeOnATabRoot(unittest.TestCase):
    def test_tab_roots(self):
        for page in TAB_ROOTS:
            with self.subTest(page=page or "home"):
                self.assertNotIn('class="rb-level ', _title_block(_built(page)))


class FooterLicenceMatchesTheLicenceFile(unittest.TestCase):
    """The footer said MIT covers the tooling. LICENSE names the metadata too."""

    def test_footer(self):
        self.assertIn("metadata", _read(REPO_ROOT / "LICENSE").split("MIT License")[0])
        html = _built("data")
        footer = re.sub(r"<[^>]+>", "", html[html.index('class="rb-footer'):])
        self.assertIn("MIT for the tooling and metadata.", footer)


class WideTablesStackAndFiltersAreBuilt(unittest.TestCase):
    """Level 2 and 3 tables overflowed a phone (emulator summary, gaps,
    verification modes, emulators index, data: V5, J8). The filter box,
    added after paint, pushed the table down: CLS 0.066 on
    gaps-files-to-source (T-F10)."""

    def test_every_wide_table_stacks(self):
        for page in ("emulators/duckstation", "gaps", "gaps-files-to-source", "emulators", "data",
                     "wiki/verification-modes"):
            html = (DIST / page / "index.html")
            if not html.is_file():
                continue
            for table in _tables(_read(html)):
                if len(_headers(table)) < 4:
                    continue
                with self.subTest(page=page, header=_headers(table)):
                    self.assertIn('data-rb-stack="true"', table.split(">", 1)[0])

    def test_long_tables_get_their_labels_at_runtime(self):
        """Labels on every cell of a long stacked table were 122 KB of
        emulators/mame and took it over the 600,000-byte page budget."""
        self.assertIn("if (kind === 'kv' || rows.length >= RECORD_ROWS) return;", _read(PLUGIN))
        source = _read(SITE_TS)
        self.assertIn("const labelCells = (table: HTMLTableElement) => {", source)
        self.assertIn("labelCells(table);", source)
        html = _built("emulators/mame")
        self.assertLess(len(html.encode()), 600_000)

    def test_the_filter_box_is_in_the_html(self):
        html = _built("gaps-files-to-source")
        boxes = re.findall(r'<div class="rb-table-filter">(.*?)</div>\s*<table', html, re.S)
        self.assertTrue(boxes)
        for box in boxes:
            self.assertRegex(box, r'<label for="rb-table-filter-\d+">Filter [^<]+</label>')
            self.assertRegex(box, r'<input id="rb-table-filter-\d+" type="search"')
            self.assertRegex(box, r'aria-live="polite">[\d,]+ rows</span>')
        source = _read(SITE_TS)
        self.assertNotIn("controls.className = 'rb-table-filter'", source)
        self.assertIn("controls?.matches('.rb-table-filter')", source)

    def test_every_long_table_has_its_box(self):
        html = _built("systems")
        for table in _tables(html):
            rows = len(re.findall(r"<tr\b", table.split("<tbody>", 1)[-1]))
            if rows < 20:
                continue
            start = html.index(table)
            self.assertIn('class="rb-table-filter"', html[max(0, start - 600):start])

    def test_the_placeholder_names_the_columns(self):
        """Every filter offered "Name, platform, system, hash...", over the
        console list too, which has no hash (V small)."""
        self.assertNotIn("Name, platform, system, hash", _read(SITE_TS))
        cases = [["File", "Region", "Required", "Hash"], ["Console", "Files"], ["System", "MD5", "Size"]]
        out = _node_module(
            f"import {{ filterPlaceholder }} from {json.dumps(PLUGIN.as_uri())};"
            f"console.log(JSON.stringify({json.dumps(cases)}.map(filterPlaceholder)));"
        )
        self.assertEqual(json.loads(out), ["File, region, required, hash...", "Console, files...", "System, MD5, size..."])
        html = _built("systems")
        self.assertRegex(html, r'placeholder="Console[^"]*\.\.\."')
        self.assertNotRegex(html, r'placeholder="[^"]*hash[^"]*"')


class HashLookupGivesOneVerdict(unittest.TestCase):
    """The lookup read "24 matches", "Setups that list it (12)" over 17 rows,
    and emulators by id. ?md5= showed the empty form (N8, J7)."""

    def test_parameters(self):
        source = _read(SITE_TS)
        self.assertIn("const HASH_PARAMS = ['hash', 'md5', 'crc32', 'sha256'];", source)
        self.assertIn("HASH_PARAMS.map((key) => params.get(key))", source)

    def test_counts_say_what_they_count(self):
        source = _read(SITE_TS)
        self.assertNotIn("'match' : 'matches'", source)
        self.assertIn("count(platforms.length, 'declaration', 'declarations')} by ${count(setups.size, 'setup', 'setups')}", source)
        self.assertIn("count(listers.size, 'setup lists', 'setups list')", source)
        self.assertIn("'file in the collection', 'files in the collection'", source)

    def test_emulators_by_name(self):
        source = _read(SITE_TS)
        self.assertIn("json(`api/v1/emulators/${owner}.json`)", source)
        self.assertIn("profile.emulator || profile.display_name || owner", source)
        profile = json.loads(_read(DIST / "api" / "v1" / "emulators" / "duckstation.json")) \
            if (DIST / "api" / "v1" / "emulators" / "duckstation.json").is_file() else None
        if profile is None:
            self.skipTest("no built site")
        self.assertEqual(profile["items"][0]["profile"]["emulator"], "DuckStation")

    def test_a_console_page_card_reads_its_manufacturer_file(self):
        """Every collection match on a console page (systems/sony-playstation/)
        asked for api/v1/systems/sony-playstation.json, which does not exist:
        the verdict lost the file's path."""
        source = _read(SITE_TS)
        self.assertIn("api/v1/systems/${words.slice(0, size).join('-')}.json", source)
        api = DIST / "api" / "v1" / "systems"
        if not api.is_dir():
            self.skipTest("no built site")
        self.assertFalse((api / "sony-playstation.json").exists())
        self.assertTrue((api / "sony.json").is_file())

    def test_no_match_leads_somewhere(self):
        source = _read(SITE_TS)
        self.assertIn("link('contributing/', 'add it')", source)
        anchor = re.search(r"const WANTED = 'provenance/#([^']+)';", source)
        self.assertIsNotNone(anchor)
        self.assertIn(f'id="{anchor[1]}"', _built("provenance"))
        self.assertNotIn("No file the site knows has this hash.", source)


class HashAFileHere(unittest.TestCase):
    """Find a file asked for a hash only: hashing meant another tool (J7)."""

    def test_the_chooser(self):
        source = _read(SITE_TS)
        self.assertIn("input.type = 'file';", source)
        self.assertIn("It is hashed on this device. Nothing is uploaded.", source)
        self.assertIn("crypto.subtle.digest(name, buffer)", source)
        self.assertIn("['SHA-1', 'SHA-256']", source)
        self.assertIn("lookUp(status, result, [found.sha1, found.md5, found.crc32, found.sha256])", source)

    def test_md5_and_crc32_match_python(self):
        source = _read(SITE_TS)
        block = source[source.index("// Hashing a file on this device"):source.index("type FileHashes")]
        sizes = [0, 1, 55, 56, 63, 64, 65, 119, 120, 128, 1000, 70_001]
        out = _node_module(block + (
            f"console.log(JSON.stringify({json.dumps(sizes)}.map((n) => {{"
            "const bytes = new Uint8Array(n);"
            "for (let i = 0; i < n; i += 1) bytes[i] = (i * 31 + 7) & 0xff;"
            "return [md5(bytes), crc32(bytes)]; })));"
        ))
        for size, (md5, crc) in zip(sizes, json.loads(out)):
            data = bytes((i * 31 + 7) & 0xFF for i in range(size))
            with self.subTest(size=size):
                self.assertEqual(md5, hashlib.md5(data).hexdigest())
                self.assertEqual(crc, f"{zlib.crc32(data):08x}")


class SearchFoldsPagesUnderAHash(unittest.TestCase):
    """Under "Look up this hash" came 14 unrelated pages: Magnavox for
    E490.WAV, Philips for cdi490a.zip (N8)."""

    def test_fold(self):
        source = _read(SITE_TS)
        self.assertIn("toggle.textContent = 'Pages that mention these characters';", source)
        self.assertIn("toggle.setAttribute('aria-expanded', 'false');", source)
        header = _read(COMPONENTS / "Header.astro")
        self.assertIn(
            ".pagefind-ui__drawer[data-rb-hash]:not([data-rb-pages-shown]) .pagefind-ui__results-area { display: none; }",
            header,
        )

    def test_search_fields_are_weighted_and_never_shown(self):
        config = _read(CONFIG)
        self.assertIn("metaWeights: { title: 10, files: 0.5, aliases: 10, devices: 5, consoles: 100, exact: 20, terms: 30 },", config)
        self.assertIn("const UNSHOWN_FIELDS = new Set(['files', 'aliases', 'devices', 'consoles', 'exact', 'terms']);", _read(SITE_TS))


class OsTabsNeverScrollThePage(unittest.TestCase):
    """The tabs wrap since round 4 (retrobios.css): the script picks the
    visitor's tab and never scrolls the page."""

    def test_no_page_scroll(self):
        source = _read(SITE_TS)
        self.assertNotIn("scrollIntoView", source)
        self.assertIn("osTabs();", source)


class CommandsNeverBreakInsideAWord(unittest.TestCase):
    """`--` / `platform retroarch` at 1440 px, `--` / `system` and
    `nintendo-` / `64dd` on a phone: a browser breaks a line after a hyphen,
    whatever overflow-wrap says."""

    def test_the_words_are_wrapped_and_the_text_kept(self):
        # Shiki cuts `--platform` into two tokens: the span has to hold both.
        line = {"type": "element", "tagName": "div", "properties": {"className": ["code"]}, "children": [
            {"type": "element", "tagName": "span", "properties": {"style": "a"}, "children": [
                {"type": "text", "value": "sh -s "}]},
            {"type": "element", "tagName": "span", "properties": {"style": "b"}, "children": [
                {"type": "text", "value": "--"}]},
            {"type": "element", "tagName": "span", "properties": {"style": "c"}, "children": [
                {"type": "text", "value": "platform retroarch --system nintendo-64dd"}]},
        ]}
        out = json.loads(_node_module(
            f"import {{ unbreakWords }} from {json.dumps(UNBROKEN.as_uri())};"
            f"console.log(JSON.stringify(unbreakWords({json.dumps(line)})));"
        ))

        def text(node: dict) -> str:
            return node.get("value", "") + "".join(text(child) for child in node.get("children", []))

        self.assertEqual("".join(text(n) for n in out), "sh -s --platform retroarch --system nintendo-64dd")
        words = [text(n) for n in out if n.get("properties", {}).get("className") == ["rb-nb"]]
        self.assertEqual(words, ["-s", "--platform", "--system", "nintendo-64dd"])
        # The colours of each token survive the cut.
        platform = next(n for n in out if text(n) == "--platform")
        self.assertEqual([c["properties"]["style"] for c in platform["children"]], ["b", "c"])

    def test_registered(self):
        config = _read(CONFIG)
        self.assertIn("import unbrokenTokens from './src/plugins/ec-unbroken-tokens.mjs';", config)
        self.assertIn("plugins: [unbrokenTokens()],", config)
        self.assertIn("baseStyles: `.${CLASS} { white-space: nowrap; }`", _read(UNBROKEN))
        picker = _read(COMPONENTS / "FilePicker.astro")
        self.assertIn("showCommand(cmd, `${INSTALL} --platform", picker)
        self.assertIn(".rb-picker .rb-pick-cmd .rb-nb { white-space: nowrap; }", picker)
        self.assertIn("navigator.clipboard?.writeText(cmd.textContent ?? '')", picker)

    def test_copy_gives_the_rendered_text(self):
        """The copy button's text is the block's text: the spans add nothing.
        Expressive Code leaves a leading comment line out of the copy."""
        import html as html_lib

        page = _built("platforms/retroarch")
        figures = re.findall(r"<figure\b.*?</figure>", page, re.S)
        self.assertTrue(figures)
        self.assertIn('<span class="rb-nb">', page)
        for figure in figures:
            copied = re.search(r'data-code="([^"]*)"', figure)
            if not copied:
                continue
            lines = re.findall(r'<div class="ec-line">(.*?)</div></div>', figure, re.S)
            shown = "\n".join(html_lib.unescape(re.sub(r"<[^>]+>", "", line)) for line in lines)
            code = html_lib.unescape(copied[1]).replace("\x7f", "\n")
            with self.subTest(code=code[:60]):
                self.assertTrue(shown.endswith(code), (shown, code))


class LogosAtTheirDisplaySize(unittest.TestCase):
    """136 KiB of the home page was 96 px PNG logos shown at 40 px (T-F7)."""

    def test_raster_logos_are_small_webp(self):
        manifest = json.loads(_read(LOGOS / "sources.json"))["images"]
        self.assertTrue(manifest)
        for entry in manifest:
            path = LOGOS / entry["file"]
            with self.subTest(file=entry["file"]):
                self.assertTrue(path.is_file())
                self.assertIn(path.suffix, (".webp", ".svg"))
                if path.suffix == ".webp":
                    self.assertEqual(_webp_size(path.read_bytes()), (LOGO_PIXELS, LOGO_PIXELS))
        self.assertEqual(sorted(p.name for p in LOGOS.glob("*.png")), [])
        script = _read(REPO_ROOT / "scripts" / "fetch_site_images.py")
        self.assertIn(f"LOGO_SIZE = {LOGO_PIXELS}", script)
        self.assertIn('square_image(data, LOGO_SIZE, "WEBP")', script)

    def test_pages_point_at_the_copies(self):
        html = _built("platforms/emudeck")
        self.assertIn('src="/retrobios/assets/logos/emudeck.webp"', html)


class SearchConsoleOwnership(unittest.TestCase):
    """Search Console checks the tag on every recrawl: without it the
    property goes unverified and the sitemap stops being read."""

    def test_the_head_carries_the_verification_tag(self):
        self.assertIn("{ tag: 'meta', attrs: { name: 'google-site-verification', "
                      "content: '8SueST3hNHl8_vM-OJJP0rz-ZMlI2DALLpChrwZoGMs' } }",
                      CONFIG.read_text(encoding="utf-8"))

    @unittest.skipUnless((DIST / "index.html").is_file(), "site not built")
    def test_the_home_page_serves_it(self):
        self.assertIn('<meta name="google-site-verification" '
                      'content="8SueST3hNHl8_vM-OJJP0rz-ZMlI2DALLpChrwZoGMs"',
                      (DIST / "index.html").read_text(encoding="utf-8"))



class EverySonyConsoleHasItsPage(unittest.TestCase):
    """A section shares its page's search fields: "playstation 3 bios"
    found the PlayStation page before the Sony page holding the PS3."""

    def test_sony_is_split_by_console(self):
        source = (REPO_ROOT / "scripts" / "generate_site.py").read_text(encoding="utf-8")
        self.assertIn('CONSOLE_PAGES = frozenset({"Sony"})', source)
        self.assertIn("manufacturer in CONSOLE_PAGES", source)

    @unittest.skipUnless((DIST / "index.html").is_file(), "site not built")
    def test_each_console_page_is_built(self):
        for slug in ("sony-playstation", "sony-playstation-2", "sony-playstation-3",
                     "sony-playstation-4", "sony-playstation-portable", "sony-playstation-vita",
                     "sony-pocketstation"):
            with self.subTest(page=slug):
                self.assertTrue((DIST / "systems" / slug / "index.html").is_file())

if __name__ == "__main__":
    unittest.main()
