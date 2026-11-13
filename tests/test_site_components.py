"""The site's components and runtime.

Source checks always run. Checks on the built site read website/dist and
skip when no build is there. The stacking rule runs the plugin under node
and skips without node or the site's node_modules.

Source checks always run. Checks on the built site read website/dist and
skip when no build is there. The hash functions and the table rule run
under node and skip without it.

Source checks always run. Checks on the built site read website/dist and
skip when no build is there. The rules written in TypeScript or in a build
plugin run under node and skip without it.

Source checks always run. Checks on the built site read website/dist and
skip when no build is there. The rules written in a build plugin run under
node and skip without it.
"""
from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path
import hashlib
import struct
import zlib
import html
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import list_release_pack_platforms  # noqa: E402


REPO_ROOT = Path(__file__).resolve().parents[1]
WEBSITE = REPO_ROOT / "website"
DIST = WEBSITE / "dist"
COMPONENTS = WEBSITE / "src" / "components"
SITE_TS = WEBSITE / "src" / "scripts" / "site.ts"
HASHES_TS = WEBSITE / "src" / "scripts" / "hashes.ts"
CONFIG = WEBSITE / "astro.config.mjs"
PLUGIN = WEBSITE / "src" / "plugins" / "rehype-stack-tables.mjs"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _built(page: str) -> str:
    path = DIST / page / "index.html"
    if not path.is_file():
        raise unittest.SkipTest(f"no built site at {path}")
    return _read(path)


def _tables(html: str) -> list[str]:
    return re.findall(r"<table\b.*?</table>", html, re.S)


def _headers(table: str) -> list[str]:
    head = re.search(r"<thead>(.*?)</thead>", table, re.S)
    cells = re.findall(r"<th\b[^>]*>(.*?)</th>", head.group(1), re.S) if head else []
    return [re.sub(r"<[^>]+>", "", cell).strip() for cell in cells]


class TablesStackWhenBuilt(unittest.TestCase):
    """The setup tables of Get your files were 591, 503 and 511 px wide in a
    358 px phone column: site.ts stacked them only once they neared the
    screen, so the ZIP column first painted off-screen."""

    def test_the_plugin_is_registered_and_the_runtime_rule_is_gone(self):
        config = _read(CONFIG)
        self.assertIn("import stackTables from './src/plugins/rehype-stack-tables.mjs'", config)
        self.assertIn("hastPlugins: [stackTables(), ", config)
        self.assertNotIn("stackActionTable", _read(SITE_TS))

    def test_setup_tables_carry_the_layout_in_the_html(self):
        html = _built("which-pack")
        setups = [t for t in _tables(html) if _headers(t) == ["Setup", "Runs on", "BIOS folder", "ZIP"]]
        self.assertGreaterEqual(len(setups), 3)
        for table in setups:
            with self.subTest(table=table[:80]):
                self.assertIn('data-rb-stack="true"', table.split(">", 1)[0])
                cells = re.findall(r"<td\b[^>]*>", table)
                self.assertTrue(cells)
                for cell in cells:
                    self.assertRegex(cell, r'data-label="(Setup|Runs on|BIOS folder|ZIP)"')

    def test_two_column_tables_are_label_and_value(self):
        html = _built("platforms/retroarch")
        pairs = [t for t in _tables(html) if len(_headers(t)) == 2]
        self.assertTrue(pairs)
        for table in pairs:
            self.assertIn('data-rb-stack="kv"', table.split(">", 1)[0])

    def test_the_rule_reads_the_table(self):
        node = shutil.which("node")
        if not node or not (WEBSITE / "node_modules").is_dir():
            self.skipTest("node or the site's node_modules is missing")
        cases = {
            # A setup added after the release: no ZIP link, the header still names one.
            "zip-header": {"labels": ["Setup", "Runs on", "BIOS folder", "ZIP"], "rows": 5, "action": False},
            "action": {"labels": ["A", "B", "C"], "rows": 40, "action": True},
            "pair": {"labels": ["Where", "BIOS folder"], "rows": 3, "action": False},
            "short-start": {"labels": ["System", "Runs", "BIOS folder"], "rows": 8, "action": False, "level": "start"},
            "long-setup": {"labels": ["System", "Files", "Status"], "rows": 97, "action": False, "level": "setup"},
            "reference": {"labels": ["A", "B", "C"], "rows": 5, "action": False, "level": "reference"},
            # Four columns do not fit a phone column, on any page.
            "wide": {"labels": ["File", "Region", "Required", "Hash"], "rows": 105, "action": False, "level": "reference"},
            # A hash never breaks: three columns with one overflow a phone (NetherSX2).
            "hashes": {"labels": ["File", "Required", "Hash"], "rows": 40, "action": False, "level": "reference"},
        }
        script = (
            f"import {{ stackKind }} from {json.dumps(PLUGIN.as_uri())};"
            f"const cases = {json.dumps(cases)};"
            "console.log(JSON.stringify(Object.fromEntries(Object.entries(cases).map(([k, v]) => [k, stackKind(v)]))));"
        )
        result = subprocess.run(
            [node, "--input-type=module", "-e", script],
            capture_output=True, text=True, check=True, cwd=WEBSITE,
        )
        self.assertEqual(json.loads(result.stdout), {
            "zip-header": "true", "action": "true", "pair": "kv",
            "short-start": "true", "long-setup": None, "reference": None, "wide": "true",
            "hashes": "true",
        })


class ScrollingTablesHaveTheirOwnName(unittest.TestCase):
    """Every scrolling table was the region "Data table, scrollable table"
    (axe landmark-unique on which-pack, retroarch, gaps)."""

    def test_no_bare_fallback_label(self):
        source = _read(SITE_TS)
        self.assertNotIn("'Data table'", source)
        self.assertIn("`${tableName(table)}, scrollable table`", source)
        self.assertIn("`${heading}, table ${count}`", source)


class CommandBlocksHaveNoWindowDots(unittest.TestCase):
    def test_the_dots_are_off_in_the_theme(self):
        self.assertIn("terminalTitlebarDotsOpacity: '0'", _read(CONFIG))
        css = DIST / "_astro"
        if not css.is_dir():
            self.skipTest("no built site")
        values = {m for f in css.glob("ec.*.css") for m in re.findall(r"--ec-frm-trmTtbDotsOpa:([^;]+)", _read(f))}
        self.assertEqual(values, {"0"})


class RedirectsComeFromTheGenerator(unittest.TestCase):
    def test_config_reads_the_file_and_builds_without_it(self):
        config = _read(CONFIG)
        self.assertIn("./src/generated/redirects.json", config)
        self.assertIn("if (error.code === 'ENOENT') return {};", config)
        self.assertIn("redirects: readRedirects(),", config)
        # Astro does not put the base before the new address.
        self.assertIn("BASE + to.replace(/^\\//, '')", config)


class SearchAnswersAHashAndShowsNoFileDump(unittest.TestCase):
    """Searching the scph5501 MD5 opened on Data model, results carried a
    second "#_top" title, and a system page showed its 120 file names."""

    def test_runtime(self):
        source = _read(SITE_TS)
        self.assertIn("Look up this hash", source)
        self.assertIn("files/?hash=${value}", source)
        self.assertIn("endsWith('#_top')", source)
        self.assertIn("UNSHOWN_FIELDS.has(tag.dataset.pagefindUiMeta ?? '')", source)
        # Pagefind's display rules beat the hidden attribute without this.
        self.assertIn("#starlight__search [hidden] { display: none !important; }", _read(COMPONENTS / "Header.astro"))


class SectionTabsInTheHeader(unittest.TestCase):
    def test_registered_and_built(self):
        self.assertIn("Header: './src/components/Header.astro'", _read(CONFIG))
        html = _built("which-pack")
        nav = re.search(r'<nav class="rb-tabs[^"]*"[^>]*>(.*?)</nav>', html, re.S)
        self.assertIsNotNone(nav)
        labels = [re.sub(r"<[^>]+>", "", a).strip() for a in re.findall(r"<a\b[^>]*>.*?</a>", nav.group(1), re.S)]
        self.assertEqual(labels, ["Start here", "Setups", "Explore", "Reference", "Contribute"])
        self.assertEqual(nav.group(1).count('aria-current="true"'), 1)
        self.assertRegex(nav.group(1), r'aria-current="true"[^>]*>\s*Start here')


class TheWantedPageIsInTheBar(unittest.TestCase):
    """The wanted page is the site's call to contribute: in the bar on every
    page, beside the search and menu buttons on a phone, where the section
    tabs fold into the menu."""

    LINK = re.compile(r'<a class="rb-wanted-link[^"]*" href="/retrobios/wanted/"([^>]*)>Wanted files</a>')

    def test_the_bar_holds_it_outside_the_tabs(self):
        header = _read(COMPONENTS / "Header.astro")
        bar = header[header.index('<div class="rb-header-bar">'):header.index("</div>")]
        self.assertIn('class="rb-wanted-link print:hidden"', bar)
        self.assertIn("aria-current={onWanted ? 'page' : undefined}", bar)
        # Theme colours only, the same in both themes' variables.
        style = header[header.index(".rb-wanted-link {"):header.index("@media")]
        self.assertNotRegex(style, r"#[0-9a-fA-F]{3,6}\b")
        # At 360 px the name was cut to "Retr": the logo stays, the name is
        # kept for screen readers only.
        narrow = header[header.index("@media (max-width: 26.99rem)"):]
        self.assertIn(".site-title span {", narrow[:200])
        self.assertIn("clip-path: inset(50%);", narrow[:400])

    def test_built_on_every_page_current_on_its_own(self):
        for page in ("which-pack", "files", "systems"):
            with self.subTest(page=page):
                found = self.LINK.search(_built(page))
                self.assertIsNotNone(found)
                self.assertNotIn("aria-current", found.group(1))
        own = self.LINK.search(_built("wanted"))
        self.assertIsNotNone(own)
        self.assertIn('aria-current="page"', own.group(1))


def _title_block(html: str) -> str:
    """What PageTitle draws: from the main column to the h1."""
    end = html.index('id="_top"')
    return html[html.rfind("<main", 0, end):end]


class LevelBadgeOnlyWhereItAddsSomething(unittest.TestCase):
    def test_badge_follows_the_crumb(self):
        # A tab root: the header tab already says it.
        self.assertNotIn('class="rb-level ', _title_block(_built("platforms")))
        # Under the "Start here" or "Setups" crumb the badge repeated it.
        for page in ("which-pack", "platforms/batocera"):
            with self.subTest(page=page):
                block = _title_block(_built(page))
                self.assertIn('aria-label="Breadcrumb"', block)
                self.assertNotIn('class="rb-level ', block)


class TitleLogo(unittest.TestCase):
    def test_front_matter_field(self):
        self.assertIn("logo: z.string().optional()", _read(WEBSITE / "src" / "content.config.ts"))
        title = _read(COMPONENTS / "PageTitle.astro")
        self.assertIn('<img class="rb-title-mark" src={logoSrc} alt="" width={MARK} height={MARK} />', title)


class FooterSaysWhoAndWhen(unittest.TestCase):
    def test_release_and_maintainer(self):
        tag = json.loads(_read(REPO_ROOT / "release.json"))["tag"]
        html = _built("which-pack")
        footer = html[html.index('class="rb-footer'):]
        self.assertIn("https://github.com/Abdess/retrobios/issues/new", footer)
        self.assertIn(f"/releases/tag/{tag}", footer)
        match = re.fullmatch(r"v(\d{4})\.(\d{2})\.(\d{2})", tag)
        if match:
            self.assertIn(f'<time datetime="{match[1]}-{match[2]}-{match[3]}"', footer)
        self.assertRegex(re.sub(r"<[^>]+>", "", footer), r"Abdess on GitHub\. Report a problem\.")


class FindAFileGivesAVerdict(unittest.TestCase):
    def test_lookup_renderer(self):
        source = _read(SITE_TS)
        self.assertIn("'Held in the collection at '", source)
        self.assertIn("['Setup', 'Name as declared', 'Destination', 'Hash matched', 'Required']", source)
        self.assertIn("api/v1/platforms/${item.owner}.json", source)
        self.assertIn("api/v1/systems/${words.slice(0, size).join('-')}.json", source)
        style = _read(COMPONENTS / "MarkdownContent.astro")
        self.assertIn("max-width: 40rem;", style)
        self.assertIn("width: 100%;", style)


class Picker(unittest.TestCase):
    def test_choices(self):
        source = _read(COMPONENTS / "FilePicker.astro")
        self.assertIn("box.checked = preset ? preset.includes(choice.id) : false;", source)
        self.assertIn(".sort((a, b) => a.title.localeCompare(b.title, 'en'))", source)
        self.assertIn('placeholder="Type a console"', source)
        self.assertIn("filter.focus()", source)
        self.assertIn("n.toLocaleString('en')", source)
        self.assertNotRegex(source, r"`\$\{files\.length\} files")
        self.assertIn("<figcaption>Terminal</figcaption>", source)
        self.assertIn("flex-direction: column;", source)
        # The size gap is the release against the current list, from the
        # release record reduced to the registry's release_pack setups.
        self.assertIn("import release from '../generated/release-advertised.json';", source)
        self.assertIn("It was built from the list of that day.", source)


UNBROKEN = WEBSITE / "src" / "plugins" / "ec-unbroken-tokens.mjs"
LOGOS = REPO_ROOT / "docs_assets" / "logos"

# Shown at 40 px in a tile and beside a setup's title: twice that for a
# sharp mark on a dense screen.
LOGO_PIXELS = 80
TAB_ROOTS = ("", "platforms", "explore", "wiki", "contributing")


def _title_through_heading(html: str) -> str:
    """What PageTitle draws: from the main column to the end of the h1."""
    end = html.index("</h1>", html.index('id="_top"'))
    return html[html.rfind("<main", 0, end):end]


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
                block = _title_through_heading(_built(f"platforms/{entry['platform']}"))
                self.assertIn('class="rb-title-mark', block)
                for image in re.findall(r"<img\b[^>]*>", block):
                    self.assertIn('width="40"', image)
                    self.assertIn('height="40"', image)

    def test_a_setup_with_no_logo_gets_its_initials(self):
        # Every setup has a logo today: the fallback is read where it is
        # written, the tile's and the title's.
        import sitemarkup  # noqa: PLC0415

        self.assertIn('data-initials="MM" aria-hidden="true"></span>', sitemarkup._tile_mark("MyMinUI", ""))
        component = _read(REPO_ROOT / "website" / "src" / "components" / "PageTitle.astro")
        self.assertIn("{initials(setup.name)}", component)

    def test_myminui_shows_its_logo(self):
        block = _title_through_heading(_built("platforms/myminui"))
        self.assertIn('src="/retrobios/assets/logos/myminui.webp"', block)


class NoLevelBadgeOnATabRoot(unittest.TestCase):
    def test_tab_roots(self):
        for page in TAB_ROOTS:
            with self.subTest(page=page or "home"):
                self.assertNotIn('class="rb-level ', _title_through_heading(_built(page)))


class OneTabIsNoTabBar(unittest.TestCase):
    """142 tab bars held one tab, most of them "On the device" right under
    the heading "On the device"."""

    def test_a_single_item_stands_alone(self):
        import sitemarkup
        import siteguides

        self.assertEqual(sitemarkup.tabs([("Linux", ["run it"])]), ["**Linux**", "", "run it", ""])
        self.assertEqual(sitemarkup.tabs([("", ["run it"])]), ["run it", ""])
        self.assertIn('<Tabs syncKey="os">', sitemarkup.tabs([("A", ["a"]), ("B", ["b"])]))
        device = "\n".join(siteguides.terminal_tabs(("device",), {}))
        self.assertNotIn("<Tab", device)
        self.assertNotIn("On the device", device)


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
            for table in _tables(_built(page)):
                if len(_headers(table)) < 4:
                    continue
                with self.subTest(page=page, header=_headers(table)):
                    self.assertIn('data-rb-stack="true"', table.split(">", 1)[0])

    def test_no_build_is_a_skip_not_a_pass(self):
        """Every missing page was a `continue`: with no build the test ran no
        assertion and still reported ok."""
        from unittest import mock

        module = sys.modules[__name__]
        case = WideTablesStackAndFiltersAreBuilt("test_every_wide_table_stacks")
        result = unittest.TestResult()
        with mock.patch.object(module, "DIST", REPO_ROOT / "tmp" / "no-such-dist"):
            case.run(result)
        self.assertEqual(len(result.skipped), 1)

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
        boxes = re.findall(r'<div class="rb-table-filter"[^>]*>(.*?)</div>\s*<table', html, re.S)
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
        self.assertIn("import { type FileHashes, hashFile } from './hashes.ts';", source)
        self.assertIn("lookUp(status, result, [found.sha1, found.md5, found.crc32, found.sha256])", source)
        hashing = _read(HASHES_TS)
        self.assertIn("crypto.subtle.digest(name, buffer)", hashing)
        self.assertIn("['SHA-1', 'SHA-256']", hashing)


class FileHashesMatchPython(unittest.TestCase):
    """MD5 and CRC32 are written here, Web Crypto having neither: each is
    checked against hashlib and zlib, whole and fed in uneven slices, and
    hashFile's four values against a file read in 4 MiB slices."""

    SIZES = [0, 1, 55, 56, 63, 64, 65, 119, 120, 128, 1000, 70_001]

    @staticmethod
    def _bytes(size: int) -> bytes:
        return bytes((i * 31 + 7) & 0xFF for i in range(size))

    def _run(self, body: str) -> list:
        return json.loads(_node_module(
            f"import {{ Crc32, Md5, crc32, hashFile, md5 }} from {json.dumps(HASHES_TS.as_uri())};"
            "const fill = (n) => { const b = new Uint8Array(n);"
            " for (let i = 0; i < n; i += 1) b[i] = (i * 31 + 7) & 0xff; return b; };" + body
        ))

    def test_md5_and_crc32_whole(self):
        out = self._run(
            f"console.log(JSON.stringify({json.dumps(self.SIZES)}.map((n) => "
            "{ const bytes = fill(n); return [md5(bytes), crc32(bytes)]; })));"
        )
        for size, (md5, crc) in zip(self.SIZES, out):
            data = self._bytes(size)
            with self.subTest(size=size):
                self.assertEqual(md5, hashlib.md5(data).hexdigest())
                self.assertEqual(crc, f"{zlib.crc32(data):08x}")

    def test_md5_and_crc32_in_slices(self):
        """A slice ending inside a 64-byte block carries it to the next."""
        size, steps = 200_003, [1, 63, 64, 65, 3, 1000, 7, 100_000]
        out = self._run(
            f"const bytes = fill({size}); const steps = {json.dumps(steps)};"
            "const m = new Md5(); const c = new Crc32();"
            "for (let at = 0, k = 0; at < bytes.length; k += 1) {"
            " const piece = bytes.subarray(at, at + steps[k % steps.length]);"
            " m.update(piece); c.update(piece); at += piece.length; }"
            "console.log(JSON.stringify([m.digest(), c.digest()]));"
        )
        data = self._bytes(size)
        self.assertEqual(out, [hashlib.md5(data).hexdigest(), f"{zlib.crc32(data):08x}"])

    def test_hash_file_reads_slices_and_reports_progress(self):
        size = 9 * 1024 * 1024 + 17
        out = self._run(
            f"const shares = []; const found = await hashFile(new Blob([fill({size})]),"
            " (share) => shares.push(share));"
            "console.log(JSON.stringify([found, shares.length, shares.at(-1),"
            " shares.every((v, i) => i === 0 || v >= shares[i - 1])]));"
        )
        data = self._bytes(size)
        found, steps, last, rising = out
        self.assertEqual(found, {
            "sha1": hashlib.sha1(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
            "crc32": f"{zlib.crc32(data):08x}",
            "sha256": hashlib.sha256(data).hexdigest(),
        })
        self.assertGreaterEqual(steps, 3)
        self.assertEqual(last, 1)
        self.assertTrue(rising)


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
    """The tabs wrap (retrobios.css): the script picks the
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
        self.assertIn('square_image(\n                data, LOGO_SIZE, "WEBP"', script)

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


SHORT_CODE = WEBSITE / "src" / "plugins" / "rehype-short-code.mjs"

# The four hashes of one dump, bios/Sony/PlayStation/scph5501.bin.
SCPH5501 = {
    "md5": "490f666e1afb15b7362b406ed1cea246",
    "sha1": "0555c6fae8906f3f09baf5988f00e55f88e9f30b",
    "crc32": "8d8cb7e4",
    "sha256": "11052b6499e466bbf0a709b1f9cb6834a9418e66680387912451e971cf8a1fef",
}
ANDROID_UA = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36")


def _node_typescript(script: str) -> str:
    node = shutil.which("node")
    if not node:
        raise unittest.SkipTest("node is missing")
    result = subprocess.run(
        [node, "--input-type=module-typescript", "-e", script],
        capture_output=True, text=True, check=True, cwd=WEBSITE,
    )
    return result.stdout


def _short_unmarked(html: str) -> list[str]:
    """Inline code of 30 characters or fewer without rb-short, outside pre."""
    body = re.sub(r"<pre\b.*?</pre>", "", html, flags=re.S)
    found = []
    for attributes, text in re.findall(r"<code(\s[^>]*)?>([^<]*)</code>", body):
        plain = re.sub(r"&(?:#\d+|#x[0-9a-f]+|[a-z]+);", "_", text, flags=re.I)
        if 0 < len(plain) <= 30 and "rb-short" not in (attributes or ""):
            found.append(text)
    return found


class AGithubPathStaysInTheRepository(unittest.TestCase):
    """The 404 hint linked a GitHub path typed under this site: an encoded
    /blob/..%2F..%2Fother/x resolved to another account's page."""

    def _hrefs(self, paths: list[str]) -> list:
        source = _read(SITE_TS)
        rule = source[source.index("function githubPathHref"):source.index("// End of the GitHub path rule.")]
        out = _node_typescript(rule + f"console.log(JSON.stringify({json.dumps(paths)}.map(githubPathHref)));")
        return json.loads(out)

    def test_a_path_of_the_repository_is_linked(self):
        self.assertEqual(self._hrefs([
            "blob/main/bios/Sony/PlayStation/scph5501.bin",
            "tree/main/bios/",
            "raw/main/bios/3D%20Realms/x.zip",
        ]), [
            "https://github.com/Abdess/retrobios/blob/main/bios/Sony/PlayStation/scph5501.bin",
            "https://github.com/Abdess/retrobios/tree/main/bios",
            "https://github.com/Abdess/retrobios/blob/main/bios/3D%20Realms/x.zip",
        ])

    def test_a_path_leaving_the_repository_gets_no_link(self):
        self.assertEqual(self._hrefs([
            "blob/..%2F..%2F..%2Fother/x",
            "blob/../../../other/x",
            "blob/main/%2E%2E/%2E%2E/%2E%2E/other",
            "blob/main/a%2Fb",
            "blob/main/a%5Cb",
            "blob/main//x",
            "blob/main/%E0%A4%A",
            "issues/1",
        ]), [None] * 8)


class OneVerdictWhateverHash(unittest.TestCase):
    """2.1: the SHA1 of scph5501.bin found 4 setups, its MD5 12, its SHA256
    none (V1, J4). A setup's list writes one hash of a file."""

    def test_the_other_hashes_are_read(self):
        source = _read(SITE_TS)
        self.assertIn("const heldHashes = (file: Held) =>", source)
        self.assertIn("await lookupValues(others)", source)
        self.assertIn("item.sha1 ?? files.find((file) => file && heldHashes(file).includes(item.value))?.sha1", source)
        self.assertIn("(fileOf(declared) ?? item.sha1) === item.sha1", source)

    def test_the_verdict_names_the_other_name(self):
        source = _read(SITE_TS)
        self.assertIn("'another name' : 'other names'}: `", source)
        self.assertNotIn("under the ${otherNames.length === 1 ? 'name' : 'names'}", source)

    def test_entries_match_on_any_hash_of_the_file(self):
        source = _read(SITE_TS)
        self.assertIn("const HASH_FIELDS = ['sha1', 'md5', 'crc32', 'sha256'];", source)
        self.assertIn("declaredEntry(item, valuesOf(item))", source)
        self.assertIn("readerEntry(reader.get(item.owner ?? ''), item, valuesOf(item))", source)

    def test_what_the_renderer_reads_is_built(self):
        """Each hash finds the collection record with its SHA1, and the
        manufacturer file gives the other three, so every paste reads the
        same four shards."""
        api = DIST / "api" / "v1"
        if not (api / "lookup").is_dir():
            self.skipTest("no built site")
        for value in SCPH5501.values():
            with self.subTest(value=value):
                shard = json.loads(_read(api / "lookup" / f"{value[:2]}.json"))["items"]
                held = [i for i in shard if i["value"] == value and i["layer"] == "collection"]
                self.assertEqual([i["sha1"] for i in held], [SCPH5501["sha1"]])
                self.assertIn("/systems/sony-playstation/", held[0]["url"])
        consoles = json.loads(_read(api / "systems" / "sony.json"))["items"][0]["consoles"]
        card = next(f for files in consoles.values() for f in files if f["sha1"] == SCPH5501["sha1"])
        self.assertEqual({k: card[k] for k in SCPH5501}, SCPH5501)


class TheVisitorsTab(unittest.TestCase):
    """2.2: on an Android phone the tabs opened on Windows (V4, T-F1)."""

    def _rule(self) -> str:
        source = _read(SITE_TS)
        return source[source.index("const OS_TAB_RULES"):source.index("// End of the OS tab rule.")]

    def test_labels_from_the_user_agent(self):
        cases = [
            [ANDROID_UA, ""],
            ["Mozilla/5.0 (X11; Linux x86_64) Valve Steam GameOverlay/1729", "Linux"],
            ["Mozilla/5.0 (X11; Linux x86_64; SteamOS) Firefox/130.0", ""],
            ["Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) Safari/605.1.15", ""],
            ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0", "Windows"],
            ["Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0", "Linux"],
            ["Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Safari/604.1", ""],
            ["Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) Chrome/130.0", "Chrome OS"],
        ]
        out = _node_typescript(self._rule() + f"console.log(JSON.stringify({json.dumps(cases)}.map(([ua, p]) => osTabLabel(ua, p))));")
        self.assertEqual(json.loads(out), [
            "Android (Termux)", "Steam Deck", "Steam Deck", "macOS", "Windows", "Linux", "", "",
        ])

    def test_labels_are_tab_labels(self):
        guides = _read(REPO_ROOT / "platforms" / "_guides.yml")
        for label in re.findall(r"\[/[^/]+/i, '([^']+)'\]", self._rule()):
            with self.subTest(label=label):
                self.assertIn(f"label: {label}\n", guides)

    def test_a_saved_choice_wins_and_the_guess_is_not_saved(self):
        source = _read(SITE_TS)
        block = source[source.index("const osTabs = () =>"):source.index("// The sidebar lists")]
        self.assertIn("savedTab(OS_SYNC_KEY)", block)
        self.assertIn("set.switchTab(set.tabs[index], index, false)", block)
        self.assertNotIn("localStorage.setItem", block)
        # The one choice the script saves is the setup picked in an install
        # box, under its own key: never the OS guess.
        self.assertEqual(re.findall(r"localStorage\.setItem\((\w+)", source), ["SETUP_KEY"])
        self.assertNotIn("keepTabInView", source)


class TheSidebarShowsTheCurrentPage(unittest.TestCase):
    """2.3: the current link sat at y 1364 in a 900 px window (V5)."""

    def test_the_pane_scrolls_never_the_page(self):
        source = _read(SITE_TS)
        block = source[source.index("const showCurrentPage = () =>"):source.index("// A glossary term")]
        self.assertIn("pane.scrollTop +=", block)
        self.assertIn("pane.clientHeight / 3", block)
        self.assertIn("addEventListener('toggle'", block)
        self.assertNotIn("scrollIntoView", source)
        self.assertIn("showCurrentPage();", source)


class ChromeOutOfTheIndex(unittest.TestCase):
    """2.4: excerpts opened on the title and closed on the licence line, and
    "bios" matched every page through the footer (N2, V6)."""

    def test_components(self):
        title = _read(COMPONENTS / "PageTitle.astro")
        self.assertIn('<nav class="rb-breadcrumbs" aria-label="Breadcrumb" data-pagefind-ignore>', title)
        self.assertEqual(title.count('data-pagefind-ignore data-pagefind-meta="title"'), 2)
        footer = _read(COMPONENTS / "Footer.astro")
        self.assertIn('<div class="rb-footer-root" data-pagefind-ignore>\n<Default />', footer)

    def test_built_page(self):
        html = _built("systems/sony-playstation")
        self.assertRegex(html, r'<nav class="rb-breadcrumbs[^"]*"[^>]*data-pagefind-ignore')
        self.assertRegex(html, r'<h1 id="_top"[^>]*data-pagefind-ignore[^>]*data-pagefind-meta="title"')
        root = html.index('class="rb-footer-root')
        self.assertIn("data-pagefind-ignore", html[html.rfind("<div", 0, root):root + 80])
        self.assertGreater(html.index("MIT for the tooling"), root)


class ShortCodeMarked(unittest.TestCase):
    """2.5: `--restore` split into `--` and `restore` on the home page at
    1440 px, and 51 flags split in the installer's options table (V3)."""

    def test_the_rule(self):
        out = _node_typescript(
            f"import {{ isShort, markRawCode, SHORT_CODE }} from {json.dumps(SHORT_CODE.as_uri())};"
            "console.log(JSON.stringify([SHORT_CODE, isShort('--restore', false), isShort('--restore', true),"
            "isShort('x'.repeat(31), false), markRawCode('<td><code>bios/a.bin</code> <code class=\"rb-hash\">ab</code></td>'),"
            "markRawCode('<pre><code>a</code></pre>')]));"
        )
        self.assertEqual(json.loads(out), [
            30, True, False, False,
            '<td><code class="rb-short">bios/a.bin</code> <code class="rb-hash">ab</code></td>',
            "<pre><code>a</code></pre>",
        ])

    def test_registered(self):
        config = _read(CONFIG)
        self.assertIn("hastPlugins: [stackTables(), shortCode()],", config)

    def test_every_short_code_is_marked(self):
        for page in ("", "wiki/installer", "which-pack", "emulators/duckstation", "systems/sony", "wiki/faq"):
            with self.subTest(page=page or "home"):
                self.assertEqual(_short_unmarked(_built(page)), [])
        self.assertIn('class="rb-short"', _built(""))

    def test_the_options_table(self):
        self.assertRegex(_built("wiki/installer"), r'<table[^>]*\sclass="(?:[^"]*\s)?rb-options[\s"]')


class SearchFields(unittest.TestCase):
    """2.6: `consoles` and `terms` weigh as a title (N3, T-F2, D4)."""

    def test_declared_and_never_shown(self):
        config = _read(CONFIG)
        self.assertIn("metaWeights: { title: 10, files: 0.5, aliases: 10, devices: 5, consoles: 100, exact: 20, terms: 30 },", config)
        self.assertIn("const UNSHOWN_FIELDS = new Set(['files', 'aliases', 'devices', 'consoles', 'exact', 'terms']);", _read(SITE_TS))


class SearchLoadsOnFirstUse(unittest.TestCase):
    """2.7: ui-core.js (25.8 KiB) loaded on idle on every page (T-F8)."""

    def test_the_override(self):
        self.assertIn("Search: './src/components/Search.astro',", _read(CONFIG))
        search = _read(COMPONENTS / "Search.astro")
        self.assertNotIn("requestIdleCallback", search)
        self.assertNotIn("DOMContentLoaded", search)
        self.assertIn("for (const type of ['pointerenter', 'pointerdown', 'focus'])", search)
        self.assertIn("loadSearch()?.then(", search)
        self.assertNotIn("TODO", search)


class LogosAtTheirWeight(unittest.TestCase):
    """2.7: two logos were Inkscape files, one with a 441 x 334 PNG inside."""

    def test_no_editor_markup_and_small_rasters(self):
        import base64
        import struct

        for path in sorted(LOGOS.glob("*.svg")):
            text = _read(path)
            with self.subTest(logo=path.name):
                self.assertNotRegex(text, r"inkscape:|sodipodi:|<metadata")
                self.assertNotRegex(text, r"data:image/(?!png)")
                for data in re.findall(r"data:image/png;base64,([A-Za-z0-9+/=]+)", text):
                    # Width and height of a PNG: the IHDR chunk, bytes 16 to 24.
                    width, height = struct.unpack(">II", base64.b64decode(data)[16:24])
                    self.assertLessEqual(max(width, height), 80)

    def test_the_fetcher_writes_them_so(self):
        script = _read(REPO_ROOT / "scripts" / "fetch_site_images.py")
        self.assertIn('minify_svg(shrink_embedded(safe_svg(data, url)))', script)


class CopyButtonInTheHeader(unittest.TestCase):
    """2.10: on touch the copy button covered the end of the first line."""

    def test_rule(self):
        source = _read(COMPONENTS / "MarkdownContent.astro")
        self.assertIn("@media (pointer: coarse)", source)
        self.assertIn(".expressive-code .frame.has-title .copy { inset-block-start:", source)


PLUGINS = WEBSITE / "src" / "plugins"
STACK_TABLES = PLUGINS / "rehype-stack-tables.mjs"
ENTITY = re.compile(r"&(?:#\d+|#x[0-9a-f]+|[a-z]+);", re.I)


def _node(script: str) -> str:
    node = shutil.which("node")
    if not node:
        raise unittest.SkipTest("node is missing")
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        capture_output=True, text=True, check=True, cwd=WEBSITE,
        env={"NODE_DISABLE_COMPILE_CACHE": "1", "PATH": str(Path(node).parent)},
    )
    return result.stdout


def _text(page: str) -> str:
    """A built page's visible words: tags dropped, entities read."""
    return html.unescape(re.sub(r"<[^>]+>", "", page))


def _picker_packs() -> set[str]:
    """The setups the built picker offers a release ZIP line for."""
    page = _built("which-pack")
    match = re.search(r'data-release="([^"]*)"', page)
    if not match:
        raise AssertionError("which-pack has no picker release data")
    return set(json.loads(html.unescape(match[1]))["packs"])


class PickerFollowsTheRegistry(unittest.TestCase):
    """2.1: the picker said "The ZIP of release v2026.10.10 holds 5,804
    files" for ROCKNIX while its setup page and get/ page said "No ZIP for
    ROCKNIX" (N2, J5). The picker read the raw release.json."""

    def test_source(self):
        source = _read(COMPONENTS / "FilePicker.astro")
        self.assertIn("import release from '../generated/release-advertised.json';", source)
        self.assertNotIn("release.json'", source)

    def test_picker_offers_only_registry_packs(self):
        offered = _picker_packs()
        self.assertTrue(offered)
        released = set(list_release_pack_platforms(str(REPO_ROOT / "platforms")))
        self.assertLessEqual(offered, released)

    def test_picker_setup_and_get_pages_agree(self):
        offered = _picker_packs()
        setups = json.loads(_read(DIST / "data" / "picker" / "index.json"))
        self.assertTrue(setups)
        for entry in setups:
            name = entry["platform"]
            with self.subTest(platform=name):
                get_page = _text(_built(f"get/{name}"))
                setup_page = _text(_built(f"platforms/{name}"))
                no_zip = f"No ZIP for {entry['name']}."
                self.assertEqual(name in offered, no_zip not in get_page)
                self.assertEqual(name in offered, no_zip not in setup_page)


class PathsBreakAtSeparators(unittest.TestCase):
    """2.2: `~/.var/app/org.libretro.RetroArch/config/r` then
    `etroarch/system/` on platforms/retroarch/ at 390 px (V8)."""

    def test_the_rule(self):
        uri = json.dumps(SHORT_CODE.as_uri())
        out = _node(
            f"import {{ markRawCode, withBreaks, breaksAtSeparators }} from {uri};"
            "console.log(JSON.stringify(["
            "markRawCode('<td><code>~/.config/retroarch/system/aaaaaaaaaaa/</code> <code>bios/a.bin</code></td>'),"
            "markRawCode('<td><code class=\"rb-path\">C:\\\\RetroArch-Win64\\\\system\\\\aaaaaaaaaaaaa</code></td>'),"
            "withBreaks('a/b/'), breaksAtSeparators('x'.repeat(31), false),"
            "breaksAtSeparators('a/' + 'x'.repeat(30), true), breaksAtSeparators('a/b', false)]));"
        )
        self.assertEqual(json.loads(out), [
            '<td><code>~/<wbr>.config/<wbr>retroarch/<wbr>system/<wbr>aaaaaaaaaaa/</code>'
            ' <code class="rb-short">bios/a.bin</code></td>',
            '<td><code class="rb-path">C:\\<wbr>RetroArch-Win64\\<wbr>system\\<wbr>aaaaaaaaaaaaa</code></td>',
            "a/<wbr>b/", False, False, False,
        ])

    def test_built_page(self):
        page = _built("platforms/retroarch")
        self.assertIn("~/<wbr>.var/<wbr>app/<wbr>org.libretro.RetroArch/<wbr>config/<wbr>retroarch/<wbr>system/", page)

    def test_the_page_budget(self):
        """Each `wbr` is an element: bluemsx held 3,097 of them on 9,369
        elements against a budget of 10,000. The build spends BREAK_BUDGET
        per page, the runtime writes the others."""
        uri = json.dumps(SHORT_CODE.as_uri())
        out = _node(
            f"import {{ markRawCode, BREAK_BUDGET }} from {uri};"
            "const room = { left: 3 };"
            "const path = '<code>aaaaaaaaaa/bbbbbbbbbb/cccccccccc/d</code>';"
            "console.log(JSON.stringify([BREAK_BUDGET, markRawCode(path, room), markRawCode(path, room), room.left]));"
        )
        budget, first, second, left = json.loads(out)
        self.assertEqual(first, "<code>aaaaaaaaaa/<wbr>bbbbbbbbbb/<wbr>cccccccccc/<wbr>d</code>")
        self.assertEqual(second, "<code>aaaaaaaaaa/bbbbbbbbbb/cccccccccc/d</code>")
        self.assertEqual(left, 0)
        if not DIST.is_dir():
            self.skipTest("no built site")
        # Link text the generator breaks itself (a forge address) is not code.
        code = re.compile(r"<code(?:\s[^>]*)?>(?:[^<]|<wbr>)*</code>")
        over = [str(path.relative_to(DIST)) for path in DIST.rglob("index.html")
                if sum(found.count("<wbr>") for found in code.findall(_read(path))) > budget]
        self.assertEqual(over, [])

    def test_the_runtime_writes_the_rest(self):
        source = _read(SITE_TS)
        self.assertIn("const LONG_CODE = 30;", source)
        self.assertIn("const SEPARATORS = /([/\\\\])(?!$)/g;", source)
        self.assertIn("if (unbrokenPath(code)) observer.observe(code);", source)
        self.assertIn("\nbreakPaths();\n", source)
        plugin = _read(SHORT_CODE)
        self.assertIn("export const SHORT_CODE = 30;", plugin)
        self.assertIn("const SEPARATORS = /([/\\\\])(?!$)/g;", plugin)

    def test_every_long_path_breaks_at_run_time(self):
        """Inline code over 30 characters holding a separator: the build
        broke it, or the runtime rule picks it (all text, no `wbr`)."""
        if not DIST.is_dir():
            self.skipTest("no built site")
        unbroken = []
        for path in sorted(DIST.rglob("index.html")):
            page = _read(path)
            if 'http-equiv="refresh"' in page or "sl-markdown-content" not in page:
                continue
            body = re.sub(r"<pre\b.*?</pre>", "", page[page.index("sl-markdown-content"):], flags=re.S)
            for text in re.findall(r"<code(?:\s[^>]*)?>((?:[^<]|<(?!/code>))*)</code>", body):
                plain = ENTITY.sub("_", re.sub(r"<wbr>", "", text))
                if len(plain) > 30 and re.search(r"[/\\]", plain[:-1]) \
                        and "<wbr>" not in text and "<" in text:
                    unbroken.append(f"{path.relative_to(DIST)}: {text}")
        self.assertEqual(unbroken, [])

    def test_crumb_labels_in_a_span(self):
        source = _read(COMPONENTS / "PageTitle.astro")
        self.assertIn("<a href={crumb.href}><span>{crumb.label}</span></a> : <span>{crumb.label}</span>", source)
        crumbs = _built("platforms/retroarch")
        crumbs = crumbs[crumbs.index('class="rb-breadcrumbs'):]
        crumbs = crumbs[:crumbs.index("</ol>")]
        items = re.findall(r"<li\b[^>]*>(.*?)</li>", crumbs)
        self.assertTrue(items)
        for item in items:
            self.assertRegex(item, r"^(?:<a\b[^>]*>)?<span\b[^>]*>[^<]+</span>")


class ShortStackedLabels(unittest.TestCase):
    """2.3: "Name as declared" and "On its BIOS list (destinations)" wrap
    to two lines in the stacked label column (V9)."""

    def test_the_rule(self):
        uri = json.dumps(STACK_TABLES.as_uri())
        out = _node(
            f"import {{ stackedLabel }} from {uri};"
            "console.log(JSON.stringify([stackedLabel('Declared as', 'Name as declared'),"
            "stackedLabel(undefined, 'Setup'), stackedLabel(' ', 'Setup')]));"
        )
        self.assertEqual(json.loads(out), ["Declared as", "Setup", "Setup"])

    def test_plugin_and_runtime_read_the_title(self):
        plugin = _read(STACK_TABLES)
        self.assertIn("stackedLabel(cell.properties?.title, labels[column])", plugin)
        self.assertIn("ctx.setProperty(cell, 'dataLabel', stacked[column])", plugin)
        runtime = _read(SITE_TS)
        self.assertIn("cell.getAttribute('title')?.trim() || (cell.textContent?.trim() ?? '')", runtime)
        self.assertIn("[...table.querySelectorAll('thead th')].map(stackedLabel)", runtime)
        self.assertIn("'Name as declared': 'Declared as'", runtime)
        self.assertIn("cell.dataset.label = stackedLabel(head.cells[column]);", runtime)


class LookupShowsTheDeclaredHash(unittest.TestCase):
    """2.4: with the CRC32 pasted, Batocera's row read "Hash matched: CRC32",
    though Batocera declares an MD5 (J9, N10)."""

    def test_source(self):
        source = _read(SITE_TS)
        self.assertIn("declared?: string;", source)
        self.assertIn("const declaredHash = (item: Item) => (item.declared || item.algorithm).toUpperCase();", source)
        table = source[source.index("const setupTable"):source.index("const distinct")]
        self.assertIn("declaredHash(item),", table)
        self.assertNotIn("item.algorithm", table)


class AChecksumLineIsAHash(unittest.TestCase):
    """The lookup and the search took a bare hash only: the line md5sum,
    shasum --tag, certutil or Get-FileHash prints was refused whole."""

    def test_the_hash_is_read_out_of_the_line(self):
        source = _read(SITE_TS)
        code = (source[source.index("const HASH_LENGTHS"):source.index("\n", source.index("const HASH_LENGTHS"))]
                + source[source.index("const normalizeHash"):source.index("// Tables")])
        md5, sha1 = "490f666e1afb15b7362b406ed1cea246", "b05def971d8ec59f346f2d9ac21fb742e3eb6917"
        spaced = " ".join(sha1[i:i + 2] for i in range(0, 40, 2))
        cases = [
            f"{md5}  scph5501.bin",
            f"SHA1 (scph5501.bin) = {sha1}",
            f"SHA1 hash of scph5501.bin:\r\n{spaced}\r\nCertUtil: -hashfile command completed successfully.",
            f"Algorithm Hash Path\n--------- ---- ----\nSHA1 {sha1.upper()} C:\\bios\\scph5501.bin",
            f"  0x{md5.upper()} ",
            "8d8cb7e4",
            "deadbeef.bin",
            f"{md5} {sha1}",
        ]
        out = _node_typescript(code + f"console.log(JSON.stringify({json.dumps(cases)}.map((c) => "
                           "[normalizeHash(c), isHash(normalizeHash(c))])));")
        self.assertEqual(json.loads(out), [
            [md5, True], [sha1, True], [sha1, True], [sha1, True], [md5, True],
            ["8d8cb7e4", True], ["deadbeef.bin", False], [md5 + sha1, False],
        ])

    def test_the_form_takes_the_line(self):
        source = _read(REPO_ROOT / "scripts" / "generate_site.py")
        start = source.index('<input id="rb-hash"')
        self.assertNotIn("pattern=", source[start:source.index("required>", start)])


if __name__ == "__main__":
    unittest.main()
