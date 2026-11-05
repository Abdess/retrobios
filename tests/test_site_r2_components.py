"""Round 2, package 2: the site's components and runtime.

Source checks always run. Checks on the built site read website/dist and
skip when no build is there. The stacking rule runs the plugin under node
and skips without node or the site's node_modules.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WEBSITE = REPO_ROOT / "website"
DIST = WEBSITE / "dist"
COMPONENTS = WEBSITE / "src" / "components"
SITE_TS = WEBSITE / "src" / "scripts" / "site.ts"
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
        self.assertEqual(labels, ["Start here", "Your setup", "Explore", "Reference", "Contribute"])
        self.assertEqual(nav.group(1).count('aria-current="true"'), 1)
        self.assertRegex(nav.group(1), r'aria-current="true"[^>]*>\s*Start here')


def _title_block(html: str) -> str:
    """What PageTitle draws: from the main column to the h1."""
    end = html.index('id="_top"')
    return html[html.rfind("<main", 0, end):end]


class LevelBadgeOnlyWhereItAddsSomething(unittest.TestCase):
    def test_badge_follows_the_crumb(self):
        # A tab root: the header tab already says it.
        self.assertNotIn('class="rb-level ', _title_block(_built("platforms")))
        # Under the "Start here" or "Your setup" crumb the badge repeated it.
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


if __name__ == "__main__":
    unittest.main()
