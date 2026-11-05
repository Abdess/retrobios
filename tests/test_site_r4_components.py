"""Round 4, package 2: components and runtime.

Source checks always run. Checks on the built site read website/dist and
skip when no build is there. The rules written in TypeScript or in a build
plugin run under node and skip without it.
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
SHORT_CODE = WEBSITE / "src" / "plugins" / "rehype-short-code.mjs"
LOGOS = REPO_ROOT / "docs_assets" / "logos"

# The four hashes of one dump, bios/Sony/PlayStation/scph5501.bin.
SCPH5501 = {
    "md5": "490f666e1afb15b7362b406ed1cea246",
    "sha1": "0555c6fae8906f3f09baf5988f00e55f88e9f30b",
    "crc32": "8d8cb7e4",
    "sha256": "11052b6499e466bbf0a709b1f9cb6834a9418e66680387912451e971cf8a1fef",
}
ANDROID_UA = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _built(page: str) -> str:
    path = DIST / page / "index.html"
    if not path.is_file():
        raise unittest.SkipTest(f"no built site at {path}")
    return _read(path)


def _node(script: str) -> str:
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
        out = _node(self._rule() + f"console.log(JSON.stringify({json.dumps(cases)}.map(([ua, p]) => osTabLabel(ua, p))));")
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
        out = _node(
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
        out = _node(code + f"console.log(JSON.stringify({json.dumps(cases)}.map((c) => "
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
