"""File cards and install boxes read at a glance (density round, 2026-10-27).

A system page wrote every setup's install command for each console, twice:
12 long lines for the PSP. A file card showed four full hashes, the
collection path and the catalogue records before the next file. Now a box
shows one command for the setup picked, and a card shows the name, the
size, the download, a short SHA1, the setups and the emulators. The rest
sits in closed folds, every fact still on the page.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import re
import sys
import types
import unittest
from html.parser import HTMLParser
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site as gs  # noqa: E402
import sitemarkup as markup  # noqa: E402
from cross_reference import FileConsumers  # noqa: E402

DIST = REPO_ROOT / "website" / "dist"
SITE_TS = REPO_ROOT / "website" / "src" / "scripts" / "site.ts"

SHA1 = "30a33f3651f8e1b0967a5dfe6ff714baebcce41a"
MD5 = "866855cc330b9b95cc69135fb7b41d38"
CRC32 = "7b57fa78"
SHA256 = "3ab7fcf6956d0281ada94d501fc6d1cfa8fc034f139e25fed6c829f723d92a95"


class _Visible(HTMLParser):
    """Words shown before any fold is opened: text outside closed details
    (their summary counts), hidden elements, scripts and styles."""

    VOID = {"br", "img", "input", "wbr", "hr", "meta", "link", "source"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, object]] = []
        self.hidden = 0
        self.words: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in self.VOID:
            return
        names = dict(attrs)
        if tag == "summary" and self.stack and self.stack[-1] == ("details", True):
            self.hidden -= 1
            self.stack.append((tag, "shown"))
            return
        hides = tag in ("script", "style") or "hidden" in names or (
            tag == "details" and "open" not in names)
        self.hidden += hides
        self.stack.append((tag, hides))

    def handle_endtag(self, tag: str) -> None:
        while self.stack:
            name, hides = self.stack.pop()
            if hides == "shown":
                self.hidden += 1
            elif hides:
                self.hidden -= 1
            if name == tag:
                break

    def handle_data(self, data: str) -> None:
        if not self.hidden:
            self.words += data.split()


def visible_words(html_text: str) -> list[str]:
    parser = _Visible()
    parser.feed(html_text)
    return parser.words


def _main(page: str) -> str:
    text = (DIST / page / "index.html").read_text(encoding="utf-8")
    return text[text.index("<main"):text.index("</main>")]


def _card_consumers(sha1: str) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        platforms={sha1: {"batocera", "retroarch"}}, emulators={sha1: {"ppsspp"}},
        platform_systems={sha1: {"batocera": {"sony-psp"}, "retroarch": {"sony-psp"}}},
        platform_destinations={sha1: {"batocera": {"psp/ppge_atlas.zim"},
                                      "retroarch": {"PPSSPP/ppge_atlas.zim"}}},
        installed={sha1: {"knulli": {"PPSSPP/ppge_atlas.zim"}}},
        emulator_entries={}, emulator_files={},
    )


def _card() -> dict:
    return {"name": "ppge_atlas.zim", "sha1": SHA1, "md5": MD5, "crc32": CRC32,
            "sha256": SHA256, "size": 666539,
            "path": "bios/Sony/PlayStation Portable/ppge_atlas.zim",
            "provenance": {"tosec": {"name": "ppge_atlas (PPSSPP).zim"}}}


class ASystemCardShowsTheAnswerFirst(unittest.TestCase):
    def setUp(self) -> None:
        self.lines = gs._system_file_card(_card(), _card_consumers(SHA1))
        self.text = "\n".join(self.lines)
        self.fold = self.text[self.text.index("<details"):self.text.index("</details>")]
        self.shown = self.text.replace(self.fold, "")

    def test_the_open_part(self) -> None:
        for fact in ("<code>ppge_atlas.zim</code>", ">666,539 B<", ">Download</a>",
                     "<dt>On the setup's list</dt>", "<dt>Packed for its emulators by</dt>",
                     "<dt>Emulators</dt>", f'<dt>SHA1</dt><dd class="rb-hash">{SHA1[:12]}</dd>'):
            self.assertIn(fact, self.shown)

    def test_every_hash_whole_in_one_fold_with_the_rest(self) -> None:
        for label, value in (("SHA1", SHA1), ("MD5", MD5), ("CRC32", CRC32), ("SHA256", SHA256)):
            self.assertIn(f'<dt>{label}</dt><dd class="rb-hash">{value}</dd>', self.fold)
        shown = " ".join(visible_words(self.text))
        for value in (MD5, CRC32, SHA256, SHA1):
            self.assertNotIn(value, shown)
        self.assertIn("<dt>Collection path</dt>", self.fold)
        self.assertIn("<dt>Catalogued</dt>", self.fold)
        self.assertEqual(self.text.count("<details"), 1)
        self.assertIn("<summary>Hashes, collection path and catalogues</summary>", self.fold)

    def test_the_fold_is_out_of_the_search(self) -> None:
        self.assertTrue(self.fold.startswith("<details data-pagefind-ignore>\n<summary>"))

    def test_no_fact_is_lost(self) -> None:
        # The yardstick list a page is cut by holds every fact: the
        # Starlight card holds each of its values.
        with markup.using("mkdocs"):
            yardstick = "\n".join(gs._system_file_card(_card(), _card_consumers(SHA1)))
        for label, values in re.findall(r"(?m)^- ([^:]+): (.*)$", yardstick):
            self.assertIn(f"<dt>{label}</dt>", self.text)
            for value in re.findall(r"[0-9a-f]{8,64}|`[^`]+`", values):
                self.assertIn(value.strip("`"), self.text, label)

    def test_a_card_reads_in_few_words(self) -> None:
        # Measured on this card: 31 words open, 40 before the round.
        self.assertLessEqual(len(visible_words(self.text)), min(40, int(31 * 1.05)))


class AnEmulatorCardFoldsItsHashes(unittest.TestCase):
    def setUp(self) -> None:
        entry = {"name": "scph5501.bin", "md5": "490f666e1afb15b7362b406ed1cea246",
                 "sha1": "b05def971d8ec59f346f2d9ac21fb742e3eb6917", "size": 524288,
                 "required": True, "note": "Read at boot.", "priority": 5,
                 "validation": ["md5"], "source_ref": "src/core/bios.cpp:47"}
        profile = {"emulator": "DuckStation", "files": [entry], "systems": ["sony-playstation"]}
        self.text = "\n".join(gs._render_emulator_file(
            entry, profile, None, profile["files"], lambda _f: True, anchor="file-scph5501-bin"))
        self.fold = self.text[self.text.index("<details"):self.text.index("</details>")]
        self.shown = self.text.replace(self.fold, "")

    def test_a_short_hash_open_and_every_hash_folded(self) -> None:
        # On the size's line.
        self.assertIn('- Size: 512.0 KB, SHA1 <span class="rb-hash" '
                      'data-copy="b05def971d8ec59f346f2d9ac21fb742e3eb6917">b05def971d8e</span>',
                      self.shown)
        self.assertIn('<code class="rb-hash" data-copy="">490f666e1afb15b7362b406ed1cea246</code>',
                      self.fold)
        self.assertNotIn("490f666e1afb15b7362b406ed1cea246", self.shown)

    def test_notes_open_the_rest_folded(self) -> None:
        self.assertIn("Read at boot.", self.shown)
        for fact in ("Priority: 5", "Validation: md5", "Source:"):
            self.assertIn(fact, self.fold)
            self.assertNotIn(fact, self.shown)
        self.assertIn("<summary>Hashes, priority, validation and more</summary>", self.fold)

    def test_the_markdown_yardstick_is_unchanged(self) -> None:
        with markup.using("mkdocs"):
            entry = {"name": "a.bin", "md5": "b" * 32, "size": 4}
            text = "\n".join(gs._render_emulator_file(
                entry, {"files": [entry]}, None, [entry], lambda _f: True))
        self.assertNotIn("<details", text)
        self.assertIn("- MD5: ", text)


PAIRS = [("emudeck", "sony-psp"), ("retroarch", "sony-psp"), ("retrobat", "Neo Geo")]


class AnInstallBoxShowsOneCommand(unittest.TestCase):
    def setUp(self) -> None:
        self.text = "\n".join(gs._console_install_block("PlayStation Portable", PAIRS))

    def test_one_command_per_tab_for_the_setup_picked(self) -> None:
        tabs = self.text[self.text.index("<Tabs"):self.text.index("</Tabs>")]
        self.assertEqual(re.findall(r'<TabItem label="([^"]+)"', tabs),
                         ["Windows", "macOS", "Linux", "Steam Deck"])
        self.assertEqual(tabs.count("--platform"), 4)
        # RetroArch, which runs on each tab's system, not the first by name.
        self.assertEqual(tabs.count("--platform retroarch --system"), 4)

    def test_the_default_setup(self) -> None:
        """AmberELEC led 17 system pages, a handheld system under the
        Windows tab, for being first in alphabetical order."""
        self.assertEqual(gs._default_setup([("amberelec", "psx"), ("retroarch", "Sony - PlayStation")]),
                         ("retroarch", "Sony - PlayStation"))
        self.assertEqual(gs._default_setup([("amberelec", "x"), ("batocera", "x")]), ("batocera", "x"))
        self.assertEqual(gs._default_setup([("amberelec", "x"), ("knulli", "x")]), ("amberelec", "x"))
        select = re.search(r"<select>(.*?)</select>", self.text).group(1)
        self.assertEqual(re.findall(r'<option value="([^"]+)" selected', select), ["retroarch"])

    def test_the_setup_list_carries_every_command(self) -> None:
        select = re.search(r"<select>(.*?)</select>", self.text).group(1)
        options = re.findall(r'<option value="([^"]+)"(?: selected)? data-sh="([^"]+)" data-ps="([^"]+)">',
                             select)
        self.assertEqual([value for value, _sh, _ps in options], ["emudeck", "retroarch", "retrobat"])
        self.assertIn(("retrobat", "--platform retrobat --system 'Neo Geo'",
                       "--platform retrobat --system 'Neo Geo'"), options)

    def test_without_script_the_list_of_every_command_shows(self) -> None:
        self.assertIn('<div class="rb-install" data-rb-install="" hidden>', self.text)
        listed = self.text[self.text.index('<details class="rb-install-all" open>'):]
        for platform, _system in PAIRS:
            self.assertEqual(listed.count(f"--platform {platform} --system"), 2, platform)
        self.assertIn("/i | sh -s -- --platform retrobat --system 'Neo Geo'</code>", listed)
        self.assertIn("/i.ps1))) --platform retrobat --system 'Neo Geo'</code>", listed)
        # The URL is no link inside the command, and the break adds nothing.
        self.assertIn("https://<wbr>abdess.github.io", listed)

    def test_one_setup_keeps_its_two_blocks(self) -> None:
        text = "\n".join(gs._console_install_block("PlayStation Portable", PAIRS[:1]))
        self.assertNotIn("<select", text)
        self.assertIn('```sh title="Terminal"', text)
        self.assertIn('```powershell title="PowerShell"', text)

    def test_the_yardstick_is_unchanged(self) -> None:
        # The budgets that cut a system page are measured on this Markdown:
        # a box that changed it would move cards to other pages.
        with markup.using("mkdocs"):
            text = "\n".join(gs._console_install_block("PlayStation Portable", PAIRS))
        self.assertNotIn("<select", text)
        self.assertEqual(text.count("# RetroBat"), 2)
        self.assertEqual(text.count("/i | sh"), 3)


class TheSetupListLooksLikeAList(unittest.TestCase):
    """The setup list had a rule of its own without the arrow, and read as
    a text field at 390 and 1440 px."""

    def test_the_select_takes_the_site_arrow(self) -> None:
        css = (REPO_ROOT / "website" / "src" / "styles" / "retrobios.css").read_text(encoding="utf-8")
        shared = re.search(r"\.sl-markdown-content select \{([^}]*)\}", css)
        self.assertIsNotNone(shared)
        self.assertIn("appearance: none", shared.group(1))
        self.assertIn("var(--rb-select-arrow)", shared.group(1))
        # No rule for the install box's select overrides it.
        self.assertNotRegex(css, r"rb-install-setup select")
        # The arrow is defined for both themes.
        self.assertEqual(len(re.findall(r"--rb-select-arrow:", css)), 2)
        # The box's select sits in Markdown content, where the shared rule applies.
        box = "\n".join(gs._console_install_block("PlayStation Portable", PAIRS))
        self.assertIn('<label class="rb-install-setup">Setup <select>', box)

    def test_the_built_select_shows_the_arrow(self) -> None:
        if not (DIST / "systems").is_dir():
            self.skipTest("no built site")
        css = "".join(path.read_text(encoding="utf-8") for path in (DIST / "_astro").glob("*.css"))
        self.assertNotIn("rb-install-setup select", css)
        self.assertRegex(css, r"\.sl-markdown-content select\{[^}]*--rb-select-arrow")


class TheScriptWiresBoth(unittest.TestCase):
    def test_pickers_and_copy_buttons_run(self) -> None:
        source = SITE_TS.read_text(encoding="utf-8")
        self.assertIn("\ninstallPickers();\n", source)
        self.assertIn("\ncopyButtons();\n", source)
        self.assertIn("const SETUP_KEY = 'rb-setup';", source)
        self.assertIn("const COPYABLE = '[data-copy]:not(button), .rb-sys-file dd.rb-hash';", source)
        # A platform row's button carries its own data-copy: never given a second button.
        self.assertIn("const own = button.dataset.copy;", source)


# Visible words of each built page: measured before the round and after it,
# the ceiling being the after value with 5 % of room. A page whose content
# grew is measured again on the same layout: Sega on 2026-11-09, with Model 2
# and new Chihiro and Hikaru files.
WORD_CEILINGS = {
    "systems/sony": (2012, 1407),
    "systems/sony-playstation": (2709, 2130),
    "systems/nintendo": (3598, 2941),
    "systems/sega": (4151, 3545),
    "emulators/duckstation": (1188, 1117),
    "emulators/yaps2": (3159, 2655),
}


class BuiltPagesReadInFewerWords(unittest.TestCase):
    def test_visible_words_under_the_ceiling(self) -> None:
        if not (DIST / "systems").is_dir():
            self.skipTest("no built site")
        for page, (before, after) in WORD_CEILINGS.items():
            with self.subTest(page=page):
                ceiling = min(before, int(after * 1.05))
                self.assertLessEqual(len(visible_words(_main(page))), ceiling)

    def test_a_built_card_holds_its_hashes(self) -> None:
        if not (DIST / "systems").is_dir():
            self.skipTest("no built site")
        main = _main("systems/sony-playstation-portable")
        card = main[main.index('id="sha1-30a33f3651f8"'):]
        card = card[:card.index('class="rb-sys-file"')]
        self.assertRegex(card, r'<dd class="rb-hash">30a33f3651f8</dd>')
        self.assertIn('<details data-pagefind-ignore', card)
        self.assertIn(">30a33f3651f8e1b0967a5dfe6ff714baebcce41a</dd>", card)
        # No link inside a command of the list: the URL is text.
        listed = main[main.index("rb-install-all"):]
        self.assertNotRegex(listed[:listed.index("</details>")], r"<code[^>]*>[^<]*<a ")


if __name__ == "__main__":
    unittest.main()
