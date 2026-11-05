"""Wiki copy and the diagrams module.

Each class names the finding it holds: a safety line the code contradicted,
install commands with no Windows form, a run's end described wrongly, pages
with two names, an FAQ answer the setups' own checks contradict, a setup
count given two ways, unreadable diagram text, and example hashes that
answered a hash search in place of the file card.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT))

import sitediagrams  # noqa: E402
from siteguides import INSTALL_SH  # noqa: E402

from tests import sitepages  # noqa: E402

WIKI = REPO_ROOT / "wiki"
FENCED = re.compile(r"^```.*?^```", re.S | re.M)


def _front(text: str) -> dict:
    match = re.match(r"---\n(.*?)\n---\n", text, re.S)
    return yaml.safe_load(match.group(1)) if match else {}


def _h1(text: str) -> str:
    match = re.search(r"^# (.+?)(?:\s*\{[^}]*\})?\s*$", FENCED.sub("", text), re.M)
    return match.group(1) if match else ""


def _section(text: str, heading: str) -> str:
    start = re.search(rf"(?m)^#+ {re.escape(heading)}(?:\s*\{{[^}}]*\}})?\n", text)
    if start is None:
        raise AssertionError(f"no section {heading!r}")
    rest = text[start.end():]
    end = re.search(r"(?m)^#{1,2} ", FENCED.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), rest))
    return rest[: end.start()] if end else rest


def _wiki(name: str) -> str:
    return (WIKI / name).read_text(encoding="utf-8")


def _built(name: str) -> str:
    sitepages.require()
    return sitepages.page(name).read_text(encoding="utf-8")


START_PAGES = ("what-are-bios-files.md", "first-install.md", "troubleshooting.md",
               "faq.md", "glossary.md", "legal.md")


class SafetyListMatchesTheInstaller(unittest.TestCase):
    """C1: "It writes only in your BIOS folder", while install.py writes the
    entries marked root: save into the setup's save folder."""

    def test_the_faq_names_the_save_folder_while_a_manifest_writes_there(self):
        saved = [
            path.name for path in sorted((REPO_ROOT / "install").glob("*.json"))
            if any(entry.get("root") == "save"
                   for entry in json.loads(path.read_text(encoding="utf-8")).get("files", []))
        ]
        section = _section(_wiki("faq.md"), "Is the command safe?")
        if saved:
            self.assertNotIn("only in your BIOS folder", section)
            self.assertIn("save folder", section)
        self.assertIn("retrobios-backup", section)
        self.assertIn("--restore", section)


class InstallCommandsHaveEveryForm(unittest.TestCase):
    """N7, B3, C6: troubleshooting and the FAQ gave only `curl ... | sh`.
    Every install command on a Start here page is marked for the system tabs,
    and the built page shows the PowerShell form beside it."""

    def test_every_install_command_on_a_start_page_is_marked(self):
        for name in START_PAGES:
            text = _wiki(name)
            with self.subTest(page=name):
                for match in re.finditer(r"(?m)^```(?:sh|bash)\n(.*?)\n```", text, re.S):
                    if "install.sh" not in match.group(1) or "|" not in match.group(1):
                        continue
                    before = text[: match.start()].rstrip("\n").rsplit("\n", 1)[-1]
                    self.assertRegex(before, r"<!--\s*os-tabs\b", match.group(1))

    def test_the_built_pages_carry_the_windows_form(self):
        for name in ("wiki/troubleshooting.md", "wiki/faq.md", "wiki/first-install.md"):
            text = _built(name)
            with self.subTest(page=name):
                self.assertIn('<TabItem label="Windows">', text)
                self.assertIn("&([scriptblock]::Create((irm", text)
                self.assertNotIn("os-tabs", text)
                self.assertIn('```powershell title="PowerShell"', text)
                self.assertIn('```sh title="Terminal"', text)

    def test_a_windows_path_replaces_the_unix_one(self):
        page = (
            "<!-- os-tabs windows: --platform retroarch --dest E:\\x -->\n```sh\n"
            f"curl -fsSL {INSTALL_SH} \\\n  | sh -s -- --platform retroarch --dest /a/b\n```\n"
        )
        text = sitediagrams.expand_commands(page)
        windows, rest = text.split('<TabItem label="macOS">', 1)
        self.assertIn("--dest E:\\x", windows)
        self.assertNotIn("/a/b", windows)
        self.assertIn("| sh -s -- --platform retroarch --dest /a/b", rest)

    def test_a_marked_block_without_an_install_command_fails_the_build(self):
        with self.assertRaises(ValueError):
            sitediagrams.expand_commands("<!-- os-tabs -->\n```sh\nls -l\n```\n")


class FirstInstallEnds(unittest.TestCase):
    """C7, B15: the page said `Done.` may list failures, and sent a wrong
    folder to a section with no answer for it."""

    def test_the_wrong_folder_answer_is_on_the_screen(self):
        # The one-liner opens the full screen: its first screen has the
        # answer, a row the page names as the interface spells it.
        import install

        section = _section(_wiki("first-install.md"), "2. Check the setup it found")
        state = install.TuiState()
        row = install.tui_rows(state)[-1].label
        self.assertIn(f"**{row}**", section)
        self.assertIn("<your setup>", section)
        self.assertNotIn("Batocera", section)

    def test_the_diagram_follows_the_steps(self):
        text = _wiki("first-install.md")
        self.assertLess(text.index("## 5. Read the result"), text.index("<!-- image: install-flow -->"))


class OneNamePerPage(unittest.TestCase):
    """N11, C4, V22: "Common questions" in the menu opened "FAQ"."""

    def test_no_wiki_page_names_itself_twice(self):
        for path in sorted(WIKI.glob("*.md")):
            text = path.read_text(encoding="utf-8")
            with self.subTest(page=path.name):
                self.assertNotIn("nav_title", _front(text))

    def test_links_to_a_renamed_page_use_its_heading(self):
        names = {path.name: _h1(path.read_text(encoding="utf-8")) for path in WIKI.glob("*.md")}
        stale = {"faq.md": "FAQ", "glossary.md": "Glossary", "legal.md": "The project's legal position"}
        for path in sorted(WIKI.glob("*.md")):
            for text, target in re.findall(r"\[([^\]]+)\]\(([a-z-]+\.md)\)", path.read_text(encoding="utf-8")):
                if target in stale and target in names:
                    with self.subTest(page=path.name, link=text):
                        self.assertNotEqual(text, stale[target])


class ArcadeFilesDependOnTheSetup(unittest.TestCase):
    """C11, C02: "Does a BIOS work on every setup? Yes." Platforms check an
    MD5 and refuse another revision, and neogeo.zip differs by setup."""

    def test_the_answer_is_not_a_plain_yes(self):
        section = _section(_wiki("faq.md"), "Does a BIOS work on every setup?").strip()
        self.assertFalse(section.startswith("Yes"))
        self.assertIn("neogeo.zip", section)

    def test_the_setups_do_install_different_neogeo_zips(self):
        digests = set()
        for path in (REPO_ROOT / "install").glob("*.json"):
            for entry in json.loads(path.read_text(encoding="utf-8")).get("files", []):
                if str(entry.get("dest", "")).lower().endswith("/neogeo.zip") or entry.get("dest") == "neogeo.zip":
                    digests.add(entry.get("sha1"))
        self.assertGreater(len(digests), 1)

    def test_zip_or_unzip_is_answered(self):
        section = _section(_wiki("faq.md"), "Zip or unzip?")
        self.assertIn("neogeo.zip", section)


class VerificationModesSplit(unittest.TestCase):
    """C12, N24, F5: the page opened on "Before a game starts", ran 37
    entries of contents, and cited checker code as plain text."""

    def test_opening(self):
        text = _wiki("verification-modes.md")
        self.assertNotIn("Before a game starts", text)
        self.assertIn("Most setups can show which BIOS files are missing.", text)

    def test_the_project_reports_have_their_own_page(self):
        modes = _wiki("verification-modes.md")
        reports = _wiki("reading-reports.md")
        for heading in ("## Hash mismatch / UNTESTED", "## verify.py reports errors", "### Reading the output"):
            with self.subTest(heading=heading):
                self.assertNotIn(heading, modes)
                self.assertIn(heading, reports)
        self.assertEqual(_front(reports).get("level"), "reference")

    def test_checker_links_are_pinned_to_the_revision_the_platform_names(self):
        named = " ".join(
            f"{data.get('version', '')} {data.get('source', '')}"
            for data in (yaml.safe_load(p.read_text(encoding="utf-8")) or {}
                         for p in (REPO_ROOT / "platforms").glob("*.yml"))
            if isinstance(data, dict)
        )
        links = re.findall(r"\((https://(?:github\.com|gitlab\.com)/[^)\s]+)\)", _wiki("verification-modes.md"))
        pinned = [url for url in links if re.search(r"/-?/?blob/", url)]
        self.assertGreaterEqual(len(pinned), 10)
        for url in pinned:
            revision = re.search(r"/blob/([^/]+)/", url).group(1)
            with self.subTest(url=url):
                self.assertNotIn(revision, ("main", "master", "HEAD"))
                self.assertIn(revision, named)


class SetupCount(unittest.TestCase):
    """C2: the home page said 15 more, the diagram 14 more, from two counts."""

    def test_one_count(self):
        from common import list_registered_platforms

        self.assertEqual(len(sitediagrams.setups()),
                         len(list_registered_platforms(str(REPO_ROOT / "platforms"), include_archived=True)))

    def test_every_rendered_count_agrees(self):
        """Each "RetroArch, Batocera, EmuDeck and N more" names three setups."""
        found = set()
        for path in [*sitepages.pages()]:
            text = path.read_text(encoding="utf-8")
            found.update(int(n) for n in re.findall(r"(?:RetroArch|EmuDeck|Batocera) and (\d+) more", text))
        found.update(int(n) for n in re.findall(
            r"and (\d+) more", sitediagrams.og_card_svg("home", "<svg></svg>")))
        self.assertTrue(found)
        self.assertEqual(found, {len(sitediagrams.setups()) - 3})


class Vocabulary(unittest.TestCase):
    """C5: one thing called device, setup, frontend, platform and game menu."""

    def test_the_glossary_defines_the_words_the_reference_uses(self):
        terms = {term for term in re.findall(r"^\*\*([^*]+)\*\*", _wiki("glossary.md"), re.M)}
        terms |= set(re.findall(r"\*\*([^*]+)\*\*", _wiki("glossary.md")))
        for word in ("Pack", "Platform", "MD5", "SHA-1", "Setup"):
            with self.subTest(word=word):
                self.assertIn(word, terms)

    def test_start_pages_and_the_first_diagram_say_setup(self):
        for name in START_PAGES[:5]:
            text = FENCED.sub("", _wiki(name)).lower()
            with self.subTest(page=name):
                self.assertNotRegex(text, r"\bfrontends?\b")
                self.assertNotIn("game menu", text)
        for figure in ("bios-chain", "install-flow"):
            with self.subTest(figure=figure):
                self.assertNotIn("rontend", sitediagrams.figure_html(figure))


class NavigationPlaces(unittest.TestCase):
    """N14, N15, N16, T5: installer and legal in Explore, build internals in
    Reference, and a legacy Getting started page in no tab."""

    def test_front_matter(self):
        expected = {
            "installer.md": "setup", "legal.md": "start",
            "architecture.md": "contribute", "tools.md": "contribute",
            "advanced-usage.md": "contribute", "reference-terms.md": "contribute",
        }
        for name, level in expected.items():
            with self.subTest(page=name):
                self.assertEqual(_front(_wiki(name))["level"], level)
        self.assertEqual(_front(_wiki("legal.md"))["order"], _front(_wiki("faq.md"))["order"] + 5)
        self.assertEqual(_front(_wiki("verification-modes.md"))["group"], "Checking files")
        self.assertEqual(_front(_wiki("community-tools.md"))["group"], "Data")
        self.assertFalse((WIKI / "getting-started.md").exists())

    def test_no_next_aside_is_left(self):
        for path in sorted(WIKI.glob("*.md")):
            with self.subTest(page=path.name):
                self.assertNotIn(":::tip[Next]", path.read_text(encoding="utf-8"))


class TroubleshootingLines(unittest.TestCase):
    """C22: "Details: When something goes wrong", a sudo line that is the
    installer's to give, and an unclear Linux line."""

    def test_lines(self):
        text = _wiki("troubleshooting.md")
        self.assertNotIn("Details: [When something goes wrong]", text)
        self.assertIn("Other messages: [When something goes wrong]", text)
        self.assertIn("Run the command once.", text)
        for name in ("troubleshooting.md", "first-install.md"):
            with self.subTest(page=name):
                self.assertNotIn("sudo", _wiki(name))
                self.assertRegex(" ".join(_wiki(name).split()), r"[Dd]o what the message says")

    def test_the_installer_names_what_to_run(self):
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        advice = source[source.index("def _write_advice"):source.index("def _plural")]
        self.assertIn("hint.command(plat, path, elevated=True)", advice)


class DiagramText(unittest.TestCase):
    """V17: 11 px text in fixed-height boxes, paths broken mid-token."""

    def test_text_reads_at_14_px_in_the_column(self):
        self.assertGreaterEqual(sitediagrams.TEXT_SIZE * sitediagrams.COLUMN / sitediagrams.WIDE, 14)

    def test_no_box_holds_more_than_three_lines(self):
        wide = sitediagrams.WIDE - 2
        layouts = {  # the box width of each wide layout: flow, grid of two, columns
            "bios-chain": (sitediagrams._bios_chain_boxes(), (wide - 26 * 3) / 4),
            "install-flow": (sitediagrams._install_boxes(), (wide - 18) / 2),
            "verification-modes": (sitediagrams._mode_boxes(), (wide - 16 * 2) / 3),
        }
        for name, (boxes, box_width) in layouts.items():
            for width in (sitediagrams.NARROW - 2, box_width):
                for box in boxes:
                    with self.subTest(figure=name, box=box.title, width=width):
                        self.assertLessEqual(len(sitediagrams.box_lines(box, width)[1]),
                                             sitediagrams.MAX_BOX_LINES)

    def test_a_path_is_mono_on_its_own_line(self):
        html = sitediagrams.figure_html("bios-chain")
        self.assertRegex(html, r'<text [^>]*style="font-family: var\(--sl-font-mono[^>]*>/userdata/bios/</text>')

    def test_boxes_of_a_row_share_one_height(self):
        for layout in (sitediagrams.flow, sitediagrams.columns):
            for vertical, total in ((False, sitediagrams.WIDE), (True, sitediagrams.NARROW)):
                _width, _height, body = layout(sitediagrams._bios_chain_boxes(), vertical, total)
                heights = {float(h) for h in re.findall(r'<rect [^>]*height="([\d.]+)"[^>]*class="rb-d-box',
                                                         "".join(body))}
                with self.subTest(layout=layout.__name__, vertical=vertical):
                    self.assertEqual(len(heights), 1)


class ExampleHashesStayOutOfSearch(unittest.TestCase):
    """F4: the scph5501 MD5 typed in search found four documentation pages
    and not the file card."""

    def test_wiki_hashes_are_excluded(self):
        text = _built("wiki/verification-modes.md")
        for match in re.finditer(r"\b[0-9a-f]{32}\b", text):
            line_start = text.rfind("\n", 0, match.start())
            context = text[line_start: match.end() + 10]
            with self.subTest(hash=match.group(0)):
                self.assertIn("data-pagefind-ignore", context)

    def test_a_fenced_hash_is_wrapped(self):
        out = sitediagrams.hide_hashes("```sh\nx 490f666e1afb15b7362b406ed1cea246\n```\n")
        self.assertTrue(out.startswith("<div data-pagefind-ignore>\n\n```sh"))

    def test_only_wiki_pages_are_touched(self):
        page = "Hash `490f666e1afb15b7362b406ed1cea246`.\n"
        self.assertEqual(sitediagrams.prepare_page(page, Path("systems/sony.md")), page)
        self.assertIn("data-pagefind-ignore", sitediagrams.prepare_page(page, Path("wiki/x.md")))


class InstallerOptionsAtAGlance(unittest.TestCase):
    """C23: a 9,000-word page with no table at the top. The table is read
    from the parser, so it lists what --help lists."""

    def test_every_option_of_the_parser_has_a_row(self):
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        declared = set(re.findall(r'parser\.add_argument\(\s*"(--[a-z-]+)"', source))
        listed = {usage.split()[0].rstrip(",") for usage, _ in sitediagrams.installer_options()}
        self.assertEqual(declared | {"--help"}, listed)

    def test_the_built_page_opens_on_a_link_per_option(self):
        text = _built("wiki/installer.md")
        glance = text.index("## Options at a glance")
        self.assertLess(glance, text.index("## One line"))
        listed = text[glance:text.index("## One line")]
        for usage, _ in sitediagrams.installer_options():
            flag = usage.split()[0].rstrip(",")
            with self.subTest(option=flag):
                self.assertIn(f"[`{flag}`](#option-{flag.lstrip('-')})", listed)
        self.assertNotIn("<!-- installer-options", text)
        # The markers of scripts/generate_installer_doc.py stay in the source.
        self.assertNotIn("generated:", text)


if __name__ == "__main__":
    unittest.main()
