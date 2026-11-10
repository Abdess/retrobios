"""Wiki copy, release docs and the diagrams module.

Each class names the finding it holds: a safety line the code contradicted,
install commands with no Windows form, a run's end described wrongly, pages
with two names, an FAQ answer the setups' own checks contradict, a setup
count given two ways, unreadable diagram text, and example hashes that
answered a hash search in place of the file card.

Each class names the finding it holds: a legal page that opened on case law,
no arcade answer where players look, a Dreamcast "yes" the Dreamcast
emulator contradicts, an offline install no one could find, setups with no
page of their own, link labels that named another page, an exit status that
could not tell missing files from a failure, and FAQ answers the community
asks for (region and language, keys and firmware). Every claim the copy
makes about an emulator or the installer is held against the repository.

Each class names the finding it holds: an error message a reader types
into search and no page that says it, an arcade answer written for
maintainers, a subfolder setting that hides every file, FAQ labels that
read as broken crumbs, no legal route to a BIOS, a packager who cannot pin
the installer, a backslash in a PowerShell command, an events table with no
sample, the installer options printed twice, and a glossary "Pack" that
ignored parts. Every claim the copy makes is held against the repository.

Each class names the finding it holds: a "no setup" command that sent
macOS and Steam Deck files where RetroArch never reads, a level 0 rule that
every emulator needs one exact name, FAQ answers that ended at a ZIP most
setups lack, a packager section pointing at release assets that do not
exist, and two copy fixes. Every claim is held against install.py, the
setup guides or the generator that writes the page a link opens.
"""
from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import fnmatch
import json
import re
import sys
import unittest
from pathlib import Path
import yaml
import importlib.util

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT))

import sitediagrams  # noqa: E402
from siteguides import INSTALL_SH  # noqa: E402
from tests import sitepages  # noqa: E402
import build_port  # noqa: E402
from check_release import SUMS, Asset, compare_release  # noqa: E402


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
                         len(list_registered_platforms(str(REPO_ROOT / "platforms"))))

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


def _flat(text: str) -> str:
    return " ".join(text.split())


def _headings(text: str) -> list[str]:
    return re.findall(r"(?m)^#{2,3} (.+?)\s*$", FENCED.sub("", text))


def _profile(name: str) -> dict:
    return yaml.safe_load((REPO_ROOT / "emulators" / f"{name}.yml").read_text(encoding="utf-8"))


def _entry(profile: dict, name: str) -> dict:
    for entry in profile.get("files", []):
        if entry.get("name") == name:
            return entry
    raise AssertionError(f"{name} not in the profile")


class TheFaqAnswersWithACommand(unittest.TestCase):
    """"Do I need every file of a console?" answered `--region us keeps only
    your region's BIOS`, with no command to run, and that run kept 44 files
    of the PlayStation set, Japanese PS2 images among them. `--core pcsx1`
    is the lever the installer itself names."""

    def test_every_file_of_a_console(self):
        section = _section(_wiki("faq.md"), "Is every file of a console needed?")
        self.assertIn("<!-- os-tabs -->", section)
        self.assertIn("--system sony-playstation --core pcsx1", section)
        self.assertNotIn("only your region", section)


class LegalOpensInPlainWords(unittest.TestCase):
    """C5: Is it legal? is a Start here page and opened on case law."""

    def setUp(self):
        self.text = _wiki("legal.md")
        self.opening = self.text.split("## The reasoning in detail", 1)[0]

    def test_the_answer_comes_before_the_reasoning(self):
        self.assertIn("## The reasoning in detail", self.text)
        self.assertIn("It depends on the country. Nothing here is legal advice.", self.opening)
        for case in ("Connectix", "Accolade", "DMCA", "CFR", "Chamberlain", "Yuzu"):
            with self.subTest(case=case):
                self.assertNotIn(case, self.opening)
                self.assertIn(case, self.text)

    def test_the_plain_lines_hold_against_the_detail(self):
        opening = _flat(self.opening)
        self.assertIn("encryption keys (Switch, 3DS, Wii U)", opening)
        self.assertIn("weakest part of the project's position", self.text)
        self.assertIn("issues/new", opening)
        self.assertIn("path or hash", opening)
        self.assertIn("identifying the file by path or hash", _flat(self.text))

    def test_the_detail_sits_under_the_reasoning_heading(self):
        detail = self.text.split("## The reasoning in detail", 1)[1]
        detail = detail.split("## Asking for a file to be removed", 1)[0]
        self.assertEqual(re.findall(r"(?m)^## ", detail), [])
        self.assertIn("### Emulation and BIOS redistribution", detail)

    def test_said_once(self):
        """A closing Summary restated the opening lines, and "not legal
        advice" came three times."""
        self.assertEqual(self.text.count("legal advice"), 1)
        self.assertNotIn("### Summary", self.text)
        self.assertIn("The project accepts that risk deliberately", self.text)

    def test_a_contact_section_names_only_a_channel_that_exists(self):
        section = _section(self.text, "Contact")
        self.assertIn("https://github.com/Abdess/retrobios/issues", section)
        self.assertNotIn("@", section)


class ArcadeAnswerWherePlayersLook(unittest.TestCase):
    """C3, N3: the romset answer sat in Reference only."""

    def test_troubleshooting_answers_after_step_three(self):
        text = _wiki("troubleshooting.md")
        headings = _headings(text)
        self.assertIn("An arcade game does not start", headings)
        self.assertGreater(headings.index("An arcade game does not start"),
                           headings.index("3. Check the folder and the names"))
        section = _flat(_section(text, "An arcade game does not start"))
        for words in ("neogeo.zip", "same emulator version", "MAME version", "Details:",
                      "technical-faq.md#which-mame-version-do-the-arcade-bios-sets-match",
                      "Run the command once."):
            with self.subTest(words=words):
                self.assertIn(words, section)

    def test_the_faq_links_the_technical_answer(self):
        section = _section(_wiki("faq.md"), "An arcade game fails (which MAME version?)")
        anchor = "technical-faq.md#which-mame-version-do-the-arcade-bios-sets-match"
        self.assertIn(anchor, section)
        self.assertIn("## Which MAME version do the arcade BIOS sets match?", _wiki("technical-faq.md"))
        self.assertLessEqual(len(re.findall(r"[.!?](?:\s|$)", section)), 2)

    def test_emulator_pages_name_the_version_the_copy_promises(self):
        for name in ("mame2003", "mame2000", "fbneo"):
            with self.subTest(profile=name):
                profile = _profile(name)
                self.assertTrue(profile.get("core_version") or profile.get("version"))

    def test_the_check_step_holds_the_searched_words(self):
        self.assertIn("## 1. Check the BIOS folder { #checking-what-you-installed }",
                      _wiki("troubleshooting.md"))


class BiosFineWhatNext(unittest.TestCase):
    """Community need 11: the page assumed the BIOS was the cause."""

    def setUp(self):
        self.section = _flat(_section(_wiki("troubleshooting.md"),
                                      "The BIOS is fine, the game still fails"))

    def test_the_three_causes(self):
        for words in ("Another emulator?", "A BIOS setting?", ".cue", ".m3u"):
            with self.subTest(words=words):
                self.assertIn(words, self.section)

    def test_the_named_setting_is_the_core_option(self):
        # libretro/pcsx_rearmed frontend/libretro_core_options.h: key
        # pcsx_rearmed_bios, label "BIOS Selection", values Auto and HLE.
        self.assertIn("**BIOS Selection** to **Auto**", self.section)
        notes = _profile("pcsx_rearmed").get("notes", "")
        self.assertIn('pcsx_rearmed_bios = "HLE"', notes)


class DreamcastIsBetterWithIt(unittest.TestCase):
    """C7: "Yes for Dreamcast" while Flycast runs without dc_boot.bin."""

    def test_flycast_falls_back(self):
        entry = _entry(_profile("flycast"), "dc_boot.bin")
        self.assertFalse(entry.get("required"))
        self.assertTrue(entry.get("hle_fallback"))

    def test_no_page_says_yes_for_dreamcast(self):
        for name in ("faq.md", "what-are-bios-files.md"):
            text = _wiki(name)
            with self.subTest(page=name):
                yes = next(line for line in text.splitlines() if line.startswith("- **Yes"))
                self.assertNotIn("Dreamcast", yes)
                self.assertRegex(_flat(text), r"\*\*Better with it:?\*\*:? (for )?Dreamcast")


class OfflineInstallIsFindable(unittest.TestCase):
    """N7: no page linked the offline install, and search did not find it."""

    ANCHOR = "without-a-network-offline-install"

    def test_the_installer_heading_says_offline(self):
        text = _wiki("installer.md")
        self.assertIn(f"## Without a network (offline install) {{ #{self.ANCHOR} }}", text)
        # Links written before the rename still land.
        self.assertIn('<span id="without-a-network"></span>', text)
        self.assertNotIn("](#without-a-network)", text)

    def test_the_faq_answers_next_to_the_sd_card(self):
        text = _wiki("faq.md")
        headings = _headings(text)
        self.assertEqual(headings.index("No internet on the device?"),
                         headings.index("Fill an SD card from a computer?") + 1)
        section = _section(text, "No internet on the device?")
        self.assertIn("--from-pack", section)
        self.assertIn(f"installer.md#{self.ANCHOR}", section)

    def test_from_pack_is_an_installer_option(self):
        self.assertIn('"--from-pack"', (REPO_ROOT / "install.py").read_text(encoding="utf-8"))


class SetupsWithoutAPage(unittest.TestCase):
    """N9, J13: ES-DE, LaunchBox and iOS found nothing."""

    def test_the_answer(self):
        section = _flat(_section(_wiki("faq.md"), "A setup is not in the list"))
        for words in ("--dest", "ES-DE", "LaunchBox", "iPhone"):
            with self.subTest(words=words):
                self.assertIn(words, section)
        # No folder is written: the copy names none it cannot cite. Link
        # targets are pages of this site, not folders.
        self.assertNotRegex(re.sub(r"\]\([^)]*\)", "]", section), r"[~/\\][A-Za-z]")

    def test_the_installer_fills_the_emulators_a_launcher_starts(self):
        installer = _flat(_wiki("installer.md"))
        self.assertIn("they reference emulators rather than owning a BIOS directory", installer)
        self.assertIn("the installer fills their own BIOS folders", installer)


class LinkLabelsMatchPages(unittest.TestCase):
    """N5: "Your setup's page" landed on a page titled Get your files."""

    def test_links_to_get_your_files_carry_its_name(self):
        for name in ("first-install.md", "troubleshooting.md", "faq.md"):
            with self.subTest(page=name):
                for label in re.findall(r"\[([^\]]+)\]\(\.\./which-pack\.md\)", _wiki(name)):
                    self.assertEqual(label, "Get the files")


class ExitStatusAndPinnedInstaller(unittest.TestCase):
    """D10, J12: --check exits 1 for missing files and for failures, and a
    packager had no fixed installer to point at."""

    def setUp(self):
        self.text = _wiki("installer.md")
        self.source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")

    def test_the_code_tells_missing_from_failure(self):
        section = _flat(_section(self.text, "Exit status"))
        self.assertIn("`--check` tells missing files (`3`) from a failure (`1`) by its code", section)
        self.assertIn("is left in `missing` and `wrong_hash`", section)
        fields = re.search(r'"check": \(([^)]*)\)', self.source).group(1)
        for field in ("missing", "wrong_hash"):
            with self.subTest(field=field):
                self.assertIn(f'"{field}"', fields)

    def test_a_packager_pins_installer_and_lists_to_one_commit(self):
        # No release carries the installer yet: the section pins a commit.
        section = _section(self.text, "One line")
        self.assertIn("raw.githubusercontent.com/Abdess/retrobios/$commit", section)
        self.assertIn("$base/install.py", section)
        self.assertIn("RETROBIOS_REF=$commit", section)
        self.assertIn('os.environ.get("RETROBIOS_REF"', self.source)


class LegalAndFaqCopy(unittest.TestCase):
    """C P3: the SD card example and the end line of a run."""

    def test_the_sd_card_example_names_its_setup(self):
        section = _flat(_section(_wiki("faq.md"), "Fill an SD card from a computer?"))
        self.assertIn("For RetroArch on a Switch, with the card in drive `E:`, run:", section)
        guides = (REPO_ROOT / "platforms" / "_guides.yml").read_text(encoding="utf-8")
        self.assertIn("where: Nintendo Switch", guides)
        self.assertIn("`retroarch/cores/system/` on the SD card", guides)
        self.assertIn("--dest E:\\retroarch\\cores\\system", section)

    def test_the_end_is_the_shown_one(self):
        # The one-liner opens the full screen: the page names the titles
        # its result screen shows, as tui_outcome writes them.
        import install

        section = _section(_wiki("first-install.md"), "5. Read the result")
        state = install.TuiState()
        state.stack, state.code = ["result"], 0
        for summary in ({"installed": 3, "up_to_date": 0, "failed": []},
                        {"installed": 2, "failed": [{"dest": "a.bin", "reason": "HTTP 404"}]},
                        {"installed": 0, "failed": [{"dest": "a.bin", "reason": "HTTP 404"}]}):
            state.summary = summary
            title, _lines = install.tui_outcome(state)
            with self.subTest(title=title):
                self.assertIn(f"**{title}**", section)


class CommunityAnswers(unittest.TestCase):
    """Community needs 6, 10 and 15: region and language, keys versus
    firmware versus BIOS, zip or unzip."""

    def setUp(self):
        self.faq = _wiki("faq.md")

    def test_language_comes_from_the_game(self):
        section = _flat(_section(self.faq, "Does the BIOS set the game's language?"))
        self.assertIn("comes from the game", section)
        self.assertIn("Flycast's **Language** option", section)

    def test_keys_firmware_bios(self):
        section = _flat(_section(self.faq, "Keys, firmware or BIOS?"))
        for name, profile in (("scph5501.bin", "duckstation"), ("PS3UPDAT.PUP", "rpcs3"),
                              ("prod.keys", "eden")):
            with self.subTest(name=name):
                self.assertIn(f"`{name}`", section)
                _entry(_profile(profile), name)
        self.assertIn("Firmware (system NCAs) must be installed through Eden's UI",
                      _profile("eden")["notes"])

    def test_zip_or_unzip_stays(self):
        self.assertIn("neogeo.zip", _section(self.faq, "Zip or unzip?"))


class StartPagesStayInBudget(unittest.TestCase):
    """The built pages: the new answers fit the level 0 ceilings."""

    def test_ceilings(self):
        from tests import test_site_copy

        sitepages.require()
        for name in ("wiki/faq.md", "wiki/troubleshooting.md", "wiki/first-install.md",
                     "wiki/what-are-bios-files.md"):
            with self.subTest(page=name):
                self.assertLessEqual(test_site_copy._load(name).words(),
                                     test_site_copy.START_PAGES[name])


ARCADE_ANCHOR = "technical-faq.md#which-mame-version-do-the-arcade-bios-sets-match"


class TroubleshootingSaysTheWordsOnScreen(unittest.TestCase):
    """C6, N3: "bios not found" ranked the page 4th, and the most quoted
    on-screen message found nothing."""

    def setUp(self):
        self.text = _wiki("troubleshooting.md")

    def test_step_one_opens_on_the_messages(self):
        step = _flat(_section(self.text, "1. Check the BIOS folder"))
        self.assertIn("**BIOS not found**, **BIOS missing** or **firmware missing**?", step)
        self.assertLess(step.index("BIOS not found"), step.index("```"))

    def test_each_message_is_cited(self):
        for source in ("bsx.cpp:1232", "fds.c:312", "libretro.cpp:866", "msg_hash_us.h:32805"):
            with self.subTest(source=source):
                self.assertIn(source, self.text)

    def test_the_disc_message(self):
        section = _flat(_section(self.text, "The BIOS is fine, the game still fails"))
        self.assertIn('"Please insert PlayStation CD-ROM"?** The BIOS works.', section)
        self.assertIn("open its `.cue` or `.m3u` file, not a `.bin`", section)

    def test_terms_for_search(self):
        terms = _front(self.text)["terms"]
        for word in ("bios not found", "bios missing", "firmware missing", "bios error"):
            with self.subTest(word=word):
                self.assertIn(word, terms)


class SubfolderTrap(unittest.TestCase):
    """C8: a BIOS setting pointed at system/dc, while Flycast adds dc/ itself."""

    def test_step_three_names_it(self):
        step = _flat(_section(_wiki("troubleshooting.md"), "3. Check the folder and the names"))
        self.assertIn("subfolder, like `system/dc`?", step)
        self.assertIn("like `dc/` for Flycast", step)

    def test_flycast_reads_dc(self):
        flycast = _profile("flycast")
        boot = next(e for e in flycast["files"] if e["name"] == "dc_boot.bin")
        self.assertEqual(boot["path"], "dc/dc_boot.bin")
        self.assertIn('appends "dc/" to the system directory', flycast["notes"])


def _arcade_profiles() -> dict[str, dict]:
    """The MAME and FinalBurn libretro cores whose name does not give the version."""
    found = {}
    for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
        if not re.match(r"(mame|fbneo|fbalpha)", path.stem):
            continue
        profile = yaml.safe_load(path.read_text(encoding="utf-8"))
        if "libretro" not in str(profile.get("type", "")):
            continue
        # Recalbox's MAME 0.258 and 0.278 carry the answer in their name.
        if _version(profile) in _retroarch_name(profile):
            continue
        found[path.stem] = profile
    return found


def _retroarch_name(profile: dict) -> str:
    """"Arcade (MAME 2003)" gives "MAME 2003", "Arcade (FinalBurn Neo) (Neo-Geo)"
    gives "FinalBurn Neo (Neo-Geo)"."""
    inner = profile["display_name"].split("(", 1)[1]
    return inner.replace(")", "", 1).strip()


def _version(profile: dict) -> str:
    return str(profile.get("mame_version") or profile["core_version"]).split()[0].lstrip("v")


class ArcadeVersionTable(unittest.TestCase):
    """C4, N3: the answer named profile ids and left out FinalBurn Neo."""

    def setUp(self):
        self.text = _wiki("technical-faq.md")
        section = _section(self.text, "Which MAME version do the arcade BIOS sets match?")
        self.section = section
        self.rows = {}
        for line in section.splitlines():
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if (line.startswith("|") and len(cells) == 2 and not set(cells[0]) <= {"-"}
                    and cells[1] != "Sets from"):
                for name in cells[0].split(", "):
                    self.rows[name] = cells[1]

    def test_the_section_opens_on_the_answer(self):
        self.assertTrue(self.section.lstrip().startswith(
            "Game sets and BIOS sets must come from the same version as the arcade\nemulator."))
        self.assertIn("| Emulator, as RetroArch names it | Sets from |", self.section)
        self.assertLess(self.section.index("| Emulator"), self.section.index("### How this is known"))

    def test_every_core_has_its_row_and_version(self):
        profiles = _arcade_profiles()
        self.assertGreaterEqual(len(profiles), 20)
        for key, profile in profiles.items():
            name = _retroarch_name(profile)
            with self.subTest(profile=key, name=name):
                self.assertIn(name, self.rows)
                self.assertIn(_version(profile), self.rows[name])

    def test_no_row_without_a_core(self):
        names = {_retroarch_name(p) for p in _arcade_profiles().values()}
        self.assertEqual(set(self.rows) - names, set())

    def test_terms_and_links(self):
        terms = _front(self.text)["terms"]
        for word in ("mame version", "romset version", "which mame"):
            with self.subTest(word=word):
                self.assertIn(word, terms)
        arcade = _section(_wiki("troubleshooting.md"), "An arcade game does not start")
        self.assertIn(ARCADE_ANCHOR, arcade)
        self.assertNotIn("emulators/index.md", arcade)
        faq = _wiki("faq.md")
        self.assertIn("## An arcade game fails (which MAME version?) "
                      "{ #my-arcade-game-does-not-start }", faq)


class FaqLabels(unittest.TestCase):
    """C9, N10: "Reference:" read as a broken crumb, "E::" as a typo, iOS unfound."""

    def setUp(self):
        self.text = _wiki("faq.md")

    def test_no_reference_label(self):
        self.assertNotRegex(self.text, r"(?m)^Reference:")
        arcade = _section(self.text, "An arcade game fails (which MAME version?)")
        self.assertIn(f"Game sets must match the emulator's version:\n[the list]({ARCADE_ANCHOR}).",
                      arcade)

    def test_the_card_sentence(self):
        self.assertIn("For RetroArch on a Switch,\nwith the card in drive `E:`, run:", self.text)

    def test_ios(self):
        self.assertIn("iPhone, iPad (iOS)", self.text)


class CopyYourOwnBios(unittest.TestCase):
    """C-other, need 12: no page answered the legal route."""

    def test_each_console_has_a_guide(self):
        section = _section(_wiki("faq.md"), "Can an owned console's BIOS be copied?")
        links = re.findall(r"\[([^\]]+)\]\((https://[^)]+)\)", section)
        self.assertEqual(dict(links), {
            "PCSX2": "https://pcsx2.net/docs/setup/bios/",
            "melonDS": "https://melonds.kuribo64.net/faq.php",
        })


def _sums_with(names: list[str]) -> dict[str, str]:
    return {name: f"{i:064x}" for i, name in enumerate(names, 1)}


class PinnedInstaller(unittest.TestCase):
    """The release page carries the packs a beginner picks from, and no
    installer or file list: a package pins those from the tag (owner,
    2026-11-10, "dans release on met le minimum sans bruit")."""

    def test_an_installer_attached_to_the_release_is_refused(self):
        record = {"tag": "v1", "packs": {"P.zip": {"download_size": 5, "assets": ["P.zip"]}}}
        sums = _sums_with(["P.zip", "install.py", "retroarch.json"])
        assets = {name: Asset(5, digest) for name, digest in sums.items()}
        assets[SUMS] = Asset(1, None)
        kinds = {(f.kind, f.name) for f in compare_release(record, sums, assets, "v1")}
        self.assertEqual(kinds, {("unrecorded", "install.py"), ("unrecorded", "retroarch.json")})

    def test_a_launcher_attached_to_the_release_is_refused(self):
        """The handheld launchers carry install.py: the site serves them
        from its own commit, the release never does."""
        record = {"tag": "v1", "packs": {"P.zip": {"download_size": 5, "assets": ["P.zip"]}}}
        sums = _sums_with(["P.zip", *build_port.ARCHIVES])
        assets = {name: Asset(5, digest) for name, digest in sums.items()}
        assets[SUMS] = Asset(1, None)
        kinds = {(f.kind, f.name) for f in compare_release(record, sums, assets, "v1")}
        self.assertEqual(kinds, {("unrecorded", name) for name in build_port.ARCHIVES})

    def test_the_release_steps_ship_none(self):
        text = _wiki("release-process.md")
        self.assertNotIn("cp install.py", text)
        sums = re.search(r"sha256sum [^>]+> SHA256SUMS.txt", text, re.S).group(0)
        upload = re.search(r"for f in dist/SHA256SUMS.txt.*?; do", text, re.S).group(0)
        for name in ("install.py", "install.sh", "install.ps1", ".json", "RetroBIOS",
                     ".muxapp", "build_port", " *.zip", "/*.zip"):
            with self.subTest(name=name):
                self.assertNotIn(name, sums)
                self.assertNotIn(name, upload)
        # A launcher built into dist/ is never caught by the glob either.
        for archive in build_port.ARCHIVES:
            with self.subTest(archive=archive):
                self.assertFalse(fnmatch.fnmatch(archive, "*_BIOS_Pack*.zip"))
        self.assertIn("*_BIOS_Pack*.zip", sums)
        self.assertIn("*_BIOS_Pack*.zip", upload)
        self.assertNotIn("scripts/build_port.py", text)

    def test_the_installer_page_pins_one_commit(self):
        # v2026.10.10 carries no install.py: until a release does, the
        # section pins a commit, never a release address.
        text = _wiki("installer.md")
        section = _flat(_section(text, "For packagers"))
        for words in ("raw.githubusercontent.com/Abdess/retrobios/$commit",
                      '"$base/install/retroarch.json"', "--manifest retroarch.json",
                      "sha256sum --check", "RETROBIOS_REF=$commit"):
            with self.subTest(words=words):
                self.assertIn(words, section)
        self.assertNotIn("releases/download/", section)
        self.assertNotIn("releases/latest/download/", section)
        terms = _front(text)["terms"]
        for word in ("manifest", "events", "exit code", "schema"):
            with self.subTest(term=word):
                self.assertIn(word, terms)


class NoBackslashInProseCode(unittest.TestCase):
    """D9: `irm \\| iex` showed its backslash outside a table."""

    def test_wiki(self):
        for path in sorted(WIKI.glob("*.md")):
            text = FENCED.sub("", path.read_text(encoding="utf-8"))
            for number, line in enumerate(text.splitlines(), 1):
                if line.lstrip().startswith("|"):
                    continue
                with self.subTest(page=path.name, line=number):
                    self.assertNotRegex(line, r"`[^`]*\\\|[^`]*`")


def _install_module():
    spec = importlib.util.spec_from_file_location("install_r4wiki", REPO_ROOT / "install.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EventsTranscript(unittest.TestCase):
    """D10: the events table had no sample of what a run writes."""

    def test_five_lines_that_follow_the_schema(self):
        section = _section(_wiki("installer.md"), "Machine-readable events")
        block = re.search(r"```json\n(.*?)\n```", section, re.S)
        self.assertIsNotNone(block)
        lines = block.group(1).splitlines()
        self.assertEqual(len(lines), 5)
        keys = _install_module().EVENT_KEYS
        events = [json.loads(line) for line in lines]
        for event in events:
            with self.subTest(event=event["event"]):
                self.assertEqual(list(event), ["event", *keys[event["event"]]])
        self.assertEqual(events[0]["event"], "start")
        self.assertEqual(events[0]["mode"], "check")
        # --check that finds files missing ends on 3 (the Exit status table).
        self.assertEqual(events[-1], {"event": "end", "code": 3})


class OneOptionsTable(unittest.TestCase):
    """T-F9: the options printed twice, the offline install 57,750 px down."""

    def setUp(self):
        self.text = _wiki("installer.md")

    def test_each_option_links_to_its_row(self):
        # The glance is written from the parser when the page is built.
        glance = _section(sitediagrams.expand_glance(self.text), "Options at a glance")
        table = _section(self.text, "Options")
        self.assertNotIn("installer-options", glance)
        self.assertNotIn("|", glance)
        for usage, _ in sitediagrams.installer_options():
            flag = usage.split()[0].rstrip(",")
            anchor = f"option-{flag.lstrip('-')}"
            with self.subTest(option=flag):
                self.assertIn(f"[`{flag}`](#{anchor})", glance)
                self.assertRegex(table, rf'(?m)^\| <span id="{anchor}"></span>`{flag}[ `]')

    def test_the_offline_install_comes_early(self):
        headings = re.findall(r"(?m)^## (.+?)(?:\s*\{[^}]*\})?$", FENCED.sub("", self.text))
        self.assertLess(headings.index("Without a network (offline install)"),
                        headings.index("The full-screen interface"))


class GlossaryPack(unittest.TestCase):
    """C-other: packs come in parts and leave out files the emulator ships."""

    def test_definition(self):
        text = _flat(_wiki("glossary.md"))
        self.assertIn("**Pack** : The ZIP, sometimes in parts, with one setup's BIOS files.", text)


INSTALL_PY = (REPO_ROOT / "install.py").read_text(encoding="utf-8")


def _guide_folders(name: str) -> dict[str, str]:
    guides = yaml.safe_load((REPO_ROOT / "platforms" / "_guides.yml").read_text(encoding="utf-8"))
    return {row["where"]: row["path"] for row in guides["guides"][name]["folders"]}


class NoSetupFoundGivesEachSystemItsFolder(unittest.TestCase):
    """C3: macOS, Linux and Steam Deck shared `~/.config/retroarch/system`."""

    def setUp(self):
        self.section = _section(_wiki("troubleshooting.md"), "If the command fails")

    def test_the_label_is_the_installer_message(self):
        self.assertIn("**`No supported platform detected`:**", self.section)
        self.assertIn('else "  No supported platform detected.")', INSTALL_PY)

    def test_the_lead_names_the_menu(self):
        self.assertIn("Not sure? Open RetroArch's **Settings > Directory > System/BIOS**",
                      _flat(self.section))

    def test_each_tab_carries_the_folder_retroarch_reads_there(self):
        expected = {
            # install.py's Windows default and the hint it prints.
            "Windows": "C:\\RetroArch-Win64\\system",
            "macOS": "~/Documents/RetroArch/system",
            "Linux": "~/.config/retroarch/system",
            "Steam Deck": "~/.var/app/org.libretro.RetroArch/config/retroarch/system",
        }
        self.assertIn('_host_path("C:/RetroArch-Win64/system")', INSTALL_PY)
        self.assertIn('"windows": "C:\\\\RetroArch-Win64\\\\system"', INSTALL_PY)
        self.assertIn('return Path.home() / "Documents" / "RetroArch"', INSTALL_PY)
        folders = _guide_folders("retroarch")
        self.assertEqual(folders["macOS"], f"`{expected['macOS']}/`")
        self.assertEqual(folders["Linux"], f"`{expected['Linux']}/`")
        self.assertEqual(folders["Steam Deck and Linux Flatpak"], f"`{expected['Steam Deck']}/`")

        tabs = sitediagrams.expand_commands(self.section)
        parts = re.split(r'<TabItem label="([^"]+)">', tabs)
        bodies = dict(zip(parts[1::2], parts[2::2]))
        self.assertEqual(set(bodies), set(expected))
        for label, folder in expected.items():
            with self.subTest(tab=label):
                self.assertIn(f"--platform retroarch --dest {folder}\n", bodies[label])
                others = {f for key, f in expected.items() if key != label}
                for other in others:
                    self.assertNotIn(f"--dest {other}\n", bodies[label])

    def test_the_built_page_shows_four_folders(self):
        sitepages.require()
        built = sitepages.page("wiki/troubleshooting.md").read_text(encoding="utf-8")
        self.assertNotIn("os-tabs", built)
        for folder in ("C:\\RetroArch-Win64\\system", "~/Documents/RetroArch/system",
                       "~/.config/retroarch/system",
                       "~/.var/app/org.libretro.RetroArch/config/retroarch/system"):
            with self.subTest(folder=folder):
                self.assertIn(f"--dest {folder}", built)


class OsTabsTakeOptionsPerSystem(unittest.TestCase):
    """The marker gives any tab its own options, and refuses words it cannot read."""

    PAGE = ("<!-- os-tabs windows: --dest E:\\x macos: --dest /m steamdeck: --dest /d -->\n"
            f"```sh\ncurl -fsSL {INSTALL_SH} | sh -s -- --dest /l\n```\n")

    def test_each_named_tab_uses_its_own(self):
        parts = re.split(r'<TabItem label="([^"]+)">', sitediagrams.expand_commands(self.PAGE))
        bodies = dict(zip(parts[1::2], parts[2::2]))
        self.assertIn("--dest E:\\x\n", bodies["Windows"])
        self.assertIn("--dest /m\n", bodies["macOS"])
        self.assertIn("--dest /l\n", bodies["Linux"])
        self.assertIn("--dest /d\n", bodies["Steam Deck"])

    def test_text_before_a_system_name_fails_the_build(self):
        page = self.PAGE.replace("os-tabs windows:", "os-tabs typo windows:")
        with self.assertRaises(ValueError):
            sitediagrams.expand_commands(page)


class MostEmulatorsNotEvery(unittest.TestCase):
    """C8: level 0 said every emulator needs one exact name."""

    def test_the_rule_names_its_exception(self):
        section = _flat(_section(_wiki("what-are-bios-files.md"), "The name must match"))
        self.assertIn("Most emulators look for one exact name, like `scph5501.bin`.", section)
        self.assertIn("A few, like DuckStation, read any name and check what the file holds.",
                      section)
        profile = yaml.safe_load((REPO_ROOT / "emulators" / "duckstation.yml").read_text(
            encoding="utf-8"))
        self.assertEqual(profile["found_by"], "content")


class FaqAnswersLeadSomewhere(unittest.TestCase):
    """C9: "Use the ZIP" for iOS, and a dead end for 12 setups without one."""

    def setUp(self):
        self.text = _wiki("faq.md")
        self.generator = (REPO_ROOT / "scripts" / "generate_site.py").read_text(encoding="utf-8")

    def test_ios_goes_to_the_iphone_section(self):
        section = _flat(_section(self.text, "A setup is not in the list"))
        self.assertIn("iPhone, iPad (iOS): no terminal. [Pick the consoles and copy them "
                      "to the app](../which-pack.md#iphone-and-ipad).", section)
        self.assertNotIn("Use the ZIP", section)
        self.assertIn('"## iPhone and iPad { #iphone-and-ipad }"', self.generator)

    def test_antivirus_answer_covers_setups_without_a_zip(self):
        section = _flat(_section(self.text, "Windows or an antivirus blocks the command"))
        self.assertIn("Use the setup's ZIP. None? [Pick the consoles]"
                      "(../which-pack.md#only-some-consoles) and download their files.",
                      section)
        self.assertNotIn("if any", section)
        self.assertIn('"## Only some consoles?"', self.generator)


class PackagersPinACommit(unittest.TestCase):
    """J4: the section fetched install.py from a release that carries none."""

    def setUp(self):
        self.section = _section(_wiki("installer.md"), "For packagers")

    def test_the_pin_read_is_the_one_install_sh_writes(self):
        sed = re.search(r"sed -n '(s/\^DEFAULT_INSTALL_SHA256=.*?/p)'", self.section)
        self.assertIsNotNone(sed)
        bootstrap = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")
        lines = re.findall(r'(?m)^DEFAULT_INSTALL_SHA256="([0-9a-f]{64})"$', bootstrap)
        self.assertEqual(len(lines), 1)

    def test_the_manifest_comes_from_the_same_commit(self):
        self.assertIn('-O "$base/install/retroarch.json"', self.section)
        self.assertTrue((REPO_ROOT / "install" / "retroarch.json").is_file())
        self.assertIn("RETROBIOS_REF=$commit python3 install.py --manifest retroarch.json",
                      self.section)
        self.assertIn('"--manifest",', INSTALL_PY)
        self.assertIn('"https://raw.githubusercontent.com/Abdess/retrobios/"', INSTALL_PY)

    def test_search_words(self):
        terms = _front(_wiki("installer.md"))["terms"]
        for word in ("packager", "pin", "reproducible"):
            with self.subTest(word=word):
                self.assertIn(word, terms)


class SearchWords(unittest.TestCase):
    """Contract with the search gate: each page carries its own words."""

    def test_troubleshooting(self):
        terms = _front(_wiki("troubleshooting.md"))["terms"]
        for word in ("check my bios folder", "check bios folder"):
            with self.subTest(word=word):
                self.assertIn(word, terms)

    def test_legal(self):
        self.assertIn("license", _front(_wiki("legal.md"))["terms"])


class SetupAndSearchCopy(unittest.TestCase):
    """C-other: the RetroPie share had no name, and Mega CD two spellings."""

    def test_retropie_share_is_named_with_its_source(self):
        section = _section(_wiki("first-install.md"), "Error: Python 3.8 or newer is required.")
        self.assertIn("share open, `\\\\RETROPIE\\bios` from Windows:", section)
        self.assertIn("samba.sh:49-52", section)
        self.assertIn("Transferring-Roms.md:29", section)

    def test_mega_cd_is_spelled_once(self):
        for path in sorted(WIKI.glob("*.md")):
            with self.subTest(page=path.name):
                self.assertNotIn("Mega-CD", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
