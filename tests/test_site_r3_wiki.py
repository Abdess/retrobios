"""Wiki copy.

Each class names the finding it holds: a legal page that opened on case law,
no arcade answer where players look, a Dreamcast "yes" the Dreamcast
emulator contradicts, an offline install no one could find, setups with no
page of their own, link labels that named another page, an exit status that
could not tell missing files from a failure, and FAQ answers the community
asks for (region and language, keys and firmware). Every claim the copy
makes about an emulator or the installer is held against the repository.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tests import sitepages  # noqa: E402

WIKI = REPO_ROOT / "wiki"
FENCED = re.compile(r"^```.*?^```", re.S | re.M)


def _wiki(name: str) -> str:
    return (WIKI / name).read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    start = re.search(rf"(?m)^#+ {re.escape(heading)}(?:\s*\{{[^}}]*\}})?\n", text)
    if start is None:
        raise AssertionError(f"no section {heading!r}")
    rest = text[start.end():]
    end = re.search(r"(?m)^#{1,2} ", FENCED.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), rest))
    return rest[: end.start()] if end else rest


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


class LegalOpensInPlainWords(unittest.TestCase):
    """C5: Is it legal? is a Start here page and opened on case law."""

    def setUp(self):
        self.text = _wiki("legal.md")
        self.opening = self.text.split("## The reasoning in detail", 1)[0]

    def test_the_answer_comes_before_the_reasoning(self):
        self.assertIn("## The reasoning in detail", self.text)
        self.assertIn("It depends on your country. Nothing here is legal advice.", self.opening)
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
        section = _section(_wiki("faq.md"), "My arcade game fails (which MAME version?)")
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
        self.assertIn("## 1. Check my BIOS folder { #checking-what-you-installed }",
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
        section = _flat(_section(_wiki("faq.md"), "My setup is not in the list"))
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
                    self.assertEqual(label, "Get your files")


class ExitStatusAndPinnedInstaller(unittest.TestCase):
    """D10, J12: --check exits 1 for missing files and for failures, and a
    packager had no fixed installer to point at."""

    def setUp(self):
        self.text = _wiki("installer.md")
        self.source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")

    def test_the_check_event_tells_missing_from_failure(self):
        section = _flat(_section(self.text, "Exit status"))
        self.assertIn("read the `check` event", section)
        self.assertIn("`missing` and `wrong_hash` count what is left", section)
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


class SmallCopyFixes(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
