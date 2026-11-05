"""Wiki.

Each class names the finding it holds: a "no setup" command that sent
macOS and Steam Deck files where RetroArch never reads, a level 0 rule that
every emulator needs one exact name, FAQ answers that ended at a ZIP most
setups lack, a packager section pointing at release assets that do not
exist, and two copy fixes. Every claim is held against install.py, the
setup guides or the generator that writes the page a link opens.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import sitediagrams  # noqa: E402
from siteguides import INSTALL_SH  # noqa: E402
from tests import sitepages  # noqa: E402

WIKI = REPO_ROOT / "wiki"
FENCED = re.compile(r"^```.*?^```", re.S | re.M)
INSTALL_PY = (REPO_ROOT / "install.py").read_text(encoding="utf-8")


def _wiki(name: str) -> str:
    return (WIKI / name).read_text(encoding="utf-8")


def _front(text: str) -> dict:
    return yaml.safe_load(text.split("---", 2)[1])


def _section(text: str, heading: str) -> str:
    start = re.search(rf"(?m)^#+ {re.escape(heading)}(?:\s*\{{[^}}]*\}})?\n", text)
    if start is None:
        raise AssertionError(f"no section {heading!r}")
    rest = text[start.end():]
    blank = FENCED.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), rest)
    end = re.search(r"(?m)^#{1,2} ", blank)
    return rest[: end.start()] if end else rest


def _flat(text: str) -> str:
    return " ".join(text.split())


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
        section = _flat(_section(self.text, "My setup is not in the list"))
        self.assertIn("iPhone, iPad (iOS): no terminal. [Pick your consoles and copy them "
                      "to the app](../which-pack.md#iphone-and-ipad).", section)
        self.assertNotIn("Use the ZIP", section)
        self.assertIn('"## iPhone and iPad { #iphone-and-ipad }"', self.generator)

    def test_antivirus_answer_covers_setups_without_a_zip(self):
        section = _flat(_section(self.text, "Windows or my antivirus blocks the command"))
        self.assertIn("Use your setup's ZIP. None? [Pick your consoles]"
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


class SmallCopyFixes(unittest.TestCase):
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
