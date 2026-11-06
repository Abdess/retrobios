"""What the site tells an AI agent: llms.txt, the ARD manifest, the WebMCP tools.

An agent asked to set up a handheld reads these first. They must lead it to
the fewest files the games need, and every address they give must exist.
"""
from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import siteagents  # noqa: E402

DIST = REPO_ROOT / "website" / "dist"
TOOLS = REPO_ROOT / "website" / "src" / "scripts" / "agent-tools.ts"
FOOTER = REPO_ROOT / "website" / "src" / "components" / "Footer.astro"
CONFIG = REPO_ROOT / "website" / "astro.config.mjs"


class TheGuideLeadsToTheFewestFiles(unittest.TestCase):
    def setUp(self) -> None:
        self.text = siteagents.llms_txt([("retroarch", "RetroArch"), ("batocera", "Batocera")])

    def test_it_is_llms_txt(self) -> None:
        self.assertTrue(self.text.startswith("# RetroBIOS\n\n> "))
        self.assertIn("\n## Setting up a device for its user\n", self.text)

    def test_every_command_installs_only_what_the_games_need(self) -> None:
        commands = re.findall(r"`((?:curl|&) [^`]+)`", self.text)
        self.assertGreaterEqual(len(commands), 3)
        for command in commands:
            with self.subTest(command=command):
                self.assertIn("--for-games --required-only", command)

    def test_each_setup_has_its_page(self) -> None:
        self.assertIn("(https://abdess.github.io/retrobios/platforms/batocera/)", self.text)

    @unittest.skipUnless((DIST / "llms.txt").is_file(), "website/dist is not built")
    def test_every_address_of_the_built_guide_exists(self) -> None:
        built = (DIST / "llms.txt").read_text(encoding="utf-8")
        for url in re.findall(r"\((https://abdess\.github\.io/retrobios/[^)]*)\)", built):
            with self.subTest(url=url):
                target = DIST / url.removeprefix(siteagents.SITE)
                self.assertTrue(target.is_file() or (target / "index.html").is_file(), url)


class TheSkillIsAnAgentSkill(unittest.TestCase):
    """ARD reserves text/markdown for agent skills (Lighthouse warns on a
    plain Markdown entry): the setup steps are published as one."""

    def test_front_matter_then_instructions(self) -> None:
        import yaml  # noqa: PLC0415

        text = siteagents.skill_md()
        head, _, body = text.removeprefix("---\n").partition("\n---\n")
        front = yaml.safe_load(head)
        self.assertEqual(set(front), {"name", "description"})
        self.assertRegex(front["name"], r"^[a-z0-9-]{1,64}$")
        self.assertLessEqual(len(front["description"]), 1024)
        self.assertTrue(body.lstrip().startswith("# "))
        for command in re.findall(r"`((?:curl|&) [^`]+)`", body):
            with self.subTest(command=command):
                self.assertIn("--for-games --required-only", command)

    def test_a_folder_is_quoted_and_a_hostile_one_asked_about(self) -> None:
        for text in (siteagents.skill_md(), siteagents.llms_txt([])):
            with self.subTest(text=text[:20]):
                self.assertIn("--dest='<card>/bios'", text)
                self.assertIn("--for-games='<folder>'", text)
                self.assertIn("starts with `-`", text)
                # The characters agent-tools.ts refuses, typographic quotes included.
                # The backtick is named in words: Markdown would read it.
                self.assertIn("a backtick", siteagents.REFUSED)
                for char in "'\"‘’‚‛“”„":
                    self.assertIn(char, siteagents.REFUSED)
                    self.assertIn(char, TOOLS.read_text(encoding="utf-8"))
                self.assertIn(siteagents.REFUSED, text)

    def test_the_manifest_types_it_as_a_skill(self) -> None:
        skill = siteagents.ard_manifest()["entries"][0]
        self.assertEqual(skill["type"], 'text/markdown; profile="urn:air:agent-skills"')
        self.assertTrue(skill["url"].endswith(siteagents.SKILL_PATH))


class TheManifestIsAnArdManifest(unittest.TestCase):
    """The terms ard-entry.schema.json requires (ards-project/ard-spec)."""

    def test_entries(self) -> None:
        entries = siteagents.ard_manifest()["entries"]
        self.assertTrue(entries)
        for entry in entries:
            with self.subTest(entry=entry.get("identifier")):
                self.assertRegex(entry["identifier"], r"^urn:air:[a-zA-Z0-9.-]+(:[a-zA-Z0-9._-]+)+$")
                self.assertTrue(entry["displayName"])
                self.assertRegex(entry["type"], r'^[a-z]+/[\w.+-]+(; [a-z]+="[^"]+")?$')
                self.assertTrue(("url" in entry) != ("data" in entry))
                self.assertTrue(2 <= len(entry["representativeQueries"]) <= 5)
                self.assertTrue(entry["url"].startswith(siteagents.SITE))

    def test_every_page_links_it(self) -> None:
        self.assertIn("rel: 'ard'", CONFIG.read_text(encoding="utf-8"))


class TheToolsReadOnly(unittest.TestCase):
    def setUp(self) -> None:
        self.source = TOOLS.read_text(encoding="utf-8")

    def test_every_page_registers_them(self) -> None:
        self.assertIn("import '../scripts/agent-tools.ts';", FOOTER.read_text(encoding="utf-8"))
        names = re.findall(r"^\s*name: '([a-z_]+)'", self.source, re.M)
        self.assertEqual(names, ["lookup_bios_hash", "emulator_bios_files", "search_retrobios",
                                 "device_setup_command"])
        self.assertEqual(self.source.count("readOnlyHint: true"), len(names))

    def test_the_setup_command_defaults_to_the_games(self) -> None:
        self.assertIn("const games = everything ? [] :", self.source)
        self.assertIn("'--required-only'", self.source)

    def test_a_value_that_could_escape_the_command_is_refused(self) -> None:
        """The command is pasted into a shell: PowerShell also ends a single-quoted
        string on the typographic quotes, and a path starting with "-" reads as
        an option."""
        self.assertIn("const unsafe = /[\\u0000-\\u001f\\u007f'\"`‘’‚‛“”„]/;", self.source)
        self.assertIn("value.startsWith('-')", self.source)
        self.assertIn("/^[a-z0-9_-]+$/.test(platform)", self.source)
        self.assertIn("`--dest=${quote(bios_folder as string)}`", self.source)

    def test_they_reach_no_other_site(self) -> None:
        code = re.sub(r"^\s*//.*$", "", self.source, flags=re.M)
        self.assertEqual(set(re.findall(r"https://[\w.-]+", code)), {"https://abdess.github.io"})


if __name__ == "__main__":
    unittest.main()
