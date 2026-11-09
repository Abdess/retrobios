"""The site's words live in Markdown and YAML, not in the generator.

Each platform's guide is in platforms/_guides.yml, read and checked by
siteguides.load_guides. A wiki page places itself in the navigation from its
front matter. Both are edited as data: a new platform or a new wiki page
needs no Python change, and a mistake stops the build with its name.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import ast
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site  # noqa: E402
import siteguides  # noqa: E402
from siteguides import GUIDES, GuideError, load_guides  # noqa: E402

GUIDES_FILE = REPO_ROOT / "platforms" / "_guides.yml"
WIKI = REPO_ROOT / "wiki"


def _registry() -> dict:
    with open(REPO_ROOT / "platforms" / "_registry.yml", encoding="utf-8") as handle:
        return yaml.safe_load(handle)["platforms"]


def _guides_text() -> str:
    return GUIDES_FILE.read_text(encoding="utf-8")


class GuidesLiveInYaml(unittest.TestCase):

    def _load(self, text: str, registry: dict | None = None) -> dict:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            path = Path(tmp) / "_guides.yml"
            path.write_text(text, encoding="utf-8")
            return load_guides(path, registry if registry is not None else _registry())

    def test_every_registered_platform_has_a_guide_in_the_file(self):
        written = yaml.safe_load(_guides_text())["guides"]
        self.assertEqual(sorted(written), sorted(_registry()))
        self.assertEqual(sorted(GUIDES), sorted(_registry()))

    def test_a_platform_without_a_guide_is_named(self):
        data = yaml.safe_load(_guides_text())
        del data["guides"]["knulli"]
        with self.assertRaisesRegex(GuideError, r"knulli is registered and has no guide"):
            self._load(yaml.safe_dump(data))

    def test_a_guide_for_no_platform_is_named(self):
        registry = _registry()
        del registry["knulli"]
        with self.assertRaisesRegex(GuideError, r"unregistered platforms: knulli"):
            self._load(_guides_text(), registry)

    def test_a_misspelt_key_is_refused(self):
        data = yaml.safe_load(_guides_text())
        data["guides"]["lakka"]["sumary"] = "A typo."
        with self.assertRaisesRegex(GuideError, r"guides\.lakka: unknown key sumary"):
            self._load(yaml.safe_dump(data))

    def test_a_terminal_no_tab_describes_is_refused(self):
        data = yaml.safe_load(_guides_text())
        data["guides"]["lakka"]["run"] = ["telnet"]
        with self.assertRaisesRegex(GuideError, r"guides\.lakka\.run: no terminal named telnet"):
            self._load(yaml.safe_dump(data))

    def test_a_folder_row_without_path_is_the_extract_folder(self):
        """The folder the pack unzips into is written once, in the registry."""
        registry = _registry()
        written = yaml.safe_load(_guides_text())["guides"]["batocera"]["folders"][0]
        self.assertNotIn("path", written)
        self.assertEqual(GUIDES["batocera"].folders[0],
                         (written["where"], f"`{registry['batocera']['extract_to']}`"))

    def test_a_folder_row_without_path_needs_an_extract_folder(self):
        registry = _registry()
        del registry["lakka"]["extract_to"]
        with self.assertRaisesRegex(GuideError, r"guides\.lakka\.folders\[0\]: no `path`"):
            self._load(_guides_text(), registry)

    def test_a_device_group_the_file_does_not_describe_is_refused(self):
        registry = _registry()
        registry["lakka"]["device_group"] = "toaster"
        with self.assertRaisesRegex(GuideError, r"lakka\.device_group 'toaster'"):
            self._load(_guides_text(), registry)

    def test_the_pack_readme_keeps_its_indent(self):
        manual = siteguides.pack_manual("retrobat")
        self.assertTrue(manual.startswith("  Option B: Manual\n  ----------------\n"))
        self.assertTrue(manual.endswith("  4. Overwrite if asked\n\n"))
        self.assertEqual(siteguides.pack_manual("minui"), "")


# A table of prose keyed by platform: what the guides file replaced.
_PLATFORM_BRANCH = re.compile(r"""(?:==|!=)\s*["']([a-z0-9-]+)["']|["']([a-z0-9-]+)["']\s*(?:==|!=)""")
# The modules that write the site and the pack README.
_RENDERERS = ("generate_site.py", "packreadme.py", "generate_readme.py")


class NoPlatformProseInScripts(unittest.TestCase):

    def test_no_table_of_prose_keyed_by_platform(self):
        platforms = set(_registry())
        found = []
        for path in sorted((REPO_ROOT / "scripts").rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not isinstance(node, ast.Dict):
                    continue
                keyed = [(k.value, v) for k, v in zip(node.keys, node.values)
                         if isinstance(k, ast.Constant) and k.value in platforms]
                prose = [key for key, value in keyed if any(
                    isinstance(c, ast.Constant) and isinstance(c.value, str)
                    and " " in c.value and len(c.value) >= 30
                    for c in ast.walk(value))]
                if len(keyed) >= 2 and prose:
                    found.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
        self.assertEqual(found, [], "per-platform text belongs in platforms/_guides.yml")

    def test_no_page_branches_on_one_platform(self):
        platforms = set(_registry())
        found = []
        scripts = REPO_ROOT / "scripts"
        for path in [scripts / name for name in _RENDERERS] + sorted(scripts.glob("site*.py")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                for match in _PLATFORM_BRANCH.finditer(line):
                    if (match.group(1) or match.group(2)) in platforms:
                        found.append(f"{path.name}:{number}: {line.strip()}")
        self.assertEqual(found, [], "a guide field says what one platform needs")


def _wiki_copy(tmp: str) -> Path:
    target = Path(tmp) / "wiki"
    shutil.copytree(WIKI, target)
    return target


class NavFromFrontMatter(unittest.TestCase):

    def _nav(self, wiki: Path) -> dict:
        nav = generate_site.generate_nav({}, {}, {}, {}, wiki)
        return {next(iter(tab)): next(iter(tab.values())) for tab in nav}

    def test_the_repository_nav_matches_the_pages(self):
        tabs = self._nav(WIKI)
        self.assertEqual(tabs["Explore"][0], "explore.md")
        self.assertEqual([next(iter(e)) for e in tabs["Explore"][1:]], ["Systems", "Emulators"])
        self.assertEqual(tabs["Setups"][-1], {"All installer options": "wiki/installer.md"})
        start = [e if isinstance(e, str) else next(iter(e)) for e in tabs["Start here"]]
        self.assertEqual(start.index("Is it legal?"), start.index("Common questions") + 1)
        self.assertEqual(tabs["Reference"][0], "wiki/index.md")

    def test_a_new_page_lands_in_its_tab_at_its_order(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            wiki = _wiki_copy(tmp)
            (wiki / "save-files.md").write_text(
                "---\nlevel: start\norder: 45\n---\n\n# Save files\n\nText.\n",
                encoding="utf-8")
            start = self._nav(wiki)["Start here"]
        targets = [e if isinstance(e, str) else next(iter(e.values())) for e in start]
        self.assertEqual(targets.index("wiki/save-files.md"),
                         targets.index("wiki/troubleshooting.md") + 1)
        self.assertIn({"Save files": "wiki/save-files.md"}, start)

    def test_a_page_without_a_level_fails_by_name(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            wiki = _wiki_copy(tmp)
            (wiki / "orphan.md").write_text("# Orphan\n\nText.\n", encoding="utf-8")
            with self.assertRaisesRegex(generate_site.NavError,
                                        r"wiki/orphan\.md: front matter needs `level:`"):
                self._nav(wiki)

    def test_a_page_without_an_order_fails_by_name(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            wiki = _wiki_copy(tmp)
            (wiki / "orphan.md").write_text(
                "---\nlevel: reference\n---\n\n# Orphan\n", encoding="utf-8")
            with self.assertRaisesRegex(
                generate_site.NavError,
                r"wiki/orphan\.md: front matter needs `order:`.*Reference tab",
            ):
                self._nav(wiki)

    def test_two_pages_on_one_place_fail_naming_both(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            wiki = _wiki_copy(tmp)
            (wiki / "twin.md").write_text(
                "---\nlevel: contribute\norder: 20\n---\n\n# Twin\n", encoding="utf-8")
            with self.assertRaisesRegex(generate_site.NavError,
                                        r"wiki/adding-a-platform\.md and wiki/twin\.md"):
                self._nav(wiki)

    def test_nav_false_keeps_a_page_out(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            wiki = _wiki_copy(tmp)
            (wiki / "hidden.md").write_text(
                "---\nlevel: start\nnav: false\n---\n\n# Hidden\n", encoding="utf-8")
            flat = repr(self._nav(wiki))
        self.assertNotIn("hidden.md", flat)

    def test_every_wiki_page_states_its_place(self):
        for page in sorted(WIKI.glob("*.md")):
            meta = generate_site._front_matter(page.read_text(encoding="utf-8"))
            with self.subTest(page=page.name):
                self.assertIn(meta.get("level"), generate_site.TABS)
                self.assertTrue(meta.get("nav") is False or isinstance(meta.get("order"), int))


if __name__ == "__main__":
    unittest.main()
