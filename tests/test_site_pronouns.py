"""The site speaks without personal pronouns.

Every page is written as an instruction or a plain statement: "Open the
Start menu.", "The installer finds the BIOS folder." No I, we, you or their
forms in the wiki sources, the pages the generators write, the README and
CONTRIBUTING, llms.txt or the agent skill. Code, URLs, markup and anchor ids
are not prose.
"""

from __future__ import annotations

import tests

import subprocess
import sys
import unittest
from functools import cache
from pathlib import Path

from tests.scratchtree import scratch_checkout
from tests.sitepages import INSTALLER, NAMES, SOURCE, pronouns

ROOT = Path(__file__).resolve().parent.parent
DOCS = Path("website") / "src" / "content" / "docs"


def _hits(paths: list[Path], root: Path = ROOT) -> list[str]:
    return [
        f"{path.relative_to(root)}:{number}: {line}"
        for path in paths
        for number, line in pronouns(path.read_text(encoding="utf-8"))
    ]


@cache
def _generated() -> Path | None:
    """The checkout copy the site was generated in, None if it failed.
    Run in the checkout, the generator rewrote website/public/data/wanted.json
    after the site was built, and test_site_wanted then read a list the
    built page did not ask for."""
    root = scratch_checkout()
    result = subprocess.run(
        [sys.executable, "scripts/generate_site.py"],
        cwd=root, capture_output=True, text=True, check=False,
    )
    return root if result.returncode == 0 else None


class Scanner(unittest.TestCase):
    def test_code_urls_and_anchors_are_not_prose(self):
        text = (
            "Run `install.py --help` first.\n"
            "```\nyou are here\n```\n"
            "See https://example.org/your/page and [a link](our-page.md).\n"
            "## Get the files { #get-your-files }\n"
            '<a title="your title">Open the menu</a>\n'
            "A US BIOS, Quake II I mean.\n"
        )
        self.assertEqual(pronouns(text), [(8, "A US BIOS, Quake II I mean.")])

    def test_each_form_is_found_in_any_case(self):
        for word in ("I", "me", "My", "mine", "we", "Us", "OUR", "you", "Yours",
                     "yourselves", "you're", "I'm"):
            with self.subTest(word=word):
                self.assertTrue(pronouns(f"Then {word} copy it."))

    def test_a_word_holding_the_letters_passes(self):
        self.assertEqual(pronouns("Usage of the menu, mine-craft, youth."), [])


class SitePronouns(unittest.TestCase):
    def test_wiki_sources(self):
        hits = _hits(sorted((ROOT / "wiki").glob("*.md")))
        self.assertEqual(hits, [], "\n".join(hits))

    def test_readme_and_contributing(self):
        hits = _hits([ROOT / "README.md", ROOT / "CONTRIBUTING.md"])
        self.assertEqual(hits, [], "\n".join(hits))

    def test_generated_pages(self):
        root = _generated()
        if root is None:
            self.fail("scripts/generate_site.py failed")
        pages = sorted(p for p in (root / DOCS).rglob("*") if p.suffix in (".md", ".mdx"))
        self.assertTrue(pages)
        hits = _hits(pages, root)
        self.assertEqual(hits, [], "\n".join(hits[:200]))

    def test_agent_files(self):
        root = _generated()
        if root is None:
            self.fail("scripts/generate_site.py failed")
        public = root / "website" / "public"
        files = [public / "llms.txt", *sorted((public / "skills").rglob("*.md"))]
        self.assertTrue(all(path.is_file() for path in files))
        hits = _hits(files, root)
        self.assertEqual(hits, [], "\n".join(hits))

    def test_release_notes(self):
        """The release page is public text too. Rendered from the committed
        record, and once more with a pack in parts, its own paragraph."""
        from release import notes
        from model import releaserecord

        record = releaserecord.load_record(ROOT / "release.json")
        first = next(iter(record["packs"]))
        parted = {**record, "packs": {**record["packs"], first: {
            **record["packs"][first], "assets": ["a.part1of2.zip", "a.part2of2.zip"]}}}
        platforms = str(ROOT / "platforms")
        hits = [f"release notes:{number}: {line}"
                for sample in (record, parted)
                for number, line in pronouns(notes.render(sample, platforms, "x"))]
        self.assertEqual(hits, [], "\n".join(hits))

    def test_every_allowed_quote_says_why(self):
        for quoted, reason in {**NAMES, **INSTALLER, **SOURCE}.items():
            with self.subTest(quoted=quoted):
                self.assertTrue(reason.strip())


if __name__ == "__main__":
    unittest.main()
