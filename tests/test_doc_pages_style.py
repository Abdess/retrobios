"""How the published pages are written: headings, openings, tone, numbers."""

from __future__ import annotations

import tests
from tests.mdsections import FENCED
from tests.sources import script_source

import re
import unittest

from tests.docpagessupport import PUBLISHED, ROOT, WIKI, _python_prose, _sentence_case


class PublishedHeadings(unittest.TestCase):
    """README.md kept '## Quick Install', the one Title Case heading left,
    because the casing test read wiki/ only."""

    def test_readme_and_contributing_use_sentence_case(self):
        offenders = []
        for page in (ROOT / "README.md", ROOT / "CONTRIBUTING.md"):
            text = FENCED.sub("", page.read_text(encoding="utf-8"))
            offenders.extend(
                f"{page.name}: {title}"
                for title in re.findall(r"(?m)^#{1,4} (.+)$", text)
                if _sentence_case(title) != title
            )
        self.assertEqual(offenders, [], "\n".join(offenders))


class FilesColumnParagraph(unittest.TestCase):
    """'Files is how many the pack holds' was glued to the paragraph above
    it, two paragraphs before the table whose column it described."""

    def test_it_names_the_column_in_its_own_paragraph_before_the_table(self):

        source = script_source("generate_readme.py")
        self.assertNotIn("Files is how many", source)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        paragraph = next(p for p in readme.split("\n\n") if "The Files column" in p)
        self.assertNotIn("\n", paragraph.strip())
        after = readme.split(paragraph, 1)[1].lstrip("\n")
        self.assertTrue(after.startswith("| Setup | Files |"))


class PageOpenings(unittest.TestCase):
    """Four pages opened by announcing what they cover."""

    META = re.compile(r"(?i)\bthis (page|guide) (covers|documents|explains|describes|picks)\b|^Diagnosis guide")

    def test_no_page_announces_itself(self):
        offenders = [
            f"{page.name}: {line[:80]}"
            for page in PUBLISHED
            for line in FENCED.sub("", page.read_text(encoding="utf-8")).splitlines()
            if self.META.search(line)
        ]
        self.assertEqual(offenders, [], "\n".join(offenders))


class NoHedgedRules(unittest.TestCase):
    """The profiling guide and the verification discipline turned rules into
    wishes ("it's worth", "Ideally", "something to look into")."""

    FILLER = re.compile(
        r"(?i)\bit'?s worth\b|\bworth noting\b|\bit helps to\b|^Ideally\b"
        r"|\bsomething to look into\b|\busually indicate\b"
    )

    def test_published_pages(self):
        offenders = [
            f"{page.name}: {line[:80]}"
            for page in PUBLISHED
            for line in FENCED.sub("", page.read_text(encoding="utf-8")).splitlines()
            if self.FILLER.search(line)
        ]
        self.assertEqual(offenders, [], "\n".join(offenders))


class DocstringsWithoutInsistence(unittest.TestCase):
    """truth.py shouted ONE and NEVER in an eighteen-line docstring, and
    generate_pack.py listed three guarantees under 'This ensures:' of which
    two said the same thing."""

    TICS = re.compile(r"\b(NEVER|ALWAYS|ONE|MUST)\b|This ensures:")

    def test_scripts_and_installer(self):
        offenders = []
        paths = sorted((ROOT / "scripts").rglob("*.py")) + [ROOT / "install.py"]
        for path in paths:
            offenders.extend(
                f"{path.relative_to(ROOT)}: {line.strip()[:80]}"
                for line in _python_prose(path.read_text(encoding="utf-8")).splitlines()
                if self.TICS.search(line)
            )
        self.assertEqual(offenders, [], "\n".join(offenders))


class PeerToneTowardPlatforms(unittest.TestCase):
    """Platform lists were called wrong, stale or corrected on public pages
    that their maintainers read."""

    WORDS = re.compile(
        r"(?i)\bgets wrong\b|\bstale (hash|entries|entry)\b|<their file>|\bpatch their\b"
        r"|, corrected\b|\bcorrected in place\b|\bdeclare incorrectly\b|\blist error\b"
        r"|\btheir syntax\b|\bthe platform lacks\b|\bthe odd one\b|\bmay not match reality\b"
        r"|\ball their code does\b|\bcan drift from\b"
    )

    def test_published_pages(self):
        offenders = [
            f"{page.name}: {line[:80]}"
            for page in PUBLISHED
            for line in page.read_text(encoding="utf-8").splitlines()
            if self.WORDS.search(line)
        ]
        self.assertEqual(offenders, [], "\n".join(offenders))


class PublishedNumbersShareOneFormat(unittest.TestCase):
    """The README gave the collection as `16011 MB` beside `19,526 files`,
    the site home as 15.6 GB, and the emulators page `10095 files`."""

    def test_generators_format_counts_and_sizes_alike(self):
        from core.sizes import size_text
        from sitegen import readme as sitegen_readme

        from tests.readmeinputs import RELEASED_SIZE, readme_inputs

        rendered = sitegen_readme.render_readme(readme_inputs())
        self.assertIn(f"| RetroArch | 4,525 | {size_text(RELEASED_SIZE)} |", rendered)
        self.assertIn("19,526 files in the collection", rendered)
        self.assertIn("{total_files:,}", script_source("generate_site.py"))
        self.assertEqual(size_text(16011 * 1024 * 1024), "15.6 GB")

    def test_the_readme_has_no_bare_large_count(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"\*\*\d{4,}\b[^*]*\*\*", readme), [])


class ReadmeKeepsItsPointers(unittest.TestCase):
    def test_the_bare_minimum_is_built_below(self):
        """The README sent a reader to 'build your own pack below' for a bare
        minimum, and the block below never named --required-only."""
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        block = readme[readme.index("<summary><strong>For developers"):readme.index("</details>")]
        self.assertIn("--required-only", block)

    def test_unsourceable_files_are_not_said_to_exist_nowhere(self):
        """The README said 138 files 'cannot be sourced at all (... dumps
        nobody has made)', while most of their reasons read 'retail data the
        collection does not hold'."""
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("sourced at all", readme)
        self.assertNotIn("nobody has made", readme)
        # The README names no count: the gap analysis it links does, by reason.
        self.assertIn("gaps/", readme)


class APlatformListIsDescribedNotJudged(unittest.TestCase):
    """adding-a-platform opened on files a platform's own list "leaves out",
    read first by the maintainer of that platform: "does not name" says the
    same without imputing an omission."""

    def test_no_page_says_a_list_leaves_files_out(self):
        pattern = re.compile(r"\blists? (?:leaves|left|leave) out\b")
        for page in sorted(WIKI.glob("*.md")):
            with self.subTest(page=page.name):
                self.assertIsNone(pattern.search(page.read_text(encoding="utf-8")))


class NoTextClaimsAScheduledScrape(unittest.TestCase):
    """The README and the setup pages said a platform is scraped on a
    schedule, and adding-a-platform said the registry feeds a CI matrix and
    the scrapers. No workflow calls list_platforms.py and no tool reads
    `schedule:`."""

    def test_no_text_ties_the_registry_to_automation(self):
        texts = {
            "adding-a-platform.md": (WIKI / "adding-a-platform.md").read_text(encoding="utf-8"),
            "generate_readme": script_source("generate_readme.py"),
            "generate_site": script_source("generate_site.py"),
            "generate_pack": script_source("generate_pack.py"),
            "list_platforms": script_source("list_platforms.py"),
            "_guides.yml": (ROOT / "platforms" / "_guides.yml").read_text(encoding="utf-8"),
        }
        for name, text in texts.items():
            with self.subTest(name):
                for claim in ("scraped on a schedule", "read again on a schedule",
                              "CI matrix", "without the automation"):
                    self.assertNotIn(claim, text)
        for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
            self.assertNotIn("list_platforms", workflow.read_text(encoding="utf-8"))


class TheCatalogRowsStateFacts(unittest.TestCase):
    """tools.md said "redump.org serves stale DATs" and "Dat-o-Matic blocks
    automation", verdicts on two preservation projects, and gave Redump's
    /static/bios links, which the scraper no longer reads."""

    def test_dates_and_routes_not_verdicts(self):
        text = (WIKI / "tools.md").read_text(encoding="utf-8")
        rows = [line for line in text.splitlines()
                if line.startswith(("| Redump |", "| No-Intro |"))]
        self.assertEqual(len(rows), 2)
        for word in ("stale", "blocks"):
            self.assertNotIn(word, " ".join(rows))
        scraper = (ROOT / "scripts" / "scraper" / "dats" / "redump_dat_scraper.py").read_text(encoding="utf-8")
        self.assertIn("/bios/<CODE>", scraper)
        self.assertIn("`/bios/<CODE>`", rows[0])


if __name__ == "__main__":
    unittest.main()
