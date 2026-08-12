#!/usr/bin/env python3
"""Writing the site: what gets rewritten, and what gets deleted.

The generated tree used to be deleted before each build. Every page was then
new, so the comparison that skips unchanged files had no earlier version to
compare against and the whole site was rewritten for the clock alone: two
consecutive builds on identical inputs differed on 1034 files. Sweeping
instead means a page is deleted only once nothing produces it, which puts a
delete on the critical path and is why these tests exist.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import sitewrite  # noqa: E402

BODY = "# Title\n\nSome prose.\n\n*Generated on 2026-01-01T00:00:00Z*\n"
FRONT = (
    "---\n"
    "generated_by: retrobios-site\n"
    'title: "Title"\n'
    "---\n\n"
    '<script type="application/ld+json">\n{"@type":"TechArticle"}\n</script>\n\n'
)


class Undecorate(unittest.TestCase):
    def test_it_removes_front_matter_and_structured_data(self):
        self.assertEqual(sitewrite._undecorated(FRONT + BODY), BODY)

    def test_a_plain_body_is_returned_unchanged(self):
        self.assertEqual(sitewrite._undecorated(BODY), BODY)

    def test_front_matter_this_build_did_not_write_is_left_alone(self):
        """A hand-maintained page with its own front matter is not ours."""
        foreign = '---\ntitle: "Hand written"\n---\n\nBody.\n'
        self.assertEqual(sitewrite._undecorated(foreign), foreign)


class TwoPassWriting(unittest.TestCase):
    """A page is written as a body, then rewritten wrapped in front matter."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.page = Path(self._tmp.name) / "page.md"
        sitewrite._produced.clear()

    def tearDown(self):
        sitewrite._produced.clear()
        self._tmp.cleanup()

    def _build(self, body: str) -> tuple[bool, bool]:
        wrote_body = sitewrite.write_if_changed(str(self.page), body)
        wrote_page = sitewrite.write_decorated(self.page, FRONT + body)
        return wrote_body, wrote_page

    def test_the_first_build_writes_and_decorates(self):
        self.assertEqual(self._build(BODY), (True, True))
        self.assertTrue(self.page.read_text().startswith("---\n"))
        self.assertIn("ld+json", self.page.read_text())

    def test_an_identical_rebuild_writes_nothing(self):
        self._build(BODY)
        self.assertEqual(self._build(BODY), (False, False))

    def test_a_rebuild_keeps_the_front_matter(self):
        """Normalizing on both sides made the decoration look like a no-op."""
        self._build(BODY)
        self._build(BODY)
        self.assertIn("ld+json", self.page.read_text())

    def test_only_the_timestamp_moving_writes_nothing(self):
        self._build(BODY)
        moved = BODY.replace("2026-01-01T00:00:00Z", "2027-06-30T12:00:00Z")
        self.assertEqual(self._build(moved), (False, False))
        self.assertIn("2026-01-01", self.page.read_text())

    def test_a_changed_body_is_written(self):
        self._build(BODY)
        self.assertEqual(self._build(BODY + "\nNew section.\n")[0], True)
        self.assertIn("New section.", self.page.read_text())
        self.assertIn("ld+json", self.page.read_text())


class Sweep(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.docs = Path(self._tmp.name)
        sitewrite._produced.clear()
        for relative in ("emulators/kept.md", "emulators/nested/deep.md",
                         "emulators/stale.md", "platforms/kept.md",
                         "untouched/manual.md"):
            path = self.docs / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x")

    def tearDown(self):
        sitewrite._produced.clear()
        self._tmp.cleanup()

    def _produce(self, *relatives: str) -> None:
        for relative in relatives:
            sitewrite._record(self.docs / relative)

    def test_it_removes_only_what_nothing_produced(self):
        self._produce("emulators/kept.md", "emulators/nested/deep.md",
                      "platforms/kept.md")
        removed = sitewrite._sweep_generated(self.docs, ["emulators", "platforms"])
        self.assertEqual(removed, 1)
        self.assertFalse((self.docs / "emulators/stale.md").exists())
        self.assertTrue((self.docs / "emulators/kept.md").exists())
        self.assertTrue((self.docs / "emulators/nested/deep.md").exists())

    def test_a_directory_outside_the_list_is_never_touched(self):
        self._produce("emulators/kept.md", "emulators/nested/deep.md",
                      "emulators/stale.md")
        sitewrite._sweep_generated(self.docs, ["emulators"])
        self.assertTrue((self.docs / "untouched/manual.md").exists())
        self.assertTrue((self.docs / "platforms/kept.md").exists())

    def test_an_emptied_directory_is_pruned(self):
        self._produce("emulators/kept.md", "emulators/stale.md")
        sitewrite._sweep_generated(self.docs, ["emulators"])
        self.assertFalse((self.docs / "emulators/nested").exists())
        self.assertTrue((self.docs / "emulators").is_dir())

    def test_a_missing_directory_is_not_an_error(self):
        self.assertEqual(sitewrite._sweep_generated(self.docs, ["absent"]), 0)

    def test_producing_nothing_empties_the_generated_tree(self):
        """The wipe this replaced, reached only when the build produced nothing."""
        removed = sitewrite._sweep_generated(self.docs, ["emulators"])
        self.assertEqual(removed, 3)
        self.assertTrue((self.docs / "untouched/manual.md").exists())

    def test_the_produced_set_survives_a_second_build_in_one_process(self):
        """It is never reset, so a second run can only sweep less, never more.

        Deleting a page a previous run produced would be the dangerous
        direction; sparing one is merely stale, and the next fresh process
        removes it.
        """
        self._produce("emulators/kept.md")
        sitewrite._sweep_generated(self.docs, ["emulators"])
        survivors = {p.name for p in (self.docs / "emulators").rglob("*")
                     if p.is_file()}
        self.assertEqual(survivors, {"kept.md"})
        (self.docs / "emulators" / "kept.md").write_text("y")
        self.assertEqual(sitewrite._sweep_generated(self.docs, ["emulators"]), 0)


if __name__ == "__main__":
    unittest.main()
