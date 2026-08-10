#!/usr/bin/env python3
"""The BaseScraper contract the wiki asks contributors to implement.

wiki/adding-a-scraper.md and wiki/adding-a-platform.md document
compare_with_config, ChangeSet.has_changes and test_connection as the
interface a new scraper plugs into. No scraper in the repository calls them,
so nothing proved they still worked; a documented contract that is never
exercised is a promise to contributors backed by nothing.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from scraper.base_scraper import (  # noqa: E402
    BaseScraper,
    BiosRequirement,
    ChangeSet,
)


class _StubScraper(BaseScraper):
    """Minimal scraper: returns what it was handed, or raises."""

    def __init__(self, requirements=None, error: Exception | None = None):
        super().__init__(url="https://example.test/bios.xml")
        self._requirements = requirements or []
        self._error = error

    def fetch_requirements(self) -> list[BiosRequirement]:
        if self._error is not None:
            raise self._error
        return self._requirements

    def validate_format(self, raw_data: str) -> bool:
        return True


def _config(*files: dict) -> dict:
    return {"systems": {"test-sys": {"files": list(files)}}}


class ChangeSetSummary(unittest.TestCase):
    def test_empty_changeset_has_no_changes(self):
        changes = ChangeSet()
        self.assertFalse(changes.has_changes)
        self.assertEqual(changes.summary(), "no changes")

    def test_summary_counts_each_kind(self):
        req = BiosRequirement(name="a.bin", system="test-sys")
        changes = ChangeSet(added=[req], removed=[req], modified=[(req, req)])
        self.assertTrue(changes.has_changes)
        self.assertEqual(changes.summary(), "+1 added, -1 removed, ~1 modified")


class CompareWithConfig(unittest.TestCase):
    def test_new_upstream_file_is_reported_as_added(self):
        scraper = _StubScraper([BiosRequirement(name="new.bin", system="test-sys")])
        changes = scraper.compare_with_config(_config())
        self.assertEqual([r.name for r in changes.added], ["new.bin"])
        self.assertTrue(changes.has_changes)

    def test_file_dropped_upstream_is_reported_as_removed(self):
        scraper = _StubScraper([])
        changes = scraper.compare_with_config(_config({"name": "old.bin"}))
        self.assertEqual([r.name for r in changes.removed], ["old.bin"])

    def test_changed_sha1_is_reported_as_modified(self):
        scraper = _StubScraper(
            [BiosRequirement(name="a.bin", system="test-sys", sha1="b" * 40)]
        )
        changes = scraper.compare_with_config(_config({"name": "a.bin", "sha1": "a" * 40}))
        self.assertEqual(len(changes.modified), 1)
        before, after = changes.modified[0]
        self.assertEqual((before.sha1, after.sha1), ("a" * 40, "b" * 40))

    def test_changed_md5_is_reported_when_no_sha1_is_declared(self):
        scraper = _StubScraper(
            [BiosRequirement(name="a.bin", system="test-sys", md5="b" * 32)]
        )
        changes = scraper.compare_with_config(_config({"name": "a.bin", "md5": "a" * 32}))
        self.assertEqual(len(changes.modified), 1)

    def test_identical_hashes_are_not_a_change(self):
        scraper = _StubScraper(
            [BiosRequirement(name="a.bin", system="test-sys", sha1="a" * 40)]
        )
        changes = scraper.compare_with_config(_config({"name": "a.bin", "sha1": "a" * 40}))
        self.assertFalse(changes.has_changes)

    def test_a_file_in_another_system_is_not_the_same_file(self):
        scraper = _StubScraper([BiosRequirement(name="a.bin", system="other-sys")])
        changes = scraper.compare_with_config(_config({"name": "a.bin"}))
        self.assertEqual([r.name for r in changes.added], ["a.bin"])
        self.assertEqual([r.name for r in changes.removed], ["a.bin"])


class TestConnection(unittest.TestCase):
    def test_reachable_source_reports_true(self):
        self.assertTrue(_StubScraper([]).test_connection())

    def test_network_failure_reports_false(self):
        self.assertFalse(_StubScraper(error=OSError("unreachable")).test_connection())

    def test_bad_payload_reports_false(self):
        self.assertFalse(_StubScraper(error=ValueError("bad format")).test_connection())

    def test_an_unexpected_error_is_not_swallowed(self):
        """Only reachability failures are absorbed; a bug must surface."""
        with self.assertRaises(KeyError):
            _StubScraper(error=KeyError("bug")).test_connection()


if __name__ == "__main__":
    unittest.main()
