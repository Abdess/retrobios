#!/usr/bin/env python3
"""Rename detection in the truth-vs-platform diff.

A platform may call a file whatever it likes: Batocera ships the same Sega CD
ROM as ROM1. A name that matches nothing in the profile is therefore not yet a
gap, and reporting it as both a missing file and an extra one would invent a
discrepancy that does not exist. Content decides, as everywhere else here.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from truth import _match_renames  # noqa: E402


def _entry(name: str, **hashes) -> dict:
    return {"name": name, **hashes}


class RenameMatching(unittest.TestCase):
    def test_a_shared_sha1_pairs_the_two_names(self):
        truth = [_entry("bios_CD_U.bin", sha1="a" * 40)]
        scraped = {"rom1.bin": _entry("ROM1.bin", sha1="a" * 40)}
        matched_truth, matched_scraped = _match_renames(truth, scraped)
        self.assertEqual(matched_truth, {"bios_cd_u.bin"})
        self.assertEqual(matched_scraped, {"rom1.bin"})

    def test_md5_and_crc32_pair_them_too(self):
        for algorithm in ("md5", "crc32"):
            with self.subTest(algorithm=algorithm):
                value = "b" * 32
                truth = [_entry("a.bin", **{algorithm: value})]
                scraped = {"b.bin": _entry("b.bin", **{algorithm: value})}
                matched_truth, _ = _match_renames(truth, scraped)
                self.assertEqual(matched_truth, {"a.bin"})

    def test_hash_comparison_ignores_case(self):
        truth = [_entry("a.bin", sha1="AbCdEf" + "0" * 34)]
        scraped = {"b.bin": _entry("b.bin", sha1="abcdef" + "0" * 34)}
        self.assertEqual(_match_renames(truth, scraped)[0], {"a.bin"})

    def test_different_content_is_not_a_rename(self):
        truth = [_entry("a.bin", sha1="a" * 40)]
        scraped = {"b.bin": _entry("b.bin", sha1="b" * 40)}
        self.assertEqual(_match_renames(truth, scraped), (set(), set()))

    def test_files_with_no_hashes_never_pair(self):
        """Two unknowns are not evidence of the same file."""
        truth = [_entry("a.bin")]
        scraped = {"b.bin": _entry("b.bin")}
        self.assertEqual(_match_renames(truth, scraped), (set(), set()))

    def test_a_non_string_hash_is_ignored_rather_than_crashing(self):
        truth = [_entry("a.bin", crc32=12345678)]
        scraped = {"b.bin": _entry("b.bin", crc32=12345678)}
        self.assertEqual(_match_renames(truth, scraped), (set(), set()))

    def test_empty_input_on_either_side_pairs_nothing(self):
        self.assertEqual(_match_renames([], {}), (set(), set()))
        self.assertEqual(_match_renames([_entry("a", sha1="a" * 40)], {}), (set(), set()))
        self.assertEqual(
            _match_renames([], {"b": _entry("b", sha1="a" * 40)}), (set(), set())
        )

    def test_each_scraped_file_pairs_once(self):
        """A file matching on several digests must not be counted twice."""
        truth = [_entry("a.bin", sha1="a" * 40, md5="b" * 32)]
        scraped = {"b.bin": _entry("b.bin", sha1="a" * 40, md5="b" * 32)}
        matched_truth, matched_scraped = _match_renames(truth, scraped)
        self.assertEqual(len(matched_truth), 1)
        self.assertEqual(len(matched_scraped), 1)

    def test_several_renames_are_all_reported(self):
        truth = [_entry("a.bin", sha1="a" * 40), _entry("c.bin", sha1="c" * 40)]
        scraped = {
            "b.bin": _entry("b.bin", sha1="a" * 40),
            "d.bin": _entry("d.bin", sha1="c" * 40),
        }
        matched_truth, matched_scraped = _match_renames(truth, scraped)
        self.assertEqual(matched_truth, {"a.bin", "c.bin"})
        self.assertEqual(matched_scraped, {"b.bin", "d.bin"})

    def test_an_unrelated_file_beside_a_rename_stays_unmatched(self):
        truth = [_entry("a.bin", sha1="a" * 40), _entry("lonely.bin", sha1="f" * 40)]
        scraped = {"b.bin": _entry("b.bin", sha1="a" * 40)}
        matched_truth, _ = _match_renames(truth, scraped)
        self.assertEqual(matched_truth, {"a.bin"})
        self.assertNotIn("lonely.bin", matched_truth)


if __name__ == "__main__":
    unittest.main()
