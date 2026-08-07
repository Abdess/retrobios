"""Tests for check_profile_refs pure functions (no network)."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from check_profile_refs import collect_tokens, match_ref, parse_source_ref


class TestParseSourceRef(unittest.TestCase):
    def test_path_with_single_line(self):
        self.assertEqual(
            parse_source_ref("src/core/bios.cpp:258"),
            ("src/core/bios.cpp", 258, 258),
        )

    def test_path_with_line_range(self):
        self.assertEqual(
            parse_source_ref("Machines/Utility/ROMCatalogue.cpp:123-129"),
            ("Machines/Utility/ROMCatalogue.cpp", 123, 129),
        )

    def test_path_without_line(self):
        self.assertEqual(
            parse_source_ref("FirmwareDatabase.cs"),
            ("FirmwareDatabase.cs", None, None),
        )


class TestCollectTokens(unittest.TestCase):
    def test_hashes_preferred_over_name(self):
        entry = {
            "name": "kernal.bin",
            "sha1": "6C4FA9465F6091B174DF27DFE679499DF447503C",
            "crc32": "789c8cc5",
        }
        tokens = collect_tokens(entry)
        self.assertIn("6c4fa9465f6091b174df27dfe679499df447503c", tokens)
        self.assertIn("789c8cc5", tokens)
        self.assertNotIn("kernal.bin", tokens)

    def test_name_fallback_without_hashes(self):
        tokens = collect_tokens({"name": "GC/USA/IPL.bin"})
        self.assertEqual(tokens, ["ipl.bin"])

    def test_adler_prefix_stripped(self):
        tokens = collect_tokens({"known_hash_adler32": "0x4f1f6f5c"})
        self.assertEqual(tokens, ["4f1f6f5c"])

    def test_hash_lists(self):
        tokens = collect_tokens({"md5": ["AABB", "ccdd"]})
        self.assertEqual(tokens, ["aabb", "ccdd"])


class TestMatchRef(unittest.TestCase):
    LINES = ["x = 0"] * 100 + ['hash = "789c8cc5"'] + ["y = 1"] * 100

    def test_anchored_inside_window(self):
        self.assertEqual(
            match_ref(self.LINES, 101, 101, ["789c8cc5"]), "anchored"
        )

    def test_moved_outside_window(self):
        self.assertEqual(match_ref(self.LINES, 5, 5, ["789c8cc5"]), "moved")

    def test_gone_when_absent(self):
        self.assertEqual(match_ref(self.LINES, 101, 101, ["deadbeef"]), "gone")

    def test_gone_when_file_missing(self):
        self.assertEqual(match_ref(None, 1, 1, ["789c8cc5"]), "gone")

    def test_anchored_no_line_searches_whole_file(self):
        self.assertEqual(
            match_ref(self.LINES, None, None, ["789c8cc5"]), "anchored"
        )


if __name__ == "__main__":
    unittest.main()
