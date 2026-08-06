"""Tests for the TorrentZip builder against real MAME romsets."""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
import zipfile

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

from torrentzip import (  # noqa: E402
    build_torrentzip,
    identify_romset,
    is_torrentzip,
    rebuild_torrentzip,
)


class TorrentZipTest(unittest.TestCase):
    """The format is deterministic: same members always give the same bytes."""

    def test_deterministic_output(self):
        members = [("b.rom", b"second"), ("a.rom", b"first")]
        self.assertEqual(build_torrentzip(members), build_torrentzip(members))

    def test_member_order_is_irrelevant(self):
        a = build_torrentzip([("a.rom", b"one"), ("b.rom", b"two")])
        b = build_torrentzip([("b.rom", b"two"), ("a.rom", b"one")])
        self.assertEqual(a, b)

    def test_case_insensitive_sorting(self):
        data = build_torrentzip([("B.rom", b"x"), ("a.rom", b"y")])
        with zipfile.ZipFile(_as_file(self, data)) as zf:
            self.assertEqual([i.filename for i in zf.infolist()], ["a.rom", "B.rom"])

    def test_fixed_timestamp_and_signature(self):
        data = build_torrentzip([("a.rom", b"payload")])
        with zipfile.ZipFile(_as_file(self, data)) as zf:
            self.assertEqual(zf.infolist()[0].date_time, (1996, 12, 24, 23, 32, 0))
            self.assertTrue(zf.comment.decode().startswith("TORRENTZIPPED-"))

    def test_roundtrip_readable_content(self):
        data = build_torrentzip([("a.rom", b"hello"), ("b.rom", b"world")])
        with zipfile.ZipFile(_as_file(self, data)) as zf:
            self.assertEqual(zf.read("a.rom"), b"hello")
            self.assertEqual(zf.read("b.rom"), b"world")

    def test_rebuild_matches_real_mame_set(self):
        """Rebuilding a shipped MAME romset reproduces it byte for byte."""
        candidates = [
            os.path.join(REPO_ROOT, "bios", "Arcade", "Arcade", "naomi2.zip"),
            os.path.join(REPO_ROOT, "bios", "Arcade", "MAME", "naomi2.zip"),
        ]
        checked = 0
        for path in candidates:
            if not os.path.exists(path) or not is_torrentzip(path):
                continue
            with open(path, "rb") as fh:
                original = fh.read()
            self.assertEqual(rebuild_torrentzip(path), original, path)
            checked += 1
        if not checked:
            self.skipTest("no TorrentZip romset available")

    def test_identify_romset_selects_matching_recipe(self):
        atoms = {"3610a686": b"alpha", "9d0d1b46": b"beta"}
        import zlib

        atoms = {
            f"{zlib.crc32(b'alpha') & 0xffffffff:08x}": b"alpha",
            f"{zlib.crc32(b'beta') & 0xffffffff:08x}": b"beta",
        }
        crc_a, crc_b = list(atoms)
        wanted = hashlib.md5(
            build_torrentzip([("a.rom", b"alpha"), ("b.rom", b"beta")])
        ).hexdigest()
        recipes = {
            "v1": [("a.rom", crc_a)],
            "v2": [("a.rom", crc_a), ("b.rom", crc_b)],
        }
        self.assertEqual(identify_romset(recipes, atoms, wanted), "v2")
        self.assertIsNone(identify_romset(recipes, atoms, "0" * 32))

    def test_identify_romset_skips_recipes_with_absent_atoms(self):
        atoms = {"aaaaaaaa": b"x"}
        recipes = {"v1": [("a.rom", "ffffffff")]}
        self.assertIsNone(identify_romset(recipes, atoms, "0" * 32))


def _as_file(test: unittest.TestCase, data: bytes) -> str:
    """Write bytes to a temp file cleaned up with the test."""
    fd, path = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    with open(path, "wb") as fh:
        fh.write(data)
    test.addCleanup(os.unlink, path)
    return path


if __name__ == "__main__":
    unittest.main()
