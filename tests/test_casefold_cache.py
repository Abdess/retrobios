"""The case-insensitive name index answers for the database it was asked about."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import _casefold_name_index  # noqa: E402


class CasefoldIndexFollowsItsSource(unittest.TestCase):
    def test_a_new_dict_gets_its_own_index(self):
        first = {"BIOS.ROM": ["a"]}
        self.assertEqual(_casefold_name_index(first)["bios.rom"], ["a"])
        second = {"Bios.Rom": ["b"]}
        self.assertEqual(_casefold_name_index(second)["bios.rom"], ["b"])

    def test_a_grown_dict_is_reindexed(self):
        index = {"A.BIN": ["a"]}
        _casefold_name_index(index)
        index["B.BIN"] = ["b"]
        self.assertIn("b.bin", _casefold_name_index(index))


if __name__ == "__main__":
    unittest.main()
