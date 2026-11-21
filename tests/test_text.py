"""Counts and lists said one way across the site, the README and reports."""

from __future__ import annotations

import tests

import unittest

from core.text import count_text, series


class CountsTakeTheirNumber(unittest.TestCase):
    def test_one_is_singular_and_thousands_are_grouped(self):
        self.assertEqual(count_text(1, "file"), "1 file")
        self.assertEqual(count_text(0, "file"), "0 files")
        self.assertEqual(count_text(1234, "file"), "1,234 files")

    def test_a_sibilant_noun_takes_es(self):
        self.assertEqual(count_text(2, "hash"), "2 hashes")
        self.assertEqual(count_text(2, "entry", "entries"), "2 entries")


class ListsHaveNoSerialComma(unittest.TestCase):
    """The README alone wrote "RetroPie, and RomM", every page "B and C"."""

    def test_series(self):
        self.assertEqual(series([]), "")
        self.assertEqual(series(["a"]), "a")
        self.assertEqual(series(["a", "b"]), "a and b")
        self.assertEqual(series(["a", "b", "c"], "or"), "a, b or c")


if __name__ == "__main__":
    unittest.main()
