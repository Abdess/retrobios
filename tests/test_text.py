"""Counts and lists said one way across the site, the README and reports."""

from __future__ import annotations

import tests

import unittest

from core.text import count_text


class CountsTakeTheirNumber(unittest.TestCase):
    def test_one_is_singular_and_thousands_are_grouped(self):
        self.assertEqual(count_text(1, "file"), "1 file")
        self.assertEqual(count_text(0, "file"), "0 files")
        self.assertEqual(count_text(1234, "file"), "1,234 files")

    def test_a_sibilant_noun_takes_es(self):
        self.assertEqual(count_text(2, "hash"), "2 hashes")
        self.assertEqual(count_text(2, "entry", "entries"), "2 entries")


if __name__ == "__main__":
    unittest.main()
