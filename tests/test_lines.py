"""One line index answers the line of every offset a parser reports."""

from __future__ import annotations

import tests

import unittest

from core.lines import LineIndex


class LinesOfOffsets(unittest.TestCase):
    TEXT = "a\nbc\n\nd"

    def test_each_offset_gets_the_count_of_newlines_before_it_plus_one(self):
        index = LineIndex(self.TEXT)
        for offset in range(len(self.TEXT) + 1):
            with self.subTest(offset=offset):
                self.assertEqual(index.line(offset), self.TEXT[:offset].count("\n") + 1)

    def test_a_line_starts_after_the_newline_before_it(self):
        index = LineIndex(self.TEXT)
        self.assertEqual([index.start(n) for n in (1, 2, 3, 4)], [0, 2, 5, 6])

    def test_a_text_without_newline_is_one_line(self):
        self.assertEqual(LineIndex("").line(0), 1)
        self.assertEqual(LineIndex("abc").line(2), 1)


class ParsersReportLines(unittest.TestCase):
    def test_mame_and_fbneo_sets_carry_their_line(self):
        from scripts.scraper.arcade.fbneo_parser import find_bios_sets
        from scripts.scraper.arcade.mame_parser import find_bios_root_sets

        mame = "\n\nGAME( 1990, neogeo, 0, ng, ng, ng_state, init, ROT0, \"SNK\", \"Neo\", MACHINE_IS_BIOS_ROOT )\n"
        self.assertEqual(find_bios_root_sets(mame, "neogeo.cpp")["neogeo"]["source_line"], 3)
        fbneo = '\n\n\nstruct BurnDriver BurnDrvNeogeo = {\n\t"neogeo", NULL, NULL, NULL, "1990",\n\tBDF_BOARDROM,\n};\n'
        self.assertEqual(find_bios_sets(fbneo, "d_neogeo.cpp")["neogeo"]["source_line"], 4)


if __name__ == "__main__":
    unittest.main()
