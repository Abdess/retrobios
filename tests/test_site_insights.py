"""The readings of scripts/site_insights.py, on synthetic figures."""
from __future__ import annotations

import datetime as dt
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import site_insights as si  # noqa: E402

PAGE = "https://abdess.github.io/retrobios/emulators/mgba/"


class FileNamesInSearches(unittest.TestCase):
    def test_each_name_carries_what_the_project_knows(self) -> None:
        queries = [si.Query("gba_bios.bin download", PAGE, 1, 300, 8.0),
                   si.Query("where to put GBA_BIOS.BIN", PAGE, 0, 50, 9.0),
                   si.Query("dsp1b.rom snes", PAGE, 0, 40, 9.0),
                   si.Query("mystery.pup", PAGE, 0, 10, 30.0),
                   si.Query("gba bios", PAGE, 5, 900, 7.0)]
        rows = si.searched_files(queries, held={"gba_bios.bin"}, declared={"gba_bios.bin", "dsp1b.rom"})
        self.assertEqual(rows, [("gba_bios.bin", 350, "held"), ("dsp1b.rom", 40, "declared, not held"),
                                ("mystery.pup", 10, "unknown")])


class SearchGaps(unittest.TestCase):
    def test_first_page_rarely_clicked(self) -> None:
        low = si.Query("swanstation", PAGE, 3, 540, 5.6)
        fine = si.Query("nethersx2 bios", PAGE, 54, 484, 4.6)
        far = si.Query("xbox bios", PAGE, 0, 900, 10.7)
        self.assertEqual(si.missed_clicks([low, fine, far]), [low])
        self.assertEqual(si.near_first_page([low, fine, far]), [far])


class SiteActions(unittest.TestCase):
    def test_events_are_grouped_by_kind_and_pages_apart(self) -> None:
        hits = [("/emulators/mgba/", 40), ("search-none/kenji nx", 3), ("search-none/dsp1b.rom", 7),
                ("helpful/no", 2), ("/old/link/ [404]", 5), ("download/Batocera_43.1_BIOS_Pack.zip", 9)]
        actions = si.site_actions(hits)
        self.assertEqual(actions["search-none"], [("dsp1b.rom", 7), ("kenji nx", 3)])
        self.assertEqual(actions["404"], [("/old/link/", 5)])
        self.assertEqual(actions["pages"], [("/emulators/mgba/", 40)])
        self.assertEqual(actions["helpful"], [("no", 2)])


class TheReport(unittest.TestCase):
    def test_a_skipped_source_leaves_no_section(self) -> None:
        text = si.report(dt.date(2026, 10, 1), dt.date(2026, 10, 28),
                         [si.Query("gba_bios.bin", PAGE, 1, 300, 8.0)], None, None,
                         held={"gba_bios.bin"}, declared=set())
        self.assertIn("## Google searches", text)
        self.assertIn("| gba_bios.bin | /emulators/mgba/ | 300 | 0.3% | 8.0 |", text)
        self.assertNotIn("## On the site", text)
        self.assertNotIn("## GitHub", text)

    def test_names_come_from_profiles_and_the_collection(self) -> None:
        db = {"indexes": {"by_name": {"SCPH5501.BIN": ["x"]}}}
        profiles = {"p": {"files": [{"name": "bios/dsp1b.rom", "aliases": ["DSP1B.bin"]}, "str"]}}
        held, declared = si.collection_names(db, profiles)
        self.assertEqual(held, {"scph5501.bin"})
        self.assertEqual(declared, {"dsp1b.rom", "dsp1b.bin"})


if __name__ == "__main__":
    unittest.main()
