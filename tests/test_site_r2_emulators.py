"""Emulator pages say what is needed first, in names.

DuckStation's page opened on "It reads 105 files, 3 of them required" and
read as "get all three", its three BIOS were cards 12 to 14 under one
heading, its header said "Official ports" and "duckstation, Duckstation",
and every system was an id ("sony-playstation").
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site as gs  # noqa: E402
import siterender  # noqa: E402

EMPTY_DB = {"files": {}, "indexes": {"by_name": {}}}


def _profile(name: str) -> dict:
    with open(REPO_ROOT / "emulators" / f"{name}.yml", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _page(name: str, profile: dict) -> str:
    return gs.generate_emulator_page(name, profile, EMPTY_DB, None, set())


def _files(count: int, **fields: object) -> list[dict]:
    return [{"name": f"f{i:03d}.bin", **fields} for i in range(count)]


class TheIntroSaysWhatIsNeeded(unittest.TestCase):
    def test_one_bios_per_region(self):
        profile = _profile("duckstation")
        intro = gs._emulator_intro("DuckStation", profile)
        self.assertIn(
            "It picks the BIOS for your game's region: scph5500.bin (Japan), "
            "scph5501.bin (North America and Latin America) or scph5502.bin "
            "(Europe and Oceania).", intro)
        others = len(profile["files"]) - 3
        self.assertIn(f"The {others} other files are optional.", intro)
        self.assertNotIn("3 of them required", intro)
        self.assertIn("DuckStation emulates Sony PlayStation.", intro)

    def test_required_files_without_regions_keep_the_count(self):
        intro = gs._emulator_intro("X", {"files": [
            {"name": "a.bin", "required": True}, {"name": "b.bin"}]})
        self.assertIn("It reads 2 files, 1 of them required", intro)

    def test_several_machines_say_who_needs_a_required_file(self):
        intro = gs._emulator_intro("X", {
            "systems": ["sony-playstation", "sega-saturn"],
            "files": [{"name": "a.bin", "required": True}]})
        self.assertIn("A required file is needed only by the machines that use it.", intro)
        one = gs._emulator_intro("X", {
            "systems": ["sony-playstation"], "files": [{"name": "a.bin", "required": True}]})
        self.assertNotIn("machines that use it", one)


class TheHeaderReadsAsWords(unittest.TestCase):
    def setUp(self) -> None:
        self.page = _page("duckstation", _profile("duckstation"))

    def test_singular_classification(self):
        self.assertIn("| Classification | Official port |", self.page)

    def test_cores_once_per_spelling(self):
        # duckstation-sa is ROCKNIX's name for the standalone build.
        self.assertIn("| Cores | duckstation, duckstation-sa |", self.page)

    def test_systems_by_name(self):
        row = next(line for line in self.page.splitlines() if line.startswith("| Systems |"))
        self.assertIn("Sony PlayStation", row)
        self.assertNotIn("[sony-playstation]", row)

    def test_region_badge_is_labelled(self):
        self.assertIn(">Region: Japan</span>", self.page)
        self.assertNotIn('rb-badge-muted">japan</span>', self.page)

    def test_profile_version_names_the_pinned_build(self):
        # DuckStation tags builds v0.1-<commits since tag 0.1>, and the
        # pin sits past the last such tag: git describe's form names both.
        self.assertRegex(str(_profile("duckstation")["core_version"]),
                         r"^v0\.1-\d+(-\d+-g[0-9a-f]{7})?$")

    def test_the_second_spelling_is_a_platform_name(self):
        # The lookup is case-sensitive and EmuELEC launches "Duckstation":
        # the page hides the duplicate, the profile keeps it.
        with open(REPO_ROOT / "platforms" / "emuelec.yml", encoding="utf-8") as handle:
            emuelec = yaml.safe_load(handle)
        self.assertIn("Duckstation", emuelec["cores"])
        self.assertIn("Duckstation", _profile("duckstation")["cores"])


class RequiredFilesComeFirst(unittest.TestCase):
    def test_sections_in_need_order(self):
        files = [
            {"name": "data.pak", "category": "game_data", "required": True},
            {"name": "opt.bin"},
            {"name": "req.bin", "required": True, "region": ["japan"], "md5": "ab" * 16},
        ]
        page = _page("x", {"type": "standalone", "files": files})
        heads = [line for line in page.splitlines() if line.startswith("## ")]
        self.assertEqual(heads[:4], ["## Files", "## Required", "## Optional", "## Game data"])
        self.assertLess(page.index("## Required"), page.index("req.bin"))
        self.assertLess(page.index("req.bin"), page.index("## Optional"))
        self.assertLess(page.index("## Game data"), page.index("data.pak"))

    def test_the_table_of_contents_turns_on(self):
        page = _page("duckstation", _profile("duckstation"))
        self.assertGreater(len(re.findall(r"^## ", page, re.M)), 2)

    def test_rows_carry_region_and_hash(self):
        files = _files(gs.EMULATOR_TABLE_MIN - 1) + [
            {"name": "req.bin", "required": True, "region": ["japan"], "md5": "ab" * 16}]
        page = _page("x", {"type": "standalone", "files": files})
        required = page[page.index("## Required"):page.index("## Optional")]
        self.assertIn('id="file-req-bin', required)
        self.assertIn("Region: Japan", required)
        self.assertIn(f'MD5\u00a0<code title="{"ab" * 16}">{"ab" * 6}</code>', required)
        self.assertNotIn("f000.bin", required)

    def test_no_table_for_a_few_cards(self):
        page = _page("x", {"type": "standalone", "files": _files(2)})
        self.assertNotIn('class="rb-entries"', page)
        self.assertIn('class="rb-file-entry"', page)

    def test_a_split_page_puts_required_on_the_first_part(self):
        count = gs.EMULATOR_CARDS_PER_PAGE * 2
        files = _files(count) + [{"name": "last.bin", "required": True}]
        parts = gs.emulator_parts("big", files)
        self.assertIn(count, parts[0][1])
        pages = gs.emulator_pages("big", {"emulator": "Big", "type": "standalone",
                                          "files": files}, {"files": {}})
        main = pages["big"]
        self.assertLess(main.index("## Required"), main.index("## Optional"))
        self.assertLess(main.index("last.bin"), main.index("f000.bin"))
        self.assertIn("## Required", pages["big-files-1"])


class TheSummaryLineIsProse(unittest.TestCase):
    def test_no_pipes_and_one_number_format(self):
        files = _files(1563, category="bios_zip") + [
            {"name": "a.pak", "category": "game_data"}, {"name": "b.pak", "category": "game_data"}]
        for f in files[:164]:
            f["required"] = True
        text = "\n".join(gs._emulator_file_summary(files))
        self.assertNotIn(" | ", text)
        self.assertNotIn("1399", text)
        self.assertIn("1,401 optional", text)
        self.assertIn("By kind: 1,563 BIOS ZIPs and 2 game data.", text)

    def test_category_badge_in_words(self):
        badges = " ".join(gs._file_badges({"name": "a", "category": "game_data"}, True))
        self.assertIn(">game data</span>", badges)


class TheIndexNamesEmulatorsAndSystems(unittest.TestCase):
    def test_columns_and_counts(self):
        # Pages another test split off would send the console elsewhere.
        siterender.reset_console_pages()
        self.addCleanup(siterender.reset_console_pages)
        saved = dict(siterender._system_page_map)
        self.addCleanup(siterender.set_system_page_map, saved)
        siterender.set_system_page_map({"sony-playstation": ("sony", "PlayStation")})
        page = gs.generate_emulators_index({
            "duckstation": {"emulator": "DuckStation", "core_classification": "official_port",
                            "systems": ["sony-playstation"], "files": _files(3)},
        })
        self.assertIn("| Emulator | Kind | Systems | Files |", page)
        self.assertIn("\n## D\n", page)
        self.assertNotIn("| Engine |", page)
        self.assertNotIn(" -- ", page)
        row = next(line for line in page.splitlines() if line.startswith("| [DuckStation]"))
        self.assertIn(f"[{siterender.system_name('sony-playstation')}]", row)
        self.assertIn("(../systems/sony.md#playstation)", row)
        self.assertNotIn("sony-playstation |", row)


if __name__ == "__main__":
    unittest.main()
