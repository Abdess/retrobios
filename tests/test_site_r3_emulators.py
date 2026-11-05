"""Emulator pages say what to get, and fit.

NetherSX2 counted three interface fonts its app ships among "4 required"
files and opened its file list on the project's counts. AetherSX2's summary
held an empty Region column that pushed Required off a phone. No MAME or
FinalBurn page said which romset its sets must match. DuckStation's page was
59 phone screens of optional cards, and MAME's index put 13,300 elements on
one page.
"""

from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site as gs  # noqa: E402
import validate_site  # noqa: E402

EMPTY_DB = {"files": {}, "indexes": {"by_name": {}}}
DIST = REPO_ROOT / "website" / "dist"


def _profile(name: str) -> dict:
    return yaml.safe_load((REPO_ROOT / "emulators" / f"{name}.yml").read_text(encoding="utf-8"))


def _page(name: str, profile: dict | None = None) -> str:
    return gs.generate_emulator_page(name, profile or _profile(name), EMPTY_DB, None, set())


def _files(count: int, **fields: object) -> list[dict]:
    return [{"name": f"f{i:03d}.bin", **fields} for i in range(count)]


class EachArcadePageNamesItsRomset(unittest.TestCase):
    def test_the_romset_by_profile(self):
        self.assertEqual(gs.emulator_romset(_profile("mame2003")), "MAME 0.78")
        # The app's version is 1.38.1, its MAME is 0.289.
        self.assertEqual(gs.emulator_romset(_profile("mame4droid-2024")), "MAME 0.289")
        self.assertEqual(gs.emulator_romset(_profile("mame2003_plus")), "MAME 0.78 (plus backports)")
        self.assertTrue(gs.emulator_romset(_profile("fbneo")).startswith("FinalBurn Neo "))
        self.assertTrue(gs.emulator_romset(_profile("fbalpha2012")).startswith("FB Alpha "))
        self.assertEqual(gs.emulator_romset(_profile("duckstation")), "")
        # HBMAME publishes no MAME release number.
        self.assertEqual(gs.emulator_romset(_profile("hbmame")), "")

    def test_a_row_and_a_line_under_the_intro(self):
        page = _page("mame2003")
        self.assertIn(f"| Romset | [MAME 0.78]({gs.ROMSET_FAQ}) |", page)
        self.assertNotIn("| MAME version |", _page("mame2016"))
        line = page.index("Its BIOS and game sets must come from the MAME 0.78 romset.")
        self.assertLess(line, page.index("About this profile"))
        self.assertIn(f"[Which version each core reads]({gs.ROMSET_FAQ})", page)

    def test_the_faq_answer_exists(self):
        faq = (REPO_ROOT / "wiki" / "technical-faq.md").read_text(encoding="utf-8")
        self.assertIn("## Which MAME version do the arcade BIOS sets match?", faq)

    def test_no_line_without_bios_zips(self):
        self.assertNotIn("must come from the", _page("duckstation"))


class WhatTheAppShipsIsNoFileToGet(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = _profile("nethersx2")
        self.page = _page("nethersx2", self.profile)

    def test_the_badge(self):
        font = next(f for f in self.profile["files"] if f["name"] == "Roboto-Regular.ttf")
        badges = " ".join(gs._file_badges(font, False))
        self.assertIn(">comes with the app</span>", badges)
        self.assertNotIn(">required</span>", badges)
        self.assertNotIn(">missing</span>", badges)
        # Installed by one build only: the other still reads it from the folder.
        dual = " ".join(gs._file_badges({"name": "a", "bundled": True, "mode": "standalone",
                                         "required": True}, False))
        self.assertIn(">required</span>", dual)
        self.assertIn("installed with the standalone emulator", dual)

    def test_counts_leave_them_out(self):
        shipped = sum(1 for f in self.profile["files"] if gs.comes_with_app(f))
        self.assertGreater(shipped, 0)
        summary = self.page[self.page.index("## Files"):]
        self.assertIn(f"{shipped} more files come with the app.", summary)
        self.assertIn(": 1 required,", summary)
        # Found by content: one BIOS of any name, said as steps.
        self.assertIn("NetherSX2 needs one Sony PlayStation 2 BIOS file, any region.", self.page)

    def test_their_own_section_after_the_others(self):
        heads = re.findall(r"^## (.+)$", self.page, re.M)
        self.assertEqual(heads[heads.index("Files") + 1:heads.index("Files") + 3],
                         ["Required", "Optional"])
        self.assertIn("Comes with the app", heads)
        section = self.page[self.page.index("## Required"):self.page.index("## Optional")]
        self.assertNotIn("Roboto-Regular.ttf", section)

    def test_the_collection_counts_go_under_the_summary(self):
        held = self.page.index("<p><small>In this collection:")
        self.assertLess(held, self.page.index("## Required"))
        self.assertNotIn("in repo", self.page[self.page.index("## Files"):held])

    def test_the_folder_is_the_apps_own(self):
        self.assertIn("| BIOS directory | `bios/`, inside the app's own data folder |", self.page)


class TheSummaryTableFitsItsContent(unittest.TestCase):
    def test_an_empty_region_column_goes(self):
        rows = gs._summary_table(_files(3, md5="ab" * 16), [0, 1, 2], lambda _i, s: s)
        self.assertNotIn("Region", rows[0])

    def test_a_constant_required_column_goes(self):
        rows = gs._summary_table(_files(3, required=True), [0, 1, 2], lambda _i, s: s)
        self.assertEqual(rows[0], "| File |")

    def test_hashes_are_short_with_the_whole_value_in_the_title(self):
        md5 = "0123456789abcdef" * 2
        cell = gs._hash_short({"md5": md5})
        self.assertEqual(cell, f'MD5 <code title="{md5}">{md5[:12]}</code>')

    def test_the_split_index_holds_each_id_on_its_link(self):
        files = _files(gs.EMULATOR_CARDS_PER_PAGE + 1, category="bios_zip")
        main = gs.emulator_pages("big", {"emulator": "Big", "type": "standalone",
                                         "files": files}, {"files": {}})["big"]
        anchor = gs.emulator_file_anchors(files)[0]
        self.assertIn(f'<a id="{anchor}" href="/retrobios/emulators/big-files-1/#{anchor}">', main)
        self.assertNotIn(f'<span id="{anchor}"></span>', main)


class LongPagesFold(unittest.TestCase):
    def test_each_entry_is_listed_once_as_a_row(self):
        files = _files(gs.EMULATOR_TABLE_MIN) + [{"name": "req.bin", "required": True}]
        page = _page("x", {"type": "standalone", "files": files})
        self.assertNotIn("| File |", page)
        self.assertNotIn(f"<summary>{gs.EMULATOR_TABLE_MIN} files</summary>", page)
        self.assertEqual(page.count('<h3 id="file-'), len(files))
        required = page[page.index("## Required"):page.index("## Optional")]
        self.assertEqual(required.count('<h3 id="file-'), 1)
        self.assertIn('class="rb-entries"', required)

    def test_a_few_cards_stay_open(self):
        page = _page("x", {"type": "standalone", "files": _files(2)})
        self.assertNotIn("<summary>2 files</summary>", page)

    def test_the_profile_card_folds(self):
        page = _page("duckstation")
        start = page.index("<summary>About this profile</summary>")
        self.assertLess(start, page.index('<div class="rb-meta-card">'))
        self.assertLess(page.index("| Type |"), page.index("</details>", start))


class DataDirectoryPagesStayOutOfSearch(unittest.TestCase):
    def test_front_matter(self):
        saved = dict(gs._DATA_MEMBERS), dict(gs._DATA_READERS)
        self.addCleanup(lambda: (gs._DATA_MEMBERS.clear(), gs._DATA_MEMBERS.update(saved[0]),
                                 gs._DATA_READERS.clear(), gs._DATA_READERS.update(saved[1])))
        gs._DATA_MEMBERS["dolphin-sys"] = {"a.bin": {"sha1": "a" * 40, "size": 1}}
        gs._DATA_READERS["dolphin-sys"] = [("dolphin-mmjr", "Dolphin MMJR"), ("dolphin", "Dolphin")]
        page = gs._data_tree_page("dolphin-sys", {}, [("data-dolphin-sys", ["a.bin"])], 0)
        front = yaml.safe_load(page.split("---\n")[1])
        self.assertEqual(front["search"], "exclude")
        self.assertEqual(front["parent"], {"label": "Dolphin", "link": "dolphin.md"})

    @unittest.skipUnless((DIST / "emulators" / "data-dolphin-sys").is_dir(), "site not built")
    def test_the_built_page_is_not_indexed(self):
        html = (DIST / "emulators" / "data-dolphin-sys" / "index.html").read_text(encoding="utf-8")
        self.assertNotIn("data-pagefind-body", html)


class AnElementBudget(unittest.TestCase):
    def test_validate_site_reports_a_crowded_page(self):
        self.assertEqual(validate_site.MAX_PAGE_ELEMENTS, 10_000)
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            page = Path(tmp) / "crowded" / "index.html"
            page.parent.mkdir()
            page.write_text("<html><body>" + "<i></i>" * 10_001
                            + "<script>" + "<b>" * 5 + "</script></body></html>")
            issues = validate_site.validate_site(Path(tmp))
        self.assertTrue(any("elements, over the 10,000 budget" in issue for issue in issues))

    @unittest.skipUnless((DIST / "emulators" / "mame" / "index.html").is_file(), "site not built")
    def test_mame_is_under_it(self):
        page = validate_site._parse_page(DIST / "emulators" / "mame" / "index.html")
        self.assertLess(page.elements, validate_site.MAX_PAGE_ELEMENTS)


if __name__ == "__main__":
    unittest.main()

