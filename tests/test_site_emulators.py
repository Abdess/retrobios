"""Emulator pages.

DuckStation's page opened on "It reads 105 files, 3 of them required" and
read as "get all three", its three BIOS were cards 12 to 14 under one
heading, its header said "Official ports" and "duckstation, Duckstation",
and every system was an id ("sony-playstation").

NetherSX2 counted three interface fonts its app ships among "4 required"
files and opened its file list on the project's counts. AetherSX2's summary
held an empty Region column that pushed Required off a phone. No MAME or
FinalBurn page said which romset its sets must match. DuckStation's page was
59 phone screens of optional cards, and MAME's index put 13,300 elements on
one page.

AetherSX2's page offered a command that answered "No supported platform
detected" and a file to get by one name, while the app reads any PS2 BIOS
by its contents. FinalBurn Neo and MAME 2003-Plus named no romset under
their intro. MAME's card pages and the data directory pages did not say
where they sit. melonDS marked its DSi files "required" above its DS files.
The `00_example` template was listed as an emulator.

61 profiles cite the folder their app reads its data from (data_root) and
no page printed it: AetherSX2's step said "inside the app's own data
folder", ten pages named the field itself, and every install block offered
Linux, Windows and Android commands, for MAME4droid an Android-only app.
215 pages printed `--emulator X` for a name no published manifest takes.
"""
from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import re
import sys
import unittest
from pathlib import Path
import yaml
import tempfile
import importlib.util
import json

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site as gs  # noqa: E402
import siterender  # noqa: E402
import validate_site  # noqa: E402


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
            "It picks the BIOS for the game's region: scph5500.bin (Japan), "
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


DIST = REPO_ROOT / "website" / "dist"


def _emulator_page(name: str, profile: dict | None = None) -> str:
    return gs.generate_emulator_page(name, profile or _profile(name), EMPTY_DB, None, set())


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
        page = _emulator_page("mame2003")
        self.assertIn(f"| Romset | [MAME 0.78]({gs.ROMSET_FAQ}) |", page)
        self.assertNotIn("| MAME version |", _emulator_page("mame2016"))
        line = page.index("Its BIOS and game sets must come from the MAME 0.78 romset.")
        self.assertLess(line, page.index("About this profile"))
        self.assertIn(f"[Which version each core reads]({gs.ROMSET_FAQ})", page)

    def test_the_faq_answer_exists(self):
        faq = (REPO_ROOT / "wiki" / "technical-faq.md").read_text(encoding="utf-8")
        self.assertIn("## Which MAME version do the arcade BIOS sets match?", faq)

    def test_no_line_without_bios_zips(self):
        self.assertNotIn("must come from the", _emulator_page("duckstation"))


class WhatTheAppShipsIsNoFileToGet(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = _profile("nethersx2")
        self.page = _emulator_page("nethersx2", self.profile)

    def test_the_badge(self):
        font = next(f for f in self.profile["files"] if f["name"] == "Roboto-Regular.ttf")
        badges = " ".join(gs._file_badges(font, False))
        self.assertIn(">comes with the app</span>", badges)
        self.assertNotIn(">required</span>", badges)
        self.assertNotIn(">missing</span>", badges)
        # Narrowed to one build, the entry is that build's alone, as verify
        # and the pack read it: EightyOne installs its ROMs, and the libretro
        # core, which embeds them, reads no entry. Nothing to fetch.
        dual = " ".join(gs._file_badges({"name": "a", "bundled": True, "mode": "standalone",
                                         "required": True}, False))
        self.assertNotIn(">required</span>", dual)
        self.assertNotIn(">missing</span>", dual)
        self.assertIn("installed with the standalone emulator", dual)
        rom = next(f for f in _profile("81")["files"] if f["name"] == "jupiterace.rom")
        self.assertTrue(gs.comes_with_app(rom))

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
        page = _emulator_page("x", {"type": "standalone", "files": files})
        self.assertNotIn("| File |", page)
        self.assertNotIn(f"<summary>{gs.EMULATOR_TABLE_MIN} files</summary>", page)
        self.assertEqual(page.count('<h3 id="file-'), len(files))
        required = page[page.index("## Required"):page.index("## Optional")]
        self.assertEqual(required.count('<h3 id="file-'), 1)
        self.assertIn('class="rb-entries"', required)

    def test_a_few_cards_stay_open(self):
        page = _emulator_page("x", {"type": "standalone", "files": _files(2)})
        self.assertNotIn("<summary>2 files</summary>", page)

    def test_the_profile_card_folds(self):
        page = _emulator_page("duckstation")
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


def _pages(name: str, profile: dict | None = None) -> dict[str, str]:
    return gs.emulator_pages(name, profile or _profile(name), EMPTY_DB, None, set())


def _front(page: str) -> dict:
    assert page.startswith("---\n"), page[:80]
    return yaml.safe_load(page[4:page.index("\n---\n", 4)])


class AnAppThatReadsAnyBios(unittest.TestCase):
    def setUp(self) -> None:
        self.page = _pages("aethersx2")["aethersx2"]

    def test_the_intro_says_what_to_do(self):
        intro = self.page[self.page.index("# AetherSX2"):self.page.index("About this profile")]
        self.assertIn("AetherSX2 needs one Sony PlayStation 2 BIOS file, any region.", intro)
        # The folder itself, per system the app runs on.
        self.assertRegex(intro, r"\n1\. .+\n2\. Put it in this folder:")
        self.assertIn("`Android/data/xyz.aethersx2.android/files/bios/`", intro)
        self.assertIn("Any file name works. The app reads what the file holds.", intro)
        self.assertNotIn("It reads", intro)

    def test_the_card_names_an_example(self):
        self.assertIn("a Sony PlayStation 2 BIOS (example: <code>ps2-0230a-20080220.bin</code>)",
                      self.page)

    def test_no_command_that_cannot_place_the_file(self):
        # Only through a setup that launches the app, on its
        # device, never as if the app on its own were found.
        install = self.page[self.page.index("Install this emulator's files"):]
        install = install[:install.index("</details>")]
        self.assertRegex(install, r"With [^:]+: the installer finds")
        # One place to run it, so no tab bar (one tab offers no choice).
        self.assertNotIn("<Tabs", install)
        self.assertIn("curl -fsSL", install)
        nether = _pages("nethersx2")["nethersx2"]
        if "--emulator nethersx2" in nether:
            self.assertIn("With ", nether)

    def test_a_core_keeps_its_command(self):
        # LRPS2 runs in RetroArch, whose BIOS folder the installer finds.
        page = _pages("lrps2")["lrps2"]
        self.assertIn("--emulator lrps2", page)
        self.assertIn("2. Put it in `pcsx2/bios/`, inside the BIOS folder.", page)
        self.assertIn("a Sony PlayStation 2 BIOS, any file name", page)

    def test_only_found_by_content_with_one_bios(self):
        # DuckStation picks the BIOS of the game's region: its intro stays.
        self.assertIsNone(gs.any_name_bios(_profile("duckstation")))
        self.assertIsNone(gs.any_name_bios(_profile("melonds")))
        self.assertIsNotNone(gs.any_name_bios(_profile("pcsx2")))

    def test_the_download_links_the_collection_card(self):
        steps = gs._any_name_steps("X", _profile("aethersx2"),
                                   gs.any_name_bios(_profile("aethersx2")),
                                   "../systems/sony.md#sha1-abc")
        self.assertIn("1. Download [`ps2-0230a-20080220.bin`](../systems/sony.md#sha1-abc).", steps)


class EveryArcadeCoreNamesItsRomset(unittest.TestCase):
    def test_finalburn_and_mame_2003_plus(self):
        for name, romset in (("fbneo", f"FinalBurn Neo {_profile('fbneo')['core_version']}"),
                             ("mame2003_plus", "MAME 0.78 (plus backports)")):
            page = _pages(name)[name]
            line = page.index(f"Its BIOS and game sets must come from the {romset} romset.")
            self.assertLess(line, page.index("About this profile"), name)


class PartsKnowWhereTheySit(unittest.TestCase):
    def test_emulator_card_parts(self):
        pages = _pages("mame")
        parts = sorted((stem for stem in pages if stem.startswith("mame-files-")),
                       key=lambda stem: int(stem.rsplit("-", 1)[1]))
        self.assertGreater(len(parts), 2)
        for index, stem in enumerate(parts):
            front = _front(pages[stem])
            self.assertEqual(front["parent"], {"label": "MAME", "link": "mame.md"})
            self.assertEqual(front["searchWeight"], 0.5)
            self.assertEqual(front["prev"]["link"],
                             f"{parts[index - 1]}.md" if index else "mame.md")
            if index + 1 < len(parts):
                self.assertEqual(front["next"]["link"], f"{parts[index + 1]}.md")
            else:
                self.assertIs(front["next"], False)

    def test_data_directory_parts(self):
        ref = "x-sys"
        members = {f"f{i:05d}": {"size": 1, "sha1": f"{i:040x}"}
                   for i in range(gs.DATA_TREE_ROWS_PER_PAGE * 2 + 1)}
        gs._DATA_MEMBERS[ref] = members
        gs._DATA_READERS[ref] = [("x", "X")]
        try:
            pages = gs.data_tree_pages(ref, members)
            self.assertEqual(len(pages), 3)
            middle = _front(gs._data_tree_page(ref, {}, pages, 1))
        finally:
            del gs._DATA_MEMBERS[ref], gs._DATA_READERS[ref]
        self.assertEqual(middle["parent"], {"label": "X", "link": "x.md"})
        self.assertEqual(middle["prev"]["link"], f"{pages[0][0]}.md")
        self.assertEqual(middle["next"]["link"], f"{pages[2][0]}.md")
        self.assertEqual(middle["search"], "exclude")


class ARequiredFileSaysForWhichSystem(unittest.TestCase):
    def test_melonds_dsi_files(self):
        page = _pages("melonds")["melonds"]
        row = page[page.index('id="file-dsi-nand-bin"'):]
        row = row[:row.index("</tr>")]
        self.assertIn(">required for Nintendo DSi</span>", row)
        self.assertNotIn(">required</span>", page)

    def test_one_system_says_required(self):
        # The section heading says it: the rows under it repeat nothing.
        page = _pages("aethersx2")["aethersx2"]
        self.assertIn("## Required", page)
        self.assertNotIn("required for", page)


class TheTemplateIsNoEmulator(unittest.TestCase):
    def test_off_the_index_and_the_search(self):
        profiles = {"00_example": _profile("00_example"), "melonds": _profile("melonds")}
        index = gs.generate_emulators_index(profiles)
        self.assertNotIn("00_example", index)
        self.assertIn("melonds.md", index)
        # A test profile gets no page at all (generate_site's public_profiles).
        self.assertEqual(_profile("00_example")["role"], "test")


@unittest.skipUnless((DIST / "emulators" / "aethersx2" / "index.html").is_file(), "site not built")
class TheBuiltEmulatorPages(unittest.TestCase):
    def _html(self, path: str) -> str:
        return (DIST / path / "index.html").read_text(encoding="utf-8")

    def test_aethersx2_downloads_from_the_collection(self):
        page = self._html("emulators/aethersx2")
        self.assertRegex(page, r'Download <a href="[^"]*/systems/sony[^"]*#sha1-[0-9a-f]{12}"')
        # The command only where a setup launches AetherSX2 itself (KNULLI,
        # ROCKNIX dropped the package in 20261101), never through RetroArch's
        # folder, which the app never reads.
        self.assertIn("With KNULLI:", page)
        self.assertNotIn("RetroArch", page.split("Install this emulator", 1)[1].split("</details>", 1)[0])

    def test_the_index_leaves_the_template_out(self):
        # 00_example has `role: test`: no page, no index row.
        self.assertNotIn("00_example", self._html("emulators"))
        self.assertIn('data-pagefind-body', self._html("emulators/melonds"))
        self.assertFalse((DIST / "emulators" / "00_example").exists())

    def test_mame_parts_have_a_parent_crumb(self):
        page = self._html("emulators/mame-files-3")
        crumbs = re.search(r'<nav[^>]*rb-breadcrumbs.*?</nav>', page, re.S)
        self.assertIsNotNone(crumbs)
        self.assertIn(">MAME<", crumbs.group(0))


CONTENT = REPO_ROOT / "website" / "src" / "content" / "docs"
EMULATORS = CONTENT / "emulators"


def _profiles_with_data_root() -> dict[str, dict]:
    found = {}
    for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
        profile = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(profile, dict) and isinstance(profile.get("data_root"), dict):
            found[path.stem] = profile
    return found


def _built_page(name: str) -> str:
    for suffix in (".mdx", ".md"):
        path = EMULATORS / f"{name}{suffix}"
        if path.exists():
            return path.read_text(encoding="utf-8")
    return ""


def _generated() -> bool:
    return EMULATORS.is_dir() and any(EMULATORS.iterdir())


def _install_section(page: str) -> str:
    match = re.search(r"<summary>Install this emulator's files</summary>(.*?)</details>",
                      page, re.S)
    return match[1] if match else ""


def _tab_labels(text: str) -> set[str]:
    return set(re.findall(r'<TabItem label="([^"]+)">', text))


def _entries(profile: dict) -> list[dict]:
    return [f for f in profile.get("files") or [] if isinstance(f, dict)]


def _alternatives(root: str) -> list[str]:
    return [part.strip().rstrip("/") for part in root.split(", else ")]


class FolderOnlyTable(unittest.TestCase):
    """The entries whose joined path is not the app's folder: one table in
    the generator, each row with its reason, and it cannot rot."""

    def test_every_row_names_a_profile_and_entries_that_exist(self) -> None:
        roots = _profiles_with_data_root()
        for profile_name, patterns, keys, reason in gs.FOLDER_ONLY:
            with self.subTest(profile=profile_name, patterns=patterns):
                self.assertIn(profile_name, roots, "no profile with data_root by that name")
                self.assertTrue(reason.strip())
                entries = _entries(roots[profile_name])
                for pattern in patterns:
                    self.assertTrue(
                        any(gs.folder_only_matches(pattern, f) for f in entries),
                        f"{pattern!r} names no entry of {profile_name}")
                self.assertLessEqual(set(keys), set(roots[profile_name]["data_root"]))

    def test_a_listed_entry_is_never_joined_to_the_root(self) -> None:
        roots = _profiles_with_data_root()
        for profile_name, patterns, keys, _reason in gs.FOLDER_ONLY:
            profile = roots[profile_name]
            for entry in _entries(profile):
                if not any(gs.folder_only_matches(p, entry) for p in patterns):
                    continue
                raw = {str(entry.get(k) or "") for k in ("path", "standalone_path")} - {""}
                for key in keys or tuple(profile["data_root"]):
                    with self.subTest(profile=profile_name, entry=entry.get("name"), key=key):
                        self.assertEqual(gs.standalone_place(profile_name, profile, entry, key), "")
                        self.assertEqual(gs.standalone_place(profile_name, profile, entry), "")
                        block = "\n".join(gs.data_folder_block(profile_name, profile))
                        for root in _alternatives(str(profile["data_root"][key]["path"])):
                            for place in raw:
                                self.assertNotIn(f"{root}/{place}", block)

    def test_built_pages_print_no_joined_path_for_a_listed_entry(self) -> None:
        if not _generated():
            self.skipTest("site pages not generated")
        roots = _profiles_with_data_root()
        for profile_name, patterns, keys, _reason in gs.FOLDER_ONLY:
            profile = roots[profile_name]
            pages = [p.read_text(encoding="utf-8")
                     for p in EMULATORS.glob(f"{profile_name}*.md*")]
            for entry in _entries(profile):
                if not any(gs.folder_only_matches(p, entry) for p in patterns):
                    continue
                for key in keys or tuple(profile["data_root"]):
                    for root in _alternatives(str(profile["data_root"][key]["path"])):
                        for place in {entry.get("path"), entry.get("standalone_path")} - {None, ""}:
                            joined = f"{root}/{place}"
                            for text in pages:
                                self.assertNotIn(joined, text, profile_name)


class DataFolderPrinted(unittest.TestCase):
    def test_every_profile_prints_each_of_its_folders(self) -> None:
        if not _generated():
            self.skipTest("site pages not generated")
        for name, profile in _profiles_with_data_root().items():
            if profile.get("type") == "alias" or profile.get("role") == "test":
                continue
            page = _built_page(name)
            with self.subTest(profile=name):
                self.assertIn('id="data-folder"', page)
                for root in profile["data_root"].values():
                    for alternative in _alternatives(str(root["path"])):
                        self.assertIn(alternative, page)

    def test_ryujinx_keys_sit_in_system(self) -> None:
        block = "\n".join(gs.data_folder_block("ryujinx", _profile("ryujinx")))
        self.assertIn("`%APPDATA%/Ryujinx/system/`", block)
        self.assertIn("`~/Library/Application Support/Ryujinx/system/`", block)
        self.assertEqual(_tab_labels(block), {"Windows", "macOS", "Linux"})

    def test_aethersx2_step_names_the_android_folder(self) -> None:
        profile = _profile("aethersx2")
        steps = gs._any_name_steps("AetherSX2", profile, gs.any_name_bios(profile), "", "aethersx2")
        self.assertIn("2. Put it in this folder:", steps)
        self.assertIn("`Android/data/xyz.aethersx2.android/files/bios/`, on the internal storage.",
                      steps)
        self.assertNotIn("app's own data folder", steps)

    def test_one_system_is_a_line_not_a_tab(self) -> None:
        block = "\n".join(gs.data_folder_block("mame4droid", _profile("mame4droid")))
        self.assertTrue(block.startswith("On Android: `Android/data/com.seleuco.mame4droid/files/`"))
        self.assertNotIn("<Tabs", block)

    def test_an_entry_found_by_name_or_shipped_is_not_placed(self) -> None:
        profile = {"type": "standalone", "data_root": {"linux": {"path": "~/x", "source_ref": "a"}}}
        self.assertEqual(gs.standalone_place("x", profile, {"name": "a.bin"}), "")
        self.assertEqual(gs.standalone_place("x", profile, {"name": "a", "path": "a", "bundled": True}),
                         "")
        self.assertEqual(gs.standalone_place("x", profile, {"name": "a", "path": "b/a"}), "b/a")
        dual = {**profile, "type": "standalone + libretro"}
        self.assertEqual(gs.standalone_place("x", dual, {"name": "a", "path": "core/a"}), "")
        self.assertEqual(gs.standalone_place("x", dual, {"name": "a", "path": "c/a",
                                                         "standalone_path": "a"}), "a")

    def test_the_metadata_card_has_a_row_per_system(self) -> None:
        rows = gs._render_metadata_rows(_profile("cxbx-reloaded"))
        self.assertIn("| Data folder (Windows) | `%APPDATA%/Cxbx-Reloaded/` |", rows)
        self.assertFalse(any("Data folder (Linux)" in row for row in rows))

    def test_no_page_names_the_field(self) -> None:
        if not _generated():
            self.skipTest("site pages not generated")
        named = sorted(str(p.relative_to(CONTENT)) for p in CONTENT.rglob("*.md*")
                       if "data_root" in p.read_text(encoding="utf-8")
                       and not p.relative_to(CONTENT).as_posix().startswith("wiki/profiling"))
        self.assertEqual(named, [])


class InstallBlockWhereItWorks(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        spec = importlib.util.spec_from_file_location("install", REPO_ROOT / "install.py")
        cls.install = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.install)
        cls.accepted: dict[str, set[str]] = {}
        for path in sorted((REPO_ROOT / "install").glob("*.json")):
            manifest = json.loads(path.read_text(encoding="utf-8"))
            names = cls.install.emulator_names(manifest, manifest.get("files") or [],
                                               manifest.get("omitted_files") or [])
            for alias, profile in names.items():
                cls.accepted.setdefault(alias, set()).add(profile)

    def test_every_printed_command_names_this_profile_in_a_manifest(self) -> None:
        if not _generated():
            self.skipTest("site pages not generated")
        for path in sorted(EMULATORS.glob("*.md*")):
            text = path.read_text(encoding="utf-8")
            for name in set(re.findall(r"--emulator ([\w.+-]+)", text)):
                with self.subTest(page=path.name, name=name):
                    self.assertIn(path.stem, self.accepted.get(name, set()))

    def test_no_os_tab_outside_the_data_root(self) -> None:
        if not _generated():
            self.skipTest("site pages not generated")
        labels = {key: gs.TERMINALS[key][0] for key in gs.TERMINALS}
        for name, profile in _profiles_with_data_root().items():
            allowed = {labels["device"]}
            for key in profile["data_root"]:
                allowed |= {labels[t] for t in gs._DATA_ROOT_TERMINALS[key]}
            with self.subTest(profile=name):
                self.assertLessEqual(_tab_labels(_install_section(_built_page(name))), allowed)

    def test_android_only_app_gets_no_desktop_command(self) -> None:
        self.assertEqual(gs._install_block("mame4droid", _profile("mame4droid")), [])
        command, setups, oses = gs.emulator_install_route("cxbx-reloaded", _profile("cxbx-reloaded"))
        self.assertEqual(oses, ("windows",))

    def test_a_lone_app_is_named_with_the_setup_that_launches_it(self) -> None:
        text = "\n".join(gs._install_block("ryujinx", _profile("ryujinx")))
        self.assertRegex(text, r"With [^:]*EmuDeck[^:]*: the installer finds")
        self.assertNotIn("Android (Termux)", text)
        self.assertNotIn("RetroArch", text)

    def test_a_dual_app_says_what_the_command_fills(self) -> None:
        text = "\n".join(gs._install_block("duckstation", _profile("duckstation")))
        self.assertIn("For DuckStation inside RetroArch, Batocera or another setup.", text)

    def test_no_files_no_command(self) -> None:
        self.assertEqual(gs._install_block("beetle_wswan", _profile("beetle_wswan")), [])

    def test_tabs_follow_the_keys_given(self) -> None:
        tabs = "\n".join(gs.install_commands("--emulator x", oses=("linux", "steamdeck")))
        self.assertEqual(_tab_labels(tabs), {"Linux", "Steam Deck"})
        self.assertIn('syncKey="os"', tabs)
        blocks = "\n".join(gs.install_commands("--emulator x"))
        self.assertIn("Windows (PowerShell):", blocks)


class SmallFixes(unittest.TestCase):
    def test_structured_blocks_closed_below_the_files(self) -> None:
        if not _generated():
            self.skipTest("site pages not generated")
        page = _built_page("cemu")
        self.assertLess(page.index("## Files"), page.index("<summary>Firmware titles</summary>"))
        self.assertNotRegex(page, r"<details[^>]*open>\s*<summary>Firmware titles")

    def test_region_choice_summary(self) -> None:
        lines = gs._emulator_file_summary(_profile("duckstation")["files"])
        self.assertIn("One of 3 is required, for the games' region.", lines[0])
        self.assertNotIn("3 required", lines[0])

    def test_no_emulator_part_says_where_it_sits(self) -> None:
        if not _generated():
            self.skipTest("site pages not generated")
        parts = sorted(EMULATORS.glob("*-files-*.md*"))
        if not parts:
            self.skipTest("no split emulator page")
        said = [p.name for p in parts if "\nPart of [" in p.read_text(encoding="utf-8")]
        self.assertEqual(said, [])


class AnEmulatorPageNamesItsSetups(unittest.TestCase):
    """emulators/handy named no setup that runs Handy: its lynxboot.img card
    names the setups whose own list holds it, not EmuDeck, ROCKNIX and
    NextUI, which pack it for the core."""

    def test_setups_come_from_the_core_resolution(self):
        coverages = {
            "b": {"config": {"cores": ["handy"]}},
            "a": {"config": {"cores": ["handy", "other"]}},
            "c": {"config": {"cores": ["other"]}},
        }
        profiles = {"handy": {"type": "libretro"}, "other": {"type": "libretro"}}
        self.assertEqual(gs.emulator_setups(coverages, profiles)["handy"], ["a", "b"])

    def test_the_page_names_them(self):
        from tests import sitepages  # noqa: PLC0415

        sitepages.require()
        text = sitepages.page("emulators/handy.md").read_text(encoding="utf-8")
        row = next(line for line in text.splitlines() if line.startswith("| Run by |"))
        for setup in ("emudeck", "rocknix", "nextui", "retroarch"):
            self.assertIn(f"/platforms/{setup}/", row)
        # Setup names on every emulator page outranked the setup's own page.
        self.assertIn("data-pagefind-ignore", row)


class SizesTheCodeComparesAreExact(unittest.TestCase):
    """raze validates DUKE3D.GRP by size, and its page showed 42.3 MB for
    44,356,548 and 44,348,015 bytes alike."""

    def test_a_validated_size_carries_its_bytes(self):
        profile = {"emulator": "x", "type": "libretro", "systems": ["sony-playstation"], "files": [
            {"name": "DUKE3D.GRP", "size": 44348015, "validation": ["size", "crc32"]},
            {"name": "other.bin", "size": 44356548},
            {"name": "built.bin", "size": 2304, "validation": {"core": ["size"]}},
        ]}
        page = _page("x", profile)
        self.assertIn("Size: 42.3 MB (44,348,015 bytes)", page)
        self.assertIn("Size: 2.2 KB (2,304 bytes)", page)
        self.assertNotIn("44,356,548", page)


class ADataDirectoryNamesAFetchableOrigin(unittest.TestCase):
    """pcee2's page linked github.com/PCSX2/pcsx2/archive/{version}.tar.gz,
    a 404, and buildbot zips showed `Revision: master (2047720058)`: a branch
    that means nothing for a buildbot URL and the server's ETag."""

    def test_the_url_is_substituted_and_a_commit_is_linked(self):
        entry = {"source_url": "https://github.com/PCSX2/pcsx2/archive/{version}.tar.gz",
                 "version": "6db638dc0373769b4c5d5b5dd7ed6da641b9a18e"}
        lines = gs.data_directory_origin(entry, {"sha": entry["version"],
                                                 "version": entry["version"]})
        self.assertEqual(lines[0], "Fetched from <https://github.com/PCSX2/pcsx2/archive/"
                                   "6db638dc0373769b4c5d5b5dd7ed6da641b9a18e.tar.gz>")
        self.assertIn("(https://github.com/PCSX2/pcsx2/commit/6db638dc0373769b4c5d5b5dd7ed6da641b9a18e)",
                      lines[1])
        self.assertNotIn("{version}", " ".join(lines))

    def test_an_etag_is_no_revision(self):
        entry = {"source_url": "https://buildbot.libretro.com/assets/system/Dolphin.zip"}
        lines = gs.data_directory_origin(entry, {"sha": '"2047720058"', "version": "master"})
        self.assertEqual(lines, ["Fetched from <https://buildbot.libretro.com/assets/system/Dolphin.zip>"])

    def test_every_registered_url_resolves(self):
        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_data_dirs.yml").read_text())
        for ref, entry in (registry.get("data_directories") or registry).items():
            if isinstance(entry, dict):
                with self.subTest(ref=ref):
                    self.assertNotIn("{", " ".join(gs.data_directory_origin(entry, {})))


if __name__ == "__main__":
    unittest.main()
