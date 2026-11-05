"""System pages and file cards.

The DS section opened on five DSi files, the Game Boy Advance line printed
BizHawk's file name where eight setups write another, the Neo Geo section
opened on a file one emulator reads, no arcade card said which release its
set matches, console headings carried an icon on 15 % of them, arcade boards
sat under "Consoles and computers", and every system page shared one card.
"""

from __future__ import annotations

import re
import sys
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site as gs  # noqa: E402
import make_og_cards  # noqa: E402

DIST = REPO_ROOT / "website" / "dist"
TMP = REPO_ROOT / "tmp"


def _file(name: str, char: str, path: str) -> dict:
    return {"name": name, "sha1": char * 40, "md5": char * 32, "size": 4096, "path": path}


def _consumers(
    readers: dict[str, list[tuple[str, dict]]],
    db_files: list[dict] = (),
    destinations: dict[str, dict[str, set[str]]] | None = None,
) -> types.SimpleNamespace:
    """Consumers where each sha1 is read by the given (emulator, entry)."""
    files_of: dict[str, list] = {}
    entries: dict[str, dict[str, int]] = {}
    emulators: dict[str, set[str]] = {}
    for sha1, read_by in readers.items():
        for emulator, entry in read_by:
            files_of.setdefault(emulator, []).append(entry)
            entries.setdefault(sha1, {})[emulator] = len(files_of[emulator]) - 1
            emulators.setdefault(sha1, set()).add(emulator)
    return types.SimpleNamespace(
        platforms={}, emulators=emulators, emulator_entries=entries,
        emulator_files=files_of, installed={}, platform_systems={},
        platform_destinations=destinations or {},
        _db={"files": {f["sha1"]: f for f in db_files}},
    )


DS = ("Nintendo", "Nintendo DS")


class TheSectionStartsWithItsOwnConsole(unittest.TestCase):
    """A file filed with the DS but read for the DSi is the DSi's."""

    def setUp(self) -> None:
        folder = "bios/Nintendo/Nintendo DS"
        self.files = [_file("NDS_Bios7.bin", "7", f"{folder}/NDS_Bios7.bin"),
                      _file("NDS_Bios9.bin", "9", f"{folder}/NDS_Bios9.bin"),
                      _file("dsi_bios7.bin", "d", f"{folder}/dsi_bios7.bin")]
        hle = {"required": False, "hle_fallback": True, "system": "nintendo-ds"}
        self.consumers = _consumers({
            "7" * 40: [("emu-a", {**hle, "name": "bios7.bin"}),
                       ("emu-b", {**hle, "name": "bios7.bin"})],
            "9" * 40: [("emu-a", {**hle, "name": "bios9.bin"})],
            "d" * 40: [("emu-a", {"name": "dsi_bios7.bin", "required": True,
                                  "system": "nintendo-dsi"})],
        })

    def test_no_dsi_file_on_the_ds_line(self) -> None:
        text = "\n".join(gs._start_with(self.files, self.consumers, section=DS))
        self.assertNotIn("dsi", text)

    def test_a_console_its_emulators_run_without_says_so(self) -> None:
        self.assertEqual(gs._start_with(self.files, self.consumers, section=DS), [
            "**No file needed** with emu-a or emu-b. For full accuracy: "
            "[`bios7.bin`](#sha1-777777777777), [`bios9.bin`](#sha1-999999999999).", ""])

    def test_the_dsi_section_names_its_file(self) -> None:
        lines = gs._start_with(self.files, self.consumers, section=("Nintendo", "Nintendo DSi"))
        self.assertEqual(lines, ["**Start with**: [`dsi_bios7.bin`](#sha1-dddddddddddd).", ""])

    def test_more_than_three_emulators_are_counted(self) -> None:
        hle = {"required": False, "hle_fallback": True, "system": "nintendo-ds"}
        consumers = _consumers({"7" * 40: [(f"emu-{n}", hle) for n in "abcd"]})
        self.assertEqual(gs._start_with(self.files[:1], consumers, section=DS)[0],
                         "**No file needed**: none of its 4 emulators requires one. "
                         "For full accuracy: [`NDS_Bios7.bin`](#sha1-777777777777).")

    def test_a_shipped_file_is_no_start(self) -> None:
        consumers = _consumers({"7" * 40: [("emu-a", {"required": True, "bundled": True,
                                                      "system": "nintendo-ds"})]})
        self.assertEqual(gs._start_with(self.files[:1], consumers, section=DS), [])


class TheNameSetupsWrite(unittest.TestCase):
    def test_most_setups_win_over_the_collection_name(self) -> None:
        f = _file("GBA_bios.rom", "a", "bios/Nintendo/Game Boy Advance/GBA_bios.rom")
        consumers = _consumers(
            {"a" * 40: [("emu-a", {"name": "GBA_bios.rom", "required": True,
                                   "system": "nintendo-gba"})]},
            destinations={"a" * 40: {"p1": {"gba_bios.bin"}, "p2": {"bios/gba_bios.bin"},
                                     "p3": {"GBA_bios.rom"}}})
        self.assertEqual(gs._start_with([f], consumers, section=("Nintendo", "Game Boy Advance")),
                         ["**Start with**: [`gba_bios.bin`](#sha1-aaaaaaaaaaaa).", ""])

    def test_no_setup_then_the_emulators_name(self) -> None:
        f = _file("x.rom", "b", "bios/Nintendo/Game Boy Advance/x.rom")
        consumers = _consumers({"b" * 40: [("emu-a", {"name": "gba_bios.bin", "required": True})]})
        self.assertEqual(gs._setup_name(f, consumers, [("emu-a", {"name": "gba_bios.bin"})]),
                         "gba_bios.bin")


class ArcadeSetsAreNamedWhereverFiled(unittest.TestCase):
    """The Neo Geo BIOS is under Arcade: the Neo Geo section named
    aes.zip, read by one emulator, and never neogeo.zip."""

    def setUp(self) -> None:
        self.aes = _file("aes.zip", "1", "bios/SNK/Neo Geo/aes.zip")
        neogeo = _file("neogeo.zip", "2", "bios/Arcade/Arcade/neogeo.zip")
        mega_cd = _file("bios_CD_U.bin", "3", "bios/Sega/Mega CD/bios_CD_U.bin")
        shader = _file("tfx.glsl", "4", "bios/Other/emu/tfx.glsl")
        mvs = {"required": True, "system": "snk-neogeo-mvs"}
        self.consumers = _consumers({
            "1" * 40: [("geolith", {"name": "aes.zip", "required": True,
                                    "system": "snk-neogeo-aes"})],
            "2" * 40: [(f"mame{n}", {**mvs, "name": "neogeo.zip"}) for n in range(3)],
            "3" * 40: [("bizhawk", {"name": "bios_CD_U.bin", "required": True,
                                    "system": "snk-neogeo-mvs"})],
            "4" * 40: [("emu", {"name": "tfx.glsl", "required": True,
                                "system": "snk-neogeo-mvs"})],
        }, db_files=[self.aes, neogeo, mega_cd, shader])

    def test_the_file_most_emulators_read_leads_and_the_arcade_set_is_linked(self) -> None:
        lines = gs._start_with([self.aes], self.consumers, section=("SNK", "Neo Geo"))
        link = f"[`neogeo.zip`](/retrobios/files/?sha1={'2' * 40})"
        self.assertEqual(lines[0], f"**Start with** {link}. Keep it zipped. "
                                   "mame0, mame1 and mame2 read it.")
        self.assertIn("Geolith reads [`aes.zip`](#sha1-111111111111) instead.", lines)

    def test_another_consoles_file_or_an_emulators_folder_is_left_out(self) -> None:
        text = "\n".join(gs._start_with([self.aes], self.consumers, section=("SNK", "Neo Geo")))
        self.assertNotIn("bios_CD_U.bin", text)
        self.assertNotIn("tfx.glsl", text)

    def test_the_card_read_by_most_emulators_comes_first(self) -> None:
        one = _file("aes.zip", "1", "bios/SNK/Neo Geo/aes.zip")
        many = _file("sp-s3.sp1", "5", "bios/SNK/Neo Geo/sp-s3.sp1")
        consumers = _consumers({
            "1" * 40: [("geolith", {"required": True})],
            "5" * 40: [(f"emu{n}", {"required": True}) for n in range(3)],
        })
        cards = gs._console_cards("SNK", [one, many], consumers, set())
        self.assertIn("sp-s3.sp1", cards[0][1][2])

    def test_a_long_list_names_the_first_files(self) -> None:
        files = [_file(f"rom{i}.bin", "abcdefgh"[i], f"bios/SNK/Neo Geo/rom{i}.bin")
                 for i in range(8)]
        consumers = _consumers({f["sha1"]: [("emu", {"required": True})] for f in files})
        self.assertEqual(gs._start_with(files, consumers, first_below=False)[0],
                         "**Start with**: [`rom0.bin`](#sha1-aaaaaaaaaaaa), [`rom1.bin`](#sha1-bbbbbbbbbbbb), "
                         "[`rom2.bin`](#sha1-cccccccccccc) and 5 more files.")


class CardsSayWhichReleaseTheSetMatches(unittest.TestCase):
    def setUp(self) -> None:
        TMP.mkdir(exist_ok=True)
        self.path = TMP / "r3_systems_set.zip"
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("sp-s2.sp1", b"bios")
        crc = f"{zipfile.ZipFile(self.path).infolist()[0].CRC:08x}"
        self.releases = {"set.zip": [
            ((("sp-s2.sp1", crc),), "mame", [(0, "0.190"), (1, "0.195"), (4, "0.220")]),
            ((("sp-s2.sp1", crc),), "fbneo", [(2, "1.0.0.03"), (7, "1.0.0.03")]),
            ((("other.bin", "00000000"),), "mame", [(9, "0.289")]),
        ]}

    def tearDown(self) -> None:
        self.path.unlink(missing_ok=True)

    def card(self) -> str:
        f = {"name": "set.zip", "sha1": "e" * 40, "md5": "e" * 32, "size": 4,
             "path": str(self.path)}
        with mock.patch.object(gs, "_romset_releases", return_value=self.releases):
            return "\n".join(gs._system_file_card(f, _consumers({})))

    def test_the_matching_releases_as_runs(self) -> None:
        self.assertIn("<dt>Romset</dt><dd>Same contents as MAME 0.190 to 0.195, 0.220 and "
                      "FBNeo 1.0.0.03</dd>", self.card())

    def test_no_match_counts_what_is_missing(self) -> None:
        self.releases["set.zip"] = self.releases["set.zip"][2:]
        self.assertIn("<dd>No match: missing 1 ROM of MAME 0.289</dd>", self.card())

    def test_no_recipe_no_line(self) -> None:
        self.releases = {}
        self.assertNotIn("Romset", self.card())

    def test_the_snapshots_cover_mame_and_fbneo(self) -> None:
        coverage = gs._romset_coverage()
        self.assertRegex(coverage, r"^MAME 0\.\d+ to 0\.\d+ or FBNeo [\d.]+$")

    def test_a_page_of_sets_links_the_version_answer(self) -> None:
        f = {"name": "set.zip", "sha1": "e" * 40, "path": "bios/SNK/Neo Geo/set.zip"}
        with mock.patch.object(gs, "_romset_releases", return_value=self.releases):
            page = gs.generate_system_page("SNK", {"Neo Geo": [f]}, _consumers({}))
        self.assertIn("MAME and FBNeo sets must match the emulator's version. [Which version "
                      f"each core reads]({gs.ROMSET_FAQ}).", page)
        anchor = gs.ROMSET_FAQ.split("#")[1]
        faq = (REPO_ROOT / "wiki" / "technical-faq.md").read_text(encoding="utf-8")
        self.assertIn("## Which MAME version do the arcade BIOS sets match?", faq)
        self.assertEqual(anchor, "which-mame-version-do-the-arcade-bios-sets-match")


class ArcadeIsItsOwnGroup(unittest.TestCase):
    def test_arcade_rows_under_arcade(self) -> None:
        f = {"name": "a.bin", "sha1": "a" * 40, "path": "bios/x/a.bin"}
        index = gs.generate_systems_index({"Arcade": {"MAME": [f]}, "Sony": {"PlayStation": [f]}})
        arcade = index.index("## Arcade")
        self.assertLess(index.index("## Consoles and computers"), arcade)
        self.assertGreater(index.index("[MAME]"), arcade)
        self.assertLess(index.index("[Sony PlayStation]"), arcade)


class EachManufacturerHasItsCard(unittest.TestCase):
    def test_a_tagline_holds_three_lines_and_counts_the_rest(self) -> None:
        names = [f"Console number {n}" for n in range(40)]
        text = make_og_cards.consoles_tagline(names)
        self.assertRegex(text, r" and \d+ more$")
        lines = make_og_cards.wrap(text, make_og_cards.TAGLINE_WIDTH, make_og_cards.TAGLINE_SIZE)
        self.assertLessEqual(len(lines), make_og_cards.TAGLINE_LINES)
        self.assertEqual(make_og_cards.consoles_tagline(["Saturn", "Dreamcast"]),
                         "BIOS files for Dreamcast and Saturn")

    def test_every_manufacturer_page_has_a_committed_card(self) -> None:
        cards = make_og_cards.system_cards()
        missing = [key for key in cards
                   if not (REPO_ROOT / "docs_assets" / "og" / f"{key}.png").is_file()]
        self.assertEqual(missing, [], "run python scripts/make_og_cards.py --only systems")
        # A card left behind by a page that went: oric.png outlived its page.
        committed = (REPO_ROOT / "docs_assets" / "og" / "systems").glob("*.png")
        stale = sorted(f"systems/{path.stem}" for path in committed
                       if f"systems/{path.stem}" not in cards)
        self.assertEqual(stale, [])


@unittest.skipUnless((DIST / "systems" / "nintendo" / "index.html").is_file(), "site not built")
class TheBuiltPages(unittest.TestCase):
    def test_no_console_heading_carries_an_icon(self) -> None:
        with_icon = [path.relative_to(DIST).as_posix() for path in DIST.glob("systems/**/index.html")
                     if re.search(r"<h2[^>]*>(?:(?!</h2>).)*<img", path.read_text(encoding="utf-8"), re.S)]
        self.assertEqual(with_icon, [])

    def test_the_ds_section_names_no_dsi_file(self) -> None:
        page = (DIST / "systems" / "nintendo" / "index.html").read_text(encoding="utf-8")
        start = page.index('id="nintendo-ds"')
        section = page[start:page.index('id="nintendo-dsi"')]
        # The section may have moved to a page of its own: no card follows.
        opening = section.split('class="rb-sys-file"')[0]
        self.assertRegex(opening, r"No file needed|Start with")
        self.assertNotRegex(opening.casefold(), r"dsi_|bios7i|bios9i")

    def test_the_gba_line_prints_the_setups_name(self) -> None:
        page = (DIST / "systems" / "nintendo" / "index.html").read_text(encoding="utf-8")
        section = page[page.index('id="game-boy-advance"'):page.index('id="game-boy-color"')]
        self.assertRegex(section[:section.index("class=\"rb-sys-file\"")], r"<code[^>]*>gba_bios.bin</code>")

    def test_the_neo_geo_section_opens_on_the_neo_geo_bios(self) -> None:
        page = (DIST / "systems" / "snk" / "index.html").read_text(encoding="utf-8")
        section = page[page.index('id="neo-geo"'):]
        opening = section[:section.index('class="rb-sys-file"')]
        self.assertRegex(opening, r"<code[^>]*>neogeo.zip</code>")
        self.assertIn("Which version each core reads", page)

    def test_the_nintendo_summary_holds_its_budget(self) -> None:
        size = (DIST / "systems" / "nintendo" / "index.html").stat().st_size
        self.assertLess(size, 540_000)


class InstallBoxesCountTowardTheSummary(unittest.TestCase):
    """Ten install boxes were 295 KB of the 583 KB Nintendo page: the
    weights that keep a section on its maker's summary counted cards only,
    and the page passed its 600 KB budget once the DS files were refiled."""

    def setUp(self) -> None:
        import siterender

        siterender.reset_console_pages()
        self.addCleanup(siterender.reset_console_pages)
        self.consoles = {
            name: [_file(f"{name}{i}.bin", "0123456789"[index * 3 + i],
                         f"bios/Maker/{name}/{name}{i}.bin") for i in range(3)]
            for index, name in enumerate(("Boxed", "Heavy", "Light"))
        }

    def pages(self, box: int) -> dict:
        def install(console: str, _declared: list) -> list[str]:
            return ["x" * box] if console == "Boxed" else []

        with mock.patch.object(gs, "_console_install_block", side_effect=install), \
                mock.patch.object(gs, "SYSTEM_SUMMARY_HTML", 50_000):
            return gs.system_pages("Maker", self.consoles, _consumers({}), budget=30_000)

    def test_a_section_with_a_heavy_install_box_moves(self) -> None:
        pages = self.pages(20_000)
        self.assertIn("maker-boxed", pages)
        self.assertNotIn("maker-light", pages)

    def test_a_light_install_box_stays(self) -> None:
        self.assertEqual(list(self.pages(10)), ["maker"])
