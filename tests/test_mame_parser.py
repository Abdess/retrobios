"""Tests for MAME source code parser."""

from __future__ import annotations

import os
import tempfile
import unittest

from scripts.scraper.mame_parser import (
    find_bios_root_sets,
    parse_mame_source_tree,
    parse_rom_block,
)

# Standard GAME macro with MACHINE_IS_BIOS_ROOT, multiple ROM entries, BIOS variants
NEOGEO_FIXTURE = """\
ROM_START( neogeo )
    ROM_REGION( 0x100000, "mainbios", 0 )

    ROM_SYSTEM_BIOS( 0, "euro", "Europe MVS (Ver. 2)" )
    ROMX_LOAD( "sp-s2.sp1", 0x00000, 0x020000, CRC(9036d879) SHA1(4f5ed7105b7128794654ce82b51723e16e389543), ROM_BIOS(0) )

    ROM_SYSTEM_BIOS( 1, "japan", "Japan MVS (Ver. 3)" )
    ROMX_LOAD( "vs-bios.rom", 0x00000, 0x020000, CRC(f0e8f27d) SHA1(ecf01bf6b3d6c7e4e0aae01e51e3ed4c0e1d5c2e), ROM_BIOS(1) )

    ROM_REGION( 0x10000, "audiocpu", 0 )
    ROM_LOAD( "sm1.sm1", 0x00000, 0x20000, CRC(94416d67) SHA1(42f9d7ddd6c0931fd64226a60dc73602b2819571) )
ROM_END

GAME( 1990, neogeo, 0, neogeo_noslot, neogeo, neogeo_state, init_neogeo, ROT0, "SNK", "Neo Geo", MACHINE_IS_BIOS_ROOT )
"""

# COMP macro with MACHINE_IS_BIOS_ROOT
DEVICE_FIXTURE = """\
ROM_START( bbcb )
    ROM_REGION( 0x40000, "maincpu", 0 )
    ROM_LOAD( "basic2.rom", 0x00000, 0x4000, CRC(a1b6a0e9) SHA1(6a0b9b8b7c3b3b9e6b7e8d0f2e7a6e7b8c9a0b1c) )
ROM_END

COMP( 1981, bbcb, 0, 0, bbcb, bbcb, bbc_state, init_bbc, "Acorn", "BBC Micro Model B", MACHINE_IS_BIOS_ROOT )
"""

# ROM_LOAD with NO_DUMP (should be skipped)
NODUMP_FIXTURE = """\
ROM_START( testnd )
    ROM_REGION( 0x10000, "maincpu", 0 )
    ROM_LOAD( "good.rom", 0x00000, 0x4000, CRC(aabbccdd) SHA1(1122334455667788990011223344556677889900) )
    ROM_LOAD( "missing.rom", 0x04000, 0x4000, NO_DUMP )
ROM_END

GAME( 2000, testnd, 0, testnd, testnd, test_state, init_test, ROT0, "Test", "Test ND", MACHINE_IS_BIOS_ROOT )
"""

# ROM_LOAD with BAD_DUMP
BADDUMP_FIXTURE = """\
ROM_START( testbd )
    ROM_REGION( 0x10000, "maincpu", 0 )
    ROM_LOAD( "badrom.bin", 0x00000, 0x4000, BAD_DUMP CRC(deadbeef) SHA1(0123456789abcdef0123456789abcdef01234567) )
ROM_END

GAME( 2000, testbd, 0, testbd, testbd, test_state, init_test, ROT0, "Test", "Test BD", MACHINE_IS_BIOS_ROOT )
"""

# CONS macro with ROM_LOAD16_WORD
CONS_FIXTURE = """\
ROM_START( megadriv )
    ROM_REGION( 0x400000, "maincpu", 0 )
    ROM_LOAD16_WORD( "epr-6209.ic7", 0x000000, 0x004000, CRC(cafebabe) SHA1(abcdef0123456789abcdef0123456789abcdef01) )
ROM_END

CONS( 1988, megadriv, 0, 0, megadriv, megadriv, md_state, init_megadriv, "Sega", "Mega Drive", MACHINE_IS_BIOS_ROOT )
"""

# GAMEL macro: GAME plus a layout, the form gq863 and aristmk5 are written with
GAMEL_FIXTURE = """\
ROM_START( gq863 )
    ROM_REGION( 0x080000, "audiocpu", 0 )
    ROM_LOAD( "863a03.7b", 0x000000, 0x080000, CRC(81498f73) SHA1(3599b40a5872eab3a00d345287635355fcb25a71) )
ROM_END

GAMEL( 1999, gq863, 0, twinkle, twinkle, twinkle_state, empty_init, ROT0, "Konami", "Twinkle System", MACHINE_IS_BIOS_ROOT, layout_bmiidx )
"""

# GAME macro WITHOUT MACHINE_IS_BIOS_ROOT (should NOT be detected)
NON_BIOS_FIXTURE = """\
ROM_START( pacman )
    ROM_REGION( 0x10000, "maincpu", 0 )
    ROM_LOAD( "pacman.6e", 0x0000, 0x1000, CRC(c1e6ab10) SHA1(e87e059c5be45753f7e9f33dff851f16d6751181) )
ROM_END

GAME( 1980, pacman, 0, pacman, pacman, pacman_state, init_pacman, ROT90, "Namco", "Pac-Man", MACHINE_SUPPORTS_SAVE )
"""

# Flag commented out inside the macro call, as xavix.cpp does for the e-kara family
COMMENTED_FLAG_FIXTURE = """\
ROM_START( ekara )
    ROM_REGION( 0x100000, "bios", 0 )
    ROM_LOAD( "ekara.bin", 0x000000, 0x100000, CRC(9b27c8bc) SHA1(4f5ed7105b7128794654ce82b51723e16e389543) )
ROM_END

ROM_START( popira )
    ROM_REGION( 0x100000, "bios", 0 )
    ROM_LOAD( "popira.bin", 0x000000, 0x100000, CRC(3c9b3b3a) SHA1(ecf01eda815909f1facec62abf3594eaa8d11075) )
ROM_END

CONS( 2000, ekara, 0, 0, ekara, ekara, ekara_state, init_xavix, "Takara", "e-kara", MACHINE_IMPERFECT_SOUND /*| MACHINE_IS_BIOS_ROOT*/ )
CONS( 2000, popira, 0, 0, popira, popira, popira_state, init_xavix, "Takara", "Popira", MACHINE_IMPERFECT_SOUND/*|MACHINE_IS_BIOS_ROOT*/ ) // no BIOS
"""

# Line comment mentioning the flag outside any macro call
LINE_COMMENT_FIXTURE = """\
ROM_START( notbios )
    ROM_REGION( 0x1000, "maincpu", 0 )
    ROM_LOAD( "notbios.bin", 0x0000, 0x1000, CRC(c1e6ab10) SHA1(e87e059c5be45753f7e9f33dff851f16d6751181) )
ROM_END

// TODO: this should probably be MACHINE_IS_BIOS_ROOT one day
GAME( 1990, notbios, 0, notbios, notbios, test_state, init_test, ROT0, "Test", "Not BIOS", MACHINE_SUPPORTS_SAVE )
"""

# A game title containing characters that must not confuse comment stripping
QUOTED_SLASH_FIXTURE = """\
ROM_START( rcgp )
    ROM_REGION( 0x1000, "maincpu", 0 )
    ROM_LOAD( "rcgp.bin", 0x0000, 0x1000, CRC(c1e6ab10) SHA1(e87e059c5be45753f7e9f33dff851f16d6751181) )
ROM_END

GAME( 1989, rcgp, 0, rcgp, rcgp, test_state, init_test, ROT0, "Namco", "R/C Grand Prix", MACHINE_IS_BIOS_ROOT )
"""

# Sizes written as arithmetic, as konamigx.c does for its GX_BIOS macro
ARITHMETIC_SIZE_FIXTURE = """\
ROM_START( konamigx )
    ROM_REGION( 8*1024*1024, "maincpu", ROMREGION_ERASEFF )
    ROM_LOAD( "300a01.34k", 0x000000, 128*1024, CRC(d5fa95f5) SHA1(c483aa98ff8ef40cdac359c19ad23fea5ecc1906) )
    ROM_LOAD( "300a02.31k", 0x020000, 0x10000+0x800, CRC(d5fa95f6) SHA1(c483aa98ff8ef40cdac359c19ad23fea5ecc1907) )
ROM_END

GAME( 1994, konamigx, 0, konamigx, konamigx, gx_state, init_gx, ROT0, "Konami", "System GX", MACHINE_IS_BIOS_ROOT )
"""


class TestFindBiosRootSets(unittest.TestCase):
    """Tests for find_bios_root_sets."""

    def test_detects_neogeo_from_game_macro(self) -> None:
        result = find_bios_root_sets(NEOGEO_FIXTURE, "src/mame/snk/neogeo.cpp")
        self.assertIn("neogeo", result)
        self.assertEqual(result["neogeo"]["source_file"], "src/mame/snk/neogeo.cpp")
        self.assertIsInstance(result["neogeo"]["source_line"], int)

    def test_detects_from_comp_macro(self) -> None:
        result = find_bios_root_sets(DEVICE_FIXTURE, "src/mame/acorn/bbc.cpp")
        self.assertIn("bbcb", result)

    def test_detects_from_cons_macro(self) -> None:
        result = find_bios_root_sets(CONS_FIXTURE, "src/mame/sega/megadriv.cpp")
        self.assertIn("megadriv", result)

    def test_detects_from_gamel_macro(self) -> None:
        result = find_bios_root_sets(GAMEL_FIXTURE, "src/mame/konami/twinkle.cpp")
        self.assertIn("gq863", result)

    def test_gamel_rom_block_is_parsed(self) -> None:
        roms = parse_rom_block(GAMEL_FIXTURE, "gq863")
        self.assertEqual([r["name"] for r in roms], ["863a03.7b"])

    def test_ignores_non_bios_games(self) -> None:
        result = find_bios_root_sets(NON_BIOS_FIXTURE, "src/mame/pacman/pacman.cpp")
        self.assertEqual(result, {})

    def test_detects_from_nodump_fixture(self) -> None:
        result = find_bios_root_sets(NODUMP_FIXTURE, "test.cpp")
        self.assertIn("testnd", result)

    def test_detects_from_baddump_fixture(self) -> None:
        result = find_bios_root_sets(BADDUMP_FIXTURE, "test.cpp")
        self.assertIn("testbd", result)

    def test_ignores_block_commented_flag(self) -> None:
        result = find_bios_root_sets(
            COMMENTED_FLAG_FIXTURE, "src/mame/tvgames/xavix.cpp"
        )
        self.assertEqual(result, {})

    def test_ignores_flag_in_line_comment(self) -> None:
        result = find_bios_root_sets(LINE_COMMENT_FIXTURE, "test.cpp")
        self.assertEqual(result, {})

    def test_keeps_flag_when_title_contains_slash(self) -> None:
        result = find_bios_root_sets(QUOTED_SLASH_FIXTURE, "test.cpp")
        self.assertIn("rcgp", result)


class TestParseRomBlock(unittest.TestCase):
    """Tests for parse_rom_block."""

    def test_extracts_rom_names(self) -> None:
        roms = parse_rom_block(NEOGEO_FIXTURE, "neogeo")
        names = [r["name"] for r in roms]
        self.assertIn("sp-s2.sp1", names)
        self.assertIn("vs-bios.rom", names)
        self.assertIn("sm1.sm1", names)

    def test_extracts_crc32_and_sha1(self) -> None:
        roms = parse_rom_block(NEOGEO_FIXTURE, "neogeo")
        sp_s2 = next(r for r in roms if r["name"] == "sp-s2.sp1")
        self.assertEqual(sp_s2["crc32"], "9036d879")
        self.assertEqual(sp_s2["sha1"], "4f5ed7105b7128794654ce82b51723e16e389543")

    def test_extracts_size(self) -> None:
        roms = parse_rom_block(NEOGEO_FIXTURE, "neogeo")
        sp_s2 = next(r for r in roms if r["name"] == "sp-s2.sp1")
        self.assertEqual(sp_s2["size"], 0x020000)

    def test_extracts_bios_metadata(self) -> None:
        roms = parse_rom_block(NEOGEO_FIXTURE, "neogeo")
        sp_s2 = next(r for r in roms if r["name"] == "sp-s2.sp1")
        self.assertEqual(sp_s2["bios_index"], 0)
        self.assertEqual(sp_s2["bios_label"], "euro")
        self.assertEqual(sp_s2["bios_description"], "Europe MVS (Ver. 2)")

    def test_non_bios_rom_has_no_bios_fields(self) -> None:
        roms = parse_rom_block(NEOGEO_FIXTURE, "neogeo")
        sm1 = next(r for r in roms if r["name"] == "sm1.sm1")
        self.assertNotIn("bios_index", sm1)
        self.assertNotIn("bios_label", sm1)

    def test_skips_no_dump(self) -> None:
        roms = parse_rom_block(NODUMP_FIXTURE, "testnd")
        names = [r["name"] for r in roms]
        self.assertIn("good.rom", names)
        self.assertNotIn("missing.rom", names)

    def test_includes_bad_dump_with_flag(self) -> None:
        roms = parse_rom_block(BADDUMP_FIXTURE, "testbd")
        self.assertEqual(len(roms), 1)
        self.assertEqual(roms[0]["name"], "badrom.bin")
        self.assertTrue(roms[0]["bad_dump"])
        self.assertEqual(roms[0]["crc32"], "deadbeef")
        self.assertEqual(roms[0]["sha1"], "0123456789abcdef0123456789abcdef01234567")

    def test_handles_rom_load16_word(self) -> None:
        roms = parse_rom_block(CONS_FIXTURE, "megadriv")
        self.assertEqual(len(roms), 1)
        self.assertEqual(roms[0]["name"], "epr-6209.ic7")
        self.assertEqual(roms[0]["crc32"], "cafebabe")

    def test_tracks_rom_region(self) -> None:
        roms = parse_rom_block(NEOGEO_FIXTURE, "neogeo")
        sp_s2 = next(r for r in roms if r["name"] == "sp-s2.sp1")
        sm1 = next(r for r in roms if r["name"] == "sm1.sm1")
        self.assertEqual(sp_s2["region"], "mainbios")
        self.assertEqual(sm1["region"], "audiocpu")

    def test_returns_empty_for_unknown_set(self) -> None:
        roms = parse_rom_block(NEOGEO_FIXTURE, "nonexistent")
        self.assertEqual(roms, [])

    def test_evaluates_arithmetic_sizes(self) -> None:
        roms = parse_rom_block(ARITHMETIC_SIZE_FIXTURE, "konamigx")
        self.assertEqual([r["name"] for r in roms], ["300a01.34k", "300a02.31k"])
        self.assertEqual(roms[0]["size"], 131072)
        self.assertEqual(roms[1]["size"], 0x10800)

    def test_tracks_region_with_arithmetic_size(self) -> None:
        roms = parse_rom_block(ARITHMETIC_SIZE_FIXTURE, "konamigx")
        self.assertEqual(roms[0]["region"], "maincpu")

    def test_good_rom_not_flagged_bad_dump(self) -> None:
        roms = parse_rom_block(NODUMP_FIXTURE, "testnd")
        good = next(r for r in roms if r["name"] == "good.rom")
        self.assertFalse(good["bad_dump"])

    def test_crc32_sha1_lowercase(self) -> None:
        fixture = """\
ROM_START( upper )
    ROM_REGION( 0x10000, "maincpu", 0 )
    ROM_LOAD( "test.rom", 0x00000, 0x4000, CRC(AABBCCDD) SHA1(AABBCCDDEEFF00112233AABBCCDDEEFF00112233) )
ROM_END
"""
        roms = parse_rom_block(fixture, "upper")
        self.assertEqual(roms[0]["crc32"], "aabbccdd")
        self.assertEqual(roms[0]["sha1"], "aabbccddeeff00112233aabbccddeeff00112233")


class TestParseMameSourceTree(unittest.TestCase):
    """Tests for parse_mame_source_tree."""

    def test_walks_source_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            mame_dir = os.path.join(tmpdir, "src", "mame", "snk")
            os.makedirs(mame_dir)
            filepath = os.path.join(mame_dir, "neogeo.cpp")
            with open(filepath, "w") as f:
                f.write(NEOGEO_FIXTURE)

            results = parse_mame_source_tree(tmpdir)
            self.assertIn("neogeo", results)
            self.assertEqual(len(results["neogeo"]["roms"]), 3)
            self.assertEqual(
                results["neogeo"]["source_file"],
                "src/mame/snk/neogeo.cpp",
            )

    def test_ignores_non_source_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            mame_dir = os.path.join(tmpdir, "src", "mame")
            os.makedirs(mame_dir)
            # Write a .txt file that should be ignored
            with open(os.path.join(mame_dir, "notes.txt"), "w") as f:
                f.write(NEOGEO_FIXTURE)

            results = parse_mame_source_tree(tmpdir)
            self.assertEqual(results, {})

    def test_scans_devices_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            dev_dir = os.path.join(tmpdir, "src", "devices", "bus")
            os.makedirs(dev_dir)
            with open(os.path.join(dev_dir, "test.cpp"), "w") as f:
                f.write(DEVICE_FIXTURE)

            results = parse_mame_source_tree(tmpdir)
            self.assertIn("bbcb", results)

    def test_empty_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            results = parse_mame_source_tree(tmpdir)
            self.assertEqual(results, {})


if __name__ == "__main__":
    unittest.main()
