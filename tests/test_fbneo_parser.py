"""Tests for the FBNeo source parser."""

from __future__ import annotations

import tests

import tempfile
import unittest
from pathlib import Path

from scripts.scraper.arcade.fbneo_parser import (
    find_bios_sets,
    parse_fbneo_source_tree,
    parse_rom_info,
    zip_name,
)

NEOGEO_FIXTURE = """\
static struct BurnRomInfo neogeoRomDesc[] = {
    { "sp-s2.sp1",       0x020000, 0x9036d879, BRF_ESS | BRF_BIOS },
    { "sp-s.sp1",        0x020000, 0xc7f2fa45, BRF_ESS | BRF_BIOS },
    { "asia-s3.rom",     0x020000, 0x91b64be3, BRF_ESS | BRF_BIOS },
    { "vs-bios.rom",     0x020000, 0xf0e8f27d, BRF_ESS | BRF_BIOS },
    { "uni-bios.rom",    0x020000, 0x2d50996a, BRF_ESS | BRF_BIOS },
    { "",                 0,        0,          0 }
};

STD_ROM_FN(neogeo)

struct BurnDriver BurnDrvneogeo = {
    "neogeo", NULL, NULL, NULL, "1990",
    "Neo Geo\\0", "BIOS only", "SNK", "Neo Geo MVS",
    NULL, NULL, NULL, NULL,
    BDF_BOARDROM, 0, HARDWARE_PREFIX_CARTRIDGE | HARDWARE_SNK_NEOGEO,
    GBF_BIOS, 0,
    NULL, neogeoRomInfo, neogeoRomName, NULL, NULL, NULL, NULL,
    neogeoInputInfo, neogeoDIPInfo,
    NULL, NULL, NULL, NULL, 0x1000,
    304, 224, 4, 3
};
"""

PGM_FIXTURE = """\
static struct BurnRomInfo pgmRomDesc[] = {
    { "pgm_t01s.rom",    0x200000, 0x1a7123a0, BRF_GRA },
    { "pgm_m01s.rom",    0x200000, 0x45ae7159, BRF_SND },
    { "pgm_p01s.rom",    0x020000, 0xe42b166e, BRF_ESS | BRF_BIOS },
    { "",                 0,        0,          0 }
};

STD_ROM_FN(pgm)

struct BurnDriver BurnDrvpgm = {
    "pgm", NULL, NULL, NULL, "1997",
    "PGM (Polygame Master)\\0", "BIOS only", "IGS", "PGM",
    NULL, NULL, NULL, NULL,
    BDF_BOARDROM, 0, HARDWARE_IGS_PGM,
    GBF_BIOS, 0,
    NULL, pgmRomInfo, pgmRomName, NULL, NULL, NULL, NULL,
    pgmInputInfo, pgmDIPInfo,
    NULL, NULL, NULL, NULL, 0x900,
    448, 224, 4, 3
};
"""

NON_BIOS_FIXTURE = """\
static struct BurnRomInfo mslugRomDesc[] = {
    { "201-p1.p1",       0x100000, 0x08d8daa5, BRF_ESS | BRF_PRG },
    { "",                 0,        0,          0 }
};

STD_ROM_FN(mslug)

struct BurnDriver BurnDrvmslug = {
    "mslug", NULL, "neogeo", NULL, "1996",
    "Metal Slug\\0", NULL, "Nazca", "Neo Geo MVS",
    NULL, NULL, NULL, NULL,
    BDF_GAME_WORKING, 2, HARDWARE_PREFIX_CARTRIDGE | HARDWARE_SNK_NEOGEO,
    GBF_PLATFORM | GBF_HORSHOOT, 0,
    NULL, mslugRomInfo, mslugRomName, NULL, NULL, NULL, NULL,
    neogeoInputInfo, neogeoDIPInfo,
    NULL, NULL, NULL, NULL, 0x1000,
    304, 224, 4, 3
};
"""

# d_snes.cpp: a console driver with its own GetZipName and a decimal size.
SNES_FIXTURE = """\
static struct BurnRomInfo snes_dsp1RomDesc[] = {
	{ "dsp1.bin", 10240, 0x2838f9f5, BRF_ESS | BRF_PRG },
};

struct BurnDriver BurnDrvsnes_dsp1 = {
	"snes_dsp1", NULL, NULL, NULL, "x",
	"DSP-1\\0", NULL, "DSP microcode", "SNES / Super Famicom",
	NULL, NULL, NULL, NULL,
	BDF_BOARDROM, 1, HARDWARE_SNES, GBF_BIOS, 0,
	SNESGetZipName, snes_dsp1RomInfo, snes_dsp1RomName, NULL, NULL, NULL, NULL, SNESInputInfo, SNESDIPInfo,
	DrvInit, DrvExit, DrvFrame, DrvDraw, DrvScan, &DrvRecalc, 0x8000,
	512, 448, 4, 3
};
"""

# d_ngp.cpp: the board ROM driver has no GetZipName of its own, its games
# open it through NgpGetZipName, and its RomDesc is not named after it.
NGP_FIXTURE = """\
static struct BurnRomInfo ngpc_ngpRomDesc[] = {
	{ "SNK Neo-Geo Pocket BIOS (1998)(SNK)(en-ja).bin", 0x10000, 0x6232df8d, BRF_PRG | BRF_BIOS },
	{ "SNK Neo-Geo Pocket Color BIOS (1999)(SNK)(en-ja).bin", 0x10000, 0x6EEB6F40, BRF_PRG | BRF_BIOS },
};

struct BurnDriver BurnDrvngpc_ngp = {
	"ngp_ngp", NULL, NULL, NULL, "1998",
	"NeoGeo Pocket (Bios)\\0", "BIOS only", "SNK", "NeoGeo Pocket",
	NULL, NULL, NULL, NULL,
	BDF_BOARDROM, 0, HARDWARE_SNK_NGP | HARDWARE_SNK_NGPC, GBF_BIOS, 0,
	NULL, ngpc_ngpRomInfo, ngpc_ngpRomName, NULL, NULL, NULL, NULL, NgpInputInfo, NgpDIPInfo,
	DrvInit, DrvExit, DrvFrame, k1geDraw, DrvScan, &BurnRecalc, 0x1000,
	160, 152, 4, 3
};

struct BurnDriver BurnDrvngpc_bakumats = {
	"ngp_bakumats", "ngp_lastblad", "ngp_ngp", NULL, "2000",
	"Bakumatsu Rouman\\0", NULL, "SNK", "NeoGeo Pocket Color",
	NULL, NULL, NULL, NULL,
	BDF_GAME_WORKING, 1, HARDWARE_SNK_NGPC, GBF_VSFIGHT, 0,
	NgpGetZipName, ngpc_bakumatsRomInfo, ngpc_bakumatsRomName, NULL, NULL, NULL, NULL, NgpInputInfo, NgpDIPInfo,
	DrvInit, DrvExit, DrvFrame, k1geDraw, DrvScan, &BurnRecalc, 0x1000,
	160, 152, 4, 3
};
"""


class TestZipName(unittest.TestCase):
    def test_cuts_the_system_prefix(self) -> None:
        self.assertEqual(zip_name("msx_msx"), "msx")
        self.assertEqual(zip_name("msx_1942"), "1942")
        self.assertEqual(zip_name("snes_st010"), "st010")

    def test_name_without_prefix_is_kept(self) -> None:
        self.assertEqual(zip_name("neogeo"), "neogeo")


class TestFindBiosSets(unittest.TestCase):
    def test_console_driver_keyed_by_its_archive(self) -> None:
        result = find_bios_sets(SNES_FIXTURE, "d_snes.cpp")
        self.assertEqual(list(result), ["dsp1"])

    def test_board_rom_keyed_by_what_its_games_open(self) -> None:
        result = find_bios_sets(NGP_FIXTURE, "d_ngp.cpp")
        self.assertEqual(list(result), ["ngp"])

    def test_detects_neogeo(self) -> None:
        result = find_bios_sets(NEOGEO_FIXTURE, "d_neogeo.cpp")
        self.assertIn("neogeo", result)
        self.assertEqual(result["neogeo"]["source_file"], "d_neogeo.cpp")

    def test_detects_pgm(self) -> None:
        result = find_bios_sets(PGM_FIXTURE, "d_pgm.cpp")
        self.assertIn("pgm", result)
        self.assertEqual(result["pgm"]["source_file"], "d_pgm.cpp")

    def test_ignores_non_bios(self) -> None:
        result = find_bios_sets(NON_BIOS_FIXTURE, "d_neogeo.cpp")
        self.assertEqual(result, {})

    def test_source_line_positive(self) -> None:
        result = find_bios_sets(NEOGEO_FIXTURE, "d_neogeo.cpp")
        self.assertGreater(result["neogeo"]["source_line"], 0)


class TestParseRomInfo(unittest.TestCase):
    def test_neogeo_rom_count(self) -> None:
        roms = parse_rom_info(NEOGEO_FIXTURE, "neogeo")
        self.assertEqual(len(roms), 5)

    def test_sentinel_skipped(self) -> None:
        roms = parse_rom_info(NEOGEO_FIXTURE, "neogeo")
        names = [r["name"] for r in roms]
        self.assertNotIn("", names)

    def test_crc32_lowercase_hex(self) -> None:
        roms = parse_rom_info(NEOGEO_FIXTURE, "neogeo")
        first = roms[0]
        self.assertEqual(first["crc32"], "9036d879")
        self.assertRegex(first["crc32"], r"^[0-9a-f]{8}$")

    def test_no_sha1(self) -> None:
        roms = parse_rom_info(NEOGEO_FIXTURE, "neogeo")
        for rom in roms:
            self.assertNotIn("sha1", rom)

    def test_neogeo_first_rom(self) -> None:
        roms = parse_rom_info(NEOGEO_FIXTURE, "neogeo")
        first = roms[0]
        self.assertEqual(first["name"], "sp-s2.sp1")
        self.assertEqual(first["size"], 0x020000)
        self.assertEqual(first["crc32"], "9036d879")

    def test_pgm_rom_count(self) -> None:
        roms = parse_rom_info(PGM_FIXTURE, "pgm")
        self.assertEqual(len(roms), 3)

    def test_pgm_bios_entry(self) -> None:
        roms = parse_rom_info(PGM_FIXTURE, "pgm")
        bios = roms[2]
        self.assertEqual(bios["name"], "pgm_p01s.rom")
        self.assertEqual(bios["crc32"], "e42b166e")

    def test_decimal_size(self) -> None:
        roms = parse_rom_info(SNES_FIXTURE, "snes_dsp1")
        self.assertEqual(roms, [{"name": "dsp1.bin", "size": 10240, "crc32": "2838f9f5"}])

    def test_unknown_set_returns_empty(self) -> None:
        roms = parse_rom_info(NEOGEO_FIXTURE, "nonexistent")
        self.assertEqual(roms, [])


class TestParseSourceTree(unittest.TestCase):
    def test_walks_drv_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            drv_dir = Path(tmpdir) / "src" / "burn" / "drv" / "neogeo"
            drv_dir.mkdir(parents=True)
            (drv_dir / "d_neogeo.cpp").write_text(NEOGEO_FIXTURE)

            result = parse_fbneo_source_tree(tmpdir)
            self.assertIn("neogeo", result)
            self.assertEqual(len(result["neogeo"]["roms"]), 5)

    def test_reads_the_rom_desc_the_driver_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            drv_dir = Path(tmpdir) / "src" / "burn" / "drv"
            drv_dir.mkdir(parents=True)
            (drv_dir / "d_ngp.cpp").write_text(NGP_FIXTURE)

            result = parse_fbneo_source_tree(tmpdir)
            self.assertEqual([r["crc32"] for r in result["ngp"]["roms"]], ["6232df8d", "6eeb6f40"])

    def test_skips_non_cpp(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            drv_dir = Path(tmpdir) / "src" / "burn" / "drv"
            drv_dir.mkdir(parents=True)
            (drv_dir / "d_neogeo.h").write_text(NEOGEO_FIXTURE)

            result = parse_fbneo_source_tree(tmpdir)
            self.assertEqual(result, {})

    def test_missing_directory_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = parse_fbneo_source_tree(tmpdir)
            self.assertEqual(result, {})

    def test_multiple_sets(self) -> None:
        combined = NEOGEO_FIXTURE + "\n" + PGM_FIXTURE
        with tempfile.TemporaryDirectory() as tmpdir:
            drv_dir = Path(tmpdir) / "src" / "burn" / "drv"
            drv_dir.mkdir(parents=True)
            (drv_dir / "d_combined.cpp").write_text(combined)

            result = parse_fbneo_source_tree(tmpdir)
            self.assertIn("neogeo", result)
            self.assertIn("pgm", result)


if __name__ == "__main__":
    unittest.main()
