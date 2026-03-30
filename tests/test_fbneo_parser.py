"""Tests for the FBNeo source parser."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from scripts.scraper.fbneo_parser import (
    find_bios_sets,
    parse_fbneo_source_tree,
    parse_rom_info,
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


class TestFindBiosSets(unittest.TestCase):

    def test_detects_neogeo(self) -> None:
        result = find_bios_sets(NEOGEO_FIXTURE, 'd_neogeo.cpp')
        self.assertIn('neogeo', result)
        self.assertEqual(result['neogeo']['source_file'], 'd_neogeo.cpp')

    def test_detects_pgm(self) -> None:
        result = find_bios_sets(PGM_FIXTURE, 'd_pgm.cpp')
        self.assertIn('pgm', result)
        self.assertEqual(result['pgm']['source_file'], 'd_pgm.cpp')

    def test_ignores_non_bios(self) -> None:
        result = find_bios_sets(NON_BIOS_FIXTURE, 'd_neogeo.cpp')
        self.assertEqual(result, {})

    def test_source_line_positive(self) -> None:
        result = find_bios_sets(NEOGEO_FIXTURE, 'd_neogeo.cpp')
        self.assertGreater(result['neogeo']['source_line'], 0)


class TestParseRomInfo(unittest.TestCase):

    def test_neogeo_rom_count(self) -> None:
        roms = parse_rom_info(NEOGEO_FIXTURE, 'neogeo')
        self.assertEqual(len(roms), 5)

    def test_sentinel_skipped(self) -> None:
        roms = parse_rom_info(NEOGEO_FIXTURE, 'neogeo')
        names = [r['name'] for r in roms]
        self.assertNotIn('', names)

    def test_crc32_lowercase_hex(self) -> None:
        roms = parse_rom_info(NEOGEO_FIXTURE, 'neogeo')
        first = roms[0]
        self.assertEqual(first['crc32'], '9036d879')
        self.assertRegex(first['crc32'], r'^[0-9a-f]{8}$')

    def test_no_sha1(self) -> None:
        roms = parse_rom_info(NEOGEO_FIXTURE, 'neogeo')
        for rom in roms:
            self.assertNotIn('sha1', rom)

    def test_neogeo_first_rom(self) -> None:
        roms = parse_rom_info(NEOGEO_FIXTURE, 'neogeo')
        first = roms[0]
        self.assertEqual(first['name'], 'sp-s2.sp1')
        self.assertEqual(first['size'], 0x020000)
        self.assertEqual(first['crc32'], '9036d879')

    def test_pgm_rom_count(self) -> None:
        roms = parse_rom_info(PGM_FIXTURE, 'pgm')
        self.assertEqual(len(roms), 3)

    def test_pgm_bios_entry(self) -> None:
        roms = parse_rom_info(PGM_FIXTURE, 'pgm')
        bios = roms[2]
        self.assertEqual(bios['name'], 'pgm_p01s.rom')
        self.assertEqual(bios['crc32'], 'e42b166e')

    def test_unknown_set_returns_empty(self) -> None:
        roms = parse_rom_info(NEOGEO_FIXTURE, 'nonexistent')
        self.assertEqual(roms, [])


class TestParseSourceTree(unittest.TestCase):

    def test_walks_drv_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            drv_dir = Path(tmpdir) / 'src' / 'burn' / 'drv' / 'neogeo'
            drv_dir.mkdir(parents=True)
            (drv_dir / 'd_neogeo.cpp').write_text(NEOGEO_FIXTURE)

            result = parse_fbneo_source_tree(tmpdir)
            self.assertIn('neogeo', result)
            self.assertEqual(len(result['neogeo']['roms']), 5)

    def test_skips_non_cpp(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            drv_dir = Path(tmpdir) / 'src' / 'burn' / 'drv'
            drv_dir.mkdir(parents=True)
            (drv_dir / 'd_neogeo.h').write_text(NEOGEO_FIXTURE)

            result = parse_fbneo_source_tree(tmpdir)
            self.assertEqual(result, {})

    def test_missing_directory_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = parse_fbneo_source_tree(tmpdir)
            self.assertEqual(result, {})

    def test_multiple_sets(self) -> None:
        combined = NEOGEO_FIXTURE + '\n' + PGM_FIXTURE
        with tempfile.TemporaryDirectory() as tmpdir:
            drv_dir = Path(tmpdir) / 'src' / 'burn' / 'drv'
            drv_dir.mkdir(parents=True)
            (drv_dir / 'd_combined.cpp').write_text(combined)

            result = parse_fbneo_source_tree(tmpdir)
            self.assertIn('neogeo', result)
            self.assertIn('pgm', result)


if __name__ == '__main__':
    unittest.main()
