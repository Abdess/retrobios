"""Recalbox's launcher layer, read from configgen with ast.

The configgen blocks the extraction reads are in
tests/launchersrecalboxsupport.py, at the lines they hold in Recalbox 10.1.1.
"""

from __future__ import annotations

import tests

import json
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

import yaml

from model.launcherrecords import emulator_names, record_emulators
from scraper import recalbox_scraper
from scraper.launchers.recalbox_configgen import (
    ALL_CORES,
    AMIBERRY_CONFIG,
    AMIBERRY_GLOBAL,
    AMIBERRY_KICKSTARTS,
    CONFIGGEN,
    CORES,
    DOLPHIN,
    FILES_MODULE,
    GSPLUS,
    HATARI,
    LIBRETRO_GENERATOR,
    MUPEN_CONFIG,
    PCSX2,
    RETROARCH,
    XEMU,
    XROAR,
)
from scraper.launchers.recalbox import (
    SOURCE_FILES,
    Launcher,
    LauncherShapeError,
    content_files,
    core_assets,
    core_file_options,
    extract_launchers,
    system_directories,
)
from scraper.launchers.recalbox_emulators import amiberry, dolphin, mupen64plus, pcsx2, xemu, xroar
from scraper.launchers.recalbox_cascades import gsplus, hatari, hatari_libretro

from tests.launchersrecalboxsupport import configgen, files, ref


REPO_ROOT = Path(__file__).resolve().parent.parent


class XroarRomPath(unittest.TestCase):
    def test_the_rom_path_is_the_bios_folder_of_the_system(self):
        (record,) = xroar(configgen())
        self.assertEqual(
            (record.emulator, record.kind, record.search_dir, record.passes_to, record.source_ref),
            ("xroar", "passes_path", "/recalbox/share/bios/<system>", "command line -rompath",
             ref(XROAR, "25")),
        )

    def test_a_rom_path_built_another_way_raises(self):
        cg = configgen(XROAR, "os.path.join(recalboxFiles.BIOS, args.system)", "args.rompath")
        with self.assertRaises(LauncherShapeError):
            xroar(cg)


class SystemDirectoryPerCore(unittest.TestCase):
    """libretroRetroarch.py:431-529, the directory RetroArch is given."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.records = system_directories(configgen())

    def by(self, emulator: str) -> list[Launcher]:
        return [r for r in self.records if r.emulator == emulator]

    def test_a_core_with_one_directory(self):
        gpsp, = self.by("gpsp")
        self.assertEqual(gpsp.kind, "passes_path")
        self.assertEqual(gpsp.build, "libretro")
        self.assertEqual(gpsp.names, [])
        self.assertEqual(gpsp.search_dir, "/recalbox/share/bios/gba")
        self.assertEqual(gpsp.passes_to, "retroarch system_directory")
        self.assertIsNone(gpsp.depends_on_option)
        self.assertEqual(gpsp.source_ref, ref(RETROARCH, "472-473"))
        geargrafx, = self.by("geargrafx")
        self.assertEqual(geargrafx.search_dir, "/recalbox/share/bios/pcenginecd")

    def test_a_core_whose_directory_depends_on_the_system(self):
        self.assertEqual(
            [(r.search_dir, r.depends_on_option, r.source_ref) for r in self.by("bsnes")],
            [
                ("/recalbox/share/bios/sgb", "system gb, gbc", ref(RETROARCH, "436-438")),
                ("/recalbox/share/bios/satellaview", "system satellaview",
                 ref(RETROARCH, "436, 439-440")),
                ("/recalbox/share/bios", "system other than gb, gbc, satellaview",
                 ref(RETROARCH, "436, 441-442")),
            ],
        )
        self.assertEqual(
            [(r.search_dir, r.depends_on_option) for r in self.by("mesen_s")],
            [("/recalbox/share/bios/sgb", "system flag SuperGameBoy"),
             ("/recalbox/share/bios/<system>", "without system flag SuperGameBoy")],
        )

    def test_a_directory_named_after_the_system(self):
        picodrive, = self.by("picodrive")
        self.assertEqual(picodrive.search_dir, "/recalbox/share/bios/<system>")

    def test_every_other_core_gets_the_bios_root(self):
        default = [r for r in self.by(ALL_CORES)
                   if r.depends_on_option == "core with no case of its own"]
        self.assertEqual([(r.search_dir, r.source_ref) for r in default],
                         [("/recalbox/share/bios", ref(RETROARCH, "513-514"))])

    def test_the_system_overrides_come_after_the_core(self):
        overrides = [r for r in self.by(ALL_CORES) if r.depends_on_option.startswith("system")]
        self.assertEqual(
            [(r.search_dir, r.depends_on_option.removesuffix(
                ", replacing the directory chosen by core")) for r in overrides],
            [
                ("/recalbox/share/bios/amiga/bios",
                 "system amiga600, amiga1200, amigacdtv, amigacd32"),
                ("/recalbox/share/bios/fds", "system fds"),
                ("/recalbox/share/bios/lynx", "system lynx"),
                ("/recalbox/share/bios/nds", "system nds"),
                ("/recalbox/share/bios/saturn", "system saturn"),
                ("/recalbox/share/bios/stv", "system stv"),
            ],
        )
        self.assertEqual(overrides[0].source_ref, ref(RETROARCH, "516-519"))

    def test_the_cases_cover_the_match(self):
        cores = {name for r in self.records for name in emulator_names(r.emulator)}
        self.assertEqual(len(cores - {ALL_CORES}), 29)

    def test_dolphin_assets_directory(self):
        assets, = core_assets(configgen())
        self.assertEqual(assets.emulator, "dolphin")
        self.assertEqual(assets.search_dir, "/recalbox/share/bios/dolphin-emu")
        self.assertEqual(assets.passes_to, "retroarch core_assets_directory")
        self.assertEqual(assets.source_ref, ref(RETROARCH, "423-424"))

    def test_a_guarded_case_raises(self):
        with self.assertRaises(LauncherShapeError):
            system_directories(configgen(RETROARCH, "case 'gpsp':", "case 'gpsp' if True:"))

    def test_a_branch_test_it_cannot_read_raises(self):
        tree = configgen(RETROARCH, "elif self.system.Name == 'sufami':",
                         "elif self.system.Name.startswith('sufami'):")
        with self.assertRaises(LauncherShapeError):
            system_directories(tree)

    def test_a_directory_it_cannot_spell_raises(self):
        tree = configgen(RETROARCH, 'recalboxFiles.BIOS + "/gba"', "gbaDirectory()")
        with self.assertRaises(LauncherShapeError):
            system_directories(tree)


class HatariTosCascade(unittest.TestCase):
    """hatariGenerator.py:103-167 and libretroCores.py:165-298."""

    def test_the_standalone_tries_the_machine_then_three_fallbacks(self):
        records = hatari(configgen())
        self.assertEqual(
            [(r.slot, r.names[0]) for r in records[:-1]],
            [("st", "atarist/st.img"), ("megast", "atarist/st.img"),
             ("ste", "atarist/ste.img"), ("megaste", "atarist/megaste.img"),
             ("tt", "atarist/tt.img"), ("falcon", "atarist/falcon.img")],
        )
        for record in records[:-1]:
            self.assertEqual(record.kind, "names_searched")
            self.assertEqual(record.names[1:], ["atarist/tos.img", "tos.img", "atarist/emutos.img"])
            self.assertEqual(record.search_dir, "/recalbox/share/bios")
            self.assertEqual(record.passes_to, "[ROM] szTosImageFileName")
            self.assertIs(record.fails_when_missing, False)
            self.assertEqual(record.source_ref, ref(HATARI, "108-138, 151-167"))
            # coreSettings is never bound in SetMachineAndBios: no option fallback.
            self.assertEqual(record.depends_on_option,
                             "machine read from the rom path through machines")

    def test_emutos_in_the_rom_path_forces_one_name(self):
        emutos = hatari(configgen())[-1]
        self.assertEqual((emutos.kind, emutos.slot, emutos.names),
                         ("fixed_name", "emutos", ["atarist/emutos.img"]))
        self.assertEqual(emutos.depends_on_option, '"emutos" in the rom path')

    def test_the_two_libretro_cores(self):
        records = hatari_libretro(configgen())
        old = [r for r in records if r.emulator == "hatari"]
        new = [r for r in records if r.emulator == "hatarib"]
        self.assertEqual([r.slot for r in old],
                         ["st", "ste", "tt", "falcon", "megaste", "emutos"])
        self.assertEqual(old[0].passes_to, "[ROM] szTosImageFileName")
        self.assertEqual(old[0].source_ref, ref(CORES, "235-239, 249-267, 280-294"))
        self.assertEqual([r.slot for r in new],
                         ["st", "megast", "ste", "megaste", "tt", "falcon"])
        self.assertEqual(new[0].names, ["atarist/st.img", "atarist/tos.img", "tos.img"])
        self.assertEqual(new[0].passes_to,
                         "core option hatarib_tos (<etos1024k> when none is found)")
        self.assertEqual(new[0].depends_on_option,
                         "machine read from the rom path through machines, "
                         "else option hatarib_machine")
        self.assertEqual(new[0].source_ref, ref(CORES, "168-198, 211-212, 214-229"))

    def test_another_existence_test_raises(self):
        tree = configgen(HATARI, "if not os.path.exists(biosFile):",
                         "if not os.path.isfile(biosFile):")
        with self.assertRaises(LauncherShapeError):
            hatari(tree)


class GsplusRom(unittest.TestCase):
    """gsplusGenerator.py:93-148."""

    def test_the_search_and_the_game_file_placeholders(self):
        searched, rom1, rom3 = gsplus(configgen())
        self.assertEqual(searched.names, ["apple2gs1.rom", "apple2gs3.rom"])
        self.assertEqual(searched.kind, "names_searched")
        self.assertEqual(searched.passes_to, "g_cfg_rom_path")
        self.assertEqual(searched.depends_on_option, 'rom path without ".gsplus"')
        self.assertEqual(searched.source_ref, ref(GSPLUS, "140-148"))
        self.assertEqual([(r.slot, r.names) for r in (rom1, rom3)],
                         [("%1", ["apple2gs1.rom"]), ("%3", ["apple2gs3.rom"])])
        self.assertEqual(rom1.source_ref, ref(GSPLUS, "107-108"))

    def test_a_last_miss_that_keeps_the_key_raises(self):
        tree = configgen(GSPLUS, 'settings.removeOption("g_cfg_rom_path")', "pass")
        with self.assertRaises(LauncherShapeError):
            gsplus(tree)


class AmiberryKickstarts(unittest.TestCase):
    """amiberryKickstarts.py:47-143 and amiberryConfig.py:337-345."""

    def test_each_system_and_rom_type(self):
        records = amiberry(configgen())
        self.assertEqual(
            [(r.slot, r.kind, r.names, r.fails_when_missing) for r in records],
            [
                ("amiga600", "names_searched",
                 ["kick37175.A500", "kick34005.A500", "kick33180.A500"], False),
                ("amiga600", "names_searched", ["kick34005.A500", "kick33180.A500"], False),
                ("amiga1200", "names_searched",
                 ["kick40068.A1200", "kick39106.A1200", "kick40068.A4000"], False),
                ("amigacd32", "fixed_name", ["kick40060.CD32", "kick40060.CD32.ext"],
                 "No BIOS found, Extended BIOS not found"),
                ("amigacdtv", "fixed_name", ["kick34005.A500", "kick34005.CDTV"],
                 "No BIOS found, Extended BIOS not found"),
                ("amiga600, amiga1200", "fixed_name", ["kick02019.AROS", "kick02019.AROS.ext"],
                 False),
                (None, "passes_path", [], False),
            ],
        )
        self.assertEqual(records[1].depends_on_option, "rom type DISK")
        self.assertEqual(records[0].search_dir, "/recalbox/share/bios/amiga/bios")
        self.assertEqual(records[0].passes_to, "kickstart_rom_file")
        self.assertEqual(records[-2].passes_to,
                         "kickstart_rom_file, kickstart_ext_rom_file "
                         "(:AROS built in when either is missing)")
        self.assertEqual(records[0].source_ref,
                         f"{ref(AMIBERRY_KICKSTARTS, '9-10, 50-53, 94-142')}, "
                         f"{ref(AMIBERRY_CONFIG, '337-345')}")

    def test_rom_path_is_the_amiga_bios_folder(self):
        record = amiberry(configgen())[-1]
        self.assertEqual(
            (record.emulator, record.build, record.search_dir, record.passes_to,
             record.source_ref),
            ("amiberry", "standalone", "/recalbox/share/bios/amiga/bios",
             "written: rom_path in amiberry.conf", ref(AMIBERRY_GLOBAL, "42")),
        )

    def test_a_rom_path_outside_the_bios_folder_raises(self):
        tree = configgen(AMIBERRY_GLOBAL, 'recalboxFiles.BIOS + "/amiga/bios/"',
                         'mount + "/roms/"')
        with self.assertRaises(LauncherShapeError):
            amiberry(tree)

    def test_a_missing_rom_path_raises(self):
        tree = configgen(AMIBERRY_GLOBAL, '"rom_path"', '"rom_dir"')
        with self.assertRaises(LauncherShapeError):
            amiberry(tree)

    def test_several_pairs_for_one_rom_type_raise(self):
        tree = configgen(AMIBERRY_KICKSTARTS, '["kick40060.CD32|kick40060.CD32.ext"]',
                         '["kick40060.CD32|kick40060.CD32.ext", "a|b"]')
        with self.assertRaises(LauncherShapeError):
            amiberry(tree)


class Pcsx2Region(unittest.TestCase):
    """pcsx2Generator.py:36-40, 55-107, 166."""

    def test_the_region_token_comes_first_then_a_fixed_order(self):
        records = pcsx2(configgen())
        eu = records[0]
        self.assertEqual(eu.slot, "EU")
        self.assertEqual(eu.names, ["ps2-0230e-20080220.bin", "ps2-0230a-20080220.bin",
                                    "ps2-0230j-20080220.bin", "ps2-0230h-20080220.bin"])
        self.assertTrue(eu.depends_on_option.startswith("rom name contains europe, france"))
        self.assertTrue(eu.depends_on_option.endswith(", uk"))
        self.assertEqual(eu.search_dir, "/recalbox/share/bios/ps2")
        self.assertEqual(eu.passes_to, "[Filenames] BIOS")
        self.assertEqual(eu.source_ref, ref(PCSX2, "37-40, 56-107, 166"))
        self.assertEqual([r.slot for r in records], ["EU", "USA", "JP", "HK", "default"])

    def test_the_chinese_name_is_written_when_the_japanese_file_exists(self):
        hk = pcsx2(configgen())[3]
        self.assertEqual((hk.kind, hk.names), ("fixed_name", ["ps2-0230h-20080220.bin"]))
        self.assertEqual(hk.depends_on_option,
                         "rom name contains china, taiwan and ps2-0230j-20080220.bin is present")

    def test_a_region_branch_of_another_shape_raises(self):
        tree = configgen(PCSX2, 'elif "uk" in lrom and Exists', 'elif "uk" in lrom or Exists')
        with self.assertRaises(LauncherShapeError):
            pcsx2(tree)


class FixedPaths(unittest.TestCase):
    def test_xemu_writes_two_paths(self):
        record, = xemu(configgen())
        self.assertEqual(record.names, ["xbox/Complex_4627.bin", "xbox/mcpx_1.0.bin"])
        self.assertEqual(record.passes_to, "[sys.files] flashrom_path, [sys.files] bootrom_path")
        self.assertEqual(record.source_ref, ref(XEMU, "16, 26, 58-59"))

    def test_mupen64plus_writes_the_64dd_ipl_for_one_system(self):
        record, = mupen64plus(configgen())
        self.assertEqual(record.names, ["64DD_IPL.bin"])
        self.assertEqual(record.passes_to, "[64DD] IPL-ROM")
        self.assertEqual(record.depends_on_option, "system 64dd")
        self.assertEqual(record.source_ref, ref(MUPEN_CONFIG, "118-121"))

    def test_dolphin_only_tests_the_ipl_for_presence(self):
        standalone, libretro = dolphin(configgen())
        names = ["gamecube/EUR/IPL.bin", "gamecube/JP/IPL.bin", "gamecube/USA/IPL.bin"]
        self.assertEqual((standalone.emulator, standalone.names), ("dolphin, dolphin-gui", names))
        self.assertEqual(standalone.passes_to, "[Core] SkipIpl (False when one is present, else True)")
        self.assertEqual(standalone.source_ref, ref(DOLPHIN, "154-163, 236-237, 273"))
        self.assertEqual((libretro.emulator, libretro.names), ("dolphin", names))
        self.assertEqual(libretro.passes_to,
                         "core option dolphin_skip_gc_bios (disabled when one is present, "
                         "else enabled)")
        self.assertEqual(libretro.source_ref, ref(CORES, "496-504"))

    def test_minivmac_boot_disk_goes_through_a_command_file(self):
        record, = content_files(configgen())
        self.assertEqual((record.emulator, record.names),
                         ("minivmac", ["macintosh/MinivMacBootv2.dsk"]))
        self.assertEqual(record.passes_to,
                         "written into /tmp/minivmac.cmd, which is loaded as the content")
        self.assertEqual(record.source_ref,
                         f"{ref(LIBRETRO_GENERATOR, '877-882')}, {ref(FILES_MODULE, '174')}")

    def test_o2em_bios_option_is_read_from_the_core_directory(self):
        cg = configgen()
        records = core_file_options(cg, system_directories(cg))
        self.assertEqual(
            [(r.names, r.search_dir, r.depends_on_option) for r in records],
            [(["o2rom.bin"], "/recalbox/share/bios/o2em", "system odyssey2"),
             (["g7400.bin"], "/recalbox/share/bios/o2em", "system videopacplus")],
        )
        self.assertEqual(records[0].passes_to, "core option o2em_bios")
        self.assertEqual(records[0].source_ref,
                         f"{ref(CORES, '350-351, 695')}, {ref(RETROARCH, '491-492')}")


class ExtractionNeverEmpty(unittest.TestCase):
    def test_every_file_read_is_one_the_scraper_fetches(self):
        tree = files()
        read: list[str] = []

        def reader(path: str) -> str:
            read.append(path)
            return tree[path]

        records = extract_launchers(reader)
        self.assertEqual(sorted(set(read)), sorted(SOURCE_FILES))
        self.assertEqual(len(records), 87)

    def test_records_fit_the_schema(self):
        schema = json.loads((REPO_ROOT / "schemas" / "platform.schema.json").read_text())
        launcher = schema["$defs"]["launcher"]
        kinds = set(launcher["properties"]["kind"]["enum"])
        for record in extract_launchers(files().__getitem__):
            self.assertEqual(sorted(set(record) - set(launcher["properties"])), [])
            self.assertEqual(sorted(set(launcher["required"]) - set(record)), [])
            self.assertIn(record["kind"], kinds)

    def test_a_files_module_without_bios_raises(self):
        with self.assertRaises(LauncherShapeError):
            configgen(FILES_MODULE, "BIOS = '/recalbox/share/bios'", "BIOS_DIR = ''")

    def test_the_scraper_refuses_a_file_it_did_not_fetch(self):
        tree = files()
        scraper = recalbox_scraper.Scraper.__new__(recalbox_scraper.Scraper)
        scraper.tag = "10.1.1"
        fetched = {path: tree[path] for path in SOURCE_FILES if path != PCSX2}
        with mock.patch.object(scraper, "_blobs", return_value=fetched), \
                self.assertRaises(LauncherShapeError):
            scraper._fetch_launchers()

    def test_the_scraper_hands_over_what_it_fetched(self):
        tree = files()
        scraper = recalbox_scraper.Scraper.__new__(recalbox_scraper.Scraper)
        scraper.tag = "10.1.1"
        reader: Callable[[str], str] = tree.__getitem__
        with mock.patch.object(scraper, "_blobs", return_value=tree):
            self.assertEqual(scraper._fetch_launchers(), extract_launchers(reader))


class PlatformRecords(unittest.TestCase):
    """The launchers platforms/recalbox.yml carries, as the scraper wrote them."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = yaml.safe_load((REPO_ROOT / "platforms" / "recalbox.yml").read_text())

    def test_every_emulator_is_one_recalbox_names(self):
        cores = set(self.config["cores"]) | {ALL_CORES}
        named = {
            name for record in self.config["launchers"]
            for name in record_emulators(record)
        }
        self.assertEqual(sorted(named - cores), [])

    def test_every_reference_is_in_configgen(self):
        for record in self.config["launchers"]:
            for part in record["source_ref"].split(", "):
                if not part[0].isdigit():
                    self.assertTrue(part.startswith(f"{CONFIGGEN}/"), record)


if __name__ == "__main__":
    unittest.main()
