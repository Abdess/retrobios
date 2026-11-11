#!/usr/bin/env python3
"""Batocera's launcher layer, read from configgen with ast.

The generator blocks below are copied from batocera-43.1 (155c2d8d) and
placed at the lines they hold there, so the source_ref an extraction writes
is checked against the revision itself.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import dataclasses
import json
import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from scraper.batocera_launchers import (  # noqa: E402
    CONFIGGEN,
    GENERATORS,
    IMPORTER,
    PATHS_MODULE,
    Configgen,
    Launcher,
    LauncherShapeError,
    config_directories,
    duckstation,
    extract_launchers,
    hatari,
    lexaloffle,
)
from scraper.retropie_launchers import Launcher as PackageLauncher  # noqa: E402

PATHS = """from pathlib import Path
from typing import Final

USERDATA: Final = Path('/userdata')
BIOS: Final = USERDATA / 'bios'
"""

IMPORTER_TEXT = """from typing import Final

_LEGACY_GENERATOR_MAP: Final[dict[str, dict[str, tuple[str, str]]]] = {
    'duckstation': {
        'duckstation-legacy': ('duckstation_legacy.duckstationLegacyGenerator', 'X'),
    },
}

_GENERATOR_MAP: Final[dict[str, tuple[str, str]]] = {
    'gsplus': ('gsplus.gsplusGenerator', 'GSplusGenerator'),
}
"""

DUCKSTATION = f"{GENERATORS}/duckstation/duckstationGenerator.py"
HATARI = f"{GENERATORS}/hatari/hatariGenerator.py"
LEXALOFFLE = f"{GENERATORS}/lexaloffle/lexaloffleGenerator.py"

DUCKSTATION_HEAD = '''from __future__ import annotations

from ...batoceraPaths import BIOS


class DuckstationGenerator(Generator):
    def generate(self, system, rom, playersControllers, metadata, guns, wheels, gameResolution):
        settings = CaseSensitiveConfigParser(interpolation=None)'''

# duckstationGenerator.py:115-136
DUCKSTATION_BIOS = '''        ## [BIOS]
        if not settings.has_section("BIOS"):
            settings.add_section("BIOS")
        settings.set("BIOS", "SearchDirectory", "/userdata/bios")
        # Boot Logo
        settings.set("BIOS", "PatchFastBoot", system.config.get("duckstation_PatchFastBoot", "false"))
        # Find & populate BIOS
        found_bios = find_bios(bios_lists)

        if not found_bios:
            raise BatoceraException("No PSX1 BIOS found")

        # Set BIOS paths
        if "Uni" in found_bios:
            uni_bios = found_bios["Uni"]
            settings.set("BIOS", "PathNTSCU", uni_bios)
            settings.set("BIOS", "PathPAL", uni_bios)
            settings.set("BIOS", "PathNTSCJ", uni_bios)
        else:
            region_mapping = {"NTSCU": "PathNTSCU", "PAL": "PathPAL", "NTSCJ": "PathNTSCJ"}
            for region, bios in found_bios.items():
                settings.set("BIOS", region_mapping[region], bios)'''

# duckstationGenerator.py:501-523
DUCKSTATION_FIND = '''def find_bios(bios_lists: Mapping[str, Sequence[str]]):
    found_bios: dict[str, str] = {}

    try:
        files_lower = {f.name.lower(): f.name for f in BIOS.iterdir()}
    except OSError as e:
        raise BatoceraException(f"Unable to read BIOS directory: {BIOS}") from e

    for region, bios_list in bios_lists.items():
        for bios in bios_list:
            if bios.lower() in files_lower:
                found_bios[region] = files_lower[bios.lower()]
                break

    return found_bios

# Define BIOS lists
bios_lists = {
    "NTSCU": ["scph101.bin", "scph1001.bin", "scph5501.bin", "scph7001.bin", "scph7501.bin"],
    "PAL": ["scph1002.bin", "scph5502.bin", "scph5552.bin", "scph7002.bin", "scph7502.bin", "scph9002.bin", "scph102a.bin", "scph102b.bin"],
    "NTSCJ": ["scph100.bin", "scph1000.bin", "scph3000.bin", "scph3500.bin", "scph5500.bin", "scph7000.bin", "scph7003.bin"],
    "Uni": ["psxonpsp660.bin", "ps1_rom.bin"]
}'''

HATARI_HEAD = '''from __future__ import annotations

from ...batoceraPaths import BIOS


class HatariGenerator(Generator):'''

# hatariGenerator.py:32-75
HATARI_GENERATE = '''    def generate(self, system, rom, playersControllers, metadata, guns, wheels, gameResolution):
        model_mapping = {
            "520st_auto":       { "machine": "st",      "tos": "auto" },
            "520st_100":        { "machine": "st",      "tos": "100"  },
            "520st_102":        { "machine": "st",      "tos": "102"  },
            "520st_104":        { "machine": "st",      "tos": "104"  },
            "520st_etos256":    { "machine": "st",      "tos": "etos256"  },
            "1040ste_auto":     { "machine": "ste",     "tos": "auto" },
            "1040ste_106":      { "machine": "ste",     "tos": "106"  },
            "1040ste_162":      { "machine": "ste",     "tos": "162"  },
            "1040ste_etos256":  { "machine": "ste",     "tos": "etos256"  },
            "megaste_auto":     { "machine": "megaste", "tos": "auto" },
            "megaste_205":      { "machine": "megaste", "tos": "205"  },
            "megaste_206":      { "machine": "megaste", "tos": "206"  },
            "megaste_etos256":  { "machine": "megaste", "tos": "etos256"  },
            "tt_auto":          { "machine": "tt",      "tos": "auto" },
            "tt_306":           { "machine": "tt",      "tos": "306"  },
            "tt_etos512":       { "machine": "tt",      "tos": "etos512"  },
            "falcon_auto":      { "machine": "falcon",  "tos": "auto" },
            "falcon_400":       { "machine": "falcon",  "tos": "400"  },
            "falcon_402":       { "machine": "falcon",  "tos": "402"  },
            "falcon_404":       { "machine": "falcon",  "tos": "404"  },
            "falcon_etos512":   { "machine": "falcon",  "tos": "etos512"  },
        }

        # Start emulator fullscreen
        commandArray: list[str | Path] = ["hatari", "--fullscreen"]

        # Machine can be st (default), ste, megaste, tt, falcon
        # st should use TOS 1.00 to TOS 1.04 (tos100 / tos102 / tos104 / emutos192k)
        # ste should use TOS 1.06 at least (tos106 / tos162 / tos206 / emutos192K)
        # megaste should use TOS 2.XX series (tos206 / emutos256k)
        # tt should use tos 3.XX / emutos512k
        # falcon should use tos 4.XX / emutos512k

        model = system.config.get("model", "none")
        mapped = model_mapping.get(model, {"machine": "st", "tos": "auto"})
        machine = mapped["machine"]
        tosversion = mapped["tos"]
        toslang = system.config.get("language", "us")

        commandArray += ["--machine", machine]
        tos = HatariGenerator.findBestTos(BIOS, machine, tosversion, toslang)
        commandArray += [ "--tos", tos]'''

# hatariGenerator.py:157-193
HATARI_FIND = '''    @staticmethod
    def findBestTos(biosdir: Path, machine: str, tos_version: str, language: str, /) -> Path:
        # all languages by preference, when value is "auto"
        all_languages = ["us", "uk", "de", "es", "fr", "it", "nl", "ru", "se", ""]

        # machine bioses by prefered orders, when value is "auto"
        all_machines_bios = {
            "st":      ["etos256", "104", "102", "100"],
            "ste":     ["etos256", "162", "106"],
            "megaste": ["etos256", "206", "205"],
            "tt":      ["etos512", "306"],
            "falcon":  ["etos512", "404", "402", "400"]
        }

        if machine in all_machines_bios:
            l_tos = []
            if tos_version != "auto":
                l_tos = [tos_version]
            l_tos.extend(all_machines_bios[machine])
            for v_tos_version in l_tos:
                l_lang = []
                if language != "auto":
                    l_lang = [language]
                l_lang.extend(all_languages)
                for v_language in l_lang:
                    if "etos" in v_tos_version:
                        biosversion = v_tos_version
                    else:
                        biosversion = f"tos{v_tos_version}"
                    tos_path = biosdir / f"{biosversion}{v_language}.img"
                    if tos_path.exists():
                        _logger.debug("tos filename: %s", tos_path.name)
                        return tos_path

                    _logger.warning("tos filename %s not found", tos_path.name)

        raise BatoceraException(f"No bios found for machine {machine}")'''


# lexaloffleGenerator.py, whole file
LEXALOFFLE_GENERATOR = '''from __future__ import annotations

import os
from typing import TYPE_CHECKING, Final

from ... import Command
from ...batoceraPaths import BIOS, HOME, ROMS, SCREENSHOTS, ensure_parents_and_open
from ...controller import generate_sdl_game_controller_config
from ...exceptions import BatoceraException
from ..Generator import Generator

if TYPE_CHECKING:
    from pathlib import Path

    from ...types import HotkeysContext

PICO8_BIN_PATH: Final = BIOS / "pico-8" / "pico8"
PICO8_ROOT_PATH: Final = ROMS / "pico8"
PICO8_CONTROLLERS: Final = HOME / ".lexaloffle" / "pico-8" / "sdl_controllers.txt"
VOX_BIN_PATH: Final = BIOS / "voxatron" / "vox"
VOX_ROOT_PATH: Final = ROMS / "voxatron"
VOX_CONTROLLERS: Final = HOME / ".lexaloffle" / "Voxatron" / "sdl_controllers.txt"


# Generator for the official pico8 binary from Lexaloffle
class LexaloffleGenerator(Generator):

    def getHotkeysContext(self) -> HotkeysContext:
        return {
            "name": "lexaloffle",
            "keys": { "exit": ["KEY_LEFTCTRL", "KEY_Q"], "menu": "KEY_ENTER", "reset": [ "KEY_LEFTCTRL", "KEY_R" ] }
        }

    def generate(self, system, rom, playersControllers, metadata, guns, wheels, gameResolution):
        if (system.name == "pico8"):
            LD_LIB=BIOS / "pico-8"
            BIN_PATH=PICO8_BIN_PATH
            CONTROLLERS=PICO8_CONTROLLERS
            ROOT_PATH=PICO8_ROOT_PATH
        elif (system.name == "voxatron"):
            LD_LIB=BIOS / "voxatron"
            BIN_PATH=VOX_BIN_PATH
            CONTROLLERS=VOX_CONTROLLERS
            ROOT_PATH=VOX_ROOT_PATH
        else:
            raise BatoceraException(f"The Lexaloffle generator has been called for an unknwon system: {system.name}.")

        if not BIN_PATH.exists():
            raise BatoceraException(f"Lexaloffle official binary not found at {BIN_PATH}")

        if not os.access(BIN_PATH, os.X_OK):
            raise BatoceraException(f"{BIN_PATH} is not set as executable")

        # the command to run
        commandArray: list[str | Path] = [BIN_PATH]
        commandArray.extend(["-desktop", SCREENSHOTS])  # screenshots
        commandArray.extend(["-windowed", "0"])                     # full screen
        # Display FPS
        if system.config.show_fps:
                commandArray.extend(["-show_fps", "1"])
        else:
                commandArray.extend(["-show_fps", "0"])

        rombase = rom.stem

        # .m3u support for multi-cart pico-8
        if rom.suffix.lower() == ".m3u":
            with rom.open() as fpin:
                lines = fpin.readlines()
            fullpath = rom.absolute().parent / lines[0].strip()
            commandArray.extend(["-root_path", fullpath.parent])
            rom = fullpath
        else:
            commandArray.extend(["-root_path", ROOT_PATH]) # store carts from splore

        if (rombase.lower() == "splore" or rombase.lower() == "console"):
            commandArray.extend(["-splore"])
        else:
            commandArray.extend(["-run", rom])

        controllersconfig = generate_sdl_game_controller_config(playersControllers)
        with ensure_parents_and_open(CONTROLLERS, "w") as file:
               file.write(controllersconfig)

        existing_library_path = os.environ.get("LD_LIBRARY_PATH")

        return Command.Command(array=commandArray, env={
            "SDL_AUDIODRIVER": "alsa",
            "LD_LIBRARY_PATH": f"{LD_LIB}:{existing_library_path}" if existing_library_path else LD_LIB
        })

    def getInGameRatio(self, config, gameResolution, rom):
        return 4/3'''


def placed(blocks: dict[int, str]) -> str:
    """Each block starting at its line, blank lines between."""
    lines: list[str] = []
    for start, block in sorted(blocks.items()):
        if len(lines) >= start:
            raise AssertionError(f"block at line {start} overlaps the previous one")
        lines += [""] * (start - 1 - len(lines))
        lines += block.splitlines()
    return "\n".join(lines) + "\n"


def configgen(files: dict[str, str]) -> Configgen:
    tree = {PATHS_MODULE: PATHS, IMPORTER: IMPORTER_TEXT, **files}
    return Configgen(tree.__getitem__)


# The generator goes on after the [BIOS] section: code between the two cited
# ranges keeps them apart.
DUCKSTATION_NEXT = '''        settings.set("CPU", "ExecutionMode", "Recompiler")'''


def duckstation_source(bios: str = DUCKSTATION_BIOS, find: str = DUCKSTATION_FIND) -> str:
    return placed({1: DUCKSTATION_HEAD, 115: bios, 138: DUCKSTATION_NEXT, 501: find})


def duckstation_tree(bios: str = DUCKSTATION_BIOS, find: str = DUCKSTATION_FIND) -> Configgen:
    return configgen({DUCKSTATION: duckstation_source(bios, find)})


def hatari_tree(generate: str = HATARI_GENERATE, find: str = HATARI_FIND) -> Configgen:
    return configgen({HATARI: placed({1: HATARI_HEAD, 32: generate, 157: find})})


def lexaloffle_tree(text: str = LEXALOFFLE_GENERATOR) -> Configgen:
    return configgen({LEXALOFFLE: text + "\n"})


class DuckStationSearch(unittest.TestCase):
    def setUp(self) -> None:
        self.records = duckstation(duckstation_tree())

    def test_each_region_list_keeps_its_search_order(self):
        self.assertEqual(
            [(r.slot, r.names) for r in self.records],
            [
                ("NTSCU", ["scph101.bin", "scph1001.bin", "scph5501.bin", "scph7001.bin",
                           "scph7501.bin"]),
                ("PAL", ["scph1002.bin", "scph5502.bin", "scph5552.bin", "scph7002.bin",
                         "scph7502.bin", "scph9002.bin", "scph102a.bin", "scph102b.bin"]),
                ("NTSCJ", ["scph100.bin", "scph1000.bin", "scph3000.bin", "scph3500.bin",
                           "scph5500.bin", "scph7000.bin", "scph7003.bin"]),
                ("Uni", ["psxonpsp660.bin", "ps1_rom.bin"]),
            ],
        )

    def test_the_lines_cited_are_the_search_and_the_lists(self):
        refs = {r.source_ref for r in self.records}
        self.assertEqual(refs, {f"{DUCKSTATION}:115-136, 501-523"})

    def test_how_the_found_name_reaches_duckstation(self):
        first, uni = self.records[0], self.records[-1]
        self.assertEqual(first.emulator, "duckstation")
        self.assertEqual(first.build, "standalone")
        self.assertEqual(first.kind, "names_searched")
        self.assertTrue(first.case_insensitive)
        self.assertEqual(first.search_dir, "/userdata/bios")
        self.assertEqual(first.passes_to, "[BIOS] PathNTSCU")
        self.assertEqual(uni.passes_to, "[BIOS] PathNTSCU, PathPAL, PathNTSCJ")

    def test_the_failure_is_raised_only_when_every_region_is_empty(self):
        for record in self.records:
            self.assertEqual(record.fails_when_missing, "No PSX1 BIOS found")
            self.assertEqual(record.fails_scope, "emulator")

    def test_an_exact_case_search_is_not_read_as_case_insensitive(self):
        find = DUCKSTATION_FIND.replace("f.name.lower()", "f.name").replace("bios.lower()", "bios")
        with self.assertRaises(LauncherShapeError):
            duckstation(duckstation_tree(find=find))

    def test_lists_that_are_no_longer_a_literal_raise(self):
        find = DUCKSTATION_FIND.replace("bios_lists = {", "BIOS_LISTS = {")
        with self.assertRaises(LauncherShapeError):
            duckstation(duckstation_tree(find=find))

    def test_paths_written_another_way_raise(self):
        bios = DUCKSTATION_BIOS.replace("region_mapping[region]", "f'Path{region}'")
        with self.assertRaises(LauncherShapeError):
            duckstation(duckstation_tree(bios=bios))


class HatariTosSearch(unittest.TestCase):
    def setUp(self) -> None:
        self.records = hatari(hatari_tree())

    def test_each_machine_tries_its_versions_in_order(self):
        self.assertEqual(
            [(r.slot, r.names) for r in self.records],
            [
                ("st", ["etos256{L}.img", "tos104{L}.img", "tos102{L}.img", "tos100{L}.img"]),
                ("ste", ["etos256{L}.img", "tos162{L}.img", "tos106{L}.img"]),
                ("megaste", ["etos256{L}.img", "tos206{L}.img", "tos205{L}.img"]),
                ("tt", ["etos512{L}.img", "tos306{L}.img"]),
                ("falcon", ["etos512{L}.img", "tos404{L}.img", "tos402{L}.img", "tos400{L}.img"]),
            ],
        )

    def test_every_version_is_tried_in_every_language(self):
        for record in self.records:
            self.assertEqual(
                record.expands, {"L": ["us", "uk", "de", "es", "fr", "it", "nl", "ru", "se", ""]}
            )

    def test_the_lines_cited_are_the_mapping_the_call_and_the_search(self):
        refs = {r.source_ref for r in self.records}
        self.assertEqual(refs, {f"{HATARI}:33-55, 67-75, 158-193"})

    def test_how_the_tos_reaches_hatari(self):
        st = self.records[0]
        self.assertEqual(st.emulator, "hatari")
        self.assertFalse(st.case_insensitive)
        self.assertEqual(st.search_dir, "/userdata/bios")
        self.assertEqual(st.passes_to, "--machine st --tos <file>")
        self.assertEqual(st.fails_when_missing, "No bios found for machine st")
        self.assertIsNone(st.fails_scope)
        self.assertEqual(st.depends_on_option, "model, language")

    def test_a_name_built_another_way_raises(self):
        find = HATARI_FIND.replace(
            'biosdir / f"{biosversion}{v_language}.img"', 'biosdir / "tos.img"'
        )
        with self.assertRaises(LauncherShapeError):
            hatari(hatari_tree(find=find))


class LexaloffleBinaries(unittest.TestCase):
    def setUp(self) -> None:
        self.records = [r.entry() for r in lexaloffle(lexaloffle_tree())]

    def test_each_system_runs_its_binary_and_loads_its_folder(self):
        self.assertEqual(
            [(r["slot"], r["kind"], r["names"], r["search_dir"], r["passes_to"])
             for r in self.records],
            [
                ("pico8", "fixed_name", ["pico-8/pico8"], "/userdata/bios", "exec"),
                ("pico8", "passes_path", [], "/userdata/bios/pico-8",
                 "environment LD_LIBRARY_PATH"),
                ("voxatron", "fixed_name", ["voxatron/vox"], "/userdata/bios", "exec"),
                ("voxatron", "passes_path", [], "/userdata/bios/voxatron",
                 "environment LD_LIBRARY_PATH"),
            ],
        )
        for record in self.records:
            self.assertEqual((record["emulator"], record["build"]), ("lexaloffle", "standalone"))

    def test_a_missing_or_non_executable_binary_stops_the_launch(self):
        pico8, library, vox, _ = self.records
        self.assertEqual(
            pico8["fails_when_missing"],
            "Lexaloffle official binary not found at /userdata/bios/pico-8/pico8, "
            "/userdata/bios/pico-8/pico8 is not set as executable",
        )
        self.assertEqual(
            vox["fails_when_missing"],
            "Lexaloffle official binary not found at /userdata/bios/voxatron/vox, "
            "/userdata/bios/voxatron/vox is not set as executable",
        )
        self.assertFalse(pico8["case_insensitive"])
        self.assertFalse(library["fails_when_missing"])

    def test_the_lines_cited_are_the_constant_the_branch_the_checks_and_the_command(self):
        self.assertEqual(
            [r["source_ref"] for r in self.records],
            [
                f"{LEXALOFFLE}:17, 35, 37, 48-55",
                f"{LEXALOFFLE}:35-36, 89",
                f"{LEXALOFFLE}:20, 40, 42, 48-55",
                f"{LEXALOFFLE}:40-41, 89",
            ],
        )

    def test_a_binary_without_the_executable_check_raises(self):
        text = LEXALOFFLE_GENERATOR.replace("os.access(BIN_PATH, os.X_OK)", "True")
        with self.assertRaises(LauncherShapeError):
            lexaloffle(lexaloffle_tree(text))

    def test_a_binary_without_the_existence_check_raises(self):
        text = LEXALOFFLE_GENERATOR.replace("BIN_PATH.exists()", "BIN_PATH")
        with self.assertRaises(LauncherShapeError):
            lexaloffle(lexaloffle_tree(text))

    def test_a_command_started_another_way_raises(self):
        text = LEXALOFFLE_GENERATOR.replace("= [BIN_PATH]", '= ["pico8"]')
        with self.assertRaises(LauncherShapeError):
            lexaloffle(lexaloffle_tree(text))

    def test_a_library_path_set_elsewhere_raises(self):
        text = LEXALOFFLE_GENERATOR.replace('"LD_LIBRARY_PATH": ', '"LIBRARY_PATH": ')
        with self.assertRaises(LauncherShapeError):
            lexaloffle(lexaloffle_tree(text))

    def test_a_binary_outside_bios_raises(self):
        text = LEXALOFFLE_GENERATOR.replace(
            'VOX_BIN_PATH: Final = BIOS / "voxatron" / "vox"',
            'VOX_BIN_PATH: Final = Path("/usr/bin/vox")',
        )
        with self.assertRaises(LauncherShapeError):
            lexaloffle(lexaloffle_tree(text))

    def test_a_generator_that_no_longer_branches_on_the_system_raises(self):
        text = LEXALOFFLE_GENERATOR.replace("system.name ==", "system.emulator ==")
        with self.assertRaises(LauncherShapeError):
            lexaloffle(lexaloffle_tree(text))


OPENMSX = f"{GENERATORS}/openmsx/openmsxGenerator.py"
OPENMSX_FILEPOOL = '''    def generate(self, system, rom):
        with settings_tcl.open("a") as file:
            file.write("filepool add -path /userdata/bios/Machines -types system_rom -position 1\\n")
            file.write("filepool add -path /userdata/bios/openmsx -types system_rom -position 2\\n")'''


MAME = f"{GENERATORS}/mame/mameGenerator.py"
MAME_PATHS = f"{GENERATORS}/mame/mamePaths.py"
MAME_HEAD = """from __future__ import annotations
from ...batoceraPaths import BIOS
from .mamePaths import MAME_BIOS
class MameGenerator:
    def generate(self, system, rom, playersControllers, metadata, guns, wheels, gameResolution):"""
MAME_COMMAND = """        if messMode == -1:
            commandArray += [ "-rompath", f"{romDirname};{MAME_BIOS};{BIOS}" ]"""
MAME_SAMPLES = """        commandArray += [ "-samplepath",  MAME_BIOS / "samples" ]"""
MAME_BOOT = """        if boot_disk:
            bootDisk = f"/userdata/bios/{boot_disk}.img"
            commandArray += [ bootType, bootDisk ]"""


class MameSearchPaths(unittest.TestCase):
    """mameGenerator.py:129-142 at batocera-43.1: `-rompath` and `-samplepath`."""

    def test_the_command_line_search_paths_are_recorded(self):
        from scraper.batocera_launchers import search_paths

        cg = configgen({
            MAME: placed({1: MAME_HEAD, 129: MAME_COMMAND, 142: MAME_SAMPLES, 378: MAME_BOOT}),
            MAME_PATHS: "from ...batoceraPaths import BIOS\nMAME_BIOS = BIOS / 'mame'\n",
        })
        records = [r.entry() for r in search_paths(cg)]
        self.assertEqual(
            [(r["emulator"], r["search_dir"], r["passes_to"], r.get("depends_on_option"))
             for r in records],
            [
                ("mame", "<romDirname>;/userdata/bios/mame;/userdata/bios",
                 "command line -rompath", "messMode == -1"),
                ("mame", "/userdata/bios/mame/samples", "command line -samplepath", None),
            ],
        )
        self.assertEqual(records[0]["source_ref"], f"{MAME}:129-130")
        # The boot disk the command names is a file, no search path.
        self.assertFalse([r for r in records if "boot_disk" in r["search_dir"]])


class ConfigDirectories(unittest.TestCase):
    """A BIOS directory written into the emulator's config, at batocera-43.1."""

    def test_each_filepool_line_hands_its_directory(self):
        cg = configgen({OPENMSX: placed({1: "class OpenmsxGenerator:", 86: OPENMSX_FILEPOOL})})
        records = [r.entry() for r in config_directories(cg, ("openmsx.openmsxGenerator",))]
        self.assertEqual(
            [(r["emulator"], r["kind"], r["search_dir"], r["source_ref"]) for r in records],
            [
                ("openmsx", "passes_path", "/userdata/bios/Machines", f"{OPENMSX}:88"),
                ("openmsx", "passes_path", "/userdata/bios/openmsx", f"{OPENMSX}:89"),
            ],
        )
        self.assertEqual(
            records[1]["passes_to"],
            "written: filepool add -path /userdata/bios/openmsx -types system_rom -position 2",
        )

    def test_a_saved_setting_hands_its_directory(self):
        amiberry = f"{GENERATORS}/amiberry/amiberryGenerator.py"
        text = placed({
            1: "from pathlib import Path\n_BIOS_DIR = Path('/userdata/bios/amiga')",
            10: "def generate():\n    amiberryconf.save('rom_path', _BIOS_DIR)",
        })
        (record,) = config_directories(configgen({amiberry: text}), ("amiberry.amiberryGenerator",))
        self.assertEqual(
            (record.search_dir, record.passes_to, record.source_ref),
            ("/userdata/bios/amiga", "rom_path", f"{amiberry}:11"),
        )

    def test_a_generator_handing_no_bios_directory_raises(self):
        cg = configgen({OPENMSX: "def generate():\n    file.write('savestate x')\n"})
        with self.assertRaises(LauncherShapeError):
            config_directories(cg, ("openmsx.openmsxGenerator",))


class ExtractionNeverEmpty(unittest.TestCase):
    def test_a_generator_of_unknown_shape_stops_the_whole_scrape(self):
        find = DUCKSTATION_FIND.replace("def find_bios(", "def locate_bios(")
        tree = {PATHS_MODULE: PATHS, IMPORTER: IMPORTER_TEXT, DUCKSTATION: duckstation_source(find=find)}
        with self.assertRaises(LauncherShapeError):
            extract_launchers(tree.__getitem__)

    def test_a_paths_module_without_bios_raises(self):
        tree = {PATHS_MODULE: "from pathlib import Path\n", IMPORTER: IMPORTER_TEXT}
        with self.assertRaises(LauncherShapeError):
            Configgen(tree.__getitem__)


class PlatformRecords(unittest.TestCase):
    """The launchers platforms/batocera.yml carries, as the scraper wrote them."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = yaml.safe_load((REPO_ROOT / "platforms" / "batocera.yml").read_text())
        cls.schema = json.loads((REPO_ROOT / "schemas" / "platform.schema.json").read_text())

    def test_every_emulator_is_one_batocera_names(self):
        cores = {*self.config["cores"], *self.config.get("standalone_cores", [])}
        named = {
            name for record in self.config["launchers"]
            for name in record["emulator"].split(", ")
        }
        self.assertEqual(sorted(named - cores), [])

    def test_every_reference_is_in_configgen(self):
        # Or in a patch Batocera applies to an emulator's own path code.
        from scraper.batocera_launchers import PATH_PATCHES

        for record in self.config["launchers"]:
            self.assertTrue(
                record["source_ref"].startswith((f"{CONFIGGEN}/", *PATH_PATCHES)), record
            )

    def test_the_schema_describes_what_the_scraper_writes(self):
        fields = {f.name for f in dataclasses.fields(Launcher)}
        described = set(self.schema["$defs"]["launcher"]["properties"])
        # package, repo and systems are written by package platforms (RetroPie).
        package_fields = {f.name for f in dataclasses.fields(PackageLauncher)} - {"lines"}
        self.assertEqual(sorted(fields - described), [])
        self.assertEqual(fields | package_fields, described)

    def test_the_wiki_names_every_launcher_field(self):
        page = (REPO_ROOT / "wiki" / "adding-a-platform.md").read_text(encoding="utf-8")
        described = self.schema["$defs"]["launcher"]["properties"]
        self.assertEqual(sorted(f for f in described if f"`{f}`" not in page), [])


if __name__ == "__main__":
    unittest.main()
