"""KNULLI's launcher layer, read from its configgen and board scripts.

The fixtures are cut-down copies of the blocks each extractor reads at
knulli-linux 20260511. Records must carry the names in the order the code
writes or tries them, cite the fixture's own lines, and a construct that is
gone must stop the scrape instead of returning nothing.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import textwrap
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from scraper import knulli_launchers as kl  # noqa: E402
from scraper.batocera_launchers import hatari, melonds  # noqa: E402
from scraper.configgen_launchers import LauncherShapeError  # noqa: E402

G = kl.GENERATORS


def text(block: str) -> str:
    return textwrap.dedent(block).lstrip("\n")


PATHS = text(
    """
    from pathlib import Path
    from typing import Final

    KNULLI_SHARE_DIR: Final = Path('/usr/share/knulli')
    DATAINIT_DIR: Final = KNULLI_SHARE_DIR / 'datainit'
    USERDATA: Final = Path('/userdata')
    HOME: Final = USERDATA / 'system'
    CONFIGS: Final = HOME / 'configs'
    BIOS: Final = USERDATA / 'bios'
    ROMS: Final = USERDATA / 'roms'
    """
)

IMPORTER = text(
    """
    from typing import Final

    _GENERATOR_MAP: Final[dict[str, tuple[str, str]]] = {
        'lexaloffle': ('lexaloffle.lexaloffleGenerator', 'LexaloffleGenerator'),
        'yabasanshiro': ('yabasanshiro.yabasanshiroGenerator', 'YabasanshiroGenerator'),
        'ryujinx': ('ryujinx.ryujinxGenerator', 'RyujinxGenerator'),
        'dolphin': ('dolphin.dolphinGenerator', 'DolphinGenerator'),
        'scummvm': ('scummvm.scummvmGenerator', 'ScummVMGenerator'),
        'openmsx': ('openmsx.openmsxGenerator', 'OpenmsxGenerator'),
        'hatari': ('hatari.hatariGenerator', 'HatariGenerator'),
        'melonds': ('melonds.melondsGenerator', 'MelonDSGenerator'),
        'pcsx2': ('pcsx2.pcsx2Generator', 'Pcsx2Generator'),
        'mame': ('mame.mameGenerator', 'MameGenerator'),
    }
    """
)

# lexaloffleGenerator.py: the binary constants, the system branches, the two
# checks that log and return, and the command.
LEXALOFFLE = text(
    """
    from ...batoceraPaths import BIOS, HOME, ROMS

    PICO8_BIN_PATH: Final = BIOS / "pico-8" / "pico8"
    VOX_BIN_PATH: Final = BIOS / "voxatron" / "vox"

    class LexaloffleGenerator(Generator):
        def generate(self, system, rom, playersControllers, metadata, guns, wheels, gameResolution):
            if (system.name == "pico8"):
                BIN_PATH=PICO8_BIN_PATH
            elif (system.name == "voxatron"):
                BIN_PATH=VOX_BIN_PATH
            else:
                return -1
            if not BIN_PATH.exists():
                eslog.error(f"Lexaloffle official binary not found at {BIN_PATH}")
                return -1
            if not os.access(BIN_PATH, os.X_OK):
                eslog.error(f"File {BIN_PATH} is not set as executable")
                return -1
            commandArray = [BIN_PATH]
            return Command.Command(array=commandArray, env={})
    """
)

# libretroOptions.py: one function of core blocks, the option or a literal.
OPTIONS = text(
    """
    def generateCoreSettings(coreSettings, system, rom, guns, wheels):
        if (system.config['core'] == 'o2em'):
            coreSettings.save('o2em_vkbd_transparency', '"25"')
            if system.isOptSet('o2em_bios'):
                coreSettings.save('o2em_bios', '"' + system.config['o2em_bios'] + '"')
            elif system.name == 'videopacplus':
                coreSettings.save('o2em_bios', '"g7400.bin"')
            else:
                coreSettings.save('o2em_bios', '"o2rom.bin"')
        if (system.config['core'] == 'neocd'):
            if system.isOptSet('neocd_bios'):
                coreSettings.save('neocd_bios', '"' + system.config['neocd_bios'] + '"')
            else:
                coreSettings.save('neocd_bios', '"neocd_z.rom (CDZ)"')
    """
)

PICO8 = text(
    """
    #!/bin/sh

    TARGET_DIR="/userdata/bios"
    PICO_DIR="$TARGET_DIR/pico-8"
    ROMS_DIR="/userdata/roms/pico8"
    TEMP_INSTALL_DIR="$ROMS_DIR/pico8-install"
    PICO_8_64_FILE="$TEMP_INSTALL_DIR/pico-8/pico8_64"
    PICO_8_DAT_FILE="$TEMP_INSTALL_DIR/pico-8/pico8.dat"
    PICO_8_ZIPFILE=$(ls -d /userdata/roms/pico8/pico-8*raspi*.zip 2>/dev/null | head -1)

    if [ -z $PICO_8_ZIPFILE ] || [ ! -f "$PICO_8_ZIPFILE" ]; then
      echo "Please add the Raspberry Pi version of Pico-8 to roms/pico8 and try again."
      exit 2
    fi

    mv $PICO_8_64_FILE "$PICO_DIR/pico8"
    mv $PICO_8_DAT_FILE "$PICO_DIR/"
    """
)

YABASANSHIRO = text(
    """
    from ...batoceraPaths import BIOS

    YABA_BIOS: Final = BIOS / "saturn_bios.bin"

    class YabasanshiroGenerator(Generator):
        def generate(self, system, rom, playersControllers, metadata, guns, wheels, gameResolution):
            commandArray = ["yabasanshiro", "-i", rom]

            if not (system.isOptSet('yaba_bios_hle') and system.config['yaba_bios_hle'] == '1'):
                if YABA_BIOS.exists():
                    commandArray[1:1] = ["-b", str(YABA_BIOS)]
            return Command.Command(array=commandArray)
    """
)

RYUJINX = text(
    """
    from ...batoceraPaths import BIOS, CONFIGS

    ryujinxConf: Final = CONFIGS / "Ryujinx"
    ryujinxKeys: Final = BIOS / "switch" / "prod.keys"

    class RyujinxGenerator(Generator):
        def generate(self, system, rom, playersControllers, metadata, guns, wheels, gameResolution):
            if ryujinxKeys.exists():
                shutil.copyfile(ryujinxKeys, ryujinxConf / "system" / "prod.keys")
    """
)

DOLPHIN_PATHS = text(
    """
    from ...batoceraPaths import BIOS

    DOLPHIN_BIOS: Final = BIOS / "GC"
    """
)

DOLPHIN = text(
    """
    from .dolphinPaths import DOLPHIN_BIOS

    class DolphinGenerator(Generator):
        def generate(self, system, rom, playersControllers, metadata, guns, wheels, gameResolution):
            if system.isOptSet("dolphin_SkipIPL") and system.getOptBoolean("dolphin_SkipIPL"):
                ipl_regions = ["USA", "EUR", "JAP"]
                if any((DOLPHIN_BIOS / region / "IPL.bin").exists() for region in ipl_regions):
                    dolphinSettings.set("Core", "SkipIPL", "False")
                else:
                    dolphinSettings.set("Core", "SkipIPL", "True")
    """
)

SCUMMVM = text(
    """
    from ...batoceraPaths import BIOS

    scummExtra: Final = BIOS / "scummvm" / "extra"

    class ScummVMGenerator(Generator):
        def generate(self, system, rom, playersControllers, metadata, guns, wheels, gameResolution):
            mkdir_if_not_exists(scummExtra)
            commandArray = ["/usr/bin/scummvm", "-f"]
            commandArray.extend(
                [f"--joystick={id}",
                f"--extrapath={scummExtra}",
                f"{romName}"]
            )
    """
)

OPENMSX = text(
    """
    class OpenmsxGenerator(Generator):
        def generate(self, system, rom, playersControllers, metadata, guns, wheels, gameResolution):
            with settings_tcl.open("a") as file:
                file.write("filepool add -path /userdata/bios/Machines -types system_rom -position 1\\n")
    """
)

LIBRETRO_CONFIG = text(
    """
    def writeLibretroConfigToFile(retroarchConfig, system, rom):
        if (system.config['core'] == 'puae') or (system.config['core'] == 'uae4arm'):
            retroarchConfig['system_directory'] = '"/userdata/bios/amiga/"'
        if system.config['core'] in [ 'mame', 'mess' ]:
            libretroMAMEConfig.generateMAMEConfigs(controllers, system, rom, guns)
    """
)

MAME_CONFIG = text(
    """
    from ...batoceraPaths import BIOS

    def generateMAMEConfigs(playersControllers, system, rom, guns):
        if system.name in [ 'mame', 'neogeo' ]:
            commandLine += [ '-rompath', f'"{rom.parent};/userdata/bios/mame/;/userdata/bios/"' ]
        if not system.isOptSet("sharemameart"):
            artPath = f"/usr/bin/mame/artwork/;{BIOS / 'mame' / 'artwork'}"
        else:
            artPath = f"/usr/bin/mame/artwork/"
        commandLine += [ '-artpath', artPath ]
        mkdir_if_not_exists(BIOS / "mame" / "samples")
    """
)

# hatariGenerator.py in KNULLI's older form: the language and model read
# with subscripts, the name built bare and joined to BIOS on the command line.
HATARI = text(
    """
    from ...batoceraPaths import BIOS

    class HatariGenerator(Generator):
        def generate(self, system, rom, playersControllers, metadata, guns, wheels, gameResolution):
            model_mapping = {"520st_auto": { "machine": "st", "tos": "auto" }}
            commandArray = ["hatari", "--fullscreen"]
            machine = "st"
            tosversion = "auto"
            if system.isOptSet("model") and system.config["model"] in model_mapping:
                machine   = model_mapping[system.config["model"]]["machine"]
                tosversion = model_mapping[system.config["model"]]["tos"]
            toslang = "us"
            if system.isOptSet("language"):
                toslang = system.config["language"]
            commandArray += ["--machine", machine]
            tos = HatariGenerator.findBestTos(BIOS, machine, tosversion, toslang)
            commandArray += [ "--tos", BIOS / tos]

        @staticmethod
        def findBestTos(biosdir, machine, tos_version, language) -> str:
            all_languages = ["us", "uk", ""]
            all_machines_bios = {
                "st":      ["etos256", "104"],
            }
            if machine in all_machines_bios:
                for v_tos_version in l_tos:
                    for v_language in l_lang:
                        if "etos" in v_tos_version:
                            biosversion = v_tos_version
                        else:
                            biosversion = f"tos{v_tos_version}"
                        filename = f"{biosversion}{v_language}.img"
                        if os.path.exists(f"{biosdir}/{filename}"):
                            return filename
            raise Exception(f"no bios found for machine {machine}")
    """
)

MELONDS = text(
    """
    from ...batoceraPaths import BIOS

    class MelonDSGenerator(Generator):
        def generate(self, system, rom, playersControllers, metadata, guns, wheels, gameResolution):
            base_config = {
                "DS": {
                    "FirmwarePath": str(BIOS / "firmware.bin"),
                    "BIOS7Path": str(BIOS / "bios7.bin"),
                },
                "Emu": {
                    "ExternalBIOSEnable": True
                },
            }
            if system.isOptSet("melonds_console"):
                base_config["Emu"]["ConsoleType"] = int(system.config["melonds_console"])
            else:
                base_config["Emu"]["ConsoleType"] = 0
    """
)


# pcsx2Generator.py: the default patches copied into BIOS when absent, and
# the BIOS folder written relative to the config folder.
PCSX2 = text(
    """
    from ...batoceraPaths import BIOS, CONFIGS, DATAINIT_DIR

    _PCSX2_CONFIG: Final = CONFIGS / "PCSX2"
    _PCSX2_BIOS: Final = BIOS / "ps2"

    class Pcsx2Generator(Generator):
        def generate(self, system, rom, playersControllers, metadata, guns, wheels, gameResolution):
            pcsx2Patches = _PCSX2_BIOS / "patches.zip"
            configureINI(_PCSX2_CONFIG, _PCSX2_BIOS, system)
            if not pcsx2Patches.exists():
                shutil.copy(DATAINIT_DIR / "bios" / "ps2" / "patches.zip", pcsx2Patches)

    def configureINI(config_directory, bios_directory, system):
        configFileName = config_directory / 'inis' / "PCSX2.ini"
        pcsx2INIConfig.set("Folders", "Bios", "../../../bios/ps2")
        pcsx2INIConfig.set("Folders", "Logs", "../../logs")
    """
)

# mameGenerator.py: the Macintosh boot disk named from the bootdisk option.
MAME = text(
    """
    class MameGenerator(Generator):
        def generate(self, system, rom, playersControllers, metadata, guns, wheels, gameResolution):
            if system.name == "macintosh" and system.isOptSet("bootdisk"):
                if system.config["bootdisk"] in [ "macos30", "macos608" ]:
                    bootType = "-flop1"
                    bootDisk = "/userdata/bios/" + system.config["bootdisk"] + ".img"
                else:
                    bootType = "-hard"
                    bootDisk = "/userdata/bios/" + system.config["bootdisk"] + ".chd"
                commandArray += [ bootType, bootDisk ]
    """
)

FEATURES = text(
    """
    mame:
        systems:
            macintosh:
                cfeatures:
                    bootdisk:
                        prompt: BOOT DISK
                        choices:
                            "System 3.0 (LD Floppy)":    macos3
                            "System 6.0.8 (LD Floppy)":  macos608
                            "System 7.5.5 (Hard Drive)": mac755
    """
)


def tree(**overrides: str) -> dict[str, str]:
    files = {
        f"{kl.CONFIGGEN}/batoceraPaths.py": PATHS,
        f"{G}/importer.py": IMPORTER,
        f"{G}/lexaloffle/lexaloffleGenerator.py": LEXALOFFLE,
        kl.LIBRETRO_OPTIONS: OPTIONS,
        kl.PICO8_INSTALLER: PICO8,
        f"{G}/yabasanshiro/yabasanshiroGenerator.py": YABASANSHIRO,
        f"{G}/ryujinx/ryujinxGenerator.py": RYUJINX,
        f"{G}/dolphin/dolphinPaths.py": DOLPHIN_PATHS,
        f"{G}/dolphin/dolphinGenerator.py": DOLPHIN,
        f"{G}/scummvm/scummvmGenerator.py": SCUMMVM,
        f"{G}/openmsx/openmsxGenerator.py": OPENMSX,
        f"{G}/libretro/libretroConfig.py": LIBRETRO_CONFIG,
        f"{G}/libretro/libretroMAMEConfig.py": MAME_CONFIG,
        f"{G}/hatari/hatariGenerator.py": HATARI,
        f"{G}/melonds/melondsGenerator.py": MELONDS,
        f"{G}/pcsx2/pcsx2Generator.py": PCSX2,
        f"{G}/mame/mameGenerator.py": MAME,
        kl.ES_FEATURES: FEATURES,
    }
    files.update(overrides)
    return files


def configgen(**overrides: str) -> kl.Configgen:
    files = tree(**overrides)
    return kl.configgen(files.__getitem__)


def sites(path: str, kind: str, **fields: object) -> list[dict]:
    spec = kl.GenericSites(path, kind, **fields)  # type: ignore[arg-type]
    return [launcher.entry() for launcher in kl.bios_sites(configgen(), spec)]


class SharedExtractors(unittest.TestCase):
    """Batocera's extractors read KNULLI's older generator forms."""

    def test_hatari_with_a_bare_name_joined_to_bios(self):
        (st,) = hatari(configgen())
        self.assertEqual(st.names, ["etos256{L}.img", "tos104{L}.img"])
        self.assertEqual(st.expands, {"L": ["us", "uk", ""]})
        self.assertEqual(st.passes_to, "--machine st --tos <file>")
        self.assertEqual(st.fails_when_missing, "no bios found for machine st")
        self.assertEqual(st.depends_on_option, "model, language")
        self.assertTrue(st.source_ref.startswith(f"{G}/hatari/hatariGenerator.py:"))

    def test_hatari_reads_the_knulli_package(self):
        (st,) = hatari(configgen())
        self.assertNotIn("package/batocera", st.source_ref)

    def test_hatari_name_built_another_way_raises(self):
        broken = HATARI.replace('filename = f"{biosversion}{v_language}.img"', "filename = x")
        with self.assertRaises(LauncherShapeError):
            hatari(configgen(**{f"{G}/hatari/hatariGenerator.py": broken}))

    def test_melonds_console_read_by_subscript(self):
        (ds,) = melonds(configgen())
        self.assertEqual(ds.names, ["firmware.bin", "bios7.bin"])
        self.assertEqual(ds.depends_on_option, "melonds_console")
        self.assertEqual(ds.source_ref, f"{G}/melonds/melondsGenerator.py:6-12, 15")

    def test_a_configgen_without_the_plain_map_raises(self):
        with self.assertRaises(LauncherShapeError):
            configgen(**{f"{G}/importer.py": "X = 1\n"})


class Lexaloffle(unittest.TestCase):
    def test_each_system_runs_its_binary(self):
        pico8, vox = kl.lexaloffle(configgen())
        self.assertEqual((pico8.slot, pico8.names), ("pico8", ["pico-8/pico8"]))
        self.assertEqual((vox.slot, vox.names), ("voxatron", ["voxatron/vox"]))
        self.assertEqual(pico8.search_dir, "/userdata/bios")
        self.assertEqual(pico8.passes_to, "exec")

    def test_the_two_checks_are_the_failure(self):
        pico8, _ = kl.lexaloffle(configgen())
        self.assertEqual(
            pico8.fails_when_missing,
            "Lexaloffle official binary not found at /userdata/bios/pico-8/pico8, "
            "File /userdata/bios/pico-8/pico8 is not set as executable",
        )

    def test_the_lines_cited(self):
        pico8, vox = kl.lexaloffle(configgen())
        path = f"{G}/lexaloffle/lexaloffleGenerator.py"
        self.assertEqual(pico8.source_ref, f"{path}:3, 8-9, 14-20")
        self.assertEqual(vox.source_ref, f"{path}:4, 10-11, 14-20")

    def test_a_raise_in_place_of_the_log_raises(self):
        broken = LEXALOFFLE.replace(
            'eslog.error(f"Lexaloffle official binary not found at {BIN_PATH}")\n            return -1',
            'raise BatoceraException(f"Lexaloffle official binary not found at {BIN_PATH}")',
        )
        with self.assertRaises(LauncherShapeError):
            kl.lexaloffle(configgen(**{f"{G}/lexaloffle/lexaloffleGenerator.py": broken}))


class PicoInstaller(unittest.TestCase):
    def test_the_files_moved_into_bios(self):
        (record,) = kl.pico8_installer(tree().__getitem__, "/userdata/bios")
        self.assertEqual(record.kind, "moves")
        self.assertEqual(record.names, ["pico-8/pico8", "pico-8/pico8.dat"])
        self.assertEqual(
            record.passes_to,
            "moved from /userdata/roms/pico8/pico-8*raspi*.zip into /userdata/bios/pico-8",
        )
        self.assertEqual(
            record.fails_when_missing,
            "Please add the Raspberry Pi version of Pico-8 to roms/pico8 and try again.",
        )
        self.assertEqual(record.source_ref, f"{kl.PICO8_INSTALLER}:3-12, 16-17")

    def test_an_installer_that_moves_nothing_into_bios_raises(self):
        broken = PICO8.replace('"$PICO_DIR/', '"/tmp/')
        with self.assertRaises(LauncherShapeError):
            kl.pico8_installer(tree(**{kl.PICO8_INSTALLER: broken}).__getitem__, "/userdata/bios")


class CoreFileOptions(unittest.TestCase):
    def test_option_then_literal_defaults(self):
        o2em, neocd = kl.core_file_options(configgen())
        self.assertEqual(o2em.emulator, "o2em")
        self.assertEqual(o2em.names, ["g7400.bin", "o2rom.bin"])
        self.assertEqual(o2em.depends_on_option, "o2em_bios (default by system.name == 'videopacplus')")
        self.assertEqual(o2em.source_ref, f"{kl.LIBRETRO_OPTIONS}:2, 4-9")
        self.assertEqual((neocd.names, neocd.depends_on_option), (["neocd_z.rom (CDZ)"], "neocd_bios"))

    def test_a_default_that_is_no_literal_raises(self):
        broken = OPTIONS.replace("'\"o2rom.bin\"'", "default_bios")
        with self.assertRaises(LauncherShapeError):
            kl.core_file_options(configgen(**{kl.LIBRETRO_OPTIONS: broken}))


class BiosSites(unittest.TestCase):
    def test_a_flag_on_the_command_line_under_a_presence_test(self):
        (record,) = sites("yabasanshiro/yabasanshiroGenerator.py", "fixed_name")
        self.assertEqual(record["names"], ["saturn_bios.bin"])
        self.assertEqual(record["passes_to"], "command line -b")
        self.assertEqual(
            record["depends_on_option"],
            "not (system.isOptSet('yaba_bios_hle') and system.config['yaba_bios_hle'] == '1')",
        )
        self.assertEqual(record["source_ref"], f"{G}/yabasanshiro/yabasanshiroGenerator.py:9-11")

    def test_a_copy_out_of_bios(self):
        (record,) = sites("ryujinx/ryujinxGenerator.py", "fixed_name")
        self.assertEqual(record["kind"], "copies")
        self.assertEqual(record["names"], ["switch/prod.keys"])
        self.assertEqual(record["search_dir"], "/userdata/bios")
        self.assertEqual(record["passes_to"], "/userdata/system/configs/Ryujinx/system/prod.keys")
        self.assertEqual(record["depends_on_option"], "ryujinxKeys.exists()")

    def test_a_presence_test_over_a_literal_list(self):
        (record,) = sites("dolphin/dolphinGenerator.py", "fixed_name")
        self.assertEqual(record["names"], ["GC/{region}/IPL.bin"])
        self.assertEqual(record["expands"], {"region": ["USA", "EUR", "JAP"]})
        self.assertEqual(record["passes_to"], "presence sets [Core] SkipIPL = False")
        self.assertEqual(record["source_ref"], f"{G}/dolphin/dolphinGenerator.py:5, 7-8")

    def test_a_flag_written_into_the_argument(self):
        (record,) = sites("scummvm/scummvmGenerator.py", "passes_path")
        self.assertEqual(record["search_dir"], "/userdata/bios/scummvm/extra")
        self.assertEqual(record["passes_to"], "command line --extrapath")

    def test_a_line_written_to_a_config(self):
        (record,) = sites("openmsx/openmsxGenerator.py", "passes_path")
        self.assertEqual(record["search_dir"], "/userdata/bios/Machines")
        self.assertTrue(record["passes_to"].startswith("written: filepool add -path"))

    def test_a_core_test_names_the_emulator(self):
        (record,) = sites("libretro/libretroConfig.py", "passes_path", build="libretro")
        self.assertEqual(record["emulator"], "puae, uae4arm")
        self.assertEqual(record["passes_to"], "system_directory")

    def test_a_helper_takes_the_cores_of_its_caller(self):
        records = sites(
            "libretro/libretroMAMEConfig.py", "passes_path", build="libretro",
            caller=("libretro/libretroConfig.py", "generateMAMEConfigs"),
        )
        self.assertEqual({r["emulator"] for r in records}, {"mame, mess"})
        # The else branch binds an art path outside /userdata/bios: no record.
        rompath, art = records
        self.assertEqual(rompath["search_dir"], "<rom.parent>;/userdata/bios/mame/;/userdata/bios/")
        self.assertEqual(rompath["passes_to"], "command line -rompath")
        self.assertEqual(art["search_dir"], "/usr/bin/mame/artwork/;/userdata/bios/mame/artwork")
        self.assertEqual(art["depends_on_option"], "not system.isOptSet('sharemameart')")
        self.assertEqual(art["source_ref"], f"{G}/libretro/libretroMAMEConfig.py:6-7, 10")

    def test_a_generator_without_a_bios_path_raises(self):
        files = tree(**{f"{G}/openmsx/openmsxGenerator.py": "def generate():\n    return 1\n"})
        spec = kl.GenericSites("openmsx/openmsxGenerator.py", "passes_path")
        with self.assertRaises(LauncherShapeError):
            kl.bios_sites(kl.configgen(files.__getitem__), spec)


class CopiesAndFolders(unittest.TestCase):
    def test_a_copy_into_bios_reads_from_the_folder_it_comes_from(self):
        (record,) = sites("pcsx2/pcsx2Generator.py", "fixed_name")
        self.assertEqual(record["kind"], "copies")
        self.assertEqual(record["names"], ["patches.zip"])
        self.assertEqual(record["search_dir"], "/usr/share/knulli/datainit/bios/ps2")
        self.assertEqual(record["passes_to"], "/userdata/bios/ps2/patches.zip")
        self.assertEqual(record["depends_on_option"], "not pcsx2Patches.exists()")

    def test_a_relative_folder_resolved_against_the_config_folder(self):
        (record,) = kl.relative_folders(configgen(), kl.RELATIVE_FOLDERS[:1])
        self.assertEqual(record.kind, "passes_path")
        self.assertEqual(record.search_dir, "/userdata/bios/ps2")
        self.assertEqual(
            record.passes_to,
            "inis/PCSX2.ini [Folders] Bios = ../../../bios/ps2, relative to /userdata/system/configs/PCSX2",
        )
        self.assertEqual(record.source_ref, f"{G}/pcsx2/pcsx2Generator.py:9, 14-15")

    def test_a_folder_written_outside_bios_raises(self):
        broken = PCSX2.replace("../../../bios/ps2", "../../../saves/ps2")
        with self.assertRaises(LauncherShapeError):
            kl.relative_folders(
                configgen(**{f"{G}/pcsx2/pcsx2Generator.py": broken}), kl.RELATIVE_FOLDERS[:1]
            )


class BootDisks(unittest.TestCase):
    def records(self, **overrides: str) -> list:
        files = tree(**overrides)
        return kl.boot_disks(kl.configgen(files.__getitem__), files.__getitem__, kl.BOOT_DISKS[:1])

    def test_each_branch_is_a_template_over_the_values_that_reach_it(self):
        floppy, hard = self.records()
        self.assertEqual((floppy.names, floppy.passes_to), (["{bootdisk}.img"], "command line -flop1"))
        self.assertEqual(floppy.expands, {"bootdisk": ["macos30", "macos608"]})
        # The values the menu offers that the code's list does not take.
        self.assertEqual((hard.names, hard.passes_to), (["{bootdisk}.chd"], "command line -hard"))
        self.assertEqual(hard.expands, {"bootdisk": ["macos3", "mac755"]})
        self.assertTrue(hard.depends_on_option.startswith("bootdisk (system.name == 'macintosh'"))
        # The menu's values are where the choices come from, the generator
        # writing the choice is the evidence.
        self.assertEqual(hard.source_ref, f"{G}/mame/mameGenerator.py:3-4, 9-10")
        self.assertEqual(hard.choices_from, f"{kl.ES_FEATURES}:8-10")
        self.assertIsNone(floppy.choices_from)

    def test_a_name_built_another_way_raises(self):
        broken = MAME.replace('"/userdata/bios/" + system.config["bootdisk"] + ".chd"', "disk")
        with self.assertRaises(LauncherShapeError):
            self.records(**{f"{G}/mame/mameGenerator.py": broken})

    def test_an_option_the_menu_no_longer_offers_raises(self):
        with self.assertRaises(LauncherShapeError):
            self.records(**{kl.ES_FEATURES: FEATURES.replace("bootdisk:", "other:")})


class PlatformFile(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = yaml.safe_load((REPO_ROOT / "platforms" / "knulli.yml").read_text())

    def test_the_layer_is_written(self):
        self.assertTrue(self.config["launchers"])

    def test_every_reference_is_in_knulli_code(self):
        for record in self.config["launchers"]:
            # Or in Batocera's patches, read from KNULLI's batocera submodule.
            self.assertTrue(
                record["source_ref"].startswith((
                    f"{kl.CONFIGGEN}/", kl.PICO8_INSTALLER,
                    *(f"{kl.BATOCERA_SUBMODULE}/{patch}" for patch in kl.PATH_PATCHES),
                )), record
            )

    def test_every_emulator_is_one_knulli_names(self):
        cores = {*self.config["cores"], *self.config.get("standalone_cores", [])}
        named = {n for record in self.config["launchers"] for n in record["emulator"].split(", ")}
        # RetroArch itself, and the MAME core names configgen tests that
        # KNULLI's es_systems.yml never offers.
        self.assertEqual(sorted(named - cores), ["mamevirtual", "mess", "retroarch"])


if __name__ == "__main__":
    unittest.main()
