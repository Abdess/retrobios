#!/usr/bin/env python3
"""Recalbox's launcher layer, read from configgen with ast.

The blocks below are copied from Recalbox 10.1.1 (projects/configgen) and
placed at the lines they hold there, so the source_ref an extraction writes
is checked against the tag itself.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import sys
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from scraper import recalbox_scraper  # noqa: E402
from scraper.recalbox_launchers import (  # noqa: E402
    ALL_CORES,
    AMIBERRY_CONFIG,
    AMIBERRY_GLOBAL,
    AMIBERRY_KICKSTARTS,
    AMIBERRY_SUBSYSTEMS,
    CONFIGGEN,
    CORES,
    DOLPHIN,
    FILES_MODULE,
    GSPLUS,
    HATARI,
    LAUNCHER,
    LIBRETRO_GENERATOR,
    MUPEN_CONFIG,
    PCSX2,
    RETROARCH,
    SOURCE_FILES,
    XEMU,
    XROAR,
    Configgen,
    Launcher,
    LauncherShapeError,
    amiberry,
    content_files,
    core_assets,
    core_file_options,
    dolphin,
    extract_launchers,
    gsplus,
    hatari,
    hatari_libretro,
    mupen64plus,
    pcsx2,
    system_directories,
    xemu,
    xroar,
)

from tests.test_launchers import placed  # noqa: E402

# recalboxFiles.py:1-12, 173-174
FILES_MODULE_BLOCKS = {
    1: """#!/usr/bin/env python
HOME_INIT = '/recalbox/share_init/system/'
HOME = '/recalbox/share/system'
CONF = HOME + '/configs'
SAVES = '/recalbox/share/saves'
SAVES_INIT = '/recalbox/share_init/saves'
SCREENSHOTS = '/recalbox/share/screenshots'
BIOS = '/recalbox/share/bios'
BIOS_INIT = '/recalbox/share_init/bios'
OVERLAYS = '/recalbox/share/overlays'
RECALBOX_OVERLAYS = '/recalbox/share_init/overlays'
RECALBOX_240P_OVERLAYS = '/recalbox/share_init/240poverlays'""",
    173: """minivmacRomFile = '/tmp/minivmac.cmd'
minivmacOsFile = BIOS + '/macintosh/MinivMacBootv2.dsk'""",
}

# emulatorlauncher.py:10-19, 29-34, 47-52, 65-67, 80-82, 125-127, 131-136
LAUNCHER_BLOCKS = {
    10: '''def getGenerator(emulator):

    # We use a if...elif...else structure in order to instantiate the strict minimum required for an emulator
    # and minimize static imports that are very time consuming, specially on low-end boards
    if emulator == "advancemame":
        module = __import__("configgen.generators.advancemame.advMameGenerator", fromlist=["AdvMameGenerator"])
        generatorClass = getattr(module, "AdvMameGenerator")
    elif emulator == "amiberry":
        module = __import__("configgen.generators.amiberry.amiberryGenerator", fromlist=["AmiberryGenerator"])
        generatorClass = getattr(module, "AmiberryGenerator")''',
    29: '''    elif emulator == "dolphin":
        module = __import__("configgen.generators.dolphin.dolphinGenerator", fromlist=["DolphinGenerator"])
        generatorClass = getattr(module, "DolphinGenerator")
    elif emulator == "dolphin-gui":
        module = __import__("configgen.generators.dolphin.dolphinGenerator", fromlist=["DolphinGenerator"])
        generatorClass = getattr(module, "DolphinGenerator")''',
    47: '''    elif emulator == "gsplus":
        module = __import__("configgen.generators.gsplus.gsplusGenerator", fromlist=["GSplusGenerator"])
        generatorClass = getattr(module, "GSplusGenerator")
    elif emulator == "hatari":
        module = __import__("configgen.generators.hatari.hatariGenerator", fromlist=["HatariGenerator"])
        generatorClass = getattr(module, "HatariGenerator")''',
    65: '''    elif emulator == "mupen64plus":
        module = __import__("configgen.generators.mupen.mupenGenerator", fromlist=["MupenGenerator"])
        generatorClass = getattr(module, "MupenGenerator")''',
    80: '''    elif emulator == "pcsx2":
        module = __import__("configgen.generators.pcsx2.pcsx2Generator", fromlist=["Pcsx2Generator"])
        generatorClass = getattr(module, "Pcsx2Generator")''',
    122: '''    elif emulator == "xroar":
        module = __import__("configgen.generators.xroar.xroarGenerator", fromlist=["XroarGenerator"])
        generatorClass = getattr(module, "XroarGenerator")''',
    125: '''    elif emulator == "xemu":
        module = __import__("configgen.generators.xemu.xemuGenerator", fromlist=["XemuGenerator"])
        generatorClass = getattr(module, "XemuGenerator")''',
    131: '''    else:
        print("Missing generator for {}".format(emulator))
        raise ValueError
        pass

    return generatorClass()''',
}

# libretroRetroarch.py:1-11, 251-253, 421-529
RETROARCH_BLOCKS = {
    1: '''from typing import List

import configgen.recalboxFiles as recalboxFiles
from configgen.Emulator import Emulator
from configgen.controllers.controller import ControllerPerPlayer
from configgen.settings.keyValueSettings import keyValueSettings
from configgen.generators.libretro.libretroChallengeLock import ChallengeLock
from configgen.utils.architecture import Architecture


class LibretroRetroarch:''',
    251: '''    # Fill retroarch configuration
    def fillRetroarchConfiguration(self):
        settings: keyValueSettings = self.settings''',
    421: '''
        # Core assets path for dolphin only
        if self.system.Core == "dolphin":
            settings.setString("core_assets_directory", "/recalbox/share/bios/dolphin-emu/")
        else:
            settings.removeOption("core_assets_directory")

        # Audio buffer (naomi2 anti-crackle, HDMI + CRT)
        self.manage_audio_buffer(settings)

        # Use bios in directories
        # Most of the case are by core name
        match self.system.Core:
            case 'a5200':
                settings.setString("system_directory", recalboxFiles.BIOS + "/atari5200")
            case 'bsnes':
                if self.system.Name == 'gb' or self.system.Name == 'gbc':
                    settings.setString("system_directory", recalboxFiles.BIOS + "/sgb")
                elif self.system.Name == 'satellaview':
                    settings.setString("system_directory", recalboxFiles.BIOS + "/satellaview")
                else:
                    settings.setString("system_directory", recalboxFiles.BIOS)
            case 'bsneshd':
                if self.system.Name == 'gb' or self.system.Name == 'gbc':
                    settings.setString("system_directory", recalboxFiles.BIOS + "/sgb")
                elif self.system.Name == 'satellaview':
                    settings.setString("system_directory", recalboxFiles.BIOS + "/satellaview")
                else:
                    settings.setString("system_directory", recalboxFiles.BIOS)
            case 'cdi2015':
                settings.setString("system_directory", recalboxFiles.BIOS + "/cdi")
            case 'dolphin':
                settings.setString("system_directory", recalboxFiles.BIOS + "/gamecube")
            case 'emuscv':
                settings.setString("system_directory", recalboxFiles.BIOS + "/scv")
            case 'fmsx':
                settings.setString("system_directory", recalboxFiles.BIOS + "/msx")
            case 'freechaf':
                settings.setString("system_directory", recalboxFiles.BIOS + "/channelf")
            case 'freeintv':
                settings.setString("system_directory", recalboxFiles.BIOS + "/intellivision")
            case 'gambatte':
                settings.setString("system_directory", recalboxFiles.BIOS + "/" + self.system.Name)
            case 'gearsystem':
                settings.setString("system_directory", recalboxFiles.BIOS + "/" + self.system.Name)
            case 'genesisplusgx':
                settings.setString("system_directory", recalboxFiles.BIOS + "/" + self.system.Name)
            case 'genesisplusgxwide':
                settings.setString("system_directory", recalboxFiles.BIOS + "/" + self.system.Name)
            case 'geolith':
                settings.setString("system_directory", recalboxFiles.BIOS + "/geolith")
            case 'gpsp':
                settings.setString("system_directory", recalboxFiles.BIOS + "/gba")
            case 'mednafen_pce_fast':
                settings.setString("system_directory", recalboxFiles.BIOS + "/" + self.system.Name)
            case 'mednafen_pcfx':
                settings.setString("system_directory", recalboxFiles.BIOS + "/pcfx")
            case 'mednafen_supergrafx':
                settings.setString("system_directory", recalboxFiles.BIOS + "/" + self.system.Name)
            case 'geargrafx':
                settings.setString("system_directory", recalboxFiles.BIOS + "/pcenginecd")
            case 'mesen_s':
                if self.system.SuperGameBoy:
                    settings.setString("system_directory", recalboxFiles.BIOS + "/sgb")
                else:
                    settings.setString("system_directory", recalboxFiles.BIOS + "/" + self.system.Name)
            case 'minivmac':
                settings.setString("system_directory", recalboxFiles.BIOS + "/macintosh")
            case 'mu':
                settings.setString("system_directory", recalboxFiles.BIOS + "/palm")
            case 'o2em':
                settings.setString("system_directory", recalboxFiles.BIOS + "/o2em")
            case 'opera':
                settings.setString("system_directory", recalboxFiles.BIOS + "/3do")
            case 'picodrive':
                settings.setString("system_directory", recalboxFiles.BIOS + "/" + self.system.Name)
            case 'pokemini':
                settings.setString("system_directory", recalboxFiles.BIOS + "/pokemini")
            case 'prosystem':
                settings.setString("system_directory", recalboxFiles.BIOS + "/atari7800")
            case 'sameboy':
                if self.system.SuperGameBoy:
                    settings.setString("system_directory", recalboxFiles.BIOS + "/sgb")
                else:
                    settings.setString("system_directory", recalboxFiles.BIOS + "/" + self.system.Name)
            case 'snes9x':
                if self.system.Name == 'satellaview':
                    settings.setString("system_directory", recalboxFiles.BIOS + "/satellaview")
                elif self.system.Name == 'sufami':
                    settings.setString("system_directory", recalboxFiles.BIOS + "/sufami")
                else:
                    settings.setString("system_directory", recalboxFiles.BIOS)
            case _:
                settings.setString("system_directory", recalboxFiles.BIOS)

        # We have a few to use by system name - when there are multiple cores with same bios
        amigaSystems = ["amiga600", "amiga1200", "amigacdtv", "amigacd32"]
        if self.system.Name in amigaSystems:
            settings.setString("system_directory", recalboxFiles.BIOS + "/amiga/bios")
        elif self.system.Name == 'fds':
            settings.setString("system_directory", recalboxFiles.BIOS + "/fds")
        elif self.system.Name == 'lynx':
            settings.setString("system_directory", recalboxFiles.BIOS + "/lynx")
        elif self.system.Name == 'nds':
            settings.setString("system_directory", recalboxFiles.BIOS + "/nds")
        elif self.system.Name == 'saturn':
            settings.setString("system_directory", recalboxFiles.BIOS + "/saturn")
        elif self.system.Name == 'stv':
            settings.setString("system_directory", recalboxFiles.BIOS + "/stv")''',
}

# libretroCores.py:1-17, 165-298, 348-355, 492-504, 633-705
CORES_BLOCKS = {
    1: '''from typing import Dict
from configgen.Emulator import Emulator
from configgen.crt.CRTTypes import CRTAdapter
from configgen.settings.keyValueSettings import keyValueSettings
from configgen.controllers.controller import ControllerPerPlayer
from configgen.utils.architecture import Architecture


def _jvsCabFamily() -> str:
    try:
        with open("/sys/devices/platform/recalboxjvs/cab_family") as f:
            return f.read().strip()
    except OSError:
        return ""


class LibretroCores:''',
    165: r'''    def configureAtariSTNew(self, coreSettings: keyValueSettings):
        # Machine list as defined in HatariB core
        MACHINE_UNKNOWN = -1
        MACHINE_ST = 0
        MACHINE_MEGA_ST = 1
        MACHINE_STE = 2
        MACHINE_MEGA_STE = 3
        MACHINE_TT = 4
        MACHINE_FALCON = 5

        # Try identify machine folder
        machines: dict[str, int] = \
        {
            "atari-st": MACHINE_ST,
            "/st/": MACHINE_ST,
            "atarimegast": MACHINE_MEGA_ST,
            "atari-megast": MACHINE_MEGA_ST,
            "atari-mega-st": MACHINE_MEGA_ST,
            "megast": MACHINE_MEGA_ST,
            "mega-st": MACHINE_MEGA_ST,
            "atariste": MACHINE_STE,
            "atari-ste": MACHINE_STE,
            "/ste/": MACHINE_STE,
            "atarimegaste": MACHINE_MEGA_STE,
            "atari-megaste": MACHINE_MEGA_STE,
            "atari-mega-ste": MACHINE_MEGA_STE,
            "megaste": MACHINE_MEGA_STE,
            "mega-ste": MACHINE_MEGA_STE,
            "ataritt": MACHINE_TT,
            "atari-tt": MACHINE_TT,
            "/tt/": MACHINE_TT,
            "falcon": MACHINE_FALCON,
            "atari-falcon": MACHINE_FALCON,
        }
        defaultMachine: int = MACHINE_UNKNOWN
        romLower: str = self.rom.lower()
        for key in machines:
            if key in romLower:
                defaultMachine: int = machines[key]
                break
        if not defaultMachine == MACHINE_UNKNOWN:
            coreSettings.setInt("hatarib_machine", defaultMachine)
            print("MACHINE: {}".format(defaultMachine))
        else:
            defaultMachine = coreSettings.getInt("hatarib_machine", MACHINE_ST)

        # Select bios
        subdir: str = "atarist"
        import os
        biosFile = os.path.join(subdir, "st.img")
        # ST/MEGAST use both st.img
        if   defaultMachine == MACHINE_FALCON  : biosFile = os.path.join(subdir, "falcon.img")
        elif defaultMachine == MACHINE_MEGA_STE: biosFile = os.path.join(subdir, "megaste.img")
        elif defaultMachine == MACHINE_TT      : biosFile = os.path.join(subdir, "tt.img")
        elif defaultMachine == MACHINE_STE     : biosFile = os.path.join(subdir, "ste.img")
        import configgen.recalboxFiles as recalboxFiles
        if not os.path.exists(os.path.join(recalboxFiles.BIOS, biosFile)):
            biosFile = os.path.join(subdir, "tos.img")
            if not os.path.exists(os.path.join(recalboxFiles.BIOS, biosFile)):
                biosFile = "tos.img"
                if not os.path.exists(os.path.join(recalboxFiles.BIOS, biosFile)):
                    biosFile = "<etos1024k>"
        if "emutos" in self.rom:
            biosFile = os.path.join(recalboxFiles.BIOS, subdir, "<etos1024k>")
        coreSettings.setString("hatarib_tos", str(biosFile))
        print("BIOS   : {}".format(biosFile))

    def configureAtariST(self, _):
        # Machines as defined in old Hatari core
        MACHINE_UNKNOWN = -1
        MACHINE_ST = 0
        MACHINE_STE = 1
        MACHINE_TT = 2
        MACHINE_FALCON = 3,
        MACHINE_MEGA_STE = 4

        # Load config
        from configgen.settings.iniSettings import IniSettings
        import configgen.recalboxFiles as recalboxFiles
        atariStSettings = IniSettings(recalboxFiles.hatariCustomConfig)
        atariStSettings.loadFile(True)

        # Auto set machine
        from typing import Dict
        # Try identify machine folder
        machines: Dict[str, int] = \
        {
            "atari-st": MACHINE_ST,
            "/st/": MACHINE_ST,
            "atariste": MACHINE_STE,
            "atari-ste": MACHINE_STE,
            "/ste/": MACHINE_STE,
            "ataritt": MACHINE_TT,
            "atari-tt": MACHINE_TT,
            "/tt/": MACHINE_TT,
            "atarimegaste": MACHINE_MEGA_STE,
            "atari-megaste": MACHINE_MEGA_STE,
            "atari-mega-ste": MACHINE_MEGA_STE,
            "megaste": MACHINE_MEGA_STE,
            "mega-ste": MACHINE_MEGA_STE,
            "falcon": MACHINE_FALCON,
            "atari-falcon": MACHINE_FALCON,
        }
        defaultMachine: int = MACHINE_UNKNOWN
        romLower: str = self.rom.lower()
        for key in machines:
            if key in romLower:
                defaultMachine: int = machines[key]
                break
        if not defaultMachine == MACHINE_UNKNOWN:
            print("MACHINE: {}".format(defaultMachine))
            atariStSettings.setString("System", "nMachineType", str(defaultMachine))

        # Select bios
        import os
        subdir: str = "atarist"
        biosPath = os.path.join(recalboxFiles.BIOS, subdir, "st.img")
        if   defaultMachine == MACHINE_STE     : biosPath = os.path.join(recalboxFiles.BIOS, subdir, "ste.img")
        elif defaultMachine == MACHINE_TT      : biosPath = os.path.join(recalboxFiles.BIOS, subdir, "tt.img")
        elif defaultMachine == MACHINE_MEGA_STE: biosPath = os.path.join(recalboxFiles.BIOS, subdir, "megaste.img")
        elif defaultMachine == MACHINE_FALCON  : biosPath = os.path.join(recalboxFiles.BIOS, subdir, "falcon.img")
        if not os.path.exists(biosPath):
            biosPath = os.path.join(recalboxFiles.BIOS, subdir, "tos.img")
            if not os.path.exists(biosPath):
                biosPath = os.path.join(recalboxFiles.BIOS, "tos.img")
                if not os.path.exists(biosPath):
                    biosPath = os.path.join(recalboxFiles.BIOS, subdir, "emutos.img")
        if "emutos" in self.rom:
            biosPath = os.path.join(recalboxFiles.BIOS, subdir, "emutos.img")
        atariStSettings.setString("ROM", "szTosImageFileName", str(biosPath))
        print("BIOS   : {}".format(biosPath))

        # Save config
        atariStSettings.saveFile()''',
    348: '''
    @staticmethod
    def configureOdyssey2(coreSettings: keyValueSettings):
        coreSettings.setString("o2em_bios", '"o2rom.bin"')

    @staticmethod
    def configureVideoPacPlus(coreSettings: keyValueSettings):
        coreSettings.setString("o2em_bios", '"g7400.bin"')''',
    492: '''    def configureDolphin(self, coreSettings: keyValueSettings) -> None:
        coreSettings.setString("dolphin_emulator_speed", '"1.0"')
        coreSettings.setString("dolphin_cpu_clock_rate", '"1.0"')

        ipl0 = "/recalbox/share/bios/gamecube/EUR/IPL.bin"
        ipl1 = "/recalbox/share/bios/gamecube/JP/IPL.bin"
        ipl2 = "/recalbox/share/bios/gamecube/USA/IPL.bin"

        import os.path
        if os.path.exists(ipl0) or os.path.exists(ipl1) or os.path.exists(ipl2):
            coreSettings.setString("dolphin_skip_gc_bios", '"disabled"')
        else:
            coreSettings.setString("dolphin_skip_gc_bios", '"enabled"')''',
    633: r'''    # Fill cores configuration
    def fillCoresConfiguration(self):
        settings = self.settings

        # Specific configuration handlers per core
        specificCoreHandlers =\
        {
            "bluemsx" : LibretroCores.configureBlueMSX,
            "dolphin": self.configureDolphin,
            "mame2003_plus": LibretroCores.configureMAME2003plus,
            "mame": self.configureMAME,
            "mame0258": self.configureMAME,
            "mame0278": self.configureMAME,
            "mupen64plus_nx" : LibretroCores.configureMUPEN64,
            "opera": LibretroCores.configureOpera,
            "parallel_n64": LibretroCores.configurePARALLELN64,
            "np2kai" : LibretroCores.configureNPKAI,
            "picodrive" : self.configurePicodrive,
            "swanstation" : self.configureSwanstation,
            "dosbox_pure" : LibretroCores.configureDosBoxPure,
            "flycast": self.configureFlycast,
            "flycast-next": self.configureFlycast,
            "fbneo": self.configureFBNeo,
            "scummvm": self.configureScummvm,
            "hatari": self.configureAtariST,
            "hatarib": self.configureAtariSTNew,
            "melonds": LibretroCores.configureMelonDS,
            "desmume": LibretroCores.configureDesmume,
            "ppsspp": self.configurePPSSPP,
            "pcsx_rearmed": self.configurePCSXRearmed,
            "mednafen_psx_hw": self.configureBeetlePSX,
            "mednafen_psx": self.configureBeetlePSX,
            "gambatte": self.configureGambatte,
            "mednafen_stv" : self.configureSTV,
            "eightyone": self.configureEightyOne,
            "tgbdual": self.configureTGBDual,
        }

        # Get handler and execute
        core = self.system.Core
        if core in specificCoreHandlers:
            function = specificCoreHandlers.get(core)
            function(settings)

        # Specific configuration handlers per system
        specificSystemHandlers =\
        {
            "amiga600"     : LibretroCores.configureAmiga600,
            "amiga1200"    : LibretroCores.configureAmiga1200,
            "amigacdtv"    : LibretroCores.configureAmigaCDTV,
            "amigacd32"    : LibretroCores.configureAmigaCD32,
            "atari5200"    : LibretroCores.configureAtari5200,
            "atari800"     : LibretroCores.configureAtari800,
            "amstradcpc"   : LibretroCores.configureAmstradCPC,
            "gx4000"       : LibretroCores.configureAmstradGX4000,
            "nds"          : self.configureNDS,
            "spectravideo" : LibretroCores.configureSpectravideo,
            "64dd"         : LibretroCores.configure64DD,
            "msx1"         : LibretroCores.configureMsx1,
            "msx2"         : LibretroCores.configureMsx2,
            "msxturbor"    : LibretroCores.configureMsxTurboR,
            "pc98"         : LibretroCores.configureNPKAI,
            "odyssey2"     : LibretroCores.configureOdyssey2,
            "videopacplus" : LibretroCores.configureVideoPacPlus,
            "sg1000"       : LibretroCores.configureSg1000,
            "naomi2"       : self.configureNaomi2,
            "saturn"       : self.configureSaturn,
        }

        # Get handler and execute
        if self.system.Name in specificSystemHandlers:
            function = specificSystemHandlers.get(self.system.Name)
            function(settings)''',
}

# libretroGenerator.py:7, 22, 814-815, 876-883
LIBRETRO_GENERATOR_BLOCKS = {
    7: '''import configgen.recalboxFiles as recalboxFiles''',
    22: '''class LibretroGenerator(Generator):''',
    814: '''    @staticmethod
    def buildRomArguments(rom: str, core: str, verbose: bool, demo: bool) -> List[str]:''',
    876: '''        # macintosh
        if core == "minivmac":
            with open(recalboxFiles.minivmacRomFile, 'w') as f:
                f.write('"Mini vMac" "' + recalboxFiles.minivmacOsFile + '" "' + rom + '"')

            rom = [recalboxFiles.minivmacRomFile]
            return rom
''',
}

# hatariGenerator.py:1-14, 103-167
HATARI_BLOCKS = {
    1: '''import os
from typing import List, Dict

from configgen.Command import Command
from configgen.Emulator import Emulator
from configgen.controllers.controller import ControllerPerPlayer
from configgen.generators.Generator import Generator
import configgen.recalboxFiles as recalboxFiles
from configgen.settings.iniSettings import IniSettings
import configgen.settings.configOverriding as configOverriding
from configgen.settings.keyValueSettings import keyValueSettings


class HatariGenerator(Generator):''',
    103: r'''
    @staticmethod
    def SetMachineAndBios(config: IniSettings, rom: str):
        # Machine list
        MACHINE_UNKNOWN = -1
        MACHINE_ST = 0
        MACHINE_MEGA_ST = 1
        MACHINE_STE = 2
        MACHINE_MEGA_STE = 3
        MACHINE_TT = 4
        MACHINE_FALCON = 5

        # Try identify machine folder
        machines: Dict[str, int] = \
        {
            "atari-st": MACHINE_ST,
            "/st/": MACHINE_ST,
            "atarimegast": MACHINE_MEGA_ST,
            "atari-megast": MACHINE_MEGA_ST,
            "atari-mega-st": MACHINE_MEGA_ST,
            "megast": MACHINE_MEGA_ST,
            "mega-st": MACHINE_MEGA_ST,
            "atariste": MACHINE_STE,
            "atari-ste": MACHINE_STE,
            "/ste/": MACHINE_STE,
            "atarimegaste": MACHINE_MEGA_STE,
            "atari-megaste": MACHINE_MEGA_STE,
            "atari-mega-ste": MACHINE_MEGA_STE,
            "megaste": MACHINE_MEGA_STE,
            "mega-ste": MACHINE_MEGA_STE,
            "ataritt": MACHINE_TT,
            "atari-tt": MACHINE_TT,
            "/tt/": MACHINE_TT,
            "falcon": MACHINE_FALCON,
            "atari-falcon": MACHINE_FALCON,
        }
        defaultMachine: int = MACHINE_UNKNOWN
        romLower: str = rom.lower()
        for key in machines:
            if key in romLower:
                defaultMachine: int = machines[key]
                break
        if not defaultMachine == MACHINE_UNKNOWN:
            config.setInt("System", "nMachineType", defaultMachine)
            print("MACHINE: {}".format(defaultMachine))
        else:
            defaultMachine = coreSettings.getInt("hatarib_machine", MACHINE_ST)

        # Select bios
        subdir: str = "atarist"
        biosFile = os.path.join(recalboxFiles.BIOS, subdir, "st.img")
        # ST/MEGAST use both st.img
        if   defaultMachine == MACHINE_FALCON  : biosFile = os.path.join(recalboxFiles.BIOS, subdir, "falcon.img")
        elif defaultMachine == MACHINE_MEGA_STE: biosFile = os.path.join(recalboxFiles.BIOS, subdir, "megaste.img")
        elif defaultMachine == MACHINE_TT      : biosFile = os.path.join(recalboxFiles.BIOS, subdir, "tt.img")
        elif defaultMachine == MACHINE_STE     : biosFile = os.path.join(recalboxFiles.BIOS, subdir, "ste.img")
        if not os.path.exists(biosFile):
            biosFile = os.path.join(recalboxFiles.BIOS, subdir, "tos.img")
            if not os.path.exists(biosFile):
                biosFile = os.path.join(recalboxFiles.BIOS, "tos.img")
                if not os.path.exists(biosFile):
                    biosFile = os.path.join(recalboxFiles.BIOS, subdir, "emutos.img")
        if "emutos" in rom:
            biosFile = os.path.join(recalboxFiles.BIOS, subdir, "emutos.img")
        config.setString("ROM", "szTosImageFileName", str(biosFile))''',
}

# gsplusGenerator.py:1-11, 93-148
GSPLUS_BLOCKS = {
    1: '''from typing import List

from configgen.Command import Command
import configgen.recalboxFiles as recalboxFiles
from configgen.Emulator import Emulator
from configgen.generators.Generator import Generator
from configgen.settings.keyValueSettings import keyValueSettings
from configgen.controllers.controller import Controller, InputItem, ControllerPerPlayer


class GSplusGenerator(Generator):''',
    93: '''    def generate(self, system: Emulator, playersControllers: ControllerPerPlayer, recalboxOptions: keyValueSettings, args):
        """
        Load, override keys and save back emulator's configuration file
        This way, any modification is kept accross emulator launches
        """

        slot: int = -1
        if ".gsplus" in args.rom:
            settings = keyValueSettings(args.rom, True)
            settings.loadFile(True)
            settings.changeSettingsFile(recalboxFiles.gsplusConfig)

            # Adjust BIOS path
            import os
            if settings.getString("g_cfg_rom_path", "") == "%1":
                settings.setString("g_cfg_rom_path", os.path.join(recalboxFiles.BIOS, "apple2gs1.rom"))
            elif settings.getString("g_cfg_rom_path", "") == "%3":
                settings.setString("g_cfg_rom_path", os.path.join(recalboxFiles.BIOS, "apple2gs3.rom"))

            # Adjust rom path
            folder = os.path.dirname(args.rom)
            for i in range(1, 33):
                if i < 3:
                    if settings.hasOption("s5d{}".format(i)) and settings.getString("s5d{}".format(i), "") != "":
                        settings.setString("s5d{}".format(i), os.path.join(folder, settings.getString("s5d{}".format(i), "")))
                    if settings.hasOption("s6d{}".format(i)) and settings.getString("s6d{}".format(i), "") != "":
                        settings.setString("s6d{}".format(i), os.path.join(folder, settings.getString("s6d{}".format(i), "")))
                if settings.hasOption("s7d{}".format(i)) and settings.getString("s7d{}".format(i), "") != "":
                    settings.setString("s7d{}".format(i), os.path.join(folder, settings.getString("s7d{}".format(i), "")))

        else:
            # Load config file
            settings = keyValueSettings(recalboxFiles.gsplusConfig, True)
            settings.loadFile(True)

            # Reset drive slots
            for i in range(1, 33):
                if i < 3:
                    if settings.hasOption("s5d{}".format(i)):
                        settings.setString("s5d{}".format(i), "")
                    if settings.hasOption("s6d{}".format(i)):
                        settings.setString("s6d{}".format(i), "")
                if settings.hasOption("s7d{}".format(i)):
                    settings.setString("s7d{}".format(i), "")

            # Reset bios
            import os
            bios = os.path.join(recalboxFiles.BIOS, "apple2gs1.rom")
            if os.path.exists(bios):
                settings.setString("g_cfg_rom_path", bios)
            else:
                bios = os.path.join(recalboxFiles.BIOS, "apple2gs3.rom")
                if os.path.exists(bios):
                    settings.setString("g_cfg_rom_path", bios)
                else:
                    settings.removeOption("g_cfg_rom_path")''',
}

# amiberryKickstarts.py:1-151
AMIBERRY_KICKSTARTS_BLOCKS = {
    1: r'''#!/usr/bin/env python
import os

import configgen.recalboxFiles as recalboxFiles
from configgen.generators.amiberry.amiberryRomType import RomType
from configgen.generators.amiberry.amiberrySubSystems import SubSystems

# Kickstarts live in the amiga subfolder (see es_bios.xml and amiberry rom_path)
def AmigaBios(name: str) -> str:
    return os.path.join(recalboxFiles.BIOS, "amiga", "bios", name)


class KickstartManager:

    BIOS_LIST = \
    {
        # Kickstart v1.2 rev 33.180 (1986)(Commodore)(A500-A1000-A2000).rom
        "kick33180.A500":  (256, "KS ROM v1.2 (A500,A1000,A2000) rev 33.180 (256k) [315093-01]"),
        # Kickstart v1.3 rev 34.5 (1987)(Commodore)(A500-A1000-A2000-CDTV).rom
        "kick34005.A500":  (256, "KS ROM v1.3 (A500,A1000,A2000) rev 34.5 (256k) [315093-02]"),
        # Kickstart v2.04 rev 37.175 (1991)(Commodore)(A500+).rom
        "kick37175.A500":  (256, "KS ROM v2.04 (A500+) rev 37.175 (512k) [390979-01]"),
        # Kickstart v3.0 rev 39.106 (1992)(Commodore)(A1200)[!].rom
        "kick39106.A1200": (256, "KS ROM v3.0 (A1200) rev 39.106 (512k) [391523-01/391524-01]"),
        # Kickstart v3.1 rev 40.63 (1993)(Commodore)(A500-A600-A2000)[!].rom
        "kick40063.A600":  (256, "KS ROM v3.1 (A600) rev 40.63 (512k)"),
        # Kickstart v3.1 rev 40.68 (1993)(Commodore)(A1200).rom
        "kick40068.A1200": (256, "KS ROM v3.1 (A1200) rev 40.68 (512k) [391773-01/391774-01]"),
        # Kickstart v3.1 rev 40.68 (1993)(Commodore)(A4000).rom
        "kick40068.A4000": (256, "KS ROM v3.1 (A4000) rev 40.68 (512k)"),

        # Kickstart v1.3 rev 34.5 (1987)(Commodore)(A500-A2000-CDTV)[!].rom
        "kick34005.CDTV": (256, "CDTV Extended ROM rev 34.5 (256k)"),

        # Kickstart v3.1 rev 40.60 (1993)(Commodore)(CD32).rom
        "kick40060.CD32":  (512, "CD32 KS ROM v3.1 rev 40.60 (512k)"),
        # CD32 Extended-ROM rev 40.60 (1993)(Commodore)(CD32).rom 87746be2
        "kick40060.CD32.ext": (1024, "CD32 extended ROM rev 40.60 (512k)"),

        # AROS Kickstart 2019
        "kick02019.AROS": (256, "KS AROS 2019 Part#1 (512k)"),
        # AROS Extended Kickstart 2019
        "kick02019.AROS.ext": (256, "KS AROS 2019 Part#2 (512k)"),
    }

    BIOS_PER_SYSTEM = \
    {
        SubSystems.A600:
        [
            (   # Use the highest kickstart with advanced hardware
                [RomType.WHDL, RomType.HDF, RomType.PACKAGE, RomType.CDROM, RomType.HDDFS],
                ["kick37175.A500", "kick34005.A500", "kick33180.A500"]
            ),
            (   # Use kickstarts 1.3/1.2 to maximize compatibility when using disks
                [RomType.DISK],
                ["kick34005.A500", "kick33180.A500"]
            ),
        ],
        SubSystems.A1200:
        [
            (   # Use kickstart 3.1 first, then 3.0. Fallback on A4000 kickstart
                [RomType.WHDL, RomType.HDF, RomType.PACKAGE, RomType.CDROM, RomType.HDDFS, RomType.DISK],
                ["kick40068.A1200", "kick39106.A1200", "kick40068.A4000"]
            ),
        ],
        SubSystems.CD32:
        [
            (   # No choice for the CD32
                [RomType.CDROM],
                ["kick40060.CD32|kick40060.CD32.ext"]
            ),
        ],
        SubSystems.CDTV:
        [
            (   # No choice for the CD32
                [RomType.CDROM],
                ["kick34005.A500|kick34005.CDTV"]
            ),
        ],
    }

    def __init__(self):
        self.rom: str = ""
        self.ext: str = ""

    @staticmethod
    def GenerateWHDSymLinks(destinationfolder: str):
        for bios in KickstartManager.BIOS_LIST:
            biosPath = AmigaBios(bios)
            biosLink = os.path.join(destinationfolder, bios)
            if not os.path.exists(biosLink) and os.path.exists(biosPath):
                os.symlink(biosPath, biosLink)

    def GetKickstartsFor(self, subsystem: SubSystems, romtype: RomType):
        # Select best available kickstart
        biosFile = None
        extFile = None
        needExt = False
        tuppleArray = KickstartManager.BIOS_PER_SYSTEM[subsystem]
        for tupple in tuppleArray:
            romTypes, biosList = tupple
            if romtype in romTypes:
                for biosCouple in biosList:
                    bios = biosCouple
                    ext = None
                    if '|' in biosCouple:
                        bios, ext = biosCouple.split('|', 2)
                        needExt = ext is not None
                    biosPath = AmigaBios(bios)
                    if os.path.exists(biosPath):
                        biosFile = biosPath
                    if needExt:
                        extPath = AmigaBios(ext)
                        if os.path.exists(extPath):
                            extFile = extPath
                    if biosFile is not None:
                        break

        # Fallbacks
        if subsystem in SubSystems.COMPUTERS:
            # Fallback to AROS 2019?
            if biosFile is None:
                arosBios = AmigaBios("kick02019.AROS")
                arosExt = AmigaBios("kick02019.AROS.ext")
                if os.path.exists(arosBios) and os.path.exists(arosExt):
                    biosFile = arosBios
                    extFile = arosExt

            # Fallback to internal Aros bios
            if biosFile is None:
                self.rom = ":AROS"
                return

        # Last check
        if biosFile is None:
            raise Exception("No BIOS found")
        # If an extened bios is required, it's not worth going further w/o it
        if extFile is None and needExt:
            raise Exception("Extended BIOS not found")

        self.rom = biosFile if biosFile is not None else ""
        self.ext = extFile if extFile is not None else ""

    @property
    def GetBIOS(self) -> str: return self.rom

    @property
    def NeedExtendedBIOS(self) -> bool: return len(self.ext) != 0

    @property
    def GetExtendedBIOS(self) -> str: return self.ext''',
}

# amiberrySubSystems.py:1-13
AMIBERRY_SUBSYSTEMS_BLOCKS = {
    1: '''#!/usr/bin/env python


class SubSystems:
    UNKNOWN = "unknown"
    A600 = "amiga600"
    A1200 = "amiga1200"
    CDTV = "amigacdtv"
    CD32 = "amigacd32"

    COMPUTERS = ( A600, A1200 )
    CONSOLES = ( CDTV, CD32 )
    HAVEMOUSE = ( A600, A1200, CDTV, CD32 )''',
}

# amiberryConfig.py:1-9, 337-345
AMIBERRY_CONFIG_BLOCKS = {
    1: '''#!/usr/bin/env python
from typing import List

from configgen.generators.amiberry.amiberrySubSystems import SubSystems
from configgen.controllers.controller import ControllerPerPlayer
from configgen.generators.amiberry.amiberryRomType import RomType


class ConfigGenerator:''',
    337: '''    def SetKickstarts(self, subsystem: SubSystems, romtype: RomType):
        from configgen.generators.amiberry.amiberryKickstarts import KickstartManager
        manager = KickstartManager()
        manager.GetKickstartsFor(subsystem, romtype)
        kickstart = manager.GetBIOS
        self.settings.setString("kickstart_rom_file", kickstart)
        if manager.NeedExtendedBIOS:
            extended = manager.GetExtendedBIOS
            self.settings.setString("kickstart_ext_rom_file", extended)''',
}

# amiberryGlobalConfig.py:1-10, 30-43
AMIBERRY_GLOBAL_BLOCKS = {
    1: '''#!/usr/bin/env python


class AmiberryGlobalConfig:

    def __init__(self, userGlobalSettingsFile, finalGlobalSettingsFile):
        self.globalSettingsFile = finalGlobalSettingsFile
        self.userSettingsFile = userGlobalSettingsFile

    def createGlobalSettings(self, verbose: bool, scanline: bool):''',
    30: '''        # Forced values
        import configgen.recalboxFiles as recalboxFiles
        mount = recalboxFiles.amiberryMountPoint
        settings.setBool("Quickstart", True)
        # Host paths (Amiberry 8.x reads them from amiberry.conf, overriding the
        # ones derived from AMIBERRY_HOME_DIR)
        settings.setString("config_path", mount + "/conf/")
        settings.setString("controllers_path", mount + "/conf/")
        settings.setString("retroarch_config", recalboxFiles.retroarchCustom)
        settings.setString("whdboot_path", mount + "/whdboot/")
        settings.setString("rp9_path", mount + "/conf/")
        # Kickstarts: Amiberry scans this folder on startup to build its ROM list
        settings.setString("rom_path", recalboxFiles.BIOS + "/amiga/bios/")
        settings.setString("logfile_path", mount + "/amiberry.log")''',
}

# pcsx2Generator.py:1-166
PCSX2_BLOCKS = {
    1: r'''#!/usr/bin/env python
from typing import Dict

from configgen.Command import Command
from configgen.Emulator import Emulator
from configgen.controllers.controller import ControllerPerPlayer
from configgen.emulatorlauncher import recalboxFiles
from configgen.generators.Generator import Generator
from configgen.settings.iniSettings import IniSettings
from configgen.settings.keyValueSettings import keyValueSettings

class Pcsx2Generator(Generator):

    pcsx2RootFolder = recalboxFiles.HOME + '/.config/PCSX2'
    pcsx2ConfigFileReg = pcsx2RootFolder + '/PCSX2-reg.ini'
    pcsx2ConfigFileGSdx = pcsx2RootFolder + '/GSdx.ini'
    pcsx2ConfigFilePAD = pcsx2RootFolder + '/PAD.ini'
    pcsx2ConfigFilePCSX2_ui = pcsx2RootFolder + '/PCSX2_ui.ini'
    pcsx2ConfigFilePCSX2_vm = pcsx2RootFolder + '/PCSX2_vm.ini'
    pcsx2ConfigFileSPU2 = pcsx2RootFolder + '/SPU2.ini'

    SECTION_DEFAULT = "default"
    # Core
    SECTION_VM_EMUCORE_GS = "EmuCore/GS"
    SECTION_VM_EMUCORE_SPEEDHACKS = "EmuCore/Speedhacks"
    # UI
    SECTION_UI_NONE = ""
    SECTION_UI_GSWINDOWS = "GSWindow"
    SECTION_UI_POPUPDISABLERS = "PopupDisablers"
    SECTION_UI_FILENAMES = "Filenames"
    # Sound (SPU2.ini)
    SECTION_SPU2_MIXING = "MIXING"
    SECTION_SPU2_OUTPUT = "OUTPUT"
    SECTION_SPU2_SDL = "SDL"

    # Bios names
    BIOS_USA = "ps2-0230a-20080220.bin"
    BIOS_EU  = "ps2-0230e-20080220.bin"
    BIOS_JP  = "ps2-0230j-20080220.bin"
    BIOS_HK  = "ps2-0230h-20080220.bin"

    @staticmethod
    def __ConfigurePad(playersControllers: ControllerPerPlayer, system: Emulator):
        with open(Pcsx2Generator.pcsx2ConfigFilePAD, "w") as f:
            if system.Rumble:
                f.write("options = 1\n")
                f.write("mouse_sensitivity = 100\n")
                f.write("ff_intensity = 32767\n")

            if 1 in playersControllers: f.write("uid[0] = {}\n".format(playersControllers[1].SdlIndex))
            if 2 in playersControllers: f.write("uid[1] = {}\n".format(playersControllers[2].SdlIndex))
            if 1 in playersControllers: f.write("SDL2 = {}\n".format(playersControllers[1].generateSDLGameDBLine(False)))
            if 2 in playersControllers: f.write("SDL2 = {}\n".format(playersControllers[2].generateSDLGameDBLine(False)))

    @staticmethod
    def __CheckPs2Bios(rom: str) -> str:
        import os.path

        def Exists(romPath: str) -> bool:
            return os.path.exists(os.path.join(recalboxFiles.BIOS, "ps2", romPath))

        # Try to get Redump region
        lrom = rom.lower()
        # EU region
        if   "europe" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "france" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "ireland" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "germany" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "belgium" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "italy" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "greece" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "croatia" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "denmark" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "spain" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "portugal" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "poland" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "finland" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "russia" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "austria" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "netherlands" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "switzerland" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "norway" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "sweden" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "scandinavia" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "australia" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "india" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "south africa" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        # USA region
        elif "canada" in lrom and Exists(Pcsx2Generator.BIOS_USA): return Pcsx2Generator.BIOS_USA
        elif "brazil" in lrom and Exists(Pcsx2Generator.BIOS_USA): return Pcsx2Generator.BIOS_USA
        elif "latin america" in lrom and Exists(Pcsx2Generator.BIOS_USA): return Pcsx2Generator.BIOS_USA
        # JP region
        elif "japan" in lrom and Exists(Pcsx2Generator.BIOS_JP): return Pcsx2Generator.BIOS_JP
        elif "korea" in lrom and Exists(Pcsx2Generator.BIOS_JP): return Pcsx2Generator.BIOS_JP
        elif "asia" in lrom and Exists(Pcsx2Generator.BIOS_JP): return Pcsx2Generator.BIOS_JP
        # CH
        elif "china" in lrom and Exists(Pcsx2Generator.BIOS_JP): return Pcsx2Generator.BIOS_HK
        elif "taiwan" in lrom and Exists(Pcsx2Generator.BIOS_JP): return Pcsx2Generator.BIOS_HK
        # Shortest name at the end
        elif "uk" in lrom and Exists(Pcsx2Generator.BIOS_EU): return Pcsx2Generator.BIOS_EU
        elif "usa" in lrom and Exists(Pcsx2Generator.BIOS_USA): return Pcsx2Generator.BIOS_USA

        # Check if PS2 bios bin in folders
        for bios in (Pcsx2Generator.BIOS_USA, Pcsx2Generator.BIOS_EU, Pcsx2Generator.BIOS_JP, Pcsx2Generator.BIOS_HK):
            if Exists(bios):
                return bios
        return ""

    @staticmethod
    def __ConfigureReg():
        reg = keyValueSettings(Pcsx2Generator.pcsx2ConfigFileReg)
        reg.loadFile(True)

        # Override Reg Configuration
        reg.setString("DocumentsFolderMode", "User")
        reg.setString("CustomDocumentsFolder", "/usr/bin/PCSX2")
        reg.setString("UseDefaultSettingsFolder", "enabled")
        reg.setString("SettingsFolder", "/recalbox/share/system/.config/PCSX2")
        reg.setString("Install_Dir", "/usr/bin/PCSX2")
        reg.setString("RunWizard", "0")

        # Save configuration
        reg.saveFile()

    @staticmethod
    def __ConfigureCore():
        import multiprocessing
        NbCpu = multiprocessing.cpu_count()

        # Override VM Configuration
        vm = IniSettings(Pcsx2Generator.pcsx2ConfigFilePCSX2_vm, True)
        vm.loadFile(True)

        vm.setString(Pcsx2Generator.SECTION_VM_EMUCORE_GS, "FrameLimitEnable", "enabled")
        vm.setString(Pcsx2Generator.SECTION_VM_EMUCORE_GS, "FramerateNTSC", "59.94")
        vm.setInt(Pcsx2Generator.SECTION_VM_EMUCORE_GS, "FrameratePAL", 50)
        vm.setString(Pcsx2Generator.SECTION_VM_EMUCORE_GS, "FrameSkipEnable", "disabled")
        vm.setInt(Pcsx2Generator.SECTION_VM_EMUCORE_GS, "FramesToDraw", 2)
        vm.setInt(Pcsx2Generator.SECTION_VM_EMUCORE_GS, "FramesToSkip", 2)
        vm.setString(Pcsx2Generator.SECTION_VM_EMUCORE_GS, "LimitScalar", "1.00")
        vm.setString(Pcsx2Generator.SECTION_VM_EMUCORE_GS, "SynchronousMTGS", "disabled")
        vm.setInt(Pcsx2Generator.SECTION_VM_EMUCORE_GS, "VsyncQueueSize", 2)
        vm.setString(Pcsx2Generator.SECTION_VM_EMUCORE_SPEEDHACKS, "vuThread", "enabled" if NbCpu > 3 else "disabled")

        # Save configuration
        vm.saveFile()

    @staticmethod
    def __ConfigureUI(system: Emulator, rom: str):
        # Game Ratio
        GAME_RATIO: Dict[str, str] = \
        {
            "16/9": "16:9",
            "4/3": "4:3",
        }

        gameRatio = GAME_RATIO[system.Ratio] if system.Ratio in GAME_RATIO else "4:3"

        # override UI Configuration
        ui = IniSettings(Pcsx2Generator.pcsx2ConfigFilePCSX2_ui, True)
        ui.defineBool("1", "0").loadFile(True)

        ui.setString(Pcsx2Generator.SECTION_UI_NONE, "AskOnBoot", "disabled")
        ui.setString(Pcsx2Generator.SECTION_UI_GSWINDOWS, "AspectRatio", gameRatio)
        ui.setString(Pcsx2Generator.SECTION_UI_POPUPDISABLERS, "Dialog.ComponentsConfig.Overrides", "disabled,ok")
        ui.setString(Pcsx2Generator.SECTION_UI_FILENAMES, "BIOS", Pcsx2Generator.__CheckPs2Bios(rom))''',
}

# dolphinGenerator.py:1-13, 113, 152-163, 228-273
DOLPHIN_BLOCKS = {
    1: '''#!/usr/bin/env python3
from configgen.Command import Command
import configgen.recalboxFiles as recalboxFiles
from configgen.Emulator import Emulator
from configgen.controllers.controller import ControllerPerPlayer
from configgen.generators.Generator import Generator
from configgen.settings.keyValueSettings import keyValueSettings
from configgen.utils.Vulkan import Vulkan
from configgen.utils.architecture import Architecture
from configgen.utils.videoMode import createCrtDesktopRes, getCrtResolution, deleteCrtDesktopRes


class DolphinGenerator(Generator):''',
    113: '''    SECTION_CORE = "Core"''',
    152: '''    # Check if Gamecube bios IPL.bin in folders
    @staticmethod
    def CheckGamecubeIpl() -> str:
        ipl0 = "/recalbox/share/bios/gamecube/EUR/IPL.bin"
        ipl1 = "/recalbox/share/bios/gamecube/JP/IPL.bin"
        ipl2 = "/recalbox/share/bios/gamecube/USA/IPL.bin"
        # if os.path? return "True" set "False" for disable "SkipIpl=Video boot intro"
        import os.path
        if os.path.exists(ipl0) or os.path.exists(ipl1) or os.path.exists(ipl2):
            return "False"
        else:
            return "True"''',
    228: r'''    def mainConfiguration(self, system: Emulator, args):
        # Get Languages
        language = self.GetLanguage()
        systemLanguage = self.GetFrontendLanguage()
        gamecubeLanguage = self.GAMECUBE_LANGUAGES[language] if language in self.GAMECUBE_LANGUAGES else 0
        # Get Netplay configs
        nickname = self.GetNetplay()
        lobbyServer = self.NETPLAY_SERVERS[systemLanguage] if systemLanguage in self.NETPLAY_SERVERS else None
        ## Get if we have all IPL.bin in folders Gc bios
        biosGamecube = self.CheckGamecubeIpl()
        ## set Gamecube Wii U adapter
        padsGamecube = self.SetGamecubeWiiUAdapter()
        # Get current rom path
        import os
        romName = os.path.basename(args.rom)
        homeDir = args.rom.replace("/" + romName, "")

        # Load Configuration
        from configgen.settings.iniSettings import IniSettings
        dolphinSettings = IniSettings(DolphinGenerator.iniFile, True)
        dolphinSettings.loadFile(True) \
                       .defineBool('True', 'False')

        # Resolution
        from configgen.utils.resolutions import ResolutionParser
        resolution = ResolutionParser(system.VideoMode)
        if resolution.isSet and resolution.selfProcess:
            dolphinSettings.setString(self.SECTION_DISPLAY, "FullscreenResolution", resolution.string)
            dolphinSettings.setBool(self.SECTION_DISPLAY, "Fullscreen", True)
        if Architecture().isX64:
            dolphinSettings.setBool(self.SECTION_DISPLAY, "RenderToMain", True)
        dolphinSettings.setBool(self.SECTION_DISPLAY, "KeepWindowOnTop", True)
        # Logging
        dolphinSettings.setBool(self.SECTION_DSP, "CaptureLog", args.verbose)
        # Force audio backend on Pulse Audio
        dolphinSettings.setString(self.SECTION_DSP, "Backend", "Pulse")
        # Analytics
        dolphinSettings.setBool(self.SECTION_ANALYTICS, "Enabled", True)
        dolphinSettings.setBool(self.SECTION_ANALYTICS, "PermissionAsked", True)
        # Bluetooth Pass-trough
        dolphinSettings.setBool(self.SECTION_BTPASSTHROUGH, "Enabled", False)
        # Core
        dolphinSettings.setInt(self.SECTION_CORE, "SelectedLanguage", gamecubeLanguage)
        dolphinSettings.setBool(self.SECTION_CORE, "WiimoteContinuousScanning", True)
        dolphinSettings.setBool(self.SECTION_CORE, "WiiKeyboard", False)
        dolphinSettings.setString(self.SECTION_CORE, "SkipIpl", biosGamecube)''',
}

# xemuGenerator.py:1-27, 30-60
XEMU_BLOCKS = {
    1: """#!/usr/bin/env python3
import shutil
import os.path
from configgen.Command import Command
from configgen.Emulator import Emulator
from configgen.generators.Generator import Generator, ControllerPerPlayer
import configgen.recalboxFiles as recalboxFiles
from configgen.settings.keyValueSettings import keyValueSettings
from configgen.utils.Vulkan import Vulkan
from configgen.generators.xemu.xemuControllers import XemuControllers


class XemuGenerator(Generator):
    SECTION_GENERAL = "general"
    SECTION_SYS = "sys"
    SECTION_SYS_FILES = "sys.files"
    SECTION_AUDIO = "audio"
    SECTION_DISPLAY = "display"
    SECTION_DISPLAY_QUALITY = "display.quality"
    SECTION_DISPLAY_UI = "display.ui"
    SECTION_DISPLAY_WINDOW = "display.window"
    SECTION_INPUT = "input"
    SECTION_NET = "net"

    savePath = recalboxFiles.SAVES + "/xbox"
    biosPath = recalboxFiles.BIOS + "/xbox"
    optionsConfigFile = recalboxFiles.CONF + '/xemu/xemu_config.ini'""",
    30: '''    def mainConfiguration(self, system: Emulator, args):
        # Load xemu config file defined in frontend options and get values
        from configgen.settings.iniSettings import IniSettings
        configSettings = IniSettings(self.optionsConfigFile, True)
        configSettings.loadFile(True).defineBool('true', 'false')

        skip_boot_anim = configSettings.getBool(self.SECTION_GENERAL, "skip_boot_anim", False)
        show_menubar = configSettings.getBool(self.SECTION_DISPLAY_UI, "show_menubar", False)
        show_notifications = configSettings.getBool(self.SECTION_DISPLAY_UI, "show_notifications", False)
        fit = configSettings.getString(self.SECTION_DISPLAY_UI, "fit", "'scale'")
        aspect_ratio = configSettings.getString(self.SECTION_DISPLAY_UI, "aspect_ratio", "'native'")
        surface_scale = configSettings.getInt(self.SECTION_DISPLAY_QUALITY, "surface_scale", 1)

        print(f"Xemu configuration: skip_boot_anim:{skip_boot_anim}")

        # Load configuration
        xemuSettings = IniSettings(self.xemuConfigFile, True)
        xemuSettings.loadFile(True).defineBool('true', 'false')

        # General
        xemuSettings.setBool(self.SECTION_GENERAL, "skip_boot_anim", skip_boot_anim)
        xemuSettings.setBool(self.SECTION_GENERAL, "show_welcome", False)
        xemuSettings.setString(self.SECTION_GENERAL, "screenshot_dir", f"'{recalboxFiles.SCREENSHOTS}'")

        # Sys
        xemuSettings.setString(self.SECTION_SYS, "mem_limit", "'128'")

        # Sys.files
        xemuSettings.setString(self.SECTION_SYS_FILES, "flashrom_path", f"'{self.biosPath}/Complex_4627.bin'")
        xemuSettings.setString(self.SECTION_SYS_FILES, "bootrom_path", f"'{self.biosPath}/mcpx_1.0.bin'")
        xemuSettings.setString(self.SECTION_SYS_FILES, "hdd_path", f"'{self.savePath}/xbox_hdd.qcow2'")''',
}

# mupenConfig.py:1-5, 117-123
MUPEN_CONFIG_BLOCKS = {
    1: '''#!/usr/bin/env python
import configgen.recalboxFiles as recalboxFiles
from configgen.Emulator import Emulator
from configgen.settings.iniSettings import IniSettings
from configgen.controllers.controller import InputItem, ControllerPerPlayer, Controller''',
    117: '''def __setIpl64DD(system: Emulator, mupenSettings: IniSettings):
    # Set ipl only for n64
    section = '64DD'
    if system.Name == "64dd":
        mupenSettings.setString(section, "IPL-ROM", "/recalbox/share/bios/64DD_IPL.bin")
    elif system.Name == "n64":
        mupenSettings.setString(section, "IPL-ROM", "")''',
}

# xroarGenerator.py:1-26 at 10.1.1
XROAR_BLOCKS = {
    8: '''class XroarGenerator(Generator):

    def generate(self, system: Emulator, playersControllers: ControllerPerPlayer, recalboxOptions: keyValueSettings, args) -> Command:

        # Make save dir
        import os
        import configgen.recalboxFiles as recalboxFiles''',
    22: '''        snapFile: str = os.path.basename(args.rom) + ".sna"
        commandArray: List[str] = [recalboxFiles.recalboxBins[system.Emulator],
                                   "-vo", "sdl", "-ui", "sdl", "-ao", "pulse",
                                   "-rompath", os.path.join(recalboxFiles.BIOS, args.system),
                                   "-snappath", os.path.join(snapshotFolder, snapFile)]''',
}

BLOCKS = {
    FILES_MODULE: FILES_MODULE_BLOCKS,
    LAUNCHER: LAUNCHER_BLOCKS,
    RETROARCH: RETROARCH_BLOCKS,
    CORES: CORES_BLOCKS,
    LIBRETRO_GENERATOR: LIBRETRO_GENERATOR_BLOCKS,
    HATARI: HATARI_BLOCKS,
    GSPLUS: GSPLUS_BLOCKS,
    AMIBERRY_KICKSTARTS: AMIBERRY_KICKSTARTS_BLOCKS,
    AMIBERRY_SUBSYSTEMS: AMIBERRY_SUBSYSTEMS_BLOCKS,
    AMIBERRY_CONFIG: AMIBERRY_CONFIG_BLOCKS,
    AMIBERRY_GLOBAL: AMIBERRY_GLOBAL_BLOCKS,
    PCSX2: PCSX2_BLOCKS,
    DOLPHIN: DOLPHIN_BLOCKS,
    XEMU: XEMU_BLOCKS,
    MUPEN_CONFIG: MUPEN_CONFIG_BLOCKS,
    XROAR: XROAR_BLOCKS,
}


def files(path: str | None = None, old: str = "", new: str = "") -> dict[str, str]:
    """The configgen tree, with `old` replaced once by `new` in `path`."""
    tree = {name: placed(blocks) for name, blocks in BLOCKS.items()}
    if path is not None:
        if old not in tree[path]:
            raise AssertionError(f"{old!r} is not in {path}")
        tree[path] = tree[path].replace(old, new, 1)
    return tree


def configgen(path: str | None = None, old: str = "", new: str = "") -> Configgen:
    return Configgen(files(path, old, new).__getitem__)


def ref(path: str, lines: str) -> str:
    return f"{path}:{lines}"


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
        cores = {name for r in self.records for name in r.emulator.split(", ")}
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
            for name in record["emulator"].split(", ")
        }
        self.assertEqual(sorted(named - cores), [])

    def test_every_reference_is_in_configgen(self):
        for record in self.config["launchers"]:
            for part in record["source_ref"].split(", "):
                if not part[0].isdigit():
                    self.assertTrue(part.startswith(f"{CONFIGGEN}/"), record)


if __name__ == "__main__":
    unittest.main()
