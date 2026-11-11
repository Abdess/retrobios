"""EmuDeck's launcher layer read from its EmuScripts.

Each fixture is a cut-down copy of the lines an extractor reads at
dragoonDorise/EmuDeck dddb30229adbbd54d5ff7283cfd70e11c4322c26. The records
must carry the names in the order the script writes them, point at the
fixture's own lines, and a construct that is gone must stop the scrape.
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

from scraper import emudeck_launchers as el  # noqa: E402
from scraper.emudeck_scraper import launcher_revision  # noqa: E402
from scraper.shell_launchers import LauncherPatternMissing, RepoTree, words  # noqa: E402

S = el.EMUSCRIPTS


def text(block: str) -> str:
    return textwrap.dedent(block).lstrip("\n")


ARES_SH = text(
    """
    ares_configFile="$HOME/.var/app/dev.ares.ares/data/ares/settings.bml"
    ares_setEmulationFolder(){
    	UserROMsPath='/home/deck/Emulation/roms/'
    	sed -i "s|$UserROMsPath|${romsPath}\\/|g" "$ares_configFile"
    	UserBIOSPath='/home/deck/Emulation/bios/'
    	sed -i "s|$UserBIOSPath|${biosPath}\\/|g" "$ares_configFile"
    }
    ares_init(){
    	configEmuFP "${ares_emuName}" "${ares_emuPath}" "true"
    }
"""
)

ARES_BML = text(
    """
    ColecoVision
      Path: /home/deck/Emulation/roms/colecovision/
      Firmware
        BIOS.World: /home/deck/Emulation/bios/colecovision.rom
      Visible: true
    PCEngineCD
      Path: /home/deck/Emulation/roms/pcenginecd/
      Firmware
        BIOS.US: /home/deck/Emulation/bios/syscard3u.pce
        BIOS.Japan: /home/deck/Emulation/bios/syscard3.pce
      Visible: true
    NeoGeoMVS
      Path: /home/deck/Emulation/roms/arcade/
      Firmware
        BIOS.World
      Visible: true
"""
)

MELONDS_SH = text(
    """
    melonDS_configFile="$HOME/.var/app/net.kuribo64.melonDS/config/melonDS/melonDS.ini"
    melonDS_resolutionFile="$HOME/.var/app/net.kuribo64.melonDS/config/melonDS/melonDS.toml"
    melonDS_init(){
    	sed -i "s|/run/media/mmcblk0p1/Emulation|$emulationPath|g" "$melonDS_configFile"
    	sed -i "s|/run/media/mmcblk0p1/Emulation|$emulationPath|g" "$melonDS_resolutionFile"
    }
    melonDS_setEmulationFolder(){
    	BIOS9PathSetting='BIOS9Path='
    	BIOS7PathSetting='BIOS7Path='
    	LastROMFolderSetting='LastROMFolder='
    	changeLine "$BIOS9PathSetting" "${BIOS9PathSetting}${biosPath}/bios9.bin" "${melonDS_configFile}"
    	changeLine "$BIOS7PathSetting" "${BIOS7PathSetting}${biosPath}/bios7.bin" "${melonDS_configFile}"
    	changeLine "$LastROMFolderSetting" "${LastROMFolderSetting}${romsPath}/nds" "${melonDS_configFile}"
    }
    melonDS_setResolution(){
    	changeLine "ScaleFactor = " "$scaleLine" "$melonDS_resolutionFile"
    }
    melonDS_setABXYstyle(){
    	buttonA='Joy_A='
    	changeLine "$buttonA" "$buttonA""0" "${melonDS_configFile}"
    }
    melonDS_update(){
    	configEmuFP "${melonDS_emuName}" "${melonDS_emuPath}"
    }
"""
)

MELONDS_INI = text(
    """
    ExternalBIOSEnable=0
    BIOS9Path=/run/media/mmcblk0p1/Emulation/bios/bios9.bin
    BIOS7Path=/run/media/mmcblk0p1/Emulation/bios/bios7.bin
"""
)

MELONDS_TOML = text(
    """
    LastROMFolder = "/run/media/mmcblk0p1/Emulation/roms/ds"
    [Emu]
    ExternalBIOSEnable = false
    ConsoleType = 0
    [DS]
    FirmwarePath = "/run/media/mmcblk0p1/Emulation/bios/firmware.bin"
    BIOS7Path = "/run/media/mmcblk0p1/Emulation/bios/bios7.bin"
    [DSi]
    NANDPath = "/run/media/mmcblk0p1/Emulation/bios/dsi_nand.bin"
"""
)

XEMU_SH = text(
    """
    Xemu_configFile="$HOME/.var/app/app.xemu.xemu/data/xemu/xemu/xemu.toml"
    Xemu_setEmulationFolder(){
        bootrrom_path='bootrom_path = '
    	flashrom_path='flashrom_path = '
    	eeprom_path='eeprom_path = '
        bootrrom_pathSetting="${bootrrom_path}""'${biosPath}/mcpx_1.0.bin'"
    	flashrom_pathSetting="${flashrom_path}""'${biosPath}/Complex_4627v1.03.bin'"
    	eeprom_pathSetting="${eeprom_path}""'${storagePath}/xemu/eeprom.bin'"
        changeLine "${bootrrom_path}" "${bootrrom_pathSetting}" "$Xemu_configFile"
        changeLine "${flashrom_path}" "${flashrom_pathSetting}" "$Xemu_configFile"
        changeLine "${eeprom_path}" "${eeprom_pathSetting}" "$Xemu_configFile"
    }
"""
)

DUCKSTATION_SH = text(
    """
    DuckStation_configFile="$HOME/.local/share/duckstation/settings.ini"
    DuckStation_setEmulationFolder(){
    	biosDir='SearchDirectory = '
    	biosDirSetting="${biosDir}""${biosPath}"
    	statesDir='SaveStates = '
    	statesDirSetting="${statesDir}""${savesPath}/duckstation/states"
    	changeLine "$biosDir" "$biosDirSetting" "$DuckStation_configFile"
    	changeLine "$statesDir" "$statesDirSetting" "$DuckStation_configFile"
    }
"""
)

PCSX2_SH = text(
    """
    PCSX2QT_configFile="$HOME/.config/PCSX2/inis/PCSX2.ini"
    PCSX2QT_setEmulationFolder() {
    	iniFieldUpdate "$PCSX2QT_configFile" "UI" "StartFullscreen" "true"
    	iniFieldUpdate "$PCSX2QT_configFile" "Folders" "Bios" "${biosPath}"
    	iniFieldUpdate "$PCSX2QT_configFile" "Folders" "Snapshots" "${storagePath}/pcsx2/snaps"
    }
"""
)

MAME_SH = text(
    """
    MAME_configFile="$HOME/.mame/mame.ini"
    MAME_setEmulationFolder(){
        gameDirOpt='rompath                   '
        newGameDirOpt="$gameDirOpt""${romsPath}/arcade;${biosPath};${biosPath}/mame"
    	changeLine "$gameDirOpt" "$newGameDirOpt" "$MAME_configFile"
    }
"""
)

RETROARCH_SH = text(
    """
    RetroArch_configFile="$HOME/.var/app/org.libretro.RetroArch/config/retroarch/retroarch.cfg"
    RetroArch_setEmulationFolder(){
    	RetroArch_setConfigOverride 'system_directory' "\\"${biosPath}\\"" "$RetroArch_configFile"
    	RetroArch_setConfigOverride 'rgui_browser_directory' "\\"${romsPath}\\"" "$RetroArch_configFile"
    }
"""
)

FLYCAST_SH = text(
    """
    Flycast_configFile="$HOME/.var/app/org.flycast.Flycast/config/flycast/emu.cfg"
    Flycast_setEmulationFolder(){
    	mkdir -p "${biosPath}/flycast/"
    	ln -sn "$HOME/.var/app/org.flycast.Flycast/data/flycast/" "${biosPath}/flycast/bios"
    }
"""
)

CITRON_SH = text(
    """
    Citron_setupStorage(){
        unlink "${biosPath}/citron/keys" 2>/dev/null
        mkdir -p "${biosPath}/citron"
        ln -sn "$HOME/.local/share/citron/keys/" "${biosPath}/citron/keys"
        ln -sn "$HOME/.local/share/citron/nand/system/Contents/registered/" "${biosPath}/citron/firmware"
    }
"""
)

SHADPS4_SH = text(
    """
    ShadPS4_dir="$HOME/.local/share/shadPS4"
    ShadPS4_setupStorage(){
        mkdir -p "${biosPath}/shadps4/"
        ln -sn "$ShadPS4_dir/sys_modules" "${biosPath}/shadps4/sys_modules"
    }
"""
)


CONFIG_EMU_FP = text(
    """
    configEmuFP(){
    	if [[ $overwrite == 'true' ]]; then
    		overwrite="--backup --suffix=.bak"
        else
            overwrite="--ignore-existing"
        fi
    	rsync -avhp --mkpath "$emudeckBackend/configs/${ID}" "$HOME/.var/app/" $overwrite
    }
"""
)


def tree(**scripts: str) -> RepoTree:
    files = {f"{S}/{name}": body for name, body in scripts.items()}
    files[el.CONFIG_EMU_FP] = CONFIG_EMU_FP
    files[f"{el.CONFIGS}/dev.ares.ares/data/ares/settings.bml"] = ARES_BML
    files[f"{el.CONFIGS}/net.kuribo64.melonDS/config/melonDS/melonDS.ini"] = MELONDS_INI
    files[f"{el.CONFIGS}/net.kuribo64.melonDS/config/melonDS/melonDS.toml"] = MELONDS_TOML
    return RepoTree.from_files(files)


class WrittenIntoTheConfig(unittest.TestCase):
    def test_ares_firmware_follows_the_rewritten_prefix(self):
        colecovision, pcecd = (r.entry() for r in el.ares(tree(**{"emuDeckares.sh": ARES_SH})))
        self.assertEqual(
            (colecovision["slot"], colecovision["names"]), ("ColecoVision", ["colecovision.rom"])
        )
        self.assertEqual(pcecd["names"], ["syscard3u.pce", "syscard3.pce"])
        self.assertEqual(pcecd["search_dir"], "${biosPath}")
        self.assertEqual(
            pcecd["passes_to"],
            "settings.bml PCEngineCD/Firmware/BIOS.US, PCEngineCD/Firmware/BIOS.Japan",
        )
        self.assertEqual(
            pcecd["source_ref"],
            f"{el.CONFIGS}/dev.ares.ares/data/ares/settings.bml:9-10, {S}/emuDeckares.sh:1, 5-6",
        )

    def test_a_firmware_key_without_a_value_is_not_a_name(self):
        records = [r.entry() for r in el.ares(tree(**{"emuDeckares.sh": ARES_SH}))]
        self.assertNotIn("NeoGeoMVS", [r["slot"] for r in records])

    def test_ares_without_the_bios_rewrite_raises(self):
        script = ARES_SH.replace("${biosPath}", "${romsPath}")
        with self.assertRaises(LauncherPatternMissing):
            el.ares(tree(**{"emuDeckares.sh": script}))

    def test_melonds_ini_keys_and_toml_rewrite(self):
        ini, toml = (r.entry() for r in el.melonds(tree(**{"emuDeckMelonDS.sh": MELONDS_SH})))
        self.assertEqual(ini["names"], ["bios9.bin", "bios7.bin"])
        self.assertEqual(ini["search_dir"], "${biosPath}")
        self.assertEqual(ini["passes_to"], "melonDS.ini BIOS9Path, BIOS7Path")
        self.assertEqual(
            ini["depends_on_option"], "ExternalBIOSEnable = 0 in the shipped melonDS.ini"
        )
        self.assertEqual(toml["names"], ["firmware.bin", "bios7.bin", "dsi_nand.bin"])
        self.assertEqual(toml["search_dir"], "${emulationPath}/bios")
        self.assertEqual(
            toml["passes_to"], "melonDS.toml [DS] FirmwarePath, BIOS7Path [DSi] NANDPath"
        )
        # The DS keys wait for ExternalBIOSEnable, the DSi keys for a DSi.
        self.assertEqual(
            toml["depends_on_option"],
            "[DS] keys: ExternalBIOSEnable = true, false in the shipped melonDS.toml; "
            "[DSi] keys: ConsoleType = 1, 0 in the shipped melonDS.toml",
        )
        # configEmuFP's update call passes --ignore-existing.
        self.assertIs(toml["kept_if_present"], True)
        self.assertEqual(
            toml["installs"]["path"],
            "${HOME}/.var/app/net.kuribo64.melonDS/config/melonDS/melonDS.toml",
        )

    def test_a_config_the_setters_rewrite_keeps_their_values(self):
        records = [r.entry() for r in el.melonds(tree(**{"emuDeckMelonDS.sh": MELONDS_SH}))]
        self.assertEqual(
            [r["search_dir"] for r in records], ["${biosPath}", "${emulationPath}/bios"]
        )

    def test_files_are_grouped_by_directory(self):
        bios, storage = (
            r.entry()
            for r in el.setter_records(tree(**{"emuDeckXemu.sh": XEMU_SH}), "emuDeckXemu.sh")
        )
        self.assertEqual(bios["names"], ["mcpx_1.0.bin", "Complex_4627v1.03.bin"])
        self.assertEqual(bios["passes_to"], "xemu.toml bootrom_path, flashrom_path")
        self.assertEqual(
            (storage["search_dir"], storage["names"]), ("${storagePath}/xemu", ["eeprom.bin"])
        )
        self.assertEqual(bios["source_ref"], f"{S}/emuDeckXemu.sh:1-10")

    def test_a_bios_directory_is_left_to_the_emulator(self):
        (record,) = (
            r.entry()
            for r in el.setter_records(
                tree(**{"emuDeckDuckStation.sh": DUCKSTATION_SH}), "emuDeckDuckStation.sh"
            )
        )
        self.assertEqual(record["kind"], "scans_dir")
        self.assertEqual(record["search_dir"], "${biosPath}")
        self.assertEqual(record["passes_to"], "settings.ini SearchDirectory")
        (pcsx2,) = (
            r.entry()
            for r in el.setter_records(tree(**{"emuDeckPCSX2QT.sh": PCSX2_SH}), "emuDeckPCSX2QT.sh")
        )
        self.assertEqual(
            (pcsx2["emulator"], pcsx2["passes_to"]), ("pcsx2", "PCSX2.ini [Folders] Bios")
        )

    def test_a_search_path_list_is_kept_whole(self):
        (record,) = (
            r.entry()
            for r in el.setter_records(tree(**{"emuDeckMAME.sh": MAME_SH}), "emuDeckMAME.sh")
        )
        self.assertEqual(record["search_dir"], "${romsPath}/arcade;${biosPath};${biosPath}/mame")
        self.assertEqual(record["passes_to"], "mame.ini rompath")

    def test_retroarch_is_handed_the_directory(self):
        (record,) = (
            r.entry()
            for r in el.setter_records(
                tree(**{"emuDeckRetroArch.sh": RETROARCH_SH}), "emuDeckRetroArch.sh"
            )
        )
        self.assertEqual(
            (record["build"], record["kind"], record["search_dir"]),
            ("libretro", "passes_path", "${biosPath}"),
        )

    def test_an_unknown_directory_key_raises(self):
        script = DUCKSTATION_SH.replace("SearchDirectory", "BiosFolder")
        with self.assertRaises(LauncherPatternMissing):
            el.setter_records(tree(**{"emuDeckDuckStation.sh": script}), "emuDeckDuckStation.sh")

    def test_a_script_that_writes_no_bios_path_raises(self):
        script = PCSX2_SH.replace('"Bios" "${biosPath}"', '"Bios" "${storagePath}/bios"')
        with self.assertRaises(LauncherPatternMissing):
            el.setter_records(tree(**{"emuDeckPCSX2QT.sh": script}), "emuDeckPCSX2QT.sh")


class LinkedIntoBios(unittest.TestCase):
    def records(self) -> list[dict]:
        # Every link script must hold a BIOS link: the ones not under test reuse Flycast's.
        scripts = {name: FLYCAST_SH for name in el.LINK_SCRIPTS}
        scripts.update({"emuDeckCitron.sh": CITRON_SH, "emuDeckShadPS4.sh": SHADPS4_SH})
        return [r.entry() for r in el.links(tree(**scripts))]

    def test_the_link_lives_in_bios_and_points_at_the_emulator(self):
        flycast = next(r for r in self.records() if r["emulator"] == "flycast")
        self.assertEqual(flycast["search_dir"], "${biosPath}/flycast/bios")
        self.assertEqual(
            flycast["passes_to"],
            "symlink ${biosPath}/flycast/bios -> ${HOME}/.var/app/org.flycast.Flycast/data/flycast/",
        )
        self.assertEqual(flycast["source_ref"], f"{S}/emuDeckFlycast.sh:4")

    def test_each_directory_of_a_different_name_is_its_own_record(self):
        citron = [r for r in self.records() if r["emulator"] == "citron"]
        self.assertEqual(
            [r["search_dir"] for r in citron],
            ["${biosPath}/citron/keys", "${biosPath}/citron/firmware"],
        )

    def test_a_variable_in_the_target_is_expanded(self):
        shadps4 = next(r for r in self.records() if r["emulator"] == "shadps4")
        self.assertEqual(
            shadps4["passes_to"],
            "symlink ${biosPath}/shadps4/sys_modules -> ${HOME}/.local/share/shadPS4/sys_modules",
        )
        self.assertEqual(shadps4["source_ref"], f"{S}/emuDeckShadPS4.sh:1, 4")

    def test_a_script_without_a_bios_link_raises(self):
        scripts = {name: FLYCAST_SH for name in el.LINK_SCRIPTS}
        scripts["emuDeckCitron.sh"] = 'ln -sn "$HOME/a" "$HOME/b"\n'
        with self.assertRaises(LauncherPatternMissing):
            el.links(tree(**scripts))


class Helpers(unittest.TestCase):
    def test_a_quote_ends_a_variable_name(self):
        self.assertEqual(
            [w.text for w in words('changeLine "$buttonA""0" "${f}"')],
            ["changeLine", "${buttonA}0", "${f}"],
        )

    def test_script_names_map_to_the_emulator_profile(self):
        self.assertEqual(el.emulator_of_script("emuDeckRMG.sh"), "mupen64plus_next")
        self.assertEqual(el.emulator_of_script("emuDeckPCSX2QT.sh"), "pcsx2")
        self.assertEqual(el.emulator_of_script("emuDeckXemu.sh"), "xemu")
        self.assertIsNone(el.emulator_of_script("RetroArch_maincfg.sh"))
        self.assertIsNone(el.emulator_of_script("README.md"))
        self.assertEqual(el.emulator_of_script("emuDeckPCSX2QT.ps1"), "pcsx2")
        self.assertIsNone(el.emulator_of_script("emuDeckTemplate.ps1"))

    def test_the_revision_comes_from_the_pinned_url(self):
        url = (
            "https://raw.githubusercontent.com/dragoonDorise/EmuDeck/"
            "dddb30229adbbd54d5ff7283cfd70e11c4322c26/functions/checkBIOS.sh"
        )
        self.assertEqual(launcher_revision(url), "dddb30229adbbd54d5ff7283cfd70e11c4322c26")
        with self.assertRaises(ValueError):
            launcher_revision(
                "https://raw.githubusercontent.com/dragoonDorise/EmuDeck/main/functions/checkBIOS.sh"
            )


class PlatformRecords(unittest.TestCase):
    """The launchers platforms/emudeck.yml carries, as the scraper wrote them."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = yaml.safe_load((REPO_ROOT / "platforms" / "emudeck.yml").read_text())

    def test_every_emulator_is_one_emudeck_installs(self):
        cores = set(self.config["cores"])
        self.assertEqual(sorted({r["emulator"] for r in self.config["launchers"]} - cores), [])

    def test_every_reference_is_an_emuscript_or_a_shipped_config(self):
        for record in self.config["launchers"]:
            for part in record["source_ref"].split(", "):
                if ":" in part:
                    self.assertTrue(part.startswith((f"{S}/", f"{el.CONFIGS}/")), record)


if __name__ == "__main__":
    unittest.main()
