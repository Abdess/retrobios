"""RetroDECK's launcher layer read from each component's scripts and presets.

Each fixture copies the lines an extractor reads from RetroDECK/components
fcd0d72995d7aa2e741e2753ac6914025b2ff1ac, placed at the line numbers they
have there, so the source_ref a record carries is the one platforms/retrodeck.yml
cites. A construct that is gone or unknown must stop the scrape.
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

from scraper import retrodeck_launchers as rd  # noqa: E402


def at(first_line: int, text: str) -> str:
    """Text placed so its first line is line `first_line` of the file."""
    return place((first_line, text))


def place(*parts: tuple[int, str]) -> str:
    """Excerpts each placed at the line it starts on in the real file."""
    lines: list[str] = []
    for first_line, text in parts:
        excerpt = textwrap.dedent(text).lstrip("\n").splitlines()
        if len(lines) >= first_line:
            raise ValueError(f"excerpt at line {first_line} overlaps the one before")
        lines += [""] * (first_line - 1 - len(lines)) + excerpt
    return "\n".join(lines) + "\n"


MELONDS_FUNCTIONS = at(3, 'melonds_config="$XDG_CONFIG_HOME/melonDS/melonDS.toml"\n')

MELONDS_PREPARE = at(7, """
    if [[ "$action" == "reset" ]]; then # Run reset-only commands
      log i "----------------------"
      log i "Resetting $component_name"
      log i "----------------------"

      create_dir -d "$XDG_CONFIG_HOME/melonDS/"
      cp -fv "$component_config/melonDS.toml" "$melonds_config"

      create_dir "$saves_path/nds/melonds"
      create_dir "$states_path/nds/melonds"
      create_dir "$cheats_path/MelonDS"

      dir_prep "$bios_path" "$XDG_CONFIG_HOME/melonDS/bios"

      set_setting_value "$melonds_config" "BIOS9Path" "\\"$bios_path/bios9.bin\\"" "melonds" "DS"
      set_setting_value "$melonds_config" "BIOS7Path" "\\"$bios_path/bios7.bin\\"" "melonds" "DS"
      set_setting_value "$melonds_config" "FirmwarePath" "\\"$bios_path/firmware.bin\\"" "melonds" "DS"

      set_setting_value "$melonds_config" "NANDPath" "\\"$bios_path/dsi_nand.bin\\"" "melonds" "DSi"
      set_setting_value "$melonds_config" "BIOS7Path" "\\"$bios_path/dsi_bios7.bin\\"" "melonds" "DSi"
      set_setting_value "$melonds_config" "BIOS9Path" "\\"$bios_path/dsi_bios9.bin\\"" "melonds" "DSi"
      set_setting_value "$melonds_config" "FirmwarePath" "\\"$bios_path/dsi_firmware.bin\\"" "melonds" "DSi"

      set_setting_value "$melonds_config" "SaveFilePath" "\\"$saves_path/nds/melonds\\"" "melonds" "Instance0"
    fi
""")

XEMU_FUNCTIONS = at(3, 'xemu_conf="$XDG_CONFIG_HOME/xemu/xemu.toml"\n')

XEMU_PREPARE = at(20, """
      cp -fv "$component_config/xemu.toml" "$xemu_conf"
      create_dir "$screenshots_path/xemu"
      set_setting_value "$xemu_conf" "screenshot_dir" "'$screenshots_path/xemu'" "xemu" "General"
      set_setting_value "$xemu_conf" "bootrom_path" "'$bios_path/mcpx_1.0.bin'" "xemu" "sys.files"
      set_setting_value "$xemu_conf" "flashrom_path" "'$bios_path/Complex.bin'" "xemu" "sys.files"
      create_dir "$saves_path/xbox/xemu"
      set_setting_value "$xemu_conf" "eeprom_path" "'$saves_path/xbox/xemu/xbox-eeprom.bin'" "xemu" "sys.files"
      set_setting_value "$xemu_conf" "hdd_path" "'$bios_path/xbox_hdd.qcow2'" "xemu" "sys.files"


      # Preparing HD dummy Image if the image is not found
      if [ ! -f "$bios_path/xbox_hdd.qcow2" ];then
        cp -f "$component_extras/xbox_hdd.qcow2" "$bios_path/xbox_hdd.qcow2"
      fi
""")

RETROARCH_PREPARE = place((23, """
      cp -fv "$component_config/retroarch.cfg" "$retroarch_config"
      cp -fv "$component_config/retroarch-core-options.cfg" "$retroarch_config_core_options"
"""), (44, """
      set_setting_value "$retroarch_config" "system_directory" "$bios_path" "retroarch"
"""), (95, """
      cp -rf "$retroarch_extras_path/pcsx2" "$bios_path/pcsx2"
      dir_prep "$bios_path" "$bios_path/pcsx2/bios"
      dir_prep "$saves_path/ps2/retroarch-core/LRPS2/memcards" "$bios_path/pcsx2/memcards"
"""))

CORE_OPTIONS = place((165, """
    duckstation_BIOS.PathNTSCJ = "scph5500.bin"
    duckstation_BIOS.PathNTSCU = "scph5501.bin"
    duckstation_BIOS.PathPAL = "scph5502.bin"
"""), (515, """
    pcsx2_bios = "scph10000.bin"
    pcsx2_boot_bios = "disabled"
"""))

DOLPHIN_PREPARE = at(19, """
      dir_prep "$saves_path/gc/dolphin/EU" "$XDG_DATA_HOME/dolphin-emu/GC/EUR" # TODO: Multi-user one-off
      dir_prep "$saves_path/gc/dolphin/US" "$XDG_DATA_HOME/dolphin-emu/GC/USA" # TODO: Multi-user one-off
      dir_prep "$saves_path/gc/dolphin/JP" "$XDG_DATA_HOME/dolphin-emu/GC/JAP" # TODO: Multi-user one-off
      dir_prep "$screenshots_path" "$XDG_DATA_HOME/dolphin-emu/ScreenShots"
""")

RPCS3_FUNCTIONS = at(11, """
    rpcs3_firmware="http://dus01.ps3.update.playstation.net/update/ps3/image/us/2026_0318_a2b60b6ac1d2e49e230144345616927c/PS3UPDAT.PUP"

    update_rpcs3_firmware() {
      if [[ $(check_network_connectivity) == "true" ]]; then
        configurator_generic_dialog "RetroDECK Configurator - Install: RPCS3 Firmware" "This tool will download the firmware."
        (
          create_dir "$roms_path/ps3/tmp"
          chmod 777 "$roms_path/ps3/tmp"
          download_file "$rpcs3_firmware" "$roms_path/ps3/tmp/PS3UPDAT.PUP" "RPCS3 Firmware"
          bash "$rpcs3_component_dir/component_launcher.sh" --installfw "$roms_path/ps3/tmp/PS3UPDAT.PUP"
          rm -rf "$roms_path/ps3/tmp"
        )
      fi
    }
""")

PICO8_LAUNCHER = at(3, 'exec "$bios_path/pico-8/pico8" -desktop_path "$screenshots_path" "$@"\n')

XROAR_PREPARE = at(12, """
      create_dir -d "$XDG_CONFIG_HOME/xroar"
      cp -f "$component_config/xroar.conf" "$xroar_config" && log i "Copied default xroar.conf to $xroar_config"
      sed -i "s#RETRODECKROMSDIR#${roms_path}#g" "$xroar_config" && log i "Set ROMs directory in xroar.conf"
      sed -i "s#RETRODECKBIOSDIR#${bios_path}#g" "$xroar_config" && log i "Set BIOS directory in xroar.conf"
""")

XROAR_CONF = place((290, """
    rompath RETRODECKROMSDIR/coco:RETRODECKROMSDIR/dragon32:RETRODECKROMSDIR/tanodragon:RETRODECKBIOSDIR
    romlist dragon=dragon
    romlist d64_1=d64_1,d64rom1,"Dragon Data Ltd - Dragon 64 - IC17","Dragon Data Ltd - TANO IC18","Eurohard S.A. - Dragon 200 IC18",dragrom
"""), (297, """
    romlist dragon64=@d64_1,@dragon
"""))


def tree(**components: dict[str, str]) -> dict[str, str]:
    return {
        f"{name}/{path}": text
        for name, files in components.items()
        for path, text in files.items()
    }


def melonds(prepare: str) -> dict[str, str]:
    return tree(melonds={
        "component_prepare.sh": prepare, "component_functions.sh": MELONDS_FUNCTIONS,
    })


def launchers(files: dict[str, str], components: list[str]) -> list[dict]:
    return rd.extract_launchers(components, files.get)


RETROARCH = {
    "component_prepare.sh": RETROARCH_PREPARE,
    "rd_assets/rd_config/retroarch-core-options.cfg": CORE_OPTIONS,
}


class FixedNames(unittest.TestCase):
    def test_melonds_gets_seven_paths_in_the_order_written(self):
        files = melonds(MELONDS_PREPARE)
        fixed = next(r for r in launchers(files, ["melonds"]) if r["kind"] == "fixed_name")
        self.assertEqual(fixed["names"], [
            "bios9.bin", "bios7.bin", "firmware.bin",
            "dsi_nand.bin", "dsi_bios7.bin", "dsi_bios9.bin", "dsi_firmware.bin",
        ])
        self.assertEqual(fixed["search_dir"], "$bios_path")
        self.assertTrue(
            fixed["passes_to"].startswith("melonDS.toml [DS] BIOS9Path, [DS] BIOS7Path")
        )
        self.assertEqual(fixed["source_ref"], "melonds/component_prepare.sh:21-23, 25-28")

    def test_melonds_reads_bios_through_a_link(self):
        files = melonds(MELONDS_PREPARE)
        link = next(r for r in launchers(files, ["melonds"]) if r["kind"] == "links")
        self.assertEqual(link["passes_to"], "$XDG_CONFIG_HOME/melonDS/bios is a symlink to it")
        self.assertEqual(link["source_ref"], "melonds/component_prepare.sh:19")

    def test_xemu_writes_three_paths_and_copies_a_blank_disk(self):
        files = tree(xemu={
            "component_prepare.sh": XEMU_PREPARE, "component_functions.sh": XEMU_FUNCTIONS,
        })
        found = launchers(files, ["xemu"])
        fixed = next(r for r in found if r["kind"] == "fixed_name")
        self.assertEqual(fixed["names"], ["mcpx_1.0.bin", "Complex.bin", "xbox_hdd.qcow2"])
        self.assertEqual(fixed["source_ref"], "xemu/component_prepare.sh:23-24, 27")
        copy = next(r for r in found if r["kind"] == "copies")
        self.assertEqual(copy["depends_on_option"], '[ ! -f "$bios_path/xbox_hdd.qcow2" ]')
        self.assertEqual(copy["source_ref"], "xemu/component_prepare.sh:32")

    def test_pico8_starts_the_binary_the_user_supplies(self):
        files = tree(**{"pico-8": {"component_launcher.sh": PICO8_LAUNCHER}})
        record = launchers(files, ["pico-8"])[0]
        self.assertEqual((record["names"], record["search_dir"]), (["pico8"], "$bios_path/pico-8"))
        self.assertIs(record["fails_when_missing"], True)
        self.assertEqual(record["source_ref"], "pico-8/component_launcher.sh:3")

    def test_rpcs3_firmware_is_downloaded_then_installed(self):
        files = tree(rpcs3={"component_functions.sh": RPCS3_FUNCTIONS})
        record = launchers(files, ["rpcs3"])[0]
        self.assertEqual(record["names"], ["PS3UPDAT.PUP"])
        self.assertEqual(record["passes_to"], "component_launcher.sh --installfw")
        self.assertIn("2026_0318_a2b60b6ac1d2e49e230144345616927c", record["depends_on_option"])
        self.assertEqual(record["source_ref"], "rpcs3/component_functions.sh:11, 19-20")

    def test_a_download_never_installed_raises(self):
        broken = RPCS3_FUNCTIONS.replace("--installfw", "--run")
        with self.assertRaises(rd.LauncherPatternMissing):
            launchers(tree(rpcs3={"component_functions.sh": broken}), ["rpcs3"])


class RetroArch(unittest.TestCase):
    def test_core_options_that_name_a_file(self):
        found = launchers(tree(retroarch=RETROARCH), ["retroarch"])
        found = [r for r in found if r["kind"] == "core_option"]
        self.assertEqual(
            [(r["names"], r["passes_to"]) for r in found],
            [
                (["scph5500.bin"], "core option duckstation_BIOS.PathNTSCJ"),
                (["scph5501.bin"], "core option duckstation_BIOS.PathNTSCU"),
                (["scph5502.bin"], "core option duckstation_BIOS.PathPAL"),
                (["scph10000.bin"], "core option pcsx2_bios"),
            ],
        )
        self.assertEqual(
            found[3]["source_ref"],
            "retroarch/rd_assets/rd_config/retroarch-core-options.cfg:515, "
            "retroarch/component_prepare.sh:24",
        )

    def test_lrps2_bios_folder_points_back_at_bios(self):
        found = launchers(tree(retroarch=RETROARCH), ["retroarch"])
        links = [r for r in found if r["kind"] == "links"]
        self.assertEqual([(r["search_dir"], r["passes_to"]) for r in links],
                         [("$bios_path", "$bios_path/pcsx2/bios is a symlink to it")])
        self.assertEqual(links[0]["source_ref"], "retroarch/component_prepare.sh:96")

    def test_a_preset_never_copied_raises(self):
        prepare = RETROARCH_PREPARE.replace("retroarch-core-options.cfg", "other.cfg")
        files = tree(retroarch={**RETROARCH, "component_prepare.sh": prepare})
        with self.assertRaises(rd.LauncherPatternMissing):
            launchers(files, ["retroarch"])


class Links(unittest.TestCase):
    def test_dolphin_reads_ipl_from_save_folders(self):
        found = launchers(tree(dolphin={"component_prepare.sh": DOLPHIN_PREPARE}), ["dolphin"])
        self.assertEqual(
            [(r["slot"], r["search_dir"]) for r in found],
            [("EUR", "$saves_path/gc/dolphin/EU"), ("USA", "$saves_path/gc/dolphin/US"),
             ("JAP", "$saves_path/gc/dolphin/JP")],
        )
        self.assertEqual(found[1]["source_ref"], "dolphin/component_prepare.sh:20")


class Presets(unittest.TestCase):
    def files(self, conf: str = XROAR_CONF) -> dict[str, str]:
        return tree(xroar={
            "component_prepare.sh": XROAR_PREPARE, "rd_assets/rd_config/xroar.conf": conf,
        })

    def test_xroar_romlists_expand_their_references_in_order(self):
        found = launchers(self.files(), ["xroar"])
        search = next(r for r in found if r["kind"] == "passes_path")
        self.assertEqual(
            search["search_dir"],
            "$roms_path/coco:$roms_path/dragon32:$roms_path/tanodragon:$bios_path",
        )
        lists = {r["slot"]: r for r in found if r["kind"] == "names_searched"}
        self.assertEqual(lists["dragon64"]["names"][:2], ["d64_1", "d64rom1"])
        self.assertEqual(lists["dragon64"]["names"][-1], "dragon")
        self.assertEqual(
            lists["d64_1"]["source_ref"],
            "xroar/rd_assets/rd_config/xroar.conf:292, xroar/component_prepare.sh:13-15",
        )

    def test_a_reference_to_an_unknown_romlist_raises(self):
        with self.assertRaises(rd.LauncherPatternMissing):
            launchers(self.files(XROAR_CONF.replace("@dragon", "@dragonx")), ["xroar"])

    def test_a_preset_without_the_placeholder_raises(self):
        with self.assertRaises(rd.LauncherPatternMissing):
            launchers(self.files(XROAR_CONF.replace("RETRODECKBIOSDIR", "/bios")), ["xroar"])


class UnknownConstructs(unittest.TestCase):
    def test_an_unclassified_use_of_bios_path_raises(self):
        broken = MELONDS_PREPARE.replace(
            'create_dir "$cheats_path/MelonDS"', 'rsync -a "$bios_path/" "$XDG_DATA_HOME/melonDS/"'
        )
        files = melonds(broken)
        with self.assertRaises(rd.LauncherPatternMissing):
            launchers(files, ["melonds"])

    def test_no_record_at_all_raises(self):
        with self.assertRaises(rd.LauncherPatternMissing):
            launchers({}, ["azahar"])


class PlatformRecords(unittest.TestCase):
    """The launchers platforms/retrodeck.yml carries, as the scraper wrote them."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = yaml.safe_load((REPO_ROOT / "platforms" / "retrodeck.yml").read_text())

    def test_every_emulator_is_a_component_retrodeck_ships(self):
        named = {r["emulator"] for r in self.config["launchers"]}
        self.assertEqual(sorted(named - set(self.config["cores"])), [])

    def test_every_reference_is_in_a_component(self):
        for record in self.config["launchers"]:
            first = record["source_ref"].split("/", 1)[0]
            self.assertIn(first, self.config["cores"], record)


if __name__ == "__main__":
    unittest.main()
