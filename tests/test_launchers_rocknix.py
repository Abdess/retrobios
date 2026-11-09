"""ROCKNIX's launcher layer read from its packages.

Each fixture is a cut-down copy of the lines an extractor reads at
ROCKNIX/distribution 20261001 (c445081a59518f37d9776e5412dd7b14910696f7).
The records must carry the names in the order the code writes or tries them,
point at the fixture's own lines, name a device only where the shipped
configs differ, and a construct that is gone must stop the scrape.
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

from scraper import rocknix_launchers as rl  # noqa: E402
from scraper.rocknix_scraper import launcher_revision  # noqa: E402
from scraper.shell_launchers import LauncherPatternMissing, RepoTree  # noqa: E402

SA = rl.STANDALONE


def text(block: str) -> str:
    return textwrap.dedent(block).lstrip("\n")


def devices(*names: str) -> dict[str, str]:
    return {f"{rl.DEVICES}/{name}/options": "" for name in names}


MELONDS_MK = text(
    """
    makeinstall_target() {
      mkdir -p ${INSTALL}/usr/config/melonDS
        cp -a ${PKG_DIR}/config/${DEVICE}/* ${INSTALL}/usr/config/melonDS
    }
"""
)

MELONDS_INI = text(
    """
    ExternalBIOSEnable=0
    BIOS9Path=/storage/roms/bios/bios9.bin
    BIOS7Path=/storage/roms/bios/bios7.bin
    FirmwarePath=/storage/roms/bios/firmware.bin
    DSiBIOS9Path=/storage/roms/bios/dsi_bios9.bin
    DSiBIOS7Path=/storage/roms/bios/dsi_bios7.bin
    DSiFirmwarePath=/storage/roms/bios/dsi_firmware.bin
    DSiNANDPath=/storage/roms/bios/dsi_nand.bin
"""
)

MELONDS_AMD64_INI = text(
    """
    ExternalBIOSEnable=0
    BIOS9Path=
    BIOS7Path=
    FirmwarePath=
    DSiBIOS9Path=
    DSiBIOS7Path=
    DSiFirmwarePath=
    DSiNANDPath=
"""
)

MELONDS_SH = text(
    """
    CONTYPE=$(get_setting console_type "${PLATFORM}" "${GAME}")
    DBOOT=$(get_setting direct_boot "${PLATFORM}" "${GAME}")
    if [ "$PLATFORM" = "ndsiware" ]; then
        sed -i '/^DirectBoot=/c\\DirectBoot=0' /storage/.config/melonDS/melonDS.ini
    else
        if [ "$DBOOT" = "0" ]; then
            sed -i '/^DirectBoot=/c\\DirectBoot=0' /storage/.config/melonDS/melonDS.ini
            sed -i '/^ExternalBIOSEnable=/c\\ExternalBIOSEnable=1' /storage/.config/melonDS/melonDS.ini
        else
            sed -i '/^ExternalBIOSEnable=/c\\ExternalBIOSEnable=0' /storage/.config/melonDS/melonDS.ini
        fi
    fi
"""
)


def melonds_tree() -> RepoTree:
    pkg = f"{SA}/melonds-sa"
    return RepoTree.from_files(
        {
            **devices("AMD64", "H700", "RK3576", "S922X"),
            f"{pkg}/package.mk": MELONDS_MK,
            f"{pkg}/scripts/start_melonds.sh": MELONDS_SH,
            f"{pkg}/config/AMD64/melonDS.ini": MELONDS_AMD64_INI,
            f"{pkg}/config/InputPlumber/melonDS.ini": MELONDS_INI,
            f"{pkg}/config/S922X/melonDS.ini": MELONDS_INI,
        },
        links={f"{pkg}/config/RK3576": "InputPlumber"},
    )


DSPERATE_MK = text(
    """
    makeinstall_target() {
      case ${DEVICE} in
        RK3576|SM4450|SM6115|SM8250|SM8550|SM8650|SM8750) CONFIG="InputPlumber" ;;
        *) CONFIG="${DEVICE}" ;;
      esac
        cp -a ${PKG_DIR}/config/${CONFIG}/* ${INSTALL}/usr/config/dsperate
    }
"""
)

DSPERATE_INI = text(
    """
    [paths]
    bios9 = /storage/roms/bios/bios9.bin
    bios7 = /storage/roms/bios/bios7.bin
    firmware = /storage/roms/bios/firmware.bin
    bios9i = /storage/roms/bios/dsi_bios9.bin
    bios7i = /storage/roms/bios/dsi_bios7.bin
    dsi_firmware = /storage/roms/bios/dsi_firmware.bin
    dsi_nand = /storage/roms/bios/dsi_nand.bin
    games = /storage/roms/nds
"""
)

AMIBERRY_SH = text(
    """
    AMIBERRY_DIR="/storage/.config/amiberry"
    AMIBERRY_CONFIG_DIR="${AMIBERRY_DIR}/conf"
    BIOS_PATH="/storage/roms/bios"
    AMIBERRY_SET_CONF() {
      if [ `echo $1 | grep -E 'AGA|CD32' | wc -l` -eq 1 ]; then
        cp ${AMIBERRY_CONFIG_DIR}/AmigaA1200-default.uae "${AMIBERRY_TMP_CONFIG}"
      else
        cp ${AMIBERRY_CONFIG_DIR}/AmigaA500-default.uae "${AMIBERRY_TMP_CONFIG}"
      fi
      sed -i "s#@BIOS_PATH@#${BIOS_PATH}#g" ${AMIBERRY_TMP_CONFIG}
    }
    if [ ! -d "${AMIBERRY_DIR}" ]
    then
      cp -rf /usr/config/amiberry ${AMIBERRY_DIR}
    fi
    cd ${AMIBERRY_DIR}
"""
)

AMIBERRY_MK = text(
    """
    makeinstall_target() {
      mkdir -p ${INSTALL}/usr/config/amiberry
        cp -a ${PKG_DIR}/config/* ${INSTALL}/usr/config/amiberry
        ln -s /storage/roms/bios ${INSTALL}/usr/config/amiberry/kickstarts
        ln -s /usr/share/libretro/autoconfig ${INSTALL}/usr/config/amiberry/controller
    }
"""
)

MEDNAFEN_TEMPLATE = text(
    """
    ;Path to firmware directory.
    filesys.path_firmware /storage/roms/bios/

    ;Path to PlayStation BIOS, Europe.
    psx.bios_eu scph5502.bin

    ;Path to PlayStation BIOS, Japan.
    psx.bios_jp scph5500.bin

    ;Enable BIOS sanity check.
    psx.bios_sanity 1

    ;Path to PC Engine CD BIOS.
    pce.cdbios syscard3.pce
"""
)

MEDNAFEN_SH = text(
    """
    if [ ! -f "$MEDNAFEN_HOME/mednafen.cfg" ]
    then
        /usr/bin/bash /usr/bin/mednafen_gen_config.sh
    fi
"""
)

YABASANSHIRO_SH = text(
    """
    BIOS=""
    USE_BIOS=$(get_setting use_hlebios "${PLATFORM}" "${GAME}")
    if [ "$USE_BIOS" = 1 ]
    then
      for BIOS in saturn_bios.bin sega_101.bin mpr-17933.bin mpr-18811-mx.ic1 mpr-19367-mx.ic1 stvbios.zip
      do
        BIOS=$(find /storage/roms/bios -name ${BIOS} -print 2>/dev/null)
        if [ ! -z "${BIOS}" ]
        then
          BIOS="-b ${BIOS}"
          break
        fi
      done
    fi
"""
)

DUCKSTATION_MK = text(
    """
    makeinstall_target() {
        cp -a ${PKG_DIR}/config/${DEVICE}/* ${INSTALL}/usr/config/duckstation
    }
"""
)

DRASTIC_SH = text(
    """
    for bios in nds_bios_arm9.bin nds_bios_arm7.bin
    do
      if [ ! -e "/storage/.config/drastic/system/${bios}" ]; then
         if [ -e "/storage/roms/bios/${bios}" ]; then
           ln -sf /storage/roms/bios/${bios} /storage/.config/drastic/system
         fi
      fi
    done
"""
)

DOLPHIN_SH = text(
    """
    CONF_DIR="/storage/.config/dolphin-emu"
    ln -sf /storage/roms/savestates/gamecube ${CONF_DIR}/StateSaves
    for REGION in EUR JAP USA
    do
      rm -rf "${CONF_DIR}/GC/${REGION}"
      ln -sf "/storage/roms/bios/GC/${REGION}" "${CONF_DIR}/GC/${REGION}"
      for SLOT in A B
      do
        MEM_CARD_FILE="MemoryCard${SLOT}.${REGION}.raw"
        CONFIG_MEM_CARD="${CONF_DIR}/GC/${MEM_CARD_FILE}"
        ROMS_BIOS_MEM_CARD="/storage/roms/bios/GC/${MEM_CARD_FILE}"
        if [ -f "${ROMS_BIOS_MEM_CARD}" ]; then
          ln -sf "${ROMS_BIOS_MEM_CARD}" "${CONFIG_MEM_CARD}"
        elif [ -f "${CONFIG_MEM_CARD}" ]; then
          ln -sf "${ROMS_BIOS_MEM_CARD}" "${CONFIG_MEM_CARD}"
        fi
      done
    done
"""
)

CEMU_SH = text(
    """
    CEMU_CONFIG_ROOT="/storage/.config/Cemu"
    CEMU_HOME_CONFIG="${CEMU_CONFIG_ROOT}/share"
    CEMU_HOME_ONLINE="${CEMU_HOME_CONFIG}/online"
    CEMU_HOME_KEYS="${CEMU_HOME_CONFIG}/keys"
    CEMU_BIOS="/storage/roms/bios/cemu"
    if [ ! -L ${CEMU_HOME_ONLINE} ]; then
      ln -sf ${CEMU_BIOS}/online ${CEMU_HOME_ONLINE}
    fi
    if [ ! -L ${CEMU_HOME_KEYS} ]; then
      ln -sf ${CEMU_BIOS}/keys ${CEMU_HOME_KEYS}
    fi
"""
)

RPCS3_SH = text(
    """
    FOLDER_LINKS=("dev_flash" "dev_hdd0" "dev_hdd1" "custom_configs")
    for FOLDER_LINK in "${FOLDER_LINKS[@]}"; do
      TARGET_FOLDER="/storage/roms/bios/rpcs3/$FOLDER_LINK"
      SOURCE_FOLDER="/storage/.config/rpcs3/$FOLDER_LINK"
      rm -rf "$SOURCE_FOLDER"
      ln -sf "$TARGET_FOLDER" "$SOURCE_FOLDER"
    done
"""
)

FLYCAST_SH = text(
    """
    if [ ! -d "/storage/roms/bios/dc" ]; then
      mkdir -p "/storage/roms/bios/dc"
    fi
    ln -sf "/storage/roms/bios/dc" "/storage/roms/dreamcast/data"
"""
)


def by(records: list[dict], emulator: str) -> list[dict]:
    return [r for r in records if r["emulator"] == emulator]


class ConfigsPerDevice(unittest.TestCase):
    def test_a_device_appears_only_where_configs_differ(self):
        records = [r.entry() for r in rl.melonds(melonds_tree())]
        self.assertEqual([r["device"] for r in records], ["AMD64", "RK3576, S922X"])
        empty, named = records
        self.assertEqual(empty["names"], [])
        self.assertTrue(empty["passes_to"].endswith("DSiNANDPath left empty"))
        self.assertEqual(
            named["names"],
            [
                "bios9.bin",
                "bios7.bin",
                "firmware.bin",
                "dsi_bios9.bin",
                "dsi_bios7.bin",
                "dsi_firmware.bin",
                "dsi_nand.bin",
            ],
        )
        self.assertEqual(named["search_dir"], "/storage/roms/bios")

    def test_a_linked_device_directory_reads_its_target(self):
        named = rl.melonds(melonds_tree())[1].entry()
        self.assertIn(f"{SA}/melonds-sa/config/InputPlumber/melonDS.ini:2-8", named["source_ref"])
        self.assertNotIn("config/RK3576", named["source_ref"])

    def test_the_external_bios_switch_is_the_option(self):
        named = rl.melonds(melonds_tree())[1].entry()
        self.assertEqual(
            named["depends_on_option"], "direct_boot = 0 sets ExternalBIOSEnable=1, otherwise 0"
        )
        self.assertIn(f"{SA}/melonds-sa/scripts/start_melonds.sh:2, 6-8", named["source_ref"])

    def test_identical_configs_give_one_record_without_device(self):
        pkg = f"{SA}/dsperate-sa"
        tree = RepoTree.from_files(
            {
                **devices("H700", "RK3576", "S922X"),
                f"{pkg}/package.mk": DSPERATE_MK,
                f"{pkg}/scripts/start_dsperate.sh": '${EMUPERF} /usr/bin/dsperate --config "${DSPERATE_INI}" "${ROM}"\n',
                f"{pkg}/config/H700/dsperate.ini": DSPERATE_INI,
                f"{pkg}/config/InputPlumber/dsperate.ini": DSPERATE_INI,
                f"{pkg}/config/S922X/dsperate.ini": DSPERATE_INI,
            }
        )
        (record,) = [r.entry() for r in rl.dsperate(tree)]
        self.assertNotIn("device", record)
        self.assertEqual(
            record["passes_to"],
            "dsperate.ini [paths] bios9, bios7, firmware, bios9i, bios7i, dsi_firmware, dsi_nand (--config)",
        )
        # The case statement sends RK3576 to InputPlumber.
        self.assertIn(f"{pkg}/config/InputPlumber/dsperate.ini:2-8", record["source_ref"])
        self.assertIn(f"{pkg}/package.mk:3-4", record["source_ref"])

    def test_an_absent_key_and_an_empty_one_hand_over_the_same(self):
        pkg = f"{SA}/duckstation-sa"
        tree = RepoTree.from_files(
            {
                **devices("AMD64", "S922X"),
                f"{pkg}/package.mk": DUCKSTATION_MK,
                f"{pkg}/config/AMD64/settings.ini": "[BIOS]\nSearchDirectory = /storage/roms/bios\n",
                f"{pkg}/config/S922X/settings.ini": text(
                    """
                [BIOS]
                SearchDirectory = /storage/roms/bios
                PathNTSCU =
                PathNTSCJ =
                PathPAL =
            """
                ),
            }
        )
        (record,) = [r.entry() for r in rl.duckstation(tree)]
        self.assertEqual(record["kind"], "scans_dir")
        self.assertEqual(record["search_dir"], "/storage/roms/bios")
        self.assertNotIn("device", record)

    def test_a_bios_written_into_a_path_key_is_an_unknown_shape(self):
        pkg = f"{SA}/duckstation-sa"
        tree = RepoTree.from_files(
            {
                **devices("S922X"),
                f"{pkg}/package.mk": DUCKSTATION_MK,
                f"{pkg}/config/S922X/settings.ini": "[BIOS]\nSearchDirectory = /storage/roms/bios\nPathNTSCU = scph5501.bin\n",
            }
        )
        with self.assertRaises(LauncherPatternMissing):
            rl.duckstation(tree)

    def test_a_package_without_a_device_copy_raises(self):
        pkg = f"{SA}/duckstation-sa"
        tree = RepoTree.from_files(
            {
                **devices("S922X"),
                f"{pkg}/package.mk": "makeinstall_target() {\n  true\n}\n",
                f"{pkg}/config/S922X/settings.ini": "[BIOS]\nSearchDirectory = /storage/roms/bios\n",
            }
        )
        with self.assertRaises(LauncherPatternMissing):
            rl.duckstation(tree)


class NamesTheConfigsFix(unittest.TestCase):
    def test_amiberry_machine_follows_the_game_name(self):
        pkg = f"{SA}/amiberry"
        uae = "amiberry.rom_path=/storage/.config/amiberry/kickstarts/\nkickstart_rom_file=@BIOS_PATH@/{}\nkickstart_ext_rom_file=\n"
        tree = RepoTree.from_files(
            {
                f"{pkg}/scripts/start_amiberry.sh": AMIBERRY_SH,
                f"{pkg}/package.mk": AMIBERRY_MK,
                f"{pkg}/config/conf/AmigaA1200-default.uae": uae.format("kick40068.A1200.rom"),
                f"{pkg}/config/conf/AmigaA500-default.uae": uae.format("kick34005.A500.rom"),
            }
        )
        a1200, a500, link, entered, copied = (r.entry() for r in rl.amiberry(tree))
        self.assertEqual((a1200["slot"], a1200["names"]), ("A1200", ["kick40068.A1200.rom"]))
        self.assertEqual(a1200["depends_on_option"], "game name matches AGA|CD32")
        self.assertEqual((a500["slot"], a500["names"]), ("A500", ["kick34005.A500.rom"]))
        self.assertEqual(a500["depends_on_option"], "game name does not match AGA|CD32")
        self.assertEqual(a500["search_dir"], "/storage/roms/bios")
        self.assertEqual(
            a1200["source_ref"],
            f"{pkg}/scripts/start_amiberry.sh:3-10, {pkg}/config/conf/AmigaA1200-default.uae:2",
        )
        self.assertEqual(link["kind"], "links")
        self.assertEqual(
            link["passes_to"], "symlink /usr/config/amiberry/kickstarts -> /storage/roms/bios"
        )
        self.assertEqual(link["source_ref"], f"{pkg}/package.mk:4")
        # The script runs amiberry in the copy of /usr/config/amiberry, which
        # carries the kickstarts link.
        self.assertEqual(
            (entered["kind"], entered["search_dir"], entered["passes_to"]),
            ("passes_path", "/storage/.config/amiberry", "working directory of start_amiberry.sh"),
        )
        self.assertEqual(entered["source_ref"], f"{pkg}/scripts/start_amiberry.sh:1, 16")
        self.assertEqual(
            copied["passes_to"],
            "symlink /storage/.config/amiberry/kickstarts -> /storage/roms/bios,"
            " copied with /usr/config/amiberry",
        )
        self.assertEqual(
            copied["source_ref"], f"{pkg}/package.mk:4, {pkg}/scripts/start_amiberry.sh:1, 14-16"
        )

    def test_mednafen_one_record_per_module(self):
        pkg = f"{SA}/mednafen"
        tree = RepoTree.from_files(
            {
                f"{pkg}/config/common/mednafen.template": MEDNAFEN_TEMPLATE,
                f"{pkg}/scripts/start_mednafen.sh": MEDNAFEN_SH,
            }
        )
        psx, pce = (r.entry() for r in rl.mednafen(tree))
        self.assertEqual((psx["slot"], psx["names"]), ("psx", ["scph5502.bin", "scph5500.bin"]))
        self.assertEqual(psx["passes_to"], "mednafen.cfg psx.bios_eu, psx.bios_jp")
        self.assertEqual(pce["names"], ["syscard3.pce"])
        self.assertEqual(psx["search_dir"], "/storage/roms/bios/")
        self.assertEqual(
            psx["source_ref"],
            f"{pkg}/config/common/mednafen.template:2, 5, 8, {pkg}/scripts/start_mednafen.sh:1-3",
        )

    def test_mednafen_without_a_firmware_directory_raises(self):
        pkg = f"{SA}/mednafen"
        tree = RepoTree.from_files(
            {
                f"{pkg}/config/common/mednafen.template": "psx.bios_eu scph5502.bin\n",
                f"{pkg}/scripts/start_mednafen.sh": MEDNAFEN_SH,
            }
        )
        with self.assertRaises(LauncherPatternMissing):
            rl.mednafen(tree)


class SearchedNames(unittest.TestCase):
    def tree(self, script: str) -> RepoTree:
        return RepoTree.from_files({f"{SA}/yabasanshiro-sa/scripts/start_yabasanshiro.sh": script})

    def test_yabasanshiro_tries_its_names_in_order(self):
        (record,) = [r.entry() for r in rl.yabasanshiro(self.tree(YABASANSHIRO_SH))]
        self.assertEqual(record["kind"], "names_searched")
        self.assertEqual(
            record["names"],
            [
                "saturn_bios.bin",
                "sega_101.bin",
                "mpr-17933.bin",
                "mpr-18811-mx.ic1",
                "mpr-19367-mx.ic1",
                "stvbios.zip",
            ],
        )
        self.assertEqual(record["passes_to"], "yabasanshiro -b <first path found>")
        self.assertEqual(record["depends_on_option"], "use_hlebios = 1 (game, then platform)")
        self.assertIs(record["case_insensitive"], False)
        self.assertEqual(
            record["source_ref"], f"{SA}/yabasanshiro-sa/scripts/start_yabasanshiro.sh:2-13"
        )

    def test_a_search_no_longer_written_as_a_loop_raises(self):
        script = YABASANSHIRO_SH.replace("for BIOS in", "BIOS_LIST=").replace("  do\n", "")
        with self.assertRaises(LauncherPatternMissing):
            rl.yabasanshiro(self.tree(script))


class Links(unittest.TestCase):
    def all_scripts(self) -> dict[str, str]:
        return {
            "drastic": DRASTIC_SH,
            "dolphin": DOLPHIN_SH,
            "flycast": FLYCAST_SH,
            "cemu": CEMU_SH,
            "rpcs3": RPCS3_SH,
        }

    def tree(self) -> RepoTree:
        scripts = self.all_scripts()
        return RepoTree.from_files({p: scripts[e] for e, p in rl.LINK_SCRIPTS})

    def emulator(self, name: str) -> list[dict]:
        return by([r.entry() for r in rl.links(self.tree())], name)

    def test_a_loop_names_each_file_and_links_into_a_directory(self):
        (record,) = self.emulator("drastic")
        self.assertEqual(record["names"], ["nds_bios_arm9.bin", "nds_bios_arm7.bin"])
        self.assertEqual(record["search_dir"], "/storage/roms/bios")
        self.assertEqual(
            record["passes_to"],
            "symlink /storage/.config/drastic/system/<name> -> /storage/roms/bios/<name>",
        )
        # The link waits for an exact-case -e test.
        self.assertIs(record["case_insensitive"], False)
        self.assertEqual(record["source_ref"], f"{rl.LINK_SCRIPTS[0][1]}:1, 4-5")

    def test_a_nested_loop_is_a_placeholder_and_its_values(self):
        regions, cards = self.emulator("dolphin")
        self.assertEqual(regions["names"], ["EUR", "JAP", "USA"])
        self.assertEqual(regions["search_dir"], "/storage/roms/bios/GC")
        self.assertEqual(cards["names"], ["MemoryCard{SLOT}.{REGION}.raw"])
        self.assertEqual(cards["expands"], {"REGION": ["EUR", "JAP", "USA"], "SLOT": ["A", "B"]})

    def test_a_link_outside_the_bios_directory_is_not_a_record(self):
        for record in self.emulator("dolphin"):
            self.assertNotIn("StateSaves", record["passes_to"])

    def test_one_by_one_links_of_one_layout_are_one_record(self):
        (record,) = self.emulator("cemu")
        self.assertEqual(record["names"], ["online", "keys"])
        self.assertEqual(
            record["passes_to"],
            "symlink /storage/.config/Cemu/share/<name> -> /storage/roms/bios/cemu/<name>",
        )

    def test_an_array_loop_takes_the_array(self):
        (record,) = self.emulator("rpcs3")
        self.assertEqual(record["names"], ["dev_flash", "dev_hdd0", "dev_hdd1", "custom_configs"])
        self.assertEqual(record["search_dir"], "/storage/roms/bios/rpcs3")
        self.assertEqual(record["source_ref"], f"{dict(rl.LINK_SCRIPTS)['rpcs3']}:1-6")

    def test_a_directory_link_has_no_names(self):
        (record,) = self.emulator("flycast")
        self.assertEqual(record["names"], [])
        self.assertEqual(
            record["passes_to"], "symlink /storage/roms/dreamcast/data -> /storage/roms/bios/dc"
        )

    def test_a_script_without_a_bios_link_raises(self):
        scripts = self.all_scripts()
        scripts["flycast"] = 'ln -sf "/storage/.config/flycast" "/storage/.local/share/flycast"\n'
        tree = RepoTree.from_files({p: scripts[e] for e, p in rl.LINK_SCRIPTS})
        with self.assertRaises(LauncherPatternMissing):
            rl.links(tree)


START_PICO8 = text(
    """
    #!/bin/bash
    . /etc/profile

    GAME_DIR="/storage/roms/pico-8/"

    case ${HW_ARCH} in
      aarch64)
        STATIC_BIN="pico8_64"
      ;;
      *)
        STATIC_BIN="pico8_dyn"
      ;;
    esac

    if [ -d "${GAME_DIR}/${HW_ARCH}" ]
    then
      LAUNCH_DIR="${GAME_DIR}/${HW_ARCH}"
    else
      LAUNCH_DIR="${GAME_DIR}"
    fi

    ${LAUNCH_DIR}/${STATIC_BIN} -home -root_path ${GAME_DIR} -joystick 0 ${OPTIONS} "${CART}"
"""
)


class ProgramsRunOutsideTheBiosFolder(unittest.TestCase):
    PATH = f"{SA}/pico-8/scripts/start_pico8.sh"

    def test_pico8_runs_its_binary_from_roms(self):
        (record,) = [r.entry() for r in rl.pico8(RepoTree.from_files({self.PATH: START_PICO8}))]
        self.assertEqual(
            (record["emulator"], record["kind"], record["names"], record["search_dir"],
             record["passes_to"]),
            ("pico-8", "fixed_name", ["pico8_64", "pico8_dyn"], "/storage/roms/pico-8", "exec"),
        )
        self.assertIn("HW_ARCH aarch64 runs pico8_64", record["depends_on_option"])
        self.assertEqual(record["source_ref"], f"{self.PATH}:4-11, 15-22")

    def test_a_script_without_its_binary_choice_raises(self):
        broken = START_PICO8.replace('STATIC_BIN="pico8_dyn"', "STATIC_BIN=$OTHER")
        with self.assertRaises(LauncherPatternMissing):
            rl.pico8(RepoTree.from_files({self.PATH: broken}))


class Revision(unittest.TestCase):
    def test_the_revision_is_the_one_the_bios_list_is_read_at(self):
        url = (
            "https://raw.githubusercontent.com/ROCKNIX/distribution/20261001/"
            "projects/ROCKNIX/packages/rocknix/sources/scripts/rocknix-systems"
        )
        self.assertEqual(launcher_revision(url), "20261001")

    def test_a_url_without_a_revision_raises(self):
        with self.assertRaises(ValueError):
            launcher_revision("https://rocknix.org/")


class PlatformRecords(unittest.TestCase):
    """The launchers platforms/rocknix.yml carries, as the scraper wrote them."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = yaml.safe_load((REPO_ROOT / "platforms" / "rocknix.yml").read_text())

    def test_every_emulator_is_one_rocknix_packages(self):
        # RetroArch itself runs the libretro cores the list names.
        cores = set(self.config["cores"])
        self.assertEqual(sorted({r["emulator"] for r in self.config["launchers"]} - cores),
                         ["retroarch"])

    def test_every_reference_is_in_the_rocknix_project(self):
        for record in self.config["launchers"]:
            for part in record["source_ref"].split(", "):
                if ":" in part:
                    self.assertTrue(part.startswith(f"{rl.ROCKNIX}/"), record)

    def test_a_device_is_named_only_beside_another_device_record(self):
        with_device: dict[tuple[str, str], int] = {}
        for record in self.config["launchers"]:
            if "device" in record:
                key = (record["emulator"], record["kind"])
                with_device[key] = with_device.get(key, 0) + 1
        self.assertTrue(with_device)
        self.assertEqual({k: n for k, n in with_device.items() if n < 2}, {})


if __name__ == "__main__":
    unittest.main()
