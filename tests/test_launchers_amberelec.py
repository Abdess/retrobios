"""AmberELEC's launcher layer, read from runemu.py and its emulator scripts.

The fixtures are cut-down copies of what each extractor reads at AmberELEC
a21975bf (prerelease-20261019_1835). Records must name the files in the
order the code writes them, cite the fixture's own lines, and a construct
that is gone must stop the scrape.
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

from scraper import amberelec_launchers as al  # noqa: E402
from scraper.configgen_launchers import LauncherShapeError  # noqa: E402


def text(block: str) -> str:
    return textwrap.dedent(block).lstrip("\n")


RUNEMU = text(
    """
    standalone_emulators = {
        'AMIBERRY': StandaloneEmulator('amiberry', ['/usr/bin/amiberry.sh', '<path>']),
        'HATARISA': StandaloneEmulator('hatari', ['/usr/bin/hatari.sh', '<path>']),
        'pico8': StandaloneEmulator('pico8_64', ['/usr/bin/pico-8.sh', '<path>']),
        'piemu': StandaloneEmulator('piemu', ['/usr/bin/bash', '-l', '/usr/bin/piemu.sh', '<path>']),
        'yabasanshiroSA': StandaloneEmulator('yabasanshiro', ['/usr/bin/yabasanshiro.sh', '<path>']),
    }

    class EmuRunner():
        def get_retroarch_command(self, shader_arg):
            if self.emulator == 'mame':
                if rom_path:
                    cmd = f'{mame_system} -{mame_slot} "{rom_path}" -rp /roms/bios/mame;/roms/bios -cfg_directory /x'
                else:
                    cmd = f'{mame_system} -rp /roms/bios/mame;/roms/bios -cfg_directory /x'
    """
)

YABASANSHIRO = text(
    """
    #!/bin/bash
    get_setting "use_hlebios"
    HLEBIOS='0'
    BIOS=""
    if [ "${HLEBIOS}" != 1 ]; then
        if [ -e "/storage/roms/bios/saturn_bios.bin" ]; then
            BIOS="-b /storage/roms/bios/saturn_bios.bin"
        else
            text_viewer -e -w -t "Notice! Yabasanshiro BIOS Missing!" -m "not found"
        fi
    fi
    { yabasanshiro -r 2 -i "${1}" ${BIOS}; } > /tmp/logs/exec.log 2>&1
    """
)

PICO8 = text(
    """
    #!/bin/bash
    mkdir -p "/storage/roms/pico-8"
    if [ ! -f "/storage/roms/pico-8/pico8_64" ] || [ ! -f "/storage/roms/pico-8/pico8.dat" ]; then
      text_viewer -e -w -t "Missing Pico-8 binaries!" -m "Extract your purchased pico8_64."
    else
      /storage/roms/pico-8/pico8_64 -home -root_path /storage/roms/pico-8 ${OPTIONS} "${CART}"
    fi
    """
)

PIEMU = text(
    """
    #!/bin/bash
    ROMS_DIR="/storage/roms"
    BIOS_DIR="$ROMS_DIR/bios"
    if [[ "$EXTENSION" == "pfs" ]]; then
    	/usr/bin/mkpfi "$BIOS_DIR/all.bin"
    fi
    """
)

HATARI_SH = text(
    """
    #!/bin/bash
    HATARI_CONFIG_DIR=/storage/.config/hatari/conf
    cp $HATARI_CONFIG_DIR/Atari-ST-default.cfg "$HATARI_TMP_CONFIG"
    nice -n -19 hatari --configfile "$HATARI_TMP_CONFIG" --disk-a "$1" >> $HATARI_LOG 2>&1
    """
)

HATARI_CFG = text(
    """
    [ROM]
    szTosImageFileName = /storage/roms/bios/tos.img
    bPatchTos = TRUE
    """
)

ATARI800_CFG = text(
    """
    Atari 800 Emulator, Version 3.1.0
    ROM_OS_A_NTSC=
    ROM_OS_A_PAL=/storage/roms/bios/ATARIOSA.ROM
    ROM_5200=/storage/roms/bios/5200.rom
    """
)

ATARI800_PATCH = text(
    """
    +	LDFLAGS += -static-libgcc
    +	CFLAGS += -DDEFAULT_CFG_NAME="\\"/storage/.config/distribution/configs/atari800.cfg\\""
    """
)

AMIBERRY_MK = text(
    """
    makeinstall_target() {
      mkdir -p ${INSTALL}/usr/config/amiberry
      ln -s /storage/roms/bios ${INSTALL}/usr/config/amiberry/kickstarts
    }
    """
)

AMIBERRY_SH = text(
    """
    #!/bin/bash
    AMIBERRY_CONFIG_DIR=$AMIBERRY_DIR/conf
    AMIBERRY_SET_CONF() {
      if [ `echo $1 | egrep 'AGA|CD32' | wc -l` -eq 1 ]; then
        cp $AMIBERRY_CONFIG_DIR/AmigaA1200-default.uae "$AMIBERRY_TMP_CONFIG"
      else
        cp $AMIBERRY_CONFIG_DIR/AmigaA500-default.uae "$AMIBERRY_TMP_CONFIG"
      fi
    }
    """
)


def uae(rom: str) -> str:
    return f"amiberry.rom_path=/storage/.config/amiberry/kickstarts/\nkickstart_rom_file=$(FILE_PATH)/{rom}\n"


SCUMMVM_SH = text(
    """
    #!/bin/bash
    case $1 in
      "libretro")
        sed -i '2,2s/^/themepath=\\/roms\\/bios\\/scummvm\\/theme\\n/' ${BIOSPATH}/scummvm.ini
        sed -i '2,2s/^/extrapath=\\/roms\\/bios\\/scummvm\\/extra\\n/' ${BIOSPATH}/scummvm.ini
        sed -i '2,2s/^/browser_lastpath=\\/roms\\/bios\\/scummvm\\/extra\\n/' ${BIOSPATH}/scummvm.ini
      ;;
    esac
    """
)

FREEJ2ME = text(
    """
    #!/bin/bash
    if [ ! -f "/storage/roms/bios/{jar}" ]; then
        cp /usr/config/distribution/freej2me/{jar} /storage/roms/bios
    fi
    """
)

EASYRPG = text(
    """
    #!/bin/bash
    install_bios() {
      BIOS="$1"
      curl -Lo "${BIOS}" "${PKG_URL}/${BIOS}"
    }
    INSTALLPATH="/storage/roms/bios"
    PKG_URL="https://dl.degica.com/rpgmakerweb/run-time-packages"
    install_bios rpg2000_rtp_installer.exe rtp/2000
    """
)


def tree(**overrides: str) -> dict[str, str]:
    files = {
        al.RUNEMU: RUNEMU,
        al.RETROARCH_CFG: 'savefile_directory = "~/saves"\nsystem_directory = "~/roms/bios"\n',
        al.RETRORUN: '/usr/bin/retrorun -c "${RRCONF}" -s /storage/roms/"$3" -d /roms/bios "$EMU" "$2"\n',
        al.SCRIPTS["yabasanshiroSA"]: YABASANSHIRO,
        al.SCRIPTS["pico8"]: PICO8,
        al.SCRIPTS["piemu"]: PIEMU,
        al.SCRIPTS["HATARISA"]: HATARI_SH,
        al.HATARI_CONFIG: HATARI_CFG,
        al.ATARI800_CONFIG: ATARI800_CFG,
        al.ATARI800_PATCH: ATARI800_PATCH,
        al.AMIBERRY_PACKAGE: AMIBERRY_MK,
        al.SCRIPTS["AMIBERRY"]: AMIBERRY_SH,
        f"{al.AMIBERRY_CONFIGS}/AmigaA1200-default.uae": uae("kick40068.A1200.rom"),
        f"{al.AMIBERRY_CONFIGS}/AmigaA500-default.uae": uae("kick34005.A500.rom"),
        al.SCRIPTS["SCUMMVMSA"]: SCUMMVM_SH,
        al.EASYRPG: EASYRPG,
        **{path: FREEJ2ME.replace("{jar}", f"{core}-lr.jar") for core, path in al.FREEJ2ME},
    }
    files.update(overrides)
    return files


def read(**overrides: str):
    return tree(**overrides).__getitem__


class Frontends(unittest.TestCase):
    def test_retroarch_system_directory(self):
        (record,) = al.retroarch(read())
        self.assertEqual(record.search_dir, "~/roms/bios")
        self.assertEqual(record.source_ref, f"{al.RETROARCH_CFG}:2")

    def test_retrorun_directory(self):
        (record,) = al.retrorun(read())
        self.assertEqual((record.search_dir, record.passes_to), ("/roms/bios", "command line -d"))

    def test_mame_search_path_of_both_commands(self):
        (record,) = al.mame(al.Runemu(read()))
        self.assertEqual(record.search_dir, "/roms/bios/mame;/roms/bios")
        self.assertEqual(record.depends_on_option, "self.emulator == 'mame'")
        self.assertEqual(record.source_ref, f"{al.RUNEMU}:11, 13, 15")

    def test_a_retroarch_config_without_the_key_raises(self):
        with self.assertRaises(LauncherShapeError):
            al.retroarch(read(**{al.RETROARCH_CFG: "x = 1\n"}))


class Standalone(unittest.TestCase):
    def test_yabasanshiro_flag_after_the_presence_test(self):
        (record,) = al.yabasanshiro(read(), al.Runemu(read()))
        self.assertEqual(record.names, ["saturn_bios.bin"])
        self.assertEqual(record.passes_to, "command line -b")
        self.assertIs(record.fails_when_missing, False)
        self.assertEqual(record.depends_on_option, "use_hlebios")
        self.assertEqual(
            record.source_ref,
            f"{al.RUNEMU}:6, {al.SCRIPTS['yabasanshiroSA']}:2, 5-7, 12",
        )

    def test_pico8_binaries_outside_bios(self):
        (record,) = al.pico8(read(), al.Runemu(read()))
        self.assertEqual(record.names, ["pico8_64", "pico8.dat"])
        self.assertEqual(record.search_dir, "/storage/roms/pico-8")
        self.assertEqual(record.fails_when_missing, "Missing Pico-8 binaries!")
        self.assertEqual(record.source_ref, f"{al.RUNEMU}:4, {al.SCRIPTS['pico8']}:3-6")

    def test_piemu_flash_image_source(self):
        (record,) = al.piemu(read(), al.Runemu(read()))
        self.assertEqual(record.names, ["all.bin"])
        self.assertEqual(record.source_ref, f"{al.RUNEMU}:5, {al.SCRIPTS['piemu']}:2-5")

    def test_hatari_default_config(self):
        (record,) = al.hatari(read(), al.Runemu(read()))
        self.assertEqual(record.names, ["tos.img"])
        self.assertEqual(record.passes_to, "Atari-ST-default.cfg [ROM] szTosImageFileName")
        self.assertEqual(
            record.source_ref,
            f"{al.RUNEMU}:3, {al.SCRIPTS['HATARISA']}:3-4, {al.HATARI_CONFIG}:2",
        )

    def test_amiberry_link_and_one_kickstart_per_config(self):
        link, a1200, a500 = al.amiberry(read(), al.Runemu(read()))
        self.assertEqual(link.kind, "links")
        self.assertEqual(link.passes_to, "/usr/config/amiberry/kickstarts is a symlink to it")
        self.assertEqual((a1200.slot, a1200.names), ("A1200", ["kick40068.A1200.rom"]))
        self.assertEqual((a500.slot, a500.names), ("A500", ["kick34005.A500.rom"]))
        self.assertEqual(a500.depends_on_option, f"not ({a1200.depends_on_option})")

    def test_a_table_running_another_script_raises(self):
        broken = RUNEMU.replace("/usr/bin/yabasanshiro.sh", "/usr/bin/yaba.sh")
        with self.assertRaises(LauncherShapeError):
            al.yabasanshiro(read(), al.Runemu(read(**{al.RUNEMU: broken})))

    def test_a_bios_test_written_another_way_raises(self):
        broken = YABASANSHIRO.replace('if [ -e "/storage', 'if test -e "/storage')
        with self.assertRaises(LauncherShapeError):
            al.yabasanshiro(read(**{al.SCRIPTS["yabasanshiroSA"]: broken}), al.Runemu(read()))


class Cores(unittest.TestCase):
    def test_atari800_built_to_read_the_shipped_config(self):
        (record,) = al.atari800(read())
        self.assertEqual(record.names, ["ATARIOSA.ROM", "5200.rom"])
        self.assertEqual(record.source_ref, f"{al.ATARI800_PATCH}:2, {al.ATARI800_CONFIG}:3-4")

    def test_atari800_built_for_another_config_raises(self):
        broken = ATARI800_PATCH.replace("atari800.cfg", "other.cfg")
        with self.assertRaises(LauncherShapeError):
            al.atari800(read(**{al.ATARI800_PATCH: broken}))

    def test_scummvm_paths_written_under_bios(self):
        theme, extra = al.scummvm(read())
        self.assertEqual(theme.search_dir, "/roms/bios/scummvm/theme")
        self.assertEqual(extra.passes_to, "scummvm.ini extrapath")

    def test_freej2me_copies_the_shipped_jar(self):
        plain, plus = al.freej2me(read())
        self.assertEqual((plain.kind, plain.names), ("copies", ["freej2me-lr.jar"]))
        self.assertEqual(plus.names, ["freej2me-plus-lr.jar"])
        self.assertEqual(plain.search_dir, "/usr/config/distribution/freej2me")

    def test_easyrpg_download_per_runtime(self):
        (record,) = al.easyrpg(read())
        self.assertEqual(
            record.search_dir,
            "https://dl.degica.com/rpgmakerweb/run-time-packages/rpg2000_rtp_installer.exe",
        )
        self.assertEqual(record.passes_to, "/storage/roms/bios/rtp/2000")

    def test_every_extractor_runs_on_the_fixture(self):
        records = al.extract_launchers(read())
        # One easyrpg runtime in the fixture, two at the pinned commit.
        self.assertEqual(len(records), 16)


class PlatformFile(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = yaml.safe_load((REPO_ROOT / "platforms" / "amberelec.yml").read_text())

    def test_the_layer_is_written(self):
        self.assertTrue(self.config["launchers"])

    def test_every_reference_is_in_the_repository(self):
        for record in self.config["launchers"]:
            self.assertTrue(record["source_ref"].startswith("packages/"), record)

    def test_every_emulator_is_one_amberelec_names(self):
        cores = {*self.config["cores"], *self.config.get("standalone_cores", [])}
        named = {n for record in self.config["launchers"] for n in record["emulator"].split(", ")}
        # RetroArch and retrorun themselves, the two runners of every core.
        self.assertEqual(sorted(named - cores), ["retroarch", "retrorun"])


if __name__ == "__main__":
    unittest.main()
