"""EmuELEC's launcher layer read from its packages.

Each fixture is a cut-down copy of the lines an extractor reads at EmuELEC
v4.8 (02b45fe53b85c45c75dbad8e44a648092dec2e72). The records must name the
core emuelecRunEmu.sh dispatches, carry the names in the order the code
tries them, point at the fixture's own lines, and a construct that is gone
must stop the scrape.
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

from scraper import emuelec_launchers as el  # noqa: E402
from scraper.emuelec_scraper import launcher_revision  # noqa: E402
from scraper.shell_launchers import LauncherPatternMissing, RepoTree  # noqa: E402

EMU = el.EMULATORS


def text(block: str) -> str:
    return textwrap.dedent(block).lstrip("\n")


RUN_EMU = text(
    """
    if [[ "${EMULATOR}" = "libretro" ]]; then
        EMU="${CORE}_libretro"
    fi
    if [[ "${EMULATOR}" = "retrorun" ]]; then
        EMU="${CORE}_libretro"
    fi
    MIDI_OUTPUT=$(get_ee_setting "ra_midi_output" "${PLATFORM}" "${BASEROMNAME}")
    if [[ ! -z "${MIDI_OUTPUT}" ]]; then
    		emuelec-utils set_midi_source "${MIDI_OUTPUT}" "${EMULATOR}"
    fi
    if [ ${EMU} == "freej2me_libretro" ]; then
    freej2me.sh

    JAVA_HOME='/storage/roms/bios/jdk'
    export JAVA_HOME
    fi
    case ${PLATFORM} in
            "atarist")
                    if [ "${EMU}" = "HATARISA" ]; then
                RUNTHIS='${TBASH} hatari.start "${ROMNAME}"'
                    fi
                    ;;
            "dreamcast"|"naomi")
                    if [ "${EMU}" = "flycastsa" ]; then
                RUNTHIS='${TBASH} flycast.sh "${ROMNAME}"'
                    elif [ "${EMU}" = "flycast_dojo" ]; then
                RUNTHIS='flycastdojo.sh "${ROMNAME}"'
                    fi
                    ;;
            "psx")
                    if [ "${EMU}" = "duckstation" ]; then
                RUNTHIS='${TBASH} duckstation.sh "${ROMNAME}"'
            fi
                    ;;
            "mame")
                    if [ "${EMU}" = "AdvanceMame" ]; then
                RUNTHIS='${TBASH} advmame.sh "${PLATFORM}" "${ROMNAME}"'
                    fi
                    ;;
            "n64")
                    if [ "${EMU}" = "rice" ]; then
                RUNTHIS='${TBASH} m64p.sh "${ROMNAME}"'
                    elif [ "${EMU}" = "glide64mk2" ]; then
                RUNTHIS='${TBASH} m64p.sh "${ROMNAME}" m64p_gl64mk2'
            fi
                    ;;
            "scummvm")
                    if [ "${EMU}" = "SCUMMVMSA" ]; then
                RUNTHIS='${TBASH} scummvm.start sa "${ROMNAME}"'
                    fi
                    ;;
            "wii"|"gamecube")
                    if [ "${EMU}" = "dolphin" ]; then
                RUNTHIS='${TBASH} dolphin.sh "${ROMNAME}"'
                    fi
                    ;;
            "pico8")
                    RUNTHIS='${TBASH} pico8.sh "${ROMNAME}"'
                            ;;
            "intellivision")
            if [ "${EMU}" = "jzintv" ]; then
                RUNTHIS='jzintv.sh "${ROMNAME}"'
            fi
            ;;
            "saturn")
            if [ "${EMU}" = "yabasanshiroSA" ]; then
                RUNTHIS='yabasanshiro.sh "${ROMNAME}"'
            elif [ "${EMU}" = "yabasanshiroSA1_5" ]; then
                	RUNTHIS='yabasanshiro1_5.sh "${ROMNAME}"'
            fi
            ;;
            esac
    case ${PLATFORM} in
    "arcade"|"mame")
    	if [ "$EMU" = "mame_libretro" ]; then
    		mame.sh
        fi
        ;;
    esac
    RUNTHIS='${RABIN} ${VERBOSE} ${RA_ARGS} -L /tmp/cores/${EMU}.so --config ${RACONF} "${ROMNAME}"'
        RUNTHIS="retrorun"
        RUNTHIS+=' ${CMD_ROTATE} --triggers -g -d /storage/roms/bios /tmp/cores/${EMU}.so "${ROMNAME}"'
"""
)

UTILS = text(
    """
    function set_midi_source()
    {
      case ${midi_source} in
        fluidsynth)
          fluidsynth -is /storage/roms/bios/sc/SC-55.sf2 &
          ;;
        timidity)
          timidity -iA --module 1 &
          ;;
        mt32)
          mt32d -o 2 -i 24 -f /roms/bios &
    			;;
    esac
    }
"""
)

RETROARCH_MK = text(
    """
      sed -i -e "s/# savestate_directory =/savestate_directory =\\/storage\\/roms\\/savestates/" ${INSTALL}/etc/retroarch.cfg
      sed -i -e "s/# system_directory =/system_directory =\\/storage\\/roms\\/bios/" ${INSTALL}/etc/retroarch.cfg
"""
)

FREEJ2ME_SH = text(
    """
    install_java

    if [[ -f "/storage/roms/bios/jdk/eeversion" ]]; then
        cp -rf /usr/lib/libretro/freej2me-lr.jar ${HOME}/roms/bios
    else
        exit 1
    fi
"""
)

PICO8_SH = text(
    """
    if [[ -e "/storage/roms/bios/pico-8" ]]; then
        mkdir -p /emuelec/bin/pico-8
        cp -rf /storage/roms/bios/pico-8/* /emuelec/bin/pico-8
        rm -rf /storage/roms/bios/pico-8
        chmod +x /emuelec/bin/pico-8/pico8_dyn
    fi
    if [[ "${CART}" == *"/splore"* ]]; then
        /emuelec/bin/pico-8/pico8_dyn -splore -home /emuelec/configs/pico-8
    else
        /emuelec/bin/pico-8/pico8_dyn -run "${CART}" -home /emuelec/configs/pico-8
    fi
"""
)

FLYCAST_SH = text(
    """
    if [ ! -L "/storage/.local/share/flycast" ]; then
        mkdir -p "/storage/roms/bios/dc"
        rm -rf "/storage/.local/share/flycast"
        ln -sf "/storage/roms/bios/dc" "/storage/.local/share/flycast"
    fi
"""
)

FLYCASTDOJO_SH = text(
    """
    LOCAL_DATA="/storage/roms/bios/dc_dojo"
    LOCAL_HOME="/storage/.local/share/flycast-dojo"
    if [ ! -L "${LOCAL_HOME}" ]; then
        rm -rf "${LOCAL_HOME}"
        ln -sf "${LOCAL_DATA}" "${LOCAL_HOME}"
    fi
"""
)

AMIBERRY_MK = text(
    """
      cp -a ${PKG_DIR}/config/*           ${INSTALL}/usr/config/amiberry/
      ln -s /storage/roms/bios 			  ${INSTALL}/usr/config/amiberry/kickstarts
"""
)

TIMIDITY_MK = text(
    """
      ln -sf /storage/roms/bios/timidity/freepats ${INSTALL}/usr/config/timidity/freepats
      ln -sf /storage/.config/timidity/freepats.cfg ${INSTALL}/etc/timidity/freepats.cfg
"""
)

DUCKSTATION_INI = text(
    """
    [BIOS]
    SearchDirectory = /storage/roms/bios
    PathNTSCU =
    PathNTSCJ =
    PathPAL =
"""
)

DUCKSTATION_MK = text(
    """
      cp -rf ${PKG_DIR}/config/* ${INSTALL}/usr/config/emuelec/configs/duckstation
"""
)

DUCKSTATION_SH = text(
    """
    CONFIG_DIR="/emuelec/configs/duckstation"
        duckstation-nogui -fullscreen -settings "${CONFIG_DIR}/settings.ini" -- "${1}"
    if [ ! -d "${CONFIG_DIR}" ]; then
        cp -rf /usr/config/emuelec/configs/duckstation/* "${CONFIG_DIR}"
    fi
"""
)


def yabasanshiro_sh(program: str) -> str:
    return text(
        f"""
        BIOS=""
        HLEBIOS=$(get_ee_setting hlebios saturn "${{ROMNAME}}")
        if [ "${{HLEBIOS}}" != 1 ]; then
            if [ -e "/storage/roms/bios/saturn_bios.bin" ]; then
                BIOS="-b /storage/roms/bios/saturn_bios.bin"
            else
                BIOS=""
            fi
        fi
        {{ {program} -r 2 -i "${{1}}" ${{BIOS}}; }} > /emuelec/logs/emuelec.log 2>&1
"""
    )


JZINTV_SH = text(
    """
    exec jzintv -f1 -z "$RES" -p /storage/roms/bios/ "$ROM" $KBD_OPT
"""
)

M64P_SH = text(
    """
    BIOSDIR="/storage/roms/bios/Mupen64plus"
    IPLROM="${BIOSDIR}/N64DD IPLROM (J).n64"
    [ ! -f "${IPLROM}" ] && IPLROM="${BIOSDIR}/IPL.n64"
    if [ -f "${GAMEDIR}/${GAMENAME}.ndd" ] && [ -f "${IPLROM}" ]; then
        RENMODE="1"
    else
        IPLROM=""
    fi
        mupen64plus --fullscreen --dd-ipl-rom "${IPLROM}" --dd-disk "${DDDISK}" "${FILE}" ;;
"""
)

HATARI_START = text(
    """
    HATARI_TMP_CONFIG="$HATARI_TMP_DIR"/.hatari-temp.cfg
    cp $HATARI_CONFIG_DIR/Atari-ST-default.cfg "$HATARI_TMP_CONFIG"
      hatari --configfile "$HATARI_TMP_CONFIG" --disk-a "$1"
"""
)

HATARI_CFG = text(
    """
    [HardDisk]
    szHardDiskDirectory = /storage/.hatari

    [ROM]
    szTosImageFileName = /storage/roms/bios/tos.img
    szCartridgeImageFileName =
"""
)

HATARI_MK = text(
    """
      cp -R ${PKG_DIR}/config/* ${INSTALL}/usr/config/hatari
"""
)

ADVMAME_MK = text(
    """
    if [ "${DEVICE}" == "OdroidGoAdvance" ]; then
       cp -r ${PKG_DIR}/config/advmame.rc_oga ${INSTALL}/usr/config/emuelec/configs/advmame/advmame.rc
    else
       cp -r ${PKG_DIR}/config/advmame.rc ${INSTALL}/usr/config/emuelec/configs/advmame/advmame.rc
    fi
"""
)

ADVMAME_RC = text(
    """
    dir_rom /storage/roms/mame
    dir_sample /storage/roms/bios/advmame/samples
"""
)

ADVMAME_SH = text(
    """
    if [[ "${1}" = "arcade" ]]; then
    sed -i "s|/roms/mame|/roms/arcade|g" ${CONFIG_DIR}/advmame.rc
     else
    sed -i "s|/roms/arcade|/roms/mame|g" ${CONFIG_DIR}/advmame.rc
    fi
    SDL_AUDIODRIVER=alsa advmame ${ARG} -quiet
    if [ ! -d "${CONFIG_DIR}" ]; then
     cp -rf /usr/config/emuelec/configs/advmame/* "${CONFIG_DIR}/"
    fi
"""
)

MAME_SH = text(
    """
    if [ ! -f "/storage/roms/bios/mame/hash/fmtowns_cd.xml" ]; then
        mkdir -p /storage/roms/bios/mame/hash
        cp -rf "/usr/config/emuelec/configs/mame/hash/"fm* "/storage/roms/bios/mame/hash"
    fi
    if [ ! -f "/storage/roms/bios/mame/ini/mame.ini" ]; then
        mkdir -p /storage/roms/bios/mame/ini
        cp -rf "/usr/config/emuelec/configs/mame/ini/"mame* "/storage/roms/bios/mame/ini"
    fi
    if [ ! -f "/storage/.config/retroarch/config/MAME/MAME.opt" ]; then
        cp -rf "/usr/config/emuelec/configs/mame/MAME/"MAME* "/storage/.config/retroarch/config/MAME"
    fi
"""
)

MAME_INI = text(
    """
    rompath                   /storage/roms/bios/mame/bios;/storage/roms/mame;/storage/roms/arcade
    samplepath                /storage/roms/bios/mame/samples
    cfg_directory             /storage/roms/bios/mame/mame/cfg
"""
)

MAME_OPT = text(
    """
    mame_boot_to_bios = "disabled"
    mame_read_config = "enabled"
"""
)

SCUMMVM_START = text(
    """
    CONFIG_DIR="/storage/.config/scummvm"
    if [ -d "/storage/.config/scummvm/extra" ]; then
    EXTRA="--extrapath=/storage/.config/scummvm/extra"
    fi
    case $1 in
    "sa")
    scummvm --fullscreen --joystick=0 $EXTRA "${GAME}"
    ;;
    "libretro")
    retroarch -L /tmp/cores/scummvm_libretro.so --config ${RATMPCONF} "${GAME}"
    ;;
    "add")
    scummvm --add --path="/storage/roms/scummvm" --recursive
    cp ${CONFIG_DIR}/scummvm.ini /storage/roms/bios/scummvm.ini
    ;;
    esac
"""
)

DOLPHIN_SH = text(
    """
    XDG_CONFIG_HOME=/emuelec/configs XDG_DATA_HOME=/storage/roms/dolphin /usr/bin/dolphin-emu-nogui -p fbdev "${1}"
"""
)

FILES = {
    el.RUN_EMU: RUN_EMU,
    el.UTILS: UTILS,
    el.RETROARCH_MK: RETROARCH_MK,
    f"{el.LIBRETRO}/freej2me/scripts/freej2me.sh": FREEJ2ME_SH,
    f"{el.BIN}/pico8.sh": PICO8_SH,
    f"{EMU}/flycastsa/scripts/flycast.sh": FLYCAST_SH,
    f"{EMU}/flycast-dojo/scripts/flycastdojo.sh": FLYCASTDOJO_SH,
    f"{EMU}/amiberry/package.mk": AMIBERRY_MK,
    f"{EMU}/amiberry-lite/package.mk": AMIBERRY_MK.replace("amiberry/", "amiberry-lite/"),
    f"{el.SX05RE}/tools/sound/timidity/package.mk": TIMIDITY_MK,
    f"{EMU}/duckstation/config/settings.ini": DUCKSTATION_INI,
    f"{EMU}/duckstation/package.mk": DUCKSTATION_MK,
    f"{EMU}/duckstation/scripts/duckstation.sh": DUCKSTATION_SH,
    el.YABASANSHIRO_SCRIPTS[0]: yabasanshiro_sh("yabasanshiro"),
    el.YABASANSHIRO_SCRIPTS[1]: yabasanshiro_sh("yabasanshiro1_5"),
    f"{EMU}/jzintv/scripts/jzintv.sh": JZINTV_SH,
    f"{EMU}/mupen64plussa/mupen64plussa-core/m64p.sh": M64P_SH,
    f"{EMU}/hatarisa/scripts/hatari.start": HATARI_START,
    f"{EMU}/hatarisa/config/conf/Atari-ST-default.cfg": HATARI_CFG,
    f"{EMU}/hatarisa/package.mk": HATARI_MK,
    f"{EMU}/advancemame/package.mk": ADVMAME_MK,
    f"{EMU}/advancemame/config/advmame.rc": ADVMAME_RC,
    f"{EMU}/advancemame/config/advmame.rc_oga": ADVMAME_RC,
    f"{EMU}/advancemame/bin/advmame.sh": ADVMAME_SH,
    f"{el.LIBRETRO}/mame/scripts/mame.sh": MAME_SH,
    f"{el.LIBRETRO}/mame/config/ini/mame.ini": MAME_INI,
    f"{el.LIBRETRO}/mame/config/MAME/MAME.opt": MAME_OPT,
    f"{EMU}/scummvmsa/bin/scummvm.start": SCUMMVM_START,
    f"{EMU}/dolphinSA/scripts/dolphin.sh": DOLPHIN_SH,
}


def tree(**changes: str | None) -> RepoTree:
    files = dict(FILES)
    for path, content in changes.items():
        if content is None:
            files.pop(path, None)
        else:
            files[path] = content
    return RepoTree.from_files(files)


def records(extractor, **changes: str | None) -> list[dict]:
    built = tree(**changes)
    return [r.entry() for r in extractor(built, el.Runs(built))]


def ref(path: str, lines: str) -> str:
    return f"{path}:{lines}"


class Dispatch(unittest.TestCase):
    def test_each_script_is_named_after_the_core_that_starts_it(self):
        runs = el.Runs(tree())
        self.assertEqual(runs.emulator("flycast.sh"), "flycastsa")
        self.assertEqual(runs.emulator("flycastdojo.sh"), "flycast_dojo")
        self.assertEqual(runs.emulator("m64p.sh"), "rice, glide64mk2")
        self.assertEqual(runs.emulator("mame.sh"), "mame")
        self.assertEqual(runs.emulator("freej2me.sh"), "freej2me")

    def test_an_arm_without_a_core_test_names_its_platform(self):
        self.assertEqual(el.Runs(tree()).emulator("pico8.sh"), "pico8")

    def test_a_script_no_longer_started_raises(self):
        runs = el.Runs(tree())
        with self.assertRaises(LauncherPatternMissing):
            runs.of("gone.sh")

    def test_a_dispatch_without_any_script_raises(self):
        with self.assertRaises(LauncherPatternMissing):
            el.Runs(tree(**{el.RUN_EMU: "echo nothing\n"}))


class LibretroRecords(unittest.TestCase):
    def test_retroarch_system_directory_comes_from_the_sed(self):
        (record,) = records(el.retroarch)
        self.assertEqual(record["search_dir"], "/storage/roms/bios")
        self.assertEqual(record["kind"], "passes_path")
        self.assertEqual(
            record["source_ref"], f"{ref(el.RETROARCH_MK, '2')}, {ref(el.RUN_EMU, '80')}"
        )

    def test_retrorun_is_handed_the_folder_with_d(self):
        (record,) = records(el.retrorun)
        self.assertEqual(
            (record["emulator"], record["search_dir"], record["passes_to"]),
            ("retrorun", "/storage/roms/bios", "retrorun -d"),
        )
        self.assertEqual(record["source_ref"], ref(el.RUN_EMU, "4, 81-82"))

    def test_freej2me_gets_java_home_and_its_jar_copied(self):
        java, jar = records(el.freej2me)
        self.assertEqual(java["passes_to"], "environment JAVA_HOME")
        self.assertEqual(java["search_dir"], "/storage/roms/bios/jdk")
        self.assertEqual(jar["kind"], "copies")
        self.assertEqual(jar["names"], ["freej2me-lr.jar"])
        self.assertEqual(jar["passes_to"], "${HOME}/roms/bios")
        self.assertEqual(jar["depends_on_option"], "/storage/roms/bios/jdk/eeversion exists")

    def test_mame_copies_its_own_files_and_hands_no_folder(self):
        # The core passes no path option and reads no mame.ini: only the
        # copies are the launcher's.
        found = records(el.mame)
        self.assertEqual([r["kind"] for r in found], ["copies", "copies"])
        self.assertEqual([r["names"] for r in found], [["fm*"], ["mame*"]])


class StandaloneRecords(unittest.TestCase):
    def test_pico8_moves_the_folder_and_runs_the_binary(self):
        (record,) = records(el.pico8)
        self.assertEqual(record["kind"], "moves")
        self.assertEqual(record["names"], ["pico8_dyn"])
        self.assertEqual(record["search_dir"], "/storage/roms/bios/pico-8")
        self.assertEqual(record["passes_to"], "/emuelec/bin/pico-8")
        self.assertEqual(
            record["source_ref"],
            f"{ref(el.RUN_EMU, '57-58')}, {ref(f'{el.BIN}/pico8.sh', '1-5, 8-10')}",
        )

    def test_pico8_without_the_removal_is_not_a_move(self):
        changed = PICO8_SH.replace("    rm -rf /storage/roms/bios/pico-8\n", "")
        with self.assertRaises(LauncherPatternMissing):
            records(el.pico8, **{f"{el.BIN}/pico8.sh": changed})

    def test_links_from_scripts_and_packages(self):
        found = records(el.links)
        self.assertEqual(
            [(r["emulator"], r["search_dir"]) for r in found],
            [
                ("flycastsa", "/storage/roms/bios/dc"),
                ("flycast_dojo", "/storage/roms/bios/dc_dojo"),
                ("amiberry", "/storage/roms/bios"),
                ("amiberry-lite", "/storage/roms/bios"),
                ("timidity", "/storage/roms/bios/timidity/freepats"),
            ],
        )
        self.assertEqual(
            found[1]["source_ref"],
            f"{ref(el.RUN_EMU, '26-27')}, "
            f"{ref(f'{EMU}/flycast-dojo/scripts/flycastdojo.sh', '1-5')}",
        )
        self.assertEqual(
            found[2]["passes_to"], "symlink /usr/config/amiberry/kickstarts -> /storage/roms/bios"
        )

    def test_a_script_without_a_bios_link_raises(self):
        with self.assertRaises(LauncherPatternMissing):
            records(el.links, **{f"{EMU}/flycastsa/scripts/flycast.sh": "flycast \"${1}\"\n"})

    def test_duckstation_scans_the_folder_its_config_names(self):
        (record,) = records(el.duckstation)
        self.assertEqual((record["kind"], record["search_dir"]), ("scans_dir", "/storage/roms/bios"))

    def test_duckstation_config_is_kept_when_present(self):
        (record,) = records(el.duckstation)
        self.assertEqual(record["installs"]["path"], "/emuelec/configs/duckstation/settings.ini")
        self.assertIs(record["kept_if_present"], True)
        self.assertEqual(record["overrides"], [])

    def test_duckstation_with_a_fixed_bios_path_raises(self):
        changed = DUCKSTATION_INI.replace("PathPAL =", "PathPAL = /storage/roms/bios/scph5502.bin")
        with self.assertRaises(LauncherPatternMissing):
            records(el.duckstation, **{f"{EMU}/duckstation/config/settings.ini": changed})

    def test_yabasanshiro_passes_the_bios_unless_hle_is_chosen(self):
        new, old = records(el.yabasanshiro)
        self.assertEqual((new["emulator"], old["emulator"]), ("yabasanshiroSA", "yabasanshiroSA1_5"))
        self.assertEqual(new["names"], ["saturn_bios.bin"])
        self.assertEqual(new["passes_to"], "yabasanshiro -b")
        self.assertEqual(old["passes_to"], "yabasanshiro1_5 -b")
        self.assertEqual(new["depends_on_option"], "hlebios != 1")
        self.assertIs(new["fails_when_missing"], False)

    def test_jzintv_is_handed_the_bios_folder(self):
        (record,) = records(el.jzintv)
        self.assertEqual((record["search_dir"], record["passes_to"]), ("/storage/roms/bios", "jzintv -p"))

    def test_mupen64plus_tries_its_ipl_names_in_order(self):
        (record,) = records(el.mupen64plus)
        self.assertEqual(record["kind"], "names_searched")
        self.assertEqual(record["names"], ["N64DD IPLROM (J).n64", "IPL.n64"])
        self.assertEqual(record["search_dir"], "/storage/roms/bios/Mupen64plus")
        self.assertEqual(record["passes_to"], "mupen64plus --dd-ipl-rom")
        self.assertEqual(record["depends_on_option"], '-f "${GAMEDIR}/${GAMENAME}.ndd"')

    def test_mupen64plus_without_a_fallback_raises(self):
        changed = M64P_SH.replace('[ ! -f "${IPLROM}" ] && IPLROM="${BIOSDIR}/IPL.n64"\n', "")
        with self.assertRaises(LauncherPatternMissing):
            records(el.mupen64plus, **{f"{EMU}/mupen64plussa/mupen64plussa-core/m64p.sh": changed})

    def test_hatari_reads_the_tos_named_by_its_default_config(self):
        (record,) = records(el.hatari)
        self.assertEqual(record["names"], ["tos.img"])
        self.assertEqual(
            record["passes_to"], "Atari-ST-default.cfg [ROM] szTosImageFileName (--configfile)"
        )

    def test_advancemame_one_record_when_every_device_agrees(self):
        roms, arcade, samples = records(el.advancemame)
        self.assertEqual(samples["search_dir"], "/storage/roms/bios/advmame/samples")
        self.assertNotIn("device", samples)
        # advmame.sh rewrites /roms/mame to /roms/arcade for the arcade system.
        self.assertEqual(
            (roms["search_dir"], roms["passes_to"], roms["depends_on_option"]),
            ("/storage/roms/mame", "advmame.rc dir_rom", "system != arcade"),
        )
        self.assertNotIn("systems", roms)
        self.assertEqual((arcade["search_dir"], arcade["systems"]), ("/storage/roms/arcade", ["arcade"]))
        self.assertTrue(arcade["source_ref"].endswith("bin/advmame.sh:1-2, 6"))

    def test_advancemame_devices_that_disagree_raise(self):
        changed = ADVMAME_RC.replace("bios/advmame", "bios/other")
        with self.assertRaises(LauncherPatternMissing):
            records(el.advancemame, **{f"{EMU}/advancemame/config/advmame.rc_oga": changed})

    def test_scummvm_extrapath_and_the_ini_copied_for_the_core(self):
        extra, ini = records(el.scummvm)
        self.assertEqual(extra["passes_to"], "scummvm --extrapath")
        self.assertEqual(extra["depends_on_option"], "/storage/.config/scummvm/extra exists")
        self.assertEqual((ini["emulator"], ini["build"]), ("scummvm", "libretro"))
        self.assertEqual(ini["search_dir"], "/storage/.config/scummvm")
        self.assertEqual(ini["passes_to"], "/storage/roms/bios/scummvm.ini")

    def test_dolphin_data_home(self):
        (record,) = records(el.dolphin)
        self.assertEqual(record["passes_to"], "environment XDG_DATA_HOME")
        self.assertEqual(record["search_dir"], "/storage/roms/dolphin")

    def test_midi_sources_that_read_the_bios_folder(self):
        found = records(el.midi)
        self.assertEqual(
            [(r["emulator"], r["kind"], r["names"], r["search_dir"]) for r in found],
            [
                ("fluidsynth", "fixed_name", ["sc/SC-55.sf2"], "/storage/roms/bios"),
                ("mt32d", "passes_path", [], "/roms/bios"),
            ],
        )
        self.assertEqual(found[0]["depends_on_option"], "ra_midi_output = fluidsynth")
        self.assertEqual(
            found[1]["source_ref"], f"{ref(el.RUN_EMU, '7-9')}, {ref(el.UTILS, '1, 10-11')}"
        )

    def test_every_extractor_runs_on_the_fixtures(self):
        found = el.extract_launchers(tree())
        # The two mame.ini folders are no longer records.
        self.assertEqual(len(found), 26)


class Revision(unittest.TestCase):
    def test_the_revision_is_the_one_the_bios_list_is_read_at(self):
        url = (
            "https://raw.githubusercontent.com/EmuELEC/EmuELEC/v4.8/"
            "packages/sx05re/emuelec/bin/batocera/batocera-systems"
        )
        self.assertEqual(launcher_revision(url), "v4.8")

    def test_a_url_without_a_revision_raises(self):
        with self.assertRaises(ValueError):
            launcher_revision("https://example.org/batocera-systems")


class PlatformRecords(unittest.TestCase):
    """The launchers platforms/emuelec.yml carries, as the scraper wrote them."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = yaml.safe_load((REPO_ROOT / "platforms" / "emuelec.yml").read_text())

    def test_the_platform_carries_launchers(self):
        self.assertTrue(self.config.get("launchers"))

    def test_every_reference_is_in_the_emuelec_packages(self):
        for record in self.config["launchers"]:
            for part in record["source_ref"].split(", "):
                if ":" in part:
                    self.assertTrue(part.startswith(f"{el.SX05RE}/"), record)


if __name__ == "__main__":
    unittest.main()
