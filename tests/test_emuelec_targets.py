"""EmuELEC's images differ by device, and only its metapackage says how.

packages/sx05re/emuelec/package.mk (v4.8) builds the S922X cores, Dolphin
and the MAME core only on Amlogic-ng, Amlogic-no, RK356x and OdroidM1, and
takes DuckStation out on the two handhelds with a sed that replaces the
first match only. With no target list, an OdroidGoAdvance pack carried the
firmware of cores its image never had.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from scraper.targets import emuelec_targets_scraper as scraper  # noqa: E402

# packages/sx05re/emuelec/package.mk:8-77 at v4.8, PKG_EMUS and
# PKG_EXPERIMENTAL shortened.
PACKAGE_MK = """PKG_DEPENDS_TARGET="toolchain ${OPENGLES} emuelec-emulationstation retroarch"
PKG_EXPERIMENTAL="nestopiaCV quasi88 yabasanshiroSA_1_11 yabasanshiroSA_1_5 fbneoSA"
PKG_EMUS="${LIBRETRO_CORES} advancemame duckstation pcsx_rearmed flycastsa"
PKG_DEPENDS_TARGET+=" emuelec-tools ${PKG_EMUS} ${PKG_EXPERIMENTAL}"

if [ "${DEVICE}" == "Amlogic-ng" ] || [ "${DEVICE}" == "Amlogic-no" ] || [ "${DEVICE}" == "RK356x" ] || [ "${DEVICE}" == "OdroidM1" ]; then
\tPKG_DEPENDS_TARGET+=" ${LIBRETRO_S922X_CORES}"
fi

if [ "${DEVICE}" == "OdroidGoAdvance" ] || [ "${DEVICE}" == "GameForce" ]; then
\tPKG_DEPENDS_TARGET+=" kmscon odroidgoa-utils"
\tfor discore in duckstation mesen-s virtualjaguar quicknes MC; do
\t\tPKG_DEPENDS_TARGET=$(echo ${PKG_DEPENDS_TARGET} | sed "s|${discore} | |")
\tdone
\tPKG_DEPENDS_TARGET+=" yabasanshiro"
else
\tPKG_DEPENDS_TARGET+=" fbterm"
fi

if [ "${ARCH}" == "aarch64" ]; then
  for discore in quicknes parallel-n64 pcsx_rearmed; do
\t\tPKG_DEPENDS_TARGET=$(echo ${PKG_DEPENDS_TARGET} | sed "s|${discore}| |")
\tdone

  PKG_DEPENDS_TARGET+=" swanstation \\
                        lib32-essential \\
                        lib32-pcsx_rearmed \\
                        lib32-parallel-n64
                        lib32-libusb"

  if [ "${DEVICE}" == "Amlogic-ng" ] || [ "${DEVICE}" == "Amlogic-no" ] || [ "${DEVICE}" == "RK356x" ] || [ "${DEVICE}" == "OdroidM1" ]; then
    PKG_DEPENDS_TARGET+=" dolphinSA"
  fi

  if [ "${DEVICE}" == "Amlogic-old" ]; then
    for discore in yabasanshiroSA_1_11 yabasanshiroSA_1_5 yabasanshiro same_cdi duckstation; do
      PKG_DEPENDS_TARGET=$(echo ${PKG_DEPENDS_TARGET} | sed "s|${discore} | |")
    done
  fi
fi

if [ "${DEVICE}" == "Amlogic-ng" ] || [ "${DEVICE}" == "Amlogic-no" ] || [ "${DEVICE}" == "RK356x" ] || [ "${DEVICE}" == "OdroidM1" ]; then
\tPKG_DEPENDS_TARGET+=" mame"
fi

if [ "${DEVICE}" == "RK356x" ] || [ "${DEVICE}" == "OdroidM1" ]; then
 for discore in flycast-dojo; do
\t\tPKG_DEPENDS_TARGET=$(echo ${PKG_DEPENDS_TARGET} | sed "s|${discore}| |")
\tdone
fi
"""

# distributions/EmuELEC/options:274-373 at v4.8, shortened.
OPTIONS = """LIBRETRO_CORES="mgba \\
parallel-n64 \\
pcsx_rearmed \\
flycast"

LIBRETRO_S922X_CORES="beetle-saturn \\
mesen \\
quicknes \\
virtualjaguar"
"""

# packages/sx05re/emuelec-emulationstation/package.mk:114-143 at v4.8.
ES_MK = """CORESFILE="${INSTALL}/usr/config/emulationstation/es_systems.cfg"

if [[ "${DEVICE}" != "Amlogic-ng" || "${DEVICE}" != "Amlogic-ne" || "${DEVICE}" != "Amlogic-no" ]]; then
    if [[ ${DEVICE} == "OdroidGoAdvance" || "${DEVICE}" == "GameForce" ]]; then
        remove_cores="mesen-s quicknes mame2016 mesen"
    elif [ "${DEVICE}" == "Amlogic-old" ]; then
        remove_cores="mesen-s quicknes mame2016 mesen yabasanshiroSA yabasanshiro"
        xmlstarlet ed -L -P -d "/systemList/system[name='saturn']" ${CORESFILE}
        xmlstarlet ed -L -P -d "/systemList/system[name='phillips-cdi']" ${CORESFILE}
        xmlstarlet ed -L -P -d "/systemList/system/emulators/emulator[@name='Duckstation']" ${CORESFILE}
    fi
    for discore in ${remove_cores}; do
        sed -i "s|<core>${discore}</core>||g" ${CORESFILE}
        sed -i '/^[[:space:]]*$/d' ${CORESFILE}
    done
fi

if [[ ${DEVICE} != "OdroidGoAdvance" ]] && [[ "${DEVICE}" != "GameForce" ]]; then
\txmlstarlet ed -L -P -d "/systemList/system/emulators/emulator[@name='retrorun']" ${CORESFILE}
else
\txmlstarlet ed -L -P -d "/systemList/system/emulators/emulator[@name='Duckstation']" ${CORESFILE}
fi
"""


def _system(name: str, *emulators: tuple[str, list[dict]]) -> dict:
    return {"name": name, "emulators": [{"name": e, "cores": c} for e, c in emulators]}


ES_JSON = json.dumps({"systems": [
    _system("nes", ("libretro", [{"name": "mesen", "default": True}])),
    _system("snes", ("libretro", [{"name": "snes9x", "default": True}, {"name": "mesen-s"}])),
    _system("psx",
            ("libretro", [{"name": "pcsx_rearmed", "default": True},
                          {"name": "pcsx_rearmed_32b"}, {"name": "swanstation"}]),
            ("Duckstation", [{"name": "Duckstation"}]),
            ("retrorun", [{"name": "pcsx_rearmed_32b"}])),
    _system("n64", ("libretro", [{"name": "parallel_n64_32b"}])),
]})

ARCHS = {"mesen": "", "duckstation": "aarch64", "pcsx_rearmed": "any",
             "lib32-pcsx_rearmed": "aarch64", "swanstation": "any",
             "lib32-parallel-n64": "aarch64"}

ASSETS = [
    "EmuELEC-Amlogic-ng.aarch64-4.8-Generic.img.gz",
    "EmuELEC-Amlogic-ng.aarch64-4.8.tar",
    "EmuELEC-GameForce.aarch64-4.8-chi.img.gz.sha256",
    "EmuELEC-OdroidGoAdvance.aarch64-4.8-odroidgo2.tar",
    "EmuELEC-OdroidM1.aarch64-4.8.img.gz",
]


class TheMetapackageDecidesEachDevice(unittest.TestCase):
    def setUp(self):
        self.meta = scraper.read_metapackage(PACKAGE_MK, OPTIONS)

    def test_devices_are_the_images_the_release_publishes(self):
        self.assertEqual(scraper.release_devices(ASSETS), {
            "Amlogic-ng": "aarch64", "GameForce": "aarch64",
            "OdroidGoAdvance": "aarch64", "OdroidM1": "aarch64",
        })

    def test_the_lists_the_rules_work_on(self):
        self.assertEqual(self.meta.emus, ["mgba", "parallel-n64", "pcsx_rearmed", "flycast",
                                          "advancemame", "duckstation", "pcsx_rearmed",
                                          "flycastsa"])
        self.assertEqual(self.meta.lib32, ["swanstation", "lib32-essential",
                                           "lib32-pcsx_rearmed", "lib32-parallel-n64",
                                           "lib32-libusb"])

    def test_the_big_devices_build_the_s922x_cores_dolphin_and_mame(self):
        packages = scraper.device_packages(self.meta, "Amlogic-ng", "aarch64")
        for package in ("beetle-saturn", "mesen", "virtualjaguar", "dolphinSA", "mame",
                        "duckstation", "fbterm"):
            self.assertIn(package, packages)
        # quicknes is added, then the aarch64 loop takes it out.
        self.assertNotIn("quicknes", packages)

    def test_the_handhelds_lose_duckstation_and_gain_their_tools(self):
        packages = scraper.device_packages(self.meta, "OdroidGoAdvance", "aarch64")
        for package in ("duckstation", "mesen", "beetle-saturn", "dolphinSA", "mame", "fbterm"):
            self.assertNotIn(package, packages)
        self.assertEqual(packages[-1:], ["lib32-libusb"])
        self.assertIn("kmscon", packages)
        self.assertIn("yabasanshiro", packages)

    def test_sed_takes_out_the_first_match_only(self):
        # pcsx_rearmed is written twice, in LIBRETRO_CORES and in PKG_EMUS:
        # the aarch64 loop removes the first and the 64-bit core is built.
        for device in ("Amlogic-ng", "OdroidGoAdvance"):
            packages = scraper.device_packages(self.meta, device, "aarch64")
            self.assertEqual(packages.count("pcsx_rearmed"), 1, device)
            self.assertNotIn("parallel-n64", packages, device)

    def test_a_pattern_with_a_trailing_space_misses_the_last_word(self):
        self.assertEqual(scraper._sed_first("a duckstation", "duckstation "), "a duckstation")
        self.assertEqual(scraper._sed_first("a  duckstation  b", "duckstation "), "a  b")
        # Without the space, the pattern takes a word's tail too.
        self.assertEqual(scraper._sed_first("lib32-pcsx_rearmed", "pcsx_rearmed"), "lib32- ")

    def test_a_changed_rule_stops_the_scrape(self):
        changed = PACKAGE_MK.replace("duckstation mesen-s virtualjaguar quicknes MC",
                                     "duckstation mesen-s")
        with self.assertRaises(RuntimeError):
            scraper.read_metapackage(changed, OPTIONS)


class EachPackageBuildsWhereItsArchAllows(unittest.TestCase):
    def test_pkg_arch(self):
        self.assertTrue(scraper.arch_builds("", "aarch64"))
        self.assertTrue(scraper.arch_builds("any", "aarch64"))
        self.assertTrue(scraper.arch_builds("aarch64 arm", "aarch64"))
        # mupen64plus and uae4arm say PKG_ARCH="arm": skipped on aarch64.
        self.assertFalse(scraper.arch_builds("arm", "aarch64"))
        self.assertFalse(scraper.arch_builds("any !aarch64", "aarch64"))

    def test_every_cited_install_line_is_read(self):
        install = scraper.PROVIDERS["mgba"][0]
        text = f'PKG_ARCH="any"\nmakeinstall_target() {{\n  {install.line}\n}}\n'
        with self.assertRaises(RuntimeError):
            scraper._require(text.replace("mgba_libretro", "mgba2_libretro"),
                             (install.line,), install.path)
        scraper._require(text, (install.line,), install.path)


class TheFrontendOffersWhatTheDeviceKeeps(unittest.TestCase):
    def test_handhelds_drop_bare_cores_and_duckstation(self):
        systems = scraper.es_systems_for(ES_JSON, ES_MK, "GameForce")
        # mesen is the nes default: written with an attribute, sed misses it.
        self.assertEqual(systems["nes"], [("libretro", ["mesen"])])
        self.assertEqual(systems["snes"], [("libretro", ["snes9x"])])
        self.assertEqual([e for e, _ in systems["psx"]], ["libretro", "retrorun"])

    def test_other_devices_drop_retrorun(self):
        systems = scraper.es_systems_for(ES_JSON, ES_MK, "Amlogic-ng")
        self.assertEqual([e for e, _ in systems["psx"]], ["libretro", "Duckstation"])
        self.assertEqual(systems["snes"], [("libretro", ["snes9x", "mesen-s"])])

    def test_a_device_keeps_what_it_builds_and_offers(self):
        meta = scraper.read_metapackage(PACKAGE_MK, OPTIONS)
        archs = {**dict.fromkeys(scraper.PROVIDERS, "any"), **ARCHS}
        cores = {}
        for device in ("Amlogic-ng", "OdroidGoAdvance"):
            packages = [p for p in scraper.device_packages(meta, device, "aarch64")
                        if p in scraper.PROVIDERS or p in scraper.NO_ES_CORE]
            systems = scraper.es_systems_for(ES_JSON, ES_MK, device)
            cores[device] = scraper.device_cores(packages, "aarch64", archs, systems)
        self.assertEqual(cores["Amlogic-ng"], ["Duckstation", "mesen", "parallel_n64_32b",
                                               "pcsx_rearmed", "pcsx_rearmed_32b",
                                               "swanstation"])
        self.assertEqual(cores["OdroidGoAdvance"], ["parallel_n64_32b", "pcsx_rearmed",
                                                    "pcsx_rearmed_32b", "swanstation"])

    def test_a_package_never_read_stops_the_scrape(self):
        archs = dict.fromkeys(scraper.PROVIDERS, "any")
        with self.assertRaises(RuntimeError):
            scraper.device_cores(["mgba", "newcore"], "aarch64", archs, {})


class TheCommittedListFollowsTheRules(unittest.TestCase):
    def test_the_handhelds_list_no_core_they_do_not_build(self):
        import yaml  # noqa: PLC0415

        targets = yaml.safe_load((REPO_ROOT / "platforms" / "targets" / "emuelec.yml")
                                 .read_text(encoding="utf-8"))["targets"]
        self.assertEqual(set(targets), {"amlogic-ng", "gameforce", "odroidgoadvance", "odroidm1"})
        big = set(targets["amlogic-ng"]["cores"])
        for device in ("gameforce", "odroidgoadvance"):
            self.assertEqual(big - set(targets[device]["cores"]), {
                "Duckstation", "dolphin", "mame", "mednafen_saturn", "mesen", "mesen-s",
                "virtualjaguar",
            })
        self.assertEqual(targets["odroidm1"]["cores"], targets["amlogic-ng"]["cores"])


if __name__ == "__main__":
    unittest.main()
