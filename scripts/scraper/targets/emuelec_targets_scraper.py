"""Scraper for EmuELEC per-device emulator availability.

Sources (EmuELEC/EmuELEC, at the tag platforms/emuelec.yml names, v4.8):
  - the release's asset names: one `EmuELEC-<DEVICE>.<ARCH>-<version>`
    image per device (Amlogic-ng, GameForce, OdroidGoAdvance, OdroidM1 at
    v4.8). The tree names no device list: projects/ holds the directories
    of many more devices than the release builds.
  - packages/sx05re/emuelec/package.mk -- the metapackage, whose
    PKG_DEPENDS_TARGET is each device's package list (lines 8-77)
  - distributions/EmuELEC/options -- LIBRETRO_CORES and
    LIBRETRO_S922X_CORES (lines 274-373)
  - each core package's package.mk -- PKG_ARCH, which scripts/build:28-30
    reads to skip a package, and the install step naming the .so or binary
  - packages/sx05re/emuelec-emulationstation/package.mk -- the cores and
    emulators makeinstall_target deletes from es_systems.cfg per device
    (lines 114-143)
  - es_systems.json and ports.yaml, read the way the platform scraper reads
    them

A device keeps a core when a package it builds installs that core and its
es_systems.cfg still offers it. The OdroidGoAdvance image carries neither
DuckStation nor Dolphin nor the MAME core: without a target list, its pack
shipped their firmware anyway.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from typing import NamedTuple

import yaml

from . import BaseTargetScraper

PLATFORM_NAME = "emuelec"

REPO = "EmuELEC/EmuELEC"
RAW = "https://raw.githubusercontent.com/EmuELEC/EmuELEC/{ref}/{path}"
RELEASE_API = "https://api.github.com/repos/EmuELEC/EmuELEC/releases/tags/{ref}"
META_MK = "packages/sx05re/emuelec/package.mk"
OPTIONS = "distributions/EmuELEC/options"
ES_MK = "packages/sx05re/emuelec-emulationstation/package.mk"

try:
    from ..base_scraper import fetch_bytes, github_headers
    from ..batocera_scraper import _not_cores
    from ..emuelec_scraper import (
        BUILDS_OF, ES_SYSTEMS_TEMPLATE, PORTS_TEMPLATE, RUNNERS, port_engines, with_ports,
    )
    from ..es_emulators import SystemEmulators, es_cores
except ImportError:
    from scraper.base_scraper import fetch_bytes, github_headers
    from scraper.batocera_scraper import _not_cores
    from scraper.emuelec_scraper import (
        BUILDS_OF, ES_SYSTEMS_TEMPLATE, PORTS_TEMPLATE, RUNNERS, port_engines, with_ports,
    )
    from scraper.es_emulators import SystemEmulators, es_cores

_ASSET_RE = re.compile(r"^EmuELEC-(?P<device>[A-Za-z0-9-]+)\.(?P<arch>[a-z0-9_]+)-")

# The metapackage, line for line. Each rule below transcribes these lines;
# a tag that rewrites one stops the scrape instead of reading it wrong.
_META_LINES = (
    'PKG_DEPENDS_TARGET="toolchain ${OPENGLES} emuelec-emulationstation retroarch"',
    'PKG_DEPENDS_TARGET+=" emuelec-tools ${PKG_EMUS} ${PKG_EXPERIMENTAL}"',
    'if [ "${DEVICE}" == "Amlogic-ng" ] || [ "${DEVICE}" == "Amlogic-no" ] || '
    '[ "${DEVICE}" == "RK356x" ] || [ "${DEVICE}" == "OdroidM1" ]; then',
    'PKG_DEPENDS_TARGET+=" ${LIBRETRO_S922X_CORES}"',
    'if [ "${DEVICE}" == "OdroidGoAdvance" ] || [ "${DEVICE}" == "GameForce" ]; then',
    'PKG_DEPENDS_TARGET+=" kmscon odroidgoa-utils"',
    "for discore in duckstation mesen-s virtualjaguar quicknes MC; do",
    'PKG_DEPENDS_TARGET=$(echo ${PKG_DEPENDS_TARGET} | sed "s|${discore} | |")',
    'PKG_DEPENDS_TARGET+=" yabasanshiro"',
    'PKG_DEPENDS_TARGET+=" fbterm"',
    'if [ "${ARCH}" == "aarch64" ]; then',
    "for discore in quicknes parallel-n64 pcsx_rearmed; do",
    'PKG_DEPENDS_TARGET=$(echo ${PKG_DEPENDS_TARGET} | sed "s|${discore}| |")',
    'PKG_DEPENDS_TARGET+=" dolphinSA"',
    'if [ "${DEVICE}" == "Amlogic-old" ]; then',
    "for discore in yabasanshiroSA_1_11 yabasanshiroSA_1_5 yabasanshiro same_cdi duckstation; do",
    'PKG_DEPENDS_TARGET+=" mame"',
    'if [ "${DEVICE}" == "RK356x" ] || [ "${DEVICE}" == "OdroidM1" ]; then',
    "for discore in flycast-dojo; do",
)
_LIB32_RE = re.compile(r'PKG_DEPENDS_TARGET\+=" (swanstation [^"]*)"')
_BIG = ("Amlogic-ng", "Amlogic-no", "RK356x", "OdroidM1")
_HANDHELD = ("OdroidGoAdvance", "GameForce")

# What emuelec-emulationstation's makeinstall_target does to es_systems.cfg.
_ES_LINES = (
    'if [[ "${DEVICE}" != "Amlogic-ng" || "${DEVICE}" != "Amlogic-ne" || '
    '"${DEVICE}" != "Amlogic-no" ]]; then',
    'if [[ ${DEVICE} == "OdroidGoAdvance" || "${DEVICE}" == "GameForce" ]]; then',
    'remove_cores="mesen-s quicknes mame2016 mesen"',
    'remove_cores="mesen-s quicknes mame2016 mesen yabasanshiroSA yabasanshiro"',
    "xmlstarlet ed -L -P -d \"/systemList/system[name='saturn']\" ${CORESFILE}",
    "xmlstarlet ed -L -P -d \"/systemList/system[name='phillips-cdi']\" ${CORESFILE}",
    'sed -i "s|<core>${discore}</core>||g" ${CORESFILE}',
    'if [[ ${DEVICE} != "OdroidGoAdvance" ]] && [[ "${DEVICE}" != "GameForce" ]]; then',
    "xmlstarlet ed -L -P -d \"/systemList/system/emulators/emulator[@name='retrorun']\" ${CORESFILE}",
    "xmlstarlet ed -L -P -d \"/systemList/system/emulators/emulator[@name='Duckstation']\" ${CORESFILE}",
)


class Install(NamedTuple):
    """One line of a package.mk that puts a core on the image."""

    path: str
    line: str
    cores: tuple[str, ...]
    # The ARCH test the line sits under in makeinstall_target, if any.
    arch: str | None = None


def _lr(package: str, line: str, *cores: str, arch: str | None = None) -> Install:
    return Install(f"packages/sx05re/libretro/{package}/package.mk", line, cores, arch)


def _sa(package: str, line: str, *cores: str) -> Install:
    return Install(f"packages/sx05re/emulators/{package}/package.mk", line, cores)


def _lib32(package: str, line: str, *cores: str) -> Install:
    return Install(f"packages/lib32/emuelec/libretro/{package}/package.mk", line, cores)


_TO = "${INSTALL}/usr/lib/libretro/"

# Package -> the ES core names its install step puts on the image, with the
# line that does it (v4.8). A libretro core is the .so it copies to
# /usr/lib/libretro, the name emuelecRunEmu.sh:101-116 loads as
# ${CORE}_libretro. A standalone name is the program the runner's case for
# it starts (emuelecRunEmu.sh:164-353), installed by the line cited, or by
# the package's default make/cmake/meson install where the line cited only
# adds the launch script beside it.
PROVIDERS: dict[str, tuple[Install, ...]] = {
    "2048": (_lr("2048", f"cp 2048_libretro.so {_TO}", "2048"),),
    "81": (_lr("81", f"cp 81_libretro.so {_TO}", "81"),),
    "a5200": (_lr("a5200", f"cp a5200_libretro.so {_TO}", "a5200"),),
    "atari800": (_lr("atari800", f"cp atari800_libretro.so {_TO}", "atari800"),),
    "beetle-lynx": (_lr("beetle-lynx", f"cp mednafen_lynx_libretro.so {_TO}", "mednafen_lynx"),),
    "beetle-ngp": (_lr("beetle-ngp", f"cp mednafen_ngp_libretro.so {_TO}", "mednafen_ngp"),),
    "beetle-pce": (_lr("beetle-pce", f"cp mednafen_pce_fast_libretro.so {_TO}",
                       "mednafen_pce_fast"),),
    "beetle-pcfx": (_lr("beetle-pcfx", f"cp mednafen_pcfx_libretro.so {_TO}", "mednafen_pcfx"),),
    # line 20: the build makes mednafen_saturn_libretro.so (Makefile TARGET_NAME).
    "beetle-saturn": (_lr("beetle-saturn", "cp mednafen_saturn_*.so $INSTALL/usr/lib/libretro/",
                          "mednafen_saturn"),),
    "beetle-supergrafx": (_lr("beetle-supergrafx", f"cp mednafen_supergrafx_libretro.so {_TO}",
                              "mednafen_supergrafx"),),
    "beetle-vb": (_lr("beetle-vb", f"cp mednafen_vb_libretro.so {_TO}", "mednafen_vb"),),
    "beetle-wswan": (_lr("beetle-wswan", f"cp mednafen_wswan_libretro.so {_TO}",
                         "mednafen_wswan"),),
    "bk": (_lr("bk", f"cp ${{PKG_BUILD}}/bk_libretro.so {_TO}", "bk"),),
    "bluemsx": (_lr("bluemsx", f"cp bluemsx_libretro.so {_TO}", "bluemsx"),),
    "cannonball": (_lr("cannonball", f"cp cannonball_libretro.so {_TO}", "cannonball"),),
    "cap32": (_lr("cap32", f"cp cap32_libretro.so {_TO}", "cap32"),),
    "daphne": (_lr("daphne", f"cp daphne_libretro.so {_TO}", "daphne"),),
    "dinothawr": (_lr("dinothawr", f"cp dinothawr_libretro.so {_TO}", "dinothawr"),),
    "dosbox-pure": (_lr("dosbox-pure", f"cp dosbox_pure_libretro.so {_TO}dosbox_pure_libretro.so",
                        "dosbox_pure"),),
    "dosbox-svn": (_lr("dosbox-svn", "cp ${PKG_BUILD}/libretro/dosbox_svn_libretro.so "
                       "${INSTALL}/usr/lib/libretro", "dosbox_svn"),),
    "easyrpg": (_lr("easyrpg", f"cp ${{PKG_BUILD}}/.${{TARGET_NAME}}/easyrpg_libretro.so {_TO}",
                    "easyrpg"),),
    "fake_08": (_lr("fake_08", f"cp -v ${{PKG_BUILD}}/platform/libretro/fake08_libretro.so {_TO}",
                    "fake08"),),
    "fbalpha2012": (_lr("fbalpha2012", f"cp fbalpha2012_libretro.so {_TO}", "fbalpha2012"),),
    "fbneo": (_lr("fbneo", f"cp ${{PKG_BUILD}}/src/burner/libretro/fbneo_libretro.so {_TO}",
                  "fbneo"),),
    "fceumm": (_lr("fceumm", f"cp fceumm_libretro.so {_TO}", "fceumm"),),
    "fceumm-mod": (_lr("fceumm-mod", f"cp ${{PKG_BUILD}}/fceumm_mod_libretro.* {_TO}",
                       "fceumm_mod"),),
    # lines 47-51: flycast_32b on arm, flycast elsewhere.
    "flycast": (
        _lr("flycast", f"cp flycast_libretro.so {_TO}flycast_32b_libretro.so", "flycast_32b",
            arch="arm"),
        _lr("flycast", f"cp flycast_libretro.so {_TO}", "flycast", arch="!arm"),
    ),
    "fmsx-libretro": (_lr("fmsx-libretro", f"cp fmsx_libretro.so {_TO}", "fmsx"),),
    "freeintv": (_lr("freeintv", f"cp freeintv_libretro.so {_TO}", "freeintv"),),
    "freej2me": (_lr("freej2me", 'cp `find . -name "freej2me_libretro.so" | xargs echo` '
                     "${INSTALL}/usr/lib/libretro", "freej2me"),),
    "fuse-libretro": (_lr("fuse-libretro", f"cp fuse_libretro.so {_TO}", "fuse"),),
    "gambatte": (_lr("gambatte", f"cp gambatte_libretro.so {_TO}", "gambatte"),),
    "gearboy": (_lr("gearboy", f"cp platforms/libretro/gearboy_libretro.so {_TO}", "gearboy"),),
    "gearcoleco": (_lr("gearcoleco", f"cp platforms/libretro/gearcoleco_libretro.so {_TO}",
                       "gearcoleco"),),
    "geargrafx": (_lr("geargrafx", f"cp platforms/libretro/geargrafx_libretro.so {_TO}",
                      "geargrafx"),),
    "gearlynx": (_lr("gearlynx", f"cp platforms/libretro/gearlynx_libretro.so {_TO}",
                     "gearlynx"),),
    "gearsystem": (_lr("gearsystem", f"cp platforms/libretro/gearsystem_libretro.so {_TO}",
                       "gearsystem"),),
    "genesis-plus-gx": (_lr("genesis-plus-gx",
                            f"cp genesis_plus_gx_libretro.so {_TO}genesis_plus_gx_libretro.so",
                            "genesis_plus_gx"),),
    "genesis-plus-gx-wide": (_lr("genesis-plus-gx-wide", "cp genesis_plus_gx_wide_libretro.so "
                                 f"{_TO}genesis_plus_gx_wide_libretro.so",
                                 "genesis_plus_gx_wide"),),
    # PKG_NAME is genesis_plus_gx_cart_special (line 4).
    "genesis_plus_gx_cart_special": (_lr("genesis_plus_gx_cart_special",
                                         f"cp genesis_plus_gx_libretro.so {_TO}"
                                         "${PKG_NAME}_libretro.so",
                                         "genesis_plus_gx_cart_special"),),
    "geolith": (_lr("geolith", f"cp geolith_libretro.so {_TO}", "geolith"),),
    "gpsp": (_lr("gpsp", f"cp -v gpsp_libretro.so {_TO}", "gpsp"),),
    "gw-libretro": (_lr("gw-libretro", f"cp gw_libretro.so {_TO}", "gw"),),
    "handy": (_lr("handy", f"cp handy_libretro.so {_TO}", "handy"),),
    "hatari": (_lr("hatari", f"cp ../hatari_libretro.so {_TO}", "hatari"),),
    # line 65: the build's only .so is mame_libretro.so.
    "mame": (_lr("mame", f"cp *.so {_TO}", "mame"),),
    "mame2003-plus": (_lr("mame2003-plus", f"cp mame2003_plus_libretro.so {_TO}",
                          "mame2003_plus"),),
    "mame2010": (_lr("mame2010", f"cp mame2010_libretro.so {_TO}", "mame2010"),),
    "meowpc98": (_lr("meowpc98", f"cp libretro/nekop2_libretro.so {_TO}", "nekop2"),),
    "mesen": (_lr("mesen", f"cp Libretro/mesen_libretro.so {_TO}", "mesen"),),
    "mesen-s": (_lr("mesen-s", f"cp Libretro/mesen-s_libretro.so {_TO}", "mesen-s"),),
    "mgba": (_lr("mgba", f"cp mgba_libretro.so {_TO}", "mgba"),),
    "mrboom": (_lr("mrboom", f"cp mrboom_libretro.so {_TO}", "mrboom"),),
    # PKG_ARCH="arm" (line 25): scripts/build skips it on aarch64.
    "mupen64plus": (_lr("mupen64plus", f"cp mupen64plus_libretro.so {_TO}"
                        "mupen64plus_32b_libretro.so", "mupen64plus_32b"),),
    "mupen64plus-nx": (_lr("mupen64plus-nx", f"cp mupen64plus_next_libretro.so {_TO}",
                           "mupen64plus_next"),),
    "mupen64plus-nx-alt": (_lr("mupen64plus-nx-alt", f"cp mupen64plus_next_libretro.so {_TO}"
                               "mupen64plus_next_alt_libretro.so", "mupen64plus_next_alt"),),
    "neocd_libretro": (_lr("neocd_libretro", f"cp ${{PKG_BUILD}}/neocd_libretro.so {_TO}",
                           "neocd"),),
    "nestopia": (_lr("nestopia", f"cp libretro/nestopia_libretro.so {_TO}", "nestopia"),),
    "np2kai": (_lr("np2kai", f"cp ${{PKG_BUILD}}/sdl/np2kai_libretro.so {_TO}", "np2kai"),),
    "nxengine": (_lr("nxengine", f"cp nxengine_libretro.so {_TO}", "nxengine"),),
    "o2em": (_lr("o2em", f"cp o2em_libretro.so {_TO}", "o2em"),),
    "opera": (_lr("opera", f"cp opera_libretro.so {_TO}", "opera"),),
    # lines 42-46: pcsx_rearmed_32b on arm, pcsx_rearmed elsewhere.
    "pcsx_rearmed": (
        _lr("pcsx_rearmed", "cp pcsx_rearmed_libretro.so "
            "${INSTALL}${INSTALLTO}/pcsx_rearmed_32b_libretro.so", "pcsx_rearmed_32b", arch="arm"),
        _lr("pcsx_rearmed", "cp pcsx_rearmed_libretro.so ${INSTALL}${INSTALLTO}",
            "pcsx_rearmed", arch="!arm"),
    ),
    "picodrive": (_lr("picodrive", f"cp ${{PKG_BUILD}}/picodrive_libretro.so {_TO}",
                      "picodrive"),),
    "pocketcdg": (_lr("pocketcdg", f"cp pocketcdg_libretro.so {_TO}", "pocketcdg"),),
    "pokemini": (_lr("pokemini", f"cp pokemini_libretro.so {_TO}", "pokemini"),),
    "potator": (_lr("potator", "cp ${PKG_BUILD}/platform/libretro/potator_libretro.so "
                    f"{_TO}potator_libretro.so", "potator"),),
    "prboom": (_lr("prboom", f"cp prboom_libretro.so {_TO}prboom_libretro.so", "prboom"),),
    "prosystem": (_lr("prosystem", f"cp prosystem_libretro.so {_TO}", "prosystem"),),
    "puae": (_lr("puae", f"cp puae_libretro.so {_TO}", "puae"),),
    "puae2021": (_lr("puae2021", f"cp -v puae2021_libretro.so {_TO}", "puae2021"),),
    "px68k": (_lr("px68k", f"cp px68k_libretro.so {_TO}", "px68k"),),
    "reminiscence": (_lr("reminiscence", f"cp reminiscence_libretro.so {_TO}", "reminiscence"),),
    "same_cdi": (_lr("same_cdi", f"cp -v same_cdi_libretro.so {_TO}", "same_cdi"),),
    "sameboy": (_lr("sameboy", f"cp libretro/sameboy_libretro.so {_TO}", "sameboy"),),
    "sameduck": (_lr("sameduck", f"cp build/bin/sameduck_libretro.so {_TO}", "sameduck"),),
    "scummvm": (_lr("scummvm", 'cp "${PKG_BUILD}/backends/platform/libretro/scummvm_libretro."'
                    "{so,info} ${INSTALL}/usr/lib/libretro/", "scummvm"),),
    "snes9x": (_lr("snes9x", f"cp libretro/snes9x_libretro.so {_TO}", "snes9x"),),
    "snes9x2002": (_lr("snes9x2002", f"cp snes9x2002_libretro.so {_TO}", "snes9x2002"),),
    "snes9x2005_plus": (_lr("snes9x2005_plus", f"cp snes9x2005_plus_libretro.so {_TO}",
                            "snes9x2005_plus"),),
    "snes9x2010": (_lr("snes9x2010", f"cp snes9x2010_libretro.so {_TO}", "snes9x2010"),),
    "stella": (_lr("stella", f"cp ${{PKG_BUILD}}/src/os/libretro/stella_libretro.so {_TO}",
                   "stella"),),
    "supafaust": (_lr("supafaust", f"cp -v mednafen_supafaust_libretro.so {_TO}",
                      "mednafen_supafaust"),),
    "swanstation": (_lr("swanstation", "cp ${PKG_BUILD}/.${TARGET_NAME}/swanstation_libretro.so "
                        f"{_TO}", "swanstation"),),
    "tgbdual": (_lr("tgbdual", f"cp tgbdual_libretro.so {_TO}", "tgbdual"),),
    "tic-80": (_lr("tic-80", "cp ${PKG_BUILD}/.${TARGET_NAME}/bin/tic80_libretro.so "
                   f"{_TO}tic80_libretro.so", "tic80"),),
    "tyrquake": (_lr("tyrquake", f"cp tyrquake_libretro.so {_TO}", "tyrquake"),),
    # PKG_ARCH="arm" (line 25): scripts/build skips it on aarch64.
    "uae4arm": (_lr("uae4arm", f"cp uae4arm_libretro.so {_TO}uae4arm_32b_libretro.so",
                    "uae4arm_32b"),),
    "uzem": (_lr("uzem", f"cp uzem_libretro.so {_TO}", "uzem"),),
    "vba-next": (_lr("vba-next", f"cp vba_next_libretro.so {_TO}", "vba_next"),),
    "vbam": (_lr("vbam", f"cp ../src/libretro/vbam_libretro.so {_TO}", "vbam"),),
    "vecx": (_lr("vecx", f"cp vecx_libretro.so {_TO}vecx_libretro.so", "vecx"),),
    # line 55: make_target builds one vice_<emu>_libretro.so per emulator it
    # loops over (lines 37-50), x64, x64sc, x128, xplus4 and xvic among them.
    "vice": (_lr("vice", f"cp built/vice_*_libretro.so {_TO}",
                 "vice_x128", "vice_x64", "vice_x64sc", "vice_xplus4", "vice_xvic"),),
    "virtualjaguar": (_lr("virtualjaguar", f"cp virtualjaguar_libretro.so {_TO}",
                          "virtualjaguar"),),
    "xmil": (_lr("xmil", f"cp ${{PKG_BUILD}}/libretro/x1_libretro.so {_TO}", "x1"),),
    "xrick": (_lr("xrick", f"cp xrick_libretro.so {_TO}", "xrick"),),
    "yabasanshiro": (_lr("yabasanshiro", f"cp yabause/src/libretro/yabasanshiro_libretro.so {_TO}",
                         "yabasanshiro"),),
    "lib32-flycast": (_lib32("lib32-flycast", "cp -va flycast_libretro.so "
                             f"{_TO}flycast_32b_libretro.so", "flycast_32b"),),
    "lib32-mupen64plus": (_lib32("lib32-mupen64plus", "cp mupen64plus_libretro.so "
                                 f"{_TO}mupen64plus_32b_libretro.so", "mupen64plus_32b"),),
    "lib32-parallel-n64": (_lib32("lib32-parallel-n64", "cp parallel_n64_libretro.so "
                                  f"{_TO}parallel_n64_32b_libretro.so", "parallel_n64_32b"),),
    "lib32-pcsx_rearmed": (_lib32("lib32-pcsx_rearmed", "cp pcsx_rearmed_libretro.so "
                                  f"{_TO}pcsx_rearmed_32b_libretro.so", "pcsx_rearmed_32b"),),
    "lib32-uae4arm": (_lib32("lib32-uae4arm", "cp uae4arm_libretro.so "
                             f"{_TO}uae4arm_32b_libretro.so", "uae4arm_32b"),),
    # Standalone emulators, by the program the runner starts.
    "PPSSPPSDL": (_sa("PPSSPPSDL", 'cp `find . -name "PPSSPPSDL" | xargs echo` '
                      "${INSTALL}/usr/bin/PPSSPPSDL", "PPSSPPSDL"),),
    "advancemame": (_sa("advancemame", "cp -r ${PKG_BUILD}/obj/mame/linux/blend/advmame "
                        "${INSTALL}/usr/bin", "AdvanceMame"),),
    "amiberry": (_sa("amiberry", "cp -a amiberry* ${INSTALL}/usr/bin/amiberry", "AMIBERRY"),),
    "dolphinSA": (_sa("dolphinSA", "cp -rf ${PKG_BUILD}/.${TARGET_NAME}/Binaries/"
                      "dolphin-emu-nogui ${INSTALL}/usr/bin", "dolphin"),),
    # dosbox comes from the meson install, dosbox.start from line 28.
    "dosbox-staging": (_sa("dosbox-staging", "cp -a ${PKG_DIR}/scripts/* ${INSTALL}/usr/bin/",
                           "DOSBOXSDL2"),),
    "duckstation": (_sa("duckstation", "cp -rf ${PKG_BUILD}/.${TARGET_NAME}/bin/"
                        "duckstation-nogui ${INSTALL}/usr/bin", "Duckstation"),),
    "ecwolf": (_sa("ecwolf", "cp ${PKG_BUILD}/ecwolf ${INSTALL}/usr/bin/ecwolf", "ECWolf"),),
    "fbneoSA": (_sa("fbneoSA", "cp -rf ${PKG_BUILD}/fbneo ${INSTALL}/usr/bin", "FBNEOSA"),),
    "flycastsa": (_sa("flycastsa", "cp ${PKG_BUILD}/.${TARGET_NAME}/flycast "
                      "${INSTALL}/usr/bin/flycast", "flycastsa"),),
    "hatarisa": (_sa("hatarisa", "cp src/hatari ${INSTALL}/usr/bin", "HATARISA"),),
    # hypseus comes from the cmake install (PKG_TOOLCHAIN, line 13).
    "hypseus-singe": (_sa("hypseus-singe", 'PKG_TOOLCHAIN="cmake"', "HYPSEUS"),),
    "ikemen-go": (_sa("ikemen-go", 'cp "$PKG_BUILD/bin/Ikemen_Go_"* "$INSTALL/usr/bin/Ikemen_Go"',
                      "ikemen"),),
    "jzintv": (_sa("jzintv", "cp bin/jzintv ${INSTALL}/usr/bin", "jzintv"),),
    # The metapackage's dependencies (line 10). mupen64plus itself comes from
    # mupen64plussa-ui-console's makeinstall_target.
    "mupen64plussa": (
        _sa("mupen64plussa", 'PKG_DEPENDS_TARGET="toolchain mupen64plussa-core '
            "mupen64plussa-ui-console mupen64plussa-audio-sdl mupen64plussa-input-sdl "
            'mupen64plussa-rsp-hle mupen64plussa-video-rice mupen64plussa-video-glide64mk2"',
            "mupen64plussa"),
        Install("packages/sx05re/emulators/mupen64plussa/mupen64plussa-ui-console/package.mk",
                "cp ${PKG_BUILD}/projects/unix/mupen64plus ${UBINDIR}", ()),
    ),
    "openbor": (_sa("openbor", 'cp `find . -name "OpenBOR.elf" | xargs echo` '
                    "${INSTALL}/usr/bin/OpenBOR", "OPENBOR"),),
    # scummvm comes from the make install, moved to /usr/bin at line 51.
    "scummvmsa": (_sa("scummvmsa", "mv ${INSTALL}/usr/local/bin ${INSTALL}/usr/", "SCUMMVMSA"),),
    # solarus-run comes from the cmake install, solarus.sh from line 22.
    "solarus": (_sa("solarus", "cp ${PKG_DIR}/scripts/* ${INSTALL}/usr/bin", "Solarus"),),
    "stellasa": (_sa("stellasa", "cp -rf ${PKG_BUILD}/stella ${INSTALL}/usr/bin", "STELLASA"),),
    "yabasanshiroSA_1_11": (_sa("yabasanshiroSA_1_11", "cp -a ${PKG_BUILD}/src/retro_arena/"
                                "yabasanshiro ${INSTALL}/usr/bin", "yabasanshiro"),),
    "lib32-bennugd-monolithic": (Install(
        "packages/lib32/emuelec/ports/lib32-bennugd-monolithic/package.mk",
        "cp ${PKG_BUILD}/projects/cmake/bgdi/bgdi ${INSTALL}/usr/bin", ("bgdi",)),),
    # The metapackage's own bin/ (line 82) carries pico8.sh, which starts the
    # PICO-8 binary the user copies to bios/pico-8.
    "emuelec": (Install(META_MK, "cp -rf ${PKG_DIR}/bin ${INSTALL}/usr", ("Pico-8",)),),
}

# Packages of a device list whose install step puts no ES core on the image.
NO_ES_CORE: dict[str, str] = {
    "toolchain": "build toolchain",
    "${OPENGLES}": "graphics driver",
    "emuelec-emulationstation": "the frontend",
    "retroarch": "the libretro frontend",
    "lib32-retroarch": "the 32-bit libretro frontend, retroarch32",
    "emuelec-tools": "system tools",
    "emuelec-32bit-info": "the .info files of the 32-bit cores",
    "lib32-essential": "32-bit runtime",
    "lib32-libusb": "32-bit library",
    "lib32-box86": "x86 translator",
    "fbterm": "terminal",
    "kmscon": "terminal",
    "odroidgoa-utils": "device tools and retrorun, a runner",
    "amiberry-lite": "amiberry-lite, which es_systems.json names nowhere",
    "yabasanshiroSA_1_5": "yabasanshiro1_5, which es_systems.json names nowhere",
    "lib32-droidports": "gmloader, which es_cores drops (_overrides.yml)",
    "gme": "gme_libretro.so, which es_systems.json names nowhere",
    "nestopiaCV": "nestopiaCV_libretro.so, which es_systems.json names nowhere",
    "quasi88": "quasi88_libretro.so, which es_systems.json names nowhere",
    "spring": "spring_*_libretro.so, which es_systems.json names nowhere",
}

# ES core names no package of any device builds, by the package that would.
# The port engines are dependencies of emuelec-ports (its package.mk,
# lines 17-59), and no package of the image depends on emuelec-ports;
# flycast-dojo is in no device list.
UNBUILT: dict[str, str] = {
    **dict.fromkeys(
        ("CGeniusExe", "Chocolate-Doom", "GZDoom", "LZDoom", "OpenJazz", "RigelEngine",
         "VVVVVV", "abuse", "bs", "bstone", "ccleste", "cdogs-sdl", "devilutionx",
         "eduke32", "fallout-ce", "fallout2-ce", "fheroes2", "hcl", "hode", "hurrican",
         "opentyrian", "prince", "smw", "sonic2013", "soniccd", "sonicmania", "supertux2",
         "supertuxkart", "xash3d"),
        "emuelec-ports",
    ),
    "flycast_dojo": "flycast-dojo",
}


def release_devices(asset_names: list[str]) -> dict[str, str]:
    """{device: architecture} of each image a release publishes."""
    found: dict[str, str] = {}
    for name in asset_names:
        match = _ASSET_RE.match(name)
        if match:
            found.setdefault(match.group("device"), match.group("arch"))
    if not found:
        raise RuntimeError("the EmuELEC release publishes no device image")
    return found


def _require(text: str, lines: tuple[str, ...], where: str) -> None:
    present = {line.strip() for line in text.splitlines()}
    missing = [line for line in lines if line not in present]
    if missing:
        raise RuntimeError(f"{where} no longer reads {missing[0]!r}")


def _quoted(text: str, name: str, where: str) -> list[str]:
    """The words of `NAME="..."`; a backslash-newline inside the quotes is
    removed by bash, so the value reads as one line."""
    match = re.search(rf'^\s*{name}="([^"]*)"', text, re.MULTILINE)
    if match is None:
        raise RuntimeError(f"{where} sets no {name}")
    return match.group(1).replace("\\\n", " ").split()


class Metapackage(NamedTuple):
    emus: list[str]
    experimental: list[str]
    s922x: list[str]
    lib32: list[str]


def read_metapackage(package_mk: str, options: str) -> Metapackage:
    """The lists the metapackage rules work on, with PKG_EMUS expanded."""
    _require(package_mk, _META_LINES, META_MK)
    emus = _quoted(package_mk, "PKG_EMUS", META_MK)
    if emus[:1] != ["${LIBRETRO_CORES}"]:
        raise RuntimeError(f"{META_MK}: PKG_EMUS no longer starts with ${{LIBRETRO_CORES}}")
    lib32 = _LIB32_RE.search(package_mk)
    if lib32 is None:
        raise RuntimeError(f"{META_MK}: no aarch64 lib32 list")
    return Metapackage(
        emus=_quoted(options, "LIBRETRO_CORES", OPTIONS) + emus[1:],
        experimental=_quoted(package_mk, "PKG_EXPERIMENTAL", META_MK),
        s922x=_quoted(options, "LIBRETRO_S922X_CORES", OPTIONS),
        lib32=lib32.group(1).replace("\\\n", " ").split(),
    )


def _sed_first(words: str, pattern: str) -> str:
    """`echo ${PKG_DEPENDS_TARGET} | sed "s|<pattern>| |"`: the unquoted echo
    joins the words with single spaces, sed replaces the first match only,
    anywhere in the line, a word's tail included."""
    line = " ".join(words.split())
    at = line.find(pattern)
    return line if at < 0 else f"{line[:at]} {line[at + len(pattern):]}"


def device_packages(meta: Metapackage, device: str, arch: str) -> list[str]:
    """PKG_DEPENDS_TARGET of the metapackage for one device (lines 8-77)."""
    depends = "toolchain ${OPENGLES} emuelec-emulationstation retroarch"
    depends += " emuelec-tools " + " ".join(meta.emus) + " " + " ".join(meta.experimental)
    if device in _BIG:
        depends += " " + " ".join(meta.s922x)
    if device in _HANDHELD:
        depends += " kmscon odroidgoa-utils"
        for discore in ("duckstation", "mesen-s", "virtualjaguar", "quicknes", "MC"):
            depends = _sed_first(depends, f"{discore} ")
        depends += " yabasanshiro"
    else:
        depends += " fbterm"
    if arch == "aarch64":
        for discore in ("quicknes", "parallel-n64", "pcsx_rearmed"):
            depends = _sed_first(depends, discore)
        depends += " " + " ".join(meta.lib32)
        if device in _BIG:
            depends += " dolphinSA"
        if device == "Amlogic-old":
            for discore in ("yabasanshiroSA_1_11", "yabasanshiroSA_1_5", "yabasanshiro",
                            "same_cdi", "duckstation"):
                depends = _sed_first(depends, f"{discore} ")
    if device in _BIG:
        depends += " mame"
    if device in ("RK356x", "OdroidM1"):
        depends = _sed_first(depends, "flycast-dojo")
    return depends.split()


def arch_builds(pkg_arch: str, arch: str) -> bool:
    """scripts/build:28-30: an empty PKG_ARCH builds everywhere, `!<arch>`
    excludes, otherwise the list names the arch or `any`."""
    words = pkg_arch.split()
    if not words:
        return True
    if f"!{arch}" in words:
        return False
    return arch in words or "any" in words


def pkg_arch(package_mk: str) -> str:
    match = re.search(r'^PKG_ARCH="([^"]*)"', package_mk, re.MULTILINE)
    return match.group(1) if match else ""


def es_systems_for(es_json: str, es_mk: str, device: str) -> SystemEmulators:
    """es_systems.json as es_systems.cfg reads after makeinstall_target's
    deletions on one device (emuelec-emulationstation/package.mk:114-143).

    `sed "s|<core>X</core>||g"` matches a core written without attributes:
    generate_es_systems.py gives `default="true"` to the first default core
    of a system and `incompatible_extensions` to a core listing them.
    """
    _require(es_mk, _ES_LINES, ES_MK)
    if device in _HANDHELD:
        remove_cores = {"mesen-s", "quicknes", "mame2016", "mesen"}
        drop_systems: set[str] = set()
        drop_emulators = {"Duckstation"}
    elif device == "Amlogic-old":
        remove_cores = {"mesen-s", "quicknes", "mame2016", "mesen", "yabasanshiroSA",
                        "yabasanshiro"}
        drop_systems = {"saturn", "phillips-cdi"}
        drop_emulators = {"Duckstation", "retrorun"}
    else:
        # Line 117 holds for every device: no name is all three at once.
        remove_cores = set()
        drop_systems = set()
        drop_emulators = {"retrorun"}
    systems: SystemEmulators = {}
    for system in json.loads(es_json).get("systems", []):
        if system["name"] in drop_systems:
            continue
        default_set = False
        emulators = []
        for emulator in system.get("emulators") or []:
            kept = []
            for core in emulator.get("cores") or []:
                bare = "incompatible" not in core
                if core.get("default", False) and not default_set:
                    default_set = True
                    bare = False
                if not (bare and core["name"] in remove_cores):
                    kept.append(core["name"])
            if emulator["name"] not in drop_emulators:
                emulators.append((emulator["name"], kept))
        systems[system["name"]] = emulators
    return systems


def device_cores(
    packages: list[str],
    arch: str,
    archs: dict[str, str],
    systems: SystemEmulators,
) -> list[str]:
    """ES core names a device both installs and offers.

    `archs` maps each package of PROVIDERS to its PKG_ARCH.
    """
    unknown = sorted(
        p for p in set(packages) if p not in PROVIDERS and p not in NO_ES_CORE
        and p not in UNBUILT.values()
    )
    if unknown:
        raise RuntimeError(f"{META_MK}: no install step read for {', '.join(unknown)}")
    unbuilt = sorted(set(packages) & set(UNBUILT.values()))
    if unbuilt:
        raise RuntimeError(f"{META_MK}: {unbuilt[0]} is built and its cores are read as absent")
    installed: set[str] = set()
    for package in [*set(packages), "emuelec"]:
        if package not in PROVIDERS or not arch_builds(archs[package], arch):
            continue
        for install in PROVIDERS[package]:
            if install.arch is None or (install.arch == arch) or (
                install.arch.startswith("!") and install.arch[1:] != arch
            ):
                installed.update(install.cores)
    offered, _standalone, _dual = es_cores(
        systems, RUNNERS, BUILDS_OF, _not_cores(PLATFORM_NAME)
    )
    return sorted(installed & set(offered))


def check_names(systems: SystemEmulators) -> None:
    """Every ES core name is installed by a package read or known unbuilt."""
    offered, _standalone, _dual = es_cores(
        systems, RUNNERS, BUILDS_OF, _not_cores(PLATFORM_NAME)
    )
    provided = {core for installs in PROVIDERS.values() for i in installs for core in i.cores}
    unread = sorted(set(offered) - provided - set(UNBUILT))
    if unread:
        raise RuntimeError(f"es_systems.json names {', '.join(unread)}, no package read installs it")


def check_installs(texts: dict[str, str]) -> dict[str, str]:
    """{package: PKG_ARCH}, after checking each cited install line is there."""
    archs: dict[str, str] = {}
    for package, installs in PROVIDERS.items():
        for install in installs:
            _require(texts[install.path], (install.line,), install.path)
        archs[package] = pkg_arch(texts[installs[0].path])
    return archs


class Scraper(BaseTargetScraper):
    """Per-device core lists from EmuELEC's metapackage."""

    def __init__(self, url: str = "https://github.com/" + REPO) -> None:
        super().__init__(url=url)
        self.ref = ""

    def _raw(self, path: str) -> str:
        return fetch_bytes(RAW.format(ref=self.ref, path=path)).decode("utf-8")

    def fetch_targets(self) -> dict:
        return self.device_targets()

    def device_targets(self, ref: str | None = None) -> dict:
        """The targets file, read at `ref`, by default the revision
        platforms/emuelec.yml was scraped at."""
        self.ref = ref or self.pinned_revision(PLATFORM_NAME)
        release = json.loads(
            fetch_bytes(RELEASE_API.format(ref=self.ref), headers=github_headers())
        )
        devices = release_devices([asset["name"] for asset in release.get("assets", [])])
        meta = read_metapackage(self._raw(META_MK), self._raw(OPTIONS))
        paths = sorted({i.path for installs in PROVIDERS.values() for i in installs})
        archs = check_installs({path: self._raw(path) for path in paths})
        es_json = fetch_bytes(ES_SYSTEMS_TEMPLATE.format(ref=self.ref)).decode("utf-8")
        ports = port_engines(fetch_bytes(PORTS_TEMPLATE.format(ref=self.ref)).decode("utf-8"))
        es_mk = self._raw(ES_MK)
        check_names(with_ports(es_systems_for(es_json, es_mk, "Amlogic-ng"), ports))
        targets: dict[str, dict] = {}
        for device, arch in sorted(devices.items()):
            systems = with_ports(es_systems_for(es_json, es_mk, device), ports)
            cores = device_cores(device_packages(meta, device, arch), arch, archs, systems)
            targets[device.lower()] = {"architecture": arch, "cores": cores}
            print(f"  {device.lower()} ({arch}): {len(cores)} cores", file=sys.stderr)
        return {
            "platform": PLATFORM_NAME,
            "source": f"{self.url}/blob/{self.ref}/{META_MK}",
            "devices_source": release["html_url"],
            "scraped_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "targets": targets,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        allow_abbrev=False, description="Scrape EmuELEC per-device cores"
    )
    parser.add_argument("--dry-run", action="store_true", help="Show target summary")
    parser.add_argument("--output", "-o", help="Output YAML file")
    args = parser.parse_args()

    scraper = Scraper()
    data = scraper.fetch_targets()
    if args.dry_run:
        for name, info in data["targets"].items():
            print(f"  {name} ({info['architecture']}): {len(info['cores'])} cores")
        return
    if args.output:
        scraper.write_output(data, args.output)
        print(f"Written to {args.output}")
        return
    print(yaml.dump(data, default_flow_style=False, sort_keys=False))


if __name__ == "__main__":
    main()
