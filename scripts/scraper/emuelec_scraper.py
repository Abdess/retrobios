#!/usr/bin/env python3
"""Scraper for EmuELEC's batocera-systems.

Source: packages/sx05re/emuelec/bin/batocera/batocera-systems
Format: Python source, Batocera's `systems` dict, parsed by batocera_scraper
Hash: MD5

`naomi` and `Dinothawr` are written twice in the dict. Python keeps the later
value of a repeated key when the script runs, and so does the parser: naomi
is the entry at line 461 (naomi_boot.bin and naomi.zip, line 444 naming
naomi.zip alone), Dinothawr the one at line 776 (dinothawr.game, line 494
naming level_3-3.tmx).

Verification (batocera-systems at the release tag):
- checkBios (lines 817-833): md5sum() of the file at /storage/roms/<file>
  against the declared md5, an empty md5 meaning presence only. It never
  reads zippedFile: the FM Towns entries that name a member hash the whole
  archive against the member's md5. There is no emulator or core gate.
- Run with no argument by EmulationStation's BIOS screen
  (EmuELEC/emuelec-emulationstation 09356d0d, es-app/src/ApiSystem.cpp:
  645-655, `--filter <system>` for one system), and with `--strictfilter
  <platform>` by ee_check_bios after a failed launch
  (packages/sx05re/emuelec/profile.d/99-emuelec.conf:261, called from
  emuelecRunEmu.sh:605).
"""

from __future__ import annotations

import re
import shlex
import urllib.error
import urllib.request

from safeparse import yaml_load_upstream

from .base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_version
from .batocera_scraper import (
    SYSTEM_SLUG_MAP as BATOCERA_SLUGS,
)
from .batocera_scraper import (
    _not_cores,
    extract_systems_dict,
    platform_systems,
    requirements_from_systems,
)
from .emuelec_launchers import extract_launchers
from .es_emulators import (
    SystemEmulators,
    attach_system_cores,
    es_cores,
    json_systems,
    system_cores,
)
from .shell_launchers import RepoTree

PLATFORM_NAME = "emuelec"

REPO = "EmuELEC/EmuELEC"
_RAW = "https://raw.githubusercontent.com/EmuELEC/EmuELEC/{ref}/"
SOURCE_TEMPLATE = _RAW + "packages/sx05re/emuelec/bin/batocera/batocera-systems"
ES_SYSTEMS_TEMPLATE = _RAW + "packages/sx05re/emuelec-emulationstation/config/es_systems.json"
PORTS_TEMPLATE = _RAW + "packages/sx05re/emuelec-ports/sources/ports.yaml"

# Batocera's names, plus the keys EmuELEC writes that Batocera does not:
# console keys under the slug the other scrapers give them, and each port
# under the system of the profile of the engine its name gives
# (devilutionx, prboom, opentyrian, cannonball, nxengine, tyrquake,
# reminiscence, xrick, vvvvvv, eduke32, sonic2013, sonic-mania, dinothawr,
# rigelengine).
SYSTEM_SLUG_MAP = {
    **BATOCERA_SLUGS,
    "atari7800": "atari-7800",
    "atarilynx": "atari-lynx",
    "n64": "nintendo-64",
    "o2em": "magnavox-odyssey2",
    "Diablo": "diablo",
    "Hellfire": "diablo",
    "Dinothawr": "dinothawr",
    "Quake": "quake",
    "VVVVVV": "vvvvvv",
    "DOOM1": "doom",
    "DOOM2": "doom",
    "OpenTyrian": "tyrian",
    "Cannonball": "sega-outrun",
    "CaveStory": "cave-story",
    "REminiscence": "flashback",
    "RickDangerous": "xrick",
    "eduke32": "duke3d",
    "sonic1": "sonic-1-2013",
    "sonic2": "sonic-2-2013",
    "sonicmania": "sonic-mania",
    "RigelEngine": "duke-nukem-2",
}

# es_systems.json names libretro cores under `libretro`, and `retrorun`
# loads the libretro core it lists. emuelecRunEmu.sh:101-116 turns either
# into ${CORE}_libretro. Any other emulator runs the core it names
# (EMU="${CORE}", line 107) through the case at lines 164-353.
RUNNERS: dict[str, str | None] = {"libretro": None, "retrorun": None}

# A standalone emulator and the libretro core of the same emulator, from the
# packages each one builds (packages/sx05re/emulators/<pkg>/package.mk
# PKG_SITE): hatarisa hatari/hatari, stellasa stella-emu/stella, fbneoSA
# finalburnneo/FBNeo, flycastsa flyinghead/flycast, scummvmsa
# scummvm/scummvm, PPSSPPSDL hrydgard/ppsspp.
BUILDS_OF = {
    "HATARISA": "hatari",
    "STELLASA": "stella",
    "FBNEOSA": "fbneo",
    "flycastsa": "flycast",
    "SCUMMVMSA": "scummvm",
    "PPSSPPSDL": "ppsspp",
}

# The ES system `ports` (es_systems.json:2570-2590) runs one generated
# script per entry of ports.yaml through emuelecRunApp.sh:22, and its single
# emulator `ports` is that dispatch, not a program. The scripts are rendered
# from port.sh.j2 by port_builder.py (emuelec-ports/package.mk:62-64): each
# runs its `commands`, so the engine is the libretro core a command hands
# emuelecRunEmu.sh with -C (lines 367-369 load <core>_libretro.so), or the
# program `port_exe` names.
PORTS_SYSTEM = "ports"


def launcher_revision(url: str) -> str:
    """The tag or commit a batocera-systems URL is read at."""
    found = re.search(rf"/{REPO}/([^/]+)/packages/", url)
    if found is None:
        raise ValueError(f"{url} names no {REPO} revision")
    return found.group(1)


def port_engines(text: str) -> list[tuple[str, str, str | None, bool]]:
    """(port, engine, check_bios key, libretro?) for each entry of ports.yaml.

    The engine is written as the OS writes it: the libretro core a command
    hands emuelecRunEmu.sh with -C, else `port_exe`. `check_bios` is the
    batocera-systems key the script hands ee_check_bios on a failed start
    (port.sh.j2:23-25), the key the port's files are listed under.
    """
    data = yaml_load_upstream(text)
    if not isinstance(data, dict) or not data:
        raise ValueError("ports.yaml names no port")
    engines = []
    for port, spec in data.items():
        core = None
        for command in map(str, spec.get("commands") or []):
            if "emuelecRunEmu.sh" in command:
                core = next(
                    (w[2:] for w in shlex.split(command) if w.startswith("-C")), core
                )
        engine = core or spec.get("port_exe")
        if not engine:
            raise ValueError(f"ports.yaml: {port} names neither a core nor port_exe")
        engines.append((str(port), str(engine), spec.get("check_bios"), core is not None))
    return engines


def with_ports(
    systems: SystemEmulators, engines: list[tuple[str, str, str | None, bool]]
) -> SystemEmulators:
    """The ES systems, each port engine filed under `ports` and its own key."""
    def entry(engine: str, libretro: bool) -> tuple[str, list[str]]:
        return ("libretro", [engine]) if libretro else (engine, [engine])

    result = {**systems, PORTS_SYSTEM: [entry(e, lr) for _, e, _, lr in engines]}
    for _, engine, key, libretro in engines:
        if key:
            result[key] = [*result.get(key, []), entry(engine, libretro)]
    return result

class Scraper(BaseScraper):
    """Scraper for EmuELEC's batocera-systems."""

    def __init__(self, url: str | None = None) -> None:
        self.tag = "" if url else fetch_github_latest_version(REPO)
        super().__init__(url=url or SOURCE_TEMPLATE.format(ref=self.tag))

    def _fetch_text(self, url: str) -> str:
        req = urllib.request.Request(url, headers={"User-Agent": "retrobios-scraper/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to fetch {url}: {e}") from e

    def validate_format(self, raw_data: str) -> bool:
        has_dict = re.search(r"^systems\s*=\s*\{", raw_data, re.MULTILINE) is not None
        return has_dict and "def checkBios" in raw_data and '"biosFiles"' in raw_data

    def fetch_requirements(self) -> list[BiosRequirement]:
        raw = self._fetch_raw()
        if not self.validate_format(raw):
            raise ValueError("batocera-systems format validation failed")
        # Paths are relative to /storage/roms (`prefix`, lines 859-865): the
        # list names neogeo/ and ports/ beside bios/.
        return requirements_from_systems(extract_systems_dict(raw), SYSTEM_SLUG_MAP, strip="")

    def generate_platform_yaml(self) -> dict:
        systems = platform_systems(
            self.fetch_requirements(), extract_systems_dict(self._fetch_raw()), SYSTEM_SLUG_MAP
        )
        # es_systems.json gives each system its emulators in menu order (psx,
        # lines 3610-3660: libretro pcsx_rearmed_32b, pcsx_rearmed,
        # swanstation, then Duckstation).
        es_systems = with_ports(
            json_systems(self._fetch_text(ES_SYSTEMS_TEMPLATE.format(ref=self.tag))),
            port_engines(self._fetch_text(PORTS_TEMPLATE.format(ref=self.tag))),
        )
        not_cores = _not_cores(PLATFORM_NAME)
        cores, standalone, dual = es_cores(es_systems, RUNNERS, BUILDS_OF, not_cores)
        # Each system keeps the list es_systems.json gives it: it says whose
        # files a platform entry asks for. What runs is what an image carries.
        attach_system_cores(systems, system_cores(es_systems, RUNNERS, not_cores))
        built = self._built()
        unbuilt = {n for n in cores if n not in built}
        cores, standalone, dual = ([n for n in names if n in built] for names in (cores, standalone, dual))
        # Runners (retroarch, retrorun) and the launcher's own spellings are
        # no ES core name: only a record of an emulator no image carries goes.
        launchers = [
            r for r in extract_launchers(RepoTree.github(REPO, launcher_revision(self.url)))
            if not set(str(r["emulator"]).split(", ")) <= unbuilt
        ]
        return {
            "platform": "EmuELEC",
            "version": self.tag.removeprefix("v"),
            "homepage": "https://emuelec.org",
            "source": self.url,
            "base_destination": "",
            # RetroArch's system_directory is /storage/roms/bios
            # (packages/sx05re/libretro_base/retroarch/package.mk:117).
            "core_destination": "bios",
            "hash_type": "md5",
            "verification_mode": "md5",
            "cores": cores,
            "standalone_cores": standalone,
            "dual_mode_cores": dual,
            "systems": systems,
            # Read at the revision the BIOS list comes from, for the
            # emulators an image carries.
            "launchers": launchers,
        }

    def _built(self) -> set[str]:
        """The cores at least one released device image carries.

        Read by the targets scraper: a device keeps a core when a package it
        builds installs it and its es_systems.cfg still offers it. The port
        engines depend on emuelec-ports, which no package of an image
        depends on, and flycast-dojo is in no device list (UNBUILT there).
        """
        from .targets.emuelec_targets_scraper import Scraper as DeviceTargets
        targets = DeviceTargets().device_targets(self.tag)["targets"]
        return {name for entry in targets.values() for name in entry["cores"]}


def main() -> None:
    from .base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape EmuELEC BIOS requirements")


if __name__ == "__main__":
    main()
