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

from model.sourcerevision import required_revision
from model.launcherrecords import record_emulators
from model.targets import not_cores
from .base_scraper import fetch_github_latest_version, fetch_text
from .batocera_scraper import (
    SYSTEM_SLUG_MAP as BATOCERA_SLUGS,
)
from .batocera_scraper import (
    CheckBiosScraper,
)
from .emuelec_launchers import extract_launchers
from .es_emulators import (
    attach_system_cores,
    es_cores,
    json_systems,
    system_cores,
)
from scraper.shell_launchers import RepoTree
from .emuelec_systems import (
    BUILDS_OF,
    ES_SYSTEMS_TEMPLATE,
    PORTS_TEMPLATE,
    RUNNERS,
    _RAW,
    port_engines,
    with_ports,
)
from .targets.emuelec_targets_scraper import Scraper as DeviceTargets

PLATFORM_NAME = "emuelec"

REPO = "EmuELEC/EmuELEC"
SOURCE_TEMPLATE = _RAW + "packages/sx05re/emuelec/bin/batocera/batocera-systems"

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


class Scraper(CheckBiosScraper):
    """Scraper for EmuELEC's batocera-systems."""

    slug_map = SYSTEM_SLUG_MAP
    # Paths are relative to /storage/roms (`prefix`, lines 859-865): the
    # list names neogeo/ and ports/ beside bios/.
    strip = ""

    def __init__(self, url: str | None = None) -> None:
        self.tag = "" if url else fetch_github_latest_version(REPO)
        super().__init__(url=url or SOURCE_TEMPLATE.format(ref=self.tag))

    def generate_platform_yaml(self) -> dict:
        systems = self.platform_systems()
        # es_systems.json gives each system its emulators in menu order (psx,
        # lines 3610-3660: libretro pcsx_rearmed_32b, pcsx_rearmed,
        # swanstation, then Duckstation).
        es_systems = with_ports(
            json_systems(fetch_text(ES_SYSTEMS_TEMPLATE.format(ref=self.tag))),
            port_engines(fetch_text(PORTS_TEMPLATE.format(ref=self.tag))),
        )
        dropped = not_cores(PLATFORM_NAME)
        cores, standalone, dual = es_cores(es_systems, RUNNERS, BUILDS_OF, dropped)
        # Each system keeps the list es_systems.json gives it: it says whose
        # files a platform entry asks for. What runs is what an image carries.
        attach_system_cores(systems, system_cores(es_systems, RUNNERS, dropped))
        built = self._built()
        unbuilt = {n for n in cores if n not in built}
        cores, standalone, dual = ([n for n in names if n in built] for names in (cores, standalone, dual))
        # Runners (retroarch, retrorun) and the launcher's own spellings are
        # no ES core name: only a record of an emulator no image carries goes.
        launchers = [
            r for r in extract_launchers(RepoTree.github(REPO, required_revision(self.url, REPO)))
            if not set(record_emulators(r)) <= unbuilt
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
        targets = DeviceTargets().device_targets(self.tag)["targets"]
        return {name for entry in targets.values() for name in entry["cores"]}


def main() -> None:
    from .base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape EmuELEC BIOS requirements")


if __name__ == "__main__":
    main()
