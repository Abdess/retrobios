#!/usr/bin/env python3
"""Scraper for AmberELEC's batocera-systems.

Source: packages/amberelec/sources/scripts/batocera-systems
Format: Python source, Batocera's `systems` dict, parsed by batocera_scraper
Hash: MD5

AmberELEC has published no release since 20230203. Its builds come from the
dev branch as prereleases in AmberELEC/AmberELEC-prerelease, each naming the
commit it was built from. The scraper reads the list at the commit of the
newest one. That list accepts every md5 the 20230203 one does for the files
it keeps (syscard3.pce 38179df8, BS-X.bin 96cf17bf) and adds
neogeo/aes.zip.

Verification (batocera-systems at that commit):
- checkBios (lines 583-643): md5sum() of the file at /storage/roms/<file>
  against the declared md5, an empty md5 meaning presence only. For a
  zippedFile entry, checkInsideZip() (lines 530-561) matches the member name
  with casefold() and hashes it.
- Run with no argument by EmulationStation's BIOS screen
  (AmberELEC/emulationstation e3846751, es-app/src/ApiSystem.cpp:603-613),
  which also passes `--filter <system>`. ee_check_bios
  (packages/amberelec/profile.d/99-distribution.conf:320) passes
  `--strictfilter`, which the script's argument switch (lines 665-687) does
  not handle: that call prints nothing and exits 0.

The launcher layer is read at the same commit (amberelec_launchers): runemu.py,
the scripts its standalone table runs and the configs their packages install.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from .amberelec_launchers import extract_launchers
from .base_scraper import BaseScraper, BiosRequirement, github_headers
from .batocera_scraper import (
    SYSTEM_SLUG_MAP as BATOCERA_SLUGS,
)
from .batocera_scraper import (
    _not_cores,
    extract_systems_dict,
    platform_systems,
    requirements_from_systems,
)
from .es_emulators import attach_system_cores, es_cores, system_cores, xml_systems

PLATFORM_NAME = "amberelec"

REPO = "AmberELEC/AmberELEC"
PRERELEASE_REPO = "AmberELEC/AmberELEC-prerelease"
_RAW = "https://raw.githubusercontent.com/AmberELEC/AmberELEC/{ref}/"
SOURCE_TEMPLATE = _RAW + "packages/amberelec/sources/scripts/batocera-systems"
ES_SYSTEMS_TEMPLATE = _RAW + "packages/ui/emulationstation/config/es_systems.cfg"

# Batocera's names, plus the keys AmberELEC writes that Batocera does not,
# filed under the slug the other scrapers already give them.
SYSTEM_SLUG_MAP = {
    **BATOCERA_SLUGS,
    "atari7800": "atari-7800",
    "atarilynx": "atari-lynx",
    "n64": "nintendo-64",
    "o2em": "magnavox-odyssey2",
}

# runemu.py: `retroarch` and `retrorun` load the libretro core es_systems.cfg
# names. `mame` lists MAME machines and runs them on the libretro MAME core
# (lines 233-261 set self.core = 'mame', line 355 builds the RetroArch command).
RUNNERS: dict[str, str | None] = {"retroarch": None, "retrorun": None, "mame": "mame"}
# runemu.py:110-128 starts every other emulator through the script its
# standalone_emulators table names, keyed by the emulator name es_systems.cfg
# writes. Three are the standalone build of an emulator the list also offers
# as a libretro core, the package's PKG_SITE naming the same project:
# hatarisa hatari/hatari (packages/games/emulators/hatarisa), ppssppsa
# hrydgard/ppsspp (PPSSPPSDL runs its ppsspp.sh, line 116) and scummvmsa
# scummvm/scummvm.
BUILDS_OF = {"HATARISA": "hatari", "PPSSPPSDL": "ppsspp", "SCUMMVMSA": "scummvm"}

_PRERELEASE_COMMIT = re.compile(r"AmberELEC/AmberELEC@([0-9a-f]{40})")


def prerelease_commit(body: str) -> str:
    """The commit a prerelease's notes say it was built from."""
    found = _PRERELEASE_COMMIT.search(body or "")
    if found is None:
        raise RuntimeError("the newest AmberELEC prerelease names no commit")
    return found.group(1)


def fetch_newest_prerelease() -> tuple[str, str]:
    """(tag, commit) of the newest AmberELEC prerelease."""
    url = f"https://api.github.com/repos/{PRERELEASE_REPO}/releases?per_page=1"
    try:
        req = urllib.request.Request(url, headers=github_headers())
        with urllib.request.urlopen(req, timeout=15) as resp:
            releases = json.loads(resp.read())
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        raise RuntimeError(f"cannot list the releases of {PRERELEASE_REPO}: {e}") from e
    if not releases or not releases[0].get("tag_name"):
        raise RuntimeError(f"{PRERELEASE_REPO} lists no release")
    return releases[0]["tag_name"], prerelease_commit(releases[0].get("body", ""))


class Scraper(BaseScraper):
    """Scraper for AmberELEC's batocera-systems."""

    def __init__(self, url: str | None = None) -> None:
        if url:
            self.tag, self.commit = "", ""
        else:
            self.tag, self.commit = fetch_newest_prerelease()
        super().__init__(url=url or SOURCE_TEMPLATE.format(ref=self.commit))

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
        # Paths are relative to /storage/roms (`prefix`, lines 667-675): the
        # list names neogeo/neogeo.zip beside bios/.
        return requirements_from_systems(extract_systems_dict(raw), SYSTEM_SLUG_MAP, strip="")

    def generate_platform_yaml(self) -> dict:
        systems = platform_systems(
            self.fetch_requirements(), extract_systems_dict(self._fetch_raw()), SYSTEM_SLUG_MAP
        )
        # es_systems.cfg gives each <system> its <emulators> in menu order
        # (atarist, lines 267-288: retroarch's hatari, then HATARISA).
        es_systems = xml_systems(self._fetch_text(ES_SYSTEMS_TEMPLATE.format(ref=self.commit)))
        not_cores = _not_cores(PLATFORM_NAME)
        cores, standalone, dual = es_cores(es_systems, RUNNERS, BUILDS_OF, not_cores)
        attach_system_cores(systems, system_cores(es_systems, RUNNERS, not_cores))
        return {
            "platform": "AmberELEC",
            "version": self.tag,
            "homepage": "https://amberelec.org",
            "source": self.url,
            "base_destination": "",
            # RetroArch's system_directory is ~/roms/bios
            # (packages/games/tools/retroarch/sources/retroarch.cfg:611).
            "core_destination": "bios",
            "hash_type": "md5",
            "verification_mode": "md5",
            "cores": cores,
            "standalone_cores": standalone,
            "dual_mode_cores": dual,
            "systems": systems,
            "launchers": extract_launchers(
                lambda path: self._fetch_text(_RAW.format(ref=self.commit) + path)
            ),
        }


def main() -> None:
    from .base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape AmberELEC BIOS requirements")


if __name__ == "__main__":
    main()
