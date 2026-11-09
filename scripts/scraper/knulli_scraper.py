#!/usr/bin/env python3
"""Scraper for KNULLI's knulli-systems.

Source: package/system/knulli-scripts/scripts/knulli-systems
Format: Python source, Batocera's `systems` dict, parsed by batocera_scraper
Hash: MD5

`msx1` and `msx2+` are written twice in the dict. Python keeps the later
value of a repeated key when the script runs, and so does the parser.

Verification (knulli-systems at the release tag):
- checkBios (lines 867-927): md5sum() of the file at /userdata/<file>
  against the declared md5, an empty md5 meaning presence only. For a
  zippedFile entry, checkInsideZip() (lines 814-845) matches the member name
  with casefold() and hashes it. A system or file carrying `emulator` and
  `core` is checked only when es_systems.cfg offers that pair (coreExists,
  lines 847-865).
- Run by EmulationStation's BIOS screen (knulli-cfw/batocera-emulationstation
  10834d00, es-app/src/ApiSystem.cpp:764-774) and by knulli-support:69.

es_systems.yml and configgen-defaults.yml have Batocera's shape, so the cores
are read with Batocera's code. The launcher layer comes from KNULLI's own
configgen package and board scripts at the same tag (knulli_launchers):
Batocera's extractors where a generator is still Batocera's code, KNULLI's
where it is older or its own.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request

from .base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_version
from .batocera_scraper import (
    SYSTEM_SLUG_MAP as BATOCERA_SLUGS,
)
from .batocera_scraper import (
    _not_cores,
    boards_build,
    configgen_cores,
    es_systems_by_system,
    es_systems_libretro_systems,
    extract_systems_dict,
    installable_cores,
    platform_systems,
    records_run,
    requirements_from_systems,
)
from .es_emulators import attach_system_cores
from .targets.knulli_targets_scraper import Scraper as BoardTargets
from .batocera_launchers import configs_root
from .knulli_launchers import BATOCERA_SUBMODULE, extract_launchers
from .knulli_launchers import configgen as knulli_configgen

PLATFORM_NAME = "knulli"

REPO = "knulli-cfw/knulli-linux"
_RAW = "https://raw.githubusercontent.com/knulli-cfw/knulli-linux/{ref}/"
# The batocera.linux revision KNULLI's submodule pins, and its files.
_SUBMODULE = "https://api.github.com/repos/knulli-cfw/knulli-linux/contents/{path}?ref={ref}"
_BATOCERA_RAW = "https://raw.githubusercontent.com/batocera-linux/batocera.linux/{ref}/"
SOURCE_TEMPLATE = _RAW + "package/system/knulli-scripts/scripts/knulli-systems"
CONFIGGEN_DEFAULTS_TEMPLATE = (
    _RAW + "package/system/knulli-configgen/configs/configgen-defaults.yml"
)
ES_SYSTEMS_TEMPLATE = _RAW + "package/emulationstation/knulli-es-system/es_systems.yml"

# Batocera's names, plus the keys KNULLI writes that Batocera does not,
# filed under the slug the other scrapers already give them. msu-md holds the
# Mega-CD BIOS files Batocera files under megadrive-msu.
SYSTEM_SLUG_MAP = {
    **BATOCERA_SLUGS,
    "o2em": "magnavox-odyssey2",
    "msu-md": "sega-mega-cd",
    "xbox": "microsoft-xbox",
}


class Scraper(BaseScraper):
    """Scraper for KNULLI's knulli-systems."""

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

    def submodule_revision(self) -> str:
        """The batocera.linux commit KNULLI's batocera submodule pins at the tag."""
        import json  # noqa: PLC0415

        from .base_scraper import github_headers  # noqa: PLC0415

        url = _SUBMODULE.format(path=BATOCERA_SUBMODULE, ref=self.tag)
        req = urllib.request.Request(url, headers=github_headers())
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                found = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to fetch {url}: {e}") from e
        if not isinstance(found, dict) or found.get("type") != "submodule" or not found.get("sha"):
            raise RuntimeError(f"{url}: {BATOCERA_SUBMODULE} is not a submodule")
        return str(found["sha"])

    def validate_format(self, raw_data: str) -> bool:
        has_dict = re.search(r"^systems\s*=\s*\{", raw_data, re.MULTILINE) is not None
        return has_dict and "def checkBios" in raw_data and '"biosFiles"' in raw_data

    def fetch_requirements(self) -> list[BiosRequirement]:
        raw = self._fetch_raw()
        if not self.validate_format(raw):
            raise ValueError("knulli-systems format validation failed")
        return requirements_from_systems(extract_systems_dict(raw), SYSTEM_SLUG_MAP)

    def generate_platform_yaml(self) -> dict:
        systems = platform_systems(
            self.fetch_requirements(), extract_systems_dict(self._fetch_raw()), SYSTEM_SLUG_MAP
        )
        # es_systems.yml files machine selectors and plugins under an
        # emulator as Batocera's does: Batocera's list of them applies, with
        # KNULLI's own.
        defaults = self._fetch_text(CONFIGGEN_DEFAULTS_TEMPLATE.format(ref=self.tag))
        es_systems = self._fetch_text(ES_SYSTEMS_TEMPLATE.format(ref=self.tag))
        dropped = _not_cores("batocera") | _not_cores(PLATFORM_NAME)
        revision = self.submodule_revision()
        launchers = extract_launchers(
            lambda path: self._fetch_text(_RAW.format(ref=self.tag) + path),
            lambda path: self._fetch_text(_BATOCERA_RAW.format(ref=revision) + path),
        )
        # What runs is what at least one board builds, read by the targets
        # scraper from the Kconfig of KNULLI's tree and its batocera and
        # buildroot submodules (boards_build).
        selection = BoardTargets().build_selection(self.tag)
        built = boards_build(selection, launchers)
        launchers = records_run(launchers, built)
        cores, standalone, dual = configgen_cores(defaults, es_systems, dropped, built)
        installable = installable_cores(selection, cores)
        # Each system's own list (psx, es_systems.yml:640-653: libretro
        # pcsx_rearmed, swanstation, mednafen_psx, then duckstation and
        # duckstation-legacy).
        attach_system_cores(
            systems, es_systems_by_system(es_systems, defaults, dropped, built)
        )
        result = {
            "platform": "KNULLI",
            "version": self.tag,
            "homepage": "https://knulli.org",
            "source": self.url,
            "base_destination": "bios",
            "hash_type": "md5",
            "verification_mode": "md5",
            "cores": cores,
            "systems": systems,
        }
        if standalone:
            result["standalone_cores"] = standalone
        if dual:
            result["dual_mode_cores"] = dual
        if installable:
            result["installable_cores"] = installable
        # configgen hands a libretro core /userdata/saves/<system>, as
        # Batocera's does: the systems each core runs for are its save folders.
        result["libretro_systems"] = es_systems_libretro_systems(es_systems, dropped)
        result["launchers"] = launchers
        result["configs_root"] = configs_root(
            knulli_configgen(lambda path: self._fetch_text(_RAW.format(ref=self.tag) + path))
        )
        return result


def main() -> None:
    from .base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape KNULLI BIOS requirements")


if __name__ == "__main__":
    main()
