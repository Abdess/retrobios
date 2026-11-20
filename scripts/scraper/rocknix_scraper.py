#!/usr/bin/env python3
"""Scraper for ROCKNIX BIOS requirements.

Source: projects/ROCKNIX/packages/rocknix/sources/scripts/rocknix-systems
Format: Python source, a `systems` mapping of per-system BIOS declarations
Hash: MD5

ROCKNIX verification logic (rocknix-systems, checkBios):
- md5sum() of the file on disk against the declared md5
- checkInsideZip() when zippedFile is set, with an optional altmd5
- an empty md5 means the check is presence only

EmulationStation surfaces the result through ApiSystem::getBiosInformations,
which shells out to `rocknix-systems` (es-app/src/ApiSystem.cpp:486-516).
"""
from __future__ import annotations

from typing import ClassVar

from .batocera_scraper import CheckBiosScraper
from model.sourcerevision import required_revision
from .base_scraper import (
    fetch_github_latest_version,
    fetch_text,
    github_json,
)
from .rocknix_launchers import extract_launchers
from scraper.shell_launchers import RepoTree
from .rocknix_packages import dual_mode_emulators, standalone_emulators
from .targets.rocknix_targets_scraper import Scraper as DeviceTargets

PLATFORM_NAME = "rocknix"

GITHUB_REPO = "ROCKNIX/distribution"

SOURCE_TEMPLATE = (
    "https://raw.githubusercontent.com/ROCKNIX/distribution/{ref}/"
    "projects/ROCKNIX/packages/rocknix/sources/scripts/rocknix-systems"
)
# The branch a test or a manual run can still name. A scrape reads the tag
# of the release its YAML is labelled with.
SOURCE_URL = SOURCE_TEMPLATE.format(ref="next")
EMULATORS_MK_URL = (
    "https://raw.githubusercontent.com/ROCKNIX/distribution/{ref}"
    "/projects/ROCKNIX/packages/virtual/emulators/package.mk"
)
STANDALONE_TREE_URL = (
    "https://api.github.com/repos/ROCKNIX/distribution/contents/"
    "projects/ROCKNIX/packages/emulators/standalone?ref={ref}"
)


# ROCKNIX system key -> retrobios system ID
SYSTEM_SLUG_MAP = {
    "xbox": "microsoft-xbox",
    "gamecube": "nintendo-gamecube",
    "nds": "nintendo-ds",
    "gb": "nintendo-gb",
    "gba": "nintendo-gba",
    "gbc": "nintendo-gbc",
    "dreamcast": "sega-dreamcast",
    "gamegear": "sega-game-gear",
    "mastersystem": "sega-master-system",
    "segacd": "sega-mega-cd",
    "saturn": "sega-saturn",
    "psx": "sony-playstation",
    "ps2": "sony-playstation-2",
    "ps3": "sony-playstation-3",
    "psp": "sony-psp",
    "3do": "3do",
    "amiga": "commodore-amiga",
    "atari5200": "atari-5200",
    "atari7800": "atari-7800",
    "atarilynx": "atari-lynx",
    "colecovision": "coleco-colecovision",
    "intellivision": "mattel-intellivision",
    "msx": "microsoft-msx",
    "neogeo": "snk-neogeo",
    "neogeocd": "snk-neogeo-cd",
    "pcengine": "nec-pc-engine",
    "pcenginecd": "nec-pc-engine-cd",
    "x68000": "sharp-x68000",
    "zxspectrum": "sinclair-zx-spectrum",
}

class Scraper(CheckBiosScraper):
    """Scraper for the ROCKNIX rocknix-systems script, read like batocera-systems."""

    slug_map: ClassVar[dict[str, str]] = SYSTEM_SLUG_MAP
    list_name: ClassVar[str] = "rocknix-systems"

    def __init__(self, url: str | None = None) -> None:
        self.tag = None if url else fetch_github_latest_version(GITHUB_REPO)
        super().__init__(url=url or SOURCE_TEMPLATE.format(ref=self.tag))

    def _built_cores(self, standalone: list[str]) -> tuple[list[str], list[str]]:
        """(cores, standalone cores) at least one device image carries.

        RetroArch runs the libretro cores the packages of its emulators
        metapackage install per device
        (projects/ROCKNIX/packages/virtual/emulators/package.mk), read by
        the targets scraper, where every libretro profile counted before. A
        standalone package no device carries is not run either.
        """
        builds = DeviceTargets().device_builds(self.tag or required_revision(self.url, GITHUB_REPO))
        libretro = sorted({core for _arch, lr, _sa in builds.values() for core in lr})
        carried = set(standalone_emulators(sorted({p for *_rest, sa in builds.values() for p in sa})))
        standalone = [name for name in standalone if name in carried]
        return sorted({*libretro, *standalone}), standalone

    def _fetch_standalone(self) -> list[str]:
        """The packages of projects/ROCKNIX/packages/emulators/standalone."""
        url = STANDALONE_TREE_URL.format(ref=self.tag or "next")
        listing = github_json(url, f"Failed to list {url}", timeout=30, error=ConnectionError)
        packages = [item["name"] for item in listing if item.get("type") == "dir"]
        if not packages:
            raise RuntimeError(f"no standalone emulator package at {url}")
        return standalone_emulators(packages)

    def _fetch_emulators_mk(self) -> str:
        """The package.mk that adds each emulator and core to es_systems."""
        url = EMULATORS_MK_URL.format(ref=self.tag or "next")
        text = fetch_text(url)
        if "add_emu_core" not in text:
            raise RuntimeError(f"no add_emu_core line in {url}")
        return text

    def generate_platform_yaml(self) -> dict:
        """Build the ROCKNIX platform configuration."""
        cores, standalone = self._built_cores(self._fetch_standalone())
        return {
            "platform": "ROCKNIX",
            "version": self.tag or fetch_github_latest_version(GITHUB_REPO),
            "homepage": "https://rocknix.org",
            "source": self.url,
            "base_destination": "bios",
            "hash_type": "md5",
            "verification_mode": "md5",
            "cores": cores,
            "standalone_cores": standalone,
            # Launched both ways only where package.mk also adds the
            # emulator as a RetroArch core.
            "dual_mode_cores": dual_mode_emulators(standalone, self._fetch_emulators_mk()),
            "systems": self.platform_systems(),
            # Read at the revision the BIOS list comes from.
            "launchers": extract_launchers(
                RepoTree.github(GITHUB_REPO, required_revision(self.url, GITHUB_REPO))
            ),
        }


def main() -> None:
    """Entry point."""
    from .base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape ROCKNIX BIOS requirements")


if __name__ == "__main__":
    main()
