#!/usr/bin/env python3
"""Scraper for RetroBat batocera-systems.json.

Source: https://github.com/RetroBat-Official/emulatorlauncher
Format: JSON with system keys containing biosFiles arrays
Hash: MD5 primary
"""

from __future__ import annotations

import re
from pathlib import Path

from model.sourcerevision import platform_revision, required_revision
from .base_scraper import (
    BaseScraper,
    BiosRequirement,
    fetch_branch_head,
    fetch_bytes,
    fetch_github_latest_version,
    fetch_text,
    json_object,
    systems_from_requirements,
)
from .batocera_scraper import SYSTEM_SLUG_MAP as BATOCERA_SLUGS
from .es_emulators import es_cores, libretro_systems, xml_systems
from .retrobat_launchers import SOURCE_FILES as LAUNCHER_FILES
from .retrobat_launchers import extract_launchers

PLATFORM_NAME = "retrobat"
PLATFORM_FILE = Path(__file__).resolve().parents[2] / "platforms" / "retrobat.yml"

LAUNCHER_REPO = "RetroBat-Official/emulatorlauncher"
SOURCE_URL = (
    "https://raw.githubusercontent.com/RetroBat-Official/emulatorlauncher/"
    "{rev}/batocera-systems/Resources/batocera-systems.json"
)

LAUNCHER_FILE_URL = (
    "https://raw.githubusercontent.com/RetroBat-Official/emulatorlauncher/{rev}/{path}"
)

GITHUB_REPO = "RetroBat-Official/retrobat"

ES_SYSTEMS_URL = (
    "https://raw.githubusercontent.com/RetroBat-Official/retrobat/{tag}"
    "/system/templates/emulationstation/es_systems.cfg"
)


def pinned_revision(platform_file: Path = PLATFORM_FILE) -> str:
    """The emulatorLauncher commit platforms/retrobat.yml was read from.

    A rescrape reads this commit unless told to move, so a change to an
    extractor shows in the diff alone, without upstream's commits since.
    """
    return platform_revision(platform_file, LAUNCHER_REPO, commit=True)


def resolve_revision(revision: str | None) -> str:
    """The commit to read: the pin when None, a branch's head, or a sha."""
    if revision is None:
        return pinned_revision()
    if re.fullmatch(r"[0-9a-f]{40}", revision):
        return revision
    return fetch_branch_head(LAUNCHER_REPO, revision)


def fetch_launchers(rev: str) -> list[dict]:
    """Launcher records read from the generators at the commit the BIOS list comes from."""
    texts = {
        path: fetch_bytes(LAUNCHER_FILE_URL.format(rev=rev, path=path)).decode("utf-8-sig")
        for path in LAUNCHER_FILES
    }
    return extract_launchers(texts)


# RetroBat's system keys are Batocera's (its emulatorlauncher reads the same
# batocera-systems.json format): psx, nds and atari800 met no profile system
# until the two shared one map.
SYSTEM_SLUG_MAP = {
    **BATOCERA_SLUGS,
    "amiga4000": "commodore-amiga",
    "arcadia": "emerson-arcadia-2001",
    "ecwolf": "wolfenstein3d",
    "namco2x6": "namco-system246",
    "ps2": "sony-playstation-2",
    "ps3": "sony-playstation-3",
    "psvita": "sony-playstation-vita",
    "gsplus": "apple-iigs",
}


class Scraper(BaseScraper):
    """Scraper for RetroBat batocera-systems.json."""

    def __init__(self, url: str | None = None, revision: str | None = None) -> None:
        # The BIOS list and the generators are read at one commit, the one
        # platforms/retrobat.yml pins unless a revision moves it (--revision
        # master reads the branch head). The commit read is recorded.
        if url is None:
            url = SOURCE_URL.format(rev=resolve_revision(revision))
        elif revision is not None:
            raise ValueError("pass a url or a revision, not both")
        super().__init__(url=url)

    def fetch_requirements(self) -> list[BiosRequirement]:
        """Parse batocera-systems.json and return BIOS requirements."""
        raw = self._fetch_raw()

        if not self.validate_format(raw):
            raise ValueError("batocera-systems.json format validation failed")

        data = self._fetch_json()
        requirements = []

        for sys_key, sys_data in data.items():
            if not isinstance(sys_data, dict):
                continue

            bios_files = sys_data.get("biosFiles", [])
            if not isinstance(bios_files, list):
                continue

            for bios in bios_files:
                if not isinstance(bios, dict):
                    continue

                declared_path = bios.get("file", "")
                file_path = declared_path
                md5 = bios.get("md5", "")

                if not file_path:
                    continue

                # Strip bios/ prefix from file paths
                if file_path.startswith("bios/"):
                    file_path = file_path[5:]

                name = file_path.split("/")[-1] if "/" in file_path else file_path

                native: dict[str, object] = {}
                sys_name = sys_data.get("name", "") if isinstance(sys_data, dict) else ""
                if sys_name:
                    native["native_name"] = sys_name
                # One held file of a group is enough (Program.cs): verify reads it.
                if bios.get("group"):
                    native["group"] = str(bios["group"])

                requirements.append(
                    BiosRequirement(
                        name=name,
                        system=SYSTEM_SLUG_MAP.get(sys_key, sys_key),
                        md5=md5 or None,
                        destination=file_path,
                        required=not bios.get("optional", False),
                        native_id=sys_key,
                        native_path=declared_path,
                        native=native,
                    )
                )

        return requirements

    def validate_format(self, raw_data: str) -> bool:
        """Validate that raw_data is valid JSON containing biosFiles entries."""
        data = json_object(raw_data)
        if data is None:
            return False

        has_bios = False
        for sys_data in data.values():
            if isinstance(sys_data, dict) and "biosFiles" in sys_data:
                has_bios = True
                break

        return has_bios

    def generate_platform_yaml(self) -> dict:
        """Generate a platform YAML config dict from scraped data."""
        requirements = self.fetch_requirements()

        source_data = self._fetch_json()
        display_names: dict[str, str] = {}
        for sys_key, sys_data in source_data.items():
            if isinstance(sys_data, dict):
                dname = sys_data.get("name", "")
                if dname:
                    slug = SYSTEM_SLUG_MAP.get(sys_key, sys_key)
                    display_names[slug] = dname

        systems = systems_from_requirements(
            requirements,
            lambda req: {"name": display_names[req.system]} if display_names.get(req.system) else {},
        )

        version = fetch_github_latest_version(GITHUB_REPO)
        es_url = ES_SYSTEMS_URL.format(tag=version)
        es_text = fetch_text(es_url)
        # emulatorLauncher starts a libretro core by its name under
        # <emulator name="libretro">, any other emulator by its own name.
        es_systems = xml_systems(es_text)
        cores, standalone, dual = es_cores(es_systems, {"libretro": None})
        # emulatorLauncher hands a libretro core saves\\<system> at each launch
        # (LibRetro.Generator.cs Configure: savefile_directory).
        core_systems = libretro_systems(es_systems)

        return {
            "platform": "RetroBat",
            "version": version,
            "homepage": "https://www.retrobat.org",
            "source": self.url,
            "base_destination": "bios",
            "hash_type": "md5",
            "verification_mode": "md5",
            "cores": cores,
            "standalone_cores": standalone,
            # Launched both ways: each layout gets its files.
            **({"dual_mode_cores": dual} if dual else {}),
            "systems": systems,
            # The systems each libretro core runs for: its save folders.
            "libretro_systems": core_systems,
            "launchers": fetch_launchers(required_revision(self.url, LAUNCHER_REPO, commit=True)),
        }


def main() -> None:
    from scripts.scraper.base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape retrobat BIOS requirements")


if __name__ == "__main__":
    main()
