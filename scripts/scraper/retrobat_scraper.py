#!/usr/bin/env python3
"""Scraper for RetroBat batocera-systems.json.

Source: https://github.com/RetroBat-Official/emulatorlauncher
Format: JSON with system keys containing biosFiles arrays
Hash: MD5 primary
"""

from __future__ import annotations

import json

try:
    from .base_scraper import (
        BaseScraper,
        BiosRequirement,
        fetch_github_latest_version,
        requirement_entry,
    )
except ImportError:
    from base_scraper import (
        BaseScraper,
        BiosRequirement,
        fetch_github_latest_version,
        requirement_entry,
    )

PLATFORM_NAME = "retrobat"

SOURCE_URL = (
    "https://raw.githubusercontent.com/RetroBat-Official/emulatorlauncher/"
    "master/batocera-systems/Resources/batocera-systems.json"
)

GITHUB_REPO = "RetroBat-Official/retrobat"

# Map RetroBat system keys to our normalized system IDs
SYSTEM_SLUG_MAP = {
    "ps2": "sony-playstation-2",
    "ps3": "sony-playstation-3",
    "psvita": "sony-playstation-vita",
    "gsplus": "apple-iigs",
}


class Scraper(BaseScraper):
    """Scraper for RetroBat batocera-systems.json."""

    def __init__(self, url: str = SOURCE_URL):
        super().__init__(url=url)
        self._parsed: dict | None = None

    def _parse_json(self) -> dict:
        if self._parsed is not None:
            return self._parsed

        raw = self._fetch_raw()
        try:
            self._parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON: {e}") from e
        return self._parsed

    def fetch_requirements(self) -> list[BiosRequirement]:
        """Parse batocera-systems.json and return BIOS requirements."""
        raw = self._fetch_raw()

        if not self.validate_format(raw):
            raise ValueError("batocera-systems.json format validation failed")

        data = self._parse_json()
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

                requirements.append(
                    BiosRequirement(
                        name=name,
                        system=SYSTEM_SLUG_MAP.get(sys_key, sys_key),
                        md5=md5 or None,
                        destination=file_path,
                        required=True,
                        native_id=sys_key,
                        native_path=declared_path,
                        native=native,
                    )
                )

        return requirements

    def validate_format(self, raw_data: str) -> bool:
        """Validate that raw_data is valid JSON containing biosFiles entries."""
        try:
            data = json.loads(raw_data)
        except (json.JSONDecodeError, TypeError):
            return False

        if not isinstance(data, dict):
            return False

        has_bios = False
        for sys_key, sys_data in data.items():
            if isinstance(sys_data, dict) and "biosFiles" in sys_data:
                has_bios = True
                break

        return has_bios

    def generate_platform_yaml(self) -> dict:
        """Generate a platform YAML config dict from scraped data."""
        requirements = self.fetch_requirements()

        # Parse source to extract display names per system
        raw = self._fetch_raw()
        source_data = json.loads(raw)
        display_names: dict[str, str] = {}
        for sys_key, sys_data in source_data.items():
            if isinstance(sys_data, dict):
                dname = sys_data.get("name", "")
                if dname:
                    slug = SYSTEM_SLUG_MAP.get(sys_key, sys_key)
                    display_names[slug] = dname

        systems = {}
        for req in requirements:
            if req.system not in systems:
                sys_entry: dict = {"files": []}
                dname = display_names.get(req.system)
                if dname:
                    sys_entry["name"] = dname
                systems[req.system] = sys_entry

            systems[req.system]["files"].append(requirement_entry(req))

        version = ""
        tag = fetch_github_latest_version(GITHUB_REPO)
        if tag:
            version = tag

        return {
            "platform": "RetroBat",
            "version": version,
            "homepage": "https://www.retrobat.org",
            "source": SOURCE_URL,
            "base_destination": "bios",
            "hash_type": "md5",
            "verification_mode": "md5",
            "systems": systems,
        }


def main():
    from scripts.scraper.base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape retrobat BIOS requirements")


if __name__ == "__main__":
    main()
