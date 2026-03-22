#!/usr/bin/env python3
"""Scraper for RomM BIOS requirements.

Source: https://github.com/rommapp/romm
Format: known_bios_files.json in backend/models/fixtures/
Hash:   MD5 (primary), SHA1, CRC

RomM stores BIOS requirements in known_bios_files.json,
it contains bios files for all emulators, and is formatted as a mapping of "<console>:<bios_file>": { "size": "<size_in_bytes>", "crc": "<crc>", "md5": "<md5>", "sha1": "<sha1>" }.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    from .base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_version
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from scraper.base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_version

PLATFORM_NAME = "RomM"

BIOS_REPO = "rommapp/romm"
BIOS_BRANCH = "master"
BIOS_FILE = "backend/models/fixtures/known_bios_files.json"
BIOS_URL = (
    f"https://raw.githubusercontent.com/{BIOS_REPO}/refs/heads/{BIOS_BRANCH}/{BIOS_FILE}"
)

class Scraper(BaseScraper):
    """RomM BIOS scraper from known_bios_files.json."""

    def __init__(self, url = BIOS_URL):
        super().__init__(url)

    def fetch_metadata(self) -> dict:
        version = fetch_github_latest_version(BIOS_REPO) or "unknown"
        return {
            "name": PLATFORM_NAME,
            "version": version,
            "homepage": "https://romm.app",
            "source": self.url,
        }

    def fetch_requirements(self) -> list[BiosRequirement]:
        """Parse known_bios_files.json and return BIOS requirements."""
        raw = self._fetch_raw()

        if not self.validate_format(raw):
            raise ValueError("known_bios_files.json format validation failed")

        roms = json.loads(raw)
        requirements = []

        for key, info in roms.items():
            if ":" not in key:
                continue
            system, name = key.split(":", 1)
            requirements.append(BiosRequirement(
                name=name,
                system=system,
                size=int(info.get("size", 0)),
                crc32=info.get("crc"),
                md5=info.get("md5"),
                sha1=info.get("sha1"),
            ))

        return requirements

    def validate_format(self, raw_data: str) -> bool:
        """Validate that the raw data is a JSON object with the expected structure."""
        try:
            data = json.loads(raw_data)
            if not isinstance(data, dict):
                return False
            for key, value in data.items():
                if ":" not in key or not isinstance(value, dict):
                    return False
                if not all(k in value for k in ("size", "crc", "md5", "sha1")):
                    return False
            return True
        except json.JSONDecodeError:
            return False

    def generate_platform_yaml(self) -> dict:
        """Generate platform YAML content for RomM."""
        requirements = self.fetch_requirements()
        metadata = self.fetch_metadata()

        systems: dict[str, dict] = {}
        for req in requirements:
            if req.system not in systems:
                systems[req.system] = {"files": []}

            entry: dict = {
                "name": req.name,
                "destination": f"{req.system}/{req.name}",
                "size": req.size,
                "crc": req.crc32,
                "md5": req.md5,
                "sha1": req.sha1,
            }

            systems[req.system]["files"].append(entry)

        return {
            "platform": metadata["name"],
            "version": metadata["version"],
            "homepage": metadata["homepage"],
            "source": metadata["source"],
            "base_destination": "bios",
            "hash_type": "md5",
            "verification_mode": "md5",
            "cores": [],
            "systems": systems,
        }

def main():
    try:
        from .base_scraper import scraper_cli
    except ImportError:
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from scraper.base_scraper import scraper_cli
    scraper_cli(Scraper, "Scrape RomM BIOS requirements")

if __name__ == "__main__":
    main()