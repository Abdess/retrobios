#!/usr/bin/env python3
"""Scraper for RomM BIOS requirements.

Source: https://github.com/rommapp/romm
Format: JSON fixture mapping "slug:filename" to {size, crc, md5, sha1}
Hash: SHA1 primary (all four hashes available per entry)

RomM stores known BIOS hashes in known_bios_files.json. At startup, the
fixture is loaded into Redis. When scanning or uploading firmware, RomM
verifies: file size must match AND at least one hash (MD5, SHA1, CRC32)
must match (firmware.py:verify_file_hashes).

RomM hashes files as opaque blobs (no ZIP content inspection). Arcade
BIOS ZIPs are matched by their container hash, which varies by MAME
version and ZIP tool. This is a known limitation (rommapp/romm#2888).

Folder structure: {library}/bios/{platform_slug}/{filename} (flat).
Slugs are IGDB-style platform identifiers.
"""

from __future__ import annotations

import json
import sys

try:
    from .base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_version
except ImportError:
    from base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_version

PLATFORM_NAME = "romm"

SOURCE_URL = (
    "https://raw.githubusercontent.com/rommapp/romm/"
    "master/backend/models/fixtures/known_bios_files.json"
)

GITHUB_REPO = "rommapp/romm"

# IGDB slug -> retrobios system ID
SLUG_MAP: dict[str, str] = {
    "3do": "3do",
    "64dd": "nintendo-64dd",
    "acpc": "amstrad-cpc",
    "amiga": "commodore-amiga",
    "arcade": "arcade",
    "atari-st": "atari-st",
    "atari5200": "atari-5200",
    "atari7800": "atari-7800",
    "atari8bit": "atari-400-800",
    "colecovision": "coleco-colecovision",
    "dc": "sega-dreamcast",
    "doom": "doom",
    "enterprise": "enterprise-64-128",
    "fairchild-channel-f": "fairchild-channel-f",
    "fds": "nintendo-fds",
    "gamegear": "sega-game-gear",
    "gb": "nintendo-gb",
    "gba": "nintendo-gba",
    "gbc": "nintendo-gbc",
    "genesis": "sega-mega-drive",
    "intellivision": "mattel-intellivision",
    "j2me": "j2me",
    "lynx": "atari-lynx",
    "mac": "apple-macintosh-ii",
    "msx": "microsoft-msx",
    "msx2": "microsoft-msx",
    "nds": "nintendo-ds",
    "neo-geo-cd": "snk-neogeo-cd",
    "nes": "nintendo-nes",
    "ngc": "nintendo-gamecube",
    "odyssey-2-slash-videopac-g7000": "magnavox-odyssey2",
    "pc-9800-series": "nec-pc-98",
    "pc-fx": "nec-pc-fx",
    "pokemon-mini": "nintendo-pokemon-mini",
    "ps2": "sony-playstation-2",
    "psp": "sony-psp",
    "psx": "sony-playstation",
    "satellaview": "nintendo-satellaview",
    "saturn": "sega-saturn",
    "scummvm": "scummvm",
    "segacd": "sega-mega-cd",
    "sharp-x68000": "sharp-x68000",
    "sms": "sega-master-system",
    "snes": "nintendo-snes",
    "sufami-turbo": "nintendo-sufami-turbo",
    "super-gb": "nintendo-sgb",
    "tg16": "nec-pc-engine",
    "tvc": "videoton-tvc",
    "videopac-g7400": "philips-videopac",
    "wolfenstein": "wolfenstein-3d",
    "x1": "sharp-x1",
    "xbox": "microsoft-xbox",
    "zxs": "sinclair-zx-spectrum",
}


class Scraper(BaseScraper):
    """Scraper for RomM known_bios_files.json."""

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
        """Parse known_bios_files.json and return BIOS requirements."""
        raw = self._fetch_raw()

        if not self.validate_format(raw):
            raise ValueError("known_bios_files.json format validation failed")

        data = self._parse_json()
        requirements = []

        for key, entry in data.items():
            if ":" not in key:
                continue

            igdb_slug, filename = key.split(":", 1)
            system = SLUG_MAP.get(igdb_slug)
            if not system:
                print(f"Warning: unmapped IGDB slug '{igdb_slug}'", file=sys.stderr)
                continue

            sha1 = (entry.get("sha1") or "").strip() or None
            md5 = (entry.get("md5") or "").strip() or None
            crc32 = (entry.get("crc") or "").strip() or None
            size = int(entry["size"]) if entry.get("size") else None

            requirements.append(BiosRequirement(
                name=filename,
                system=system,
                sha1=sha1,
                md5=md5,
                crc32=crc32,
                size=size,
                destination=f"{igdb_slug}/{filename}",
                required=True,
            ))

        return requirements

    def validate_format(self, raw_data: str) -> bool:
        """Validate that raw_data is a JSON dict with slug:filename keys."""
        try:
            data = json.loads(raw_data)
        except (json.JSONDecodeError, TypeError):
            return False

        if not isinstance(data, dict):
            return False

        for key in list(data.keys())[:5]:
            if ":" not in key:
                return False
            _, entry = key.split(":", 1), data[key]
            if not isinstance(data[key], dict):
                return False
            if "md5" not in data[key] and "sha1" not in data[key]:
                return False

        return len(data) > 0

    def generate_platform_yaml(self) -> dict:
        """Generate a platform YAML config dict from scraped data."""
        requirements = self.fetch_requirements()

        systems: dict[str, dict] = {}
        for req in requirements:
            if req.system not in systems:
                systems[req.system] = {"files": []}

            entry: dict = {
                "name": req.name,
                "destination": req.destination,
                "required": req.required,
            }
            if req.sha1:
                entry["sha1"] = req.sha1
            if req.md5:
                entry["md5"] = req.md5
            if req.crc32:
                entry["crc32"] = req.crc32
            if req.size:
                entry["size"] = req.size

            systems[req.system]["files"].append(entry)

        version = ""
        tag = fetch_github_latest_version(GITHUB_REPO)
        if tag:
            version = tag

        return {
            "inherits": "emulatorjs",
            "platform": "RomM",
            "version": version,
            "homepage": "https://romm.app",
            "source": SOURCE_URL,
            "base_destination": "bios",
            "hash_type": "sha1",
            "verification_mode": "md5",
            "systems": systems,
        }


def main():
    from scripts.scraper.base_scraper import scraper_cli
    scraper_cli(Scraper, "Scrape RomM BIOS requirements")


if __name__ == "__main__":
    main()
