#!/usr/bin/env python3
"""Scraper for RomM BIOS requirements.

Platform contributed by @PixNyb (#37).

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
import re
import sys

from .base_scraper import (
    BaseScraper,
    BiosRequirement,
    fetch_bytes,
    fetch_github_latest_version,
    requirement_entry,
)

PLATFORM_NAME = "romm"

GITHUB_REPO = "rommapp/romm"

SOURCE_URL = (
    "https://raw.githubusercontent.com/rommapp/romm/{tag}"
    "/backend/models/fixtures/known_bios_files.json"
)

# The player's core table. _EJS_CORES_MAP is what EmulatorJS 4.2.3 runs, and
# _EJS_NIGHTLY_CORES_MAP adds the nightly cores RomM merges in when netplay is
# enabled (getSupportedEJSCores). Both are cores RomM can launch, so the pack
# carries what either needs: azahar, bsnes and genesis_plus_gx_wide exist only
# in the nightly map.
CORES_URL = (
    "https://raw.githubusercontent.com/rommapp/romm/{tag}"
    "/frontend/src/utils/index.ts"
)
CORE_MAPS = ("_EJS_CORES_MAP", "_EJS_NIGHTLY_CORES_MAP")


def parse_player_cores(source: str) -> list[str]:
    """Every core named by the player's core maps, sorted.

    A map missing from the file, or one naming no core, means the source has
    changed shape: that raises instead of publishing a shorter list.
    """
    cores: set[str] = set()
    for name in CORE_MAPS:
        match = re.search(
            rf"const {name}\b[^=]*=\s*\{{(.*?)^\}}", source, re.S | re.M
        )
        if match is None:
            raise RuntimeError(f"{name} not found in the RomM player source")
        found = set(re.findall(r"\[([^\]]*)\]", match.group(1)))
        named = {
            core
            for values in found
            for core in re.findall(r'"([A-Za-z0-9_]+)"', values)
        }
        if not named:
            raise RuntimeError(f"{name} names no core")
        cores |= named
    return sorted(cores)

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
    "neogeoaes": "snk-neogeo-aes",
    "neogeomvs": "snk-neogeo-mvs",
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
    "turbografx-cd": "nec-pc-engine-cd",
    "tvc": "videoton-tvc",
    "videopac-g7400": "philips-videopac",
    "wolfenstein": "wolfenstein-3d",
    "x1": "sharp-x1",
    "xbox": "microsoft-xbox",
    "zxs": "sinclair-zx-spectrum",
}


# Slugs whose player runs the same core as another slug and reads firmware
# from its own folder. RomM keys the fixture by tg16 only, but its player maps
# both tg16 and turbografx-cd to mednafen_pce (frontend/src/utils/index.ts:481-482)
# and lists firmware per platform folder (backend/handler/filesystem/
# firmware_handler.py get_firmware_fs_structure), so a CD library without the
# system cards under its own slug cannot boot a disc.
#
# Mirrors are per file, not per core: a slug sharing a core with another reads
# only the firmware that core needs for its own system. The Neo Geo slugs run
# fbneo, as arcade does (index.ts:410-418), and fbneo boots every Neo Geo
# game from neogeo.zip, but the fixture gives it to arcade alone. None mirrors
# every file of the slug.
FIRMWARE_MIRRORS: dict[str, dict[str, tuple[str, ...] | None]] = {
    "tg16": {"turbografx-cd": None},
    "arcade": {"neogeoaes": ("neogeo.zip",), "neogeomvs": ("neogeo.zip",)},
}


class Scraper(BaseScraper):
    """Scraper for RomM known_bios_files.json."""

    def __init__(self) -> None:
        self.tag = fetch_github_latest_version(GITHUB_REPO)
        super().__init__(url=SOURCE_URL.format(tag=self.tag))
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

            mirrors = [
                slug
                for slug, names in FIRMWARE_MIRRORS.get(igdb_slug, {}).items()
                if names is None or filename in names
            ]
            for slug in (igdb_slug, *mirrors):
                requirements.append(
                    BiosRequirement(
                        name=filename,
                        system=SLUG_MAP[slug],
                        sha1=sha1,
                        md5=md5,
                        crc32=crc32,
                        size=size,
                        destination=f"{slug}/{filename}",
                        required=True,
                        native_id=slug,
                        mirror_of=None if slug == igdb_slug else igdb_slug,
                    )
                )

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

            systems[req.system]["files"].append(requirement_entry(req))

        return {
            "inherits": "emulatorjs",
            "platform": "RomM",
            "version": self.tag,
            "homepage": "https://romm.app",
            "source": self.url,
            "base_destination": "bios",
            "hash_type": "sha1",
            "verification_mode": "md5",
            # Firmware.verify_file_hashes: size, then md5, sha1 or crc.
            "hash_rule": "size_and_any_hash",
            "cores": parse_player_cores(
                fetch_bytes(CORES_URL.format(tag=self.tag)).decode("utf-8")
            ),
            "systems": systems,
        }


def main() -> None:
    from scripts.scraper.base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape RomM BIOS requirements")


if __name__ == "__main__":
    main()
