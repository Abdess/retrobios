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

import re

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

PLATFORM_NAME = "rocknix"

GITHUB_REPO = "ROCKNIX/distribution"

SOURCE_URL = (
    "https://raw.githubusercontent.com/ROCKNIX/distribution/next/"
    "projects/ROCKNIX/packages/rocknix/sources/scripts/rocknix-systems"
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

_SYSTEM_HEADER = re.compile(
    r'"(?P<key>[\w\-]+)"\s*:\s*\{\s*"name"\s*:\s*"(?P<name>[^"]+)"\s*,'
    r'\s*"biosFiles"\s*:\s*\[',
)
_FIELD = re.compile(r'"(\w+)"\s*:\s*"([^"]*)"')


def _slice_bios_block(source: str, start: int) -> tuple[str, int]:
    """Return the biosFiles list body starting at an opening bracket."""
    depth = 0
    for i in range(start, len(source)):
        char = source[i]
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return source[start + 1:i], i
    raise ValueError("unterminated biosFiles list")


def parse_systems(source: str) -> dict[str, dict]:
    """Extract per-system BIOS declarations from the rocknix-systems source.

    Parsed textually rather than evaluated: the file is upstream code, and
    the declarations are plain string literals.
    """
    source = re.sub(r"#[^\n]*", "", source)
    systems: dict[str, dict] = {}

    for header in _SYSTEM_HEADER.finditer(source):
        body, _ = _slice_bios_block(source, header.end() - 1)
        files = []
        for raw_entry in re.findall(r"\{[^{}]*\}", body):
            fields = dict(_FIELD.findall(raw_entry))
            if fields.get("file"):
                files.append(fields)
        systems[header.group("key")] = {
            "name": header.group("name"),
            "biosFiles": files,
        }

    if not systems:
        raise ValueError("no system declarations found in rocknix-systems")
    return systems


class Scraper(BaseScraper):
    """Scraper for the ROCKNIX rocknix-systems script."""

    def __init__(self, url: str = SOURCE_URL):
        super().__init__(url=url)

    def validate_format(self, raw_data: str) -> bool:
        """Validate the rocknix-systems format."""
        has_dict = re.search(r"^systems\s*=\s*\{", raw_data, re.MULTILINE) is not None
        has_check = "def checkBios" in raw_data
        return has_dict and has_check and '"biosFiles"' in raw_data and '"md5"' in raw_data

    def fetch_requirements(self) -> list[BiosRequirement]:
        """Parse rocknix-systems and return BIOS requirements."""
        if not self.validate_format(self._fetch_raw()):
            raise ValueError("rocknix-systems format validation failed")
        requirements = []

        for key, entry in parse_systems(self._fetch_raw()).items():
            system_slug = SYSTEM_SLUG_MAP.get(key, key)
            for bios in entry["biosFiles"]:
                path = bios["file"]
                # Declared paths are relative to the storage root: strip the
                # leading bios/ so destinations match base_destination
                destination = path[len("bios/"):] if path.startswith("bios/") else path
                req = BiosRequirement(
                    name=destination.rsplit("/", 1)[-1],
                    system=system_slug,
                    md5=bios.get("md5", "") or None,
                    alt_md5=bios.get("altmd5", "") or None,
                    destination=destination,
                    required=True,
                    native_id=key,
                    native={"native_name": entry["name"]},
                )
                if bios.get("zippedFile"):
                    req.zipped_file = bios["zippedFile"]
                requirements.append(req)

        return requirements

    def generate_platform_yaml(self) -> dict:
        """Build the ROCKNIX platform configuration."""
        raw = parse_systems(self._fetch_raw())
        names = {key: entry["name"] for key, entry in raw.items()}
        systems: dict[str, dict] = {}

        for req in self.fetch_requirements():
            entry = systems.setdefault(
                req.system,
                {
                    "files": [],
                    "native_id": req.native_id,
                    "name": names.get(req.native_id, req.system),
                },
            )
            entry["files"].append(requirement_entry(req))

        return {
            "platform": "ROCKNIX",
            "version": fetch_github_latest_version(GITHUB_REPO) or "",
            "homepage": "https://rocknix.org",
            "source": SOURCE_URL,
            "base_destination": "bios",
            "hash_type": "md5",
            "verification_mode": "md5",
            "cores": "all_libretro",
            "systems": systems,
        }


def main() -> None:
    """Entry point."""
    try:
        from .base_scraper import scraper_cli
    except ImportError:
        from base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape ROCKNIX BIOS requirements")


if __name__ == "__main__":
    main()
