#!/usr/bin/env python3
"""Scraper for MiSTer FPGA BIOS requirements.

Source: ajgowans/BiosDB_MiSTer, branch db, file bios_db.json.zip
Format: MiSTer Downloader database (JSON inside a ZIP)
Hash: MD5

MiSTer verification logic (MiSTer-devel/Downloader_MiSTer):
- file_system.py:705-712, hash_file() is a plain MD5 of the file bytes
- jobs/process_db_index_worker.py:216, an installed file is up to date when
  its MD5 equals the description hash
- jobs/process_db_index_worker.py:242, integrity checks compare MD5 only;
  the declared size is logged on failure but never gates the result
- jobs/fetch_file_worker.py:61-65, a freshly downloaded file is rejected on
  MD5 mismatch

The database carries no required/optional flag: every entry is installed
unless the user sets a tag filter, which defaults to empty (config.py:161).
Entries reached through the archives section (UniBIOS) are extracted from a
remote ZIP and carry the hash of the extracted member, not of the archive.
"""
from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone

try:
    from .base_scraper import (
        BaseScraper,
        BiosRequirement,
        _read_limited,
        requirement_entry,
    )
except ImportError:
    from base_scraper import (
        BaseScraper,
        BiosRequirement,
        _read_limited,
        requirement_entry,
    )

PLATFORM_NAME = "misterfpga"

SOURCE_URL = (
    "https://raw.githubusercontent.com/ajgowans/BiosDB_MiSTer/db/bios_db.json.zip"
)

DB_MEMBER = "bios_db.json"

# Files live under games/ on the SD card; base_destination carries that prefix
DB_ROOT = "games/"

# MiSTer core folder -> (retrobios system ID, display name, core repository)
SYSTEM_MAP = {
    "3DO": ("3do", "3DO Interactive Multiplayer", "3DO_MiSTer"),
    "Apple-IIgs": ("apple-iigs", "Apple IIGS", "Apple-IIgs_MiSTer"),
    "Astrocade": ("bally-astrocade", "Bally Astrocade", "Astrocade_MiSTer"),
    "AtariLynx": ("atari-lynx", "Atari Lynx", "AtariLynx_MiSTer"),
    "CD-i": ("philips-cdi", "Philips CD-i", "CDi_MiSTer"),
    "COCO3": ("tandy-coco", "Tandy Color Computer 3", "CoCo3_MiSTer"),
    "Casio_PV-2000": ("casio-pv2000", "Casio PV-2000", "Casio_PV-2000_MiSTer"),
    "CreatiVision": ("creativision", "VTech CreatiVision", "CreatiVision_MiSTer"),
    "GAMEBOY": ("nintendo-gb", "Game Boy / Game Boy Color", "Gameboy_MiSTer"),
    "GBA": ("nintendo-gba", "Game Boy Advance", "GBA_MiSTer"),
    "Gamate": ("gamate", "Bit Corporation Gamate", "Gamate_MiSTer"),
    "GameCom": ("tiger-game-com", "Tiger Game.com", ""),
    "Intellivision": ("mattel-intellivision", "Mattel Intellivision", "Intv_MiSTer"),
    "Interact": ("interact", "Interact Home Computer", "Interact_MiSTer"),
    "Jaguar": ("atari-jaguar", "Atari Jaguar", "Jaguar_MiSTer"),
    "MSX1": ("microsoft-msx", "MSX1", "MSX1_MiSTer"),
    "MegaCD": ("sega-mega-cd", "Sega CD / Mega-CD", "MegaCD_MiSTer"),
    "N64": ("nintendo-64", "Nintendo 64", "N64_MiSTer"),
    "NEOGEO": ("snk-neogeo", "Neo Geo AES / MVS", "NeoGeo_MiSTer"),
    "NES": ("nintendo-nes", "NES / Famicom Disk System", "NES_MiSTer"),
    "NeoGeo-CD": ("snk-neogeo-cd", "Neo Geo CD", "NeoGeo_MiSTer"),
    "NeoGeoPocket": ("snk-neogeo-pocket", "Neo Geo Pocket", ""),
    "PC8801": ("nec-pc-88", "NEC PC-8801", "PC88_MiSTer"),
    "PSX": ("sony-playstation", "Sony PlayStation", "PSX_MiSTer"),
    "PocketChallengeV2": (
        "pocket-challenge-v2",
        "Benesse Pocket Challenge V2",
        "WonderSwan_MiSTer",
    ),
    "PokemonMini": ("nintendo-pokemon-mini", "Pokemon Mini", "PokemonMini_MiSTer"),
    "SCV": ("epoch-scv", "Epoch Super Cassette Vision", "SuperCassetteVision_MiSTer"),
    "SGB": ("nintendo-sgb", "Super Game Boy", "SGB_MiSTer"),
    "SNES": ("nintendo-snes", "Super NES / Super Famicom", "SNES_MiSTer"),
    "Saturn": ("sega-saturn", "Sega Saturn", "Saturn_MiSTer"),
    "TGFX16-CD": ("nec-pc-engine-cd", "PC Engine CD / TurboGrafx-CD", "TurboGrafx16_MiSTer"),
    "TI-99_4A": ("ti99", "Texas Instruments TI-99/4A", "TI-99_4A_MiSTer"),
    "WonderSwan": ("wonderswan", "Bandai WonderSwan", "WonderSwan_MiSTer"),
    "WonderSwanColor": (
        "wonderswan-color",
        "Bandai WonderSwan Color",
        "WonderSwan_MiSTer",
    ),
}


def parse_db(raw: str) -> dict[str, dict]:
    """Return every installable file entry of the database, keyed by path.

    Entries listed under archives are inlined: the Downloader extracts them
    from a remote ZIP, and their hash describes the extracted member.
    """
    data = json.loads(raw)
    entries: dict[str, dict] = dict(data.get("files", {}))
    for archive in data.get("archives", {}).values():
        inline = archive.get("summary_inline", {}).get("files", {})
        entries.update(inline)
    if not entries:
        raise ValueError("no file entries found in bios_db.json")
    return entries


def system_of(path: str) -> str:
    """Return the core folder a database path belongs to."""
    remainder = path[len(DB_ROOT):] if path.startswith(DB_ROOT) else path
    return remainder.split("/", 1)[0]


class Scraper(BaseScraper):
    """Scraper for the MiSTer BiosDB database."""

    def __init__(self, url: str = SOURCE_URL):
        super().__init__(url=url)

    def _fetch_raw(self) -> str:
        """Fetch bios_db.json.zip and return the JSON it contains."""
        if self._raw_data is not None:
            return self._raw_data
        req = urllib.request.Request(
            self.url, headers={"User-Agent": "retrobios-scraper/1.0"}
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = _read_limited(resp)
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to fetch {self.url}: {e}") from e
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            self._raw_data = archive.read(DB_MEMBER).decode("utf-8")
        return self._raw_data

    def validate_format(self, raw_data: str) -> bool:
        """Validate the BiosDB database format."""
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError:
            return False
        if data.get("db_id") != "bios_db":
            return False
        files = data.get("files")
        if not isinstance(files, dict) or not files:
            return False
        return all(
            isinstance(entry.get("hash"), str) and isinstance(entry.get("size"), int)
            for entry in files.values()
        )

    def fetch_requirements(self) -> list[BiosRequirement]:
        """Parse bios_db.json and return BIOS requirements."""
        raw = self._fetch_raw()
        if not self.validate_format(raw):
            raise ValueError("bios_db.json format validation failed")

        requirements = []
        for path, entry in sorted(parse_db(raw).items()):
            folder = system_of(path)
            system, _, _ = SYSTEM_MAP.get(folder, (folder.lower(), folder, ""))
            destination = path[len(DB_ROOT):] if path.startswith(DB_ROOT) else path
            requirements.append(
                BiosRequirement(
                    name=destination.rsplit("/", 1)[-1],
                    system=system,
                    md5=entry["hash"],
                    size=entry.get("size"),
                    destination=destination,
                    required=True,
                    native_id=folder,
                )
            )
        return requirements

    def generate_platform_yaml(self) -> dict:
        """Build the MiSTer FPGA platform configuration."""
        data = json.loads(self._fetch_raw())
        systems: dict[str, dict] = {}

        for req in self.fetch_requirements():
            _, display, repo = SYSTEM_MAP.get(
                req.native_id or "", (req.system, req.system, "")
            )
            entry = systems.setdefault(
                req.system,
                {
                    "files": [],
                    "native_id": req.native_id,
                    "name": display,
                    "docs": f"https://github.com/MiSTer-devel/{repo}" if repo else "",
                },
            )
            entry["files"].append(requirement_entry(req))

        for entry in systems.values():
            if not entry["docs"]:
                del entry["docs"]

        timestamp = data.get("timestamp")
        released = (
            datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d")
            if isinstance(timestamp, (int, float))
            else ""
        )

        return {
            "platform": "MiSTer FPGA",
            "version": released,
            "homepage": "https://misterfpga.org",
            "source": SOURCE_URL,
            "base_destination": "games",
            "hash_type": "md5",
            "verification_mode": "md5",
            "cores": [],
            "systems": dict(sorted(systems.items())),
        }


def main() -> None:
    """Entry point."""
    try:
        from .base_scraper import scraper_cli
    except ImportError:
        from base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape MiSTer FPGA BIOS requirements")


if __name__ == "__main__":
    main()
