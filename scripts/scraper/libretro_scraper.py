#!/usr/bin/env python3
"""Scraper for libretro System.dat (RetroArch, Lakka).

Source: https://github.com/libretro/libretro-database/blob/master/dat/System.dat
Format: clrmamepro DAT
Hash: SHA1 primary
"""

from __future__ import annotations

import sys
import urllib.request
import urllib.error

from .base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_version
from .dat_parser import parse_dat, parse_dat_metadata, validate_dat_format

PLATFORM_NAME = "libretro"

SOURCE_URL = (
    "https://raw.githubusercontent.com/libretro/libretro-database/"
    "master/dat/System.dat"
)

# Libretro cores that expect BIOS files in a subdirectory of system/.
# System.dat lists filenames flat; the scraper prepends the prefix.
# ref: each core's libretro.c or equivalent — see platforms/README.md
CORE_SUBDIR_MAP = {
    "nec-pc-98": "np2kai",         # libretro-np2kai/sdl/libretro.c
    "sharp-x68000": "keropi",      # px68k/libretro/libretro.c
    "sega-dreamcast": "dc",        # flycast/shell/libretro/libretro.cpp
    "sega-dreamcast-arcade": "dc", # flycast — same subfolder
}

SYSTEM_SLUG_MAP = {
    "3DO Company, The - 3DO": "3do",
    "Amstrad - CPC": "amstrad-cpc",
    "Arcade": "arcade",
    "Atari - 400-800": "atari-400-800",
    "Atari - 5200": "atari-5200",
    "Atari - 7800": "atari-7800",
    "Atari - Lynx": "atari-lynx",
    "Atari - ST": "atari-st",
    "Coleco - ColecoVision": "coleco-colecovision",
    "Commodore - Amiga": "commodore-amiga",
    "Commodore - C128": "commodore-c128",
    "Dinothawr": "dinothawr",
    "DOS": "dos",
    "EPOCH/YENO Super Cassette Vision": "epoch-scv",
    "Elektronika - BK-0010/BK-0011(M)": "elektronika-bk",
    "Enterprise - 64/128": "enterprise-64-128",
    "Fairchild Channel F": "fairchild-channel-f",
    "Id Software - Doom": "doom",
    "J2ME": "j2me",
    "MacII": "apple-macintosh-ii",
    "Magnavox - Odyssey2": "magnavox-odyssey2",
    "Mattel - Intellivision": "mattel-intellivision",
    "Microsoft - MSX": "microsoft-msx",
    "NEC - PC Engine - TurboGrafx 16 - SuperGrafx": "nec-pc-engine",
    "NEC - PC-98": "nec-pc-98",
    "NEC - PC-FX": "nec-pc-fx",
    "Nintendo - Famicom Disk System": "nintendo-fds",
    "Nintendo - Game Boy Advance": "nintendo-gba",
    "Nintendo - GameCube": "nintendo-gamecube",
    "Nintendo - Gameboy": "nintendo-gb",
    "Nintendo - Gameboy Color": "nintendo-gbc",
    "Nintendo - Nintendo 64DD": "nintendo-64dd",
    "Nintendo - Nintendo DS": "nintendo-ds",
    "Nintendo - Nintendo Entertainment System": "nintendo-nes",
    "Nintendo - Pokemon Mini": "nintendo-pokemon-mini",
    "Nintendo - Satellaview": "nintendo-satellaview",
    "Nintendo - SuFami Turbo": "nintendo-sufami-turbo",
    "Nintendo - Super Game Boy": "nintendo-sgb",
    "Nintendo - Super Nintendo Entertainment System": "nintendo-snes",
    "Phillips - Videopac+": "philips-videopac",
    "SNK - NeoGeo CD": "snk-neogeo-cd",
    "ScummVM": "scummvm",
    "Sega - Dreamcast": "sega-dreamcast",
    "Sega - Dreamcast-based Arcade": "sega-dreamcast-arcade",
    "Sega - Game Gear": "sega-game-gear",
    "Sega - Master System - Mark III": "sega-master-system",
    "Sega - Mega CD - Sega CD": "sega-mega-cd",
    "Sega - Mega Drive - Genesis": "sega-mega-drive",
    "Sega - Saturn": "sega-saturn",
    "Sharp - X1": "sharp-x1",
    "Sharp - X68000": "sharp-x68000",
    "Sinclair - ZX Spectrum": "sinclair-zx-spectrum",
    "Sony - PlayStation": "sony-playstation",
    "Sony - PlayStation 2": "sony-playstation-2",
    "Sony - PlayStation Portable": "sony-psp",
    "Texas Instruments TI-83": "ti-83",
    "Videoton - TV Computer": "videoton-tvc",
    "Wolfenstein 3D": "wolfenstein-3d",
}


class Scraper(BaseScraper):
    """Scraper for libretro System.dat."""

    def __init__(self, url: str = SOURCE_URL):
        super().__init__(url=url)


    def fetch_requirements(self) -> list[BiosRequirement]:
        """Parse System.dat and return BIOS requirements."""
        raw = self._fetch_raw()

        if not self.validate_format(raw):
            raise ValueError("System.dat format validation failed")

        roms = parse_dat(raw)
        requirements = []

        for rom in roms:
            system_slug = SYSTEM_SLUG_MAP.get(rom.system, rom.system.lower().replace(" ", "-"))

            destination = rom.name
            name = rom.name.split("/")[-1] if "/" in rom.name else rom.name

            subdir = CORE_SUBDIR_MAP.get(system_slug)
            if subdir and not destination.startswith(subdir + "/"):
                destination = f"{subdir}/{destination}"

            requirements.append(BiosRequirement(
                name=name,
                system=system_slug,
                sha1=rom.sha1 or None,
                md5=rom.md5 or None,
                crc32=rom.crc32 or None,
                size=rom.size or None,
                destination=destination,
                required=True,
            ))

        return requirements

    def validate_format(self, raw_data: str) -> bool:
        """Validate System.dat format."""
        return validate_dat_format(raw_data)

    def fetch_metadata(self) -> dict:
        """Fetch version info from System.dat header and GitHub API."""
        raw = self._fetch_raw()
        meta = parse_dat_metadata(raw)

        retroarch_version = fetch_github_latest_version("libretro/RetroArch")
        db_version = fetch_github_latest_version("libretro/libretro-database")

        return {
            "dat_version": meta.version,
            "retroarch_version": retroarch_version,
            "db_version": db_version,
        }

    def _fetch_core_metadata(self) -> dict[str, dict]:
        """Fetch per-core metadata from libretro-core-info .info files."""
        metadata = {}
        try:
            url = f"https://api.github.com/repos/libretro/libretro-core-info/git/trees/master?recursive=1"
            req = urllib.request.Request(url, headers={
                "User-Agent": "retrobios-scraper/1.0",
                "Accept": "application/vnd.github.v3+json",
            })
            with urllib.request.urlopen(req, timeout=30) as resp:
                import json
                tree = json.loads(resp.read())

            info_files = [
                item["path"] for item in tree.get("tree", [])
                if item["path"].endswith("_libretro.info")
            ]

            for filename in info_files:
                core_name = filename.replace("_libretro.info", "")
                try:
                    info_url = f"https://raw.githubusercontent.com/libretro/libretro-core-info/master/{filename}"
                    req = urllib.request.Request(info_url, headers={"User-Agent": "retrobios-scraper/1.0"})
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        content = resp.read().decode("utf-8")

                    info = {}
                    for line in content.split("\n"):
                        line = line.strip()
                        if " = " in line:
                            key, _, value = line.partition(" = ")
                            info[key.strip()] = value.strip().strip('"')

                    fw_count = int(info.get("firmware_count", "0"))
                    if fw_count == 0:
                        continue

                    system_name = info.get("systemname", "")
                    manufacturer = info.get("manufacturer", "")
                    display_name = info.get("display_name", "")
                    categories = info.get("categories", "")

                    # Map core to our system slug via firmware paths
                    from .coreinfo_scraper import CORE_SYSTEM_MAP
                    system_slug = CORE_SYSTEM_MAP.get(core_name)
                    if not system_slug:
                        continue

                    if system_slug not in metadata:
                        metadata[system_slug] = {
                            "core": core_name,
                            "manufacturer": manufacturer,
                            "display_name": display_name or system_name,
                            "docs": f"https://docs.libretro.com/library/{core_name}/",
                        }
                except (urllib.error.URLError, urllib.error.HTTPError):
                    continue
        except (ConnectionError, ValueError, OSError):
            pass

        return metadata

    def generate_platform_yaml(self) -> dict:
        """Generate a platform YAML config dict, merging System.dat with core-info metadata."""
        requirements = self.fetch_requirements()
        metadata = self.fetch_metadata()
        core_meta = self._fetch_core_metadata()

        systems = {}
        for req in requirements:
            if req.system not in systems:
                system_entry = {"files": []}
                if req.system in core_meta:
                    cm = core_meta[req.system]
                    if cm.get("core"):
                        system_entry["core"] = cm["core"]
                    if cm.get("manufacturer"):
                        system_entry["manufacturer"] = cm["manufacturer"]
                    if cm.get("docs"):
                        system_entry["docs"] = cm["docs"]
                systems[req.system] = system_entry

            entry = {
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

        # Systems not in System.dat but needed for RetroArch — added via
        # shared groups in _shared.yml. The includes directive is resolved
        # at load time by load_platform_config().
        EXTRA_SYSTEMS = {
            "nec-pc-88": {
                "includes": ["quasi88"],
                "core": "quasi88",
                "manufacturer": "NEC",
                "docs": "https://docs.libretro.com/library/quasi88/",
            },
        }
        for sys_id, sys_data in EXTRA_SYSTEMS.items():
            if sys_id not in systems:
                systems[sys_id] = sys_data

        # Inject shared group references for systems that have core-specific
        # subdirectory requirements already defined in _shared.yml.
        SYSTEM_SHARED_GROUPS = {
            "nec-pc-98": ["np2kai"],
            "sharp-x68000": ["keropi"],
            "sega-saturn": ["kronos"],
        }
        for sys_id, groups in SYSTEM_SHARED_GROUPS.items():
            if sys_id in systems:
                systems[sys_id].setdefault("includes", []).extend(
                    g for g in groups if g not in systems[sys_id].get("includes", [])
                )

        return {
            "platform": "RetroArch",
            "version": metadata["retroarch_version"] or "",
            "dat_version": metadata["dat_version"] or "",
            "homepage": "https://www.retroarch.com",
            "source": "https://github.com/libretro/libretro-database/blob/master/dat/System.dat",
            "base_destination": "system",
            "hash_type": "sha1",
            "verification_mode": "existence",
            "systems": systems,
        }


def main():
    from scripts.scraper.base_scraper import scraper_cli
    scraper_cli(Scraper, "Scrape libretro BIOS requirements")


if __name__ == "__main__":
    main()
