#!/usr/bin/env python3
"""Scraper for Recalbox BIOS requirements.

Source: https://gitlab.com/recalbox/recalbox/-/raw/master/board/recalbox/fsoverlay/recalbox/share_init/system/.emulationstation/es_bios.xml
Format: XML (es_bios.xml)
Hash: MD5 (multiple valid hashes per entry, comma-separated)

Recalbox verification logic:
- Checks MD5 of file on disk against list of valid hashes
- Multiple MD5s accepted per BIOS (different ROM revisions)
- Alternate file paths (pipe-separated)
- hashMatchMandatory flag: if false, wrong hash = warning (YELLOW) not error (RED)
- ZIP files get composite MD5 calculation
"""

from __future__ import annotations

import sys
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET

from .base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_tag

PLATFORM_NAME = "recalbox"

SOURCE_URL = (
    "https://gitlab.com/recalbox/recalbox/-/raw/master/"
    "board/recalbox/fsoverlay/recalbox/share_init/system/"
    ".emulationstation/es_bios.xml"
)

SYSTEM_SLUG_MAP = {
    "3do": "3do",
    "amiga600": "commodore-amiga",
    "amiga1200": "commodore-amiga",
    "amigacd32": "commodore-amiga",
    "amigacdtv": "commodore-amiga",
    "amstradcpc": "amstrad-cpc",
    "atari800": "atari-400-800",
    "atari5200": "atari-5200",
    "atari7800": "atari-7800",
    "atarilynx": "atari-lynx",
    "atarist": "atari-st",
    "c64": "commodore-c64",
    "channelf": "fairchild-channel-f",
    "colecovision": "coleco-colecovision",
    "dreamcast": "sega-dreamcast",
    "fds": "nintendo-fds",
    "gamecube": "nintendo-gamecube",
    "gamegear": "sega-game-gear",
    "gb": "nintendo-gb",
    "gba": "nintendo-gba",
    "gbc": "nintendo-gbc",
    "intellivision": "mattel-intellivision",
    "jaguar": "atari-jaguar",
    "mastersystem": "sega-master-system",
    "megadrive": "sega-mega-drive",
    "msx": "microsoft-msx",
    "msx1": "microsoft-msx",
    "msx2": "microsoft-msx",
    "n64": "nintendo-64",
    "naomi": "sega-dreamcast-arcade",
    "naomigd": "sega-dreamcast-arcade",
    "atomiswave": "sega-dreamcast-arcade",
    "nds": "nintendo-ds",
    "neogeo": "snk-neogeo",
    "neogeocd": "snk-neogeo-cd",
    "o2em": "magnavox-odyssey2",
    "pcengine": "nec-pc-engine",
    "pcenginecd": "nec-pc-engine",
    "pcfx": "nec-pc-fx",
    "ps2": "sony-playstation-2",
    "psx": "sony-playstation",
    "saturn": "sega-saturn",
    "scummvm": "scummvm",
    "segacd": "sega-mega-cd",
    "snes": "nintendo-snes",
    "supergrafx": "nec-pc-engine",
    "x68000": "sharp-x68000",
    "zxspectrum": "sinclair-zx-spectrum",
}


class Scraper(BaseScraper):
    """Scraper for Recalbox es_bios.xml."""

    def __init__(self, url: str = SOURCE_URL):
        super().__init__(url=url)

    def _fetch_cores(self) -> list[str]:
        """Extract unique core names from es_bios.xml bios elements."""
        raw = self._fetch_raw()
        root = ET.fromstring(raw)
        cores: set[str] = set()
        for bios_elem in root.findall(".//system/bios"):
            raw_core = bios_elem.get("core", "").strip()
            if not raw_core:
                continue
            for part in raw_core.split(","):
                name = part.strip()
                if name:
                    cores.add(name)
        return sorted(cores)

    def fetch_requirements(self) -> list[BiosRequirement]:
        """Parse es_bios.xml and return BIOS requirements."""
        raw = self._fetch_raw()

        if not self.validate_format(raw):
            raise ValueError("es_bios.xml format validation failed")

        root = ET.fromstring(raw)
        requirements = []
        seen = set()

        for system_elem in root.findall(".//system"):
            platform = system_elem.get("platform", "")
            system_slug = SYSTEM_SLUG_MAP.get(platform, platform)

            for bios_elem in system_elem.findall("bios"):
                paths_str = bios_elem.get("path", "")
                md5_str = bios_elem.get("md5", "")
                core = bios_elem.get("core", "")
                mandatory = bios_elem.get("mandatory", "true") != "false"
                hash_match_mandatory = bios_elem.get("hashMatchMandatory", "true") != "false"
                note = bios_elem.get("note", "")

                paths = [p.strip() for p in paths_str.split("|") if p.strip()]
                if not paths:
                    continue

                primary_path = paths[0]
                name = primary_path.split("/")[-1] if "/" in primary_path else primary_path

                md5_list = [m.strip() for m in md5_str.split(",") if m.strip()]
                all_md5 = ",".join(md5_list) if md5_list else None

                dedup_key = primary_path
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                requirements.append(BiosRequirement(
                    name=name,
                    system=system_slug,
                    md5=all_md5,
                    destination=primary_path,
                    required=mandatory,
                    native_id=platform,
                ))

        return requirements

    def fetch_full_requirements(self) -> list[dict]:
        """Parse es_bios.xml preserving all Recalbox-specific fields."""
        raw = self._fetch_raw()
        root = ET.fromstring(raw)
        requirements = []

        for system_elem in root.findall(".//system"):
            platform = system_elem.get("platform", "")
            system_name = system_elem.get("name", platform)
            system_slug = SYSTEM_SLUG_MAP.get(platform, platform)

            for bios_elem in system_elem.findall("bios"):
                paths_str = bios_elem.get("path", "")
                md5_str = bios_elem.get("md5", "")
                core = bios_elem.get("core", "")
                mandatory = bios_elem.get("mandatory", "true") != "false"
                hash_match_mandatory = bios_elem.get("hashMatchMandatory", "true") != "false"
                note = bios_elem.get("note", "")

                paths = [p.strip() for p in paths_str.split("|") if p.strip()]
                md5_list = [m.strip() for m in md5_str.split(",") if m.strip()]

                if not paths:
                    continue

                name = paths[0].split("/")[-1] if "/" in paths[0] else paths[0]

                requirements.append({
                    "name": name,
                    "system": system_slug,
                    "system_name": system_name,
                    "paths": paths,
                    "md5_list": md5_list,
                    "core": core,
                    "mandatory": mandatory,
                    "hash_match_mandatory": hash_match_mandatory,
                    "note": note,
                })

        return requirements

    def validate_format(self, raw_data: str) -> bool:
        """Validate es_bios.xml format."""
        return "<biosList" in raw_data and "<system" in raw_data and "<bios" in raw_data

    def generate_platform_yaml(self) -> dict:
        """Generate a platform YAML config dict from scraped data."""
        requirements = self.fetch_requirements()

        systems = {}
        for req in requirements:
            if req.system not in systems:
                sys_entry: dict = {"files": []}
                if req.native_id:
                    sys_entry["native_id"] = req.native_id
                systems[req.system] = sys_entry

            entry = {
                "name": req.name,
                "destination": req.destination,
                "required": req.required,
            }
            if req.md5:
                entry["md5"] = req.md5

            systems[req.system]["files"].append(entry)

        version = fetch_github_latest_tag("recalbox/recalbox", prefix="") or ""
        # Recalbox uses GitLab - GitHub API may not resolve
        if not version:
            version = "10.0"

        return {
            "platform": "Recalbox",
            "version": version,
            "homepage": "https://www.recalbox.com",
            "source": SOURCE_URL,
            "base_destination": "bios",
            "hash_type": "md5",
            "verification_mode": "md5",
            "cores": self._fetch_cores(),
            "systems": systems,
        }


def main():
    """CLI entry point."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Scrape Recalbox es_bios.xml")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--full", action="store_true", help="Show full Recalbox-specific fields")
    parser.add_argument("--output", "-o")
    args = parser.parse_args()

    scraper = Scraper()

    try:
        if args.full:
            reqs = scraper.fetch_full_requirements()
            print(json.dumps(reqs[:5], indent=2))
            print(f"\nTotal: {len(reqs)} BIOS entries")
            return
        reqs = scraper.fetch_requirements()
    except (ConnectionError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.dry_run:
        from collections import defaultdict
        by_system = defaultdict(list)
        for r in reqs:
            by_system[r.system].append(r)
        for sys_name, files in sorted(by_system.items()):
            print(f"\n{sys_name} ({len(files)} files):")
            for f in files[:5]:
                print(f"  {f.name} (md5={f.md5[:12] if f.md5 else 'N/A'}...)")
            if len(files) > 5:
                print(f"  ... +{len(files)-5} more")
        print(f"\nTotal: {len(reqs)} BIOS files across {len(by_system)} systems")
        return

    if args.json:
        config = scraper.generate_platform_yaml()
        print(json.dumps(config, indent=2))
        return

    by_system = {}
    for r in reqs:
        by_system.setdefault(r.system, []).append(r)
    print(f"Scraped {len(reqs)} BIOS files across {len(by_system)} systems")


if __name__ == "__main__":
    main()
