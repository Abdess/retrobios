#!/usr/bin/env python3
"""Scraper for libretro-core-info firmware declarations.

Source: https://github.com/libretro/libretro-core-info
Format: .info files with firmware0_path, firmware0_desc, firmware0_opt patterns
Hash: From notes field (MD5) or cross-referenced with System.dat

Complements libretro_scraper (System.dat) with:
- Exact firmware paths per core
- Required vs optional status
- Firmware for cores not covered by System.dat
"""

from __future__ import annotations

import re
import sys
import urllib.request
import urllib.error
import json

try:
    from .base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_version
except ImportError:
    # Allow running directly: python scripts/scraper/coreinfo_scraper.py
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from scraper.base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_version

PLATFORM_NAME = "libretro_coreinfo"

GITHUB_API = "https://api.github.com/repos/libretro/libretro-core-info"
RAW_BASE = "https://raw.githubusercontent.com/libretro/libretro-core-info/master"

CORE_SYSTEM_MAP = {
    "pcsx_rearmed": "sony-playstation",
    "mednafen_psx": "sony-playstation",
    "mednafen_psx_hw": "sony-playstation",
    "swanstation": "sony-playstation",
    "duckstation": "sony-playstation",
    "pcsx1": "sony-playstation",
    "lrps2": "sony-playstation-2",
    "play": "sony-playstation-2",
    "ppsspp": "sony-psp",
    "fbneo": "arcade",
    "mame": "arcade",
    "mame2003": "arcade",
    "mame2003_plus": "arcade",
    "dolphin": "nintendo-gamecube",
    "melonds": "nintendo-ds",
    "melonds_ds": "nintendo-ds",
    "desmume": "nintendo-ds",
    "mgba": "nintendo-gba",
    "vba_next": "nintendo-gba",
    "gpsp": "nintendo-gba",
    "gambatte": "nintendo-gb",
    "sameboy": "nintendo-gb",
    "gearboy": "nintendo-gb",
    "bsnes": "nintendo-snes",
    "snes9x": "nintendo-snes",
    "higan_sfc": "nintendo-snes",
    "mesen-s": "nintendo-snes",
    "nestopia": "nintendo-nes",
    "fceumm": "nintendo-nes",
    "mesen": "nintendo-nes",
    "mupen64plus_next": "nintendo-64",
    "parallel_n64": "nintendo-64",
    "flycast": "sega-dreamcast",
    "reicast": "sega-dreamcast",
    "kronos": "sega-saturn",
    "mednafen_saturn": "sega-saturn",
    "yabause": "sega-saturn",
    "genesis_plus_gx": "sega-mega-drive",
    "picodrive": "sega-mega-drive",
    "mednafen_pce": "nec-pc-engine",
    "mednafen_pce_fast": "nec-pc-engine",
    "mednafen_pcfx": "nec-pc-fx",
    "mednafen_ngp": "snk-neogeo-pocket",
    "mednafen_lynx": "atari-lynx",
    "handy": "atari-lynx",
    "hatari": "atari-st",
    "puae": "commodore-amiga",
    "fuse": "sinclair-zx-spectrum",
    "dosbox_pure": "dos",
    "dosbox_svn": "dos",
    "scummvm": "scummvm",
    "opera": "3do",
    "4do": "3do",
    "ep128emu": "enterprise-64-128",
    "freej2me": "j2me",
    "squirreljme": "j2me",
    "numero": "ti-83",
    "neocd": "snk-neogeo-cd",
    "vice_x64": "commodore-c64",
    "vice_x128": "commodore-c128",
    "cap32": "amstrad-cpc",
    "o2em": "magnavox-odyssey2",
    "vecx": "vectrex",
    "virtualjaguar": "atari-jaguar",
    "prosystem": "atari-7800",
    "stella": "atari-2600",
    "a5200": "atari-5200",
    "bluemsx": "microsoft-msx",
    "fmsx": "microsoft-msx",
    "px68k": "sharp-x68000",
    "x1": "sharp-x1",
    "quasi88": "nec-pc-88",
    "np2kai": "nec-pc-98",
    "theodore": "thomson",
    "81": "sinclair-zx81",
    "crocods": "amstrad-cpc",
    "dinothawr": "dinothawr",
}


def _parse_info_file(content: str) -> dict:
    """Parse a .info file into a dictionary."""
    result = {}
    for line in content.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r'^(\w+)\s*=\s*"?(.*?)"?\s*$', line)
        if match:
            key, value = match.group(1), match.group(2)
            result[key] = value
    return result


_SKIP_EXTENSIONS = {".dll", ".so", ".dylib", ".exe", ".bat", ".sh"}
_DIRECTORY_MARKERS = {"folder", "directory", "dir"}


def _is_directory_ref(path: str, desc: str) -> bool:
    """Check if a firmware entry is a directory reference rather than a file."""
    if "." not in path.split("/")[-1]:
        return True
    desc_lower = desc.lower()
    return any(marker in desc_lower for marker in _DIRECTORY_MARKERS)


def _is_native_lib(path: str) -> bool:
    """Check if path is a native library (.dll, .so, .dylib) - not a BIOS."""
    ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
    return ext.lower() in _SKIP_EXTENSIONS


def _extract_firmware(info: dict) -> list[dict]:
    """Extract firmware entries, filtering out directories and native libraries."""
    count_str = info.get("firmware_count", "0")
    try:
        count = int(count_str)
    except ValueError:
        return []

    firmware = []
    for i in range(count):
        path = info.get(f"firmware{i}_path", "")
        desc = info.get(f"firmware{i}_desc", "")
        opt = info.get(f"firmware{i}_opt", "false")

        if not path:
            continue

        if _is_directory_ref(path, desc):
            continue

        if _is_native_lib(path):
            continue

        firmware.append({
            "path": path,
            "desc": desc,
            "optional": opt.lower() == "true",
        })

    return firmware


def _extract_md5_from_notes(info: dict) -> dict[str, str]:
    """Extract MD5 hashes from the notes field."""
    notes = info.get("notes", "")
    md5_map = {}

    for match in re.finditer(r'\(!\)\s+(.+?)\s+\(md5\):\s+([a-f0-9]{32})', notes):
        filename = match.group(1).strip()
        md5 = match.group(2)
        md5_map[filename] = md5

    return md5_map


class Scraper(BaseScraper):
    """Scraper for libretro-core-info firmware declarations."""

    def __init__(self):
        self._info_files: dict[str, dict] | None = None

    def _fetch_info_list(self) -> list[str]:
        """Fetch list of all .info files from GitHub API."""
        # Use the tree API to get all files at once
        url = f"{GITHUB_API}/git/trees/master?recursive=1"
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "retrobios-scraper/1.0",
                "Accept": "application/vnd.github.v3+json",
            })
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())

            return [
                item["path"] for item in data.get("tree", [])
                if item["path"].endswith("_libretro.info")
            ]
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            raise ConnectionError(f"Failed to list core-info files: {e}") from e

    def _fetch_info_file(self, filename: str) -> dict:
        """Fetch and parse a single .info file."""
        url = f"{RAW_BASE}/{filename}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "retrobios-scraper/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read().decode("utf-8")
            return _parse_info_file(content)
        except (urllib.error.URLError, urllib.error.HTTPError):
            return {}

    def fetch_requirements(self) -> list[BiosRequirement]:
        """Fetch firmware requirements from all core .info files."""
        info_files = self._fetch_info_list()
        requirements = []
        seen = set()

        for filename in info_files:
            info = self._fetch_info_file(filename)
            firmware_list = _extract_firmware(info)

            if not firmware_list:
                continue

            core_name = filename.replace("_libretro.info", "")
            system = CORE_SYSTEM_MAP.get(core_name, core_name)

            md5_map = _extract_md5_from_notes(info)

            for fw in firmware_list:
                path = fw["path"]
                if path in seen:
                    continue
                seen.add(path)

                basename = path.split("/")[-1] if "/" in path else path
                # Full path when basename is generic to avoid SGB1.sfc/program.rom vs SGB2.sfc/program.rom collisions
                GENERIC_NAMES = {"program.rom", "data.rom", "boot.rom", "bios.bin", "firmware.bin"}
                name = path if basename.lower() in GENERIC_NAMES else basename
                md5 = md5_map.get(basename)

                requirements.append(BiosRequirement(
                    name=name,
                    system=system,
                    md5=md5,
                    destination=path,
                    required=not fw["optional"],
                ))

        return requirements

    def validate_format(self, raw_data: str) -> bool:
        """Validate .info file format."""
        return "firmware_count" in raw_data or "display_name" in raw_data

    def fetch_metadata(self) -> dict:
        """Fetch version info from GitHub."""
        version = fetch_github_latest_version("libretro/libretro-core-info")
        return {"version": version or ""}


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Scrape libretro-core-info firmware requirements")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--compare-db", help="Compare against database.json")
    args = parser.parse_args()

    scraper = Scraper()

    try:
        reqs = scraper.fetch_requirements()
    except ConnectionError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.compare_db:
        import json as _json
        with open(args.compare_db) as f:
            db = _json.load(f)

        found = 0
        missing = []
        for r in reqs:
            if r.name in db["indexes"]["by_name"]:
                found += 1
            elif r.md5 and r.md5 in db["indexes"]["by_md5"]:
                found += 1
            else:
                missing.append(r)

        print(f"Core-info: {len(reqs)} unique firmware paths")
        print(f"Found in DB: {found}")
        print(f"Missing: {len(missing)}")
        if missing:
            print("\nMissing files:")
            for r in sorted(missing, key=lambda x: x.system):
                opt = "(optional)" if not r.required else "(REQUIRED)"
                print(f"  {r.system}: {r.destination} {opt}")
        return

    from collections import defaultdict
    by_system = defaultdict(list)
    for r in reqs:
        by_system[r.system].append(r)

    print(f"Total: {len(reqs)} unique firmware paths across {len(by_system)} systems")
    for sys_name, files in sorted(by_system.items()):
        req_count = sum(1 for f in files if f.required)
        opt_count = sum(1 for f in files if not f.required)
        print(f"  {sys_name}: {req_count} required, {opt_count} optional")


if __name__ == "__main__":
    main()
