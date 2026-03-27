#!/usr/bin/env python3
"""Scraper for EmuDeck BIOS requirements.

Sources:
  1. checkBIOS.sh - MD5 hash whitelists per system
     https://raw.githubusercontent.com/dragoonDorise/EmuDeck/main/functions/checkBIOS.sh
  2. CSV cheat sheets - BIOS filenames per manufacturer
     https://raw.githubusercontent.com/EmuDeck/emudeck.github.io/main/docs/tables/{name}-cheat-sheet.csv
Hash: MD5 primary
"""

from __future__ import annotations

import csv
import io
import re
import sys
import urllib.request
import urllib.error

try:
    from .base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_version
except ImportError:
    from base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_version

PLATFORM_NAME = "emudeck"

CHECKBIOS_URL = (
    "https://raw.githubusercontent.com/dragoonDorise/EmuDeck/"
    "main/functions/checkBIOS.sh"
)

CSV_BASE_URL = (
    "https://raw.githubusercontent.com/EmuDeck/emudeck.github.io/"
    "main/docs/tables"
)

CSV_SHEETS = [
    "sony-cheat-sheet.csv",
    "sega-cheat-sheet.csv",
    "nintendo-cheat-sheet.csv",
    "snk-cheat-sheet.csv",
    "panasonic-cheat-sheet.csv",
    "nec-cheat-sheet.csv",
    "microsoft-cheat-sheet.csv",
    "coleco-cheat-sheet.csv",
    "atari-cheat-sheet.csv",
    "bandai-cheat-sheet.csv",
    "mattel-cheat-sheet.csv",
]

HASH_ARRAY_MAP = {
    "PSBios": "sony-playstation",
    "PS2Bios": "sony-playstation-2",
    "CDBios": "sega-mega-cd",
    "SaturnBios": "sega-saturn",
}

FUNCTION_HASH_MAP = {
    "checkDreamcastBios": "sega-dreamcast",
    "checkDSBios": "nintendo-ds",
}

SYSTEM_SLUG_MAP = {
    "psx": "sony-playstation",
    "ps2": "sony-playstation-2",
    "ps3": "sony-playstation-3",
    "psp": "sony-psp",
    "psvita": "sony-psvita",
    "segacd": "sega-mega-cd",
    "megacd": "sega-mega-cd",
    "saturn": "sega-saturn",
    "dreamcast": "sega-dreamcast",
    "sega32x": "sega-32x",
    "mastersystem": "sega-master-system",
    "genesis": "sega-mega-drive",
    "megadrive": "sega-mega-drive",
    "gamegear": "sega-game-gear",
    "naomi": "sega-dreamcast-arcade",
    "naomi2": "sega-dreamcast-arcade",
    "atomiswave": "sega-dreamcast-arcade",
    "nds": "nintendo-ds",
    "3ds": "nintendo-3ds",
    "n3ds": "nintendo-3ds",
    "n64": "nintendo-64",
    "n64dd": "nintendo-64dd",
    "gc": "nintendo-gamecube",
    "gamecube": "nintendo-gamecube",
    "wii": "nintendo-wii",
    "wiiu": "nintendo-wii-u",
    "switch": "nintendo-switch",
    "nes": "nintendo-nes",
    "famicom": "nintendo-nes",
    "snes": "nintendo-snes",
    "gb": "nintendo-gb",
    "gba": "nintendo-gba",
    "gbc": "nintendo-gbc",
    "virtualboy": "nintendo-virtual-boy",
    "fbneo": "snk-neogeo",
    "neogeocd": "snk-neogeo-cd",
    "neogeocdjp": "snk-neogeo-cd",
    "ngp": "snk-neogeo-pocket",
    "ngpc": "snk-neogeo-pocket-color",
    "3do": "panasonic-3do",
    "pcengine": "nec-pc-engine",
    "pcenginecd": "nec-pc-engine",
    "pcfx": "nec-pc-fx",
    "pc88": "nec-pc-88",
    "pc98": "nec-pc-98",
    "colecovision": "coleco-colecovision",
}

KNOWN_BIOS_FILES = {
    "sony-playstation": [
        {"name": "scph5500.bin", "destination": "scph5500.bin", "region": "JP"},
        {"name": "scph5501.bin", "destination": "scph5501.bin", "region": "US"},
        {"name": "scph5502.bin", "destination": "scph5502.bin", "region": "EU"},
    ],
    "sony-playstation-2": [
        {"name": "SCPH-70004_BIOS_V12_EUR_200.BIN", "destination": "SCPH-70004_BIOS_V12_EUR_200.BIN"},
        {"name": "SCPH-70004_BIOS_V12_EUR_200.EROM", "destination": "SCPH-70004_BIOS_V12_EUR_200.EROM"},
        {"name": "SCPH-70004_BIOS_V12_EUR_200.ROM1", "destination": "SCPH-70004_BIOS_V12_EUR_200.ROM1"},
        {"name": "SCPH-70004_BIOS_V12_EUR_200.ROM2", "destination": "SCPH-70004_BIOS_V12_EUR_200.ROM2"},
    ],
    "sega-mega-cd": [
        {"name": "bios_CD_E.bin", "destination": "bios_CD_E.bin", "region": "EU"},
        {"name": "bios_CD_U.bin", "destination": "bios_CD_U.bin", "region": "US"},
        {"name": "bios_CD_J.bin", "destination": "bios_CD_J.bin", "region": "JP"},
    ],
    "sega-saturn": [
        {"name": "sega_101.bin", "destination": "sega_101.bin", "region": "JP"},
        {"name": "mpr-17933.bin", "destination": "mpr-17933.bin", "region": "US/EU"},
        {"name": "saturn_bios.bin", "destination": "saturn_bios.bin"},
    ],
    "sega-dreamcast": [
        {"name": "dc_boot.bin", "destination": "dc/dc_boot.bin"},
        {"name": "dc_flash.bin", "destination": "dc/dc_flash.bin"},
    ],
    "nintendo-ds": [
        {"name": "bios7.bin", "destination": "bios7.bin"},
        {"name": "bios9.bin", "destination": "bios9.bin"},
        {"name": "firmware.bin", "destination": "firmware.bin"},
    ],
    "snk-neogeo": [
        {"name": "neogeo.zip", "destination": "neogeo.zip"},
        {"name": "neocdz.zip", "destination": "neocdz.zip"},
    ],
    "panasonic-3do": [
        {"name": "panafz1.bin", "destination": "panafz1.bin"},
    ],
    "nintendo-nes": [
        {"name": "disksys.rom", "destination": "disksys.rom"},
    ],
    "sega-dreamcast-arcade": [
        {"name": "naomi.zip", "destination": "dc/naomi.zip"},
    ],
}

_RE_ARRAY = re.compile(
    r'(?:local\s+)?(\w+)=\(\s*((?:[0-9a-fA-F]+\s*)+)\)',
    re.MULTILINE,
)

_RE_FUNC = re.compile(
    r'function\s+(check\w+Bios)\s*\(\)',
    re.MULTILINE,
)

_RE_LOCAL_HASHES = re.compile(
    r'local\s+hashes=\(\s*((?:[0-9a-fA-F]+\s*)+)\)',
    re.MULTILINE,
)


def _fetch_url(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "retrobios-scraper/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.URLError as e:
        raise ConnectionError(f"Failed to fetch {url}: {e}") from e


class Scraper(BaseScraper):
    """Scraper for EmuDeck checkBIOS.sh and CSV cheat sheets."""

    def __init__(self, checkbios_url: str = CHECKBIOS_URL, csv_base_url: str = CSV_BASE_URL):
        super().__init__(url=checkbios_url)
        self.checkbios_url = checkbios_url
        self.csv_base_url = csv_base_url
        self._raw_script: str | None = None
        self._csv_cache: dict[str, str] = {}

    def _fetch_script(self) -> str:
        if self._raw_script is not None:
            return self._raw_script
        self._raw_script = _fetch_url(self.checkbios_url)
        return self._raw_script

    def _fetch_csv(self, sheet: str) -> str:
        if sheet in self._csv_cache:
            return self._csv_cache[sheet]
        url = f"{self.csv_base_url}/{sheet}"
        try:
            data = _fetch_url(url)
        except ConnectionError:
            data = ""
        self._csv_cache[sheet] = data
        return data

    def _parse_hash_arrays(self, script: str) -> dict[str, list[str]]:
        """Extract named MD5 hash arrays from bash script."""
        result: dict[str, list[str]] = {}
        for match in _RE_ARRAY.finditer(script):
            name = match.group(1)
            hashes_raw = match.group(2)
            hashes = [h.strip() for h in hashes_raw.split() if h.strip()]
            if name in HASH_ARRAY_MAP:
                result[HASH_ARRAY_MAP[name]] = hashes
        return result

    def _parse_function_hashes(self, script: str) -> dict[str, list[str]]:
        """Extract local hash arrays from named check functions."""
        result: dict[str, list[str]] = {}
        for func_match in _RE_FUNC.finditer(script):
            func_name = func_match.group(1)
            if func_name not in FUNCTION_HASH_MAP:
                continue
            system = FUNCTION_HASH_MAP[func_name]
            func_start = func_match.start()
            next_func = _RE_FUNC.search(script, func_match.end())
            func_end = next_func.start() if next_func else len(script)
            func_body = script[func_start:func_end]
            local_match = _RE_LOCAL_HASHES.search(func_body)
            if local_match:
                hashes_raw = local_match.group(1)
                hashes = [h.strip() for h in hashes_raw.split() if h.strip()]
                result[system] = hashes
        return result

    @staticmethod
    def _clean_markdown(text: str) -> str:
        """Strip markdown/HTML artifacts from CSV fields."""
        text = re.sub(r'\*\*', '', text)  # bold
        text = re.sub(r':material-[^:]+:\{[^}]*\}', '', text)  # mkdocs material icons
        text = re.sub(r':material-[^:]+:', '', text)
        text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)  # [text](url) -> text
        text = re.sub(r'<br\s*/?>', ' ', text)  # <br/>
        text = re.sub(r'<[^>]+>', '', text)  # remaining HTML
        return text.strip()

    def _parse_csv_bios(self, csv_text: str) -> list[dict]:
        """Parse BIOS file info from a cheat sheet CSV."""
        entries = []
        if not csv_text.strip():
            return entries
        reader = csv.DictReader(io.StringIO(csv_text))
        for row in reader:
            bios_col = ""
            for key in row:
                if key and "bios" in key.lower():
                    bios_col = self._clean_markdown((row[key] or ""))
                    break
            if not bios_col or bios_col.lower() in ("not required", ""):
                continue
            folder_col = ""
            for key in row:
                if key and "folder" in key.lower():
                    folder_col = self._clean_markdown((row[key] or ""))
                    break
            system_col = ""
            for key in row:
                if key and "system" in key.lower():
                    system_col = self._clean_markdown((row[key] or ""))
                    break
            slug = None
            for part in re.split(r'[`\s]+', folder_col):
                part = part.strip().strip('`').lower()
                if part and part in SYSTEM_SLUG_MAP:
                    slug = SYSTEM_SLUG_MAP[part]
                    break
            if not slug:
                clean = re.sub(r'[^a-z0-9\-]', '', folder_col.strip().strip('`').lower())
                slug = clean if clean else "unknown"
            entries.append({
                "system": slug,
                "system_name": system_col,
                "bios_raw": bios_col,
            })
        return entries

    def _extract_filenames_from_bios_field(self, bios_raw: str) -> list[dict]:
        """Extract individual BIOS filenames from a CSV BIOS field."""
        results = []
        bios_raw = re.sub(r'<br\s*/?>', ' ', bios_raw)
        bios_raw = bios_raw.replace('`', '')
        patterns = re.findall(
            r'[\w\-./]+\.(?:bin|rom|zip|BIN|ROM|ZIP|EROM|ROM1|ROM2|n64|txt|keys)',
            bios_raw,
        )
        for p in patterns:
            name = p.split("/")[-1] if "/" in p else p
            results.append({"name": name, "destination": p})
        return results

    def fetch_requirements(self) -> list[BiosRequirement]:
        script = self._fetch_script()
        if not self.validate_format(script):
            raise ValueError("checkBIOS.sh format validation failed")

        hash_arrays = self._parse_hash_arrays(script)
        func_hashes = self._parse_function_hashes(script)
        all_hashes: dict[str, list[str]] = {}
        all_hashes.update(hash_arrays)
        all_hashes.update(func_hashes)

        requirements: list[BiosRequirement] = []
        seen: set[tuple[str, str]] = set()

        for system, file_list in KNOWN_BIOS_FILES.items():
            system_hashes = all_hashes.get(system, [])
            for f in file_list:
                key = (system, f["name"])
                if key in seen:
                    continue
                seen.add(key)
                requirements.append(BiosRequirement(
                    name=f["name"],
                    system=system,
                    destination=f.get("destination", f["name"]),
                    required=True,
                ))

            for md5 in system_hashes:
                requirements.append(BiosRequirement(
                    name=f"{system}:{md5}",
                    system=system,
                    md5=md5,
                    destination="",
                    required=True,
                ))

        for sheet in CSV_SHEETS:
            csv_text = self._fetch_csv(sheet)
            entries = self._parse_csv_bios(csv_text)
            for entry in entries:
                system = entry["system"]
                files = self._extract_filenames_from_bios_field(entry["bios_raw"])
                for f in files:
                    key = (system, f["name"])
                    if key in seen:
                        continue
                    seen.add(key)
                    if system in KNOWN_BIOS_FILES:
                        continue
                    requirements.append(BiosRequirement(
                        name=f["name"],
                        system=system,
                        destination=f.get("destination", f["name"]),
                        required=True,
                    ))

        return requirements

    def validate_format(self, raw_data: str) -> bool:
        has_ps = "PSBios=" in raw_data or "PSBios =" in raw_data
        has_func = "checkPS1BIOS" in raw_data or "checkPS2BIOS" in raw_data
        has_md5 = re.search(r'[0-9a-f]{32}', raw_data) is not None
        return has_ps and has_func and has_md5

    def generate_platform_yaml(self) -> dict:
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
            if req.md5:
                entry["md5"] = req.md5
            systems[req.system]["files"].append(entry)

        version = ""
        try:
            v = fetch_github_latest_version("dragoonDorise/EmuDeck")
            if v:
                version = v
        except (ConnectionError, ValueError, OSError):
            pass

        cores = self._fetch_installed_emulators()

        return {
            "platform": "EmuDeck",
            "version": version or "",
            "homepage": "https://www.emudeck.com",
            "source": CHECKBIOS_URL,
            "base_destination": "bios",
            "hash_type": "md5",
            "verification_mode": "md5",
            "cores": cores,
            "systems": systems,
        }

    def _fetch_installed_emulators(self) -> list[str]:
        """Fetch the list of emulators installed by EmuDeck from EmuScripts.

        Returns core names normalized to match emulator profile keys.
        """
        import json

        api_url = (
            "https://api.github.com/repos/dragoonDorise/EmuDeck/"
            "contents/functions/EmuScripts"
        )
        name_overrides = {
            "pcsx2qt": "pcsx2", "rpcs3legacy": "rpcs3",
            "cemuproton": "cemu", "rmg": "mupen64plus_next",
        }
        skip = {"retroarch_maincfg", "retroarch"}

        try:
            req = urllib.request.Request(
                api_url, headers={"User-Agent": "retrobios-scraper/1.0"},
            )
            data = json.loads(urllib.request.urlopen(req, timeout=30).read())
        except (urllib.error.URLError, OSError):
            return []

        cores: list[str] = []
        seen: set[str] = set()
        for entry in data:
            name = entry.get("name", "")
            if not name.endswith(".sh"):
                continue
            name = re.sub(r"\.sh$", "", name)
            name = re.sub(r"^emuDeck", "", name, flags=re.IGNORECASE)
            if not name:
                continue
            key = name.lower()
            if key in skip:
                continue
            core = name_overrides.get(key, key)
            if core not in seen:
                seen.add(core)
                cores.append(core)
        return sorted(cores)


def main():
    from scripts.scraper.base_scraper import scraper_cli
    scraper_cli(Scraper, "Scrape emudeck BIOS requirements")


if __name__ == "__main__":
    main()
