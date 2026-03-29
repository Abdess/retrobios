#!/usr/bin/env python3
"""Scraper for BizHawk BIOS requirements.

Source: https://github.com/TASEmulators/BizHawk
Format: C# source (FirmwareDatabase.cs)
Hash: SHA1 primary

BizHawk declares firmware in FirmwareDatabase.cs using four patterns:
  File(sha1, size, name, desc, isBad?)        - file definition
  Firmware(system, id, desc)                   - firmware slot declaration
  Option(system, id, in fileref, status?)      - binds file to slot
  FirmwareAndOption(sha1, size, sys, id, ...)  - combined one-liner

Variable assignments (var x = File(...)) let Option() reference files
by name. Multiple options per firmware slot are ranked by status;
the Ideal non-bad option is selected as canonical.
"""

from __future__ import annotations

import re
import sys

try:
    from .base_scraper import (
        BaseScraper,
        BiosRequirement,
        fetch_github_latest_tag,
        scraper_cli,
    )
except ImportError:
    from base_scraper import (
        BaseScraper,
        BiosRequirement,
        fetch_github_latest_tag,
        scraper_cli,
    )

PLATFORM_NAME = "bizhawk"

SOURCE_URL = (
    "https://raw.githubusercontent.com/TASEmulators/BizHawk/"
    "master/src/BizHawk.Emulation.Common/Database/FirmwareDatabase.cs"
)

GITHUB_REPO = "TASEmulators/BizHawk"

STATUS_RANK = {
    "Bad": 0,
    "Unacceptable": 1,
    "Unknown": 2,
    "Acceptable": 3,
    "Ideal": 4,
}

GAME_DATA_SYSTEMS = {"BSX", "Doom"}
GAME_DATA_FILES = {"VEC_Minestorm.vec"}

SYSTEM_ID_MAP: dict[str, str] = {
    "32X": "sega-32x",
    "3DO": "3do",
    "3DS": "nintendo-3ds",
    "A26": "atari-2600",
    "A78": "atari-7800",
    "Amiga": "commodore-amiga",
    "AmstradCPC": "amstrad-cpc",
    "AppleII": "apple-ii",
    "BSX": "nintendo-satellaview",
    "C64": "commodore-c64",
    "ChannelF": "fairchild-channel-f",
    "Coleco": "coleco-colecovision",
    "Doom": "doom",
    "DS": "nintendo-ds",
    "FDS": "nintendo-fds",
    "G7400": "philips-videopac-plus",
    "GB": "nintendo-gb",
    "GBA": "nintendo-gba",
    "GBC": "nintendo-gbc",
    "GEN": "sega-mega-drive",
    "GG": "sega-game-gear",
    "GGL": "sega-game-gear",
    "INTV": "mattel-intellivision",
    "Jaguar": "atari-jaguar",
    "Lynx": "atari-lynx",
    "MAME": "arcade",
    "MSX": "microsoft-msx",
    "N64": "nintendo-64",
    "N64DD": "nintendo-64dd",
    "NDS": "nintendo-ds",
    "NES": "nintendo-nes",
    "NGP": "snk-neo-geo-pocket",
    "O2": "philips-videopac",
    "PCECD": "nec-pc-engine-cd",
    "PCFX": "nec-pc-fx",
    "PS2": "sony-playstation-2",
    "PSX": "sony-playstation",
    "SAT": "sega-saturn",
    "SGB": "nintendo-super-game-boy",
    "SGX": "nec-supergrafx",
    "SMS": "sega-master-system",
    "SNES": "nintendo-snes",
    "TI83": "texas-instruments-ti-83",
    "UZE": "uzebox",
    "VEC": "gce-vectrex",
    "WSWAN": "bandai-wonderswan",
    "ZXSpectrum": "sinclair-zx-spectrum",
}

# Cores that overlap with BizHawk's system coverage
BIZHAWK_CORES = [
    "gambatte", "mgba", "sameboy", "melonds", "snes9x", "bsnes",
    "beetle_psx", "beetle_saturn", "beetle_pce", "beetle_pcfx",
    "beetle_wswan", "beetle_vb", "beetle_ngp", "opera", "stella",
    "picodrive", "ppsspp", "handy", "quicknes", "genesis_plus_gx",
    "ares", "mupen64plus_next", "puae", "prboom", "virtualjaguar",
    "vice_x64", "mame",
]


def _safe_arithmetic(expr: str) -> int:
    """Compute simple integer arithmetic (+ and *) without code execution.

    Handles: plain integers, multiplication chains (4 * 1024 * 1024),
    addition of products (128 + 64 * 1024).
    """
    expr = expr.strip()
    total = 0
    for addend in expr.split("+"):
        factors = addend.strip().split("*")
        product = 1
        for f in factors:
            product *= int(f.strip())
        total += product
    return total


def _strip_comments(source: str) -> str:
    """Remove block comments and #if false blocks."""
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    source = re.sub(
        r"#if\s+false\b.*?#endif", "", source, flags=re.DOTALL
    )
    return source


def parse_firmware_database(
    source: str,
) -> tuple[list[dict], dict[str, dict]]:
    """Parse BizHawk FirmwareDatabase.cs source into firmware records.

    Returns (records, files_by_hash) where each record is a dict with keys:
        system, firmware_id, sha1, name, size, description, status
    """
    source = _strip_comments(source)

    # ── Pass 1: collect File() definitions ────────────────────────
    files_by_hash: dict[str, dict] = {}
    var_to_hash: dict[str, str] = {}

    file_re = re.compile(
        r'(?:var\s+(\w+)\s*=\s*)?'
        r'File\(\s*'
        r'(?:"([A-Fa-f0-9]+)"|SHA1Checksum\.Dummy)\s*,\s*'
        r'([^,]+?)\s*,\s*'
        r'"([^"]+)"\s*,\s*'
        r'"([^"]*)"'
        r'(?:\s*,\s*isBad:\s*(true|false))?'
        r'\s*\)'
    )

    for m in file_re.finditer(source):
        var_name = m.group(1)
        sha1 = m.group(2)  # None for SHA1Checksum.Dummy
        size_expr = m.group(3)
        name = m.group(4)
        desc = m.group(5)
        is_bad = m.group(6) == "true"

        size = _safe_arithmetic(size_expr)
        file_entry = {
            "sha1": sha1,
            "size": size,
            "name": name,
            "description": desc,
            "is_bad": is_bad,
        }

        key = sha1 if sha1 else f"dummy_{name}"
        files_by_hash[key] = file_entry
        if var_name:
            var_to_hash[var_name] = key

    # ── Pass 2: collect firmware slots and options ────────────────

    # FirmwareAndOption one-liner
    fao_re = re.compile(
        r'FirmwareAndOption\(\s*'
        r'(?:"([A-Fa-f0-9]+)"|SHA1Checksum\.Dummy)\s*,\s*'
        r'([^,]+?)\s*,\s*'
        r'"([^"]+)"\s*,\s*'
        r'"([^"]+)"\s*,\s*'
        r'"([^"]+)"\s*,\s*'
        r'"([^"]*)"'
        r'(?:\s*,\s*FirmwareOptionStatus\.(\w+))?'
        r'\s*\)'
    )

    # Firmware(system, id, desc)
    firmware_re = re.compile(
        r'Firmware\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]*)"\s*\)'
    )

    # Option(system, id, in varref|File(...), status?)
    option_re = re.compile(
        r'Option\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*'
        r'(?:in\s+(\w+)'
        r'|File\(\s*"([A-Fa-f0-9]+)"\s*,\s*([^,]+?)\s*,\s*"([^"]+)"\s*,\s*"([^"]*)"\s*\))'
        r'(?:\s*,\s*FirmwareOptionStatus\.(\w+))?'
        r'\s*\)'
    )

    # Collect firmware slots
    firmware_slots: dict[tuple[str, str], str] = {}
    for m in firmware_re.finditer(source):
        system, fw_id, desc = m.group(1), m.group(2), m.group(3)
        firmware_slots[(system, fw_id)] = desc

    # Collect options per slot: list of (file_entry, status)
    slot_options: dict[tuple[str, str], list[tuple[dict, str]]] = {}

    for m in option_re.finditer(source):
        system, fw_id = m.group(1), m.group(2)
        var_ref = m.group(3)
        inline_sha1 = m.group(4)
        status = m.group(8) or "Acceptable"

        if var_ref:
            key = var_to_hash.get(var_ref)
            if key and key in files_by_hash:
                file_entry = files_by_hash[key]
            else:
                continue
        elif inline_sha1:
            size_expr = m.group(5)
            name = m.group(6)
            desc = m.group(7)
            file_entry = {
                "sha1": inline_sha1,
                "size": _safe_arithmetic(size_expr),
                "name": name,
                "description": desc,
                "is_bad": False,
            }
        else:
            continue

        slot_key = (system, fw_id)
        slot_options.setdefault(slot_key, []).append((file_entry, status))

    # Build records from FirmwareAndOption one-liners
    records: list[dict] = []

    for m in fao_re.finditer(source):
        sha1 = m.group(1)
        size_expr = m.group(2)
        system = m.group(3)
        fw_id = m.group(4)
        name = m.group(5)
        desc = m.group(6)
        status = m.group(7) or "Acceptable"

        records.append({
            "system": system,
            "firmware_id": fw_id,
            "sha1": sha1,
            "name": name,
            "size": _safe_arithmetic(size_expr),
            "description": desc,
            "status": status,
        })

    # Build records from Firmware+Option pairs, picking best option
    for (system, fw_id), options in slot_options.items():
        desc = firmware_slots.get((system, fw_id), "")

        # Filter out bad files, then pick highest-ranked status
        viable = [(f, s) for f, s in options if not f.get("is_bad")]
        if not viable:
            viable = options

        viable.sort(key=lambda x: STATUS_RANK.get(x[1], 2), reverse=True)
        best_file, best_status = viable[0]

        records.append({
            "system": system,
            "firmware_id": fw_id,
            "sha1": best_file["sha1"],
            "name": best_file["name"],
            "size": best_file["size"],
            "description": best_file.get("description", desc),
            "status": best_status,
        })

    return records, files_by_hash


class Scraper(BaseScraper):
    """BizHawk firmware database scraper."""

    def __init__(self):
        super().__init__(url=SOURCE_URL)

    def validate_format(self, raw_data: str) -> bool:
        return "FirmwareDatabase" in raw_data and "FirmwareAndOption" in raw_data

    def fetch_requirements(self) -> list[BiosRequirement]:
        raw = self._fetch_raw()
        if not self.validate_format(raw):
            raise ValueError("unexpected FirmwareDatabase.cs format")

        records, _ = parse_firmware_database(raw)
        requirements: list[BiosRequirement] = []

        for rec in records:
            system_id = SYSTEM_ID_MAP.get(rec["system"], rec["system"].lower())

            req = BiosRequirement(
                name=rec["name"],
                system=system_id,
                sha1=rec["sha1"],
                size=rec["size"] if rec["size"] else None,
                required=rec.get("status") != "Bad",
            )
            requirements.append(req)

        return requirements

    def generate_platform_yaml(self) -> dict:
        """Generate a platform YAML config dict from scraped data."""
        requirements = self.fetch_requirements()

        systems: dict[str, dict] = {}
        for req in requirements:
            if req.system not in systems:
                systems[req.system] = {"files": []}

            entry: dict = {
                "name": req.name,
                "destination": req.name,
                "required": req.required,
            }
            if req.sha1:
                entry["sha1"] = req.sha1.lower()
            if req.size:
                entry["size"] = req.size

            systems[req.system]["files"].append(entry)

        version = fetch_github_latest_tag(GITHUB_REPO) or ""

        return {
            "platform": "BizHawk",
            "version": version,
            "homepage": "https://tasvideos.org/BizHawk",
            "source": SOURCE_URL,
            "base_destination": "Firmware",
            "hash_type": "sha1",
            "verification_mode": "sha1",
            "cores": BIZHAWK_CORES,
            "systems": systems,
        }


def main():
    scraper_cli(Scraper, "Scrape BizHawk BIOS requirements")


if __name__ == "__main__":
    main()
