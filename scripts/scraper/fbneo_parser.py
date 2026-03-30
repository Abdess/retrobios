"""Parser for FBNeo source files to extract BIOS sets and ROM definitions.

Parses BurnRomInfo structs (static ROM arrays) and BurnDriver structs
(driver registration) from FBNeo C source files. BIOS sets are identified
by the BDF_BOARDROM flag in BurnDriver definitions.
"""

from __future__ import annotations

import os
import re
from pathlib import Path


_ROM_ENTRY_RE = re.compile(
    r'\{\s*"([^"]+)"\s*,\s*(0x[\da-fA-F]+)\s*,\s*(0x[\da-fA-F]+)\s*,\s*([^}]+)\}',
)

_BURN_DRIVER_RE = re.compile(
    r'struct\s+BurnDriver\s+BurnDrv(\w+)\s*=\s*\{(.*?)\};',
    re.DOTALL,
)

_ROM_DESC_RE = re.compile(
    r'static\s+struct\s+BurnRomInfo\s+(\w+)RomDesc\s*\[\s*\]\s*=\s*\{(.*?)\};',
    re.DOTALL,
)


def find_bios_sets(source: str, filename: str) -> dict[str, dict]:
    """Find BDF_BOARDROM drivers in source code.

    Returns a dict mapping set name to metadata:
        {set_name: {"source_file": str, "source_line": int}}
    """
    results: dict[str, dict] = {}

    for match in _BURN_DRIVER_RE.finditer(source):
        body = match.group(2)
        if 'BDF_BOARDROM' not in body:
            continue

        # Set name is the first quoted string in the struct body
        name_match = re.search(r'"([^"]+)"', body)
        if not name_match:
            continue

        set_name = name_match.group(1)
        line_num = source[:match.start()].count('\n') + 1

        results[set_name] = {
            'source_file': filename,
            'source_line': line_num,
        }

    return results


def parse_rom_info(source: str, set_name: str) -> list[dict]:
    """Parse a BurnRomInfo array for the given set name.

    Returns a list of dicts with keys: name, size, crc32.
    Sentinel entries (empty name) are skipped.
    """
    pattern = re.compile(
        r'static\s+struct\s+BurnRomInfo\s+'
        + re.escape(set_name)
        + r'RomDesc\s*\[\s*\]\s*=\s*\{(.*?)\};',
        re.DOTALL,
    )
    match = pattern.search(source)
    if not match:
        return []

    body = match.group(1)
    roms: list[dict] = []

    for entry in _ROM_ENTRY_RE.finditer(body):
        name = entry.group(1)
        if not name:
            continue
        size = int(entry.group(2), 16)
        crc32 = format(int(entry.group(3), 16), '08x')

        roms.append({
            'name': name,
            'size': size,
            'crc32': crc32,
        })

    return roms


def parse_fbneo_source_tree(base_path: str) -> dict[str, dict]:
    """Walk the FBNeo driver source tree and extract all BIOS sets.

    Scans .cpp files under src/burn/drv/ for BDF_BOARDROM drivers,
    then parses their associated BurnRomInfo arrays.

    Returns a dict mapping set name to:
        {source_file, source_line, roms: [{name, size, crc32}, ...]}
    """
    drv_path = Path(base_path) / 'src' / 'burn' / 'drv'
    if not drv_path.is_dir():
        return {}

    results: dict[str, dict] = {}

    for root, _dirs, files in os.walk(drv_path):
        for fname in files:
            if not fname.endswith('.cpp'):
                continue

            filepath = Path(root) / fname
            source = filepath.read_text(encoding='utf-8', errors='replace')
            rel_path = str(filepath.relative_to(base_path))

            bios_sets = find_bios_sets(source, rel_path)
            for set_name, meta in bios_sets.items():
                roms = parse_rom_info(source, set_name)
                results[set_name] = {
                    'source_file': meta['source_file'],
                    'source_line': meta['source_line'],
                    'roms': roms,
                }

    return results
