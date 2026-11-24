"""Parser for FBNeo source files to extract BIOS sets and ROM definitions.

Parses BurnRomInfo structs (static ROM arrays) and BurnDriver structs
(driver registration) from FBNeo C source files. BIOS sets are identified
by the BDF_BOARDROM flag in BurnDriver definitions, and keyed by the
archive the driver opens.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from core.lines import LineIndex

# Sizes are written in hex or decimal (d_snes.cpp: ``{ "dsp1.bin", 10240, ...``).
_ROM_ENTRY_RE = re.compile(
    r'\{\s*"([^"]+)"\s*,\s*(0x[\da-fA-F]+|\d+)\s*,\s*(0x[\da-fA-F]+)\s*,\s*([^}]+)\}',
)

_BURN_DRIVER_RE = re.compile(
    r"struct\s+BurnDriver\s+BurnDrv(\w+)\s*=\s*\{(.*?)\};",
    re.DOTALL,
)

# The first three fields of a BurnDriver: name, parent, board ROM.
_DRIVER_HEAD_RE = re.compile(r'\s*("[^"]*"|NULL)\s*,\s*("[^"]*"|NULL)\s*,\s*("[^"]*"|NULL)')

# The GetZipName field of a BurnDriver and its RomInfo, which names the
# RomDesc array (BurnDrvngpc_ngp is "ngp_ngp" and reads ngpc_ngpRomDesc).
_ZIP_AND_ROMS_RE = re.compile(r"(\w+)\s*,\s*(\w+)RomInfo\s*,")


def zip_name(driver: str) -> str:
    """The archive a driver opens through a system GetZipName.

    Every non-arcade GetZipName cuts the system prefix up to its underscore
    (MSXGetZipName in d_msx.cpp: ``msx_msx`` opens msx.zip, ``msx_1942``
    opens 1942.zip). The arcade drivers have none and open their own name.
    """
    return driver.split("_", 1)[1] if "_" in driver else driver


def _quoted(field: str) -> str:
    return field.strip('"') if field != "NULL" else ""


def find_bios_sets(source: str, filename: str) -> dict[str, dict]:
    """Find BDF_BOARDROM drivers in source code.

    A board ROM set is keyed by the archive the games open it under: their
    GetZipName reads the board ROM name too (``i == 1``), so ``ngp_ngp``,
    whose own field is NULL, is looked up as ngp.zip by every NGP game.

    Returns a dict mapping that archive to metadata:
        {archive: {"source_file": str, "source_line": int, "rom_desc": str}}
    """
    lines = LineIndex(source)
    boards: list[tuple[str, int, bool, str]] = []
    zipped_boards: set[str] = set()

    for match in _BURN_DRIVER_RE.finditer(source):
        body = match.group(2)
        head = _DRIVER_HEAD_RE.match(body)
        fields = _ZIP_AND_ROMS_RE.search(body)
        own_zip = fields is not None and fields.group(1) != "NULL"
        if head and own_zip and _quoted(head.group(3)):
            zipped_boards.add(_quoted(head.group(3)))
        if "BDF_BOARDROM" not in body:
            continue
        # Set name is the first quoted string in the struct body
        name_match = re.search(r'"([^"]+)"', body)
        if not name_match:
            continue
        driver = name_match.group(1)
        rom_desc = fields.group(2) if fields else driver
        boards.append((driver, lines.line(match.start()), own_zip, rom_desc))

    return {
        (zip_name(driver) if own_zip or driver in zipped_boards else driver): {
            "source_file": filename,
            "source_line": line,
            "rom_desc": rom_desc,
        }
        for driver, line, own_zip, rom_desc in boards
    }


def parse_rom_info(source: str, set_name: str) -> list[dict]:
    """Parse a BurnRomInfo array for the given set name.

    Returns a list of dicts with keys: name, size, crc32.
    Sentinel entries (empty name) are skipped.
    """
    pattern = re.compile(
        r"static\s+struct\s+BurnRomInfo\s+"
        + re.escape(set_name)
        + r"RomDesc\s*\[\s*\]\s*=\s*\{(.*?)\};",
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
        size = int(entry.group(2), 0)
        crc32 = format(int(entry.group(3), 16), "08x")

        roms.append(
            {
                "name": name,
                "size": size,
                "crc32": crc32,
            }
        )

    return roms


def parse_fbneo_source_tree(base_path: str) -> dict[str, dict]:
    """Walk the FBNeo driver source tree and extract all BIOS sets.

    Scans .cpp files under src/burn/drv/ for BDF_BOARDROM drivers,
    then parses their associated BurnRomInfo arrays.

    Returns a dict mapping the archive each driver opens to:
        {source_file, source_line, roms: [{name, size, crc32}, ...]}
    """
    drv_path = Path(base_path) / "src" / "burn" / "drv"
    if not drv_path.is_dir():
        return {}

    results: dict[str, dict] = {}

    for root, _dirs, files in os.walk(drv_path):
        for fname in files:
            if not fname.endswith(".cpp"):
                continue

            filepath = Path(root) / fname
            source = filepath.read_text(encoding="utf-8", errors="replace")
            rel_path = str(filepath.relative_to(base_path))

            bios_sets = find_bios_sets(source, rel_path)
            for archive, meta in bios_sets.items():
                roms = parse_rom_info(source, meta["rom_desc"])
                results[archive] = {
                    "source_file": meta["source_file"],
                    "source_line": meta["source_line"],
                    "roms": roms,
                }

    return results
