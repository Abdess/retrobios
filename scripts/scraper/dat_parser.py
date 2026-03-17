"""Parser for clrmamepro DAT format.

Parses files like libretro's System.dat which uses the format:
    game (
        name "System"
        comment "Platform Name"
        rom ( name filename size 12345 crc ABCD1234 md5 ... sha1 ... )
    )
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class DatRom:
    """A ROM entry from a DAT file."""
    name: str
    size: int
    crc32: str
    md5: str
    sha1: str
    system: str  # From the preceding comment line


@dataclass
class DatMetadata:
    """Metadata from a DAT file header."""
    name: str = ""
    version: str = ""
    description: str = ""
    author: str = ""
    homepage: str = ""
    url: str = ""


def parse_dat(content: str) -> list[DatRom]:
    """Parse clrmamepro DAT content and return list of DatRom entries.

    Handles:
    - Quoted filenames with spaces: name "7800 BIOS (U).rom"
    - Path filenames: name "pcsx2/bios/file.bin"
    - Unquoted filenames: name cpc464.rom
    - Inconsistent indentation (tabs vs spaces)
    """
    roms = []
    current_system = ""

    for line in content.split("\n"):
        stripped = line.strip()

        if stripped.startswith("comment "):
            value = stripped[8:].strip().strip('"')
            if value in ("System", "System, firmware, and BIOS files used by libretro cores."):
                continue
            current_system = value

        elif stripped.startswith("rom (") or stripped.startswith("rom("):
            rom = _parse_rom_line(stripped, current_system)
            if rom:
                roms.append(rom)

    return roms


def parse_dat_metadata(content: str) -> DatMetadata:
    """Extract metadata from the clrmamepro header block."""
    meta = DatMetadata()
    in_header = False

    for line in content.split("\n"):
        stripped = line.strip()
        if stripped.startswith("clrmamepro"):
            in_header = True
            continue
        if in_header and stripped == ")":
            break
        if in_header:
            for field in ("name", "version", "description", "author", "homepage", "url"):
                if stripped.startswith(f"{field} "):
                    value = stripped[len(field) + 1:].strip().strip('"')
                    setattr(meta, field, value)

    return meta


def _parse_rom_line(line: str, system: str) -> DatRom | None:
    """Parse a single rom ( ... ) line."""
    # rfind because filenames may contain parentheses like "(E).rom"
    start = line.find("(")
    end = line.rfind(")")
    if start == -1 or end == -1 or end <= start:
        return None

    content = line[start + 1:end].strip()

    fields = {}
    i = 0
    tokens = _tokenize(content)

    while i < len(tokens) - 1:
        key = tokens[i]
        value = tokens[i + 1]
        fields[key] = value
        i += 2

    name = fields.get("name", "")
    if not name:
        return None

    try:
        size = int(fields.get("size", "0"))
    except ValueError:
        size = 0

    return DatRom(
        name=name,
        size=size,
        crc32=fields.get("crc", "").lower(),
        md5=fields.get("md5", ""),
        sha1=fields.get("sha1", ""),
        system=system,
    )


def _tokenize(content: str) -> list[str]:
    """Tokenize DAT content, handling quoted strings."""
    tokens = []
    i = 0
    while i < len(content):
        while i < len(content) and content[i] in (" ", "\t"):
            i += 1
        if i >= len(content):
            break

        if content[i] == '"':
            i += 1
            start = i
            while i < len(content) and content[i] != '"':
                i += 1
            tokens.append(content[start:i])
            i += 1
        else:
            start = i
            while i < len(content) and content[i] not in (" ", "\t"):
                i += 1
            tokens.append(content[start:i])

    return tokens


def validate_dat_format(content: str) -> bool:
    """Validate that content is a valid clrmamepro DAT file.

    Checks for:
    - clrmamepro header
    - game block
    - rom entries
    """
    has_header = "clrmamepro" in content[:500]
    has_game = "game (" in content
    has_rom = "rom (" in content or "rom(" in content
    has_comment = 'comment "' in content

    return has_header and has_game and has_rom and has_comment
