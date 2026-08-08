"""Parser for Logiqx XML DAT format.

Parses files like No-Intro daily packs and TOSEC releases which use:
    <datafile>
        <header><name>...</name><version>...</version></header>
        <game name="[BIOS] Game Boy Advance (World)">
            <description>...</description>
            <rom name="..." size="16384" crc="..." md5="..." sha1="..."/>
        </game>
    </datafile>
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


@dataclass
class LogiqxRom:
    """A ROM entry from a Logiqx DAT file."""

    game: str
    description: str
    name: str
    size: int
    crc32: str
    md5: str
    sha1: str


@dataclass
class LogiqxDat:
    """A parsed Logiqx DAT file."""

    name: str = ""
    version: str = ""
    roms: list[LogiqxRom] = field(default_factory=list)


def parse_logiqx(content: str | bytes) -> LogiqxDat:
    """Parse Logiqx XML DAT content.

    Handles both <game> and <machine> entries, and games with
    multiple <rom> children. Content declaring XML entities is
    rejected: DAT files never define them, and expanding entities
    from untrusted packs opens entity-expansion attacks.
    """
    haystack = content if isinstance(content, str) else content.decode("utf-8", "replace")
    if "<!ENTITY" in haystack.upper():
        raise ValueError("XML entity declarations are not allowed in DAT files")
    root = ET.fromstring(content)
    dat = LogiqxDat()

    header = root.find("header")
    if header is not None:
        dat.name = header.findtext("name", "").strip()
        dat.version = header.findtext("version", "").strip()

    for game in list(root.iter("game")) + list(root.iter("machine")):
        game_name = game.get("name", "")
        description = game.findtext("description", "").strip()
        for rom in game.iter("rom"):
            name = rom.get("name", "")
            if not name:
                continue
            try:
                size = int(rom.get("size", "0"))
            except ValueError:
                size = 0
            dat.roms.append(
                LogiqxRom(
                    game=game_name,
                    description=description or game_name,
                    name=name,
                    size=size,
                    crc32=rom.get("crc", "").lower(),
                    md5=rom.get("md5", "").lower(),
                    sha1=rom.get("sha1", "").lower(),
                )
            )

    return dat


def validate_logiqx_format(content: str | bytes) -> bool:
    """Validate that content parses as a Logiqx DAT with rom entries."""
    try:
        dat = parse_logiqx(content)
    except ET.ParseError:
        return False
    return bool(dat.roms)
