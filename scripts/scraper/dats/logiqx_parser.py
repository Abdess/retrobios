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

from model.safeparse import parse_untrusted_xml


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
class LogiqxGame:
    """A <game> or <machine> of a Logiqx DAT, its serials and named ROMs."""

    name: str
    description: str
    serials: list[str]
    roms: list[LogiqxRom]


@dataclass
class LogiqxDat:
    """A parsed Logiqx DAT file."""

    name: str = ""
    version: str = ""
    roms: list[LogiqxRom] = field(default_factory=list)

    def provenance_entries(self, roms: list[LogiqxRom] | None = None) -> list[dict]:
        """The provenance snapshot form of the ROMs given, all of them by default."""
        return [
            {
                "dat": self.name,
                "name": rom.name,
                "description": rom.description,
                "size": rom.size,
                "crc32": rom.crc32,
                "md5": rom.md5,
                "sha1": rom.sha1,
            }
            for rom in (self.roms if roms is None else roms)
        ]


def parse_logiqx_games(content: str | bytes) -> tuple[str, str, list[LogiqxGame]]:
    """Header name, version and games of Logiqx XML DAT content.

    Handles both <game> and <machine> entries, and games with
    multiple <rom> children. A ROM without a name is left out. Content
    declaring XML entities is rejected: DAT files never define them, and
    expanding entities from untrusted packs opens entity-expansion attacks.
    """
    root = parse_untrusted_xml(content, "DAT files")
    header = root.find("header")
    name = version = ""
    if header is not None:
        name = header.findtext("name", "").strip()
        version = header.findtext("version", "").strip()

    games: list[LogiqxGame] = []
    for game in list(root.iter("game")) + list(root.iter("machine")):
        game_name = game.get("name", "")
        description = game.findtext("description", "").strip() or game_name
        serial = game.findtext("serial") or ""
        roms: list[LogiqxRom] = []
        for rom in game.iter("rom"):
            rom_name = rom.get("name", "")
            if not rom_name:
                continue
            try:
                size = int(rom.get("size", "0"))
            except ValueError:
                size = 0
            roms.append(
                LogiqxRom(
                    game=game_name,
                    description=description,
                    name=rom_name,
                    size=size,
                    crc32=rom.get("crc", "").lower(),
                    md5=rom.get("md5", "").lower(),
                    sha1=rom.get("sha1", "").lower(),
                )
            )
        games.append(LogiqxGame(
            game_name, description, [s.strip() for s in serial.split(",") if s.strip()], roms,
        ))
    return name, version, games


def parse_logiqx(content: str | bytes) -> LogiqxDat:
    """Parse Logiqx XML DAT content into its header and every named ROM."""
    name, version, games = parse_logiqx_games(content)
    return LogiqxDat(name, version, [rom for game in games for rom in game.roms])


def validate_logiqx_format(content: str | bytes) -> bool:
    """Validate that content parses as a Logiqx DAT with rom entries."""
    try:
        dat = parse_logiqx(content)
    except ET.ParseError:
        return False
    return bool(dat.roms)
