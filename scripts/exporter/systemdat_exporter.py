"""Exporter for libretro System.dat (clrmamepro DAT format).

One 'game' block, systems separated by a comment line carrying the name
libretro gives them, matching libretro-database/dat/System.dat.
"""

from __future__ import annotations

import re

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scraper.dat_parser import parse_dat

from .base_exporter import BaseExporter
from .baseline import NativeFile, NativeSystem, Report

SOURCE_URL = (
    "https://raw.githubusercontent.com/libretro/libretro-database/master/dat/System.dat"
)


_QUOTED_NAME = re.compile(r'rom \( name "([^"]+)"')


def _quote(name: str, quoted: frozenset[str] = frozenset()) -> str:
    """Quote a ROM name the way the original does.

    Where it must be, and where the maintainers chose to: the file quotes
    246 names it did not need to, and writing them bare put a quoting change
    on every one of those lines of the diff.
    """
    return f'"{name}"' if name in quoted or any(c in name for c in ' ()') else name


# libretro indents most lines with a tab and 39 with four spaces (the Amiga
# kickstarts, the TI-83). Read with a tab only, those lines left the base and
# came back re-rendered, re-indented and moved to the end of their section.
_ROM_NAME = re.compile(r'^(\s+)rom \( name ("[^"]+"|\S+)')


_CRC = re.compile(r" crc (\S+)")


def _patch(line: str, indent: str, ours: str) -> str:
    """The original line where our values agree with it, else ours in its form.

    libretro writes one crc in lower case (Dinothawr.zip's 683ed4ad) and the
    others in upper case. A line whose values did not change keeps its bytes,
    and a corrected crc takes the case of the line it lands on. The
    indentation stays libretro's.
    """
    ours = indent + ours.lstrip("\t")
    if line.lower() == ours.lower():
        return line
    theirs = _CRC.search(line)
    if theirs and theirs.group(1) != theirs.group(1).upper():
        ours = _CRC.sub(lambda m: f" crc {m.group(1).lower()}", ours, count=1)
    return ours


def _sections(original: str) -> list[tuple[str, list[str]]]:
    """The system sections of a System.dat, each comment with its rom lines."""
    _, sep, body = original.partition("\ngame (")
    if not sep:
        return []
    sections: list[tuple[str, list[str]]] = []
    for line in body.splitlines():
        stripped = line.lstrip()
        if stripped.startswith('comment "') and stripped != 'comment "System"':
            sections.append((stripped[len('comment "'):].rstrip('"'), []))
        elif stripped.startswith("rom (") and line != stripped and sections:
            sections[-1][1].append(line)
    return sections


class Exporter(BaseExporter):
    """Write libretro's System.dat, corrected."""

    @staticmethod
    def platform_name() -> str:
        return "retroarch"

    @staticmethod
    def native_filename() -> str:
        return "System.dat"

    @staticmethod
    def carries() -> frozenset[str]:
        return frozenset({"size", "crc32", "md5", "sha1"})

    @staticmethod
    def native_sources() -> dict[str, str]:
        return {"System.dat": SOURCE_URL}

    @classmethod
    def writable(cls, fe: NativeFile, require: str = "") -> bool:
        """A clrmamepro rom line is a hash record, and the DAT has no other.

        The original never states a rom it cannot hash, so neither do we.
        """
        if fe.platform is not None:
            return True
        return any(fe.hash(h) for h in ("crc32", "md5", "sha1"))

    @staticmethod
    def _rom_name(fe: NativeFile) -> str:
        """The name the DAT gives a rom.

        libretro writes the path for some entries (ep128emu/roms/cpc464.rom)
        and the bare name for others whose destination has a directory all
        the same (iplromco.dat, which lives under keropi/), so its own
        spelling is recorded rather than derived. An addition has no
        spelling of libretro's to follow and is named by where the core reads
        it: two PCSX2 convert.glsl shaders under one bare name were one line.
        """
        declared = fe.native("native_path", "")
        if declared:
            return str(declared)
        return fe.destination if fe.platform is None else fe.name

    def _header(self, originals: dict[str, str], scraped: dict | None) -> list[str]:
        """Reuse the original header verbatim when we have the original."""
        original = originals.get(self.native_filename(), "")
        if original:
            head, sep, _ = original.partition("\ngame (")
            if sep:
                return head.split("\n")

        version = ""
        if scraped:
            version = scraped.get("dat_version", scraped.get("version", ""))
        lines = [
            "clrmamepro (",
            '\tname "System"',
            '\tdescription "System"',
            '\tcomment "System, firmware, and BIOS files used by libretro cores."',
        ]
        if version:
            lines.append(f"\tversion {version}")
        lines.extend(
            [
                '\tauthor "libretro"',
                '\thomepage "https://github.com/libretro/libretro-database/blob/master'
                '/dat/System.dat"',
                '\turl "https://raw.githubusercontent.com/libretro/libretro-database'
                '/master/dat/System.dat"',
                ")",
                "",
            ]
        )
        return lines

    def written(self, fe: NativeFile, field_name: str) -> str:
        """A record holds one value per field, the one record_hash names."""
        return fe.record_hash(field_name)

    def fills(self, fe: NativeFile, field_name: str) -> bool:
        return self.states(fe, field_name) and self.record_fills(fe, field_name)

    def render(
        self,
        systems: dict[str, NativeSystem],
        report: Report,
        originals: dict[str, str],
        scraped: dict | None = None,
    ) -> dict[str, str]:
        lines = self._header(originals, scraped)
        lines.extend(["game (", '\tname "System"', '\tcomment "System"'])
        original = originals.get(self.native_filename(), "")
        quoted = frozenset(_QUOTED_NAME.findall(original))

        ours: dict[str, dict[str, str]] = {}
        added: dict[str, set[str]] = {}
        # A rom name is one line: an addition whose name an earlier entry
        # took is not written, and was counted added.
        self._shadowed: set[int] = set()
        for system, files in self.exportable(systems):
            rendered: dict[str, str] = {}
            for fe in files:
                if not any(fe.hash(h) for h in ("crc32", "md5", "sha1")):
                    continue
                name = _quote(self._rom_name(fe), quoted)
                parts = [f"name {name}"]
                size = fe.size()
                if size:
                    parts.append(f"size {size}")
                crc = fe.record_hash("crc32")
                if crc:
                    parts.append(f"crc {crc.upper()}")
                md5 = fe.record_hash("md5")
                if md5:
                    parts.append(f"md5 {md5}")
                sha1 = fe.record_hash("sha1")
                if sha1:
                    parts.append(f"sha1 {sha1}")
                if name in rendered:
                    if fe.platform is None:
                        self._shadowed.add(id(fe))
                    continue
                rendered[name] = f"\trom ( {' '.join(parts)} )"
                if fe.platform is None:
                    added.setdefault(system.native_id, set()).add(name)
            if rendered:
                ours[system.native_id] = rendered

        def section(comment: str, roms: list[str]) -> None:
            lines.append("")
            # libretro's comment is the system name as the DAT spells it,
            # "Atari - 400-800". Prettifying it drops the separator.
            lines.append(f'\tcomment "{comment}"')
            lines.extend(roms)

        # libretro's own sections are the base: a rom line our transcription
        # does not carry (added or renamed after a scrape) stays as written.
        for comment, roms in _sections(original):
            rendered = ours.pop(comment, {})
            body = []
            for line in roms:
                match = _ROM_NAME.match(line)
                if match and match.group(2) in rendered:
                    body.append(_patch(line, match.group(1), rendered.pop(match.group(2))))
                else:
                    body.append(line)
            body.extend(rendered.values())
            section(comment, body)
        # A section is titled with the system as libretro spells it, and we
        # know no title for one it does not have: 20 sections came out under
        # our slugs (commodore-c64, quake, laseractive, xrick).
        self._untitled = {
            id(fe)
            for system, files in self.exportable(systems)
            if system.native_id in ours
            for fe in files
            if fe.platform is None
        }
        for comment in sorted(ours):
            own = [line for name, line in ours[comment].items()
                   if name not in added.get(comment, set())]
            if own:
                section(comment, own)

        lines.append(")")
        lines.append("")
        return {self.native_filename(): "\n".join(lines)}

    def lands(self, fe: NativeFile) -> bool:
        return (
            self.writable(fe)
            and id(fe) not in getattr(self, "_untitled", set())
            and id(fe) not in getattr(self, "_shadowed", set())
        )

    def validate(
        self,
        systems: dict[str, NativeSystem],
        produced: dict[str, str],
    ) -> list[str]:
        content = produced[self.native_filename()]
        parsed = parse_dat(content)
        exported = {rom.name for rom in parsed}

        issues: list[str] = []
        for system in systems.values():
            for fe in system.files:
                if not self.lands(fe) or not any(fe.hash(h) for h in ("crc32", "md5", "sha1")):
                    continue
                if self._rom_name(fe) not in exported:
                    issues.append(f"absent from the DAT: {system.native_id}/{fe.name}")
        if not content.rstrip().endswith(")"):
            issues.append("the game block is not closed")
        return issues
