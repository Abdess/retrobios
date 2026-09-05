"""Exporter for libretro System.dat (clrmamepro DAT format).

One 'game' block, systems separated by a comment line carrying the name
libretro gives them, matching libretro-database/dat/System.dat.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scraper.dat_parser import parse_dat

from .base_exporter import BaseExporter
from .baseline import NativeSystem, Report

SOURCE_URL = (
    "https://raw.githubusercontent.com/libretro/libretro-database/master/dat/System.dat"
)


def _quote(name: str) -> str:
    """Quote a ROM name the way the original does: only when it must be."""
    return f'"{name}"' if any(c in name for c in ' ()') else name


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
    def writable(cls, fe, require: str = "") -> bool:
        """A clrmamepro rom line is a hash record, and the DAT has no other.

        The original never states a rom it cannot hash, so neither do we.
        """
        if fe.platform is not None:
            return True
        return any(fe.hash(h) for h in ("crc32", "md5", "sha1"))

    @staticmethod
    def _rom_name(fe) -> str:
        """The name the DAT gives a rom.

        libretro writes the path for some entries (ep128emu/roms/cpc464.rom)
        and the bare name for others whose destination has a directory all
        the same (iplromco.dat, which lives under keropi/), so its own
        spelling is recorded rather than derived.
        """
        declared = fe.native("native_path", "")
        return str(declared) if declared else fe.name

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

    def render(
        self,
        systems: dict[str, NativeSystem],
        report: Report,
        originals: dict[str, str],
        scraped: dict | None = None,
    ) -> dict[str, str]:
        lines = self._header(originals, scraped)
        lines.extend(["game (", '\tname "System"', '\tcomment "System"'])

        for system, files in sorted(
            self.exportable(systems), key=lambda pair: pair[0].native_id
        ):
            rendered: list[str] = []
            for fe in files:
                if not any(fe.hash(h) for h in ("crc32", "md5", "sha1")):
                    continue
                parts = [f"name {_quote(self._rom_name(fe))}"]
                size = fe.size()
                if size:
                    parts.append(f"size {size}")
                crc = fe.hash("crc32")
                if crc:
                    parts.append(f"crc {crc.upper()}")
                md5 = fe.hash("md5")
                if md5:
                    parts.append(f"md5 {md5}")
                sha1 = fe.hash("sha1")
                if sha1:
                    parts.append(f"sha1 {sha1}")
                rendered.append(f"\trom ( {' '.join(parts)} )")

            if not rendered:
                continue
            lines.append("")
            # libretro's comment is the system name as the DAT spells it,
            # "Atari - 400-800". Prettifying it drops the separator.
            lines.append(f'\tcomment "{system.native_id}"')
            lines.extend(rendered)

        lines.append(")")
        lines.append("")
        return {self.native_filename(): "\n".join(lines)}

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
                if not any(fe.hash(h) for h in ("crc32", "md5", "sha1")):
                    continue
                if self._rom_name(fe) not in exported:
                    issues.append(f"absent from the DAT: {system.native_id}/{fe.name}")
        if not content.rstrip().endswith(")"):
            issues.append("the game block is not closed")
        return issues
