"""Exporter for libretro System.dat (clrmamepro DAT format)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scraper.dat_parser import parse_dat

from .base_exporter import BaseExporter


def _slug_to_native(slug: str) -> str:
    """Convert a system slug to a native 'Manufacturer - Console' name."""
    parts = slug.split("-", 1)
    if len(parts) == 1:
        return parts[0].title()
    manufacturer = parts[0].replace("-", " ").title()
    console = parts[1].replace("-", " ").title()
    return f"{manufacturer} - {console}"


class Exporter(BaseExporter):
    """Export truth data to libretro System.dat format."""

    @staticmethod
    def platform_name() -> str:
        return "retroarch"

    def export(
        self,
        truth_data: dict,
        output_path: str,
        scraped_data: dict | None = None,
    ) -> None:
        native_map: dict[str, str] = {}
        if scraped_data:
            for sys_id, sys_data in scraped_data.get("systems", {}).items():
                nid = sys_data.get("native_id")
                if nid:
                    native_map[sys_id] = nid

        lines: list[str] = []
        lines.append('clrmamepro (')
        lines.append('\tname "System.dat"')
        lines.append(')')

        systems = truth_data.get("systems", {})
        for sys_id in sorted(systems):
            sys_data = systems[sys_id]
            native_name = native_map.get(sys_id, _slug_to_native(sys_id))

            for fe in sys_data.get("files", []):
                name = fe.get("name", "")
                if name.startswith("_"):
                    continue

                dest = fe.get("path", name)
                size = fe.get("size", 0)
                crc = fe.get("crc32", "")
                md5 = fe.get("md5", "")
                sha1 = fe.get("sha1", "")

                rom_parts = [f'name "{name}"']
                rom_parts.append(f"size {size}")
                if crc:
                    rom_parts.append(f"crc {crc}")
                if md5:
                    rom_parts.append(f"md5 {md5}")
                if sha1:
                    rom_parts.append(f"sha1 {sha1}")
                rom_str = " ".join(rom_parts)

                game_name = f"{native_name}/{dest}"
                lines.append("")
                lines.append("game (")
                lines.append(f'\tname "{game_name}"')
                lines.append(f'\tdescription "{name}"')
                lines.append(f"\trom ( {rom_str} )")
                lines.append(")")

        lines.append("")
        Path(output_path).write_text("\n".join(lines), encoding="utf-8")

    def validate(self, truth_data: dict, output_path: str) -> list[str]:
        content = Path(output_path).read_text(encoding="utf-8")
        parsed = parse_dat(content)

        exported_names: set[str] = set()
        for rom in parsed:
            exported_names.add(rom.name)

        issues: list[str] = []
        for sys_id, sys_data in truth_data.get("systems", {}).items():
            for fe in sys_data.get("files", []):
                name = fe.get("name", "")
                if name.startswith("_"):
                    continue
                if name not in exported_names:
                    issues.append(f"missing: {name} (system {sys_id})")

        return issues
