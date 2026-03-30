"""Exporter for Batocera batocera-systems format.

Produces a Python dict matching the exact format of
batocera-linux/batocera-scripts/scripts/batocera-systems.
"""

from __future__ import annotations

from pathlib import Path

from .base_exporter import BaseExporter




class Exporter(BaseExporter):
    """Export truth data to Batocera batocera-systems format."""

    @staticmethod
    def platform_name() -> str:
        return "batocera"

    def export(
        self,
        truth_data: dict,
        output_path: str,
        scraped_data: dict | None = None,
    ) -> None:
        # Build native_id and display name maps from scraped data
        native_map: dict[str, str] = {}
        if scraped_data:
            for sys_id, sys_data in scraped_data.get("systems", {}).items():
                nid = sys_data.get("native_id")
                if nid:
                    native_map[sys_id] = nid

        lines: list[str] = ["systems = {", ""]

        systems = truth_data.get("systems", {})
        for sys_id in sorted(systems):
            sys_data = systems[sys_id]
            files = sys_data.get("files", [])
            if not files:
                continue

            native_id = native_map.get(sys_id, sys_id)
            scraped_sys = scraped_data.get("systems", {}).get(sys_id) if scraped_data else None
            display_name = self._display_name(sys_id, scraped_sys)

            # Build biosFiles entries as compact single-line dicts
            bios_parts: list[str] = []
            for fe in files:
                name = fe.get("name", "")
                if name.startswith("_") or self._is_pattern(name):
                    continue
                dest = self._dest(fe)
                md5 = fe.get("md5", "")
                if isinstance(md5, list):
                    md5 = md5[0] if md5 else ""

                entry_parts = []
                if md5:
                    entry_parts.append(f'"md5": "{md5}"')
                entry_parts.append(f'"file": "bios/{dest}"')
                bios_parts.append("{ " + ", ".join(entry_parts) + " }")

            bios_str = ", ".join(bios_parts)
            line = (
                f'    "{native_id}": '
                f'{{ "name": "{display_name}", '
                f'"biosFiles": [ {bios_str} ] }},'
            )
            lines.append(line)

        lines.append("")
        lines.append("}")
        lines.append("")
        Path(output_path).write_text("\n".join(lines), encoding="utf-8")

    def validate(self, truth_data: dict, output_path: str) -> list[str]:
        content = Path(output_path).read_text(encoding="utf-8")
        issues: list[str] = []
        for sys_data in truth_data.get("systems", {}).values():
            for fe in sys_data.get("files", []):
                name = fe.get("name", "")
                if name.startswith("_") or self._is_pattern(name):
                    continue
                dest = self._dest(fe)
                if dest not in content and name not in content:
                    issues.append(f"missing: {name}")
        return issues
