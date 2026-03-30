"""Exporter for Recalbox es_bios.xml format.

Produces XML matching the exact format of recalbox's es_bios.xml:
- XML namespace declaration
- <system fullname="..." platform="...">
- <bios path="system/file" md5="..." core="..." /> with optional mandatory, hashMatchMandatory, note
- mandatory absent = true (only explicit when false)
- 2-space indentation
"""

from __future__ import annotations

from pathlib import Path

from .base_exporter import BaseExporter




class Exporter(BaseExporter):
    """Export truth data to Recalbox es_bios.xml format."""

    @staticmethod
    def platform_name() -> str:
        return "recalbox"

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

        lines: list[str] = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<biosList xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
            ' xsi:noNamespaceSchemaLocation="es_bios.xsd">',
        ]

        systems = truth_data.get("systems", {})
        for sys_id in sorted(systems):
            sys_data = systems[sys_id]
            files = sys_data.get("files", [])
            if not files:
                continue

            native_id = native_map.get(sys_id, sys_id)
            scraped_sys = scraped_data.get("systems", {}).get(sys_id) if scraped_data else None
            display_name = self._display_name(sys_id, scraped_sys)

            lines.append(f'  <system fullname="{display_name}" platform="{native_id}">')

            for fe in files:
                name = fe.get("name", "")
                if name.startswith("_") or self._is_pattern(name):
                    continue

                dest = self._dest(fe)
                # Recalbox paths include system prefix
                path = f"{native_id}/{dest}" if "/" not in dest else dest

                md5 = fe.get("md5", "")
                if isinstance(md5, list):
                    md5 = ",".join(md5)

                required = fe.get("required", True)

                # Build cores string from _cores
                cores_list = fe.get("_cores", [])
                core_str = ",".join(f"libretro/{c}" for c in cores_list) if cores_list else ""

                attrs = [f'path="{path}"']
                if md5:
                    attrs.append(f'md5="{md5}"')
                if not required:
                    attrs.append('mandatory="false"')
                if not required:
                    attrs.append('hashMatchMandatory="true"')
                if core_str:
                    attrs.append(f'core="{core_str}"')

                lines.append(f'    <bios {" ".join(attrs)} />')

            lines.append("  </system>")

        lines.append("</biosList>")
        lines.append("")
        Path(output_path).write_text("\n".join(lines), encoding="utf-8")

    def validate(self, truth_data: dict, output_path: str) -> list[str]:
        from xml.etree.ElementTree import parse as xml_parse

        tree = xml_parse(output_path)
        root = tree.getroot()

        exported_paths: set[str] = set()
        for bios_el in root.iter("bios"):
            path = bios_el.get("path", "")
            if path:
                exported_paths.add(path)
                # Also index basename
                exported_paths.add(path.split("/")[-1])

        issues: list[str] = []
        for sys_data in truth_data.get("systems", {}).values():
            for fe in sys_data.get("files", []):
                name = fe.get("name", "")
                if name.startswith("_") or self._is_pattern(name):
                    continue
                dest = self._dest(fe)
                if name not in exported_paths and dest not in exported_paths:
                    issues.append(f"missing: {name}")
        return issues
