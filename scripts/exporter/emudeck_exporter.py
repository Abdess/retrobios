"""Exporter for EmuDeck checkBIOS.sh format.

Produces a bash script compatible with EmuDeck's checkBIOS.sh,
containing MD5 hash arrays and per-system check functions.
"""

from __future__ import annotations

import re
from pathlib import Path

from .base_exporter import BaseExporter

# System slug -> (bash array name, check function name)
_SYSTEM_BASH_MAP: dict[str, tuple[str, str]] = {
    "sony-playstation": ("PSBios", "checkPS1BIOS"),
    "sony-playstation-2": ("PS2Bios", "checkPS2BIOS"),
    "sega-mega-cd": ("CDBios", "checkSegaCDBios"),
    "sega-saturn": ("SaturnBios", "checkSaturnBios"),
    "sega-dreamcast": ("DCBios", "checkDreamcastBios"),
    "nintendo-ds": ("DSBios", "checkDSBios"),
}


def _slug_to_bash_name(slug: str) -> str:
    """Convert a system slug to a CamelCase bash identifier."""
    parts = slug.split("-")
    return "".join(p.capitalize() for p in parts) + "Bios"


def _slug_to_func_name(slug: str) -> str:
    """Convert a system slug to a check function name."""
    parts = slug.split("-")
    return "check" + "".join(p.capitalize() for p in parts) + "Bios"


def _collect_md5s(files: list[dict]) -> list[str]:
    """Extract unique MD5 hashes from file entries."""
    hashes: list[str] = []
    seen: set[str] = set()
    for fe in files:
        md5 = fe.get("md5", "")
        if isinstance(md5, list):
            for h in md5:
                h_lower = h.lower()
                if h_lower and h_lower not in seen:
                    seen.add(h_lower)
                    hashes.append(h_lower)
        elif md5:
            h_lower = md5.lower()
            if h_lower not in seen:
                seen.add(h_lower)
                hashes.append(h_lower)
    return hashes


class Exporter(BaseExporter):
    """Export truth data to EmuDeck checkBIOS.sh format."""

    @staticmethod
    def platform_name() -> str:
        return "emudeck"

    def export(
        self,
        truth_data: dict,
        output_path: str,
        scraped_data: dict | None = None,
    ) -> None:
        systems = truth_data.get("systems", {})

        # Collect per-system hash arrays and file lists
        sys_hashes: dict[str, list[str]] = {}
        sys_files: dict[str, list[dict]] = {}
        for sys_id in sorted(systems):
            files = systems[sys_id].get("files", [])
            valid_files = [
                f for f in files
                if not f.get("name", "").startswith("_")
                and not self._is_pattern(f.get("name", ""))
            ]
            if not valid_files:
                continue
            sys_files[sys_id] = valid_files
            sys_hashes[sys_id] = _collect_md5s(valid_files)

        lines: list[str] = [
            "#!/bin/bash",
            "# EmuDeck BIOS check script",
            "# Generated from retrobios truth data",
            "",
        ]

        # Emit hash arrays for systems that have MD5s
        for sys_id in sorted(sys_hashes):
            hashes = sys_hashes[sys_id]
            if not hashes:
                continue
            array_name, _ = _SYSTEM_BASH_MAP.get(
                sys_id, (_slug_to_bash_name(sys_id), ""),
            )
            lines.append(f"{array_name}=({' '.join(hashes)})")
        lines.append("")

        # Emit check functions
        for sys_id in sorted(sys_files):
            hashes = sys_hashes.get(sys_id, [])
            _, func_name = _SYSTEM_BASH_MAP.get(
                sys_id, ("", _slug_to_func_name(sys_id)),
            )

            lines.append(f"{func_name}(){{")

            if hashes:
                array_name, _ = _SYSTEM_BASH_MAP.get(
                    sys_id, (_slug_to_bash_name(sys_id), ""),
                )
                lines.append('    localRONE="NULL"')
                lines.append('    for entry in "$biosPath/"*')
                lines.append("    do")
                lines.append('        if [ -f "$entry" ]; then')
                lines.append('            md5=($(md5sum "$entry"))')
                lines.append(
                    f'            for hash in "${{{array_name}[@]}}"; do',
                )
                lines.append(
                    '                if [[ "$md5" == *"${hash}"* ]]; then',
                )
                lines.append('                    RONE=true')
                lines.append("                fi")
                lines.append("            done")
                lines.append("        fi")
                lines.append("    done")
                lines.append('    if [ $RONE == true ]; then')
                lines.append('        echo "true"')
                lines.append("    else")
                lines.append('        echo "false"')
                lines.append("    fi")
            else:
                # No MD5 hashes — check file existence
                for fe in sys_files[sys_id]:
                    dest = self._dest(fe)
                    if dest:
                        lines.append(
                            f'    if [ -f "$biosPath/{dest}" ]; then',
                        )
                        lines.append('        echo "true"')
                        lines.append("        return")
                        lines.append("    fi")
                lines.append('    echo "false"')

            lines.append("}")
            lines.append("")

        # Emit setBIOSstatus aggregator
        lines.append("setBIOSstatus(){")
        for sys_id in sorted(sys_files):
            _, func_name = _SYSTEM_BASH_MAP.get(
                sys_id, ("", _slug_to_func_name(sys_id)),
            )
            var = re.sub(r"^check", "", func_name)
            var = re.sub(r"Bios$", "BIOS", var)
            var = re.sub(r"BIOS$", "_bios", var)
            lines.append(f"    {var}=$({func_name})")
        lines.append("}")
        lines.append("")

        Path(output_path).write_text("\n".join(lines), encoding="utf-8")

    def validate(self, truth_data: dict, output_path: str) -> list[str]:
        content = Path(output_path).read_text(encoding="utf-8")
        issues: list[str] = []

        for sys_id, sys_data in truth_data.get("systems", {}).items():
            files = sys_data.get("files", [])
            valid_files = [
                f for f in files
                if not f.get("name", "").startswith("_")
                and not self._is_pattern(f.get("name", ""))
            ]
            if not valid_files:
                continue

            # Check that MD5 hashes appear in the output
            for fe in valid_files:
                md5 = fe.get("md5", "")
                if isinstance(md5, list):
                    for h in md5:
                        if h and h.lower() not in content:
                            issues.append(f"missing hash: {h} ({sys_id})")
                elif md5 and md5.lower() not in content:
                    issues.append(f"missing hash: {md5} ({sys_id})")

            # Check that a check function exists for this system
            _, func_name = _SYSTEM_BASH_MAP.get(
                sys_id, ("", _slug_to_func_name(sys_id)),
            )
            if func_name not in content:
                issues.append(f"missing function: {func_name} ({sys_id})")

        return issues
