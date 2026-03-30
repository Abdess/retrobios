"""Exporter for EmuDeck checkBIOS.sh format.

Produces a bash script matching the exact pattern of EmuDeck's
functions/checkBIOS.sh: per-system check functions with MD5 arrays
inside the function body, iterating over $biosPath/* files.

Two patterns:
- MD5 pattern: systems with known hashes, loop $biosPath/*, md5sum each, match
- File-exists pattern: systems with specific paths, check -f
"""

from __future__ import annotations

import re
from pathlib import Path

from .base_exporter import BaseExporter

# Map our system IDs to EmuDeck function naming conventions
_SYSTEM_CONFIG: dict[str, dict] = {
    "sony-playstation": {
        "func": "checkPS1BIOS",
        "var": "PSXBIOS",
        "array": "PSBios",
        "pattern": "md5",
    },
    "sony-playstation-2": {
        "func": "checkPS2BIOS",
        "var": "PS2BIOS",
        "array": "PS2Bios",
        "pattern": "md5",
    },
    "sega-mega-cd": {
        "func": "checkSegaCDBios",
        "var": "SEGACDBIOS",
        "array": "CDBios",
        "pattern": "md5",
    },
    "sega-saturn": {
        "func": "checkSaturnBios",
        "var": "SATURNBIOS",
        "array": "SaturnBios",
        "pattern": "md5",
    },
    "sega-dreamcast": {
        "func": "checkDreamcastBios",
        "var": "BIOS",
        "array": "hashes",
        "pattern": "md5",
    },
    "nintendo-ds": {
        "func": "checkDSBios",
        "var": "BIOS",
        "array": "hashes",
        "pattern": "md5",
    },
    "nintendo-switch": {
        "func": "checkCitronBios",
        "pattern": "file-exists",
        "firmware_path": "$biosPath/citron/firmware",
        "keys_path": "$biosPath/citron/keys/prod.keys",
    },
}


def _make_md5_function(cfg: dict, md5s: list[str]) -> list[str]:
    """Generate a MD5-checking function matching EmuDeck's exact pattern."""
    func = cfg["func"]
    var = cfg["var"]
    array = cfg["array"]
    md5_str = " ".join(md5s)

    return [
        f"{func}(){{",
        "",
        f'\t{var}="NULL"',
        "",
        '\tfor entry in "$biosPath/"*',
        "\tdo",
        '\t\tif [ -f "$entry" ]; then',
        '\t\t\tmd5=($(md5sum "$entry"))',
        f'\t\t\tif [[ "${var}" != true ]]; then',
        f"\t\t\t\t{array}=({md5_str})",
        f'\t\t\t\tfor i in "${{{array}[@]}}"',
        "\t\t\t\tdo",
        '\t\t\t\tif [[ "$md5" == *"${i}"* ]]; then',
        f"\t\t\t\t\t{var}=true",
        "\t\t\t\t\tbreak",
        "\t\t\t\telse",
        f"\t\t\t\t\t{var}=false",
        "\t\t\t\tfi",
        "\t\t\t\tdone",
        "\t\t\tfi",
        "\t\tfi",
        "\tdone",
        "",
        "",
        f"\tif [ ${var} == true ]; then",
        '\t\techo "$entry true";',
        "\telse",
        '\t\techo "false";',
        "\tfi",
        "}",
    ]


def _make_file_exists_function(cfg: dict) -> list[str]:
    """Generate a file-exists function matching EmuDeck's pattern."""
    func = cfg["func"]
    firmware = cfg.get("firmware_path", "")
    keys = cfg.get("keys_path", "")

    return [
        f"{func}(){{",
        "",
        f'\tlocal FIRMWARE="{firmware}"',
        f'\tlocal KEYS="{keys}"',
        '\tif [[ -f "$KEYS" ]] && [[ "$( ls -A "$FIRMWARE")" ]]; then',
        '\t\t\techo "true";',
        "\telse",
        '\t\t\techo "false";',
        "\tfi",
        "}",
    ]


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
        lines: list[str] = ["#!/bin/bash"]

        systems = truth_data.get("systems", {})

        for sys_id, cfg in sorted(_SYSTEM_CONFIG.items(), key=lambda x: x[1]["func"]):
            sys_data = systems.get(sys_id)
            if not sys_data:
                continue

            lines.append("")

            if cfg["pattern"] == "md5":
                md5s: list[str] = []
                for fe in sys_data.get("files", []):
                    name = fe.get("name", "")
                    if self._is_pattern(name) or name.startswith("_"):
                        continue
                    md5 = fe.get("md5", "")
                    if isinstance(md5, list):
                        md5s.extend(m for m in md5 if m and re.fullmatch(r"[a-f0-9]{32}", m))
                    elif md5 and re.fullmatch(r"[a-f0-9]{32}", md5):
                        md5s.append(md5)
                if md5s:
                    lines.extend(_make_md5_function(cfg, md5s))
            elif cfg["pattern"] == "file-exists":
                lines.extend(_make_file_exists_function(cfg))

        lines.append("")
        Path(output_path).write_text("\n".join(lines), encoding="utf-8")

    def validate(self, truth_data: dict, output_path: str) -> list[str]:
        content = Path(output_path).read_text(encoding="utf-8")
        issues: list[str] = []

        systems = truth_data.get("systems", {})
        for sys_id, cfg in _SYSTEM_CONFIG.items():
            if cfg["pattern"] != "md5":
                continue
            sys_data = systems.get(sys_id)
            if not sys_data:
                continue
            for fe in sys_data.get("files", []):
                md5 = fe.get("md5", "")
                if isinstance(md5, list):
                    md5 = md5[0] if md5 else ""
                if md5 and re.fullmatch(r"[a-f0-9]{32}", md5) and md5 not in content:
                    issues.append(f"missing md5: {md5} ({fe.get('name', '')})")

        for sys_id, cfg in _SYSTEM_CONFIG.items():
            func = cfg["func"]
            if func in content:
                continue
            sys_data = systems.get(sys_id)
            if not sys_data or not sys_data.get("files"):
                continue
            # Only flag if the system has usable data for the function type
            if cfg["pattern"] == "md5":
                has_md5 = any(
                    fe.get("md5") and isinstance(fe.get("md5"), str)
                    and re.fullmatch(r"[a-f0-9]{32}", fe["md5"])
                    for fe in sys_data["files"]
                )
                if has_md5:
                    issues.append(f"missing function: {func}")
            elif cfg["pattern"] == "file-exists":
                issues.append(f"missing function: {func}")

        return issues
