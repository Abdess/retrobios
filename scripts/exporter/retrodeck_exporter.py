"""Exporter for RetroDECK component_manifest.json format.

Produces a JSON file compatible with RetroDECK's component manifests.
Each system maps to a component with BIOS entries containing filename,
md5 (comma-separated if multiple), paths ($bios_path default), and
required status.

Path tokens: $bios_path for bios/, $roms_path for roms/.
Entries without an explicit path default to $bios_path.
"""

from __future__ import annotations

import json
import re
from collections import OrderedDict
from pathlib import Path

from .base_exporter import BaseExporter

# retrobios slug -> RetroDECK system ID (reverse of scraper SYSTEM_SLUG_MAP)
_REVERSE_SLUG: dict[str, str] = {
    "nintendo-nes": "nes",
    "nintendo-snes": "snes",
    "nintendo-64": "n64",
    "nintendo-64dd": "n64dd",
    "nintendo-gamecube": "gc",
    "nintendo-wii": "wii",
    "nintendo-wii-u": "wiiu",
    "nintendo-switch": "switch",
    "nintendo-gb": "gb",
    "nintendo-gbc": "gbc",
    "nintendo-gba": "gba",
    "nintendo-ds": "nds",
    "nintendo-3ds": "3ds",
    "nintendo-fds": "fds",
    "nintendo-sgb": "sgb",
    "nintendo-virtual-boy": "virtualboy",
    "nintendo-pokemon-mini": "pokemini",
    "sony-playstation": "psx",
    "sony-playstation-2": "ps2",
    "sony-playstation-3": "ps3",
    "sony-psp": "psp",
    "sony-psvita": "psvita",
    "sega-mega-drive": "megadrive",
    "sega-mega-cd": "megacd",
    "sega-saturn": "saturn",
    "sega-dreamcast": "dreamcast",
    "sega-dreamcast-arcade": "naomi",
    "sega-game-gear": "gamegear",
    "sega-master-system": "mastersystem",
    "nec-pc-engine": "pcengine",
    "nec-pc-fx": "pcfx",
    "nec-pc-98": "pc98",
    "nec-pc-88": "pc88",
    "3do": "3do",
    "amstrad-cpc": "amstradcpc",
    "arcade": "arcade",
    "atari-400-800": "atari800",
    "atari-5200": "atari5200",
    "atari-7800": "atari7800",
    "atari-jaguar": "atarijaguar",
    "atari-lynx": "atarilynx",
    "atari-st": "atarist",
    "commodore-c64": "c64",
    "commodore-amiga": "amiga",
    "philips-cdi": "cdimono1",
    "fairchild-channel-f": "channelf",
    "coleco-colecovision": "colecovision",
    "mattel-intellivision": "intellivision",
    "microsoft-msx": "msx",
    "microsoft-xbox": "xbox",
    "doom": "doom",
    "j2me": "j2me",
    "apple-macintosh-ii": "macintosh",
    "apple-ii": "apple2",
    "apple-iigs": "apple2gs",
    "enterprise-64-128": "enterprise",
    "tiger-game-com": "gamecom",
    "hartung-game-master": "gmaster",
    "epoch-scv": "scv",
    "watara-supervision": "supervision",
    "bandai-wonderswan": "wonderswan",
    "snk-neogeo-cd": "neogeocd",
    "tandy-coco": "coco",
    "tandy-trs-80": "trs80",
    "dragon-32-64": "dragon",
    "pico8": "pico8",
    "wolfenstein-3d": "wolfenstein",
    "sinclair-zx-spectrum": "zxspectrum",
}


def _dest_to_path_token(destination: str) -> str:
    """Convert a truth destination path to a RetroDECK path token."""
    if destination.startswith("roms/"):
        return "$roms_path/" + destination.removeprefix("roms/")
    if destination.startswith("bios/"):
        return "$bios_path/" + destination.removeprefix("bios/")
    # Default: bios path
    return "$bios_path/" + destination


class Exporter(BaseExporter):
    """Export truth data to RetroDECK component_manifest.json format."""

    @staticmethod
    def platform_name() -> str:
        return "retrodeck"

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

        manifest: OrderedDict[str, dict] = OrderedDict()

        systems = truth_data.get("systems", {})
        for sys_id in sorted(systems):
            sys_data = systems[sys_id]
            files = sys_data.get("files", [])
            if not files:
                continue

            native_id = native_map.get(sys_id, _REVERSE_SLUG.get(sys_id, sys_id))

            bios_entries: list[OrderedDict] = []
            for fe in files:
                name = fe.get("name", "")
                if name.startswith("_") or self._is_pattern(name):
                    continue

                dest = self._dest(fe)
                path_token = _dest_to_path_token(dest)

                md5 = fe.get("md5", "")
                if isinstance(md5, list):
                    md5 = ",".join(m for m in md5 if m)

                required = fe.get("required", True)

                entry: OrderedDict[str, object] = OrderedDict()
                entry["filename"] = name
                if md5:
                    # Validate MD5 entries
                    parts = [
                        m.strip().lower()
                        for m in str(md5).split(",")
                        if re.fullmatch(r"[0-9a-f]{32}", m.strip())
                    ]
                    if parts:
                        entry["md5"] = ",".join(parts) if len(parts) > 1 else parts[0]
                entry["paths"] = path_token
                entry["required"] = required

                system_val = native_id
                entry["system"] = system_val

                bios_entries.append(entry)

            if bios_entries:
                if native_id in manifest:
                    # Merge into existing component (multiple truth systems
                    # may map to the same native ID)
                    existing_names = {e["filename"] for e in manifest[native_id]["bios"]}
                    for entry in bios_entries:
                        if entry["filename"] not in existing_names:
                            manifest[native_id]["bios"].append(entry)
                else:
                    component = OrderedDict()
                    component["system"] = native_id
                    component["bios"] = bios_entries
                    manifest[native_id] = component

        Path(output_path).write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def validate(self, truth_data: dict, output_path: str) -> list[str]:
        data = json.loads(Path(output_path).read_text(encoding="utf-8"))

        exported_names: set[str] = set()
        for comp_data in data.values():
            bios = comp_data.get("bios", [])
            if isinstance(bios, list):
                for entry in bios:
                    fn = entry.get("filename", "")
                    if fn:
                        exported_names.add(fn)

        issues: list[str] = []
        for sys_data in truth_data.get("systems", {}).values():
            for fe in sys_data.get("files", []):
                name = fe.get("name", "")
                if name.startswith("_") or self._is_pattern(name):
                    continue
                if name not in exported_names:
                    issues.append(f"missing: {name}")
        return issues
