#!/usr/bin/env python3
"""Scraper for RetroDECK BIOS requirements.

Source: https://github.com/RetroDECK/components
Format: component_manifest.json per component directory
Hash:   MD5 (primary), SHA256 for some entries (melonDS DSi)

RetroDECK stores BIOS requirements in component_manifest.json files,
one per emulator component. BIOS entries can appear in three locations:
  - top-level 'bios' key
  - preset_actions.bios (duckstation, dolphin, pcsx2)
  - cores.bios (retroarch)

Path tokens: $bios_path, $saves_path, $roms_path map to
~/retrodeck/bios/, ~/retrodeck/saves/, ~/retrodeck/roms/ respectively.
$saves_path entries are directory placeholders (excluded).
$roms_path entries (neogeo.zip etc.) get roms/ prefix in destination.
Entries with no paths key default to bios/ (RetroDECK's default BIOS dir).

Verification logic (api_data_processing.sh:289-405):
  - md5sum per file, compared against known_md5 (comma-separated list)
  - envsubst resolves path tokens at runtime
  - Multi-threaded on system_cpu_max_threads
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path

try:
    from .base_scraper import BaseScraper, BiosRequirement
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from scraper.base_scraper import BaseScraper, BiosRequirement

PLATFORM_NAME = "retrodeck"
COMPONENTS_REPO = "RetroDECK/components"
COMPONENTS_BRANCH = "main"
COMPONENTS_API_URL = (
    f"https://api.github.com/repos/{COMPONENTS_REPO}"
    f"/git/trees/{COMPONENTS_BRANCH}"
)
RAW_BASE = (
    f"https://raw.githubusercontent.com/{COMPONENTS_REPO}"
    f"/{COMPONENTS_BRANCH}"
)
SKIP_DIRS = {"archive_later", "archive_old", "automation-tools", ".github"}
NON_EMULATOR_COMPONENTS = {
    "framework", "es-de", "steam-rom-manager", "flips", "portmaster",
}

# RetroDECK system ID -> retrobios slug.
# None = skip (system not relevant for BIOS packs).
# Missing key = pass through as-is.
SYSTEM_SLUG_MAP: dict[str, str | None] = {
    # Nintendo
    "nes": "nintendo-nes",
    "snes": "nintendo-snes",
    "snesna": "nintendo-snes",
    "n64": "nintendo-64",
    "n64dd": "nintendo-64dd",
    "gc": "nintendo-gamecube",
    "wii": "nintendo-wii",
    "wiiu": "nintendo-wii-u",
    "switch": "nintendo-switch",
    "gb": "nintendo-gb",
    "gbc": "nintendo-gbc",
    "gba": "nintendo-gba",
    "nds": "nintendo-ds",
    "3ds": "nintendo-3ds",
    "n3ds": "nintendo-3ds",
    "fds": "nintendo-fds",
    "sgb": "nintendo-sgb",
    "virtualboy": "nintendo-virtual-boy",
    # Sony
    "psx": "sony-playstation",
    "ps2": "sony-playstation-2",
    "ps3": "sony-playstation-3",
    "psp": "sony-psp",
    "psvita": "sony-psvita",
    # Sega
    "megadrive": "sega-mega-drive",
    "genesis": "sega-mega-drive",
    "megacd": "sega-mega-cd",
    "megacdjp": "sega-mega-cd",
    "segacd": "sega-mega-cd",
    "saturn": "sega-saturn",
    "saturnjp": "sega-saturn",
    "dreamcast": "sega-dreamcast",
    "naomi": "sega-dreamcast-arcade",
    "naomi2": "sega-dreamcast-arcade",
    "atomiswave": "sega-dreamcast-arcade",
    "gamegear": "sega-game-gear",
    "mastersystem": "sega-master-system",
    "sms": "sega-master-system",
    # NEC
    "pcengine": "nec-pc-engine",
    "pcenginecd": "nec-pc-engine",
    "turbografx16": "nec-pc-engine",
    "pcfx": "nec-pc-fx",
    "pc98": "nec-pc-98",
    "pc9800": "nec-pc-98",
    "pc88": "nec-pc-88",
    "pc8800": "nec-pc-88",
    # Other
    "3do": "3do",
    "amstradcpc": "amstrad-cpc",
    "arcade": "arcade",
    "mame": "arcade",
    "fbneo": "arcade",
    "atari800": "atari-400-800",
    "atari5200": "atari-5200",
    "atari7800": "atari-7800",
    "atarijaguar": "atari-jaguar",
    "atarilynx": "atari-lynx",
    "atarist": "atari-st",
    "atarixe": "atari-400-800",
    "c64": "commodore-c64",
    "amiga": "commodore-amiga",
    "cdimono1": "philips-cdi",
    "channelf": "fairchild-channel-f",
    "colecovision": "coleco-colecovision",
    "intellivision": "mattel-intellivision",
    "msx": "microsoft-msx",
    "xbox": "microsoft-xbox",
    "doom": "doom",
    "j2me": "j2me",
    "mac2": "apple-macintosh-ii",
    "macintosh": "apple-macintosh-ii",
    "apple2": "apple-ii",
    "apple2gs": "apple-iigs",
    "enterprise": "enterprise-64-128",
    "gamecom": "tiger-game-com",
    "gmaster": "hartung-game-master",
    "pokemini": "nintendo-pokemon-mini",
    "scv": "epoch-scv",
    "supervision": "watara-supervision",
    "wonderswan": "bandai-wonderswan",
    "neogeocd": "snk-neogeo-cd",
    "neogeocdjp": "snk-neogeo-cd",
    "coco": "tandy-coco",
    "trs80": "tandy-trs-80",
    "dragon": "dragon-32-64",
    "tanodragon": "dragon-32-64",
    "pico8": "pico8",
    "wolfenstein": "wolfenstein-3d",
    "zxspectrum": "sinclair-zx-spectrum",
}


def _sanitize_path(p: str) -> str:
    """Fix upstream typos in path tokens."""
    return re.sub(r"\$saves_\w+", "$saves_path", p)


def _resolve_path(p: str) -> str:
    """Resolve RetroDECK path tokens to pack-relative paths."""
    p = _sanitize_path(p)
    p = p.replace("$bios_path", "bios")
    p = p.replace("$saves_path", "saves")
    p = p.replace("$roms_path", "roms")
    return p.strip("/")


def _extract_bios_entries(component_val: dict) -> list[dict]:
    """Extract BIOS entries from all three possible locations in a component.

    No dedup here — dedup is done in fetch_requirements() with full
    (system, filename) key to avoid dropping valid same-filename entries
    across different systems.
    """
    entries: list[dict] = []

    def collect(bios_data: list | dict) -> None:
        if isinstance(bios_data, dict):
            bios_data = [bios_data]
        if not isinstance(bios_data, list):
            return
        for entry in bios_data:
            if isinstance(entry, dict) and entry.get("filename", "").strip():
                entries.append(entry)

    if "bios" in component_val:
        collect(component_val["bios"])

    pa = component_val.get("preset_actions", {})
    if isinstance(pa, dict) and "bios" in pa:
        collect(pa["bios"])

    cores = component_val.get("cores", {})
    if isinstance(cores, dict) and "bios" in cores:
        collect(cores["bios"])

    return entries


def _map_system(raw_system: str) -> str | None:
    """Map RetroDECK system ID to retrobios slug.

    Returns None for systems explicitly excluded from the map.
    Unknown systems pass through as-is.
    """
    if raw_system in SYSTEM_SLUG_MAP:
        return SYSTEM_SLUG_MAP[raw_system]
    return raw_system


class Scraper(BaseScraper):
    """RetroDECK BIOS scraper from component manifests."""

    platform_name = PLATFORM_NAME

    def __init__(self, manifests_dir: str = "") -> None:
        super().__init__()
        self.manifests_dir = manifests_dir
        self._manifests: list[tuple[str, dict]] | None = None

    def _get_manifests(self) -> list[tuple[str, dict]]:
        """Fetch manifests once, cache for reuse."""
        if self._manifests is None:
            self._manifests = (
                self._fetch_local_manifests()
                if self.manifests_dir
                else self._fetch_remote_manifests()
            )
        return self._manifests

    def _fetch_remote_manifests(self) -> list[tuple[str, dict]]:
        """Fetch component manifests via GitHub API."""
        token = os.environ.get("GITHUB_TOKEN", "")
        headers = {"User-Agent": "retrobios-scraper/1.0"}
        if token:
            headers["Authorization"] = f"token {token}"

        try:
            req = urllib.request.Request(COMPONENTS_API_URL, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                tree = json.loads(resp.read().decode())
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            raise ConnectionError(f"Failed to fetch component tree: {e}") from e

        if tree.get("truncated"):
            print("  WARNING: GitHub tree response truncated", file=sys.stderr)

        component_dirs = [
            item["path"]
            for item in tree.get("tree", [])
            if item["type"] == "tree" and item["path"] not in SKIP_DIRS
        ]

        manifests: list[tuple[str, dict]] = []
        for comp in sorted(component_dirs):
            url = f"{RAW_BASE}/{comp}/component_manifest.json"
            print(f"  {comp} ...", file=sys.stderr, end="", flush=True)
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode())
                manifests.append((comp, data))
                print(" ok", file=sys.stderr)
            except (urllib.error.HTTPError, urllib.error.URLError):
                print(" skip", file=sys.stderr)
            except json.JSONDecodeError as e:
                print(f" parse error: {e}", file=sys.stderr)
        return manifests

    def _fetch_local_manifests(self) -> list[tuple[str, dict]]:
        """Read manifests from local RetroDECK install."""
        root = Path(self.manifests_dir)
        manifests: list[tuple[str, dict]] = []
        for d in sorted(root.iterdir()):
            if not d.is_dir() or d.name in SKIP_DIRS or d.name.startswith("."):
                continue
            mf = d / "component_manifest.json"
            if not mf.exists():
                continue
            try:
                with open(mf) as f:
                    manifests.append((d.name, json.load(f)))
            except (json.JSONDecodeError, OSError) as e:
                print(f"  WARNING: {mf}: {e}", file=sys.stderr)
        return manifests

    def validate_format(self, raw_data: str) -> bool:
        try:
            return isinstance(json.loads(raw_data), dict)
        except (json.JSONDecodeError, TypeError):
            return False

    def fetch_requirements(self) -> list[BiosRequirement]:
        manifests = self._get_manifests()

        requirements: list[BiosRequirement] = []
        seen: set[tuple[str, str]] = set()

        for comp_name, manifest in manifests:
            for comp_key, comp_val in manifest.items():
                if not isinstance(comp_val, dict):
                    continue

                default_system = comp_val.get("system", comp_key)
                if isinstance(default_system, list):
                    default_system = default_system[0] if default_system else comp_key

                for entry in _extract_bios_entries(comp_val):
                    filename = entry["filename"].strip()
                    raw_system = entry.get("system", default_system)
                    if isinstance(raw_system, list):
                        raw_system = raw_system[0] if raw_system else default_system

                    system = _map_system(str(raw_system))
                    if system is None:
                        continue

                    # Resolve path
                    paths_raw = entry.get("paths")
                    if isinstance(paths_raw, str):
                        resolved = _resolve_path(paths_raw)
                    elif isinstance(paths_raw, list):
                        resolved = ""
                        for p in paths_raw:
                            rp = _resolve_path(str(p))
                            if not rp.startswith("saves"):
                                resolved = rp
                                break
                        if not resolved:
                            continue
                    else:
                        resolved = ""

                    # Skip saves-only entries
                    if resolved.startswith("saves"):
                        continue

                    # Build destination — default to bios/ if no path specified
                    if resolved:
                        destination = f"{resolved}/{filename}"
                    else:
                        destination = f"bios/{filename}"

                    # MD5 handling — sanitize upstream errors
                    md5_raw = entry.get("md5", "")
                    if isinstance(md5_raw, list):
                        parts = [str(m).strip().lower() for m in md5_raw if m]
                    elif md5_raw:
                        parts = [str(md5_raw).strip().lower()]
                    else:
                        parts = []
                    # Keep only valid 32-char hex MD5 hashes
                    valid = [p for p in parts if re.fullmatch(r"[0-9a-f]{32}", p)]
                    md5 = ",".join(valid)

                    required_raw = entry.get("required", "")
                    required = bool(required_raw) and str(required_raw).lower() not in (
                        "false", "no", "optional", "",
                    )

                    key = (system, filename.lower())
                    if key in seen:
                        existing = next(
                            (r for r in requirements if (r.system, r.name.lower()) == key),
                            None,
                        )
                        if existing and md5 and existing.md5 and md5 != existing.md5:
                            print(
                                f"  WARNING: {filename} ({system}): MD5 conflict "
                                f"({existing.md5[:12]}... vs {md5[:12]}...)",
                                file=sys.stderr,
                            )
                        continue
                    seen.add(key)

                    requirements.append(BiosRequirement(
                        name=filename,
                        system=system,
                        destination=destination,
                        md5=md5,
                        required=required,
                    ))

        return requirements

    def generate_platform_yaml(self) -> dict:
        reqs = self.fetch_requirements()
        manifests = self._get_manifests()

        cores = sorted({
            comp_name for comp_name, _ in manifests
            if comp_name not in SKIP_DIRS
            and comp_name not in NON_EMULATOR_COMPONENTS
        })

        systems: dict[str, dict] = {}
        for req in reqs:
            sys_entry = systems.setdefault(req.system, {"files": []})
            file_entry: dict = {
                "name": req.name,
                "destination": req.destination,
                "required": req.required,
            }
            if req.md5:
                file_entry["md5"] = req.md5
            sys_entry["files"].append(file_entry)

        return {
            "platform": "RetroDECK",
            "version": "",
            "homepage": "https://retrodeck.net",
            "source": "https://github.com/RetroDECK/components",
            "base_destination": "",
            "hash_type": "md5",
            "verification_mode": "md5",
            "cores": cores,
            "systems": systems,
        }


def main() -> None:
    from scraper.base_scraper import scraper_cli
    scraper_cli(Scraper, "Scrape RetroDECK BIOS requirements")


if __name__ == "__main__":
    main()
