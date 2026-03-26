"""Scraper for EmuDeck emulator targets.

Sources:
  SteamOS: dragoonDorise/EmuDeck — functions/EmuScripts/*.sh
  Windows: EmuDeck/emudeck-we — functions/EmuScripts/*.ps1
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

import yaml

from . import BaseTargetScraper

PLATFORM_NAME = "emudeck"

STEAMOS_API = "https://api.github.com/repos/dragoonDorise/EmuDeck/contents/functions/EmuScripts"
WINDOWS_API = "https://api.github.com/repos/EmuDeck/emudeck-we/contents/functions/EmuScripts"

# Map EmuDeck script names to emulator profile keys
# Script naming: emuDeckDolphin.sh -> dolphin
# Some need explicit mapping when names differ
_NAME_OVERRIDES: dict[str, str] = {
    "pcsx2qt": "pcsx2",
    "rpcs3legacy": "rpcs3",
    "cemuproton": "cemu",
    "rmg": "mupen64plus_next",
    "bigpemu": "bigpemu",
    "eden": "eden",
    "suyu": "suyu",
    "ares": "ares",
}

# Scripts that are not emulators (config helpers, etc.)
_SKIP = {"retroarch_maincfg", "retroarch"}


def _fetch(url: str) -> str | None:
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "retrobios-scraper/1.0"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.URLError as e:
        print(f"  skip {url}: {e}", file=sys.stderr)
        return None


def _list_emuscripts(api_url: str) -> list[str]:
    """List emulator script filenames from GitHub API."""
    raw = _fetch(api_url)
    if not raw:
        return []
    entries = json.loads(raw)
    names = []
    for e in entries:
        name = e.get("name", "")
        if name.endswith(".sh") or name.endswith(".ps1"):
            names.append(name)
    return names


def _script_to_core(filename: str) -> str | None:
    """Convert EmuScripts filename to core profile key."""
    # Strip extension and emuDeck prefix
    name = re.sub(r'\.(sh|ps1)$', '', filename, flags=re.IGNORECASE)
    name = re.sub(r'^emuDeck', '', name, flags=re.IGNORECASE)
    if not name:
        return None
    key = name.lower()
    if key in _SKIP:
        return None
    return _NAME_OVERRIDES.get(key, key)


class Scraper(BaseTargetScraper):
    """Fetches emulator lists for EmuDeck SteamOS and Windows targets."""

    def __init__(self, url: str = "https://github.com/dragoonDorise/EmuDeck"):
        super().__init__(url=url)

    def _fetch_cores_for_target(self, api_url: str, label: str,
                                arch: str = "x86_64") -> list[str]:
        print(f"  fetching {label} EmuScripts...", file=sys.stderr)
        scripts = _list_emuscripts(api_url)
        cores: list[str] = []
        seen: set[str] = set()
        has_retroarch = False
        for script in scripts:
            core = _script_to_core(script)
            if core and core not in seen:
                seen.add(core)
                cores.append(core)
            # Detect RetroArch presence (provides all libretro cores)
            name = re.sub(r'\.(sh|ps1)$', '', script, flags=re.IGNORECASE)
            if name.lower() in ("emudeckretroarch", "retroarch_maincfg"):
                has_retroarch = True

        standalone_count = len(cores)
        # EmuDeck ships RetroArch = all its libretro cores are available
        if has_retroarch:
            ra_cores = self._load_retroarch_cores(arch)
            for c in ra_cores:
                if c not in seen:
                    seen.add(c)
                    cores.append(c)

        print(f"    {label}: {standalone_count} standalone + "
              f"{len(cores) - standalone_count} via RetroArch = {len(cores)} total",
              file=sys.stderr)
        return sorted(cores)

    @staticmethod
    def _load_retroarch_cores(arch: str) -> list[str]:
        """Load RetroArch target cores for given architecture."""
        import os
        target_path = os.path.join("platforms", "targets", "retroarch.yml")
        if not os.path.exists(target_path):
            return []
        with open(target_path) as f:
            data = yaml.safe_load(f) or {}
        # Find a target matching the architecture
        for tname, tinfo in data.get("targets", {}).items():
            if tinfo.get("architecture") == arch:
                return tinfo.get("cores", [])
        return []

    def fetch_targets(self) -> dict:
        steamos_cores = self._fetch_cores_for_target(STEAMOS_API, "SteamOS")
        windows_cores = self._fetch_cores_for_target(WINDOWS_API, "Windows")

        targets: dict[str, dict] = {}
        if steamos_cores:
            targets["steamos"] = {
                "architecture": "x86_64",
                "cores": steamos_cores,
            }
        if windows_cores:
            targets["windows"] = {
                "architecture": "x86_64",
                "cores": windows_cores,
            }

        return {
            "platform": "emudeck",
            "source": self.url,
            "scraped_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "targets": targets,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scrape EmuDeck emulator targets"
    )
    parser.add_argument("--dry-run", action="store_true", help="Show target summary")
    parser.add_argument("--output", "-o", help="Output YAML file")
    args = parser.parse_args()

    scraper = Scraper()
    data = scraper.fetch_targets()

    if args.dry_run:
        for name, info in data["targets"].items():
            print(f"  {name} ({info['architecture']}): {len(info['cores'])} emulators")
        return

    if args.output:
        scraper.write_output(data, args.output)
        print(f"Written to {args.output}")
        return

    print(yaml.dump(data, default_flow_style=False, sort_keys=False))


if __name__ == "__main__":
    main()
