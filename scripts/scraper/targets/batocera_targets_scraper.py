"""Scraper for Batocera per-board emulator availability.

Sources (batocera-linux/batocera.linux):
  - configs/batocera-*.board  — board definitions, each sets BR2_PACKAGE_BATOCERA_TARGET_*
  - package/batocera/core/batocera-system/Config.in — flag-to-package mapping
  - es_systems.yml — emulator-to-requireAnyOf flag mapping
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

PLATFORM_NAME = "batocera"

GITHUB_API = "https://api.github.com/repos/batocera-linux/batocera.linux/contents"
RAW_BASE = "https://raw.githubusercontent.com/batocera-linux/batocera.linux/master"

CONFIG_IN_URL = (
    f"{RAW_BASE}/package/batocera/core/batocera-system/Config.in"
)
ES_SYSTEMS_URL = (
    f"{RAW_BASE}/package/batocera/emulationstation/batocera-emulationstation/"
    "es_systems.yml"
)

_HEADERS = {
    "User-Agent": "retrobios-scraper/1.0",
    "Accept": "application/vnd.github.v3+json",
}

_TARGET_FLAG_RE = re.compile(r'^(BR2_PACKAGE_BATOCERA_TARGET_\w+)=y', re.MULTILINE)
_REQUIRE_ANYOF_RE = re.compile(
    r'requireAnyOf\s*:\s*\[([^\]]+)\]', re.MULTILINE
)


def _arch_from_flag(flag: str) -> str:
    """Guess architecture from board flag name."""
    low = flag.lower()
    if "x86_64" in low or "x86-64" in low:
        return "x86_64"
    if "x86" in low and "64" not in low:
        return "x86"
    return "aarch64"


def _fetch(url: str, headers: dict | None = None) -> str | None:
    h = headers or {"User-Agent": "retrobios-scraper/1.0"}
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.URLError as e:
        print(f"  skip {url}: {e}", file=sys.stderr)
        return None


def _fetch_json(url: str) -> list | dict | None:
    text = _fetch(url, headers=_HEADERS)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        print(f"  json parse error {url}: {e}", file=sys.stderr)
        return None


def _parse_config_in(text: str) -> dict[str, list[str]]:
    """Parse Config.in: map BR2_PACKAGE_BATOCERA_TARGET_* flags to packages."""
    flag_to_packages: dict[str, list[str]] = {}
    # Find blocks: if BR2_PACKAGE_BATOCERA_TARGET_X ... select BR2_PACKAGE_Y
    block_re = re.compile(
        r'if\s+(BR2_PACKAGE_BATOCERA_TARGET_\w+)(.*?)endif',
        re.DOTALL,
    )
    select_re = re.compile(r'select\s+(BR2_PACKAGE_\w+)')
    for m in block_re.finditer(text):
        flag = m.group(1)
        block = m.group(2)
        packages = select_re.findall(block)
        flag_to_packages.setdefault(flag, []).extend(packages)
    return flag_to_packages


def _parse_es_systems(text: str) -> dict[str, list[str]]:
    """Parse es_systems.yml: map emulator name to list of requireAnyOf flags."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return {}

    emulator_flags: dict[str, list[str]] = {}
    if not isinstance(data, dict):
        return emulator_flags

    systems = data.get("systems", data) if "systems" in data else data
    if not isinstance(systems, list):
        # Could be a dict
        systems = list(systems.values()) if isinstance(systems, dict) else []

    for system in systems:
        if not isinstance(system, dict):
            continue
        for emulator_entry in system.get("emulators", []):
            if not isinstance(emulator_entry, dict):
                continue
            for emu_name, emu_data in emulator_entry.items():
                if not isinstance(emu_data, dict):
                    continue
                require = emu_data.get("requireAnyOf", [])
                if isinstance(require, list):
                    emulator_flags.setdefault(emu_name, []).extend(require)

    return emulator_flags


class Scraper(BaseTargetScraper):
    """Cross-references Batocera boards, Config.in, and es_systems to build target lists."""

    def __init__(self, url: str = "https://github.com/batocera-linux/batocera.linux"):
        super().__init__(url=url)

    def _list_boards(self) -> list[str]:
        """List batocera-*.board files from configs/ via GitHub API."""
        data = _fetch_json(f"{GITHUB_API}/configs")
        if not data or not isinstance(data, list):
            return []
        return [
            item["name"] for item in data
            if isinstance(item, dict)
            and item.get("name", "").startswith("batocera-")
            and item.get("name", "").endswith(".board")
        ]

    def _fetch_board_flag(self, board_name: str) -> str | None:
        """Fetch a board file and extract its BR2_PACKAGE_BATOCERA_TARGET_* flag."""
        url = f"{RAW_BASE}/configs/{board_name}"
        text = _fetch(url)
        if text is None:
            return None
        m = _TARGET_FLAG_RE.search(text)
        return m.group(1) if m else None

    def fetch_targets(self) -> dict:
        """Build per-board emulator availability map."""
        print("  fetching board list...", file=sys.stderr)
        boards = self._list_boards()
        if not boards:
            print("  warning: no boards found", file=sys.stderr)

        print("  fetching Config.in...", file=sys.stderr)
        config_in_text = _fetch(CONFIG_IN_URL)
        flag_to_packages: dict[str, list[str]] = {}
        if config_in_text:
            flag_to_packages = _parse_config_in(config_in_text)

        print("  fetching es_systems.yml...", file=sys.stderr)
        es_text = _fetch(ES_SYSTEMS_URL)
        emulator_flags: dict[str, list[str]] = {}
        if es_text:
            emulator_flags = _parse_es_systems(es_text)

        # Build reverse index: package -> emulators
        package_to_emulators: dict[str, list[str]] = {}
        for emu, flags in emulator_flags.items():
            for flag in flags:
                package_to_emulators.setdefault(flag, []).append(emu)

        targets: dict[str, dict] = {}
        for board_name in sorted(boards):
            target_key = board_name.removeprefix("batocera-").removesuffix(".board")
            print(f"  processing {target_key}...", file=sys.stderr)
            flag = self._fetch_board_flag(board_name)
            if flag is None:
                continue

            arch = _arch_from_flag(flag)
            selected_packages = set(flag_to_packages.get(flag, []))

            # Find emulators available for this board
            emulators: set[str] = set()
            for pkg, emus in package_to_emulators.items():
                if pkg in selected_packages:
                    emulators.update(emus)

            targets[target_key] = {
                "architecture": arch,
                "cores": sorted(emulators),
            }

        return {
            "platform": "batocera",
            "source": self.url,
            "scraped_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "targets": targets,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scrape Batocera per-board emulator targets"
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
