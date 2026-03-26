"""Scraper for RetroPie libretro core availability per platform.

Source: https://github.com/RetroPie/RetroPie-Setup/tree/master/scriptmodules/libretrocores
Parses rp_module_id and rp_module_flags from each scriptmodule to determine
which platforms each core supports.
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

PLATFORM_NAME = "retropie"

GITHUB_API_URL = (
    "https://api.github.com/repos/RetroPie/RetroPie-Setup/contents"
    "/scriptmodules/libretrocores"
)
RAW_BASE_URL = (
    "https://raw.githubusercontent.com/RetroPie/RetroPie-Setup/master"
    "/scriptmodules/libretrocores/"
)

# Platform flag sets: flags that the platform possesses
PLATFORM_FLAGS: dict[str, set[str]] = {
    "rpi1": {"arm", "armv6", "rpi", "gles"},
    "rpi2": {"arm", "armv7", "neon", "rpi", "gles"},
    "rpi3": {"arm", "armv8", "neon", "rpi", "gles"},
    "rpi4": {"arm", "armv8", "neon", "rpi", "gles", "gles3", "gles31"},
    "rpi5": {"arm", "armv8", "neon", "rpi", "gles", "gles3", "gles31"},
    "x86": {"x86"},
    "x86_64": {"x86"},
}

ARCH_MAP: dict[str, str] = {
    "rpi1": "armv6",
    "rpi2": "armv7",
    "rpi3": "armv7",
    "rpi4": "aarch64",
    "rpi5": "aarch64",
    "x86": "x86",
    "x86_64": "x86_64",
}

# Flags that are build directives, not platform restrictions
_BUILD_FLAGS = {"nodistcc"}

_MODULE_ID_RE = re.compile(r'rp_module_id\s*=\s*["\']([^"\']+)["\']')
_MODULE_FLAGS_RE = re.compile(r'rp_module_flags\s*=\s*["\']([^"\']*)["\']')


def _fetch(url: str, accept: str = "text/plain") -> str | None:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "retrobios-scraper/1.0", "Accept": accept},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.URLError as e:
        print(f"  skip {url}: {e}", file=sys.stderr)
        return None


def _is_available(flags_str: str, platform: str) -> bool:
    """Return True if the core is available on the given platform."""
    platform_has = PLATFORM_FLAGS.get(platform, set())
    tokens = flags_str.split() if flags_str.strip() else []

    for token in tokens:
        if token in _BUILD_FLAGS:
            continue
        if token.startswith("!"):
            # Exclusion: if platform has this flag, core is excluded
            flag = token[1:]
            if flag in platform_has:
                return False
        else:
            # Requirement: platform must have this flag
            if token not in platform_has:
                return False

    return True


def _parse_module(content: str) -> tuple[str | None, str]:
    """Return (module_id, flags_string) from a scriptmodule file."""
    id_match = _MODULE_ID_RE.search(content)
    flags_match = _MODULE_FLAGS_RE.search(content)
    module_id = id_match.group(1) if id_match else None
    flags = flags_match.group(1) if flags_match else ""
    return module_id, flags


class Scraper(BaseTargetScraper):
    """Fetches RetroPie libretro core availability by parsing scriptmodules."""

    def __init__(self, url: str = GITHUB_API_URL):
        super().__init__(url=url)

    def _list_scriptmodules(self) -> list[str]:
        """Return list of .sh filenames from the libretrocores directory."""
        raw = _fetch(self.url, accept="application/vnd.github+json")
        if raw is None:
            return []
        try:
            entries = json.loads(raw)
        except json.JSONDecodeError as e:
            print(f"  JSON parse error: {e}", file=sys.stderr)
            return []
        return [e["name"] for e in entries if e.get("name", "").endswith(".sh")]

    def _fetch_module(self, filename: str) -> str | None:
        return _fetch(f"{RAW_BASE_URL}{filename}")

    def fetch_targets(self) -> dict:
        print("  listing RetroPie scriptmodules...", file=sys.stderr)
        filenames = self._list_scriptmodules()
        if not filenames:
            print("  warning: no scriptmodules found", file=sys.stderr)

        # {platform: [core_id, ...]}
        platform_cores: dict[str, list[str]] = {p: [] for p in PLATFORM_FLAGS}

        for filename in filenames:
            content = self._fetch_module(filename)
            if content is None:
                continue
            module_id, flags = _parse_module(content)
            if not module_id:
                print(f"  warning: no rp_module_id in {filename}", file=sys.stderr)
                continue
            for platform in PLATFORM_FLAGS:
                if _is_available(flags, platform):
                    platform_cores[platform].append(module_id)

        print(f"  parsed {len(filenames)} scriptmodules", file=sys.stderr)

        targets: dict[str, dict] = {}
        for platform, arch in ARCH_MAP.items():
            cores = sorted(platform_cores.get(platform, []))
            targets[platform] = {
                "architecture": arch,
                "cores": cores,
            }

        return {
            "platform": "retropie",
            "source": self.url,
            "scraped_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "targets": targets,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scrape RetroPie libretro core targets from scriptmodules"
    )
    parser.add_argument("--dry-run", action="store_true", help="Show target summary")
    parser.add_argument("--output", "-o", help="Output YAML file")
    args = parser.parse_args()

    scraper = Scraper()
    data = scraper.fetch_targets()

    if args.dry_run:
        for name, info in data["targets"].items():
            print(f"  {name} ({info['architecture']}): {len(info['cores'])} cores")
        return

    if args.output:
        scraper.write_output(data, args.output)
        print(f"Written to {args.output}")
        return

    print(yaml.dump(data, default_flow_style=False, sort_keys=False))


if __name__ == "__main__":
    main()
