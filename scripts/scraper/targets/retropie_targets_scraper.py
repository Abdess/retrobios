"""Scraper for RetroPie package availability per platform.

Source: https://github.com/RetroPie/RetroPie-Setup/tree/master/scriptmodules
Parses rp_module_id and rp_module_flags from each scriptmodule of the
package sections the platform list reads (emulators, libretrocores, ports)
to determine which platforms each package supports.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

import yaml

from . import BaseTargetScraper

PLATFORM_NAME = "retropie"

GITHUB_API_URL = (
    "https://api.github.com/repos/RetroPie/RetroPie-Setup/contents/scriptmodules"
)
RAW_BASE_URL = (
    "https://raw.githubusercontent.com/RetroPie/RetroPie-Setup/master/scriptmodules/"
)
# The sections the platform scraper reads: a standalone package missing here
# is filtered out of every targeted pack.
PACKAGE_DIRS = ("emulators", "libretrocores", "ports")

# The flags RetroPie's set_platform_defaults, cpu_* and platform_* functions
# give each platform (scriptmodules/system.sh), with the video stack of the
# images it ships: videocore and dispmanx on rpi1-3, kms with fkms dispmanx
# on rpi4 (buster), kms on rpi5.
PLATFORM_FLAGS: dict[str, set[str]] = {
    "rpi1": {"rpi1", "32bit", "arm", "armv6", "rpi", "gles", "videocore", "dispmanx"},
    "rpi2": {"rpi2", "32bit", "arm", "armv7", "neon", "rpi", "gles", "videocore",
             "dispmanx"},
    "rpi3": {"rpi3", "32bit", "arm", "armv8", "neon", "rpi", "gles", "videocore",
             "dispmanx"},
    "rpi4": {"rpi4", "32bit", "arm", "armv8", "neon", "rpi", "gles", "gles3", "gles31",
             "mesa", "kms", "dispmanx"},
    "rpi5": {"rpi5", "32bit", "arm", "armv8", "neon", "rpi", "gles", "gles3", "gles31",
             "mesa", "kms"},
    "x86": {"x86", "32bit", "gl", "vulkan", "x11"},
    "x86_64": {"x86", "64bit", "gl", "vulkan", "x11"},
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

_MODULE_ID_RE = re.compile(r'rp_module_id\s*=\s*["\']([^"\']+)["\']')
_MODULE_FLAGS_RE = re.compile(r'rp_module_flags\s*=\s*["\']([^"\']*)["\']')


def _fetch(url: str, accept: str = "text/plain") -> str:
    headers = {"User-Agent": "retrobios-scraper/1.0", "Accept": accept}
    token = os.environ.get("GITHUB_TOKEN")
    if token and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.URLError as e:
        # A target written from a failed request loses its cores in silence.
        raise RuntimeError(f"cannot fetch {url}: {e}") from e


def _is_available(flags_str: str, platform: str) -> bool:
    """Whether RetroPie enables a module on *platform*.

    Port of rp_registerModule (scriptmodules/packages.sh): flags are read in
    order from an enabled default; !all disables, a flag the platform has
    enables, !flag disables when the platform has it. A flag the platform
    does not know (sdl1, nodistcc) changes nothing, and a comparison against
    the build host (:$__gcc_version:-lt:7) cannot be decided here, so it
    leaves the module as it was.
    """
    platform_has = PLATFORM_FLAGS.get(platform, set())
    enabled = True
    for token in flags_str.split():
        if token == "!all":
            enabled = False
        elif token in platform_has:
            enabled = True
        elif token.startswith("!") and token[1:] in platform_has:
            enabled = False
    return enabled


def _parse_module(content: str) -> tuple[str | None, str]:
    """Return (module_id, flags_string) from a scriptmodule file."""
    id_match = _MODULE_ID_RE.search(content)
    flags_match = _MODULE_FLAGS_RE.search(content)
    module_id = id_match.group(1) if id_match else None
    flags = flags_match.group(1) if flags_match else ""
    return module_id, flags


class Scraper(BaseTargetScraper):
    """Fetches RetroPie package availability by parsing scriptmodules."""

    def __init__(self, url: str = GITHUB_API_URL):
        super().__init__(url=url)

    def _list_scriptmodules(self) -> list[str]:
        """Return section/filename for every .sh of the package sections."""
        names: list[str] = []
        for section in PACKAGE_DIRS:
            url = f"{self.url}/{section}"
            entries = json.loads(_fetch(url, accept="application/vnd.github+json"))
            listed = [
                f"{section}/{e['name']}" for e in entries if e.get("name", "").endswith(".sh")
            ]
            if not listed:
                raise RuntimeError(f"no scriptmodules listed at {url}")
            names.extend(listed)
        return names

    def _fetch_module(self, filename: str) -> str:
        return _fetch(f"{RAW_BASE_URL}{filename}")

    def fetch_targets(self) -> dict:
        print("  listing RetroPie scriptmodules...", file=sys.stderr)
        filenames = self._list_scriptmodules()

        # {platform: [core_id, ...]}
        platform_cores: dict[str, list[str]] = {p: [] for p in PLATFORM_FLAGS}

        for filename in filenames:
            content = self._fetch_module(filename)
            module_id, flags = _parse_module(content)
            if not module_id:
                print(f"  warning: no rp_module_id in {filename}", file=sys.stderr)
                continue
            # A libretro package is lr-<core> with the buildbot name hyphenated
            # (lr-beetle-psx -> beetle_psx); a standalone package keeps the id
            # the platform list carries (dosbox-staging).
            core_name = module_id
            if core_name.startswith("lr-"):
                core_name = core_name[3:].replace("-", "_")
            for platform in PLATFORM_FLAGS:
                if _is_available(flags, platform):
                    platform_cores[platform].append(core_name)

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
        description="Scrape RetroPie package targets from scriptmodules"
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
