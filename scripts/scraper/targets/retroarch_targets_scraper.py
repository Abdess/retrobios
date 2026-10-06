"""Scraper for RetroArch buildbot nightly targets.

Source: https://buildbot.libretro.com/nightly/
Fetches directory listings per target to determine available cores.

Buildbot structure varies by platform:
- linux:       {path}/latest/  -> *_libretro.so.zip
- windows:     {path}/latest/  -> *_libretro.dll.zip
- apple/osx:   {path}/latest/  -> *_libretro.dylib.zip
- android:     android/latest/{arch}/  -> *_libretro_android.so.zip
- switch:      nintendo/switch/libnx/latest/  -> *_libretro_libnx.nro.zip
- 3ds:         nintendo/3ds/latest/3dsx/  -> *_libretro.3dsx.zip
- wii/ngc:     {path}/latest/  -> *_libretro_{plat}.dol.zip
- wiiu:        nintendo/wiiu/latest/  -> *_libretro.rpx.zip
- psp:         playstation/psp/latest/  -> *_libretro_psp.PBP.zip
- ps2:         playstation/ps2/latest/  -> *_libretro_ps2.elf.zip
- vita:        bundles only (VPK) - no individual cores
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

import yaml

from . import BaseTargetScraper

PLATFORM_NAME = "retroarch"

BUILDBOT_URL = "https://buildbot.libretro.com/nightly/"

# (url_path_under_nightly, target_name, architecture)
# url_path must end at the directory containing core files
TARGETS: list[tuple[str, str, str]] = [
    ("linux/x86_64/latest", "linux-x86_64", "x86_64"),
    ("linux/armhf/latest", "linux-armhf", "armhf"),
    ("linux/armv7-neon-hf/latest", "linux-armv7-neon-hf", "armv7"),
    ("windows/x86_64/latest", "windows-x86_64", "x86_64"),
    ("windows/x86/latest", "windows-x86", "x86"),
    ("android/latest/arm64-v8a", "android-arm64-v8a", "aarch64"),
    ("android/latest/armeabi-v7a", "android-armeabi-v7a", "armv7"),
    ("android/latest/x86_64", "android-x86_64", "x86_64"),
    ("android/latest/x86", "android-x86", "x86"),
    ("apple/osx/x86_64/latest", "osx-x86_64", "x86_64"),
    ("apple/osx/arm64/latest", "osx-arm64", "aarch64"),
    ("apple/ios-arm64/latest", "ios-arm64", "aarch64"),
    ("apple/tvos-arm64/latest", "tvos-arm64", "aarch64"),
    ("nintendo/switch/libnx/latest", "nintendo-switch", "aarch64"),
    ("nintendo/3ds/latest/3dsx", "nintendo-3ds", "arm"),
    ("nintendo/ngc/latest", "nintendo-gamecube", "ppc"),
    ("nintendo/wii/latest", "nintendo-wii", "ppc"),
    ("nintendo/wiiu/latest", "nintendo-wiiu", "ppc"),
    ("playstation/ps2/latest", "playstation-ps2", "mips"),
    ("playstation/psp/latest", "playstation-psp", "mips"),
    # vita: only VPK bundles on buildbot -cores listed via libretro-super recipes
]

# Recipe-based targets: (recipe_path_under_RECIPE_BASE_URL, target_name, architecture)
RECIPE_TARGETS: list[tuple[str, str, str]] = [
    ("playstation/vita", "playstation-vita", "armv7"),
]

RECIPE_BASE_URL = (
    "https://raw.githubusercontent.com/libretro/libretro-super/master/recipes/"
)

# Match any href containing _libretro followed by a platform-specific extension
# Covers: .so.zip, .dll.zip, .dylib.zip, .nro.zip, .dol.zip, .rpx.zip,
#         .3dsx.zip, .PBP.zip, .elf.zip, _android.so.zip
_HREF_RE = re.compile(
    r'href="([^"]*?(\w+)_libretro[^"]*?\.zip)"',
    re.IGNORECASE,
)

# Extract core name: everything before _libretro
_CORE_NAME_RE = re.compile(r"^(.+?)_libretro")


class Scraper(BaseTargetScraper):
    """Fetches core lists per target from RetroArch buildbot nightly."""

    def __init__(self, url: str = BUILDBOT_URL):
        super().__init__(url=url)

    def _fetch_url(self, url: str) -> str:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "retrobios-scraper/1.0"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.URLError as e:
            # A target written from a failed request loses its cores in silence.
            raise RuntimeError(f"cannot fetch {url}: {e}") from e

    def _fetch_cores_for_target(self, path: str) -> list[str]:
        url = f"{self.url}{path}/"
        html = self._fetch_url(url)
        cores: list[str] = []
        seen: set[str] = set()
        for match in _HREF_RE.finditer(html):
            href = match.group(1)
            filename = href.split("/")[-1]
            m = _CORE_NAME_RE.match(filename)
            if m:
                core = m.group(1)
                if core not in seen:
                    seen.add(core)
                    cores.append(core)
        return sorted(cores)

    def _parse_recipe_cores(self, text: str) -> list[str]:
        cores: list[str] = []
        seen: set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if not parts:
                continue
            core = parts[0]
            if core not in seen:
                seen.add(core)
                cores.append(core)
        return sorted(cores)

    def _fetch_cores_for_recipe(self, recipe_path: str) -> list[str]:
        url = f"{RECIPE_BASE_URL}{recipe_path}"
        return self._parse_recipe_cores(self._fetch_url(url))

    def fetch_targets(self) -> dict:
        targets: dict[str, dict] = {}
        for path, target_name, arch in TARGETS:
            print(f"  fetching {target_name}...", file=sys.stderr)
            cores = self._fetch_cores_for_target(path)
            if not cores:
                raise RuntimeError(f"no cores listed for {target_name}")
            targets[target_name] = {
                "architecture": arch,
                "cores": cores,
            }
            print(f"  {target_name}: {len(cores)} cores", file=sys.stderr)
        for recipe_path, target_name, arch in RECIPE_TARGETS:
            print(f"  fetching {target_name} (recipe)...", file=sys.stderr)
            cores = self._fetch_cores_for_recipe(recipe_path)
            if not cores:
                raise RuntimeError(f"no cores listed for {target_name}")
            targets[target_name] = {
                "architecture": arch,
                "cores": cores,
            }
            print(f"  {target_name}: {len(cores)} cores", file=sys.stderr)
        return {
            "platform": "retroarch",
            "source": self.url,
            "scraped_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "targets": targets,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scrape RetroArch buildbot nightly targets"
    )
    parser.add_argument("--dry-run", action="store_true", help="Show target summary")
    parser.add_argument("--output", "-o", help="Output YAML file")
    args = parser.parse_args()

    scraper = Scraper()
    data = scraper.fetch_targets()

    total_cores = sum(len(t["cores"]) for t in data["targets"].values())
    print(
        f"\n{len(data['targets'])} targets, {total_cores} total core entries",
        file=sys.stderr,
    )

    if args.dry_run:
        for name, info in sorted(data["targets"].items()):
            print(
                f"  {name:30s} {info['architecture']:10s} {len(info['cores']):>4d} cores"
            )
        return

    if args.output:
        scraper.write_output(data, args.output)
        print(f"Written to {args.output}")
        return

    print(yaml.dump(data, default_flow_style=False, sort_keys=False))


if __name__ == "__main__":
    main()
