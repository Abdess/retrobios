"""Scraper for Recalbox per-board emulator availability.

Sources (recalbox/recalbox on GitLab, at the tag platforms/recalbox.yml names):
  - configs/recalbox-<board>_defconfig -- the Buildroot packages each image
    enables, one `BR2_PACKAGE_<NAME>=y` line per emulator package
  - package/recalbox-romfs2/systems/<system>/system.ini -- the cores of each
    system, each `[core.N]` naming the package that builds it, with board
    overrides (`package.<board>`, `[core.N.<board>]`)

Recalbox runs on Raspberry Pi 3 to 5, two handhelds and x86_64: without a
target list, a Pi 3 pack carried the firmware of emulators only x86_64 builds.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone


from . import BaseTargetScraper, target_cli
from ..base_scraper import fetch_bytes, fetch_text
from ..recalbox_scraper import SYSTEMS_TREE_URL, Scraper as PlatformScraper, board_cores

PLATFORM_NAME = "recalbox"

CONFIGS_TREE_URL = (
    "https://gitlab.com/api/v4/projects/recalbox%2Frecalbox/repository/tree"
    "?path=configs&ref={tag}&per_page=100"
)
DEFCONFIG_URL = "https://gitlab.com/recalbox/recalbox/-/raw/{tag}/configs/{name}"
_DEFCONFIG_RE = re.compile(r"^recalbox-(\w+)_defconfig$")
_ENABLED_RE = re.compile(r"^(BR2_PACKAGE_\w+)=y\s*$", re.MULTILINE)


def enabled_packages(defconfig: str) -> set[str]:
    """The Buildroot packages a defconfig turns on."""
    return set(_ENABLED_RE.findall(defconfig))


def defconfig_arch(defconfig: str) -> str:
    """The architecture a defconfig builds for, from its Buildroot arch symbol."""
    for symbol, arch in (("BR2_x86_64", "x86_64"), ("BR2_aarch64", "aarch64"),
                         ("BR2_arm", "armhf")):
        if re.search(rf"^{symbol}=y\s*$", defconfig, re.MULTILINE):
            return arch
    raise RuntimeError("defconfig names no BR2_x86_64, BR2_aarch64 or BR2_arm")


class Scraper(BaseTargetScraper):
    """Per-board core lists from Recalbox's defconfigs and system.ini files."""

    def __init__(self, url: str = "https://gitlab.com/recalbox/recalbox") -> None:
        super().__init__(url=url)

    def fetch_targets(self) -> dict:
        tag = self.pinned_revision(PLATFORM_NAME)
        platform = PlatformScraper(tag)
        listing = json.loads(fetch_bytes(CONFIGS_TREE_URL.format(tag=tag)))
        boards = {
            match.group(1): item["name"]
            for item in listing
            if (match := _DEFCONFIG_RE.match(item.get("name", "")))
        }
        if not boards:
            raise RuntimeError(f"no recalbox-*_defconfig in configs/ at {tag}")

        systems: list[str] = []
        page = 1
        while True:
            entries = json.loads(fetch_bytes(SYSTEMS_TREE_URL.format(tag=tag, page=page)))
            systems += [e["name"] for e in entries
                        if e.get("type") == "tree" and not e["name"].startswith(".")]
            if len(entries) < 100:
                break
            page += 1
        inis = platform._system_inis(systems)

        targets: dict[str, dict] = {}
        for board, name in sorted(boards.items()):
            defconfig = fetch_text(DEFCONFIG_URL.format(tag=tag, name=name))
            enabled = enabled_packages(defconfig)
            cores: set[str] = set()
            for text in inis:
                cores |= board_cores(text, board, enabled)
            arch = defconfig_arch(defconfig)
            targets[board] = {"architecture": arch, "cores": sorted(cores)}
            print(f"  {board} ({arch}): {len(cores)} cores", file=sys.stderr)

        return {
            "platform": PLATFORM_NAME,
            "source": f"{self.url}/-/tree/{tag}/configs",
            "scraped_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "targets": targets,
        }


def main() -> None:
    target_cli(Scraper, "Scrape Recalbox per-board cores")


if __name__ == "__main__":
    main()
