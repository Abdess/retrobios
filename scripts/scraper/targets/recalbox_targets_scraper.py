"""Scraper for Recalbox per-board emulator availability.

Sources (recalbox/recalbox on GitLab, at the tag platforms/recalbox.yml names):
  - configs/*_defconfig -- the board each image builds, its
    `BR2_PACKAGE_RECALBOX_TARGET_<BOARD>=y` line, and the Buildroot packages
    it enables, one `BR2_PACKAGE_<NAME>=y` line per emulator package
  - package/recalbox-romfs2/systems/<system>/system.ini -- the cores of each
    system, each `[core.N]` naming the package that builds it, with board
    overrides (`package.<board>`, `[core.N.<board>]`)

Recalbox runs on Raspberry Pi 3 to 5, two handhelds and x86_64: without a
target list, a Pi 3 pack carried the firmware of emulators only x86_64 builds.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone


from . import BaseTargetScraper, target_cli
from ..base_scraper import fetch_text
from ..recalbox_romfs import defconfig_boards
from ..recalbox_scraper import Scraper as PlatformScraper, board_cores, tree_listing

PLATFORM_NAME = "recalbox"

DEFCONFIG_URL = "https://gitlab.com/recalbox/recalbox/-/raw/{tag}/configs/{name}"


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
        defconfigs = {
            item["name"]: fetch_text(DEFCONFIG_URL.format(tag=tag, name=item["name"]))
            for item in tree_listing("configs", tag)
            if item.get("name", "").endswith("_defconfig")
        }
        built = defconfig_boards(defconfigs.items())
        if not built:
            raise RuntimeError(f"no defconfig in configs/ at {tag} names a Recalbox target")

        inis = platform._system_inis(platform.system_folders())

        targets: dict[str, dict] = {}
        for board, (name, config) in sorted(built.items()):
            cores: set[str] = set()
            for text in inis:
                cores |= board_cores(text, board, config.enabled)
            arch = defconfig_arch(defconfigs[name])
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
