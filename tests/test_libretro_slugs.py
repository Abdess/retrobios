"""Scraped system ids are slugs the profiles know.

The libretro scraper filed System.dat's PC-8801, DSi and CD-i under
`nec---pc-8801`, `nintendo---nintendo-dsi` and `philips---cd-i`, fallback
slugs no profile declares. Target filtering kept the DSi BIOS in packs for
hardware without a DSi core, and PC-8801 survived only as a hand-added
duplicate system carrying the quasi88 group.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class ScrapedSystemIdsAreSlugs(unittest.TestCase):
    def test_no_fallback_slug(self):
        for path in sorted((REPO_ROOT / "platforms").glob("*.yml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            systems = data.get("systems") if isinstance(data, dict) else None
            for sys_id in systems or {}:
                with self.subTest(platform=path.stem, system=sys_id):
                    self.assertNotIn("---", str(sys_id))

    def test_pc88_keeps_the_mk2sr_extension_set(self):
        """System.dat pairs the mkII SR main ROM with other models' extensions.

        The quasi88 group supplies N88EXT0-3.ROM, which the core reads first
        (src/LIBRETRO/libretro.c:109-112) and which match that main ROM.
        """
        from common import load_platform_config

        config = load_platform_config("retroarch", str(REPO_ROOT / "platforms"))
        names = {
            f.get("name") for f in config["systems"]["nec-pc-88"].get("files", [])
        }
        for name in ("N88EXT0.ROM", "N88EXT1.ROM", "N88EXT2.ROM", "N88EXT3.ROM"):
            self.assertIn(name, names)


if __name__ == "__main__":
    unittest.main()
