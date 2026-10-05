"""--one-per-slot and --region read one grouping of a pack.

The slot pass put each core extra under every system of its profile. PicoDrive
ranks its Mega CD BIOSes within sega-megacd; spread across sega-megadrive,
sega-32x and the rest, they shared a tier with unranked files, the tier was
ruled undecidable, and the keep overrode the drop.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class SlotPassReadsTheRegionGrouping(unittest.TestCase):
    def test_ranked_mega_cd_alternatives_are_decided(self):
        if not (REPO_ROOT / "database.json").is_file():
            self.skipTest("database.json not built")
        import generate_pack as gp
        from common import load_database, load_emulator_profiles, load_platform_config

        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        db = load_database("database.json")
        profiles = load_emulator_profiles("emulators")
        config = load_platform_config("retroarch", "platforms")
        drops, _fallbacks, _undecided = gp._select_variants(
            config, config["systems"], "emulators", db,
            config.get("base_destination", ""), profiles, None, "full", None, True,
        )
        names = {os.path.basename(d) for d in drops}
        for name in ("jp_mcd1_9111.bin", "eu_mcd1_9210.bin"):
            self.assertIn(name, names)

    def test_one_grouping_function(self):
        source = (REPO_ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8")
        self.assertNotIn("def _pack_member_groups", source)


class VariantGroupSpansSystems(unittest.TestCase):
    def test_us_request_withdraws_the_other_mega_cd_lists(self):
        """PicoDrive files US under sega-segacd and EU/JP under sega-megacd.

        find_bios (platform/libretro/libretro.c:1296) fills one slot from one
        of three lists. Grouped by system, sega-megacd had no US member and was
        kept whole as a fallback.
        """
        if not (REPO_ROOT / "database.json").is_file():
            self.skipTest("database.json not built")
        import generate_pack as gp
        import region as region_mod
        from common import load_database, load_emulator_profiles, load_platform_config

        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        db = load_database("database.json")
        profiles = load_emulator_profiles("emulators")
        config = load_platform_config("retroarch", "platforms")
        drops, _fallbacks, _undecided = gp._select_variants(
            config, config["systems"], "emulators", db,
            config.get("base_destination", ""), profiles, None, "full",
            region_mod.parse_requested("us"), False,
        )
        names = {os.path.basename(d) for d in drops}
        for name in ("jp_mcd1_9111.bin", "eu_mcd2_9306.bin"):
            self.assertIn(name, names)
        for name in ("us_scd2_9306.bin", "us_scd1_9210.bin"):
            self.assertNotIn(name, names)


if __name__ == "__main__":
    unittest.main()
