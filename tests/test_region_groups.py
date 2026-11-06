"""A core extra competes for a region only with files of its own machine.

CLK profiles 30 systems and names none per file. Its extras were filed in
the region group of every one of them: its American MSX ROM made RetroDECK's
Enterprise group drop the German Enterprise ROM under --region us.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from packextras import extra_region_groups, system_spellings  # noqa: E402


class TheGroupFollowsWhatTheProfileSays(unittest.TestCase):
    def test_a_file_system(self):
        self.assertEqual(
            extra_region_groups({"source_system": "msx", "source_systems": ["msx", "vic20"]}),
            ["msx"],
        )

    def test_a_single_system_profile(self):
        self.assertEqual(extra_region_groups({"source_systems": ["sega-saturn"]}), ["sega-saturn"])

    def test_a_multi_system_profile_without_a_file_system(self):
        groups = extra_region_groups({
            "source_emulator": "clk", "destination": "MSX/msx-american.rom",
            "source_systems": ["msx", "enterprise-64-128", "vic20"],
        })
        self.assertEqual(groups, ["clk:file:MSX/msx-american.rom"])

    def test_a_variant_group_stays_one_slot(self):
        self.assertEqual(
            extra_region_groups({"source_emulator": "picodrive", "variant_group": "mcd",
                                 "source_systems": ["sega-segacd", "sega-mega-cd"]}),
            ["picodrive:variant:mcd"],
        )


class TheEnterpriseKeepsItsRom(unittest.TestCase):
    def test_retrodeck_keeps_brd_rom_under_a_region(self):
        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not built")
        import region
        from common import load_database, load_emulator_profiles, load_platform_config
        from packextras import platform_region_groups

        db = load_database(str(REPO_ROOT / "database.json"))
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        config = load_platform_config("retrodeck", str(REPO_ROOT / "platforms"))
        groups, _ = platform_region_groups(
            config, config["systems"], str(REPO_ROOT / "emulators"), db,
            config.get("base_destination", ""), profiles,
        )
        drops = region.resolve_region_drops(
            groups, region.build_region_index(profiles), ["north-america"]
        )
        self.assertNotIn("bios/brd.rom", drops)

    def test_brd_rom_is_chosen_by_the_content_not_a_territory(self):
        # core.hpp:221-226: "[req brd-rom]" in the content name selects it,
        # whatever the user's country, as "[req zrom]" selects hun.rom.
        from common import load_emulator_profiles

        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        entry = next(
            f for f in profiles["ep128emu_core"]["files"] if f["name"] == "brd.rom"
        )
        self.assertFalse(entry.get("region"))


class TheGroupTakesThePlatformSpelling(unittest.TestCase):
    def test_a_profile_spelling_maps_to_the_platform_one(self):
        spellings = system_spellings(["sega-master-system", "sony-playstation"])
        self.assertEqual(
            extra_region_groups({"source_system": "sega-mastersystem"}, spellings),
            ["sega-master-system"],
        )

    def test_a_system_the_platform_lacks_keeps_its_name(self):
        spellings = system_spellings(["sony-playstation"])
        self.assertEqual(
            extra_region_groups({"source_systems": ["sega-saturn"]}, spellings),
            ["sega-saturn"],
        )

    def test_file_and_variant_groups_are_untouched(self):
        spellings = system_spellings(["sega-megacd"])
        self.assertEqual(
            extra_region_groups({"source_emulator": "picodrive", "variant_group": "mcd",
                                 "source_system": "sega-megacd"}, spellings),
            ["picodrive:variant:mcd"],
        )


if __name__ == "__main__":
    unittest.main()
