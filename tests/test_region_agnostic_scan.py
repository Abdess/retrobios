"""A file an agnostic scan accepts by shape keeps out of region choices.

PCSX2 picks no PS2 BIOS by territory, yet the copies its scan put under
pcsx2/bios/ were looked up by name and took DuckStation's region, which
describes DuckStation's own PS1-on-PS2 choice: `--region eu` withdrew
pcsx2/bios/ps2_scph50006.bin from RetroArch, Lakka, RetroPie, RetroDECK and
ROCKNIX. Reads the repository: skips when the database is absent.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class ScanCopiesStay(unittest.TestCase):
    def test_no_scan_copy_is_withdrawn(self):
        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not built")
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        import region as region_mod
        from common import load_database, load_emulator_profiles, load_platform_config
        from packextras import platform_region_groups

        db = load_database("database.json")
        profiles = load_emulator_profiles("emulators")
        config = load_platform_config("retroarch")
        extras: list[dict] = []
        groups, _ = platform_region_groups(
            config, config["systems"], "emulators", db,
            config.get("base_destination", ""), profiles, extras_out=extras,
        )
        scanned = {
            e["destination"] for e in extras
            if e.get("agnostic_scan") and not e.get("region")
        }
        if not scanned:
            self.skipTest("no agnostic scan copy in the RetroArch pack")
        index = region_mod.platform_region_index(config, profiles)
        for regions in (["europe"], ["japan"], ["north-america"]):
            with self.subTest(regions=regions):
                drops = region_mod.resolve_region_drops(groups, index, regions)
                self.assertEqual(sorted(drops & scanned), [])


if __name__ == "__main__":
    unittest.main()
