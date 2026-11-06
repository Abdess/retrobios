"""A filename-agnostic scan seeds only from the build the platform runs.

armsx2 declares bios_mode: agnostic, and its proverb.zip is a standalone
file the Android app fetches into its arcade/ folder. The scan never read
`mode:` and put it at system/proverb.zip in every pack running armsx2 as a
libretro core, while verify set the entry aside. Reads the repository.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class ScanFollowsTheBuild(unittest.TestCase):
    def test_no_standalone_seed_in_a_libretro_pack(self):
        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not built")
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        from common import load_database, load_emulator_profiles, load_platform_config
        from packextras import _collect_emulator_extras

        profiles = load_emulator_profiles("emulators")
        entry = next(
            (f for f in profiles.get("armsx2", {}).get("files", [])
             if f.get("name") == "proverb.zip"),
            None,
        )
        if entry is None or entry.get("mode") != "standalone":
            self.skipTest("armsx2 no longer declares a standalone proverb.zip")
        config = load_platform_config("retroarch")
        extras = _collect_emulator_extras(
            config, "emulators", load_database("database.json"), set(),
            config.get("base_destination", ""), profiles,
        )
        self.assertNotIn(
            ("proverb.zip", "ARMSX2"),
            {(e["name"], e.get("source_emulator")) for e in extras},
        )


if __name__ == "__main__":
    unittest.main()
