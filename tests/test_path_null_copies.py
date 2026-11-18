"""An entry with `path: null` is never copied to the root of a pack.

The pass that copies a file covered elsewhere to each destination a core
reads skipped neither: Dolphin's codehandler.bin, which ships in its Sys
tree, landed at system/codehandler.bin in RetroArch, Lakka and RetroPie.
Reads the repository: skips when the database is absent.
"""

from __future__ import annotations

import tests

import os
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


class NoPathNoCopy(unittest.TestCase):
    def test_codehandler_stays_out(self):
        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not built")
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        from model.database import load_database
        from model.profiles import load_emulator_profiles
        from model.platforms import load_platform_config
        from packs.extras import _collect_emulator_extras

        profiles = load_emulator_profiles("emulators")
        nameless = {
            (p.get("emulator", n), f["name"])
            for n, p in profiles.items() for f in p.get("files", [])
            if isinstance(f, dict) and "path" in f and f["path"] is None
        }
        config = load_platform_config("retroarch")
        extras = _collect_emulator_extras(
            config, "emulators", load_database("database.json"), set(),
            config.get("base_destination", ""), profiles,
        )
        self.assertEqual(
            [e["destination"] for e in extras
             if (e.get("source_emulator"), e["name"]) in nameless],
            [],
        )


if __name__ == "__main__":
    unittest.main()
