"""An entry with `path: null` is never copied to the root of a pack.

The pass that copies a file covered elsewhere to each destination a core
reads skipped neither: Dolphin's codehandler.bin, which ships in its Sys
tree, landed at system/codehandler.bin in RetroArch, Lakka and RetroPie.
Reads the repository: skips when the database is absent.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class NoPathNoCopy(unittest.TestCase):
    def test_codehandler_stays_out(self):
        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not built")
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        from common import load_database, load_emulator_profiles, load_platform_config
        from packextras import _collect_emulator_extras

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
