"""Same-named core files at two paths stay two files in standalone mode.

find_undeclared_files keyed its dedup on standalone_path alone when the
platform runs the core standalone, while the destination it then writes
falls back on path. Batocera runs clk standalone, clk declares basic.rom
under Acorn/ and Electron/ without a standalone_path, and the second was
dropped from the pack.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class StandaloneFallsBackOnPath(unittest.TestCase):
    def test_both_paths_survive(self):
        from verify import find_undeclared_files

        profile = {
            "emulator": "Clock Signal",
            "type": "standalone + libretro",
            "systems": ["acorn-electron"],
            "files": [
                {"name": "basic.rom", "path": "Acorn/basic.rom", "required": True},
                {"name": "basic.rom", "path": "Electron/basic.rom", "required": True},
            ],
        }
        config = {"cores": ["clk"], "standalone_cores": ["clk"], "systems": {}}
        db = {"files": {}, "indexes": {}}
        found = find_undeclared_files(config, "emulators", db, emu_profiles={"clk": profile})
        self.assertEqual(
            sorted(f["path"] for f in found if f["name"] == "basic.rom"),
            ["Acorn/basic.rom", "Electron/basic.rom"],
        )


if __name__ == "__main__":
    unittest.main()
