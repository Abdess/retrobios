"""Same-named core files at two paths stay two files in standalone mode.

find_undeclared_files keyed its dedup on standalone_path alone when the
platform runs the core standalone, while the destination it then writes
falls back on path. Batocera runs clk standalone, clk declares basic.rom
under Acorn/ and Electron/ without a standalone_path, and the second was
dropped from the pack.
"""

from __future__ import annotations

import tests

import unittest


class StandaloneFallsBackOnPath(unittest.TestCase):
    def test_both_paths_survive(self):
        from packs.gaps import find_undeclared_files

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


class UnsourceableFilesCountedLikeGaps(unittest.TestCase):
    """The site counted a platform's unsourceable core files by distinct
    name over every profile: gamecontrollerdb.txt read at four paths by four
    cores was one, and hatari's standalone keymap counted where hatari runs
    as a core only."""

    def test_one_per_slot_in_the_build_the_platform_runs(self):
        from packs.gaps import scan_core_files

        reason = {"unsourceable": "written by the user"}
        profiles = {
            "a": {"emulator": "A", "type": "libretro", "systems": ["s"], "files": [
                {"name": "db.txt", "path": "a/db.txt", **reason},
                {"name": "keymap", "path": "keymap", "mode": "standalone", **reason},
                {"name": "<font>.ttf", "path": "<font>.ttf", **reason},
            ]},
            "b": {"emulator": "B", "type": "libretro", "systems": ["s"], "files": [
                {"name": "db.txt", "path": "b/db.txt", **reason},
            ]},
        }
        config = {"cores": ["a", "b"], "systems": {}}
        db = {"files": {}, "indexes": {}}
        found = scan_core_files(config, "emulators", db, emu_profiles=profiles).unsourceable
        self.assertEqual(sorted(r["path"] for r in found), ["a/db.txt", "b/db.txt"])


if __name__ == "__main__":
    unittest.main()
