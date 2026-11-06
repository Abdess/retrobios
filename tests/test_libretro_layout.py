"""A profile's path: is where the libretro core reads the file.

pack_structure prefixed files as well as data directories: PPSSPP's
`PPSSPP/ppge_atlas.zim` became PPSSPP/PPSSPP/, while the platform packs,
which never read the field, put libretro Dolphin's IPL, DSP ROMs, fonts,
segaboot and Wii user files at the root of system/. libretro Dolphin reads
Sys from system/dolphin-emu/Sys and keeps User in the save directory.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from packpaths import _resolve_destination  # noqa: E402
from validation import (  # noqa: E402
    outside_gap_scope,
    read_from_save_dir,
    read_from_system_dir,
)


class PathIsTheDestination(unittest.TestCase):
    def test_no_prefix_on_a_file(self):
        entry = {"name": "ppge_atlas.zim", "path": "PPSSPP/ppge_atlas.zim"}
        self.assertEqual(_resolve_destination(entry, False), "PPSSPP/ppge_atlas.zim")
        dual = {"name": "IPL.bin", "path": "dolphin-emu/Sys/GC/USA/IPL.bin",
                "standalone_path": "GC/USA/IPL.bin"}
        self.assertEqual(_resolve_destination(dual, False), "dolphin-emu/Sys/GC/USA/IPL.bin")
        self.assertEqual(_resolve_destination(dual, True), "GC/USA/IPL.bin")


class LoadFromPerBuild(unittest.TestCase):
    ENTRY = {"name": "SYSCONF", "path": "Wii/shared2/sys/SYSCONF",
             "load_from": {"libretro": "save_dir"}}

    def test_each_build_reads_its_own_place(self):
        self.assertFalse(read_from_system_dir(self.ENTRY, False))
        self.assertTrue(read_from_system_dir(self.ENTRY, True))
        # The libretro build's copy goes below the save directory, the
        # standalone one below the folder the platform hands it.
        self.assertTrue(read_from_save_dir(self.ENTRY, False))
        self.assertFalse(read_from_save_dir(self.ENTRY, True))
        self.assertFalse(outside_gap_scope(self.ENTRY, False))
        self.assertFalse(outside_gap_scope(self.ENTRY, True))

    def test_a_plain_value_holds_for_both(self):
        entry = {"name": "x", "load_from": "save_dir"}
        self.assertFalse(read_from_system_dir(entry, False))
        self.assertFalse(read_from_system_dir(entry, True))


class RetroArchCarriesDolphinWhereItReads(unittest.TestCase):
    """Reads the repository: skips when the database is absent."""

    def test_no_dolphin_file_at_the_root(self):
        if not (REPO_ROOT / "database.json").exists():
            self.skipTest("database.json is not built")
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        from common import load_database, load_emulator_profiles, load_platform_config
        from packextras import _collect_emulator_extras

        config = load_platform_config("retroarch")
        extras = _collect_emulator_extras(
            config, "emulators", load_database("database.json"), set(),
            config.get("base_destination", ""), load_emulator_profiles("emulators"),
        )
        dolphin = [
            e["destination"] for e in extras
            if e.get("source_emulator") in ("Dolphin", "Ishiiruka")
            and e.get("root") != "save"
        ]
        self.assertTrue(dolphin)
        self.assertEqual(
            [d for d in dolphin if not d.startswith("dolphin-emu/Sys/")], []
        )
        # The User tree goes below the save directory, each core's folder
        # first (RetroArch sorts saves by core).
        user = {
            e["pack_path"] for e in extras
            if e.get("source_emulator") in ("Dolphin", "Ishiiruka")
            and e.get("root") == "save"
        }
        self.assertIn("saves/dolphin-emu/User/GBA/gba_bios.bin", user)
        self.assertTrue(all(
            p.startswith(("saves/dolphin-emu/User/", "saves/Ishiiruka/User/")) for p in user
        ))
        self.assertIn("dolphin-emu/Sys/Triforce/segaboot.gcm", dolphin)


if __name__ == "__main__":
    unittest.main()
