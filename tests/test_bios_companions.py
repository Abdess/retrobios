"""Companions travel with the BIOS image they belong to.

PCSX2 opens <bios>.rom1 or <stem>.rom1, and nvm and mec the same way. Its
profile named them rom1.bin, ROM2.BIN and EROM.BIN, names the code never
opens. ROM2.BIN found a misfiled Galaksija ROM inside the PS2 folder, and a
4 MB size bound then swept GameIndex.yaml and cheat archives to the root of
the Batocera BIOS folder.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from packextras import _companion_extensions, _companions  # noqa: E402


class Companions(unittest.TestCase):
    PROFILE = {"files": [
        {"name": "ps2-0230a-20080220.bin"},
        {"name": "ps2-0230a-20080220.rom1"},
        {"name": "ps2-0230a-20080220.nvm"},
        {"name": "GameIndex.yaml"},
    ]}

    def test_extensions_come_from_entries_named_after_the_bios(self):
        self.assertEqual(
            _companion_extensions(self.PROFILE, "ps2-0230a-20080220.bin"), {"rom1", "nvm"}
        )

    def test_only_files_named_after_the_image_follow_it(self):
        files_db = {
            "a": {"path": "bios/PS2/SCPH-70004.ROM1", "name": "SCPH-70004.ROM1"},
            "b": {"path": "bios/PS2/scph70004.bin.nvm", "name": "scph70004.bin.nvm"},
            "c": {"path": "bios/PS2/GameIndex.yaml", "name": "GameIndex.yaml"},
            "d": {"path": "bios/Other/SCPH-70004.ROM1", "name": "SCPH-70004.ROM1"},
        }
        found = _companions("bios/PS2/SCPH-70004.BIN", "SCPH-70004.BIN", {"rom1", "nvm"}, files_db)
        self.assertEqual([sha for sha, _ in found], ["a"])

    def test_a_companion_is_named_as_pcsx2_spells_it(self):
        """PCSX2 stats SCPH-70004.BIN.rom1 then SCPH-70004.rom1, case kept
        (BiosTools.cpp:214-229). The pack wrote SCPH-70004.ROM1, which a
        Linux platform never finds, and the DVD ROM was skipped."""
        files_db = {
            "a": {"path": "bios/PS2/SCPH-70004.ROM1", "name": "SCPH-70004.ROM1"},
            "b": {"path": "bios/PS2/scph-70004.bin.rom2", "name": "scph-70004.bin.rom2"},
        }
        found = _companions(
            "bios/PS2/SCPH-70004.BIN", "SCPH-70004.BIN", {"rom1", "rom2"}, files_db
        )
        self.assertEqual(
            [entry["name"] for _, entry in found],
            ["SCPH-70004.rom1", "SCPH-70004.BIN.rom2"],
        )

    def test_a_companion_entry_scans_its_own_extension_only(self):
        """The rom1 entry declared max 4 MB and swept every smaller file of
        the PS2 folder (cheats, GameIndex.yaml, DVD firmware) to the BIOS
        root under its stored name, SCPH-70004.ROM1 included."""
        import os
        import tempfile

        from packextras import _agnostic_scan_extras

        profile = {
            "emulator": "PCSX2", "bios_mode": "agnostic", "files": [
                {"name": "ps2-0230a-20080220.bin", "found_by": "content",
                 "min_size": 8, "max_size": 16},
                {"name": "ps2-0230a-20080220.rom1", "max_size": 4},
            ],
        }
        stored = {
            "ps2-0230a-20080220.bin": b"I" * 8,
            "SCPH-70004.BIN": b"B" * 8,
            "SCPH-70004.ROM1": b"R" * 6,
            "246C.ROM1": b"N" * 3,
            "cheats_ws.zip": b"Z",
            "GameIndex.yaml": b"Y",
        }
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                files, by_name = {}, {}
                for name, payload in stored.items():
                    path = f"bios/PS2/{name}"
                    os.makedirs("bios/PS2", exist_ok=True)
                    Path(path).write_bytes(payload)
                    sha1 = f"{len(files):040d}"
                    files[sha1] = {"path": path, "name": name, "size": len(payload),
                                   "sha1": sha1}
                    by_name[name] = [sha1]
                db = {"files": files, "indexes": {
                    "by_name": by_name, "by_md5": {}, "by_crc32": {}, "by_path_suffix": {},
                }}
                extras = _agnostic_scan_extras(
                    {"pcsx2": profile}, {"pcsx2"}, db, by_name, set(), "",
                )
            finally:
                os.chdir(cwd)
        names = {e["destination"] for e in extras}
        self.assertIn("SCPH-70004.rom1", names)
        self.assertFalse({"SCPH-70004.ROM1", "cheats_ws.zip", "GameIndex.yaml"} & names)
        # Read beside the image the core selected only: no 246C image here.
        self.assertNotIn("246C.rom1", names)

    def test_a_shared_image_brings_each_cores_companions(self):
        """Recalbox runs LRPS2 and the old libretro PCSX2 on one ps2/ folder.
        LRPS2's scan placed SCPH-70004.BIN and its rom1, and the second core's
        scan stopped at the taken image, so the .erom only it reads stayed out."""
        import os
        import tempfile

        from packextras import _agnostic_scan_extras

        def profile(name: str, ext: str) -> dict:
            return {"emulator": name, "bios_mode": "agnostic", "files": [
                {"name": "ps2-0230a-20080220.bin", "found_by": "content",
                 "path": "ps2/ps2-0230a-20080220.bin", "min_size": 8, "max_size": 16},
                {"name": f"ps2-0230a-20080220.{ext}", "path": f"ps2/ps2-0230a-20080220.{ext}"},
            ]}

        stored = {
            "ps2-0230a-20080220.bin": b"I" * 8,
            "ps2-0230a-20080220.rom1": b"R",
            "ps2-0230a-20080220.erom": b"E",
        }
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                files, by_name = {}, {}
                for name, payload in stored.items():
                    path = f"bios/PS2/{name}"
                    os.makedirs("bios/PS2", exist_ok=True)
                    Path(path).write_bytes(payload)
                    sha1 = f"{len(files):040d}"
                    files[sha1] = {"path": path, "name": name, "size": len(payload),
                                   "sha1": sha1}
                    by_name[name] = [sha1]
                db = {"files": files, "indexes": {
                    "by_name": by_name, "by_md5": {}, "by_crc32": {}, "by_path_suffix": {},
                }}
                profiles = {"a": profile("A", "rom1"), "b": profile("B", "erom")}
                extras = _agnostic_scan_extras(
                    profiles, {"a", "b"}, db, by_name, set(), "", taken={},
                )
            finally:
                os.chdir(cwd)
        placed = [(e["destination"], e["source_profile"]) for e in extras]
        self.assertEqual(sorted(placed), [
            ("ps2/ps2-0230a-20080220.bin", "a"),
            ("ps2/ps2-0230a-20080220.erom", "b"),
            ("ps2/ps2-0230a-20080220.rom1", "a"),
        ])

    def test_pcsx2_profiles_name_no_free_standing_companion(self):
        for name in ("pcsx2", "pcsx2-legacy"):
            profile = yaml.safe_load((REPO_ROOT / "emulators" / f"{name}.yml").read_text())
            names = {str(f.get("name", "")).lower() for f in profile.get("files", [])}
            with self.subTest(profile=name):
                self.assertFalse({"rom1.bin", "rom2.bin", "erom.bin"} & names)


if __name__ == "__main__":
    unittest.main()
