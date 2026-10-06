"""Companions travel with the BIOS image they belong to.

PCSX2 opens <bios>.rom1 or <stem>.rom1, and nvm and mec the same way. Its
profile named them rom1.bin, ROM2.BIN and EROM.BIN, names the code never
opens; ROM2.BIN found a misfiled Galaksija ROM inside the PS2 folder, and a
4 MB size bound then swept GameIndex.yaml and cheat archives to the root of
the Batocera BIOS folder.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

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

    def test_pcsx2_profiles_name_no_free_standing_companion(self):
        import yaml

        for name in ("pcsx2", "pcsx2-legacy"):
            profile = yaml.safe_load((REPO_ROOT / "emulators" / f"{name}.yml").read_text())
            names = {str(f.get("name", "")).lower() for f in profile.get("files", [])}
            with self.subTest(profile=name):
                self.assertFalse({"rom1.bin", "rom2.bin", "erom.bin"} & names)


if __name__ == "__main__":
    unittest.main()
