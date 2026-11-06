"""PC-88 ROMs live in the PC-88 folder.

Sixteen ROMs that only quasi88 reads (N88EXT0-3, N88KNJ1, N88SUB, the n88
set, the disk subsystem ROM, pc88.rom) were stored under bios/NEC/PC-98,
and the site linked the nec-pc-88 system to the PC-98 page. A file in the
PC-98 folder must have a reader whose systems include the PC-98, or be one
no PC-88 emulator reads. Reads the repository.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

PC98 = {"pc-98", "nec-pc-98"}
PC88 = {"nec-pc-88", "nec-pc-80"}


class PC88FilesStayInPC88(unittest.TestCase):
    def test_no_pc88_only_file_under_pc98(self):
        folder = REPO_ROOT / "bios" / "NEC" / "PC-98"
        if not folder.is_dir():
            self.skipTest("bios/NEC/PC-98 is absent")
        from common import load_emulator_profiles

        readers: dict[str, set[str]] = {}
        for profile in load_emulator_profiles(str(REPO_ROOT / "emulators")).values():
            systems = {str(s) for s in profile.get("systems") or []}
            for entry in profile.get("files") or []:
                if not isinstance(entry, dict):
                    continue
                for name in [entry.get("name", ""), *(entry.get("aliases") or [])]:
                    readers.setdefault(str(name).lower(), set()).update(systems)
        misfiled = sorted(
            path.name for path in folder.iterdir()
            if path.is_file()
            and readers.get(path.name.lower())
            and readers[path.name.lower()] <= PC88
        )
        self.assertEqual(misfiled, [])
        self.assertFalse((folder / "pc88.rom").exists())


if __name__ == "__main__":
    unittest.main()
