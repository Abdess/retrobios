"""Sega ROMs live under bios/Sega.

The SF-7000 disk unit ROM, which only the sega-sf7000 entries read, sat in
bios/Microsoft/MSX because blueMSX keeps its machine folders together. The
collection files a dump under the maker of the machine it belongs to, and
the blueMSX layout is a destination the pack writes, not a storage rule.
Reads the repository.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class SegaFilesStayUnderSega(unittest.TestCase):
    def test_no_sega_only_file_under_msx(self):
        folder = REPO_ROOT / "bios" / "Microsoft" / "MSX"
        if not folder.is_dir():
            self.skipTest("bios/Microsoft/MSX is absent")
        from common import load_emulator_profiles

        systems: dict[str, set[str]] = {}
        for profile in load_emulator_profiles(str(REPO_ROOT / "emulators")).values():
            for entry in profile.get("files") or []:
                if not isinstance(entry, dict) or not entry.get("system"):
                    continue
                for name in [entry.get("name", ""), *(entry.get("aliases") or [])]:
                    key = Path(str(name)).name.lower()
                    systems.setdefault(key, set()).add(str(entry["system"]))
        misfiled = sorted(
            str(path.relative_to(folder))
            for path in folder.rglob("*")
            if path.is_file()
            and systems.get(path.name.lower())
            and all(s.startswith("sega-") for s in systems[path.name.lower()])
        )
        self.assertEqual(misfiled, [])

    def test_sf7000_rom_is_filed_under_sega(self):
        self.assertTrue((REPO_ROOT / "bios" / "Sega" / "SF-7000" / "sf7000.rom").is_file())


if __name__ == "__main__":
    unittest.main()
