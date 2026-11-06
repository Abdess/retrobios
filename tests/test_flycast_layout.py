"""Flycast's two builds read the same files from two directories.

The libretro port looks in <system>/dc/ (shell/libretro/libretro.cpp:2249-2250).
The standalone emulator looks in its data directory, whose root holds the
files with no dc/ level (core/oslib/oslib.cpp:118-196, core/stdclass.cpp:95-125).
Without standalone_path the standalone layout of a pack fell back on path:
and put every file one directory too deep.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import unittest
from pathlib import Path

import yaml

PROFILE = Path(__file__).resolve().parent.parent / "emulators" / "flycast.yml"


class FlycastStandaloneLayout(unittest.TestCase):
    def test_every_entry_has_the_data_directory_layout(self) -> None:
        profile = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
        self.assertEqual(profile["type"], "standalone + libretro")
        for entry in profile["files"]:
            with self.subTest(entry=entry["name"]):
                self.assertTrue(entry["path"].startswith("dc/"))
                self.assertEqual(entry.get("standalone_path"), entry["path"][len("dc/"):])


if __name__ == "__main__":
    unittest.main()
