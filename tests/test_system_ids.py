"""A machine has one system id in the profiles, and a file goes to its own.

picodrive filed the Mega CD as sega-segacd and fbneo the disk system as
nes-fds, where every other profile and every platform says sega-megacd and
nintendo-fds. On RomM, which keeps firmware per system folder, picodrive's
Mega CD BIOS went to gamegear/, the first of its systems, and fbneo's
channelf.zip and SNES DSP sets to colecovision/.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import SYSTEM_ALIASES, load_emulator_profiles  # noqa: E402
from packextras import _slug_for  # noqa: E402


class ProfilesSpellEachMachineOnce(unittest.TestCase):
    def test_no_profile_uses_an_alias_spelling(self):
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        found = sorted(
            f"{name}: {sid}"
            for name, profile in profiles.items()
            for sid in [
                *profile.get("systems", []),
                *(f.get("system") for f in profile.get("files", []) if f.get("system")),
            ]
            if str(sid).lower() in SYSTEM_ALIASES
        )
        self.assertEqual(sorted(set(found)), [])


class AFileGoesToItsOwnSystemFolder(unittest.TestCase):
    PROFILES = {"picodrive": {"systems": ["sega-game-gear", "sega-megacd"]}}
    SYSTEMS = {"sega-game-gear", "sega-mega-cd"}
    NORM = {"gamegear": "sega-game-gear", "megacd": "sega-mega-cd"}
    SLUGS = {"sega-game-gear": "gamegear", "sega-mega-cd": "segacd"}

    def slug(self, entry):
        return _slug_for(entry, self.PROFILES, self.SYSTEMS, self.NORM, self.SLUGS)

    def test_the_entry_system_decides(self):
        self.assertEqual(
            self.slug({"profile": "picodrive", "system": "sega-megacd"}), "segacd"
        )

    def test_without_one_the_emulator_systems_decide(self):
        self.assertEqual(self.slug({"profile": "picodrive"}), "gamegear")


if __name__ == "__main__":
    unittest.main()
