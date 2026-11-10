"""A profile's `emulator:` is the name the project gives itself.

The site titles every emulator page and link with it. A value equal to the
file stem reads as an id ("corsixth", "shadps4") unless the project writes its
own name that way.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import load_emulator_profiles  # noqa: E402

STEM_NAMED = {
    # Template and test cores, no emulator page.
    "00_example": "template",
    "test": "role test",
    "testgl": "role test",
    "testvulkan": "role test",
    "vidtest": "role test",
    # Aliases, no emulator page.
    "ep128emu": "alias",
    "mednafen_gba": "alias",
    "mednafen_lynx": "alias",
    "mednafen_ngp": "alias",
    "mednafen_pce": "alias",
    "mednafen_pcfx": "alias",
    "mednafen_psx": "alias",
    "mednafen_psx_hw": "alias",
    "mednafen_saturn": "alias",
    "mednafen_vb": "alias",
    "mednafen_wswan": "alias",
    "mkxp-z": "alias",
    "parallel_n64_debug": "alias",
    # Libretro cores whose .info corename is the stem.
    "2048": "corename 2048",
    "a5200": "corename a5200",
    "b2": "corename b2",
    "bnes": "corename bnes",
    "boom3": "corename boom3",
    "bsnes": "corename bsnes, the project writes bsnes",
    "bsnes-jg": "corename bsnes-jg",
    "galaksija": "corename galaksija",
    "nes": "corename nes",
    "uzem": "corename uzem",
    "vecx": "corename vecx",
    "xemu": "corename xemu, the project writes xemu",
    "yaps2": "corename yaps2, README title yaps2",
    # Lowercase project names.
    "advanced_drastic": "README title advanced_drastic",
    "ares": "the project writes ares",
    "ccleste": "README title ccleste",
    "dhewm3": "window title dhewm3 (ENGINE_VERSION)",
    "dsda-doom": "README title dsda-doom",
    "fheroes2": "README title fheroes2",
    "hode": "README title hode",
    "ioquake3": "the project writes ioquake3",
    "izapple2": "README title izapple2",
    "jgenesis": "README title jgenesis",
    "n64emu": "README title n64emu",
    "np2pi": "repository and binary np2pi, no title in the source",
    "rpix86": "the author writes rpix86",
    "simple64": "window title simple64",
    "sixtyforce": "site title sixtyforce",
    "veesem": "README title veesem",
    "zcdi": "README title zcdi",
}


class ProfileNames(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profiles = load_emulator_profiles(
            REPO_ROOT / "emulators", skip_aliases=False
        )

    def test_emulator_name_is_not_the_file_stem(self) -> None:
        stem_named = sorted(
            stem
            for stem, profile in self.profiles.items()
            if str(profile.get("emulator", "")) == stem
            and stem not in STEM_NAMED
        )
        self.assertEqual(stem_named, [], "set emulator: to the project's own name")

    def test_allow_list_has_no_stale_entry(self) -> None:
        stale = sorted(
            stem
            for stem in STEM_NAMED
            if str(self.profiles.get(stem, {}).get("emulator", "")) != stem
        )
        self.assertEqual(stale, [])


if __name__ == "__main__":
    unittest.main()
