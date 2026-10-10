"""Truth lays a core out the way verify and the pack builder do.

truth.py kept its own rule: with no standalone_cores it read the profile
type, called a dual profile "both" and a standalone one "standalone", and
kept `mode: standalone` files that runs_standalone, and so the pack, leave
out on RetroBat, EmuDeck and RetroDECK.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from truth import generate_platform_truth  # noqa: E402


def _names(truth: dict) -> set[str]:
    return {
        f["name"]
        for system in truth.get("systems", {}).values()
        for f in system.get("files", [])
    }


class TruthFollowsRunsStandalone(unittest.TestCase):
    PROFILE = {
        "emulator": "Dual",
        "type": "standalone + libretro",
        "systems": ["sony-playstation"],
        "files": [
            {"name": "both.bin", "system": "sony-playstation", "md5": "a" * 32},
            {"name": "only_sa.bin", "system": "sony-playstation", "md5": "b" * 32,
             "mode": "standalone"},
            {"name": "only_lr.bin", "system": "sony-playstation", "md5": "c" * 32,
             "mode": "libretro"},
        ],
    }

    def test_no_standalone_cores_means_libretro_layout(self):
        config = {"cores": ["dual"], "systems": {}}
        truth = generate_platform_truth("p", config, {}, {"dual": self.PROFILE})
        self.assertEqual(_names(truth), {"both.bin", "only_lr.bin"})

    def test_named_standalone_core_gets_its_files(self):
        config = {"cores": ["dual"], "standalone_cores": ["dual"], "systems": {}}
        truth = generate_platform_truth("p", config, {}, {"dual": self.PROFILE})
        self.assertEqual(_names(truth), {"both.bin", "only_sa.bin"})



class AnArchiveStandsForItsMembers(unittest.TestCase):
    """fbneo declares bubsys.zip as the ROMs inside it. As loose truth files
    the members were added to RetroArch's System.dat, and the 480-byte
    boot.bin, filed under the Dreamcast by its bare name, merged with
    RetroDream's 2 MB BIOS."""

    PROFILES = {
        "fbneo": {
            "emulator": "FBNeo", "type": "libretro", "systems": ["konami-bubsys"],
            "files": [
                {"name": "boot.bin", "archive": "bubsys.zip", "system": "konami-bubsys",
                 "required": True, "size": 480, "crc32": "f0774fc2"},
                {"name": "400b03.8g", "archive": "bubsys.zip", "system": "konami-bubsys",
                 "required": True, "size": 8192, "crc32": "85c2afc5"},
            ],
        },
        "retrodream": {
            "emulator": "RetroDream", "type": "libretro", "systems": ["sega-dreamcast"],
            "files": [{"name": "boot.bin", "path": "boot.bin", "system": "sega-dreamcast",
                       "size": 2097152, "md5": "e10c53c2f8b90bab96ead2d368858623"}],
        },
    }
    CONFIG = {
        "cores": ["fbneo", "retrodream"],
        "systems": {"sega-dreamcast": {"files": [
            {"name": "boot.bin", "destination": "dc/boot.bin"}]}},
    }

    def test_the_archive_is_the_file(self):
        truth = generate_platform_truth("p", self.CONFIG, {}, self.PROFILES)
        bubsys = truth["systems"]["konami-bubsys"]["files"]
        self.assertEqual([f["name"] for f in bubsys], ["bubsys.zip"])
        self.assertEqual(
            sorted(m["name"] for m in bubsys[0]["contents"]), ["400b03.8g", "boot.bin"]
        )
        self.assertTrue(bubsys[0]["required"])

    def test_a_member_name_claims_no_other_system(self):
        truth = generate_platform_truth("p", self.CONFIG, {}, self.PROFILES)
        dreamcast = truth["systems"]["sega-dreamcast"]["files"]
        self.assertEqual([(f["name"], f["size"]) for f in dreamcast], [("boot.bin", 2097152)])
        self.assertEqual(dreamcast[0]["_cores"], ["retrodream"])


class AnUnattributedEntryIsNotGuessed(unittest.TestCase):
    """CLK names twenty-three machines and none of its ROMs says which: all
    of them went under amstrad-cpc, its first system, and the RomM export
    listed Apple, Mac, ZX and Amiga firmware as Amstrad CPC firmware."""

    PROFILE = {
        "emulator": "CLK", "type": "libretro",
        "systems": ["amstrad-cpc", "apple-ii", "sinclair-zx81"],
        "files": [{"name": "apple2gs.rom", "size": 131072},
                  {"name": "zx81.rom", "size": 8192}],
    }

    def truth(self, systems):
        config = {"cores": ["clk"], "systems": systems}
        return generate_platform_truth("p", config, {}, {"clk": self.PROFILE})

    def test_several_candidate_systems_file_nothing(self):
        truth = self.truth({"amstrad-cpc": {"files": []}, "apple-ii": {"files": []}})
        self.assertEqual(_names(truth), set())
        self.assertEqual(truth["_coverage"]["unattributed"], {"clk": 2})

    def test_the_platform_declaration_decides(self):
        truth = self.truth({"amstrad-cpc": {"files": []},
                            "apple-ii": {"files": [{"name": "apple2gs.rom"}]}})
        self.assertEqual(
            [f["name"] for f in truth["systems"]["apple-ii"]["files"]], ["apple2gs.rom"]
        )

    def test_one_candidate_system_takes_them(self):
        truth = self.truth({"sinclair-zx81": {"files": []}})
        self.assertEqual(
            sorted(f["name"] for f in truth["systems"]["sinclair-zx81"]["files"]),
            ["apple2gs.rom", "zx81.rom"],
        )

if __name__ == "__main__":
    unittest.main()
