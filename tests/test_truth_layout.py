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


if __name__ == "__main__":
    unittest.main()
