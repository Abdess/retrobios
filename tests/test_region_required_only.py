"""--region decides among the files --required-only keeps.

The regional choice ran over optional candidates too. In Batocera's Vic20
group the optional Japanese kernel won for --region jp, the required PAL
and NTSC kernels were dropped as beaten, and --required-only then removed
the optional winner: the slot shipped empty.
"""

from __future__ import annotations

import tests
from tests.sources import script_source

import ast
import unittest
from pathlib import Path

from packs.extraregions import platform_region_groups

REPO_ROOT = Path(__file__).resolve().parents[1]


class RequiredOnlyBeforeRegion(unittest.TestCase):
    def test_optional_files_leave_the_groups(self):
        systems = {"vic20": {"files": [
            {"name": "kernel-ntsc.bin", "destination": "Vic20/kernel-ntsc.bin", "required": True},
            {"name": "kernel-japanese.bin", "destination": "Vic20/kernel-japanese.bin",
             "required": False},
        ]}}
        groups, _ = platform_region_groups(
            {}, systems, "emulators", None, "", {}, include_extras=False, required_only=True,
        )
        self.assertEqual(groups["vic20"], [("Vic20/kernel-ntsc.bin", "kernel-ntsc.bin")])

    def test_every_caller_passes_it(self):
        tree = ast.parse(script_source("generate_pack.py"))
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and getattr(node.func, "id", None) == "platform_region_groups"
        ]
        self.assertGreaterEqual(len(calls), 2)
        for call in calls:
            self.assertIn("required_only", {kw.arg for kw in call.keywords})


class EmulatorModeToo(unittest.TestCase):
    """--emulator mednafen_pce_fast --region us --required-only shipped 0 files:
    the optional US cards won the group, then --required-only removed them."""

    def test_the_required_card_survives(self):
        from packs.extraregions import emulator_region_drops

        profile = {"systems": ["nec-pc-engine"], "files": [
            {"name": "syscard3.pce", "required": True, "region": ["japan"]},
            {"name": "syscard3u.pce", "required": False, "region": ["north-america"]},
        ]}
        drops = emulator_region_drops([("pce", profile)], False, ["north-america"], True)
        self.assertNotIn("syscard3.pce", drops)


if __name__ == "__main__":
    unittest.main()
