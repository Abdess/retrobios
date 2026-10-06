"""--region decides among the files --required-only keeps.

The regional choice ran over optional candidates too. In Batocera's Vic20
group the optional Japanese kernel won for --region jp, the required PAL
and NTSC kernels were dropped as beaten, and --required-only then removed
the optional winner: the slot shipped empty.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from packextras import platform_region_groups  # noqa: E402


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
        tree = ast.parse((REPO_ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8"))
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and getattr(node.func, "id", None) == "platform_region_groups"
        ]
        self.assertGreaterEqual(len(calls), 2)
        for call in calls:
            self.assertIn("required_only", {kw.arg for kw in call.keywords})


if __name__ == "__main__":
    unittest.main()
