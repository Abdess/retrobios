"""A targeted pack is checked under the target reading it was built with.

`--all --target x86_64` packs a platform that has no target file unnarrowed
under the target's name (Recalbox, Lakka, BizHawk, MiSTer, ROCKNIX). The
conformance check read the same target without the --all tolerance, raised
FileNotFoundError on the first of those packs and stopped the run in a
traceback after every pack had been written.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import build_target_cores_cache  # noqa: E402
from generate_pack import _target_cores_for  # noqa: E402


class CheckReadsTheTargetLikeTheBuild(unittest.TestCase):
    def test_a_platform_without_a_target_file(self):
        with tempfile.TemporaryDirectory() as platforms:
            built, kept = build_target_cores_cache(
                ["recalbox"], "x86_64", platforms, is_all=True
            )
            self.assertEqual((built, kept), ({"recalbox": None}, ["recalbox"]))
            self.assertIsNone(_target_cores_for("recalbox", "x86_64", platforms))

    def test_a_platform_with_a_target_file_is_narrowed(self):
        cores = _target_cores_for("retroarch", "switch", str(REPO_ROOT / "platforms"))
        self.assertTrue(cores)


if __name__ == "__main__":
    unittest.main()
