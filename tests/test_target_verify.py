"""A targeted pack is checked under the target reading it was built with.

`--all --target x86_64` packs a platform that has no target file unnarrowed
under the target's name (Recalbox, Lakka, BizHawk, MiSTer, ROCKNIX). The
conformance check read the same target without the --all tolerance, raised
FileNotFoundError on the first of those packs and stopped the run in a
traceback after every pack had been written. Such a platform is now left
out of a targeted --all run, and the check refuses it as the build does.
"""

from __future__ import annotations

import sys
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import build_target_cores_cache  # noqa: E402
from generate_pack import _target_cores_for  # noqa: E402


class CheckReadsTheTargetLikeTheBuild(unittest.TestCase):
    def test_a_platform_without_a_target_file(self):
        # Left out of a targeted --all run rather than built unfiltered, and
        # a run where no platform has the target is refused.
        with tempfile.TemporaryDirectory() as platforms, \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError):
                build_target_cores_cache(["recalbox"], "x86_64", platforms, is_all=True)
        # The build never packs such a platform under the target, so the
        # check refuses it too instead of reading the full pack.
        with self.assertRaises(FileNotFoundError):
            _target_cores_for("recalbox", "x86_64", platforms)

    def test_a_platform_with_a_target_file_is_narrowed(self):
        cores = _target_cores_for("retroarch", "switch", str(REPO_ROOT / "platforms"))
        self.assertTrue(cores)


class ANameClaimsOnlyANarrowingThatHappened(unittest.TestCase):
    """--all --target switch packed BizHawk and MiSTer whole, and named them
    BizHawk_..._Switch_BIOS_Pack.zip with a README saying 'cores available
    on switch'."""

    def test_a_platform_without_the_target_is_named_plainly(self):
        from generate_pack import _narrowings, _platform_target

        platforms = str(REPO_ROOT / "platforms")
        self.assertIsNone(_platform_target("bizhawk", "switch", platforms))
        self.assertEqual(_narrowings("full", None, None, False, False), [])
        self.assertEqual(
            _platform_target("retroarch", "nx", platforms), "nintendo-switch"
        )


if __name__ == "__main__":
    unittest.main()
