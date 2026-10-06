"""A platform whose pack or manifest raised fails the run.

Both loops printed ERROR and moved on. The exit code came from the packs
present on disk, so a pack never written, or a manifest install.py would
keep serving from an older run, left the run green.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_pack as gp  # noqa: E402


def _boom(*args, **kwargs):
    raise OSError(28, "No space left on device")


class FailedPlatformFailsTheRun(unittest.TestCase):
    def setUp(self):
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self.addCleanup(self.tmp.cleanup)

    def _args(self) -> argparse.Namespace:
        return argparse.Namespace(
            all_variants=False, source="full", required_only=False,
            platforms_dir="platforms", target=None, split=False,
            emulators_dir="emulators", regions=[],
            one_per_slot=False, offline=True, bios_dir="bios",
            output_dir=self.tmp.name, verify_packs=False,
        )

    def test_pack_mode(self):
        with mock.patch.object(gp, "generate_pack", _boom), \
                mock.patch.object(gp, "verify_and_finalize_packs", return_value=True):
            with self.assertRaises(SystemExit) as ctx:
                gp._run_platform_packs(
                    self._args(), [(["retropie"], "retropie")], {}, {}, {}, {}, {}, None
                )
        self.assertEqual(ctx.exception.code, 1)

    def test_manifest_mode(self):
        with mock.patch.object(gp, "generate_manifest", _boom):
            with self.assertRaises(SystemExit) as ctx:
                gp._run_manifest_mode(
                    self._args(), [(["retropie"], "retropie")], {}, {}, {}, {}
                )
        self.assertEqual(ctx.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
