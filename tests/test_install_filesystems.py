"""What an install does for the device and file system it lands on."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from test_install_selection import FakeRepository  # noqa: E402


class AndroidMediaScanner(unittest.TestCase):
    """Without a .nomedia the BIOS folder's samples, overlays and videos
    showed in the phone's gallery and music apps."""

    def setUp(self):
        self.repo = FakeRepository().__enter__()
        self.addCleanup(self.repo.__exit__)

    def _run(self, os_name: str, *options: str):
        proc = subprocess.run(self.repo.command("--yes", "--no-input", *options),
                              env={**self.repo.env(), "RETROBIOS_OS": os_name},
                              capture_output=True, text=True, timeout=60,
                              stdin=subprocess.DEVNULL)
        return self.repo, proc

    def test_an_android_install_writes_one(self):
        repo, proc = self._run("android")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        marker = repo.dest / ".nomedia"
        self.assertTrue(marker.is_file())
        self.assertEqual(marker.stat().st_size, 0)
        self.assertIn("Added .nomedia", proc.stdout)

    def test_a_second_run_leaves_it_and_says_nothing(self):
        self._run("android")
        _, proc = self._run("android")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("Added .nomedia", proc.stdout)
        # The marker is not a file of the list: the check finds all in place.
        _, check = self._run("android", "--check")
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_a_check_and_a_dry_run_write_nothing(self):
        for options in (("--check",), ("--dry-run",)):
            with self.subTest(options=options):
                self._run("android", *options)
                self.assertFalse((self.repo.dest / ".nomedia").exists())

    def test_other_systems_get_none(self):
        repo, proc = self._run("linux")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse((repo.dest / ".nomedia").exists())


if __name__ == "__main__":
    unittest.main()
