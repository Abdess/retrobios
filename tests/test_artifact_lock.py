#!/usr/bin/env python3
"""Concurrency guard on the pack output directory.

Two runs building the same dist/ leave readers looking at half-written
ZIPs, which surfaces as BadZipFile far from its cause.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import ArtifactLockBusy, artifact_lock  # noqa: E402


class ArtifactLockTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_writer_excludes_writer(self):
        with artifact_lock(self.dir):
            with self.assertRaises(ArtifactLockBusy):
                with artifact_lock(self.dir):
                    pass

    def test_writer_excludes_reader(self):
        with artifact_lock(self.dir):
            with self.assertRaises(ArtifactLockBusy):
                with artifact_lock(self.dir, exclusive=False):
                    pass

    def test_readers_share(self):
        with artifact_lock(self.dir, exclusive=False):
            with artifact_lock(self.dir, exclusive=False):
                pass

    def test_lock_is_released_on_exit(self):
        with artifact_lock(self.dir):
            pass
        with artifact_lock(self.dir):
            pass

    def test_lock_is_released_on_error(self):
        with self.assertRaises(ValueError):
            with artifact_lock(self.dir):
                raise ValueError("boom")
        with artifact_lock(self.dir):
            pass

    def test_separate_directories_do_not_contend(self):
        other = tempfile.mkdtemp()
        with artifact_lock(self.dir):
            with artifact_lock(other):
                pass

    def test_lock_survives_a_missing_directory(self):
        missing = os.path.join(self.dir, "not-created-yet")
        with artifact_lock(missing):
            self.assertTrue(os.path.isdir(missing))


class PackLockCliTest(unittest.TestCase):
    """generate_pack and pipeline must refuse a directory held elsewhere."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, *argv],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=300,
        )

    def test_generate_pack_refuses_locked_output(self):
        with artifact_lock(self.dir):
            proc = self._run(
                [
                    "scripts/generate_pack.py",
                    "--platform",
                    "misterfpga",
                    "--output-dir",
                    self.dir,
                    "--offline",
                ]
            )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("is in use by another run", proc.stdout)

    def test_verify_packs_refuses_a_writer(self):
        with artifact_lock(self.dir):
            proc = self._run(
                [
                    "scripts/generate_pack.py",
                    "--platform",
                    "misterfpga",
                    "--verify-packs",
                    "--output-dir",
                    self.dir,
                ]
            )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("is in use by another run", proc.stdout)

    def test_pipeline_refuses_locked_output(self):
        with artifact_lock(self.dir):
            proc = self._run(
                [
                    "scripts/pipeline.py",
                    "--offline",
                    "--skip-docs",
                    "--output-dir",
                    self.dir,
                ]
            )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("is in use by another run", proc.stdout)


if __name__ == "__main__":
    unittest.main()
