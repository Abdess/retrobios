"""The flat-tree migration says its plan through the caller, and a failed copy reaches the command once."""

from __future__ import annotations

import tests

import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from devtools import biosmigrate

REPO_ROOT = Path(__file__).resolve().parents[1]


class MigrationSaysItsPlan(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.source = self.dir / "src"
        self.target = self.dir / "bios"
        flat = self.source / "Sony - PlayStation"
        flat.mkdir(parents=True)
        (flat / "scph5501.bin").write_bytes(b"a" * 16)
        (flat / "scph1001.bin").write_bytes(b"b" * 16)
        held = self.target / "Sony" / "PlayStation"
        held.mkdir(parents=True)
        (held / "scph1001.bin").write_bytes(b"b" * 16)

    def test_a_dry_run_returns_its_plan_without_printing(self):
        said: list[str] = []
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            moved, skipped, errors, hashes = biosmigrate.migrate_local(
                self.source, self.target, True, said.append)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual((moved, skipped, errors, len(hashes)), (1, 1, [], 1))
        self.assertEqual(said, ["  Sony - PlayStation/ -> bios/Sony/PlayStation/",
                                "    SKIP (exists): scph1001.bin",
                                "    COPY: scph5501.bin"])
        self.assertFalse((self.target / "Sony" / "PlayStation" / "scph5501.bin").exists())

    def test_a_failed_copy_is_returned_not_said(self):
        said: list[str] = []
        with mock.patch.object(biosmigrate.shutil, "copy2", side_effect=OSError("denied")):
            moved, _, errors, _ = biosmigrate.migrate_local(
                self.source, self.target, False, said.append)
        self.assertEqual(moved, 0)
        self.assertEqual([(f.name, e) for f, e in errors], [("scph5501.bin", "denied")])
        self.assertFalse(any("denied" in line for line in said))

    def test_the_command_names_each_error_once(self):
        flat = self.source / "Sony - PlayStation"
        (self.target / "Sony" / "PlayStation").chmod(0o500)
        self.addCleanup((self.target / "Sony" / "PlayStation").chmod, 0o700)
        if os.access(self.target / "Sony" / "PlayStation", os.W_OK):
            self.skipTest("running as a user every folder lets write")
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "migrate.py"),
             "--source", str(self.source), "--target", str(self.target)],
            capture_output=True, text=True, check=False, cwd=self.dir,
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(proc.stdout.count("scph5501.bin: "), 1, proc.stdout)
        self.assertIn(f"  {flat / 'scph5501.bin'}: ", proc.stdout)


if __name__ == "__main__":
    unittest.main()
