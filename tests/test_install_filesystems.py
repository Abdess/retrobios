"""What an install does for the device and file system it lands on."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import errno
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import install  # noqa: E402
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


class NamesAFatCardCannotHold(unittest.TestCase):
    """RetroDECK names three files with a colon (zxs:48.rom): on an exFAT
    card each write failed with EINVAL, on every run."""

    def test_the_probe_reads_einval_as_a_refusal(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            refused = OSError(errno.EINVAL, "Invalid argument")
            closed = PermissionError(errno.EACCES, "Permission denied")
            with mock.patch.object(install.os, "name", "posix"):
                self.assertTrue(install.holds_fat_refused_names(Path(tmp) / "a" / "b"))
                with mock.patch.object(install.tempfile, "mkstemp", side_effect=refused):
                    self.assertFalse(install.holds_fat_refused_names(Path(tmp)))
                with mock.patch.object(install.tempfile, "mkstemp", side_effect=closed):
                    self.assertTrue(install.holds_fat_refused_names(Path(tmp)))
            self.assertEqual(os.listdir(tmp), [])

    def test_windows_refuses_them_on_any_drive(self):
        with mock.patch.object(install.os, "name", "nt"):
            self.assertFalse(install.holds_fat_refused_names(Path(".")))

    def _install(self, holds: bool) -> tuple[str, list[str]]:
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        old, dest = root / "old", root / "dest"
        old.mkdir()
        files = []
        for name, payload in (("zxs:48.rom", b"zx 48"), ("gba_bios.bin", b"gba")):
            (old / name.replace(":", "_")).write_bytes(payload)
            files.append({"dest": name, "sha1": hashlib.sha1(payload).hexdigest(),
                          "sha256": hashlib.sha256(payload).hexdigest(),
                          "size": len(payload), "repo_path": f"bios/{name}"})
        listed = root / "list.json"
        listed.write_text(json.dumps({"manifest_version": 2, "platform": "retrodeck",
                                      "files": files}))
        out = io.StringIO()
        argv = ["install.py", "--platform", "retrodeck", "--dest", str(dest),
                "--manifest", str(listed), "--from", str(old), "--no-input"]
        with mock.patch.object(install, "holds_fat_refused_names", return_value=holds), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch("sys.argv", argv), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                install.main()
            except SystemExit as exc:
                self.assertIn(exc.code, (0, None), out.getvalue())
        self.addCleanup(install.LOCAL.reset)
        return (" ".join(out.getvalue().split()),
                sorted(p.name for p in dest.iterdir()) if dest.is_dir() else [])

    def test_the_names_are_left_out_and_said(self):
        said, installed = self._install(holds=False)
        self.assertEqual(installed, ["gba_bios.bin"])
        self.assertIn("1 file left out: the file system of", said)
        self.assertIn('cannot hold a name with any of < > : " | ? * (zxs:48.rom)', said)

    def test_a_folder_that_holds_them_gets_them(self):
        said, installed = self._install(holds=True)
        self.assertEqual(installed, ["gba_bios.bin", "zxs:48.rom"])
        self.assertNotIn("left out", said)


if __name__ == "__main__":
    unittest.main()
