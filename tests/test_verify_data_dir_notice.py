"""verify --platform names the data directories that were never refreshed.

A platform entry can resolve only through a data directory tree (AmberELEC's
Machines/*/config.ini in the blueMSX tree). On a checkout where data/ was
never refreshed, verify counted 200 such entries missing with no word on the
cause, while an online pack build refreshes the trees and packs them.
verify --emulator already named its uncached trees.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_db  # noqa: E402
from verify import print_platform_result, verify_platform  # noqa: E402


class UncachedDataDirectoryNotice(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)
        Path("emulators").mkdir()
        Path("data/present").mkdir(parents=True)
        self.db = {"files": {}, "indexes": generate_db.build_indexes({}, {})}
        self.config = {
            "platform": "Tree", "verification_mode": "md5",
            "systems": {"msx": {"files": [{
                "name": "config.ini", "destination": "Machines/MSX/config.ini",
            }]}},
        }
        self.registry = {
            "absent": {"local_cache": "data/absent"},
            "present": {"local_cache": "data/present"},
        }

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def _run(self) -> tuple[dict, str]:
        result = verify_platform(
            self.config, self.db, "emulators", {}, data_dir_registry=self.registry,
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            print_platform_result(result, ["Tree"])
        return result, out.getvalue()

    def test_an_uncached_tree_is_named(self):
        result, printed = self._run()
        self.assertEqual(result["data_dir_notices"], ["absent"])
        self.assertIn("Data directories not cached (1)", printed)
        self.assertIn("refresh_data_dirs.py", printed)
        self.assertIn(": absent", printed)

    def test_no_note_when_every_tree_is_cached(self):
        Path("data/absent").mkdir()
        result, printed = self._run()
        self.assertEqual(result["data_dir_notices"], [])
        self.assertNotIn("refresh_data_dirs", printed)


if __name__ == "__main__":
    unittest.main()
