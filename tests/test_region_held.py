"""A dump the frontend refuses does not hold a regional slot.

platform_region_groups counted a declaration as held as soon as a file
answered it, hash_mismatch included. On a md5 platform the builder leaves
that file out as unsafe, so a US file with the wrong md5 displaced a correct
Japanese one, and the system shipped no BIOS at all.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from packextras import _ships  # noqa: E402


class ARefusedDumpHoldsNothing(unittest.TestCase):
    def test_held_follows_the_frontend(self):
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        previous = os.getcwd()
        os.chdir(root)
        self.addCleanup(os.chdir, previous)
        Path("bios").mkdir()
        data = b"US BIOS, ANOTHER REVISION"
        Path("bios/us.bin").write_bytes(data)
        sha1 = hashlib.sha1(data).hexdigest()
        db = {
            "files": {sha1: {"path": "bios/us.bin", "name": "us.bin", "size": len(data),
                             "md5": hashlib.md5(data).hexdigest(), "crc32": ""}},
            "indexes": {"by_md5": {}, "by_name": {"us.bin": [sha1]}, "by_crc32": {},
                        "by_path_suffix": {}},
        }
        entry = {"name": "us.bin", "md5": "0" * 32}
        self.assertFalse(_ships({"verification_mode": "md5"}, entry, db))
        self.assertTrue(_ships({"verification_mode": "existence"}, entry, db))
        self.assertTrue(_ships({"verification_mode": "md5"}, {"name": "us.bin"}, db))


if __name__ == "__main__":
    unittest.main()
