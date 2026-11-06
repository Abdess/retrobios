"""compute_hashes reads a file once per process and change."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import hashing  # noqa: E402


class HashesAreReadOncePerContent(unittest.TestCase):
    """verify --all hashed GB_dmg.bin 13 times and scph5501.bin 12, once
    per platform and entry, in one process."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.file = self.dir / "rom.bin"
        self.file.write_bytes(b"a" * 64)

    def test_a_second_ask_reads_nothing(self):
        first = hashing.compute_hashes(self.file)
        with mock.patch.object(hashing, "_compute_hashes", side_effect=AssertionError):
            self.assertEqual(hashing.compute_hashes(self.file), first)
            self.assertEqual(
                hashing.compute_hashes(self.file, frozenset({"md5"})),
                {"md5": first["md5"]},
            )

    def test_a_rewrite_in_place_is_read_again(self):
        first = hashing.compute_hashes(self.file)
        with open(self.file, "r+b") as handle:
            handle.write(b"b" * 64)
        self.assertNotEqual(hashing.compute_hashes(self.file)["sha1"], first["sha1"])


if __name__ == "__main__":
    unittest.main()
