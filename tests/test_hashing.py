"""compute_hashes reads a file once per process and change, and one loop digests files and streams."""

from __future__ import annotations

import tests

import hashlib
import io
import shutil
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest import mock

from core import hashing

REPO_ROOT = Path(__file__).resolve().parents[1]


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


class OneDigestLoopForFilesAndStreams(unittest.TestCase):
    """A ZIP member, a file and an open stream are hashed by the same loop,
    so the pack check, the PR review and the recipes agree with the resolver."""

    DATA = bytes(range(256)) * 600  # over two 64 KiB reads

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.file = self.dir / "rom.bin"
        self.file.write_bytes(self.DATA)

    def test_a_stream_gives_the_file_digests(self):
        expected = {
            "sha1": hashlib.sha1(self.DATA).hexdigest(),
            "md5": hashlib.md5(self.DATA).hexdigest(),
            "sha256": hashlib.sha256(self.DATA).hexdigest(),
            "crc32": format(zlib.crc32(self.DATA) & 0xFFFFFFFF, "08x"),
            "adler32": format(zlib.adler32(self.DATA) & 0xFFFFFFFF, "08x"),
        }
        self.assertEqual(hashing.compute_hashes(self.file, cache=False), expected)
        with open(self.file, "rb") as handle:
            self.assertEqual(hashing.stream_hashes(handle, frozenset(expected)), expected)
        self.assertEqual(hashing.stream_hashes(io.BytesIO(self.DATA), frozenset({"crc32"})),
                         {"crc32": expected["crc32"]})

    def test_a_zip_member_and_md5sum(self):
        archive = self.dir / "set.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("rom.bin", self.DATA)
        with zipfile.ZipFile(archive) as zf, zf.open("rom.bin") as member:
            sha1 = hashing.stream_hashes(member, frozenset({"sha1"}))["sha1"]
        self.assertEqual(sha1, hashing.file_digest(self.file))
        self.assertEqual(hashing.md5sum(self.file), hashlib.md5(self.DATA).hexdigest())
        self.assertEqual(hashing.md5sum(io.BytesIO(self.DATA)), hashlib.md5(self.DATA).hexdigest())


if __name__ == "__main__":
    unittest.main()
