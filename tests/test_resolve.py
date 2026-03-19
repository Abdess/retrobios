"""Tests for resolve_local_file from common.py."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from common import resolve_local_file, compute_hashes, md5_composite


class TestResolveLocalFile(unittest.TestCase):
    """Test resolve_local_file resolution chain."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        # Create a fake BIOS file
        self.bios_content = b"fake bios data for testing"
        self.bios_path = os.path.join(self.tmpdir, "bios.bin")
        with open(self.bios_path, "wb") as f:
            f.write(self.bios_content)
        hashes = compute_hashes(self.bios_path)
        self.sha1 = hashes["sha1"]
        self.md5 = hashes["md5"]
        self.crc32 = hashes["crc32"]

        # Create a second file in .variants/
        self.variant_path = os.path.join(self.tmpdir, ".variants", "bios.bin.abcd1234")
        os.makedirs(os.path.dirname(self.variant_path), exist_ok=True)
        self.variant_content = b"variant bios data"
        with open(self.variant_path, "wb") as f:
            f.write(self.variant_content)
        variant_hashes = compute_hashes(self.variant_path)
        self.variant_sha1 = variant_hashes["sha1"]
        self.variant_md5 = variant_hashes["md5"]

        # Create a ZIP file with an inner ROM
        self.zip_path = os.path.join(self.tmpdir, "game.zip")
        self.inner_content = b"inner rom data"
        self.inner_md5 = hashlib.md5(self.inner_content).hexdigest()
        with zipfile.ZipFile(self.zip_path, "w") as zf:
            zf.writestr("rom.bin", self.inner_content)
        zip_hashes = compute_hashes(self.zip_path)
        self.zip_sha1 = zip_hashes["sha1"]
        self.zip_md5 = zip_hashes["md5"]

        # Build a minimal database
        self.db = {
            "files": {
                self.sha1: {
                    "path": self.bios_path,
                    "name": "bios.bin",
                    "md5": self.md5,
                    "size": len(self.bios_content),
                },
                self.variant_sha1: {
                    "path": self.variant_path,
                    "name": "bios.bin",
                    "md5": self.variant_md5,
                    "size": len(self.variant_content),
                },
                self.zip_sha1: {
                    "path": self.zip_path,
                    "name": "game.zip",
                    "md5": self.zip_md5,
                    "size": os.path.getsize(self.zip_path),
                },
            },
            "indexes": {
                "by_md5": {
                    self.md5: self.sha1,
                    self.variant_md5: self.variant_sha1,
                    self.zip_md5: self.zip_sha1,
                },
                "by_name": {
                    "bios.bin": [self.sha1, self.variant_sha1],
                    "game.zip": [self.zip_sha1],
                    "alias.bin": [self.sha1],
                },
                "by_crc32": {
                    self.crc32: self.sha1,
                },
            },
        }

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_sha1_exact_match(self):
        entry = {"sha1": self.sha1, "name": "bios.bin"}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "exact")
        self.assertEqual(path, self.bios_path)

    def test_md5_direct_match(self):
        entry = {"md5": self.md5, "name": "something_else.bin"}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "md5_exact")
        self.assertEqual(path, self.bios_path)

    def test_name_match_no_md5(self):
        """No MD5 provided: resolve by name from by_name index."""
        entry = {"name": "bios.bin"}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "exact")
        # Primary (non-.variants/) path preferred
        self.assertEqual(path, self.bios_path)

    def test_alias_match_no_md5(self):
        """Alias name in by_name index resolves the file."""
        entry = {"name": "unknown.bin", "aliases": ["alias.bin"]}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "exact")
        self.assertEqual(path, self.bios_path)

    def test_not_found(self):
        entry = {"sha1": "0000000000000000000000000000000000000000", "name": "missing.bin"}
        path, status = resolve_local_file(entry, self.db)
        self.assertIsNone(path)
        self.assertEqual(status, "not_found")

    def test_hash_mismatch_fallback(self):
        """File found by name but MD5 doesn't match -> hash_mismatch."""
        wrong_md5 = "a" * 32
        entry = {"name": "bios.bin", "md5": wrong_md5}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "hash_mismatch")
        # Should prefer primary over .variants/
        self.assertEqual(path, self.bios_path)

    def test_zipped_file_resolution_via_zip_contents(self):
        """zipped_file entry resolved through zip_contents index."""
        zip_contents = {self.inner_md5: self.zip_sha1}
        entry = {
            "name": "nonexistent_zip.zip",
            "md5": self.inner_md5,
            "zipped_file": "rom.bin",
        }
        path, status = resolve_local_file(entry, self.db, zip_contents)
        self.assertEqual(status, "zip_exact")
        self.assertEqual(path, self.zip_path)

    def test_variants_deprioritized(self):
        """Primary path preferred over .variants/ path."""
        # Both bios_path and variant_path have name "bios.bin" in by_name
        entry = {"name": "bios.bin"}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "exact")
        self.assertNotIn(".variants", path)

    def test_truncated_md5_match(self):
        """Batocera truncated MD5 (29 chars) matches via prefix."""
        truncated = self.md5[:29]
        entry = {"md5": truncated, "name": "something.bin"}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "md5_exact")
        self.assertEqual(path, self.bios_path)


if __name__ == "__main__":
    unittest.main()
