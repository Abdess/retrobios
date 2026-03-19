"""Tests for pack generation logic in generate_pack.py."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from common import compute_hashes
from generate_pack import build_zip_contents_index


class TestBuildZipContentsIndex(unittest.TestCase):
    """Test build_zip_contents_index: maps inner ROM MD5 to container SHA1."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.inner_content = b"inner rom data for index test"
        self.inner_md5 = hashlib.md5(self.inner_content).hexdigest()

        self.zip_path = os.path.join(self.tmpdir, "container.zip")
        with zipfile.ZipFile(self.zip_path, "w") as zf:
            zf.writestr("rom.bin", self.inner_content)

        hashes = compute_hashes(self.zip_path)
        self.zip_sha1 = hashes["sha1"]
        self.zip_md5 = hashes["md5"]

        self.db = {
            "files": {
                self.zip_sha1: {
                    "path": self.zip_path,
                    "name": "container.zip",
                    "md5": self.zip_md5,
                    "size": os.path.getsize(self.zip_path),
                },
            },
            "indexes": {
                "by_md5": {self.zip_md5: self.zip_sha1},
                "by_name": {"container.zip": [self.zip_sha1]},
                "by_crc32": {},
            },
        }

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_inner_md5_maps_to_container_sha1(self):
        index = build_zip_contents_index(self.db)
        self.assertIn(self.inner_md5, index)
        self.assertEqual(index[self.inner_md5], self.zip_sha1)

    def test_non_zip_files_skipped(self):
        """Non-ZIP files in db don't appear in index."""
        plain_path = os.path.join(self.tmpdir, "plain.bin")
        with open(plain_path, "wb") as f:
            f.write(b"not a zip")
        hashes = compute_hashes(plain_path)
        self.db["files"][hashes["sha1"]] = {
            "path": plain_path,
            "name": "plain.bin",
            "md5": hashes["md5"],
            "size": 9,
        }
        index = build_zip_contents_index(self.db)
        # Only the inner_md5 from the ZIP should be present
        self.assertEqual(len(index), 1)

    def test_missing_file_skipped(self):
        """ZIP path that doesn't exist on disk is skipped."""
        self.db["files"]["fake_sha1"] = {
            "path": "/nonexistent/file.zip",
            "name": "file.zip",
            "md5": "a" * 32,
            "size": 0,
        }
        index = build_zip_contents_index(self.db)
        self.assertEqual(len(index), 1)

    def test_bad_zip_skipped(self):
        """Corrupt ZIP file is skipped without error."""
        bad_path = os.path.join(self.tmpdir, "bad.zip")
        with open(bad_path, "wb") as f:
            f.write(b"corrupt data")
        hashes = compute_hashes(bad_path)
        self.db["files"][hashes["sha1"]] = {
            "path": bad_path,
            "name": "bad.zip",
            "md5": hashes["md5"],
            "size": 12,
        }
        index = build_zip_contents_index(self.db)
        self.assertEqual(len(index), 1)


class TestFileStatusAggregation(unittest.TestCase):
    """Test worst-status-wins logic for pack file aggregation."""

    def test_worst_status_wins(self):
        """Simulate the worst-status-wins dict pattern from generate_pack."""
        sev_order = {"ok": 0, "untested": 1, "missing": 2}
        file_status = {}

        def update_status(dest, status):
            prev = file_status.get(dest)
            if prev is None or sev_order.get(status, 0) > sev_order.get(prev, 0):
                file_status[dest] = status

        update_status("system/bios.bin", "ok")
        update_status("system/bios.bin", "missing")
        self.assertEqual(file_status["system/bios.bin"], "missing")

        update_status("system/other.bin", "untested")
        update_status("system/other.bin", "ok")
        self.assertEqual(file_status["system/other.bin"], "untested")

    def test_dedup_same_destination_packed_once(self):
        """Same destination from multiple systems: only first is packed."""
        seen = set()
        packed = []
        entries = [
            {"dest": "shared/bios.bin", "source": "sys1"},
            {"dest": "shared/bios.bin", "source": "sys2"},
            {"dest": "unique/other.bin", "source": "sys3"},
        ]
        for e in entries:
            if e["dest"] in seen:
                continue
            seen.add(e["dest"])
            packed.append(e["dest"])
        self.assertEqual(len(packed), 2)
        self.assertIn("shared/bios.bin", packed)
        self.assertIn("unique/other.bin", packed)


class TestEmuDeckNoDestination(unittest.TestCase):
    """EmuDeck entries with no destination are counted as checks."""

    def test_no_destination_counted_as_check(self):
        """EmuDeck-style entries (md5 whitelist, no filename) are tracked."""
        file_status = {}
        # Simulate generate_pack logic for empty dest
        sys_id = "psx"
        name = ""
        md5 = "abc123"
        by_md5 = {"abc123": "sha1_match"}

        dest = ""  # empty destination
        if not dest:
            fkey = f"{sys_id}/{name}"
            if md5 and md5 in by_md5:
                file_status.setdefault(fkey, "ok")
            else:
                file_status[fkey] = "missing"

        self.assertIn("psx/", file_status)
        self.assertEqual(file_status["psx/"], "ok")

    def test_no_destination_missing(self):
        file_status = {}
        sys_id = "psx"
        name = ""
        md5 = "abc123"
        by_md5 = {}

        dest = ""
        if not dest:
            fkey = f"{sys_id}/{name}"
            if md5 and md5 in by_md5:
                file_status.setdefault(fkey, "ok")
            else:
                file_status[fkey] = "missing"

        self.assertEqual(file_status["psx/"], "missing")


class TestUserProvidedEntries(unittest.TestCase):
    """Test user_provided storage handling."""

    def test_user_provided_creates_instruction_file(self):
        """Simulate user_provided entry packing logic."""
        tmpdir = tempfile.mkdtemp()
        try:
            zip_path = os.path.join(tmpdir, "test_pack.zip")
            with zipfile.ZipFile(zip_path, "w") as zf:
                entry = {
                    "name": "PS3UPDAT.PUP",
                    "storage": "user_provided",
                    "instructions": "Download from sony.com",
                }
                instr_name = f"INSTRUCTIONS_{entry['name']}.txt"
                zf.writestr(instr_name, f"File needed: {entry['name']}\n\n{entry['instructions']}\n")

            with zipfile.ZipFile(zip_path, "r") as zf:
                names = zf.namelist()
                self.assertIn("INSTRUCTIONS_PS3UPDAT.PUP.txt", names)
                content = zf.read("INSTRUCTIONS_PS3UPDAT.PUP.txt").decode()
                self.assertIn("PS3UPDAT.PUP", content)
                self.assertIn("sony.com", content)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestZippedFileHashMismatch(unittest.TestCase):
    """Test zipped_file with hash_mismatch triggers check_inside_zip."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.inner_content = b"correct inner rom"
        self.inner_md5 = hashlib.md5(self.inner_content).hexdigest()
        self.zip_path = os.path.join(self.tmpdir, "game.zip")
        with zipfile.ZipFile(self.zip_path, "w") as zf:
            zf.writestr("rom.bin", self.inner_content)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_hash_mismatch_zip_inner_ok(self):
        """hash_mismatch on container, but inner ROM MD5 matches."""
        from verify import check_inside_zip, Status
        result = check_inside_zip(self.zip_path, "rom.bin", self.inner_md5)
        self.assertEqual(result, Status.OK)

    def test_hash_mismatch_zip_inner_not_found(self):
        from verify import check_inside_zip
        result = check_inside_zip(self.zip_path, "missing.bin", self.inner_md5)
        self.assertEqual(result, "not_in_zip")


if __name__ == "__main__":
    unittest.main()
