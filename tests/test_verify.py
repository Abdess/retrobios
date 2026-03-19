"""Tests for verification logic in verify.py."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from common import md5sum
from verify import (
    Status,
    Severity,
    check_inside_zip,
    compute_severity,
    verify_entry_existence,
    verify_entry_md5,
    verify_platform,
)


class TestComputeSeverity(unittest.TestCase):
    """Exhaustive test of compute_severity for all 12 combinations."""

    # existence mode
    def test_existence_ok_required(self):
        self.assertEqual(compute_severity(Status.OK, True, "existence"), Severity.OK)

    def test_existence_ok_optional(self):
        self.assertEqual(compute_severity(Status.OK, False, "existence"), Severity.OK)

    def test_existence_missing_required(self):
        self.assertEqual(compute_severity(Status.MISSING, True, "existence"), Severity.WARNING)

    def test_existence_missing_optional(self):
        self.assertEqual(compute_severity(Status.MISSING, False, "existence"), Severity.INFO)

    def test_existence_untested_required(self):
        self.assertEqual(compute_severity(Status.UNTESTED, True, "existence"), Severity.OK)

    def test_existence_untested_optional(self):
        self.assertEqual(compute_severity(Status.UNTESTED, False, "existence"), Severity.OK)

    # md5 mode
    def test_md5_ok_required(self):
        self.assertEqual(compute_severity(Status.OK, True, "md5"), Severity.OK)

    def test_md5_ok_optional(self):
        self.assertEqual(compute_severity(Status.OK, False, "md5"), Severity.OK)

    def test_md5_missing_required(self):
        self.assertEqual(compute_severity(Status.MISSING, True, "md5"), Severity.CRITICAL)

    def test_md5_missing_optional(self):
        self.assertEqual(compute_severity(Status.MISSING, False, "md5"), Severity.WARNING)

    def test_md5_untested_required(self):
        self.assertEqual(compute_severity(Status.UNTESTED, True, "md5"), Severity.WARNING)

    def test_md5_untested_optional(self):
        self.assertEqual(compute_severity(Status.UNTESTED, False, "md5"), Severity.WARNING)


class TestVerifyEntryExistence(unittest.TestCase):
    """Test verify_entry_existence: present, missing+required, missing+optional."""

    def test_present(self):
        entry = {"name": "bios.bin", "required": True}
        result = verify_entry_existence(entry, "/some/path")
        self.assertEqual(result["status"], Status.OK)
        self.assertTrue(result["required"])

    def test_missing_required(self):
        entry = {"name": "bios.bin", "required": True}
        result = verify_entry_existence(entry, None)
        self.assertEqual(result["status"], Status.MISSING)
        self.assertTrue(result["required"])

    def test_missing_optional(self):
        entry = {"name": "bios.bin", "required": False}
        result = verify_entry_existence(entry, None)
        self.assertEqual(result["status"], Status.MISSING)
        self.assertFalse(result["required"])

    def test_required_defaults_true(self):
        entry = {"name": "bios.bin"}
        result = verify_entry_existence(entry, None)
        self.assertTrue(result["required"])


class TestVerifyEntryMd5(unittest.TestCase):
    """Test verify_entry_md5 with various scenarios."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.content = b"test bios content for md5"
        self.file_path = os.path.join(self.tmpdir, "bios.bin")
        with open(self.file_path, "wb") as f:
            f.write(self.content)
        self.actual_md5 = md5sum(self.file_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_md5_match(self):
        entry = {"name": "bios.bin", "md5": self.actual_md5}
        result = verify_entry_md5(entry, self.file_path)
        self.assertEqual(result["status"], Status.OK)

    def test_md5_mismatch(self):
        entry = {"name": "bios.bin", "md5": "a" * 32}
        result = verify_entry_md5(entry, self.file_path)
        self.assertEqual(result["status"], Status.UNTESTED)
        self.assertIn("reason", result)

    def test_multi_hash_recalbox(self):
        """Recalbox comma-separated MD5 list: any match = OK."""
        wrong_md5 = "b" * 32
        entry = {"name": "bios.bin", "md5": f"{wrong_md5},{self.actual_md5}"}
        result = verify_entry_md5(entry, self.file_path)
        self.assertEqual(result["status"], Status.OK)

    def test_truncated_md5_batocera(self):
        """Batocera 29-char truncated MD5 matches via prefix."""
        truncated = self.actual_md5[:29]
        entry = {"name": "bios.bin", "md5": truncated}
        result = verify_entry_md5(entry, self.file_path)
        self.assertEqual(result["status"], Status.OK)

    def test_no_md5_is_ok(self):
        """No MD5 expected: file present = OK."""
        entry = {"name": "bios.bin"}
        result = verify_entry_md5(entry, self.file_path)
        self.assertEqual(result["status"], Status.OK)

    def test_md5_exact_resolve_status_bypass(self):
        """resolve_status='md5_exact' skips hash computation."""
        entry = {"name": "bios.bin", "md5": "wrong" * 8}
        result = verify_entry_md5(entry, self.file_path, resolve_status="md5_exact")
        self.assertEqual(result["status"], Status.OK)

    def test_missing_file(self):
        entry = {"name": "bios.bin", "md5": self.actual_md5, "required": True}
        result = verify_entry_md5(entry, None)
        self.assertEqual(result["status"], Status.MISSING)

    def test_required_propagated(self):
        entry = {"name": "bios.bin", "md5": self.actual_md5, "required": False}
        result = verify_entry_md5(entry, self.file_path)
        self.assertFalse(result["required"])


class TestCheckInsideZip(unittest.TestCase):
    """Test check_inside_zip for various scenarios."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.inner_content = b"inner rom content"
        self.inner_md5 = hashlib.md5(self.inner_content).hexdigest()

        self.zip_path = os.path.join(self.tmpdir, "container.zip")
        with zipfile.ZipFile(self.zip_path, "w") as zf:
            zf.writestr("ROM.BIN", self.inner_content)

        self.bad_zip = os.path.join(self.tmpdir, "bad.zip")
        with open(self.bad_zip, "wb") as f:
            f.write(b"not a zip file")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_found_and_match(self):
        result = check_inside_zip(self.zip_path, "ROM.BIN", self.inner_md5)
        self.assertEqual(result, Status.OK)

    def test_found_and_mismatch(self):
        result = check_inside_zip(self.zip_path, "ROM.BIN", "f" * 32)
        self.assertEqual(result, Status.UNTESTED)

    def test_not_in_zip(self):
        result = check_inside_zip(self.zip_path, "MISSING.BIN", self.inner_md5)
        self.assertEqual(result, "not_in_zip")

    def test_bad_zip(self):
        result = check_inside_zip(self.bad_zip, "ROM.BIN", self.inner_md5)
        self.assertEqual(result, "error")

    def test_casefold_match(self):
        """Batocera uses casefold() for filename comparison."""
        result = check_inside_zip(self.zip_path, "rom.bin", self.inner_md5)
        self.assertEqual(result, Status.OK)

    def test_empty_md5_means_ok(self):
        """Empty expected_md5 -> OK if file found (existence check inside ZIP)."""
        result = check_inside_zip(self.zip_path, "ROM.BIN", "")
        self.assertEqual(result, Status.OK)


class TestVerifyPlatform(unittest.TestCase):
    """Test verify_platform aggregation logic."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        # Create two files
        self.file_a = os.path.join(self.tmpdir, "a.bin")
        self.file_b = os.path.join(self.tmpdir, "b.bin")
        with open(self.file_a, "wb") as f:
            f.write(b"file a content")
        with open(self.file_b, "wb") as f:
            f.write(b"file b content")

        from common import compute_hashes
        ha = compute_hashes(self.file_a)
        hb = compute_hashes(self.file_b)

        self.db = {
            "files": {
                ha["sha1"]: {"path": self.file_a, "name": "a.bin", "md5": ha["md5"], "size": 14},
                hb["sha1"]: {"path": self.file_b, "name": "b.bin", "md5": hb["md5"], "size": 14},
            },
            "indexes": {
                "by_md5": {
                    ha["md5"]: ha["sha1"],
                    hb["md5"]: hb["sha1"],
                },
                "by_name": {
                    "a.bin": [ha["sha1"]],
                    "b.bin": [hb["sha1"]],
                },
                "by_crc32": {},
            },
        }
        self.sha1_a = ha["sha1"]
        self.sha1_b = hb["sha1"]
        self.md5_a = ha["md5"]
        self.md5_b = hb["md5"]

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_all_ok_existence(self):
        config = {
            "platform": "TestPlatform",
            "verification_mode": "existence",
            "systems": {
                "sys1": {
                    "files": [
                        {"name": "a.bin", "sha1": self.sha1_a, "required": True},
                        {"name": "b.bin", "sha1": self.sha1_b, "required": False},
                    ]
                }
            },
        }
        # No emulators dir needed for basic test
        emu_dir = os.path.join(self.tmpdir, "emulators")
        os.makedirs(emu_dir, exist_ok=True)
        result = verify_platform(config, self.db, emu_dir)
        self.assertEqual(result["platform"], "TestPlatform")
        self.assertEqual(result["verification_mode"], "existence")
        self.assertEqual(result["total_files"], 2)
        self.assertEqual(result["severity_counts"][Severity.OK], 2)

    def test_worst_status_wins_per_destination(self):
        """Two entries for same destination: worst status wins."""
        config = {
            "platform": "Test",
            "verification_mode": "existence",
            "systems": {
                "sys1": {
                    "files": [
                        {"name": "a.bin", "sha1": self.sha1_a, "destination": "shared.bin", "required": True},
                    ]
                },
                "sys2": {
                    "files": [
                        {"name": "missing.bin", "sha1": "0" * 40, "destination": "shared.bin", "required": True},
                    ]
                },
            },
        }
        emu_dir = os.path.join(self.tmpdir, "emulators")
        os.makedirs(emu_dir, exist_ok=True)
        result = verify_platform(config, self.db, emu_dir)
        # shared.bin should have worst status (missing)
        self.assertEqual(result["total_files"], 1)
        # The worst severity for required+missing in existence mode = WARNING
        self.assertEqual(result["severity_counts"][Severity.WARNING], 1)

    def test_severity_counts_sum_to_total(self):
        config = {
            "platform": "Test",
            "verification_mode": "md5",
            "systems": {
                "sys1": {
                    "files": [
                        {"name": "a.bin", "sha1": self.sha1_a, "md5": self.md5_a, "required": True},
                        {"name": "missing.bin", "sha1": "0" * 40, "md5": "f" * 32, "required": True},
                    ]
                }
            },
        }
        emu_dir = os.path.join(self.tmpdir, "emulators")
        os.makedirs(emu_dir, exist_ok=True)
        result = verify_platform(config, self.db, emu_dir)
        total_from_counts = sum(result["severity_counts"].values())
        self.assertEqual(total_from_counts, result["total_files"])

    def test_required_field_in_details(self):
        config = {
            "platform": "Test",
            "verification_mode": "existence",
            "systems": {
                "sys1": {
                    "files": [
                        {"name": "a.bin", "sha1": self.sha1_a, "required": False},
                    ]
                }
            },
        }
        emu_dir = os.path.join(self.tmpdir, "emulators")
        os.makedirs(emu_dir, exist_ok=True)
        result = verify_platform(config, self.db, emu_dir)
        detail = result["details"][0]
        self.assertFalse(detail["required"])


if __name__ == "__main__":
    unittest.main()
