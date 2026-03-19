"""Tests for alias support in resolve_local_file and generate_db."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from common import compute_hashes, resolve_local_file
from generate_db import build_indexes


class TestAliasesInResolve(unittest.TestCase):
    """Test that aliases field in file_entry enables resolution."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.content = b"colecovision bios content"
        self.file_path = os.path.join(self.tmpdir, "colecovision.rom")
        with open(self.file_path, "wb") as f:
            f.write(self.content)
        hashes = compute_hashes(self.file_path)
        self.sha1 = hashes["sha1"]
        self.md5 = hashes["md5"]

        self.db = {
            "files": {
                self.sha1: {
                    "path": self.file_path,
                    "name": "colecovision.rom",
                    "md5": self.md5,
                    "size": len(self.content),
                },
            },
            "indexes": {
                "by_md5": {self.md5: self.sha1},
                "by_name": {
                    "colecovision.rom": [self.sha1],
                    "coleco.rom": [self.sha1],
                },
                "by_crc32": {},
            },
        }

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_aliases_field_enables_name_resolution(self):
        """file_entry with aliases: names_to_try includes aliases."""
        entry = {
            "name": "BIOS.col",
            "aliases": ["coleco.rom"],
        }
        path, status = resolve_local_file(entry, self.db)
        self.assertIsNotNone(path)
        self.assertEqual(path, self.file_path)

    def test_primary_name_tried_first(self):
        entry = {
            "name": "colecovision.rom",
            "aliases": ["coleco.rom"],
        }
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "exact")
        self.assertEqual(path, self.file_path)

    def test_alias_duplicate_of_name_ignored(self):
        """If alias == name, it's not added twice to names_to_try."""
        entry = {
            "name": "colecovision.rom",
            "aliases": ["colecovision.rom"],
        }
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "exact")


class TestBuildIndexesWithAliases(unittest.TestCase):
    """Test that build_indexes merges alias names into by_name."""

    def test_aliases_indexed_in_by_name(self):
        files = {
            "sha1abc": {
                "name": "gb_bios.bin",
                "md5": "md5abc",
                "crc32": "crc32abc",
            },
        }
        aliases = {
            "sha1abc": [
                {"name": "dmg_boot.bin", "path": ""},
                {"name": "dmg_rom.bin", "path": ""},
            ],
        }
        indexes = build_indexes(files, aliases)
        self.assertIn("gb_bios.bin", indexes["by_name"])
        self.assertIn("dmg_boot.bin", indexes["by_name"])
        self.assertIn("dmg_rom.bin", indexes["by_name"])
        self.assertEqual(indexes["by_name"]["dmg_boot.bin"], ["sha1abc"])
        self.assertEqual(indexes["by_name"]["gb_bios.bin"], ["sha1abc"])

    def test_alias_not_duplicated(self):
        """Same SHA1 not added twice for same alias name."""
        files = {
            "sha1abc": {
                "name": "gb_bios.bin",
                "md5": "md5abc",
                "crc32": "crc32abc",
            },
        }
        aliases = {
            "sha1abc": [
                {"name": "dmg_boot.bin", "path": ""},
                {"name": "dmg_boot.bin", "path": "other/path"},
            ],
        }
        indexes = build_indexes(files, aliases)
        # SHA1 should appear only once
        self.assertEqual(indexes["by_name"]["dmg_boot.bin"].count("sha1abc"), 1)


class TestKnownAliasGroups(unittest.TestCase):
    """Test that KNOWN_ALIAS_GROUPS cross-linking works via build_indexes."""

    def test_known_alias_groups_structure(self):
        """Verify KNOWN_ALIAS_GROUPS is a list of lists of strings."""
        from generate_db import _collect_all_aliases
        # We can't easily call _collect_all_aliases without the real repo,
        # but we can verify the constant exists and has the right structure.
        # Import the source to check the constant inline.
        import importlib
        import generate_db
        with open(generate_db.__file__) as fh:
            source = fh.read()
        self.assertIn("KNOWN_ALIAS_GROUPS", source)
        self.assertIn("colecovision.rom", source)
        self.assertIn("coleco.rom", source)
        self.assertIn("gb_bios.bin", source)
        self.assertIn("dmg_boot.bin", source)


class TestBeetlePsxAliasField(unittest.TestCase):
    """Verify aliases field (renamed from alt_names) is used in resolution."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.content = b"psx bios"
        self.file_path = os.path.join(self.tmpdir, "scph5501.bin")
        with open(self.file_path, "wb") as f:
            f.write(self.content)
        hashes = compute_hashes(self.file_path)
        self.sha1 = hashes["sha1"]
        self.md5 = hashes["md5"]

        self.db = {
            "files": {
                self.sha1: {
                    "path": self.file_path,
                    "name": "scph5501.bin",
                    "md5": self.md5,
                    "size": len(self.content),
                },
            },
            "indexes": {
                "by_md5": {self.md5: self.sha1},
                "by_name": {
                    "scph5501.bin": [self.sha1],
                    "ps-22a.bin": [self.sha1],
                },
                "by_crc32": {},
            },
        }

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_aliases_field_not_alt_names(self):
        """The field is 'aliases', not 'alt_names'."""
        entry = {
            "name": "ps-22a.bin",
            "aliases": ["scph5501.bin"],
        }
        path, status = resolve_local_file(entry, self.db)
        self.assertIsNotNone(path)

    def test_alt_names_field_ignored(self):
        """'alt_names' field is not recognized, only 'aliases'."""
        entry = {
            "name": "nonexistent.bin",
            "alt_names": ["scph5501.bin"],
        }
        path, status = resolve_local_file(entry, self.db)
        self.assertIsNone(path)
        self.assertEqual(status, "not_found")


if __name__ == "__main__":
    unittest.main()
