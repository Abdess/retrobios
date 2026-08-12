#!/usr/bin/env python3
"""Judging a candidate that was found by its name.

A file reached through a directory walk was matched on its filename, which is
the weakest evidence the resolver has: kanji.rom names a font inside a paid
Android package, an openMSX font and a 3DO ROM. Whatever the entry declares
about content is checked before such a candidate may be returned, and this
predicate is that check.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402

PAYLOAD = b"THE BYTES THE ENTRY MEANS"
OTHER = b"A DIFFERENT FILE ANSWERING TO THE SAME NAME"


def digests(blob: bytes) -> dict:
    return {
        "sha1": hashlib.sha1(blob).hexdigest(),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "md5": hashlib.md5(blob).hexdigest(),
        "crc32": format(zlib.crc32(blob) & 0xFFFFFFFF, "08x"),
    }


class DeclaredHashVerdict(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.right = root / "right.bin"
        self.right.write_bytes(PAYLOAD)
        self.wrong = root / "wrong.bin"
        self.wrong.write_bytes(OTHER)
        self.d = digests(PAYLOAD)

    def tearDown(self):
        self._tmp.cleanup()

    def verdict(self, path, **declared):
        base = dict(
            has_strong_hash=True, sha1_candidates=set(), sha256_candidates=set(),
            md5_list=[], crc_raw="", zipped_file=None, declared_size=None,
        )
        base.update(declared)
        return common.declared_hash_verdict(str(path), **base)

    def test_no_declared_hash_means_the_name_is_all_there_is(self):
        self.assertEqual(
            self.verdict(self.right, has_strong_hash=False), "data_dir"
        )

    def test_a_matching_sha1_confirms_the_candidate(self):
        self.assertEqual(
            self.verdict(self.right, sha1_candidates={self.d["sha1"]}),
            "data_dir_hash_exact",
        )

    def test_a_contradicted_sha1_rejects_it(self):
        self.assertEqual(
            self.verdict(self.wrong, sha1_candidates={self.d["sha1"]}),
            "hash_mismatch",
        )

    def test_sha256_is_checked(self):
        self.assertEqual(
            self.verdict(self.wrong, sha256_candidates={self.d["sha256"]}),
            "hash_mismatch",
        )

    def test_crc32_is_checked(self):
        self.assertEqual(
            self.verdict(self.wrong, crc_raw=self.d["crc32"]), "hash_mismatch"
        )

    def test_a_truncated_md5_still_decides(self):
        """Batocera publishes 29-character prefixes, which are still evidence."""
        self.assertEqual(
            self.verdict(self.right, md5_list=[self.d["md5"][:29]]),
            "data_dir_hash_exact",
        )
        self.assertEqual(
            self.verdict(self.wrong, md5_list=[self.d["md5"][:29]]),
            "hash_mismatch",
        )

    def test_every_declaration_has_to_hold(self):
        """One satisfied hash does not excuse another that is contradicted."""
        self.assertEqual(
            self.verdict(
                self.right,
                sha1_candidates={self.d["sha1"]},
                crc_raw="deadbeef",
            ),
            "hash_mismatch",
        )

    def test_a_size_beside_a_crc32_is_enforced(self):
        self.assertEqual(
            self.verdict(
                self.right, crc_raw=self.d["crc32"], declared_size=len(PAYLOAD)
            ),
            "data_dir_hash_exact",
        )
        self.assertEqual(
            self.verdict(
                self.right, crc_raw=self.d["crc32"], declared_size=len(PAYLOAD) + 1
            ),
            "hash_mismatch",
        )

    def test_a_list_of_allowed_sizes_is_accepted(self):
        self.assertEqual(
            self.verdict(
                self.right,
                crc_raw=self.d["crc32"],
                declared_size=[1, len(PAYLOAD)],
            ),
            "data_dir_hash_exact",
        )

    def test_a_zipped_member_is_checked_inside_the_archive(self):
        """With zipped_file the md5 describes a ROM, not the container."""
        archive = Path(self._tmp.name) / "set.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("rom.bin", PAYLOAD)
        self.assertEqual(
            self.verdict(
                archive, md5_list=[self.d["md5"]], zipped_file="rom.bin"
            ),
            "data_dir_hash_exact",
        )
        self.assertEqual(
            self.verdict(
                archive, md5_list=[digests(OTHER)["md5"]], zipped_file="rom.bin"
            ),
            "hash_mismatch",
        )


class AgnosticFallback(unittest.TestCase):
    """Cores that accept any filename identify a file by its shape alone."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.match = self.root / "anything.bin"
        self.match.write_bytes(b"x" * 64)
        self.files_db = {
            "a": {"path": str(self.match), "size": 64},
            "b": {"path": str(self.root / "absent.bin"), "size": 64},
        }

    def tearDown(self):
        self._tmp.cleanup()

    def test_a_file_of_the_declared_size_under_the_prefix_answers(self):
        entry = {
            "agnostic": True,
            "agnostic_path_prefix": str(self.root),
            "size": 64,
        }
        self.assertEqual(
            common._resolve_agnostic(entry, self.files_db, False),
            (str(self.match), "agnostic_fallback"),
        )

    def test_a_declared_hash_outranks_the_shape(self):
        entry = {"agnostic": True, "agnostic_path_prefix": str(self.root), "size": 64}
        self.assertIsNone(common._resolve_agnostic(entry, self.files_db, True))

    def test_the_wrong_size_is_not_a_candidate(self):
        entry = {
            "agnostic": True,
            "agnostic_path_prefix": str(self.root),
            "size": 65,
        }
        self.assertIsNone(common._resolve_agnostic(entry, self.files_db, False))

    def test_a_size_range_is_honoured(self):
        entry = {
            "agnostic": True,
            "agnostic_path_prefix": str(self.root),
            "min_size": 32,
            "max_size": 128,
        }
        self.assertIsNotNone(common._resolve_agnostic(entry, self.files_db, False))

    def test_without_a_prefix_nothing_is_scanned(self):
        entry = {"agnostic": True, "size": 64}
        self.assertIsNone(common._resolve_agnostic(entry, self.files_db, False))

    def test_an_entry_that_is_not_agnostic_is_left_alone(self):
        entry = {"agnostic_path_prefix": str(self.root), "size": 64}
        self.assertIsNone(common._resolve_agnostic(entry, self.files_db, False))


if __name__ == "__main__":
    unittest.main()
