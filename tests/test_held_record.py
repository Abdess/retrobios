"""The gap report, the pack check and the variant search find a held file
by the resolver's rule.

The gap report counted a file held on any crc32 hit, without the declared
size and even when a stronger declared hash contradicted it. The pack check
split md5 lists by hand and took a loose ROM for the member a zipped_file
md5 names. The variant search kept its own kind-to-index table.
"""

from __future__ import annotations

import tests

import tempfile
import unittest
from pathlib import Path

from model.database import declared_records, record_for_hash, records_for_hash
from packs.crossrefsource import entry_source
from packs.packhashes import _repo_satisfies_declaration
from resolve.lookup import held_record_for
from resolve.acceptance import _variant_candidates

SHA_A, SHA_B = "a" * 40, "b" * 40
MD5_A, MD5_B = "1" * 32, "2" * 32


def _db(files: dict, **indexes: dict) -> dict:
    return {"files": files, "indexes": {
        "by_md5": {}, "by_sha256": {}, "by_crc32": {}, "by_name": {}, **indexes,
    }}


def _index(db: dict) -> dict:
    return {
        "by_name": {}, "by_name_lower": {}, "by_path_suffix": {},
        "by_md5": db["indexes"]["by_md5"], "by_sha256": db["indexes"]["by_sha256"],
        "by_crc32": db["indexes"]["by_crc32"], "db_files": db["files"],
        "data_names": set(),
    }


class RecordsForHash(unittest.TestCase):
    def test_a_list_valued_index_entry_names_every_held_record(self):
        db = _db(
            {SHA_A: {"path": "a"}, SHA_B: {"path": "b"}},
            by_crc32={"deadbeef": [SHA_A, "c" * 40, SHA_B]},
        )
        self.assertEqual(records_for_hash(db, "crc32", "DEADBEEF"), [SHA_A, SHA_B])
        self.assertEqual(record_for_hash(db, "crc32", "deadbeef"), SHA_A)

    def test_a_cut_md5_names_the_one_held_md5_it_starts(self):
        db = _db({SHA_A: {"path": "a"}}, by_md5={MD5_A: SHA_A})
        self.assertEqual(records_for_hash(db, "md5", MD5_A[:29]), [SHA_A])
        self.assertEqual(records_for_hash(db, "md5", MD5_B[:29]), [])


class DeclaredRecords(unittest.TestCase):
    """The site's system index, file lookup and gap table name a held file
    by one rule: systems.json missed 494 files declared by crc32 or sha256."""

    def setUp(self):
        self.db = _db(
            {SHA_A: {"path": "a", "size": 4}, SHA_B: {"path": "b", "size": 8}},
            by_md5={MD5_A: SHA_A}, by_sha256={"f" * 64: SHA_B},
            by_crc32={"deadbeef": SHA_A, "cafef00d": SHA_B},
        )

    def test_a_crc32_alone_names_a_record_of_the_declared_size(self):
        found = declared_records(self.db, {"crc32": ["deadbeef"]}, 4)
        self.assertEqual(found, {("crc32", "deadbeef"): [SHA_A]})
        found = declared_records(self.db, {"crc32": ["deadbeef"]}, [8, 16])
        self.assertEqual(found, {("crc32", "deadbeef"): []})

    def test_a_crc32_beside_a_stronger_hash_names_what_that_hash_names(self):
        # An erased flash block shares its crc32 with every other one.
        found = declared_records(self.db, {"sha1": [SHA_B], "crc32": ["deadbeef"]})
        self.assertEqual(found, {("sha1", SHA_B): [SHA_B], ("crc32", "deadbeef"): []})
        found = declared_records(self.db, {"md5": [MD5_A], "crc32": ["deadbeef"]})
        self.assertEqual(found[("crc32", "deadbeef")], [SHA_A])

    def test_sha256_and_a_cut_md5_name_their_record(self):
        found = declared_records(self.db, {"sha256": ["f" * 64], "md5": [MD5_A[:29]]})
        self.assertEqual(found, {("sha256", "f" * 64): [SHA_B], ("md5", MD5_A[:29]): [SHA_A]})

    def test_an_algorithm_without_an_index_names_nothing(self):
        self.assertEqual(declared_records(self.db, {"adler32": ["1234abcd"]}), {})


class GapReportHeldRule(unittest.TestCase):
    def setUp(self):
        self.db = _db(
            {SHA_A: {"path": "bios/x.bin", "md5": MD5_A, "crc32": "deadbeef", "size": 4}},
            by_md5={MD5_A: SHA_A}, by_crc32={"deadbeef": SHA_A},
        )

    def test_a_crc32_hit_outside_the_declared_size_is_not_held(self):
        index = _index(self.db)
        self.assertEqual(entry_source({"name": "y", "crc32": "deadbeef", "size": 4}, index),
                         "bios")
        self.assertIsNone(entry_source({"name": "y", "crc32": "deadbeef", "size": 8}, index))

    def test_a_contradicting_stronger_hash_wins_over_the_crc32(self):
        index = _index(self.db)
        entry = {"name": "y", "sha1": "c" * 40, "crc32": "deadbeef"}
        self.assertIsNone(entry_source(entry, index))
        self.assertIsNone(held_record_for(entry, self.db))


class PackCheckHeldRule(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        loose = Path(tmp.name) / "rom.bin"
        loose.write_bytes(b"rom")
        self.db = _db(
            {SHA_A: {"path": str(loose), "name": "rom.bin", "md5": MD5_A}},
            by_md5={MD5_A: SHA_A},
        )

    def test_an_md5_list_is_read_as_its_values(self):
        entries = [{"name": "rom.bin", "md5": [MD5_B, MD5_A]}]
        self.assertTrue(_repo_satisfies_declaration(entries, self.db, "md5"))

    def test_a_cut_md5_is_never_satisfied(self):
        """Batocera compares whole digests: a held file a cut md5 names
        would still be refused, so the gap is coverage, not divergence."""
        entries = [{"name": "rom.bin", "md5": MD5_A[:29]}]
        self.assertFalse(_repo_satisfies_declaration(entries, self.db, "md5"))

    def test_a_zipped_file_md5_is_no_loose_file(self):
        entries = [{"name": "set.zip", "md5": MD5_A, "zipped_file": "rom.bin"}]
        self.assertFalse(_repo_satisfies_declaration(entries, self.db, "md5"))

    def test_a_contradicting_sha1_refuses_the_md5_match(self):
        entries = [{"name": "rom.bin", "md5": MD5_A, "sha1": SHA_B}]
        self.assertFalse(_repo_satisfies_declaration(entries, self.db, "md5"))


class VariantCandidates(unittest.TestCase):
    def test_every_record_of_a_list_valued_entry_is_a_candidate(self):
        db = _db(
            {SHA_A: {"path": "a"}, SHA_B: {"path": "b"}},
            by_md5={MD5_A: [SHA_A, SHA_B]}, by_name={"rom.bin": [SHA_B]},
        )
        found = list(_variant_candidates({"md5": {MD5_A}, "sha1": {"c" * 40}}, db, "rom.bin"))
        self.assertEqual(found, [SHA_A, SHA_B, SHA_B])


if __name__ == "__main__":
    unittest.main()
