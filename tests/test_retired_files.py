"""A file that leaves the collection keeps its published address.

a2diskiing.zip (bd02f6a0) was rebuilt from its recipe on 2026-10-22 and
filed under Apple II as d9bb1897. Its card's address, files/?sha1=bd02f6a0,
answered that no file the site knows has the hash and asked for a
contribution of a file the collection had held.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import retired_files  # noqa: E402

OLD = "bd" * 20
NEW = "d9" * 20


def _db(**files: dict) -> dict:
    return {"files": files}


class WhatLeftIsRecorded(unittest.TestCase):
    def setUp(self):
        self.old = _db(**{
            OLD: {"name": "a2diskiing.zip", "path": "bios/Arcade/Arcade/a2diskiing.zip",
                  "md5": "43" * 16, "crc32": "292ef826", "size": 589},
            "11" * 20: {"name": "kept.bin", "path": "bios/A/B/kept.bin"},
        })
        self.new = _db(**{
            NEW: {"name": "a2diskiing.zip", "path": "bios/Apple/Apple II/a2diskiing.zip"},
            "11" * 20: {"name": "kept.bin", "path": "bios/A/B/kept.bin"},
        })

    def test_the_departure_and_the_file_in_its_place(self):
        left = retired_files.retired_between(self.old, self.new, "2026-10-22")
        self.assertEqual(list(left), [OLD])
        self.assertEqual(left[OLD]["left"], "2026-10-22")
        self.assertEqual(left[OLD]["successor"], NEW)
        self.assertEqual(left[OLD]["md5"], "43" * 16)

    def test_the_first_departure_stays_and_a_return_leaves_the_record(self):
        first = retired_files.merge({}, retired_files.retired_between(self.old, self.new, "2026-10-22"),
                                    self.new)
        again = retired_files.merge(first, {OLD: {"left": "2026-11-01"}}, self.new)
        self.assertEqual(again[OLD]["left"], "2026-10-22")
        self.assertEqual(retired_files.merge(again, {}, self.old), {})

    def test_generate_db_writes_it_beside_the_database(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            database = Path(tmp) / "database.json"
            path = retired_files.retired_path(database)
            self.assertEqual(path, Path(tmp) / "retired.json")
            self.assertEqual(retired_files.update(path, self.old, self.new, "2026-10-22"), 1)
            self.assertEqual(retired_files.update(path, self.old, self.new, "2026-10-23"), 0)
            record = json.loads(path.read_text())["files"]
            self.assertEqual(record[OLD]["left"], "2026-10-22")
        source = (REPO_ROOT / "scripts" / "generate_db.py").read_text(encoding="utf-8")
        self.assertIn("retired_files.update(", source)


class TheLookupAnswersForIt(unittest.TestCase):
    def test_records_lead_to_the_card_in_its_place(self):
        import generate_site  # noqa: PLC0415

        retired = {OLD: {"name": "a2diskiing.zip", "path": "bios/Arcade/Arcade/a2diskiing.zip",
                         "crc32": "292ef826", "left": "2026-10-22", "successor": "ee" * 20},
                   "ee" * 20: {"name": "a2diskiing.zip", "path": "bios/Apple/x/a2diskiing.zip",
                               "left": "2026-10-23", "successor": NEW}}
        files = {NEW: {"name": "a2diskiing.zip"}}
        locations = [{"sha1": NEW, "url": "/retrobios/systems/apple/#sha1-d9d9d9d9d9d9"}]
        records = generate_site.retired_records(retired, files, locations)
        found = {(r["sha1"], r["algorithm"]): r for r in records}
        # Followed to the file held today, through the copy that left after.
        self.assertEqual(found[(OLD, "sha1")]["url"], locations[0]["url"])
        self.assertEqual(found[(OLD, "sha1")]["successor"], NEW)
        self.assertEqual(found[(OLD, "crc32")]["value"], "292ef826")
        self.assertEqual(found[(OLD, "sha1")]["layer"], "retired")
        self.assertEqual(found[(OLD, "sha1")]["left"], "2026-10-22")

    def test_the_committed_record_holds_the_reported_file(self):
        record = retired_files.load(REPO_ROOT / "retired.json")
        if not record:
            self.skipTest("retired.json is not written")
        self.assertIn("bd02f6a0ce8accba7ea5415fd22c2e8f23ec4b10", record)
        database = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
        self.assertFalse(set(record) & set(database["files"]))

    def test_the_page_script_answers_with_it(self):
        script = (REPO_ROOT / "website" / "src" / "scripts" / "site.ts").read_text(encoding="utf-8")
        self.assertIn("item.layer === 'retired'", script)
        self.assertIn("left the collection on", script)


if __name__ == "__main__":
    unittest.main()
