"""A manifest entry always names somewhere to fetch it from.

The entry was built twice, once for the platform's files and once for the
core extras, and only the first copy turned a file with no repo path and no
release asset into an omission. An extra whose hash matched nothing in the
database (a copy not yet indexed, or a hash computed wrong) was written with
an empty repo_path, and the installer refused the whole manifest.
"""

from __future__ import annotations

import ast
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_pack as gp  # noqa: E402


def _held_file(db: dict) -> tuple[str, dict] | None:
    for sha1, record in db.get("files", {}).items():
        path = REPO_ROOT / record.get("path", "")
        if record.get("size", 0) < 4096 and path.is_file():
            return sha1, record
    return None


class AnEntryWithoutSourceIsAnOmission(unittest.TestCase):
    def setUp(self):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            self.skipTest("database.json is not built")
        self.db = json.loads(db_path.read_text(encoding="utf-8"))
        held = _held_file(self.db)
        if held is None:
            self.skipTest("no small indexed file on disk")
        self.sha1, self.record = held

    def _run_core_entries(self, hashes: dict) -> tuple[list, dict, list]:
        name = Path(self.record["path"]).name
        extra = {
            "name": name,
            "sha1": self.sha1,
            "destination": f"probe/{name}",
            "source_emulator": "probe",
        }
        files: list = []
        omitted: dict = {}
        pack_only: list = []

        def record(full_dest, entry, system, reason, cores):
            omitted[full_dest] = reason

        with mock.patch.object(gp, "compute_hashes", return_value=hashes):
            gp._manifest_core_entries(
                [extra], {}, self.db, str(REPO_ROOT / "bios"), "", str(REPO_ROOT),
                {}, True, set(), False, set(), set(), set(), files, {},
                record, pack_only,
            )
        return files, omitted, pack_only

    def test_a_hash_the_database_lacks_is_omitted(self):
        files, omitted, pack_only = self._run_core_entries(
            {"sha1": "0" * 40, "sha256": "0" * 64}
        )
        self.assertEqual(files, [])
        self.assertEqual(list(omitted.values()), ["not_found"])
        self.assertEqual(pack_only, [self.record["size"]])

    def test_a_held_file_is_an_entry_with_its_repo_path(self):
        files, omitted, _pack_only = self._run_core_entries(
            {"sha1": self.sha1, "sha256": self.record.get("sha256", "")}
        )
        self.assertEqual(omitted, {})
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0]["repo_path"])


class OneBuilderForEveryEntry(unittest.TestCase):
    """Two copies of the entry let one drift: the guard lived in one only."""

    def test_the_download_record_is_built_in_one_place(self):
        tree = ast.parse((REPO_ROOT / "scripts" / "generate_pack.py").read_text())
        builders = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Dict)
            and {"repo_path", "sha256"}
            <= {k.value for k in node.keys if isinstance(k, ast.Constant)}
        ]
        self.assertEqual(len(builders), 1, f"entry dicts at lines {builders}")


if __name__ == "__main__":
    unittest.main()
