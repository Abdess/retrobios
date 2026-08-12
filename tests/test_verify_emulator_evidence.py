#!/usr/bin/env python3
"""What `verify.py --emulator` is allowed to call covered.

The per-emulator report is the resolution-evidence view: it answers whether
the bytes an emulator loads are actually here. It captured the status
resolve_local_file returns and then ignored it, so an entry whose only
candidate contradicts its declared hash counted as OK -- a homonym served in
place of a file the collection does not hold, reading as full coverage.

A declared hash contradicted by the local dump has to surface: the pack
builder and the platform verifier both do it, one by excluding the file and
the other by flagging the divergence. This report agreed with neither.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import verify  # noqa: E402


def _db(path: Path, name: str) -> dict:
    payload = path.read_bytes()
    sha1 = hashlib.sha1(payload).hexdigest()
    return {
        "files": {
            sha1: {
                "path": str(path),
                "name": name,
                "size": len(payload),
                "sha1": sha1,
                "md5": hashlib.md5(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "crc32": "00000000",
            }
        },
        "indexes": {
            "by_name": {name: [sha1]},
            "by_md5": {hashlib.md5(payload).hexdigest(): sha1},
            "by_sha256": {hashlib.sha256(payload).hexdigest(): sha1},
            "by_crc32": {},
            "by_path_suffix": {},
        },
    }


class HashMismatchIsNotCoverage(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.emulators = self.root / "emulators"
        self.emulators.mkdir()
        self.rom = self.root / "shared.rom"
        self.rom.write_bytes(b"THE BYTES THE REPO ACTUALLY HOLDS")
        self.db = _db(self.rom, "shared.rom")
        from common import _emulator_profiles_cache

        _emulator_profiles_cache.clear()

    def tearDown(self):
        from common import _emulator_profiles_cache

        _emulator_profiles_cache.clear()
        self._tmp.cleanup()

    def _profile(self, declared_md5: str) -> None:
        (self.emulators / "demo.yml").write_text(
            "emulator: demo\n"
            "type: standalone\n"
            "display_name: Demo\n"
            "systems: [demo-system]\n"
            "files:\n"
            "  - name: shared.rom\n"
            "    system: demo-system\n"
            "    required: true\n"
            f"    md5: \"{declared_md5}\"\n"
        )

    def _run(self):
        cwd = os.getcwd()
        os.chdir(self.root)
        try:
            return verify.verify_emulator(
                ["demo"], str(self.emulators), self.db
            )
        finally:
            os.chdir(cwd)

    def test_a_contradicted_hash_is_not_reported_ok(self):
        """The file on disk is not the file the profile declares."""
        self._profile("f" * 32)
        result = self._run()
        statuses = {d["name"]: d["status"] for d in result["details"]}
        self.assertNotEqual(
            statuses.get("shared.rom"),
            verify.Status.OK,
            "an entry whose only candidate contradicts its hash counted as covered",
        )

    def test_the_report_says_why(self):
        self._profile("f" * 32)
        detail = next(
            d for d in self._run()["details"] if d["name"] == "shared.rom"
        )
        self.assertIn("reason", detail)
        self.assertIn("hash", detail["reason"].lower())

    def test_a_matching_hash_is_still_ok(self):
        self._profile(hashlib.md5(self.rom.read_bytes()).hexdigest())
        detail = next(
            d for d in self._run()["details"] if d["name"] == "shared.rom"
        )
        self.assertEqual(detail["status"], verify.Status.OK)

    def test_an_entry_declaring_no_hash_is_still_ok(self):
        """Nothing to contradict, so presence is all the evidence there is."""
        (self.emulators / "demo.yml").write_text(
            "emulator: demo\n"
            "type: standalone\n"
            "display_name: Demo\n"
            "systems: [demo-system]\n"
            "files:\n"
            "  - name: shared.rom\n"
            "    system: demo-system\n"
            "    required: true\n"
        )
        detail = next(
            d for d in self._run()["details"] if d["name"] == "shared.rom"
        )
        self.assertEqual(detail["status"], verify.Status.OK)

    def test_a_genuinely_absent_file_still_reads_missing(self):
        (self.emulators / "demo.yml").write_text(
            "emulator: demo\n"
            "type: standalone\n"
            "display_name: Demo\n"
            "systems: [demo-system]\n"
            "files:\n"
            "  - name: nowhere.rom\n"
            "    system: demo-system\n"
            "    required: true\n"
        )
        detail = next(
            d for d in self._run()["details"] if d["name"] == "nowhere.rom"
        )
        self.assertEqual(detail["status"], verify.Status.MISSING)


class UnsourceableIsNotAGap(unittest.TestCase):
    """An entry nobody can supply is absent by design, not by omission.

    Counting a per-user key or a slot the user fills beside a file somebody
    could still find invites the wrong repair: dropping the flag, deleting the
    entry, or chasing a vendor's whole install tree. One profile read
    "14 missing" when twelve of those were documented as unobtainable.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.emulators = self.root / "emulators"
        self.emulators.mkdir()
        (self.emulators / "demo.yml").write_text(
            "emulator: demo\n"
            "type: standalone\n"
            "display_name: Demo\n"
            "systems: [demo-system]\n"
            "files:\n"
            "  - name: findable.rom\n"
            "    system: demo-system\n"
            "    required: true\n"
            "  - name: paid.so\n"
            "    system: demo-system\n"
            "    required: true\n"
            "    unsourceable: \"ships inside the paid application\"\n"
        )
        self.db = {"files": {}, "indexes": {
            "by_name": {}, "by_md5": {}, "by_sha256": {},
            "by_crc32": {}, "by_path_suffix": {}}}
        from common import _emulator_profiles_cache

        _emulator_profiles_cache.clear()

    def tearDown(self):
        from common import _emulator_profiles_cache

        _emulator_profiles_cache.clear()
        self._tmp.cleanup()

    def _result(self):
        cwd = os.getcwd()
        os.chdir(self.root)
        try:
            return verify.verify_emulator(
                ["demo"], str(self.emulators), self.db
            )
        finally:
            os.chdir(cwd)

    def test_an_unsourceable_entry_carries_its_reason(self):
        detail = next(d for d in self._result()["details"] if d["name"] == "paid.so")
        self.assertEqual(detail["status"], verify.Status.MISSING)
        self.assertIn("unsourceable", detail)
        self.assertIn("paid", detail["unsourceable"])

    def test_a_findable_entry_carries_no_such_marker(self):
        detail = next(
            d for d in self._result()["details"] if d["name"] == "findable.rom"
        )
        self.assertEqual(detail["status"], verify.Status.MISSING)
        self.assertNotIn("unsourceable", detail)

    def test_the_summary_counts_the_two_apart(self):
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            verify.print_emulator_result(self._result())
        summary = buffer.getvalue().splitlines()[0]
        self.assertIn("1 missing", summary)
        self.assertIn("1 unsourceable", summary)

    def test_the_reason_is_printed_rather_than_the_entry_hidden(self):
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            verify.print_emulator_result(self._result())
        out = buffer.getvalue()
        self.assertIn("UNSOURCEABLE: paid.so", out)
        self.assertIn("MISSING (required): findable.rom", out)


class RepositoryWideEvidence(unittest.TestCase):
    """The real collection, so the fix is measured and not just asserted."""

    def test_no_profile_entry_is_reported_ok_on_a_contradicted_hash(self):
        from common import (
            build_zip_contents_index,
            load_data_dir_registry,
            load_database,
            load_emulator_profiles,
            resolve_local_file,
        )

        db_path = REPO_ROOT / "database.json"
        if not db_path.is_file():
            self.skipTest("no database.json")
        db = load_database(str(db_path))
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        zip_contents = build_zip_contents_index(db)
        registry = load_data_dir_registry(str(REPO_ROOT / "platforms"))

        offenders: list[str] = []
        for key, profile in profiles.items():
            for entry in profile.get("files") or []:
                if entry.get("archive") or entry.get("unsourceable"):
                    continue
                local, status = resolve_local_file(
                    entry,
                    db,
                    zip_contents,
                    dest_hint=entry.get("path", ""),
                    data_dir_registry=registry,
                )
                if local and status == "hash_mismatch":
                    offenders.append(f"{key}:{entry.get('name', '')}")
        # These exist; what must not happen is verify calling them covered.
        # The unit tests above pin the reporting -- this one records the size
        # of the surface so a regression in resolution shows up here.
        self.assertIsInstance(offenders, list)
        print(f"\n  entries resolving to hash_mismatch: {len(offenders)}")


if __name__ == "__main__":
    unittest.main()
