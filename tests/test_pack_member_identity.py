"""Every pack member is bytes the collection recognises.

A member whose sha1 and md5 matched nothing was counted `untracked` with
zero errors and the pack passed, so bytes altered while the ZIP was written
went unseen. Archives the builder assembles (MAME clone sets) are
recognised by their members.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import io
import json
import re
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from packverify import verify_pack  # noqa: E402


class MembersMustBeKnown(unittest.TestCase):
    def test_unknown_bytes_are_an_error_and_assembled_sets_pass(self):
        known = b"known rom" * 10
        md5 = hashlib.md5(known).hexdigest()
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("rom.bin", known)
        db = {"files": {}, "indexes": {"by_md5": {md5: "s"}, "by_name": {}}}
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            pack = Path(tmp) / "P_BIOS_Pack.zip"
            with zipfile.ZipFile(pack, "w") as zf:
                zf.writestr("clone.zip", inner.getvalue())
                zf.writestr("garbled.bin", b"no such dump")
            ok, manifest = verify_pack(str(pack), db)
        statuses = {f["path"]: f["status"] for f in manifest["files"]}
        self.assertEqual(statuses["clone.zip"], "verified_members")
        self.assertFalse(ok)
        self.assertTrue(any("garbled.bin" in e for e in manifest["errors"]))


class DataMembersAreCheckedByContent(unittest.TestCase):
    """A data-directory member was verified by name and size: bytes altered
    while the pack was written kept their length and passed."""

    def test_same_size_other_bytes_is_an_error(self):
        good = b"A" * 64
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            cache = Path(tmp) / "cache"
            (cache / "Sys").mkdir(parents=True)
            (cache / "Sys" / "font.bin").write_bytes(good)
            registry = {"demo": {"local_cache": str(cache)}}
            db = {"files": {}, "indexes": {"by_md5": {}, "by_name": {}}}
            pack = Path(tmp) / "P_BIOS_Pack.zip"
            with zipfile.ZipFile(pack, "w") as zf:
                zf.writestr("system/Sys/font.bin", good)
                zf.writestr("system/Sys/other/font.bin", b"B" * 64)
            ok, manifest = verify_pack(str(pack), db, registry)
        statuses = {f["path"]: f["status"] for f in manifest["files"]}
        self.assertEqual(statuses["system/Sys/font.bin"], "verified_data")
        self.assertNotEqual(statuses["system/Sys/other/font.bin"], "verified_data")
        self.assertFalse(ok)


class SchemaAcceptsEveryStatus(unittest.TestCase):
    """verified_members reached every pack manifest and the schema refused it."""

    def test_each_status_packverify_writes_is_in_the_schema(self):
        source = (REPO_ROOT / "scripts" / "packverify.py").read_text(encoding="utf-8")
        written = set(re.findall(r'status = "([a-z_]+)"', source))
        schema = json.loads(
            (REPO_ROOT / "schemas" / "pack-manifest.schema.json").read_text(encoding="utf-8")
        )
        allowed = set(
            schema["properties"]["files"]["items"]["properties"]["status"]["enum"]
        )
        self.assertTrue(written)
        self.assertEqual(sorted(written - allowed), [])


class OneComparisonOfArchiveMembers(unittest.TestCase):
    """verify_pack compared member CRCs twice, each copy with its own local
    import and names (_sc/_pc, _pc2/_dc)."""

    def test_the_helper_answers_both_ways(self):
        import io
        import tempfile
        import zipfile

        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from packverify import _same_members  # noqa: PLC0415

        def archive(members: dict) -> bytes:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as zf:
                for member, data in members.items():
                    zf.writestr(member, data)
            return buffer.getvalue()

        with tempfile.TemporaryDirectory() as directory:
            held = Path(directory) / "held.zip"
            held.write_bytes(archive({"a.rom": b"A", "b.rom": b"B"}))
            pack = io.BytesIO()
            with zipfile.ZipFile(pack, "w") as zf:
                zf.writestr("same.zip", archive({"b.rom": b"B", "a.rom": b"A"}))
                zf.writestr("other.zip", archive({"a.rom": b"X"}))
                zf.writestr("broken.zip", b"not a zip")
            with zipfile.ZipFile(pack) as zf:
                self.assertTrue(_same_members(zf, "same.zip", str(held)))
                self.assertFalse(_same_members(zf, "other.zip", str(held)))
                self.assertFalse(_same_members(zf, "broken.zip", str(held)))
        source = (Path(__file__).resolve().parents[1] / "scripts" / "packverify.py").read_text()
        self.assertNotIn("import io as _io", source)


if __name__ == "__main__":
    unittest.main()
