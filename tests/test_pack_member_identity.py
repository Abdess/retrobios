"""Every pack member is bytes the collection recognises.

A member whose sha1 and md5 matched nothing was counted `untracked` with
zero errors and the pack passed, so bytes altered while the ZIP was written
went unseen. Archives the builder assembles (MAME clone sets) are
recognised by their members.
"""

from __future__ import annotations

import hashlib
import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class MembersMustBeKnown(unittest.TestCase):
    def test_unknown_bytes_are_an_error_and_assembled_sets_pass(self):
        from packverify import verify_pack

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


class SchemaAcceptsEveryStatus(unittest.TestCase):
    """verified_members reached every pack manifest and the schema refused it."""

    def test_each_status_packverify_writes_is_in_the_schema(self):
        import json
        import re

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


if __name__ == "__main__":
    unittest.main()
