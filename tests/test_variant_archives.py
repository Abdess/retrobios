"""Every reader of collection archives sees the .variants/ copies.

A copy kept as ``x.zip.1a2b3c4d`` is an archive, and the members it alone
holds are held: the site lookup, the gap report's member index, the inner
ROM index of the resolver and the pack check each tested a ``.zip`` suffix
and skipped them. All of them read members through core.ziptools.
"""

from __future__ import annotations

import tests

import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from core.ziptools import build_zip_contents_index, zip_members
from packs.supplemental import archive_members
from packs.integrity import _same_content
from sitegen.cards import _release_name
from sitegen.lookup import _archive_member_records


def _write_zip(path: Path, members: dict[str, bytes]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


class VariantArchives(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.primary = _write_zip(self.root / "bios" / "set.zip", {"a.rom": b"a" * 16})
        self.variant = _write_zip(
            self.root / "bios" / ".variants" / "set.zip.1a2b3c4d",
            {"a.rom": b"a" * 16, "only.rom": b"v" * 16},
        )

    def test_members_come_from_the_central_directory(self):
        with zipfile.ZipFile(self.variant, "a") as zf:
            zf.writestr("dir/", b"")
        members = zip_members(self.variant)
        self.assertEqual([m.name for m in members], ["a.rom", "only.rom"])
        self.assertEqual(members[1].size, 16)
        self.assertEqual(len(members[1].crc32), 8)
        garbage = self.root / "bad.zip"
        garbage.write_bytes(b"not an archive")
        with self.assertRaises(zipfile.BadZipFile):
            zip_members(garbage)

    def test_the_gap_report_lists_the_members_of_a_copy(self):
        found = dict(archive_members(self.root / "bios"))
        self.assertEqual(found[str(self.variant)], ["a.rom", "only.rom"])

    def test_a_copy_answers_only_for_what_no_primary_holds(self):
        import hashlib

        db = {"files": {
            "p": {"path": str(self.primary)},
            "v": {"path": str(self.variant)},
        }}
        index = build_zip_contents_index(db, self.root, cache_path=None)
        self.assertEqual(index[hashlib.md5(b"a" * 16).hexdigest()], "p")
        self.assertEqual(index[hashlib.md5(b"v" * 16).hexdigest()], "v")

    def test_the_site_lookup_records_the_members_of_a_copy(self):
        entry = {"path": str(self.variant.relative_to(self.root)), "name": "set.zip"}
        records = _archive_member_records(entry, "v", "/files/", root=self.root)
        self.assertEqual(sorted(r["name"] for r in records), ["a.rom", "only.rom"])

    def test_the_pack_check_compares_members_with_a_copy(self):
        packed = io.BytesIO()
        with zipfile.ZipFile(packed, "w") as zf:
            zf.writestr("set.zip", _rebuilt(self.variant))
        with zipfile.ZipFile(packed) as zf:
            self.assertTrue(_same_content(zf, "set.zip", str(self.variant)))


def _rebuilt(source: Path) -> bytes:
    """The same members written again, so the bytes differ."""
    out = io.BytesIO()
    with zipfile.ZipFile(source) as src, \
            zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            dst.writestr(info.filename, src.read(info))
    return out.getvalue()


class MameReleaseNames(unittest.TestCase):
    def test_a_mame_label_reads_as_its_version(self):
        self.assertEqual(_release_name("mame", "MAME mame0220", {}), "0.220")
        self.assertEqual(_release_name("mame", "MAME master", {}), "MAME master")
        self.assertEqual(_release_name("fbneo", "FBNeo x", {"FBNeo x": "1.0.0.03"}),
                         "1.0.0.03")


if __name__ == "__main__":
    unittest.main()
