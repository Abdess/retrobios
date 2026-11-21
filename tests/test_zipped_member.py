"""An archive pinned by the ROM inside it ships only if it holds that ROM.

With no md5 on the entry, the pack never looked inside: trs80.zip without
level1.rom went out as OK where verify said "not found inside ZIP".
"""

from __future__ import annotations

import tests

import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml

from core.ziptools import build_zip_contents_index
from packs.platformpack import generate_pack

REPO_ROOT = Path(__file__).resolve().parent.parent


class ZippedMemberIsChecked(unittest.TestCase):
    def test_an_archive_without_the_member_is_not_shipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "platforms").mkdir()
            archive = root / "bios" / "trs80.zip"
            archive.parent.mkdir()
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("other.rom", b"x")
            data = archive.read_bytes()
            sha1 = hashlib.sha1(data).hexdigest()
            db = {
                "files": {sha1: {"name": "trs80.zip", "path": str(archive), "size": len(data),
                                 "md5": hashlib.md5(data).hexdigest(), "sha1": sha1}},
                "indexes": {"by_name": {"trs80.zip": [sha1]}, "by_md5": {}, "by_crc32": {},
                            "by_path_suffix": {}},
            }
            (root / "platforms" / "_registry.yml").write_text(
                yaml.dump({"platforms": {"plat": {"config": "plat.yml"}}})
            )
            (root / "platforms" / "plat.yml").write_text(yaml.dump({
                "platform": "Plat", "verification_mode": "md5",
                "systems": {"trs80": {"files": [
                    {"name": "trs80.zip", "zipped_file": "level1.rom"},
                ]}},
            }))
            pack = generate_pack(
                "plat", str(root / "platforms"), db, str(root / "bios"), str(root / "dist"),
                emulators_dir=str(root / "emulators"), zip_contents=build_zip_contents_index(db),
                emu_profiles={}, offline=True,
            )
            names = zipfile.ZipFile(pack).namelist() if pack else []
            self.assertNotIn("trs80.zip", names)



class PackIntegrityChecksTheMember(unittest.TestCase):
    """Step 6 skipped a zipped_file entry without md5 and matched a cut md5
    by prefix: dragon32.zip without d32.rom passed where Batocera refuses it
    (batocera-systems checkInsideZip with md5 "", whole-string compare)."""

    def _verdict(self, members: dict[str, bytes], entry: dict) -> str | None:
        import io

        from packs.integrity import _check_member_hash

        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            for name, data in members.items():
                zf.writestr(name, data)
        pack = io.BytesIO()
        with zipfile.ZipFile(pack, "w") as zf:
            zf.writestr("bios/dragon32.zip", inner.getvalue())
        with zipfile.ZipFile(pack) as zf:
            return _check_member_hash(zf, "bios/dragon32.zip", entry, "md5")

    def test_member_needed_without_md5(self):
        entry = {"name": "dragon32.zip", "zipped_file": "d32.rom"}
        self.assertIn("not found inside ZIP", self._verdict({"other.rom": b"x"}, entry))
        self.assertIsNone(self._verdict({"D32.ROM": b"x"}, entry))

    def test_whole_md5_only(self):
        md5 = hashlib.md5(b"x").hexdigest()
        members = {"d32.rom": b"x"}
        entry = {"name": "dragon32.zip", "zipped_file": "d32.rom"}
        self.assertIsNone(self._verdict(members, {**entry, "md5": f"{'0' * 32},{md5}"}))
        self.assertIsNone(self._verdict(members, {**entry, "md5": ["0" * 32, md5.upper()]}))
        self.assertIsNotNone(self._verdict(members, {**entry, "md5": md5[:29]}))


class TheMemberIndexIsCachedByContent(unittest.TestCase):
    """Each pipeline step that resolves a zipped_file decompressed all 54 845
    archive members again, about 23 s a step."""

    def test_a_second_process_reads_the_cache(self):
        from unittest import mock

        from core import ziptools

        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "set.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("small.rom", b"a" * 16)
                zf.writestr("large.rom", b"b" * 64)
            sha1 = hashlib.sha1(archive.read_bytes()).hexdigest()
            db = {"files": {sha1: {"path": str(archive), "name": "set.zip"}}}
            cache = str(Path(tmp) / "members.json")
            first = ziptools.build_zip_contents_index(db, cache_path=cache)
            ziptools._zip_contents_cache = None
            with mock.patch.object(ziptools, "_members_md5",
                                   side_effect=AssertionError("archive reopened")):
                second = ziptools.build_zip_contents_index(db, cache_path=cache)
                ziptools._zip_contents_cache = None
                bounded = ziptools.build_zip_contents_index(db, max_entry_size=32,
                                                            cache_path=cache)
            ziptools._zip_contents_cache = None
        self.assertEqual(first, second)
        self.assertEqual(set(first), {hashlib.md5(b"a" * 16).hexdigest(),
                                      hashlib.md5(b"b" * 64).hexdigest()})
        self.assertEqual(set(bounded), {hashlib.md5(b"a" * 16).hexdigest()})

if __name__ == "__main__":
    unittest.main()
