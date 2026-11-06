"""An archive pinned by the ROM inside it ships only if it holds that ROM.

With no md5 on the entry, the pack never looked inside: trs80.zip without
level1.rom went out as OK where verify said "not found inside ZIP".
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import build_zip_contents_index  # noqa: E402
from generate_pack import generate_pack  # noqa: E402


class ZippedMemberIsChecked(unittest.TestCase):
    def test_an_archive_without_the_member_is_not_shipped(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
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



class TheMemberIndexIsCachedByContent(unittest.TestCase):
    """Each pipeline step that resolves a zipped_file decompressed all 54 845
    archive members again, about 23 s a step."""

    def test_a_second_process_reads_the_cache(self):
        from unittest import mock  # noqa: PLC0415

        import ziptools  # noqa: PLC0415

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
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
