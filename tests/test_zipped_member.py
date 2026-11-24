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
                emulators_dir=str(root / "emulators"), zip_contents=build_zip_contents_index(db, root),
                emu_profiles={}, offline=True,
            )
            names = zipfile.ZipFile(pack).namelist() if pack else []
            self.assertNotIn("trs80.zip", names)


class VariantArchivesAreIndexed(unittest.TestCase):
    """A .variants/ copy is named neogeo.zip.<md5 prefix>: the contents
    index skipped every one, so a ROM only such a copy holds answered no
    zipped_file pin. A member a primary holds still answers with it."""

    def test_variant_members_count_and_the_primary_wins(self):
        from core import ziptools

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary = root / "bios" / "set.zip"
            variant = root / "bios" / ".variants" / "set.zip.1a2b3c4d"
            variant.parent.mkdir(parents=True)
            with zipfile.ZipFile(primary, "w") as zf:
                zf.writestr("shared.rom", b"shared")
            with zipfile.ZipFile(variant, "w") as zf:
                zf.writestr("shared.rom", b"shared")
                zf.writestr("own.rom", b"own")
            files = {}
            # The variant first, as a database may list it.
            for path in (variant, primary):
                data = path.read_bytes()
                files[hashlib.sha1(data).hexdigest()] = {"path": str(path), "name": path.name}
            sha1_of = {entry["path"]: sha1 for sha1, entry in files.items()}
            ziptools._zip_contents_cache = None
            index = build_zip_contents_index({"files": files}, root, cache_path=None)
            self.assertEqual(index[hashlib.md5(b"own").hexdigest()], sha1_of[str(variant)])
            self.assertEqual(index[hashlib.md5(b"shared").hexdigest()], sha1_of[str(primary)])



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

    def test_an_unreadable_nested_archive_is_the_reason(self):
        """A composite entry over a member that is no ZIP reported a container
        md5 mismatch, a comparison Recalbox never makes, and printed the real
        cause to stderr where no caller of the errors list saw it."""
        import contextlib
        import io

        from packs.integrity import _check_member_hash

        pack = io.BytesIO()
        with zipfile.ZipFile(pack, "w") as zf:
            zf.writestr("bios/dragon32.zip", b"not a zip")
        entry = {"name": "dragon32.zip", "md5": "0" * 32, "zip_digest": "composite"}
        stderr = io.StringIO()
        with zipfile.ZipFile(pack) as zf, contextlib.redirect_stderr(stderr):
            error = _check_member_hash(zf, "bios/dragon32.zip", entry, "md5")
        self.assertIsNotNone(error)
        self.assertIn("bios/dragon32.zip: unreadable nested archive (", error)
        self.assertEqual(stderr.getvalue(), "")


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
            first = ziptools.build_zip_contents_index(db, Path(tmp), cache_path=cache)
            ziptools._zip_contents_cache = None
            with mock.patch.object(ziptools, "_members_md5",
                                   side_effect=AssertionError("archive reopened")):
                second = ziptools.build_zip_contents_index(db, Path(tmp), cache_path=cache)
                ziptools._zip_contents_cache = None
                bounded = ziptools.build_zip_contents_index(db, Path(tmp), max_entry_size=32,
                                                            cache_path=cache)
            ziptools._zip_contents_cache = None
        self.assertEqual(first, second)
        self.assertEqual(set(first), {hashlib.md5(b"a" * 16).hexdigest(),
                                      hashlib.md5(b"b" * 64).hexdigest()})
        self.assertEqual(set(bounded), {hashlib.md5(b"a" * 16).hexdigest()})


class TheMemberIndexReadsUnderTheCollection(unittest.TestCase):
    """The index tested each database path against the working directory: a
    site built from another collection's database read this checkout's
    archives, and a run started elsewhere found none."""

    def test_paths_are_read_under_the_root_whatever_the_working_directory(self):
        import os

        from core import ziptools

        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as elsewhere:
            root = Path(tmp)
            archive = root / "bios" / "set.zip"
            archive.parent.mkdir()
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("own.rom", b"own")
            db = {"files": {"s" * 40: {"path": "bios/set.zip", "name": "set.zip"}}}
            previous = os.getcwd()
            os.chdir(elsewhere)
            self.addCleanup(os.chdir, previous)
            ziptools._zip_contents_cache = None
            self.addCleanup(setattr, ziptools, "_zip_contents_cache", None)
            found = build_zip_contents_index(db, root, cache_path=None)
            self.assertEqual(found, {hashlib.md5(b"own").hexdigest(): "s" * 40})
            # Another root is another answer, never the cached one.
            self.assertEqual(build_zip_contents_index(db, Path(elsewhere), cache_path=None), {})


if __name__ == "__main__":
    unittest.main()
