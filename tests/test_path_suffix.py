"""Which tails of a stored path can answer a declared destination."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from common import resolve_local_file  # noqa: E402
from generate_db import _path_suffixes  # noqa: E402


class TestPathSuffixes(unittest.TestCase):
    """Every tail down to two segments, never the bare filename."""

    def test_longest_first_and_never_the_bare_name(self):
        self.assertEqual(
            _path_suffixes("bios/Nintendo/GameCube/GC/USA/IPL.bin"),
            [
                "Nintendo/GameCube/GC/USA/IPL.bin",
                "GameCube/GC/USA/IPL.bin",
                "GC/USA/IPL.bin",
                "USA/IPL.bin",
            ],
        )

    def test_a_deep_tree_keeps_every_level(self):
        # Seven 3DS system archives differ only past the sixth segment; a
        # single key per file merged all seven onto one.
        suffixes = _path_suffixes(
            "bios/Nintendo/3DS/Citra/nand/0000/title/0004009b/00014002/"
            "content/00000000.app.romfs"
        )
        self.assertIn(
            "nand/0000/title/0004009b/00014002/content/00000000.app.romfs",
            suffixes,
        )
        self.assertEqual(suffixes[0].split("/")[0], "Nintendo")

    def test_a_file_at_the_root_has_no_tail(self):
        self.assertEqual(_path_suffixes("bios/thing.rom"), [])

    def test_a_path_without_the_bios_prefix_is_still_split(self):
        self.assertEqual(
            _path_suffixes("Sony/PlayStation/scph5501.bin"),
            ["Sony/PlayStation/scph5501.bin", "PlayStation/scph5501.bin"],
        )

    def test_backslashes_and_empty_segments_are_normalised(self):
        self.assertEqual(
            _path_suffixes("bios\\\\Sega\\\\Saturn\\\\sat.bin"),
            ["Sega/Saturn/sat.bin", "Saturn/sat.bin"],
        )


class TestResolutionAmbiguity(unittest.TestCase):
    """A tail that could name several files names none of them."""

    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp(prefix="suffix-"))
        cls.previous = os.getcwd()
        cls.paths = {
            "a" * 40: "bios/Other/emu_one/resources/shaders/convert.glsl",
            "b" * 40: "bios/Other/emu_two/pcsx2/resources/shaders/convert.glsl",
            "c" * 40: "bios/Other/emu_three/assets/sounds/unlock.wav",
            "d" * 40: "bios/Vendor/Console/GC/JAP/IPL.bin",
        }
        for sha1, rel in cls.paths.items():
            target = cls.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(sha1[:4].encode())
        files, by_name, by_suffix = {}, {}, {}
        for sha1, rel in cls.paths.items():
            name = rel.rsplit("/", 1)[-1]
            files[sha1] = {"path": rel, "name": name, "md5": "", "size": 4,
                           "crc32": "", "sha1": sha1}
            by_name.setdefault(name, []).append(sha1)
            for suffix in _path_suffixes(rel):
                if suffix != name:
                    by_suffix.setdefault(suffix, []).append(sha1)
        cls.db = {
            "files": files,
            "indexes": {"by_md5": {}, "by_name": by_name, "by_crc32": {},
                        "by_path_suffix": by_suffix},
        }
        os.chdir(cls.root)

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.previous)
        shutil.rmtree(cls.root, ignore_errors=True)

    def _resolve(self, name: str, hint: str):
        return resolve_local_file({"name": name}, self.db, dest_hint=hint)

    def test_a_full_tail_claimed_twice_goes_to_the_closest_owner(self):
        # emu_one stores it right at its destination; emu_two nests it one
        # directory deeper. The one that IS the destination wins.
        path, status = self._resolve(
            "convert.glsl", "resources/shaders/convert.glsl"
        )
        self.assertEqual(status, "path_exact")
        self.assertIn("emu_one", path)

    def test_a_tail_two_segments_short_is_not_followed(self):
        # "sounds/achievements/unlock.wav" would reach emu_three, which is a
        # different emulator's tree, so the name step answers instead.
        path, status = self._resolve(
            "unlock.wav", "pcsx2/resources/sounds/unlock.wav"
        )
        self.assertEqual(status, "name_exact")
        self.assertIn("emu_three", path)

    def test_one_segment_of_descent_is_allowed(self):
        path, status = self._resolve("IPL.bin", "system/GC/JAP/IPL.bin")
        self.assertEqual(status, "path_exact")
        self.assertIn("JAP", path)

    def test_an_exact_tail_still_wins(self):
        path, status = self._resolve("IPL.bin", "GC/JAP/IPL.bin")
        self.assertEqual(status, "path_exact")
        self.assertIn("JAP", path)


class TestSizeGateOnTheNameStep(unittest.TestCase):
    """A name answer must still be a plausible size for the entry."""

    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp(prefix="sizegate-"))
        cls.previous = os.getcwd()
        small = cls.root / "bios/Apple/IIGS/ROM"
        large = cls.root / "bios/Apple/Macintosh/ROM"
        for path, payload in ((small, b"x" * 8), (large, b"y" * 64)):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        cls.db = {
            "files": {
                "a" * 40: {"path": "bios/Apple/IIGS/ROM", "name": "ROM",
                           "md5": "", "size": 8, "crc32": "", "sha1": "a" * 40},
                "b" * 40: {"path": "bios/Apple/Macintosh/ROM", "name": "ROM",
                           "md5": "", "size": 64, "crc32": "", "sha1": "b" * 40},
            },
            "indexes": {
                "by_md5": {}, "by_crc32": {}, "by_path_suffix": {},
                "by_name": {"ROM": ["a" * 40, "b" * 40]},
            },
        }
        os.chdir(cls.root)

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.previous)
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_a_candidate_outside_the_declared_range_is_refused(self):
        entry = {"name": "ROM", "min_size": 32, "max_size": 128,
                 "validation": ["size"]}
        path, _ = resolve_local_file(entry, self.db)
        self.assertIn("Macintosh", path)

    def test_a_present_file_of_the_wrong_size_is_still_returned(self):
        # Reported as present and untested, never as absent: the user has a
        # file under that name and needs to be told it is the wrong one.
        entry = {"name": "ROM", "size": 999, "validation": ["size"]}
        path, status = resolve_local_file(entry, self.db)
        self.assertIsNotNone(path)
        self.assertEqual(status, "hash_mismatch")

    def test_a_size_without_validation_rejects_nothing(self):
        # Documented behaviour: a size is informative until the emulator
        # itself checks it.
        entry = {"name": "ROM", "size": 999}
        path, _ = resolve_local_file(entry, self.db)
        self.assertIsNotNone(path)


if __name__ == "__main__":
    unittest.main()
