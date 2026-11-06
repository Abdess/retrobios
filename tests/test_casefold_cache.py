"""The case-insensitive name index answers for the database it was asked about."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import _casefold_name_index  # noqa: E402


class CasefoldIndexFollowsItsSource(unittest.TestCase):
    def test_a_new_dict_gets_its_own_index(self):
        first = {"BIOS.ROM": ["a"]}
        self.assertEqual(_casefold_name_index(first)["bios.rom"], ["a"])
        second = {"Bios.Rom": ["b"]}
        self.assertEqual(_casefold_name_index(second)["bios.rom"], ["b"])

    def test_a_grown_dict_is_reindexed(self):
        index = {"A.BIN": ["a"]}
        _casefold_name_index(index)
        index["B.BIN"] = ["b"]
        self.assertIn("b.bin", _casefold_name_index(index))


class APrimaryUnderAnotherCasing(unittest.TestCase):
    """x1 asked for IPLROM.X1, and only Recalbox's second md5 sat under that
    casing, in .variants/, and it won over iplrom.x1, the dump every
    platform pins, in the same directory."""

    def setUp(self):
        import shutil  # noqa: PLC0415
        import tempfile  # noqa: PLC0415

        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.files: dict = {}
        self.by_name: dict = {}

    def _put(self, relative: str, data: bytes, indexed_as: str | None = None) -> None:
        import hashlib  # noqa: PLC0415

        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        sha1 = hashlib.sha1(data).hexdigest()
        self.files[sha1] = {"path": str(path), "sha1": sha1, "size": len(data)}
        name = indexed_as or path.name.split(".variants/")[-1]
        if "/.variants/" in relative:
            name = name.rsplit(".", 1)[0]
        self.by_name.setdefault(name, []).append(sha1)

    def _resolve(self, name: str) -> str:
        from common import _casefold_index_cache, resolve_local_file  # noqa: PLC0415

        _casefold_index_cache.clear()
        db = {"files": self.files, "indexes": {"by_name": self.by_name, "by_md5": {},
                                               "by_path_suffix": {}, "by_crc32": {}}}
        path, _status = resolve_local_file({"name": name}, db)
        return str(Path(path).relative_to(self.root))

    def test_the_primary_beside_the_variant_wins(self):
        self._put("bios/Sharp/X1/iplrom.x1", b"pinned")
        self._put("bios/Sharp/X1/.variants/IPLROM.X1.c4db9a6e", b"second md5")
        self.assertEqual(self._resolve("IPLROM.X1"), "bios/Sharp/X1/iplrom.x1")

    def test_another_machines_file_does_not(self):
        self._put("bios/NEC/PC-88/font.rom", b"pc-88 font")
        self._put("bios/NEC/PC-98/.variants/FONT.ROM.541271ea", b"pc-98 font")
        self.assertEqual(self._resolve("FONT.ROM"),
                         "bios/NEC/PC-98/.variants/FONT.ROM.541271ea")

    def test_an_alias_naming_another_file_does_not(self):
        # System.dat pins a font's md5 under IPLROM.X1T.
        self._put("bios/Sharp/X1/FNT0808.X1", b"font", indexed_as="iplrom.x1t")
        self._put("bios/Sharp/X1/.variants/IPLROM.X1T.44620f57", b"turbo ipl")
        self.assertEqual(self._resolve("IPLROM.X1T"),
                         "bios/Sharp/X1/.variants/IPLROM.X1T.44620f57")


if __name__ == "__main__":
    unittest.main()
