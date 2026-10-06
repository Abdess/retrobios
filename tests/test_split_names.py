"""A --split part is named after its group and its platform version.

The intermediate name of each part joined every system id of the group: the
"Other" group of RetroBat (100 systems) gave a 786-byte file name, the write
failed with ENAMETOOLONG and the platform's split was never produced. The
directory holding the parts did not carry the version the parts carry, so a
rescrape that moved the version left both generations under one
SHA256SUMS.txt.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common
from common import build_zip_contents_index, compute_hashes
from generate_pack import generate_split_packs


class SplitPartNames(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.platforms = root / "platforms"
        self.emulators = root / "emulators"
        self.out = root / "dist"
        bios = root / "bios" / "Test"
        for path in (self.platforms, self.emulators, bios):
            path.mkdir(parents=True)
        blob = bios / "shared.bin"
        blob.write_bytes(b"shared")
        h = compute_hashes(str(blob))
        self.db = {
            "files": {
                h["sha1"]: {
                    "name": "shared.bin", "md5": h["md5"], "sha1": h["sha1"],
                    "sha256": h["sha256"], "path": str(blob), "paths": [str(blob)],
                }
            },
            "indexes": {
                "by_md5": {h["md5"]: h["sha1"]},
                "by_name": {"shared.bin": [h["sha1"]]},
                "by_crc32": {},
                "by_path_suffix": {},
            },
        }
        (self.platforms / "_registry.yml").write_text(
            yaml.dump({"platforms": {"longplat": {"status": "active"}}})
        )
        self.sha1 = h["sha1"]

    def tearDown(self):
        self.tmp.cleanup()

    def _platform(self, version: str, systems: int) -> None:
        config = {
            "platform": "LongTest",
            "version": version,
            "verification_mode": "existence",
            "systems": {
                f"unbranded-system-number-{n:03d}": {
                    "files": [{"name": "shared.bin", "sha1": self.sha1}]
                }
                for n in range(systems)
            },
        }
        (self.platforms / "longplat.yml").write_text(yaml.dump(config))
        common._platform_config_cache.clear()

    def _split(self, group_by: str) -> list[str]:
        return generate_split_packs(
            "longplat", str(self.platforms), self.db, self.tmp.name, str(self.out),
            group_by=group_by, emulators_dir=str(self.emulators),
            zip_contents=build_zip_contents_index(self.db), emu_profiles={},
        )

    def test_a_large_group_is_written(self):
        self._platform("1.0", 40)
        parts = self._split("manufacturer")
        self.assertEqual(
            [os.path.basename(p) for p in parts], ["LongTest_1.0_Other_BIOS_Pack.zip"]
        )
        self.assertTrue(os.path.isfile(parts[0]))

    def test_two_versions_do_not_share_a_directory(self):
        self._platform("1.0", 2)
        first = {os.path.dirname(p) for p in self._split("system")}
        self._platform("1.1", 2)
        second = {os.path.dirname(p) for p in self._split("system")}
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)
        self.assertNotEqual(first, second)
        for directory in second:
            self.assertTrue(
                all("_1.1_" in name for name in os.listdir(directory)),
                os.listdir(directory),
            )


if __name__ == "__main__":
    unittest.main()
