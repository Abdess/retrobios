"""A name means the dump its declarations prove, not whatever is filed under it.

The collection files the DSi Panda (Japan) (Intense) devkit boot ROMs as
dsi_bios7.bin and dsi_bios9.bin. Their eMMC key-Y at 0x8308 is zeroed, so a
retail NAND cannot be opened with them. Every hash declared under those names
(Batocera's md5, melonDS's crc32) designates a retail dump in the same
directory, yet RetroBat and dsperate, which declare no hash, were served the
devkit ROMs by the name step.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_db  # noqa: E402
from common import resolve_local_file  # noqa: E402

DEVKIT = b"D" * 64
RETAIL = b"R" * 64
OTHER = b"O" * 64


def record(path: str, data: bytes) -> dict:
    return {
        "path": path,
        "name": path.rsplit("/", 1)[-1],
        "size": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "crc32": f"{zlib.crc32(data):08x}",
        "sha256": hashlib.sha256(data).hexdigest(),
    }


class ProvenNameIndex(unittest.TestCase):
    def setUp(self):
        self.files = {
            hashlib.sha1(DEVKIT).hexdigest(): record("bios/N/DSi/dsi_bios7.bin", DEVKIT),
            hashlib.sha1(RETAIL).hexdigest(): record("bios/N/DSi/biosdsi7.bin", RETAIL),
            hashlib.sha1(OTHER).hexdigest(): record("bios/X/Y/other.bin", OTHER),
        }
        self.indexes = generate_db.build_indexes(self.files, {})

    def index(self, declarations: list[dict]) -> dict:
        return generate_db.proven_name_index(self.files, self.indexes, declarations)

    def test_name_points_at_the_proven_dump_beside_it(self):
        declared = [{"name": "dsi_bios7.bin", "md5": hashlib.md5(RETAIL).hexdigest()}]
        self.assertEqual(
            self.index(declared),
            {"dsi_bios7.bin": [hashlib.sha1(RETAIL).hexdigest()]},
        )

    def test_a_proven_holder_keeps_its_name(self):
        declared = [
            {"name": "dsi_bios7.bin", "md5": hashlib.md5(RETAIL).hexdigest()},
            {"name": "dsi_bios7.bin", "crc32": f"{zlib.crc32(DEVKIT):08x}"},
        ]
        self.assertEqual(self.index(declared), {})

    def test_a_dump_filed_elsewhere_proves_nothing(self):
        declared = [{"name": "dsi_bios7.bin", "md5": hashlib.md5(OTHER).hexdigest()}]
        self.assertEqual(self.index(declared), {})

    def test_a_member_hash_proves_nothing(self):
        declared = [{
            "name": "dsi_bios7.bin",
            "md5": hashlib.md5(RETAIL).hexdigest(),
            "zipped_file": "x.bin",
        }]
        self.assertEqual(self.index(declared), {})


class HashlessEntryTakesTheProvenDump(unittest.TestCase):
    def test_resolver_reads_the_index(self):
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        previous = os.getcwd()
        os.chdir(root)
        self.addCleanup(os.chdir, previous)
        Path("bios/N/DSi").mkdir(parents=True)
        Path("bios/N/DSi/dsi_bios7.bin").write_bytes(DEVKIT)
        Path("bios/N/DSi/biosdsi7.bin").write_bytes(RETAIL)
        files = {
            hashlib.sha1(DEVKIT).hexdigest(): record("bios/N/DSi/dsi_bios7.bin", DEVKIT),
            hashlib.sha1(RETAIL).hexdigest(): record("bios/N/DSi/biosdsi7.bin", RETAIL),
        }
        indexes = generate_db.build_indexes(files, {})
        db = {"files": files, "indexes": indexes}
        entry = {"name": "dsi_bios7.bin", "size": 64}
        self.assertEqual(
            resolve_local_file(entry, db)[0], "bios/N/DSi/dsi_bios7.bin"
        )
        indexes["by_proven_name"] = generate_db.proven_name_index(
            files, indexes,
            [{"name": "dsi_bios7.bin", "md5": hashlib.md5(RETAIL).hexdigest()}],
        )
        self.assertEqual(
            resolve_local_file(entry, db), ("bios/N/DSi/biosdsi7.bin", "name_exact")
        )


class TheCollectionServesRetailRoms(unittest.TestCase):
    def test_dsi_boot_roms(self):
        db = json.loads((REPO_ROOT / "database.json").read_text())
        index = db["indexes"].get("by_proven_name", {})
        for name in ("dsi_bios7.bin", "dsi_bios9.bin"):
            held = [db["files"][sha1]["path"] for sha1 in index.get(name, [])]
            self.assertTrue(held, name)
            self.assertFalse(any(path.endswith(f"/{name}") for path in held), held)


if __name__ == "__main__":
    unittest.main()
