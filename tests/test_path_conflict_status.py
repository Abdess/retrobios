"""A declaration that conflicts with a packed path is counted by what it resolves to.

RetroArch declares SGB1.sfc as a file and SGB1.sfc/<rom> as files inside it.
The builder ships one shape and counted every conflicting declaration OK,
resolved or not; verify.py resolves each on its own. A required file absent
from the collection read as covered in the pack report and as missing in verify.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import re
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402
import generate_db  # noqa: E402
import generate_pack as builder  # noqa: E402
from verify import verify_platform  # noqa: E402


class ConflictingDeclarations(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        bios = self.root / "bios" / "Nintendo"
        self.platforms = self.root / "platforms"
        self.emulators = self.root / "emulators"
        for directory in (bios, self.platforms, self.emulators):
            directory.mkdir(parents=True)
        payload = b"super game boy"
        (bios / "SGB1.sfc").write_bytes(payload)
        sha1 = hashlib.sha1(payload).hexdigest()
        files = {
            sha1: {
                "path": str(bios / "SGB1.sfc"), "name": "SGB1.sfc",
                "size": len(payload), "sha1": sha1,
                "md5": hashlib.md5(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(), "crc32": "00000001",
            }
        }
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
        platform = {
            "platform": "Conflict",
            "verification_mode": "existence",
            "base_destination": "system",
            "cores": [],
            "systems": {
                "nintendo-sgb": {"files": [
                    {"name": "SGB1.sfc", "destination": "SGB1.sfc", "required": True},
                    {"name": "nothere.rom", "destination": "SGB1.sfc/nothere.rom",
                     "required": True},
                ]},
            },
        }
        (self.platforms / "conflict.yml").write_text(yaml.dump(platform))
        (self.platforms / "_registry.yml").write_text(
            yaml.dump({"platforms": {"conflict": {"status": "active"}}})
        )
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()

    def tearDown(self):
        common._platform_config_cache.clear()
        self._tmp.cleanup()

    def test_the_pack_and_verify_count_alike(self):
        out = self.root / "dist"
        out.mkdir()
        report = io.StringIO()
        with contextlib.redirect_stdout(report):
            builder.generate_pack(
                "conflict", str(self.platforms), self.db, str(self.root / "bios"),
                str(out), emulators_dir=str(self.emulators), emu_profiles={},
                offline=True,
            )
        packed = re.search(r"(\d+)/(\d+) files OK", report.getvalue())
        self.assertIsNotNone(packed, report.getvalue())

        config = common.load_platform_config("conflict", str(self.platforms))
        verified = verify_platform(config, self.db, str(self.emulators))
        counts = verified["status_counts"]
        self.assertEqual(counts.get("missing"), 1)
        self.assertEqual(
            (int(packed.group(1)), int(packed.group(2))),
            (counts.get("ok", 0), verified["total_files"]),
        )


class AnExtraDoesNotPassAHashCheck(unittest.TestCase):
    """A md5 platform declares scph1001.bin with a hash the collection lacks;
    a core declares our dump at the same path. The builder ships the core's
    file and called the declaration OK, while the frontend, which hashes the
    file, rejects it and verify reports it untested."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        bios = self.root / "bios" / "Sony"
        self.platforms = self.root / "platforms"
        self.emulators = self.root / "emulators"
        for directory in (bios, self.platforms, self.emulators):
            directory.mkdir(parents=True)
        payload = b"our psx dump"
        (bios / "psx-us.bin").write_bytes(payload)
        sha1 = hashlib.sha1(payload).hexdigest()
        md5 = hashlib.md5(payload).hexdigest()
        files = {
            sha1: {
                "path": str(bios / "psx-us.bin"), "name": "psx-us.bin",
                "size": len(payload), "sha1": sha1, "md5": md5,
                "sha256": hashlib.sha256(payload).hexdigest(), "crc32": "00000002",
            }
        }
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
        platform = {
            "platform": "Hashed",
            "verification_mode": "md5",
            "cores": ["fxcore"],
            "systems": {"sony-playstation": {"files": [
                {"name": "scph1001.bin", "destination": "scph1001.bin",
                 "md5": "0123456789abcdef0123456789abcdef", "required": True},
            ]}},
        }
        (self.platforms / "hashed.yml").write_text(yaml.dump(platform))
        (self.platforms / "_registry.yml").write_text(
            yaml.dump({"platforms": {"hashed": {"status": "active"}}})
        )
        profile = {
            "emulator": "FX", "type": "libretro", "cores": ["fxcore"],
            "systems": ["sony-playstation"],
            "files": [{"name": "psx-us.bin", "path": "scph1001.bin", "md5": md5,
                       "required": True}],
        }
        (self.emulators / "fxcore.yml").write_text(yaml.dump(profile))
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()

    def tearDown(self):
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()
        self._tmp.cleanup()

    def test_the_declaration_stays_failed(self):
        out = self.root / "dist"
        out.mkdir()
        report = io.StringIO()
        with contextlib.redirect_stdout(report):
            builder.generate_pack(
                "hashed", str(self.platforms), self.db, str(self.root / "bios"),
                str(out), emulators_dir=str(self.emulators), offline=True,
            )
        packed = re.search(r"(\d+)/(\d+) files OK", report.getvalue())
        self.assertIsNotNone(packed, report.getvalue())
        config = common.load_platform_config("hashed", str(self.platforms))
        verified = verify_platform(config, self.db, str(self.emulators))
        self.assertEqual(verified["status_counts"].get("ok", 0), 0)
        self.assertEqual(int(packed.group(1)), 0, report.getvalue())


if __name__ == "__main__":
    unittest.main()
