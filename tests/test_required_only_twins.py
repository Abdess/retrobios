"""A required declaration is never silenced by its optional twin.

RetroDECK declares the four Atari 5200 ROMs optional under atari-400-800 and
required under atari-5200, same md5. The preferred declaration for a shared
destination was chosen over the full set, then applied to a loop that had
already dropped the optional entries: under --required-only the preferred
(optional) entry was skipped for being optional and the required one for not
being preferred, and the destination left the pack, the status counts and
the manifest without a trace.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402
import generate_db  # noqa: E402
import generate_pack as builder  # noqa: E402


class RequiredTwins(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bios = self.root / "bios" / "Atari"
        self.platforms = self.root / "platforms"
        self.emulators = self.root / "emulators"
        for directory in (self.bios, self.platforms, self.emulators):
            directory.mkdir(parents=True)
        payload = b"atari os"
        (self.bios / "ATARIOSB.ROM").write_bytes(payload)
        md5 = hashlib.md5(payload).hexdigest()
        sha1 = hashlib.sha1(payload).hexdigest()
        files = {
            sha1: {
                "path": str(self.bios / "ATARIOSB.ROM"), "name": "ATARIOSB.ROM",
                "size": len(payload), "sha1": sha1, "md5": md5,
                "sha256": hashlib.sha256(payload).hexdigest(), "crc32": "00000008",
            }
        }
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
        platform = {
            "platform": "Twins",
            "verification_mode": "md5",
            "base_destination": "bios",
            "cores": [],
            "systems": {
                # Sorted first: the optional declaration is the preferred one.
                "atari-400-800": {"files": [
                    {"name": "ATARIOSB.ROM", "destination": "ATARIOSB.ROM",
                     "md5": md5, "required": False},
                ]},
                "atari-5200": {"files": [
                    {"name": "ATARIOSB.ROM", "destination": "ATARIOSB.ROM",
                     "md5": md5, "required": True},
                ]},
            },
        }
        (self.platforms / "twins.yml").write_text(yaml.dump(platform))
        (self.platforms / "_registry.yml").write_text(
            yaml.dump({"platforms": {"twins": {"status": "active"}}})
        )
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()

    def tearDown(self):
        common._platform_config_cache.clear()
        self._tmp.cleanup()

    def test_the_required_only_pack_carries_the_required_file(self):
        out = self.root / "dist"
        out.mkdir()
        zip_path = builder.generate_pack(
            "twins", str(self.platforms), self.db, str(self.root / "bios"), str(out),
            emulators_dir=str(self.emulators), emu_profiles={},
            required_only=True, offline=True,
        )
        with zipfile.ZipFile(zip_path) as archive:
            self.assertIn("ATARIOSB.ROM", archive.namelist())

    def test_the_required_only_manifest_lists_it(self):
        manifest = builder.generate_manifest(
            "twins", str(self.platforms), self.db, str(self.root / "bios"),
            str(self.platforms / "_registry.yml"),
            emulators_dir=str(self.emulators), emu_profiles={},
            required_only=True, offline=True,
        )
        listed = {entry["dest"] for entry in manifest["files"]}
        self.assertIn("ATARIOSB.ROM", listed)


if __name__ == "__main__":
    unittest.main()
