"""A path declared twice, once unpinned and once with a pin the copy misses.

The unpinned declaration ships the file and the pinned one refuses it. The
builder wrote "excluded" over the shipped path, so its summary said "1 unsafe
excluded" for a file inside the archive, while verify counted it untested
and listed no exclusion. Both orders of the two systems are checked: the
refusal read first left "excluded" behind the file the second one ships.
"""

from __future__ import annotations

import tests

import contextlib
import hashlib
import io
import os
import tempfile
import unittest
from pathlib import Path

import yaml

from model.platforms import _platform_config_cache
from collection.indexes import build_indexes
from packs import archive
from packs import platformpack
from packs.verdicts import Status
from packs.coverage import verify_platform

REPO_ROOT = Path(__file__).resolve().parent.parent

PAYLOAD = b"a console firmware"
SHA1 = hashlib.sha1(PAYLOAD).hexdigest()


class TwinDeclarationStatus(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)
        for d in ("emulators", "platforms", "bios/Twin"):
            Path(d).mkdir(parents=True)
        Path("bios/Twin/fw.bin").write_bytes(PAYLOAD)
        files = {SHA1: {
            "path": "bios/Twin/fw.bin", "name": "fw.bin", "size": len(PAYLOAD),
            "sha1": SHA1, "md5": hashlib.md5(PAYLOAD).hexdigest(),
            "sha256": hashlib.sha256(PAYLOAD).hexdigest(), "crc32": "00000001",
        }}
        self.db = {"files": files, "indexes": build_indexes(files, {})}
        Path("platforms/_registry.yml").write_text(
            yaml.dump({"platforms": {"twin": {"config": "twin.yml"}}})
        )
        self.addCleanup(_platform_config_cache.clear)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def _config(self, unpinned: str, pinned: str) -> dict:
        config = {
            "platform": "Twin", "verification_mode": "md5",
            "systems": {
                unpinned: {"files": [{"name": "fw.bin", "destination": "fw.bin"}]},
                pinned: {"files": [{
                    "name": "fw.bin", "destination": "fw.bin", "md5": "0" * 32,
                }]},
            },
        }
        Path("platforms/twin.yml").write_text(yaml.dump(config))
        _platform_config_cache.clear()
        return config

    def _check(self, config: dict) -> None:
        record = archive.PackRecord()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            platformpack.generate_pack(
                "twin", "platforms", self.db, "bios", "out",
                emulators_dir="emulators", emu_profiles={}, record=record,
                offline=True,
            )
        self.assertIn("fw.bin", record.members)
        summary = out.getvalue()
        self.assertNotIn("excluded", summary.lower())
        self.assertIn("0/1 files OK, 1 untested", summary)
        self.assertIn("UNTESTED: fw.bin", summary)
        report = verify_platform(config, self.db, "emulators", {})
        self.assertEqual(report["status_counts"], {Status.UNTESTED: 1})
        self.assertEqual(report["excluded_files"], [])

    def test_unpinned_declaration_read_first(self):
        self._check(self._config("aaa", "bbb"))

    def test_pinned_declaration_read_first(self):
        self._check(self._config("zzz", "bbb"))



class TheCoresChooseAfterARefusal(TwinDeclarationStatus):
    """A refused declaration left "excluded" on the path, and the builder
    then skipped the cores' choice for the next declaration: the pack held
    the copy the name found while the installer placed the variant the core
    accepts."""

    ACCEPTED = b"the firmware the core checks, sixty-four bytes long........."

    def test_the_pack_ships_the_variant_the_manifest_places(self):
        from packs.manifest import generate_manifest

        accepted_sha1 = hashlib.sha1(self.ACCEPTED).hexdigest()
        Path("bios/Other").mkdir()
        Path("bios/Other/fw.bin").write_bytes(self.ACCEPTED)
        files = dict(self.db["files"])
        files[accepted_sha1] = {
            "path": "bios/Other/fw.bin", "name": "fw.bin", "size": len(self.ACCEPTED),
            "sha1": accepted_sha1, "md5": hashlib.md5(self.ACCEPTED).hexdigest(),
            "sha256": hashlib.sha256(self.ACCEPTED).hexdigest(), "crc32": "00000002",
        }
        self.db = {"files": files, "indexes": build_indexes(files, {})}
        self.assertEqual(self.db["indexes"]["by_name"]["fw.bin"][0], SHA1)
        profile = {
            "emulator": "Core", "type": "libretro", "systems": ["bbb"],
            "files": [{"name": "fw.bin", "size": len(self.ACCEPTED), "validation": ["size"]}],
        }
        Path("emulators/core.yml").write_text(yaml.dump(profile))
        config = self._config("bbb", "aaa")
        config["cores"] = ["core"]
        config["version"] = "1"
        Path("platforms/twin.yml").write_text(yaml.dump(config))
        _platform_config_cache.clear()

        record = archive.PackRecord()
        with contextlib.redirect_stdout(io.StringIO()):
            platformpack.generate_pack(
                "twin", "platforms", self.db, "bios", "out",
                emulators_dir="emulators", emu_profiles={"core": profile},
                record=record, offline=True,
            )
        manifest = generate_manifest(
            "twin", "platforms", self.db, "bios", "platforms/_registry.yml",
            emulators_dir="emulators", emu_profiles={"core": profile}, offline=True,
        )
        served = {entry["dest"]: entry["sha1"] for entry in manifest["files"]}
        self.assertEqual(served.get("fw.bin"), accepted_sha1)
        self.assertEqual(record.sources.get("fw.bin"), "bios/Other/fw.bin")

if __name__ == "__main__":
    unittest.main()
