"""A core file the platform cannot place is not in the pack.

RomM files every BIOS under the slug of its system and knows no slug for
DOS or for the arcade sets MAME 2003 reads. The builder skipped those
entries without a word; the report counted them "in pack" and the manifest
listed them neither in files nor in omitted_files.
"""

from __future__ import annotations

import hashlib
import os
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
from packextras import platform_region_groups  # noqa: E402
from verify import verify_platform  # noqa: E402

PROFILE = """\
emulator: Dosbox
type: libretro
systems: [dos]
cores: [dosbox]
files:
  - name: MT32_CONTROL.ROM
    required: false
"""


class SlugPlatform(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)
        self.emulators = Path("emulators")
        self.platforms = Path("platforms")
        for d in (self.emulators, self.platforms, Path("bios/Roland"), Path("bios/Sony")):
            d.mkdir(parents=True)
        files = {}
        for rel, payload in (("bios/Roland/MT32_CONTROL.ROM", b"mt32"), ("bios/Sony/scph5501.bin", b"psx")):
            Path(rel).write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            files[sha1] = {
                "path": rel, "name": Path(rel).name, "size": len(payload), "sha1": sha1,
                "md5": hashlib.md5(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(), "crc32": "00000001",
            }
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
        self.config = {
            "platform": "Slugs",
            "verification_mode": "md5",
            "base_destination": "bios",
            "cores": ["dosbox"],
            "systems": {
                "psx": {"files": [{"name": "scph5501.bin", "destination": "psx/scph5501.bin",
                                   "md5": hashlib.md5(b"psx").hexdigest()}]},
                "ps2": {"files": [{"name": "scph.bin", "destination": "ps2/scph.bin",
                                   "md5": "0" * 32}]},
                "snes": {"files": [{"name": "s.bin", "destination": "snes/s.bin", "md5": "1" * 32}]},
            },
        }
        (self.platforms / "slugs.yml").write_text(yaml.dump(self.config))
        (self.platforms / "_registry.yml").write_text(
            yaml.dump({"platforms": {"slugs": {"status": "active"}}})
        )
        (self.emulators / "dosbox.yml").write_text(PROFILE)
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()
        self.profiles = common.load_emulator_profiles("emulators")

    def tearDown(self):
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def test_the_report_does_not_count_it_packed(self):
        report = verify_platform(
            self.config, self.db, "emulators", self.profiles, supplemental_names=set()
        )
        entry = next(u for u in report["undeclared_files"] if u["name"] == "MT32_CONTROL.ROM")
        self.assertTrue(entry["in_repo"])
        self.assertFalse(entry.get("in_pack", True))

    def test_the_manifest_says_why_it_is_absent(self):
        manifest = builder.generate_manifest(
            "slugs", "platforms", self.db, "bios", "platforms/_registry.yml",
            emulators_dir="emulators", emu_profiles=self.profiles, offline=True,
        )
        names = {entry["dest"] for entry in manifest["files"]}
        self.assertFalse(any("MT32_CONTROL" in n for n in names))
        omitted = [o for o in manifest["omitted_files"] if o["name"] == "MT32_CONTROL.ROM"]
        self.assertEqual([o["reason"] for o in omitted], ["no_platform_slug"])


class RegionKeysForEveryClaimant(unittest.TestCase):
    """Two profiles claiming one destination: the second, deduplicated by
    the collector, had no key in the region map, and the report kept it
    after the builder withdrew the destination."""

    def test_both_claimants_are_keyed(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            self.addCleanup(os.chdir, previous)
            Path("emulators").mkdir()
            Path("bios").mkdir()
            Path("bios/jp.bin").write_bytes(b"jp")
            sha1 = hashlib.sha1(b"jp").hexdigest()
            files = {sha1: {"path": "bios/jp.bin", "name": "jp.bin", "size": 2, "sha1": sha1,
                            "md5": hashlib.md5(b"jp").hexdigest(),
                            "sha256": hashlib.sha256(b"jp").hexdigest(), "crc32": "00000001"}}
            db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
            for name, extra in (("one", "    system: sys\n"), ("two", "")):
                Path(f"emulators/{name}.yml").write_text(
                    f"emulator: {name}\ntype: libretro\nsystems: [sys]\ncores: [{name}]\n"
                    f"files:\n  - name: jp.bin\n    region: [japan]\n{extra}"
                )
            common._emulator_profiles_cache.clear()
            profiles = common.load_emulator_profiles("emulators")
            config = {"platform": "P", "verification_mode": "existence", "cores": ["one", "two"],
                      "systems": {"sys": {"files": []}}}
            _groups, extra_dests = platform_region_groups(
                config, config["systems"], "emulators", db, "", profiles
            )
            claimants = {key[0] for key, dest in extra_dests.items() if dest == "jp.bin"}
            self.assertEqual(claimants, {"one", "two"}, extra_dests)


if __name__ == "__main__":
    unittest.main()
