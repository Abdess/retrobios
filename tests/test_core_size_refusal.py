"""A core's file the core refuses by its own size check is not packed for it.

An existence platform never opens the bytes, so a copy whose hash disagrees
still ships there. The core does open them: Basilisk II stops on any ROM
outside 64 KB to 1 MB (main_unix.cpp:692) and its profile asks for 512 KB
or more, yet the RetroPie pack carried the Apple IIGS' 128 KB ROM as its
ROM, the only copy of that name. The builder, the manifest and verify now
read one rule (validation.core_size_refusal).
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import os
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
from validation import core_size_refusal  # noqa: E402
from verify import find_undeclared_files, verify_platform  # noqa: E402

SIZED = """\
emulator: Sized
type: libretro
systems: [mac]
cores: [sized]
files:
  - name: ROM
    path: ROM
    required: true
    min_size: 16
    max_size: 32
    validation: [size]
"""

# A core that reads a ROM of its own under another path, with no size check:
# its copy makes the name "covered", which sends the sized core's entry
# through the builder's second pass as well.
UNSIZED = """\
emulator: Unsized
type: libretro
systems: [iigs]
cores: [unsized]
files:
  - name: ROM
    path: iigs/ROM
    required: true
"""


class _Collection(unittest.TestCase):
    payload = b""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)
        for d in ("emulators", "platforms", "bios/Apple"):
            Path(d).mkdir(parents=True)
        Path("bios/Apple/ROM").write_bytes(self.payload)
        sha1 = hashlib.sha1(self.payload).hexdigest()
        files = {sha1: {
            "path": "bios/Apple/ROM", "name": "ROM", "size": len(self.payload),
            "sha1": sha1, "md5": hashlib.md5(self.payload).hexdigest(),
            "sha256": hashlib.sha256(self.payload).hexdigest(), "crc32": "00000001",
        }}
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
        self.config = {
            "platform": "Exist", "version": "2.1", "verification_mode": "existence",
            "cores": ["sized", "unsized"],
            "systems": {"mac": {"files": []}, "iigs": {"files": []}},
        }
        Path("platforms/exist.yml").write_text(yaml.dump(self.config))
        Path("platforms/_registry.yml").write_text(
            yaml.dump({"platforms": {"exist": {"config": "exist.yml"}}})
        )
        Path("emulators/sized.yml").write_text(SIZED)
        Path("emulators/unsized.yml").write_text(UNSIZED)
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()
        self.profiles = common.load_emulator_profiles("emulators")

    def tearDown(self):
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def _report(self, profile: str) -> dict:
        undeclared = find_undeclared_files(
            self.config, "emulators", self.db, self.profiles
        )
        return next(u for u in undeclared if u["profile"] == profile)

    def _pack_members(self) -> set[str]:
        zip_path = builder.generate_pack(
            "exist", "platforms", self.db, "bios", "out",
            emulators_dir="emulators", emu_profiles=self.profiles, offline=True,
        )
        with zipfile.ZipFile(zip_path) as zf:
            return set(zf.namelist())

    def _manifest(self) -> dict:
        return builder.generate_manifest(
            "exist", "platforms", self.db, "bios", "platforms/_registry.yml",
            emulators_dir="emulators", emu_profiles=self.profiles, offline=True,
        )



class SizeTheCoreRefuses(_Collection):
    payload = b"8 bytes!"

    def test_the_rule(self):
        entry = yaml.safe_load(SIZED)["files"][0]
        self.assertIn("8 bytes", core_size_refusal(entry, "bios/Apple/ROM") or "")
        self.assertIsNone(core_size_refusal({"name": "ROM", "min_size": 16}, "bios/Apple/ROM"))

    def test_the_report_does_not_count_it_held(self):
        self.assertFalse(self._report("sized")["in_repo"])
        self.assertTrue(self._report("unsized")["in_repo"])

    def test_the_pack_does_not_carry_it(self):
        members = self._pack_members()
        self.assertIn("iigs/ROM", members)
        self.assertNotIn("ROM", members)

    def test_the_manifest_lists_it_as_omitted(self):
        manifest = self._manifest()
        self.assertEqual({f["dest"] for f in manifest["files"]}, {"iigs/ROM"})
        omitted = {o["dest"]: o for o in manifest["omitted_files"]}
        self.assertEqual(omitted["ROM"]["cores"], ["sized"])

    def test_verify_agrees_with_the_pack(self):
        report = verify_platform(self.config, self.db, "emulators", self.profiles)
        in_pack = {
            u["path"] for u in report["undeclared_files"]
            if u["in_repo"] and u.get("in_pack", True)
        }
        self.assertEqual(in_pack, {"iigs/ROM"})

    def test_another_version_the_profile_accepts_fills_the_slot(self):
        # Raze lists every BLOOD.RFF and SW.GRP its table knows under one
        # name: the copy held is one of them, and the first entry's size
        # does not refuse it.
        Path("emulators/sized.yml").write_text(
            SIZED + "  - name: ROM\n    path: ROM\n    size: 8\n    validation: [size]\n"
        )
        common._emulator_profiles_cache.clear()
        self.profiles = common.load_emulator_profiles("emulators")
        self.assertTrue(self._report("sized")["in_repo"])
        self.assertIn("ROM", self._pack_members())
        self.assertIn("ROM", {f["dest"] for f in self._manifest()["files"]})


class SizeTheCoreAccepts(_Collection):
    """The control: a copy of a size the core accepts ships to it."""

    payload = b"sixteen bytes ok"

    def test_the_report_counts_it_held(self):
        self.assertTrue(self._report("sized")["in_repo"])

    def test_the_pack_carries_it(self):
        self.assertTrue({"ROM", "iigs/ROM"} <= self._pack_members())

    def test_the_manifest_lists_it(self):
        manifest = self._manifest()
        self.assertEqual({f["dest"] for f in manifest["files"]}, {"ROM", "iigs/ROM"})

    def test_verify_agrees_with_the_pack(self):
        report = verify_platform(self.config, self.db, "emulators", self.profiles)
        in_pack = {
            u["path"] for u in report["undeclared_files"]
            if u["in_repo"] and u.get("in_pack", True)
        }
        self.assertEqual(in_pack, {"ROM", "iigs/ROM"})

    def test_the_rule_accepts_it(self):
        entry = yaml.safe_load(SIZED)["files"][0]
        self.assertIsNone(core_size_refusal(entry, "bios/Apple/ROM"))


if __name__ == "__main__":
    unittest.main()
