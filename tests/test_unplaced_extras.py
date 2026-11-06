"""A core file the platform cannot place is not in the pack.

RomM files every BIOS under the slug of its system and knows no slug for
DOS or for the arcade sets MAME 2003 reads. The builder skipped those
entries without a word: the report counted them "in pack" and the manifest
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
            "version": "2.1",
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
            yaml.dump({"platforms": {"slugs": {"config": "slugs.yml"}}})
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
            self.config, self.db, "emulators", self.profiles
        )
        entry = next(u for u in report["undeclared_files"] if u["name"] == "MT32_CONTROL.ROM")
        self.assertTrue(entry["in_repo"])
        self.assertFalse(entry.get("in_pack", True))

    def test_the_readme_fraction_does_not_count_it(self):
        # The README's second column is what the pack has: a held file the
        # platform has no folder for was counted there.
        import generate_readme

        coverage = generate_readme.compute_coverage(
            "slugs", "platforms", self.db, emulators_dir="emulators"
        )
        self.assertEqual(coverage["core_present"], 0)
        self.assertEqual(coverage["core_missing"], 1)

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
            config = {"platform": "P", "version": "2.1", "verification_mode": "existence", "cores": ["one", "two"],
                      "systems": {"sys": {"files": []}}}
            _groups, extra_dests = platform_region_groups(
                config, config["systems"], "emulators", db, "", profiles
            )
            claimants = {key[0] for key, dest in extra_dests.items() if dest == "jp.bin"}
            self.assertEqual(claimants, {"one", "two"}, extra_dests)


class FlatFirmwareFolder(unittest.TestCase):
    """RomM lists a platform's firmware folder without descending, and
    EmulatorJS writes each file under its bare name. 543 files of the RomM
    pack sat below the folder, where no core could ever read them."""

    PROFILE = (
        "emulator: Psx\ntype: libretro\nsystems: [psx]\ncores: [psx]\nfiles:\n"
        "  - name: flat.bin\n    required: false\n"
        "  - name: deep.bin\n    path: core/bios/deep.bin\n    required: false\n"
    )

    def _manifest(self, flat: bool, report: bool = False) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                for d in ("emulators", "platforms", "bios/Sony"):
                    Path(d).mkdir(parents=True)
                files = {}
                for name in ("flat.bin", "deep.bin", "scph5501.bin"):
                    payload = name.encode()
                    Path(f"bios/Sony/{name}").write_bytes(payload)
                    sha1 = hashlib.sha1(payload).hexdigest()
                    files[sha1] = {
                        "path": f"bios/Sony/{name}", "name": name, "size": len(payload),
                        "sha1": sha1, "md5": hashlib.md5(payload).hexdigest(),
                        "sha256": hashlib.sha256(payload).hexdigest(), "crc32": "00000001",
                    }
                db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
                config = {
                    "platform": "Flat", "version": "2.1", "verification_mode": "md5",
                    "base_destination": "bios", "cores": ["psx"],
                    "systems": {
                        "psx": {"files": [{"name": "scph5501.bin",
                                           "destination": "psx/scph5501.bin",
                                           "md5": hashlib.md5(b"scph5501.bin").hexdigest()}]},
                        "snes": {"files": [{"name": "s.bin", "destination": "snes/s.bin",
                                            "md5": "1" * 32}]},
                    },
                }
                Path("platforms/flat.yml").write_text(yaml.dump(config))
                entry = {"config": "flat.yml"}
                if flat:
                    entry["firmware_folder_flat"] = True
                Path("platforms/_registry.yml").write_text(
                    yaml.dump({"platforms": {"flat": entry}})
                )
                Path("emulators/psx.yml").write_text(self.PROFILE)
                common._platform_config_cache.clear()
                common._emulator_profiles_cache.clear()
                profiles = common.load_emulator_profiles("emulators")
                if report:
                    return verify_platform(
                        common.load_platform_config("flat", "platforms"), db,
                        "emulators", profiles,
                    )
                return builder.generate_manifest(
                    "flat", "platforms", db, "bios", "platforms/_registry.yml",
                    emulators_dir="emulators", emu_profiles=profiles, offline=True,
                )
            finally:
                common._platform_config_cache.clear()
                common._emulator_profiles_cache.clear()
                os.chdir(previous)

    def test_a_nested_file_is_omitted_with_its_reason(self):
        manifest = self._manifest(flat=True)
        dests = {entry["dest"] for entry in manifest["files"]}
        self.assertIn("psx/flat.bin", dests)
        self.assertFalse(any("deep.bin" in d for d in dests), dests)
        reasons = {o["name"]: o["reason"] for o in manifest["omitted_files"]}
        self.assertEqual(reasons.get("deep.bin"), "below_platform_folder")

    def test_the_report_agrees_with_the_builder(self):
        report = self._manifest(flat=True, report=True)
        entries = {u["name"]: u for u in report["undeclared_files"]}
        self.assertFalse(entries["deep.bin"].get("in_pack", True))
        self.assertEqual(entries["deep.bin"]["omitted"], "below the folder the platform lists")
        self.assertTrue(entries["flat.bin"].get("in_pack", True))

    def test_a_folder_read_recursively_keeps_it(self):
        dests = {entry["dest"] for entry in self._manifest(flat=False)["files"]}
        self.assertIn("psx/core/bios/deep.bin", dests)

    def test_the_romm_pack_holds_nothing_below_a_folder(self):
        manifest = REPO_ROOT / "install" / "romm.json"
        if not manifest.exists():
            self.skipTest("install/romm.json not generated")
        import json

        files = json.loads(manifest.read_text(encoding="utf-8"))["files"]
        self.assertEqual([f["dest"] for f in files if f["dest"].count("/") > 1], [])


class UserProvidedIsNeverTakenFromTheCollection(unittest.TestCase):
    """The builder writes instructions for a user_provided entry and never
    looks it up. verify resolved it by name, so a same-named file in bios/
    made it report 1/1 OK for a pack that holds no such file."""

    def test_verify_matches_the_builder(self):
        from verify import Status, verify_emulator

        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            self.addCleanup(os.chdir, previous)
            for d in ("emulators", "bios/Sony"):
                Path(d).mkdir(parents=True)
            Path("bios/Sony/scph5501.bin").write_bytes(b"psx")
            sha1 = hashlib.sha1(b"psx").hexdigest()
            files = {sha1: {"path": "bios/Sony/scph5501.bin", "name": "scph5501.bin",
                            "size": 3, "sha1": sha1, "md5": hashlib.md5(b"psx").hexdigest(),
                            "sha256": hashlib.sha256(b"psx").hexdigest(), "crc32": "00000001"}}
            db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
            Path("emulators/fake.yml").write_text(
                "emulator: Fake\ntype: libretro\nsystems: [psx]\ncores: [fake]\n"
                "files:\n  - name: scph5501.bin\n    storage: user_provided\n"
            )
            common._emulator_profiles_cache.clear()
            self.addCleanup(common._emulator_profiles_cache.clear)
            result = verify_emulator(["fake"], "emulators", db)
        statuses = [d["status"] for d in result["details"] if d["name"] == "scph5501.bin"]
        self.assertEqual(statuses, [Status.MISSING])
        self.assertNotIn(Status.OK, result["status_counts"])


class OnePathCountsOnce(unittest.TestCase):
    """rom.key is claimed by three Amiga cores and the pack holds one file
    there: the report said 1130 core files in the RetroArch pack, 48 more
    than it carries."""

    def test_two_claims_on_one_path_count_one_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            self.addCleanup(os.chdir, previous)
            for d in ("emulators", "bios/Commodore"):
                Path(d).mkdir(parents=True)
            Path("bios/Commodore/rom.key").write_bytes(b"key")
            sha1 = hashlib.sha1(b"key").hexdigest()
            files = {sha1: {"path": "bios/Commodore/rom.key", "name": "rom.key", "size": 3,
                            "sha1": sha1, "md5": hashlib.md5(b"key").hexdigest(),
                            "sha256": hashlib.sha256(b"key").hexdigest(), "crc32": "00000001"}}
            db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
            for core, region in (("one", ""), ("two", "    region: [world]\n")):
                Path(f"emulators/{core}.yml").write_text(
                    f"emulator: {core}\ntype: libretro\nsystems: [amiga]\ncores: [{core}]\n"
                    f"files:\n  - name: rom.key\n    required: false\n{region}"
                )
            common._emulator_profiles_cache.clear()
            self.addCleanup(common._emulator_profiles_cache.clear)
            profiles = common.load_emulator_profiles("emulators")
            config = {"platform": "P", "version": "2.1", "verification_mode": "existence", "cores": ["one", "two"],
                      "systems": {"amiga": {"files": []}}}
            report = verify_platform(config, db, "emulators", profiles)
        claims = [u for u in report["undeclared_files"] if u["name"] == "rom.key"]
        self.assertEqual(len(claims), 2)
        self.assertEqual(report["packed_extras"], {"bios": 1, "game_data": 0})


if __name__ == "__main__":
    unittest.main()
