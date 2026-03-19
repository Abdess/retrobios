"""Advanced integration tests covering remaining edge cases.

Covers: md5_composite, storage tiers (external/user_provided/release_asset),
data_directories gap suppression, shared groups, and pipeline flags.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from common import (
    check_inside_zip, load_platform_config, md5_composite, md5sum,
    resolve_local_file, load_emulator_profiles,
)
from verify import (
    Severity, Status, compute_severity, find_undeclared_files,
    verify_platform,
)


def _sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


class TestMd5Composite(unittest.TestCase):
    """Recalbox Zip::Md5Composite — sort filenames, hash all contents."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_composite_matches_manual_calculation(self):
        """md5_composite = md5(sorted_file_a_content + sorted_file_b_content)."""
        zpath = os.path.join(self.tmpdir, "test.zip")
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("b_second.rom", b"BBBB")
            zf.writestr("a_first.rom", b"AAAA")

        # Manual: sort names → a_first.rom, b_second.rom → md5(AAAA + BBBB)
        expected = hashlib.md5(b"AAAA" + b"BBBB").hexdigest()
        actual = md5_composite(zpath)
        self.assertEqual(actual, expected)

    def test_composite_ignores_directories(self):
        """Directory entries in ZIP are excluded from hash."""
        zpath = os.path.join(self.tmpdir, "withdir.zip")
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("subdir/", b"")  # directory entry
            zf.writestr("file.rom", b"DATA")

        expected = hashlib.md5(b"DATA").hexdigest()
        self.assertEqual(md5_composite(zpath), expected)

    def test_composite_independent_of_compression(self):
        """Same content, different compression → same composite hash."""
        z_stored = os.path.join(self.tmpdir, "stored.zip")
        z_deflated = os.path.join(self.tmpdir, "deflated.zip")
        with zipfile.ZipFile(z_stored, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("rom.bin", b"X" * 1000)
        with zipfile.ZipFile(z_deflated, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("rom.bin", b"X" * 1000)

        self.assertEqual(md5_composite(z_stored), md5_composite(z_deflated))

    def test_composite_used_in_resolve(self):
        """resolve_local_file uses md5_composite for ZIP files in step 4."""
        zpath = os.path.join(self.tmpdir, "recalbox.zip")
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("inner.rom", b"RECALBOX")

        composite = md5_composite(zpath)
        with open(zpath, "rb") as f:
            zdata = f.read()
        sha1 = _sha1(zdata)
        container_md5 = _md5(zdata)

        db = {
            "files": {sha1: {"path": zpath, "md5": container_md5, "name": "recalbox.zip"}},
            "indexes": {
                "by_md5": {container_md5: sha1},
                "by_name": {"recalbox.zip": [sha1]},
            },
        }
        # Entry with composite MD5 (what Recalbox would provide)
        entry = {"name": "recalbox.zip", "md5": composite}
        path, status = resolve_local_file(entry, db)
        self.assertEqual(path, zpath)
        self.assertEqual(status, "exact")


class TestStorageTiers(unittest.TestCase):
    """Test storage: external, user_provided, and release_asset."""

    def test_resolve_file_external(self):
        """storage: external → returns (None, 'external')."""
        from generate_pack import resolve_file
        entry = {"name": "PS3UPDAT.PUP", "storage": "external", "sha1": "abc"}
        path, status = resolve_file(entry, {}, "bios")
        self.assertIsNone(path)
        self.assertEqual(status, "external")

    def test_resolve_file_user_provided(self):
        """storage: user_provided → returns (None, 'user_provided')."""
        from generate_pack import resolve_file
        entry = {"name": "user_bios.bin", "storage": "user_provided"}
        path, status = resolve_file(entry, {}, "bios")
        self.assertIsNone(path)
        self.assertEqual(status, "user_provided")

    def test_resolve_file_embedded_normal(self):
        """storage: embedded (default) → delegates to resolve_local_file."""
        from generate_pack import resolve_file
        tmpdir = tempfile.mkdtemp()
        try:
            fpath = os.path.join(tmpdir, "test.bin")
            with open(fpath, "wb") as f:
                f.write(b"EMBEDDED")
            sha1 = _sha1(b"EMBEDDED")
            db = {
                "files": {sha1: {"path": fpath, "md5": _md5(b"EMBEDDED"), "name": "test.bin"}},
                "indexes": {"by_md5": {_md5(b"EMBEDDED"): sha1}, "by_name": {"test.bin": [sha1]}},
            }
            entry = {"name": "test.bin", "sha1": sha1}
            path, status = resolve_file(entry, db, tmpdir)
            self.assertEqual(path, fpath)
            self.assertEqual(status, "exact")
        finally:
            shutil.rmtree(tmpdir)

    def test_fetch_large_file_cached(self):
        """fetch_large_file returns cached file if it exists and hash matches."""
        from generate_pack import fetch_large_file
        tmpdir = tempfile.mkdtemp()
        try:
            cached = os.path.join(tmpdir, "big.bin")
            with open(cached, "wb") as f:
                f.write(b"BIGDATA")
            result = fetch_large_file("big.bin", dest_dir=tmpdir)
            self.assertEqual(result, cached)
        finally:
            shutil.rmtree(tmpdir)

    def test_fetch_large_file_bad_hash_rejected(self):
        """fetch_large_file rejects cached file with wrong hash."""
        from generate_pack import fetch_large_file
        tmpdir = tempfile.mkdtemp()
        try:
            cached = os.path.join(tmpdir, "big.bin")
            with open(cached, "wb") as f:
                f.write(b"WRONG")
            result = fetch_large_file("big.bin", dest_dir=tmpdir,
                                       expected_md5="0" * 32)
            # File should be rejected (wrong hash) and since URL won't work, returns None
            self.assertIsNone(result)
            # File should have been deleted
            self.assertFalse(os.path.exists(cached))
        finally:
            shutil.rmtree(tmpdir)


class TestDataDirectoriesSuppressGaps(unittest.TestCase):
    """data_directories refs in platform suppress cross-reference gaps."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.platforms_dir = os.path.join(self.tmpdir, "platforms")
        self.emulators_dir = os.path.join(self.tmpdir, "emulators")
        os.makedirs(self.platforms_dir)
        os.makedirs(self.emulators_dir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_data_dir_suppresses_emulator_gaps(self):
        """Emulator files covered by shared data_directory not reported as gaps."""
        import yaml

        # Platform declares dolphin-sys data directory
        platform = {
            "platform": "TestPlatform",
            "verification_mode": "existence",
            "systems": {
                "gamecube": {
                    "files": [
                        {"name": "gc_bios.bin", "destination": "gc_bios.bin", "required": True},
                    ],
                    "data_directories": [
                        {"ref": "dolphin-sys", "destination": "dolphin-emu/Sys"},
                    ],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "testplat.yml"), "w") as f:
            yaml.dump(platform, f)

        # Emulator profile with data_directories ref matching platform
        emu = {
            "emulator": "Dolphin",
            "type": "standalone + libretro",
            "systems": ["gamecube"],
            "data_directories": [{"ref": "dolphin-sys"}],
            "files": [
                {"name": "dsp_rom.bin", "required": False},
                {"name": "font_western.bin", "required": False},
            ],
        }
        with open(os.path.join(self.emulators_dir, "dolphin.yml"), "w") as f:
            yaml.dump(emu, f)

        config = load_platform_config("testplat", self.platforms_dir)
        db = {"indexes": {"by_name": {}}}
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, db, profiles)

        # dsp_rom.bin and font_western.bin should NOT appear as gaps
        # because dolphin-sys data_directory covers them
        gap_names = {u["name"] for u in undeclared}
        self.assertNotIn("dsp_rom.bin", gap_names)
        self.assertNotIn("font_western.bin", gap_names)

    def test_unmatched_data_dir_shows_gaps(self):
        """Emulator without matching data_directory in platform shows gaps."""
        import yaml

        platform = {
            "platform": "TestPlatform",
            "verification_mode": "existence",
            "systems": {
                "gamecube": {
                    "files": [
                        {"name": "gc_bios.bin", "destination": "gc_bios.bin", "required": True},
                    ],
                    # NO data_directories declared
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "testplat.yml"), "w") as f:
            yaml.dump(platform, f)

        emu = {
            "emulator": "Dolphin",
            "type": "standalone + libretro",
            "systems": ["gamecube"],
            "data_directories": [{"ref": "dolphin-sys"}],
            "files": [
                {"name": "dsp_rom.bin", "required": False},
            ],
        }
        with open(os.path.join(self.emulators_dir, "dolphin.yml"), "w") as f:
            yaml.dump(emu, f)

        config = load_platform_config("testplat", self.platforms_dir)
        db = {"indexes": {"by_name": {}}}
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, db, profiles)

        gap_names = {u["name"] for u in undeclared}
        self.assertIn("dsp_rom.bin", gap_names)


class TestSharedGroupsIncludes(unittest.TestCase):
    """Shared groups (_shared.yml) injected via includes:."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.platforms_dir = os.path.join(self.tmpdir, "platforms")
        os.makedirs(self.platforms_dir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_includes_injects_shared_files(self):
        """includes: [group] injects files from _shared.yml into platform config."""
        import yaml

        shared = {
            "shared_groups": {
                "mt32": [
                    {"name": "MT32_CONTROL.ROM", "destination": "MT32_CONTROL.ROM", "required": False},
                    {"name": "MT32_PCM.ROM", "destination": "MT32_PCM.ROM", "required": False},
                ],
            },
        }
        with open(os.path.join(self.platforms_dir, "_shared.yml"), "w") as f:
            yaml.dump(shared, f)

        platform = {
            "platform": "TestShared",
            "verification_mode": "existence",
            "systems": {
                "dos": {
                    "includes": ["mt32"],
                    "files": [
                        {"name": "dosbox.conf", "destination": "dosbox.conf", "required": False},
                    ],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "testshared.yml"), "w") as f:
            yaml.dump(platform, f)

        config = load_platform_config("testshared", self.platforms_dir)
        dos_files = config["systems"]["dos"]["files"]
        names = [f["name"] for f in dos_files]

        self.assertIn("MT32_CONTROL.ROM", names)
        self.assertIn("MT32_PCM.ROM", names)
        self.assertIn("dosbox.conf", names)

    def test_includes_empty_group_no_crash(self):
        """Referencing a non-existent shared group doesn't crash."""
        import yaml

        shared = {"shared_groups": {}}
        with open(os.path.join(self.platforms_dir, "_shared.yml"), "w") as f:
            yaml.dump(shared, f)

        platform = {
            "platform": "TestEmpty",
            "verification_mode": "existence",
            "systems": {
                "test": {
                    "includes": ["nonexistent"],
                    "files": [{"name": "a.bin", "destination": "a.bin", "required": True}],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "testempty.yml"), "w") as f:
            yaml.dump(platform, f)

        config = load_platform_config("testempty", self.platforms_dir)
        # Should not crash, files should still load
        self.assertIn("test", config["systems"])


class TestYAMLInheritance(unittest.TestCase):
    """Platform inheritance via inherits: field."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.platforms_dir = os.path.join(self.tmpdir, "platforms")
        os.makedirs(self.platforms_dir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_child_inherits_parent_systems(self):
        """Child platform gets all parent systems."""
        import yaml

        parent = {
            "platform": "Parent",
            "verification_mode": "existence",
            "base_destination": "system",
            "systems": {
                "nes": {"files": [{"name": "nes.bin", "destination": "nes.bin", "required": True}]},
                "snes": {"files": [{"name": "snes.bin", "destination": "snes.bin", "required": True}]},
            },
        }
        with open(os.path.join(self.platforms_dir, "parent.yml"), "w") as f:
            yaml.dump(parent, f)

        child = {
            "inherits": "parent",
            "platform": "Child",
            "base_destination": "BIOS",
        }
        with open(os.path.join(self.platforms_dir, "child.yml"), "w") as f:
            yaml.dump(child, f)

        config = load_platform_config("child", self.platforms_dir)
        self.assertEqual(config["platform"], "Child")
        self.assertEqual(config["base_destination"], "BIOS")
        self.assertIn("nes", config["systems"])
        self.assertIn("snes", config["systems"])

    def test_child_overrides_verification_mode(self):
        """Child can override parent's verification_mode."""
        import yaml

        parent = {
            "platform": "Parent",
            "verification_mode": "existence",
            "systems": {"sys": {"files": [{"name": "a.bin", "destination": "a.bin"}]}},
        }
        with open(os.path.join(self.platforms_dir, "parent2.yml"), "w") as f:
            yaml.dump(parent, f)

        child = {
            "inherits": "parent2",
            "platform": "ChildMD5",
            "verification_mode": "md5",
        }
        with open(os.path.join(self.platforms_dir, "child2.yml"), "w") as f:
            yaml.dump(child, f)

        config = load_platform_config("child2", self.platforms_dir)
        self.assertEqual(config["verification_mode"], "md5")


class TestPlatformGrouping(unittest.TestCase):
    """group_identical_platforms merges same-content platforms."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.platforms_dir = os.path.join(self.tmpdir, "platforms")
        os.makedirs(self.platforms_dir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_identical_platforms_grouped(self):
        """Two platforms with same files + base_dest are grouped."""
        import yaml
        from common import group_identical_platforms

        for name in ("plat_a", "plat_b"):
            p = {
                "platform": name,
                "verification_mode": "existence",
                "base_destination": "system",
                "systems": {"sys": {"files": [{"name": "x.bin", "destination": "x.bin"}]}},
            }
            with open(os.path.join(self.platforms_dir, f"{name}.yml"), "w") as f:
                yaml.dump(p, f)

        groups = group_identical_platforms(["plat_a", "plat_b"], self.platforms_dir)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0][0]), 2)

    def test_different_base_dest_separated(self):
        """Same files but different base_destination → separate groups."""
        import yaml
        from common import group_identical_platforms

        for name, dest in [("plat_sys", "system"), ("plat_bios", "BIOS")]:
            p = {
                "platform": name,
                "verification_mode": "existence",
                "base_destination": dest,
                "systems": {"sys": {"files": [{"name": "x.bin", "destination": "x.bin"}]}},
            }
            with open(os.path.join(self.platforms_dir, f"{name}.yml"), "w") as f:
                yaml.dump(p, f)

        groups = group_identical_platforms(["plat_sys", "plat_bios"], self.platforms_dir)
        self.assertEqual(len(groups), 2)


if __name__ == "__main__":
    unittest.main()
