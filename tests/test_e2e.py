"""End-to-end regression test.

ONE test scenario with YAML fixtures covering ALL code paths.
Run: python -m unittest tests.test_e2e -v

Covers:
  Resolution: SHA1, MD5, name, alias, truncated MD5, md5_composite,
              zip_contents, .variants deprio, not_found, hash_mismatch
  Verification: existence mode, md5 mode, required/optional,
                zipped_file (match/mismatch/missing inner), multi-hash
  Severity: all combos per platform mode
  Platform config: inheritance, shared groups, data_directories, grouping
  Pack: storage tiers (external/user_provided/embedded), dedup, large file cache
  Cross-reference: undeclared files, standalone skipped, alias profiles skipped,
                   data_dir suppresses gaps
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
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import yaml
from common import (
    _build_validation_index, build_zip_contents_index, check_file_validation,
    check_inside_zip, compute_hashes, diff_platform_truth,
    filter_files_by_mode,
    generate_platform_truth,
    group_identical_platforms, load_emulator_profiles, load_platform_config,
    md5_composite, md5sum, parse_md5_list, resolve_local_file,
    resolve_platform_cores, safe_extract_zip,
)
from verify import (
    Severity, Status, verify_platform, find_undeclared_files, find_exclusion_notes,
    verify_emulator, _effective_validation_label,
)


def _h(data: bytes) -> dict:
    """Return sha1, md5, crc32 for test data."""
    return {
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "crc32": format(hashlib.new("crc32", data).digest()[0], "08x")
               if False else "",  # not needed for tests
    }


class TestE2E(unittest.TestCase):
    """Single end-to-end scenario exercising every code path."""

    # ---------------------------------------------------------------
    # Fixture setup
    # ---------------------------------------------------------------

    def setUp(self):
        # Clear emulator profile cache to avoid stale data between tests
        from common import _emulator_profiles_cache
        _emulator_profiles_cache.clear()

        self.root = tempfile.mkdtemp()
        self.bios_dir = os.path.join(self.root, "bios")
        self.platforms_dir = os.path.join(self.root, "platforms")
        self.emulators_dir = os.path.join(self.root, "emulators")
        os.makedirs(self.bios_dir)
        os.makedirs(self.platforms_dir)
        os.makedirs(self.emulators_dir)

        # -- Create synthetic BIOS files --
        self.files = {}
        self._make_file("present_req.bin", b"PRESENT_REQUIRED")
        self._make_file("present_opt.bin", b"PRESENT_OPTIONAL")
        self._make_file("correct_hash.bin", b"CORRECT_HASH_DATA")
        self._make_file("wrong_hash.bin", b"WRONG_CONTENT_ON_DISK")
        self._make_file("no_md5.bin", b"NO_MD5_CHECK")
        self._make_file("truncated.bin", b"BATOCERA_TRUNCATED")
        self._make_file("alias_target.bin", b"ALIAS_FILE_DATA")
        self._make_file("leading_zero_crc.bin", b"LEADING_ZERO_CRC_12")  # crc32=0179e92e

        # Regional variant files (same name, different content, in subdirs)
        os.makedirs(os.path.join(self.bios_dir, "TestConsole", "USA"), exist_ok=True)
        os.makedirs(os.path.join(self.bios_dir, "TestConsole", "EUR"), exist_ok=True)
        self._make_file("BIOS.bin", b"BIOS_USA_CONTENT", subdir="TestConsole/USA")
        self._make_file("BIOS.bin", b"BIOS_EUR_CONTENT", subdir="TestConsole/EUR")

        # .variants/ file (should be deprioritized)
        variants_dir = os.path.join(self.bios_dir, ".variants")
        os.makedirs(variants_dir)
        self._make_file("present_req.bin", b"VARIANT_DATA", subdir=".variants")

        # ZIP with correct inner ROM
        self._make_zip("good.zip", {"inner.rom": b"GOOD_INNER_ROM"})
        # ZIP with wrong inner ROM
        self._make_zip("bad_inner.zip", {"inner.rom": b"BAD_INNER"})
        # ZIP with missing inner ROM name
        self._make_zip("missing_inner.zip", {"other.rom": b"OTHER_ROM"})
        # ZIP for md5_composite (Recalbox)
        self._make_zip("composite.zip", {"b.rom": b"BBBB", "a.rom": b"AAAA"})
        # ZIP for multi-hash
        self._make_zip("multi.zip", {"rom.bin": b"MULTI_HASH_DATA"})
        # Archive BIOS ZIP (like neogeo.zip) containing multiple ROMs
        self._make_zip("test_archive.zip", {
            "rom_a.bin": b"ARCHIVE_ROM_A",
            "rom_b.bin": b"ARCHIVE_ROM_B",
        })

        # -- Build synthetic database --
        self.db = self._build_db()

        # -- Create platform YAMLs --
        self._create_existence_platform()
        self._create_md5_platform()
        self._create_shared_groups()
        self._create_inherited_platform()
        self._create_sha1_platform()

        # -- Create emulator YAMLs --
        self._create_emulator_profiles()

    def tearDown(self):
        shutil.rmtree(self.root)

    # ---------------------------------------------------------------
    # File helpers
    # ---------------------------------------------------------------

    def _make_file(self, name: str, data: bytes, subdir: str = "") -> str:
        d = os.path.join(self.bios_dir, subdir) if subdir else self.bios_dir
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, name)
        with open(path, "wb") as f:
            f.write(data)
        h = _h(data)
        self.files[f"{subdir}/{name}" if subdir else name] = {
            "path": path, "data": data, **h,
        }
        return path

    def _make_zip(self, name: str, contents: dict[str, bytes]) -> str:
        path = os.path.join(self.bios_dir, name)
        with zipfile.ZipFile(path, "w") as zf:
            for fname, data in contents.items():
                zf.writestr(fname, data)
        with open(path, "rb") as f:
            zdata = f.read()
        h = _h(zdata)
        inner_md5s = {fn: hashlib.md5(d).hexdigest() for fn, d in contents.items()}
        self.files[name] = {"path": path, "data": zdata, "inner_md5s": inner_md5s, **h}
        return path

    def _build_db(self) -> dict:
        files_db = {}
        by_md5 = {}
        by_name = {}
        for key, info in self.files.items():
            name = os.path.basename(key)
            sha1 = info["sha1"]
            files_db[sha1] = {
                "path": info["path"],
                "md5": info["md5"],
                "name": name,
                "crc32": info.get("crc32", ""),
            }
            by_md5[info["md5"]] = sha1
            by_name.setdefault(name, []).append(sha1)
        # Add alias name to by_name
        alias_sha1 = self.files["alias_target.bin"]["sha1"]
        by_name.setdefault("alias_alt.bin", []).append(alias_sha1)
        # Build by_path_suffix for regional variant resolution
        by_path_suffix = {}
        for key, info in self.files.items():
            if "/" in key:
                # key is subdir/name, suffix is the subdir path
                by_path_suffix.setdefault(key, []).append(info["sha1"])
        return {
            "files": files_db,
            "indexes": {"by_md5": by_md5, "by_name": by_name, "by_crc32": {},
                        "by_path_suffix": by_path_suffix},
        }

    # ---------------------------------------------------------------
    # Platform YAML creators
    # ---------------------------------------------------------------

    def _create_existence_platform(self):
        f = self.files
        config = {
            "platform": "TestExistence",
            "verification_mode": "existence",
            "base_destination": "system",
            "systems": {
                "console-a": {
                    "files": [
                        {"name": "present_req.bin", "destination": "present_req.bin", "required": True},
                        {"name": "missing_req.bin", "destination": "missing_req.bin", "required": True},
                        {"name": "present_opt.bin", "destination": "present_opt.bin", "required": False},
                        {"name": "missing_opt.bin", "destination": "missing_opt.bin", "required": False},
                    ],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "test_existence.yml"), "w") as fh:
            yaml.dump(config, fh)

    def _create_md5_platform(self):
        f = self.files
        good_inner_md5 = f["good.zip"]["inner_md5s"]["inner.rom"]
        bad_inner_md5 = "deadbeefdeadbeefdeadbeefdeadbeef"
        composite_md5 = hashlib.md5(b"AAAA" + b"BBBB").hexdigest()  # sorted: a.rom, b.rom
        multi_wrong = "0000000000000000000000000000000"
        multi_right = f["multi.zip"]["inner_md5s"]["rom.bin"]
        truncated_md5 = f["truncated.bin"]["md5"][:29]  # Batocera 29-char

        config = {
            "platform": "TestMD5",
            "verification_mode": "md5",
            "systems": {
                "sys-md5": {
                    "includes": ["test_shared"],
                    "files": [
                        # Correct hash
                        {"name": "correct_hash.bin", "destination": "correct_hash.bin",
                         "md5": f["correct_hash.bin"]["md5"], "required": True},
                        # Wrong hash on disk → untested
                        {"name": "wrong_hash.bin", "destination": "wrong_hash.bin",
                         "md5": "ffffffffffffffffffffffffffffffff", "required": True},
                        # No MD5 → OK (existence within md5 platform)
                        {"name": "no_md5.bin", "destination": "no_md5.bin", "required": False},
                        # Missing required
                        {"name": "gone_req.bin", "destination": "gone_req.bin",
                         "md5": "abcd", "required": True},
                        # Missing optional
                        {"name": "gone_opt.bin", "destination": "gone_opt.bin",
                         "md5": "abcd", "required": False},
                        # zipped_file correct
                        {"name": "good.zip", "destination": "good.zip",
                         "md5": good_inner_md5, "zipped_file": "inner.rom", "required": True},
                        # zipped_file wrong inner
                        {"name": "bad_inner.zip", "destination": "bad_inner.zip",
                         "md5": bad_inner_md5, "zipped_file": "inner.rom", "required": False},
                        # zipped_file inner not found
                        {"name": "missing_inner.zip", "destination": "missing_inner.zip",
                         "md5": "abc", "zipped_file": "nope.rom", "required": False},
                        # md5_composite (Recalbox)
                        {"name": "composite.zip", "destination": "composite.zip",
                         "md5": composite_md5, "required": True},
                        # Multi-hash comma-separated (Recalbox)
                        {"name": "multi.zip", "destination": "multi.zip",
                         "md5": f"{multi_wrong},{multi_right}", "zipped_file": "rom.bin", "required": True},
                        # Truncated MD5 (Batocera 29 chars)
                        {"name": "truncated.bin", "destination": "truncated.bin",
                         "md5": truncated_md5, "required": True},
                        # Same destination from different entry → worst status wins
                        {"name": "correct_hash.bin", "destination": "dedup_target.bin",
                         "md5": f["correct_hash.bin"]["md5"], "required": True},
                        {"name": "correct_hash.bin", "destination": "dedup_target.bin",
                         "md5": "wrong_for_dedup_test", "required": True},
                    ],
                    "data_directories": [
                        {"ref": "test-data-dir", "destination": "TestData"},
                    ],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "test_md5.yml"), "w") as fh:
            yaml.dump(config, fh)

    def _create_shared_groups(self):
        shared = {
            "shared_groups": {
                "test_shared": [
                    {"name": "shared_file.rom", "destination": "shared_file.rom", "required": False},
                ],
            },
        }
        with open(os.path.join(self.platforms_dir, "_shared.yml"), "w") as fh:
            yaml.dump(shared, fh)

    def _create_inherited_platform(self):
        child = {
            "inherits": "test_existence",
            "platform": "TestInherited",
            "base_destination": "BIOS",
        }
        with open(os.path.join(self.platforms_dir, "test_inherited.yml"), "w") as fh:
            yaml.dump(child, fh)

    def _create_sha1_platform(self):
        f = self.files
        config = {
            "platform": "TestSHA1",
            "verification_mode": "sha1",
            "base_destination": "system",
            "systems": {
                "sys-sha1": {
                    "files": [
                        {"name": "correct_hash.bin", "destination": "correct_hash.bin",
                         "sha1": f["correct_hash.bin"]["sha1"], "required": True},
                        {"name": "wrong_hash.bin", "destination": "wrong_hash.bin",
                         "sha1": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "required": True},
                        {"name": "missing_sha1.bin", "destination": "missing_sha1.bin",
                         "sha1": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "required": True},
                        {"name": "optional_missing_sha1.bin", "destination": "optional_missing_sha1.bin",
                         "sha1": "cccccccccccccccccccccccccccccccccccccccc", "required": False},
                        {"name": "no_md5.bin", "destination": "no_md5.bin", "required": True},
                    ],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "test_sha1.yml"), "w") as fh:
            yaml.dump(config, fh)

    def _create_emulator_profiles(self):
        # Regular emulator with aliases, standalone file, undeclared file
        emu = {
            "emulator": "TestEmu",
            "type": "standalone + libretro",
            "systems": ["console-a", "sys-md5"],
            "data_directories": [{"ref": "test-data-dir"}],
            "files": [
                {"name": "present_req.bin", "required": True},
                {"name": "alias_target.bin", "required": False,
                 "aliases": ["alias_alt.bin"]},
                {"name": "standalone_only.bin", "required": False, "mode": "standalone"},
                {"name": "undeclared_req.bin", "required": True},
                {"name": "undeclared_opt.bin", "required": False},
            ],
        }
        with open(os.path.join(self.emulators_dir, "test_emu.yml"), "w") as fh:
            yaml.dump(emu, fh)

        # Emulator with HLE fallback
        emu_hle = {
            "emulator": "TestHLE",
            "type": "libretro",
            "systems": ["console-a"],
            "files": [
                {"name": "present_req.bin", "required": True, "hle_fallback": True},
                {"name": "hle_missing.bin", "required": True, "hle_fallback": True},
                {"name": "no_hle_missing.bin", "required": True, "hle_fallback": False},
            ],
        }
        with open(os.path.join(self.emulators_dir, "test_hle.yml"), "w") as fh:
            yaml.dump(emu_hle, fh)

        # Launcher profile (should be excluded from cross-reference)
        launcher = {
            "emulator": "TestLauncher",
            "type": "launcher",
            "systems": ["console-a"],
            "files": [{"name": "launcher_bios.bin", "required": True}],
        }
        with open(os.path.join(self.emulators_dir, "test_launcher.yml"), "w") as fh:
            yaml.dump(launcher, fh)

        # Alias profile (should be skipped)
        alias = {"emulator": "TestAlias", "type": "alias", "alias_of": "test_emu", "files": []}
        with open(os.path.join(self.emulators_dir, "test_alias.yml"), "w") as fh:
            yaml.dump(alias, fh)

        # Emulator with data_dir that matches platform → gaps suppressed
        emu_dd = {
            "emulator": "TestEmuDD",
            "type": "libretro",
            "systems": ["sys-md5"],
            "data_directories": [{"ref": "test-data-dir"}],
            "files": [
                {"name": "dd_covered.bin", "required": False},
            ],
        }
        with open(os.path.join(self.emulators_dir, "test_emu_dd.yml"), "w") as fh:
            yaml.dump(emu_dd, fh)

        # Emulator with archived files (like FBNeo with neogeo.zip)
        emu_archive = {
            "emulator": "TestArchiveEmu",
            "type": "libretro",
            "systems": ["console-a"],
            "files": [
                {"name": "rom_a.bin", "required": True, "archive": "test_archive.zip"},
                {"name": "rom_b.bin", "required": False, "archive": "test_archive.zip"},
                {"name": "missing_rom.bin", "required": True, "archive": "missing_archive.zip"},
            ],
        }
        with open(os.path.join(self.emulators_dir, "test_archive_emu.yml"), "w") as fh:
            yaml.dump(emu_archive, fh)

        # Emulator with descriptive name and path (like QEMU SeaBIOS)
        emu_descriptive = {
            "emulator": "TestDescriptive",
            "type": "libretro",
            "systems": ["console-a"],
            "files": [
                {"name": "Descriptive BIOS Name", "required": True,
                 "path": "present_req.bin"},
                {"name": "Missing Descriptive", "required": True,
                 "path": "nonexistent_path.bin"},
            ],
        }
        with open(os.path.join(self.emulators_dir, "test_descriptive.yml"), "w") as fh:
            yaml.dump(emu_descriptive, fh)

        # Emulator with validation checks (size, crc32)
        emu_val = {
            "emulator": "TestValidation",
            "type": "libretro",
            "systems": ["console-a", "sys-md5"],
            "files": [
                # Size validation — correct size (16 bytes = len(b"PRESENT_REQUIRED"))
                {"name": "present_req.bin", "required": True,
                 "validation": ["size"], "size": 16,
                 "source_ref": "test.c:10-20"},
                # Size validation — wrong expected size
                {"name": "present_opt.bin", "required": False,
                 "validation": ["size"], "size": 9999},
                # CRC32 validation — correct crc32
                {"name": "correct_hash.bin", "required": True,
                 "validation": ["crc32"], "crc32": "91d0b1d3",
                 "source_ref": "hash.c:42"},
                # CRC32 validation — wrong crc32
                {"name": "no_md5.bin", "required": False,
                 "validation": ["crc32"], "crc32": "deadbeef"},
                # CRC32 starting with '0' (regression: lstrip("0x") bug)
                {"name": "leading_zero_crc.bin", "required": True,
                 "validation": ["crc32"], "crc32": "0179e92e"},
                # MD5 validation — correct md5
                {"name": "correct_hash.bin", "required": True,
                 "validation": ["md5"], "md5": "4a8db431e3b1a1acacec60e3424c4ce8"},
                # SHA1 validation — correct sha1
                {"name": "correct_hash.bin", "required": True,
                 "validation": ["sha1"], "sha1": "a2ab6c95c5bbd191b9e87e8f4e85205a47be5764"},
                # MD5 validation — wrong md5
                {"name": "alias_target.bin", "required": False,
                 "validation": ["md5"], "md5": "0000000000000000000000000000dead"},
                # Adler32 — known_hash_adler32 field
                {"name": "present_req.bin", "required": True,
                 "known_hash_adler32": None},  # placeholder, set below
                # Min/max size range validation
                {"name": "present_req.bin", "required": True,
                 "validation": ["size"], "min_size": 10, "max_size": 100},
                # Signature — crypto check we can't reproduce, but size applies
                {"name": "correct_hash.bin", "required": True,
                 "validation": ["size", "signature"], "size": 17},
            ],
        }
        # Compute the actual adler32 of present_req.bin for the test fixture
        import zlib as _zlib
        with open(self.files["present_req.bin"]["path"], "rb") as _f:
            _data = _f.read()
        _adler = format(_zlib.adler32(_data) & 0xFFFFFFFF, "08x")
        # Set the adler32 entry (the one with known_hash_adler32=None)
        for entry in emu_val["files"]:
            if entry.get("known_hash_adler32") is None and "known_hash_adler32" in entry:
                entry["known_hash_adler32"] = f"0x{_adler}"
                break
        with open(os.path.join(self.emulators_dir, "test_validation.yml"), "w") as fh:
            yaml.dump(emu_val, fh)

        # Emulator A: declares present_req.bin at root (no path)
        emu_root = {
            "emulator": "TestRootCore",
            "type": "libretro",
            "systems": ["console-a"],
            "files": [
                {"name": "present_req.bin", "required": True},
            ],
        }
        with open(os.path.join(self.emulators_dir, "test_root_core.yml"), "w") as fh:
            yaml.dump(emu_root, fh)

        # Emulator B: declares same file at a subdirectory path
        emu_subdir = {
            "emulator": "TestSubdirCore",
            "type": "libretro",
            "systems": ["console-a"],
            "files": [
                {"name": "present_req.bin", "required": True,
                 "path": "subcore/bios/present_req.bin"},
            ],
        }
        with open(os.path.join(self.emulators_dir, "test_subdir_core.yml"), "w") as fh:
            yaml.dump(emu_subdir, fh)

    # ---------------------------------------------------------------
    # THE TEST — one method per feature area, all using same fixtures
    # ---------------------------------------------------------------

    def test_01_resolve_sha1(self):
        entry = {"name": "present_req.bin", "sha1": self.files["present_req.bin"]["sha1"]}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "exact")
        self.assertIn("present_req.bin", path)

    def test_02_resolve_md5(self):
        entry = {"name": "correct_hash.bin", "md5": self.files["correct_hash.bin"]["md5"]}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "md5_exact")

    def test_03_resolve_name_no_md5(self):
        entry = {"name": "no_md5.bin"}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "exact")

    def test_04_resolve_alias(self):
        entry = {"name": "alias_alt.bin", "aliases": []}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "exact")
        self.assertIn("alias_target.bin", path)

    def test_05_resolve_truncated_md5(self):
        truncated = self.files["truncated.bin"]["md5"][:29]
        entry = {"name": "truncated.bin", "md5": truncated}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "md5_exact")

    def test_06_resolve_not_found(self):
        entry = {"name": "nonexistent.bin", "sha1": "0" * 40}
        path, status = resolve_local_file(entry, self.db)
        self.assertIsNone(path)
        self.assertEqual(status, "not_found")

    def test_07_resolve_hash_mismatch(self):
        entry = {"name": "wrong_hash.bin", "md5": "ffffffffffffffffffffffffffffffff"}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "hash_mismatch")

    def test_08_resolve_variants_deprioritized(self):
        entry = {"name": "present_req.bin"}
        path, status = resolve_local_file(entry, self.db)
        self.assertNotIn(".variants", path)

    def test_09_resolve_zip_contents(self):
        zc = build_zip_contents_index(self.db)
        inner_md5 = self.files["good.zip"]["inner_md5s"]["inner.rom"]
        entry = {"name": "good.zip", "md5": inner_md5, "zipped_file": "inner.rom"}
        path, status = resolve_local_file(entry, self.db, zc)
        # Should find via name match (hash_mismatch since container md5 != inner md5)
        # then zip_contents would be fallback
        self.assertIsNotNone(path)

    def test_10_md5_composite(self):
        expected = hashlib.md5(b"AAAA" + b"BBBB").hexdigest()
        actual = md5_composite(self.files["composite.zip"]["path"])
        self.assertEqual(actual, expected)

    def test_11_check_inside_zip_match(self):
        inner_md5 = self.files["good.zip"]["inner_md5s"]["inner.rom"]
        r = check_inside_zip(self.files["good.zip"]["path"], "inner.rom", inner_md5)
        self.assertEqual(r, "ok")

    def test_12_check_inside_zip_mismatch(self):
        r = check_inside_zip(self.files["bad_inner.zip"]["path"], "inner.rom", "wrong")
        self.assertEqual(r, "untested")

    def test_13_check_inside_zip_not_found(self):
        r = check_inside_zip(self.files["missing_inner.zip"]["path"], "nope.rom", "abc")
        self.assertEqual(r, "not_in_zip")

    def test_14_check_inside_zip_casefold(self):
        inner_md5 = self.files["good.zip"]["inner_md5s"]["inner.rom"]
        r = check_inside_zip(self.files["good.zip"]["path"], "INNER.ROM", inner_md5)
        self.assertEqual(r, "ok")

    def test_20_verify_existence_platform(self):
        config = load_platform_config("test_existence", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        c = result["severity_counts"]
        total = result["total_files"]
        # 2 present (1 req + 1 opt), 2 missing (1 req WARNING + 1 opt INFO)
        self.assertEqual(c[Severity.OK], 2)
        self.assertEqual(c[Severity.WARNING], 1)  # required missing
        self.assertEqual(c[Severity.INFO], 1)      # optional missing
        self.assertEqual(sum(c.values()), total)

    def test_21_verify_md5_platform(self):
        config = load_platform_config("test_md5", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        c = result["severity_counts"]
        total = result["total_files"]
        self.assertEqual(sum(c.values()), total)
        # At least some OK and some non-OK
        self.assertGreater(c[Severity.OK], 0)
        self.assertGreater(total, c[Severity.OK])

    def test_22_verify_required_propagated(self):
        config = load_platform_config("test_md5", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        for d in result["details"]:
            self.assertIn("required", d)

    def test_23_verify_missing_required_is_critical(self):
        config = load_platform_config("test_md5", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        c = result["severity_counts"]
        self.assertGreater(c[Severity.CRITICAL], 0)

    def test_24_verify_missing_optional_is_warning(self):
        config = load_platform_config("test_md5", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        c = result["severity_counts"]
        self.assertGreater(c[Severity.WARNING], 0)

    def test_25_verify_sha1_platform(self):
        config = load_platform_config("test_sha1", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        self.assertEqual(result["total_files"], 5)
        self.assertEqual(result["verification_mode"], "sha1")
        ok_count = result["severity_counts"][Severity.OK]
        self.assertEqual(ok_count, 2)

    def test_26_sha1_mismatch_is_warning(self):
        config = load_platform_config("test_sha1", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        by_name = {d["name"]: d for d in result["details"]}
        self.assertEqual(by_name["wrong_hash.bin"]["status"], Status.UNTESTED)

    def test_27_sha1_missing_required_is_critical(self):
        config = load_platform_config("test_sha1", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        c = result["severity_counts"]
        self.assertGreater(c[Severity.CRITICAL], 0)

    def test_28_sha1_missing_optional_is_warning(self):
        config = load_platform_config("test_sha1", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        c = result["severity_counts"]
        self.assertGreater(c[Severity.WARNING], 0)

    def test_29_sha1_no_hash_is_existence_check(self):
        config = load_platform_config("test_sha1", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        by_name = {d["name"]: d for d in result["details"]}
        self.assertEqual(by_name["no_md5.bin"]["status"], Status.OK)

    def test_30_inheritance_inherits_systems(self):
        config = load_platform_config("test_inherited", self.platforms_dir)
        self.assertEqual(config["platform"], "TestInherited")
        self.assertEqual(config["base_destination"], "BIOS")
        self.assertIn("console-a", config["systems"])

    def test_31_shared_groups_injected(self):
        config = load_platform_config("test_md5", self.platforms_dir)
        names = [f["name"] for f in config["systems"]["sys-md5"]["files"]]
        self.assertIn("shared_file.rom", names)

    def test_40_cross_ref_finds_undeclared(self):
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        names = {u["name"] for u in undeclared}
        self.assertIn("undeclared_req.bin", names)
        self.assertIn("undeclared_opt.bin", names)

    def test_41_cross_ref_skips_standalone(self):
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        names = {u["name"] for u in undeclared}
        self.assertNotIn("standalone_only.bin", names)

    def test_42_cross_ref_skips_alias_profiles(self):
        profiles = load_emulator_profiles(self.emulators_dir)
        self.assertNotIn("test_alias", profiles)

    def test_43_cross_ref_data_dir_does_not_suppress_files(self):
        config = load_platform_config("test_md5", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        names = {u["name"] for u in undeclared}
        # dd_covered.bin is a file entry, not data_dir content — still undeclared
        self.assertIn("dd_covered.bin", names)

    def test_44_cross_ref_skips_launchers(self):
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        names = {u["name"] for u in undeclared}
        # launcher_bios.bin from TestLauncher should NOT appear
        self.assertNotIn("launcher_bios.bin", names)

    def test_45_hle_fallback_downgrades_severity(self):
        """Missing file with hle_fallback=true → INFO severity, not CRITICAL."""
        from verify import compute_severity, Severity
        # required + missing + NO HLE = CRITICAL
        sev = compute_severity("missing", True, "md5", hle_fallback=False)
        self.assertEqual(sev, Severity.CRITICAL)
        # required + missing + HLE = INFO
        sev = compute_severity("missing", True, "md5", hle_fallback=True)
        self.assertEqual(sev, Severity.INFO)
        # required + missing + HLE + existence mode = INFO
        sev = compute_severity("missing", True, "existence", hle_fallback=True)
        self.assertEqual(sev, Severity.INFO)

    def test_46_hle_index_built_from_emulator_profiles(self):
        """verify_platform reads hle_fallback from emulator profiles."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        result = verify_platform(config, self.db, self.emulators_dir, profiles)
        # present_req.bin has hle_fallback: true in TestHLE profile
        for d in result["details"]:
            if d["name"] == "present_req.bin":
                self.assertTrue(d.get("hle_fallback", False))
                break

    def test_47_cross_ref_shows_hle_on_undeclared(self):
        """Undeclared files include hle_fallback from emulator profile."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        hle_files = {u["name"] for u in undeclared if u.get("hle_fallback")}
        self.assertIn("hle_missing.bin", hle_files)

    def test_50_platform_grouping_identical(self):
        groups = group_identical_platforms(
            ["test_existence", "test_inherited"], self.platforms_dir
        )
        # Different base_destination → separate groups
        self.assertEqual(len(groups), 2)

    def test_51_platform_grouping_same(self):
        # Create two identical platforms
        for name in ("dup_a", "dup_b"):
            config = {
                "platform": name,
                "verification_mode": "existence",
                "systems": {"s": {"files": [{"name": "x.bin", "destination": "x.bin"}]}},
            }
            with open(os.path.join(self.platforms_dir, f"{name}.yml"), "w") as fh:
                yaml.dump(config, fh)
        groups = group_identical_platforms(["dup_a", "dup_b"], self.platforms_dir)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0][0]), 2)

    def test_60_storage_external(self):
        from generate_pack import resolve_file
        entry = {"name": "large.pup", "storage": "external"}
        path, status = resolve_file(entry, self.db, self.bios_dir)
        self.assertIsNone(path)
        self.assertEqual(status, "external")

    def test_61_storage_user_provided(self):
        from generate_pack import resolve_file
        entry = {"name": "user.bin", "storage": "user_provided"}
        path, status = resolve_file(entry, self.db, self.bios_dir)
        self.assertIsNone(path)
        self.assertEqual(status, "user_provided")


    def test_resolve_cores_all_libretro(self):
        """all_libretro resolves to all libretro-type profiles, excludes alias/standalone."""
        config = {"cores": "all_libretro", "systems": {"nes": {"files": []}}}
        profiles = {
            "fceumm": {"type": "libretro", "systems": ["nes"], "files": []},
            "dolphin_standalone": {"type": "standalone", "systems": ["gc"], "files": []},
            "gambatte": {"type": "pure_libretro", "systems": ["gb"], "files": []},
            "mednafen_psx_hw": {"type": "alias", "alias_of": "beetle_psx", "files": []},
        }
        result = resolve_platform_cores(config, profiles)
        self.assertEqual(result, {"fceumm", "gambatte"})

    def test_resolve_cores_explicit_list(self):
        """Explicit cores list matches against profile dict keys."""
        config = {"cores": ["fbneo", "opera"], "systems": {"arcade": {"files": []}}}
        profiles = {
            "fbneo": {"type": "pure_libretro", "systems": ["arcade"], "files": []},
            "opera": {"type": "libretro", "systems": ["3do"], "files": []},
            "mame": {"type": "libretro", "systems": ["arcade"], "files": []},
        }
        result = resolve_platform_cores(config, profiles)
        self.assertEqual(result, {"fbneo", "opera"})

    def test_resolve_cores_fallback_systems(self):
        """Missing cores: field falls back to system ID intersection."""
        config = {"systems": {"nes": {"files": []}}}
        profiles = {
            "fceumm": {"type": "libretro", "systems": ["nes"], "files": []},
            "dolphin": {"type": "libretro", "systems": ["gc"], "files": []},
        }
        result = resolve_platform_cores(config, profiles)
        self.assertEqual(result, {"fceumm"})

    def test_resolve_cores_excludes_alias(self):
        """Alias profiles never included even if name matches cores list."""
        config = {"cores": ["mednafen_psx_hw"], "systems": {}}
        profiles = {
            "mednafen_psx_hw": {"type": "alias", "alias_of": "beetle_psx", "files": []},
        }
        result = resolve_platform_cores(config, profiles)
        self.assertEqual(result, set())


    def test_cross_reference_uses_core_resolution(self):
        """Cross-reference matches by cores: field, not system intersection."""
        config = {
            "cores": ["fbneo"],
            "systems": {
                "arcade": {"files": [{"name": "neogeo.zip", "md5": "abc"}]}
            }
        }
        profiles = {
            "fbneo": {
                "emulator": "FBNeo", "systems": ["snk-neogeo-mvs"],
                "type": "pure_libretro",
                "files": [
                    {"name": "neogeo.zip", "required": True},
                    {"name": "neocdz.zip", "required": True},
                ],
            },
        }
        db = {"indexes": {"by_name": {"neocdz.zip": {"sha1": "x"}}}}
        undeclared = find_undeclared_files(config, self.emulators_dir, db, profiles)
        names = [u["name"] for u in undeclared]
        self.assertIn("neocdz.zip", names)
        self.assertNotIn("neogeo.zip", names)

    def test_exclusion_notes_uses_core_resolution(self):
        """Exclusion notes match by cores: field, not system intersection."""
        config = {
            "cores": ["desmume2015"],
            "systems": {"nds": {"files": []}}
        }
        profiles = {
            "desmume2015": {
                "emulator": "DeSmuME 2015", "type": "frozen_snapshot",
                "systems": ["nintendo-ds"],
                "files": [],
                "exclusion_note": "Frozen snapshot, code never loads BIOS",
            },
        }
        notes = find_exclusion_notes(config, self.emulators_dir, profiles)
        emu_names = [n["emulator"] for n in notes]
        self.assertIn("DeSmuME 2015", emu_names)


    def test_70_validation_index_built(self):
        """Validation index extracts checks from emulator profiles."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = _build_validation_index(profiles)
        self.assertIn("present_req.bin", index)
        self.assertIn("size", index["present_req.bin"]["checks"])
        self.assertIn(16, index["present_req.bin"]["sizes"])
        self.assertIn("correct_hash.bin", index)
        self.assertIn("crc32", index["correct_hash.bin"]["checks"])

    def test_71_validation_size_pass(self):
        """File with correct size passes validation."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = _build_validation_index(profiles)
        path = self.files["present_req.bin"]["path"]
        reason = check_file_validation(path, "present_req.bin", index)
        self.assertIsNone(reason)

    def test_72_validation_size_fail(self):
        """File with wrong size fails validation."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = _build_validation_index(profiles)
        path = self.files["present_opt.bin"]["path"]
        reason = check_file_validation(path, "present_opt.bin", index)
        self.assertIsNotNone(reason)
        self.assertIn("size mismatch", reason)

    def test_73_validation_crc32_pass(self):
        """File with correct CRC32 passes validation."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = _build_validation_index(profiles)
        path = self.files["correct_hash.bin"]["path"]
        reason = check_file_validation(path, "correct_hash.bin", index)
        self.assertIsNone(reason)

    def test_74_validation_crc32_fail(self):
        """File with wrong CRC32 fails validation."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = _build_validation_index(profiles)
        path = self.files["no_md5.bin"]["path"]
        reason = check_file_validation(path, "no_md5.bin", index)
        self.assertIsNotNone(reason)
        self.assertIn("crc32 mismatch", reason)

    def test_75_validation_applied_in_existence_mode(self):
        """Existence mode reports discrepancy when validation fails, keeps OK."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        result = verify_platform(config, self.db, self.emulators_dir, profiles)
        # present_opt.bin exists but has wrong expected size - OK with discrepancy
        for d in result["details"]:
            if d["name"] == "present_opt.bin":
                self.assertEqual(d["status"], Status.OK)
                self.assertIn("size mismatch", d.get("discrepancy", ""))
                break
        else:
            self.fail("present_opt.bin not found in details")

    def test_77_validation_crc32_leading_zero(self):
        """CRC32 starting with '0' must not be truncated (lstrip regression)."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = _build_validation_index(profiles)
        path = self.files["leading_zero_crc.bin"]["path"]
        reason = check_file_validation(path, "leading_zero_crc.bin", index)
        self.assertIsNone(reason)

    def test_78_validation_multi_size_accepted(self):
        """Multiple valid sizes from different profiles are collected as a set."""
        profiles = {
            "emu_a": {
                "type": "libretro", "files": [
                    {"name": "shared.bin", "validation": ["size"], "size": 512},
                ],
            },
            "emu_b": {
                "type": "libretro", "files": [
                    {"name": "shared.bin", "validation": ["size"], "size": 1024},
                ],
            },
        }
        index = _build_validation_index(profiles)
        self.assertEqual(index["shared.bin"]["sizes"], {512, 1024})

    def test_79_validation_md5_pass(self):
        """File with correct MD5 passes validation."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = _build_validation_index(profiles)
        path = self.files["correct_hash.bin"]["path"]
        reason = check_file_validation(path, "correct_hash.bin", index)
        self.assertIsNone(reason)

    def test_80_validation_md5_fail(self):
        """File with wrong MD5 fails validation."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = _build_validation_index(profiles)
        path = self.files["alias_target.bin"]["path"]
        reason = check_file_validation(path, "alias_target.bin", index)
        self.assertIsNotNone(reason)
        self.assertIn("md5 mismatch", reason)

    def test_81_validation_index_has_md5_sha1(self):
        """Validation index stores md5 and sha1 when declared."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = _build_validation_index(profiles)
        self.assertIn("md5", index["correct_hash.bin"]["checks"])
        self.assertIn("sha1", index["correct_hash.bin"]["checks"])
        self.assertIsNotNone(index["correct_hash.bin"]["md5"])
        self.assertIsNotNone(index["correct_hash.bin"]["sha1"])

    def test_82_validation_adler32_pass(self):
        """File with correct adler32 passes validation."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = _build_validation_index(profiles)
        path = self.files["present_req.bin"]["path"]
        reason = check_file_validation(path, "present_req.bin", index)
        self.assertIsNone(reason)

    def test_83_validation_min_max_size_pass(self):
        """File within min/max size range passes validation."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = _build_validation_index(profiles)
        path = self.files["present_req.bin"]["path"]
        reason = check_file_validation(path, "present_req.bin", index)
        self.assertIsNone(reason)
        # Verify the index has min/max
        self.assertEqual(index["present_req.bin"]["min_size"], 10)
        self.assertEqual(index["present_req.bin"]["max_size"], 100)

    def test_84_validation_crypto_tracked(self):
        """Signature/crypto checks are tracked as non-reproducible."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = _build_validation_index(profiles)
        # correct_hash.bin has [size, signature]
        self.assertIn("signature", index["correct_hash.bin"]["crypto_only"])
        # Size check still applies despite signature being non-reproducible
        path = self.files["correct_hash.bin"]["path"]
        reason = check_file_validation(path, "correct_hash.bin", index)
        self.assertIsNone(reason)  # size=16 matches

    def test_76_validation_no_effect_when_no_field(self):
        """Files without validation field are unaffected."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = _build_validation_index(profiles)
        # wrong_hash.bin has no validation in any profile
        path = self.files["wrong_hash.bin"]["path"]
        reason = check_file_validation(path, "wrong_hash.bin", index)
        self.assertIsNone(reason)


    # ---------------------------------------------------------------
    # Emulator/system mode verification
    # ---------------------------------------------------------------

    def test_90_verify_emulator_basic(self):
        """verify_emulator returns correct counts for a profile with mixed present/missing."""
        result = verify_emulator(["test_emu"], self.emulators_dir, self.db)
        self.assertIn("test_emu", result["emulators"])
        # present_req.bin and alias_target.bin are present, others missing
        self.assertGreater(result["total_files"], 0)
        self.assertGreater(result["severity_counts"][Severity.OK], 0)

    def test_91_verify_emulator_standalone_filters(self):
        """Standalone mode includes mode:standalone files, excludes mode:libretro."""
        result_lr = verify_emulator(["test_emu"], self.emulators_dir, self.db, standalone=False)
        result_sa = verify_emulator(["test_emu"], self.emulators_dir, self.db, standalone=True)
        lr_names = {d["name"] for d in result_lr["details"]}
        sa_names = {d["name"] for d in result_sa["details"]}
        # standalone_only.bin should be in standalone, not libretro
        self.assertNotIn("standalone_only.bin", lr_names)
        self.assertIn("standalone_only.bin", sa_names)

    def test_102_resolve_dest_hint_disambiguates(self):
        """dest_hint resolves regional variants with same name to distinct files."""
        usa_path, usa_status = resolve_local_file(
            {"name": "BIOS.bin"}, self.db, dest_hint="TestConsole/USA/BIOS.bin",
        )
        eur_path, eur_status = resolve_local_file(
            {"name": "BIOS.bin"}, self.db, dest_hint="TestConsole/EUR/BIOS.bin",
        )
        self.assertIsNotNone(usa_path)
        self.assertIsNotNone(eur_path)
        self.assertEqual(usa_status, "exact")
        self.assertEqual(eur_status, "exact")
        # Must be DIFFERENT files
        self.assertNotEqual(usa_path, eur_path)
        # Verify content
        with open(usa_path, "rb") as f:
            self.assertEqual(f.read(), b"BIOS_USA_CONTENT")
        with open(eur_path, "rb") as f:
            self.assertEqual(f.read(), b"BIOS_EUR_CONTENT")

    def test_103_resolve_dest_hint_fallback_to_name(self):
        """Without dest_hint, falls back to by_name (first candidate)."""
        path, status = resolve_local_file({"name": "BIOS.bin"}, self.db)
        self.assertIsNotNone(path)
        # Still finds something (first candidate by name)

    def test_92_verify_emulator_libretro_only_rejects_standalone(self):
        """Libretro-only profile rejects --standalone."""
        with self.assertRaises(SystemExit):
            verify_emulator(["test_hle"], self.emulators_dir, self.db, standalone=True)

    def test_92b_verify_emulator_game_type_rejects_standalone(self):
        """Game-type profile rejects --standalone."""
        game = {"emulator": "TestGame", "type": "game", "systems": ["console-a"], "files": []}
        with open(os.path.join(self.emulators_dir, "test_game.yml"), "w") as fh:
            yaml.dump(game, fh)
        with self.assertRaises(SystemExit):
            verify_emulator(["test_game"], self.emulators_dir, self.db, standalone=True)

    def test_93_verify_emulator_alias_rejected(self):
        """Alias profile produces error with redirect message."""
        with self.assertRaises(SystemExit):
            verify_emulator(["test_alias"], self.emulators_dir, self.db)

    def test_94_verify_emulator_launcher_rejected(self):
        """Launcher profile produces error."""
        with self.assertRaises(SystemExit):
            verify_emulator(["test_launcher"], self.emulators_dir, self.db)

    def test_95_verify_emulator_validation_applied(self):
        """Emulator mode applies validation checks as primary verification."""
        result = verify_emulator(["test_validation"], self.emulators_dir, self.db)
        # present_opt.bin has wrong size → UNTESTED
        for d in result["details"]:
            if d["name"] == "present_opt.bin":
                self.assertEqual(d["status"], Status.UNTESTED)
                self.assertIn("size mismatch", d.get("reason", ""))
                break
        else:
            self.fail("present_opt.bin not found in details")

    def test_96_verify_emulator_multi(self):
        """Multi-emulator verify aggregates files."""
        result = verify_emulator(
            ["test_emu", "test_hle"], self.emulators_dir, self.db,
        )
        self.assertEqual(len(result["emulators"]), 2)
        all_names = {d["name"] for d in result["details"]}
        # Files from both profiles
        self.assertIn("present_req.bin", all_names)
        self.assertIn("hle_missing.bin", all_names)

    def test_97_verify_emulator_data_dir_notice(self):
        """Emulator with data_directories reports notice."""
        result = verify_emulator(["test_emu"], self.emulators_dir, self.db)
        self.assertIn("test-data-dir", result.get("data_dir_notices", []))

    def test_98_verify_emulator_validation_label(self):
        """Validation label reflects the checks used."""
        result = verify_emulator(["test_validation"], self.emulators_dir, self.db)
        # test_validation has crc32, md5, sha1, size → all listed
        self.assertEqual(result["verification_mode"], "crc32+md5+sha1+signature+size")

    def test_99filter_files_by_mode(self):
        """filter_files_by_mode correctly filters standalone/libretro."""
        files = [
            {"name": "a.bin"},                         # no mode → both
            {"name": "b.bin", "mode": "libretro"},     # libretro only
            {"name": "c.bin", "mode": "standalone"},   # standalone only
            {"name": "d.bin", "mode": "both"},         # explicit both
        ]
        lr = filter_files_by_mode(files, standalone=False)
        sa = filter_files_by_mode(files, standalone=True)
        lr_names = {f["name"] for f in lr}
        sa_names = {f["name"] for f in sa}
        self.assertEqual(lr_names, {"a.bin", "b.bin", "d.bin"})
        self.assertEqual(sa_names, {"a.bin", "c.bin", "d.bin"})

    def test_100_verify_emulator_empty_profile(self):
        """Profile with files:[] produces note, not error."""
        empty = {
            "emulator": "TestEmpty", "type": "libretro",
            "systems": ["console-a"], "files": [],
            "exclusion_note": "Code never loads BIOS",
        }
        with open(os.path.join(self.emulators_dir, "test_empty.yml"), "w") as fh:
            yaml.dump(empty, fh)
        result = verify_emulator(["test_empty"], self.emulators_dir, self.db)
        # Should have a note entry, not crash
        self.assertEqual(result["total_files"], 0)
        notes = [d for d in result["details"] if d.get("note")]
        self.assertTrue(len(notes) > 0)

    def test_101_verify_emulator_severity_missing_required(self):
        """Missing required file in emulator mode → WARNING severity."""
        result = verify_emulator(["test_emu"], self.emulators_dir, self.db)
        # undeclared_req.bin is required and missing
        for d in result["details"]:
            if d["name"] == "undeclared_req.bin":
                self.assertEqual(d["status"], Status.MISSING)
                self.assertTrue(d["required"])
                break
        else:
            self.fail("undeclared_req.bin not found")
        # Severity should be WARNING (existence mode base)
        self.assertGreater(result["severity_counts"][Severity.WARNING], 0)


    def test_102_safe_extract_zip_blocks_traversal(self):
        """safe_extract_zip must reject zip-slip path traversal."""
        malicious_zip = os.path.join(self.root, "evil.zip")
        with zipfile.ZipFile(malicious_zip, "w") as zf:
            zf.writestr("../../etc/passwd", "root:x:0:0")
        dest = os.path.join(self.root, "extract_dest")
        os.makedirs(dest)
        with self.assertRaises(ValueError):
            safe_extract_zip(malicious_zip, dest)

    def test_103_safe_extract_zip_normal(self):
        """safe_extract_zip extracts valid files correctly."""
        normal_zip = os.path.join(self.root, "normal.zip")
        with zipfile.ZipFile(normal_zip, "w") as zf:
            zf.writestr("subdir/file.txt", "hello")
        dest = os.path.join(self.root, "extract_normal")
        os.makedirs(dest)
        safe_extract_zip(normal_zip, dest)
        extracted = os.path.join(dest, "subdir", "file.txt")
        self.assertTrue(os.path.exists(extracted))
        with open(extracted) as f:
            self.assertEqual(f.read(), "hello")

    def test_104_compute_hashes_correctness(self):
        """compute_hashes returns correct values for known content."""
        test_file = os.path.join(self.root, "hash_test.bin")
        data = b"retrobios test content"
        with open(test_file, "wb") as f:
            f.write(data)
        import zlib
        expected_sha1 = hashlib.sha1(data).hexdigest()
        expected_md5 = hashlib.md5(data).hexdigest()
        expected_sha256 = hashlib.sha256(data).hexdigest()
        expected_crc32 = format(zlib.crc32(data) & 0xFFFFFFFF, "08x")

        result = compute_hashes(test_file)
        self.assertEqual(result["sha1"], expected_sha1)
        self.assertEqual(result["md5"], expected_md5)
        self.assertEqual(result["sha256"], expected_sha256)
        self.assertEqual(result["crc32"], expected_crc32)

    def test_105_resolve_with_empty_database(self):
        """resolve_local_file handles empty database gracefully."""
        empty_db = {"files": {}, "indexes": {"by_md5": {}, "by_name": {}, "by_path_suffix": {}}}
        entry = {"name": "nonexistent.bin", "sha1": "abc123"}
        path, status = resolve_local_file(entry, empty_db)
        self.assertIsNone(path)
        self.assertEqual(status, "not_found")

    def test_106_parse_md5_list(self):
        """parse_md5_list normalizes comma-separated MD5s."""
        self.assertEqual(parse_md5_list(""), [])
        self.assertEqual(parse_md5_list("ABC123"), ["abc123"])
        self.assertEqual(parse_md5_list("abc, DEF , ghi"), ["abc", "def", "ghi"])
        self.assertEqual(parse_md5_list(",,,"), [])

    def test_107filter_files_by_mode(self):
        """filter_files_by_mode filters standalone/libretro correctly."""
        files = [
            {"name": "a.bin", "mode": "standalone"},
            {"name": "b.bin", "mode": "libretro"},
            {"name": "c.bin", "mode": "both"},
            {"name": "d.bin"},  # no mode
        ]
        # Libretro mode: exclude standalone
        result = filter_files_by_mode(files, standalone=False)
        names = [f["name"] for f in result]
        self.assertNotIn("a.bin", names)
        self.assertIn("b.bin", names)
        self.assertIn("c.bin", names)
        self.assertIn("d.bin", names)

        # Standalone mode: exclude libretro
        result = filter_files_by_mode(files, standalone=True)
        names = [f["name"] for f in result]
        self.assertIn("a.bin", names)
        self.assertNotIn("b.bin", names)
        self.assertIn("c.bin", names)
        self.assertIn("d.bin", names)


    def test_108_standalone_path_in_undeclared(self):
        """Undeclared files use standalone_path when core is in standalone_cores."""
        # Create a platform with standalone_cores
        config = {
            "platform": "TestStandalone",
            "verification_mode": "existence",
            "cores": ["test_emu"],
            "standalone_cores": ["test_emu"],
            "systems": {
                "console-a": {
                    "files": [
                        {"name": "present_req.bin", "destination": "present_req.bin",
                         "required": True},
                    ],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "test_standalone.yml"), "w") as fh:
            yaml.dump(config, fh)

        # Create emulator with standalone_path divergence
        emu = {
            "emulator": "TestStandaloneEmu",
            "type": "standalone + libretro",
            "cores": ["test_emu"],
            "systems": ["console-a"],
            "files": [
                {"name": "libretro_file.bin", "path": "subdir/libretro_file.bin",
                 "standalone_path": "flat_file.bin", "required": True},
                {"name": "standalone_only.bin", "mode": "standalone", "required": False},
                {"name": "libretro_only.bin", "mode": "libretro", "required": False},
            ],
        }
        with open(os.path.join(self.emulators_dir, "test_standalone_emu.yml"), "w") as fh:
            yaml.dump(emu, fh)

        config = load_platform_config("test_standalone", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        by_name = {u["name"]: u for u in undeclared}

        # standalone_path used for undeclared file (core is standalone)
        self.assertIn("libretro_file.bin", by_name)
        self.assertEqual(by_name["libretro_file.bin"]["path"], "flat_file.bin")

        # standalone-only file IS included (core is standalone)
        self.assertIn("standalone_only.bin", by_name)

        # libretro-only file is EXCLUDED (core is standalone)
        self.assertNotIn("libretro_only.bin", by_name)

    def test_109_no_standalone_cores_uses_libretro_path(self):
        """Without standalone_cores, undeclared files use path: (libretro)."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        # standalone_only.bin should be excluded (platform has no standalone_cores)
        names = {u["name"] for u in undeclared}
        self.assertNotIn("standalone_only.bin", names)

    def test_110_cores_alias_reverse_index(self):
        """resolve_platform_cores matches via cores: field aliases."""
        emu = {
            "emulator": "TestAliasCore",
            "type": "libretro",
            "cores": ["test_alias_core", "shortname"],
            "systems": ["console-a"],
            "files": [],
        }
        with open(os.path.join(self.emulators_dir, "test_alias_core.yml"), "w") as fh:
            yaml.dump(emu, fh)

        config = {"cores": ["shortname"]}
        profiles = load_emulator_profiles(self.emulators_dir)
        resolved = resolve_platform_cores(config, profiles)
        self.assertIn("test_alias_core", resolved)

    # ---------------------------------------------------------------
    # Target config tests (Task 1)
    # ---------------------------------------------------------------

    def _write_target_fixtures(self):
        """Create target config fixtures for testing."""
        targets_dir = os.path.join(self.platforms_dir, "targets")
        os.makedirs(targets_dir, exist_ok=True)
        target_config = {
            "platform": "testplatform",
            "source": "test",
            "scraped_at": "2026-01-01T00:00:00Z",
            "targets": {
                "target-full": {
                    "architecture": "x86_64",
                    "cores": ["core_a", "core_b", "core_c"],
                },
                "target-minimal": {
                    "architecture": "armv7",
                    "cores": ["core_a"],
                },
            },
        }
        with open(os.path.join(targets_dir, "testplatform.yml"), "w") as f:
            yaml.dump(target_config, f)
        single_config = {
            "platform": "singleplatform",
            "source": "test",
            "scraped_at": "2026-01-01T00:00:00Z",
            "targets": {
                "only-target": {
                    "architecture": "x86_64",
                    "cores": ["core_a", "core_b"],
                },
            },
        }
        with open(os.path.join(targets_dir, "singleplatform.yml"), "w") as f:
            yaml.dump(single_config, f)
        overrides = {
            "testplatform": {
                "targets": {
                    "target-full": {
                        "aliases": ["full", "pc", "desktop"],
                        "add_cores": ["core_d"],
                        "remove_cores": ["core_c"],
                    },
                    "target-minimal": {
                        "aliases": ["minimal", "arm"],
                    },
                },
            },
        }
        with open(os.path.join(targets_dir, "_overrides.yml"), "w") as f:
            yaml.dump(overrides, f)

    def test_load_target_config(self):
        self._write_target_fixtures()
        from common import load_target_config
        cores = load_target_config("testplatform", "target-minimal", self.platforms_dir)
        self.assertEqual(cores, {"core_a"})

    def test_target_alias_resolution(self):
        self._write_target_fixtures()
        from common import load_target_config
        cores = load_target_config("testplatform", "full", self.platforms_dir)
        self.assertEqual(cores, {"core_a", "core_b", "core_d"})

    def test_target_unknown_error(self):
        self._write_target_fixtures()
        from common import load_target_config
        with self.assertRaises(ValueError) as ctx:
            load_target_config("testplatform", "nonexistent", self.platforms_dir)
        self.assertIn("target-full", str(ctx.exception))
        self.assertIn("target-minimal", str(ctx.exception))

    def test_target_override_add_remove(self):
        self._write_target_fixtures()
        from common import load_target_config
        cores = load_target_config("testplatform", "full", self.platforms_dir)
        self.assertIn("core_d", cores)
        self.assertNotIn("core_c", cores)
        self.assertIn("core_a", cores)
        self.assertIn("core_b", cores)

    def test_target_single_target_noop(self):
        self._write_target_fixtures()
        from common import load_target_config
        cores = load_target_config("singleplatform", "only-target", self.platforms_dir)
        self.assertEqual(cores, {"core_a", "core_b"})

    def test_target_inherits(self):
        self._write_target_fixtures()
        targets_dir = os.path.join(self.platforms_dir, "targets")
        child_config = {
            "platform": "childplatform",
            "source": "test",
            "scraped_at": "2026-01-01T00:00:00Z",
            "targets": {
                "target-full": {
                    "architecture": "x86_64",
                    "cores": ["core_a"],
                },
            },
        }
        with open(os.path.join(targets_dir, "childplatform.yml"), "w") as f:
            yaml.dump(child_config, f)
        from common import load_target_config
        parent = load_target_config("testplatform", "target-minimal", self.platforms_dir)
        child = load_target_config("childplatform", "target-full", self.platforms_dir)
        self.assertEqual(parent, {"core_a"})
        self.assertEqual(child, {"core_a"})
        self.assertNotEqual(
            load_target_config("testplatform", "full", self.platforms_dir),
            child,
        )

    # ---------------------------------------------------------------
    # Target filtering in resolve_platform_cores (Task 2)
    # ---------------------------------------------------------------

    def test_target_core_intersection(self):
        self._write_target_fixtures()
        profiles = {
            "core_a": {"type": "libretro", "systems": ["sys1"]},
            "core_b": {"type": "libretro", "systems": ["sys1"]},
            "core_c": {"type": "libretro", "systems": ["sys2"]},
            "core_d": {"type": "libretro", "systems": ["sys2"]},
        }
        config = {"cores": "all_libretro"}
        result = resolve_platform_cores(config, profiles)
        self.assertEqual(result, {"core_a", "core_b", "core_c", "core_d"})
        result = resolve_platform_cores(config, profiles, target_cores={"core_a", "core_b"})
        self.assertEqual(result, {"core_a", "core_b"})

    def test_target_none_no_filter(self):
        profiles = {
            "core_a": {"type": "libretro", "systems": ["sys1"]},
            "core_b": {"type": "libretro", "systems": ["sys1"]},
        }
        config = {"cores": "all_libretro"}
        result = resolve_platform_cores(config, profiles, target_cores=None)
        self.assertEqual(result, {"core_a", "core_b"})

    def test_verify_target_filtered(self):
        """Verify with target_cores only reports files from filtered cores."""
        self._write_target_fixtures()
        core_a_path = os.path.join(self.emulators_dir, "core_a.yml")
        core_b_path = os.path.join(self.emulators_dir, "core_b.yml")
        with open(core_a_path, "w") as f:
            yaml.dump({
                "emulator": "CoreA", "type": "libretro", "systems": ["sys1"],
                "files": [{"name": "bios_a.bin", "required": True}],
            }, f)
        with open(core_b_path, "w") as f:
            yaml.dump({
                "emulator": "CoreB", "type": "libretro", "systems": ["sys1"],
                "files": [{"name": "bios_b.bin", "required": True}],
            }, f)

        config = {"cores": "all_libretro", "systems": {"sys1": {"files": []}}}
        profiles = load_emulator_profiles(self.emulators_dir)

        # Without target: both cores' files are undeclared
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        names = {u["name"] for u in undeclared}
        self.assertIn("bios_a.bin", names)
        self.assertIn("bios_b.bin", names)

        # With target filtering to core_a only
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles,
            target_cores={"core_a"},
        )
        names = {u["name"] for u in undeclared}
        self.assertIn("bios_a.bin", names)
        self.assertNotIn("bios_b.bin", names)


    # ---------------------------------------------------------------
    # Validation index per-emulator ground truth (Task: ground truth)
    # ---------------------------------------------------------------

    def test_111_validation_index_per_emulator(self):
        """Validation index includes per-emulator detail for ground truth."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = _build_validation_index(profiles)
        entry = index["present_req.bin"]
        self.assertIn("per_emulator", entry)
        pe = entry["per_emulator"]
        self.assertIn("test_validation", pe)
        detail = pe["test_validation"]
        self.assertIn("size", detail["checks"])
        self.assertEqual(detail["expected"]["size"], 16)

    def test_112_build_ground_truth(self):
        """build_ground_truth returns per-emulator detail for a filename."""
        from common import build_ground_truth
        profiles = load_emulator_profiles(self.emulators_dir)
        index = _build_validation_index(profiles)
        gt = build_ground_truth("present_req.bin", index)
        self.assertIsInstance(gt, list)
        self.assertTrue(len(gt) >= 1)
        emu_names = {g["emulator"] for g in gt}
        self.assertIn("test_validation", emu_names)
        for g in gt:
            if g["emulator"] == "test_validation":
                self.assertIn("size", g["checks"])
                self.assertIn("source_ref", g)
                self.assertIn("expected", g)

    def test_113_build_ground_truth_empty(self):
        """build_ground_truth returns [] for unknown filename."""
        from common import build_ground_truth
        profiles = load_emulator_profiles(self.emulators_dir)
        index = _build_validation_index(profiles)
        gt = build_ground_truth("nonexistent.bin", index)
        self.assertEqual(gt, [])

    def test_114_platform_result_has_ground_truth(self):
        """verify_platform attaches ground_truth to each detail entry."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        result = verify_platform(config, self.db, self.emulators_dir, profiles)
        for d in result["details"]:
            self.assertIn("ground_truth", d)
        # present_req.bin has validation in test_validation profile
        for d in result["details"]:
            if d["name"] == "present_req.bin":
                self.assertTrue(len(d["ground_truth"]) >= 1)
                emu_names = {g["emulator"] for g in d["ground_truth"]}
                self.assertIn("test_validation", emu_names)
                break
        else:
            self.fail("present_req.bin not found in details")

    def test_116_undeclared_files_have_ground_truth(self):
        """find_undeclared_files attaches ground truth fields."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        for u in undeclared:
            self.assertIn("checks", u)
            self.assertIn("source_ref", u)
            self.assertIn("expected", u)

    def test_117_platform_result_ground_truth_coverage(self):
        """verify_platform includes ground truth coverage counts."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        result = verify_platform(config, self.db, self.emulators_dir, profiles)
        gt = result["ground_truth_coverage"]
        self.assertIn("with_validation", gt)
        self.assertIn("total", gt)
        self.assertIn("platform_only", gt)
        self.assertEqual(gt["total"], result["total_files"])
        self.assertEqual(gt["platform_only"], gt["total"] - gt["with_validation"])
        self.assertGreaterEqual(gt["with_validation"], 1)

    def test_118_emulator_result_has_ground_truth(self):
        """verify_emulator attaches ground_truth to each detail entry."""
        result = verify_emulator(["test_validation"], self.emulators_dir, self.db)
        for d in result["details"]:
            self.assertIn("ground_truth", d)
        # present_req.bin should have ground truth from test_validation
        for d in result["details"]:
            if d["name"] == "present_req.bin":
                self.assertTrue(len(d["ground_truth"]) >= 1)
                break

    def test_119_emulator_result_ground_truth_coverage(self):
        """verify_emulator includes ground truth coverage counts."""
        result = verify_emulator(["test_validation"], self.emulators_dir, self.db)
        gt = result["ground_truth_coverage"]
        self.assertEqual(gt["total"], result["total_files"])

    def test_115_platform_result_ground_truth_empty_for_unknown(self):
        """Files with no emulator validation get ground_truth=[]."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        result = verify_platform(config, self.db, self.emulators_dir, profiles)
        for d in result["details"]:
            if d["name"] == "missing_opt.bin":
                self.assertEqual(d["ground_truth"], [])
                break


    def test_120_format_ground_truth_aggregate(self):
        """Aggregate format: one line with all cores."""
        from verify import _format_ground_truth_aggregate
        gt = [
            {"emulator": "beetle_psx", "checks": ["md5"], "source_ref": "libretro.cpp:252", "expected": {"md5": "abc"}},
            {"emulator": "pcsx_rearmed", "checks": ["existence"], "source_ref": None, "expected": {}},
        ]
        line = _format_ground_truth_aggregate(gt)
        self.assertIn("beetle_psx", line)
        self.assertIn("[md5]", line)
        self.assertIn("pcsx_rearmed", line)
        self.assertIn("[existence]", line)

    def test_121_format_ground_truth_verbose(self):
        """Verbose format: one line per core with expected values and source ref."""
        from verify import _format_ground_truth_verbose
        gt = [
            {"emulator": "handy", "checks": ["size", "crc32"],
             "source_ref": "rom.h:48-49", "expected": {"size": 512, "crc32": "0d973c9d"}},
        ]
        lines = _format_ground_truth_verbose(gt)
        self.assertEqual(len(lines), 1)
        self.assertIn("handy", lines[0])
        self.assertIn("size=512", lines[0])
        self.assertIn("crc32=0d973c9d", lines[0])
        self.assertIn("[rom.h:48-49]", lines[0])

    def test_122_format_ground_truth_verbose_no_source_ref(self):
        """Verbose format omits bracket when source_ref is None."""
        from verify import _format_ground_truth_verbose
        gt = [
            {"emulator": "core_a", "checks": ["existence"], "source_ref": None, "expected": {}},
        ]
        lines = _format_ground_truth_verbose(gt)
        self.assertEqual(len(lines), 1)
        self.assertNotIn("[", lines[0])

    def test_123_ground_truth_full_chain_verbose(self):
        """Full chain: file -> platform -> emulator -> source_ref visible in ground_truth."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        result = verify_platform(config, self.db, self.emulators_dir, profiles)
        for d in result["details"]:
            if d["name"] == "present_req.bin":
                gt = d["ground_truth"]
                for g in gt:
                    if g["emulator"] == "test_validation":
                        self.assertIn("size", g["checks"])
                        self.assertEqual(g["source_ref"], "test.c:10-20")
                        self.assertEqual(g["expected"]["size"], 16)
                        return
        self.fail("present_req.bin / test_validation ground truth not found")

    def test_124_ground_truth_json_includes_all(self):
        """JSON output includes ground_truth on all detail entries."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        result = verify_platform(config, self.db, self.emulators_dir, profiles)
        # Simulate --json filtering (non-OK only) — ground_truth must survive
        filtered = [d for d in result["details"] if d["status"] != Status.OK]
        for d in filtered:
            self.assertIn("ground_truth", d)
        # Also check OK entries have it (before filtering)
        ok_entries = [d for d in result["details"] if d["status"] == Status.OK]
        for d in ok_entries:
            self.assertIn("ground_truth", d)

    def test_125_ground_truth_coverage_in_md5_mode(self):
        """MD5 platform also gets ground truth coverage."""
        config = load_platform_config("test_md5", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        result = verify_platform(config, self.db, self.emulators_dir, profiles)
        gt = result["ground_truth_coverage"]
        self.assertEqual(gt["total"], result["total_files"])
        self.assertGreaterEqual(gt["with_validation"], 1)

    def test_130_required_only_excludes_optional(self):
        """--required-only excludes files with required: false from pack."""
        from generate_pack import generate_pack
        output_dir = os.path.join(self.root, "pack_reqonly")
        os.makedirs(output_dir, exist_ok=True)
        # Create a platform with one required and one optional file
        config = {
            "platform": "ReqOnlyTest",
            "verification_mode": "existence",
            "base_destination": "system",
            "systems": {
                "test-sys": {
                    "files": [
                        {"name": "present_req.bin", "destination": "present_req.bin", "required": True},
                        {"name": "present_opt.bin", "destination": "present_opt.bin", "required": False},
                    ],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "test_reqonly.yml"), "w") as fh:
            yaml.dump(config, fh)
        zip_path = generate_pack(
            "test_reqonly", self.platforms_dir, self.db, self.bios_dir, output_dir,
            required_only=True,
        )
        self.assertIsNotNone(zip_path)
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
        self.assertTrue(any("present_req.bin" in n for n in names))
        self.assertFalse(any("present_opt.bin" in n for n in names))
        # Verify _Required tag in filename
        self.assertIn("_Required_", os.path.basename(zip_path))

    def test_131_required_only_keeps_default_required(self):
        """--required-only keeps files with no required field (default = required)."""
        from generate_pack import generate_pack
        output_dir = os.path.join(self.root, "pack_reqdef")
        os.makedirs(output_dir, exist_ok=True)
        # File with no required field
        config = {
            "platform": "ReqDefTest",
            "verification_mode": "existence",
            "base_destination": "system",
            "systems": {
                "test-sys": {
                    "files": [
                        {"name": "present_req.bin", "destination": "present_req.bin"},
                    ],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "test_reqdef.yml"), "w") as fh:
            yaml.dump(config, fh)
        zip_path = generate_pack(
            "test_reqdef", self.platforms_dir, self.db, self.bios_dir, output_dir,
            required_only=True,
        )
        self.assertIsNotNone(zip_path)
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
        self.assertTrue(any("present_req.bin" in n for n in names))


    def test_132_platform_system_filter(self):
        """--platform + --system filters systems within a platform pack."""
        from generate_pack import generate_pack
        output_dir = os.path.join(self.root, "pack_sysfilter")
        os.makedirs(output_dir, exist_ok=True)
        config = {
            "platform": "SysFilterTest",
            "verification_mode": "existence",
            "base_destination": "system",
            "systems": {
                "system-a": {
                    "files": [
                        {"name": "present_req.bin", "destination": "present_req.bin"},
                    ],
                },
                "system-b": {
                    "files": [
                        {"name": "present_opt.bin", "destination": "present_opt.bin"},
                    ],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "test_sysfilter.yml"), "w") as fh:
            yaml.dump(config, fh)
        zip_path = generate_pack(
            "test_sysfilter", self.platforms_dir, self.db, self.bios_dir, output_dir,
            system_filter=["system-a"],
        )
        self.assertIsNotNone(zip_path)
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
        self.assertTrue(any("present_req.bin" in n for n in names))
        self.assertFalse(any("present_opt.bin" in n for n in names))

    def test_133_platform_system_filter_normalized(self):
        """_norm_system_id normalization matches with manufacturer prefix."""
        from common import _norm_system_id
        self.assertEqual(
            _norm_system_id("sony-playstation"),
            _norm_system_id("playstation"),
        )

    def test_134_list_systems_platform_context(self):
        """list_platform_system_ids lists systems from a platform YAML."""
        from common import list_platform_system_ids
        import io
        config = {
            "platform": "ListSysTest",
            "verification_mode": "existence",
            "systems": {
                "alpha-sys": {
                    "files": [
                        {"name": "a.bin", "destination": "a.bin"},
                    ],
                },
                "beta-sys": {
                    "files": [
                        {"name": "b1.bin", "destination": "b1.bin"},
                        {"name": "b2.bin", "destination": "b2.bin"},
                    ],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "test_listsys.yml"), "w") as fh:
            yaml.dump(config, fh)
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            list_platform_system_ids("test_listsys", self.platforms_dir)
        finally:
            sys.stdout = old_stdout
        output = captured.getvalue()
        self.assertIn("alpha-sys", output)
        self.assertIn("beta-sys", output)
        self.assertIn("1 file", output)
        self.assertIn("2 files", output)


    def test_135_split_by_system(self):
        """--split generates one ZIP per system in a subdirectory."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            plat_dir = os.path.join(tmpdir, "platforms")
            os.makedirs(plat_dir)
            bios_dir = os.path.join(tmpdir, "bios", "Test")
            os.makedirs(os.path.join(bios_dir, "SysA"))
            os.makedirs(os.path.join(bios_dir, "SysB"))
            emu_dir = os.path.join(tmpdir, "emulators")
            os.makedirs(emu_dir)
            out_dir = os.path.join(tmpdir, "dist")

            file_a = os.path.join(bios_dir, "SysA", "bios_a.bin")
            file_b = os.path.join(bios_dir, "SysB", "bios_b.bin")
            with open(file_a, "wb") as f:
                f.write(b"system_a")
            with open(file_b, "wb") as f:
                f.write(b"system_b")

            from common import compute_hashes
            ha = compute_hashes(file_a)
            hb = compute_hashes(file_b)

            db = {
                "files": {
                    ha["sha1"]: {"name": "bios_a.bin", "md5": ha["md5"],
                                 "sha1": ha["sha1"], "sha256": ha["sha256"],
                                 "path": file_a,
                                 "paths": [file_a]},
                    hb["sha1"]: {"name": "bios_b.bin", "md5": hb["md5"],
                                 "sha1": hb["sha1"], "sha256": hb["sha256"],
                                 "path": file_b,
                                 "paths": [file_b]},
                },
                "indexes": {
                    "by_md5": {ha["md5"]: ha["sha1"], hb["md5"]: hb["sha1"]},
                    "by_name": {"bios_a.bin": [ha["sha1"]], "bios_b.bin": [hb["sha1"]]},
                    "by_crc32": {}, "by_path_suffix": {},
                },
            }

            registry = {"platforms": {"splitplat": {"status": "active"}}}
            with open(os.path.join(plat_dir, "_registry.yml"), "w") as f:
                yaml.dump(registry, f)
            plat_cfg = {
                "platform": "SplitTest",
                "verification_mode": "existence",
                "systems": {
                    "test-system-a": {"files": [{"name": "bios_a.bin", "sha1": ha["sha1"]}]},
                    "test-system-b": {"files": [{"name": "bios_b.bin", "sha1": hb["sha1"]}]},
                },
            }
            with open(os.path.join(plat_dir, "splitplat.yml"), "w") as f:
                yaml.dump(plat_cfg, f)

            from generate_pack import generate_split_packs
            from common import build_zip_contents_index, load_emulator_profiles
            zip_contents = build_zip_contents_index(db)
            emu_profiles = load_emulator_profiles(emu_dir)

            zip_paths = generate_split_packs(
                "splitplat", plat_dir, db, os.path.join(tmpdir, "bios"), out_dir,
                emulators_dir=emu_dir, zip_contents=zip_contents,
                emu_profiles=emu_profiles, group_by="system",
            )
            self.assertEqual(len(zip_paths), 2)

            # Check subdirectory exists
            split_dir = os.path.join(out_dir, "SplitTest_Split")
            self.assertTrue(os.path.isdir(split_dir))

            # Verify each ZIP contains only its system's files
            for zp in zip_paths:
                with zipfile.ZipFile(zp) as zf:
                    names = zf.namelist()
                basename = os.path.basename(zp)
                if "System_A" in basename:
                    self.assertIn("bios_a.bin", names)
                    self.assertNotIn("bios_b.bin", names)
                elif "System_B" in basename:
                    self.assertIn("bios_b.bin", names)
                    self.assertNotIn("bios_a.bin", names)


    def test_136_derive_manufacturer(self):
        """derive_manufacturer extracts manufacturer correctly."""
        from common import derive_manufacturer
        # From system ID prefix
        self.assertEqual(derive_manufacturer("sony-playstation", {}), "Sony")
        self.assertEqual(derive_manufacturer("nintendo-snes", {}), "Nintendo")
        self.assertEqual(derive_manufacturer("sega-saturn", {}), "Sega")
        self.assertEqual(derive_manufacturer("atari-5200", {}), "Atari")
        # From explicit manufacturer field
        self.assertEqual(
            derive_manufacturer("3do", {"manufacturer": "Panasonic|GoldStar"}),
            "Panasonic",
        )
        # Various = skip to prefix check, then Other
        self.assertEqual(derive_manufacturer("arcade", {"manufacturer": "Various"}), "Other")
        # Fallback
        self.assertEqual(derive_manufacturer("dos", {}), "Other")

    def test_137_group_systems_by_manufacturer(self):
        """_group_systems_by_manufacturer groups correctly."""
        from generate_pack import _group_systems_by_manufacturer
        systems = {
            "sony-playstation": {"files": [{"name": "a.bin"}]},
            "sony-psp": {"files": [{"name": "b.bin"}]},
            "nintendo-snes": {"files": [{"name": "c.bin"}]},
            "arcade": {"manufacturer": "Various", "files": [{"name": "d.bin"}]},
        }
        groups = _group_systems_by_manufacturer(systems, {}, "")
        self.assertIn("Sony", groups)
        self.assertEqual(sorted(groups["Sony"]), ["sony-playstation", "sony-psp"])
        self.assertIn("Nintendo", groups)
        self.assertEqual(groups["Nintendo"], ["nintendo-snes"])
        self.assertIn("Other", groups)
        self.assertEqual(groups["Other"], ["arcade"])


    def test_138_parse_hash_input(self):
        """parse_hash_input handles various formats."""
        from generate_pack import parse_hash_input
        # Plain MD5
        result = parse_hash_input("d8f1206299c48946e6ec5ef96d014eaa")
        self.assertEqual(result, [("md5", "d8f1206299c48946e6ec5ef96d014eaa")])
        # Comma-separated
        result = parse_hash_input("d8f1206299c48946e6ec5ef96d014eaa,d8f1206299c48946e6ec5ef96d014eab")
        self.assertEqual(len(result), 2)
        # SHA1
        sha1 = "a" * 40
        result = parse_hash_input(sha1)
        self.assertEqual(result, [("sha1", sha1)])
        # CRC32
        result = parse_hash_input("abcd1234")
        self.assertEqual(result, [("crc32", "abcd1234")])

    def test_139_parse_hash_file(self):
        """parse_hash_file handles comments, empty lines, various formats."""
        from generate_pack import parse_hash_file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# PS1 BIOS files\n")
            f.write("\n")
            f.write("d8f1206299c48946e6ec5ef96d014eaa\n")
            f.write("d8f1206299c48946e6ec5ef96d014eab  scph5501.bin\n")
            f.write("scph5502.bin  d8f1206299c48946e6ec5ef96d014eac  OK\n")
            tmp_path = f.name
        try:
            result = parse_hash_file(tmp_path)
            self.assertEqual(len(result), 3)
            self.assertTrue(all(t == "md5" for t, _ in result))
        finally:
            os.unlink(tmp_path)

    def test_140_lookup_hashes_found(self):
        """lookup_hashes returns file info for known hashes."""
        import io
        import contextlib
        from generate_pack import lookup_hashes
        db = {
            "files": {
                "sha1abc": {
                    "name": "test.bin", "md5": "md5abc",
                    "sha1": "sha1abc", "sha256": "sha256abc",
                    "paths": ["Mfr/Console/test.bin"],
                    "aliases": ["alt.bin"],
                },
            },
            "indexes": {
                "by_md5": {"md5abc": "sha1abc"},
                "by_crc32": {},
            },
        }
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            lookup_hashes([("md5", "md5abc")], db, "bios", "emulators", "platforms")
        output = buf.getvalue()
        self.assertIn("test.bin", output)
        self.assertIn("sha1abc", output)
        self.assertIn("alt.bin", output)

    def test_141_lookup_hashes_not_found(self):
        """lookup_hashes reports unknown hashes."""
        import io
        import contextlib
        from generate_pack import lookup_hashes
        db = {"files": {}, "indexes": {"by_md5": {}, "by_crc32": {}}}
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            lookup_hashes([("md5", "unknown123" + "0" * 22)], db, "bios", "emulators", "platforms")
        output = buf.getvalue()
        self.assertIn("NOT FOUND", output)


    def test_142_from_md5_platform_pack(self):
        """--from-md5 with --platform generates correctly laid out ZIP."""
        import tempfile
        import json
        import zipfile
        import yaml
        with tempfile.TemporaryDirectory() as tmpdir:
            plat_dir = os.path.join(tmpdir, "platforms")
            os.makedirs(plat_dir)
            bios_dir = os.path.join(tmpdir, "bios", "Sony", "PS1")
            os.makedirs(bios_dir)
            emu_dir = os.path.join(tmpdir, "emulators")
            os.makedirs(emu_dir)
            out_dir = os.path.join(tmpdir, "dist")

            bios_file = os.path.join(bios_dir, "scph5501.bin")
            with open(bios_file, "wb") as f:
                f.write(b"ps1_bios_content")
            from common import compute_hashes
            h = compute_hashes(bios_file)

            db = {
                "files": {
                    h["sha1"]: {
                        "name": "scph5501.bin", "md5": h["md5"],
                        "sha1": h["sha1"], "sha256": h["sha256"],
                        "path": bios_file,
                        "paths": ["Sony/PS1/scph5501.bin"],
                    },
                },
                "indexes": {
                    "by_md5": {h["md5"]: h["sha1"]},
                    "by_name": {"scph5501.bin": [h["sha1"]]},
                    "by_crc32": {}, "by_path_suffix": {},
                },
            }

            registry = {"platforms": {"testplat": {"status": "active"}}}
            with open(os.path.join(plat_dir, "_registry.yml"), "w") as f:
                yaml.dump(registry, f)
            plat_cfg = {
                "platform": "TestPlat",
                "verification_mode": "md5",
                "base_destination": "bios",
                "systems": {
                    "sony-playstation": {
                        "files": [
                            {"name": "scph5501.bin", "md5": h["md5"],
                             "destination": "scph5501.bin"},
                        ]
                    }
                },
            }
            with open(os.path.join(plat_dir, "testplat.yml"), "w") as f:
                yaml.dump(plat_cfg, f)

            from generate_pack import generate_md5_pack
            from common import build_zip_contents_index
            zip_contents = build_zip_contents_index(db)

            zip_path = generate_md5_pack(
                hashes=[("md5", h["md5"])],
                db=db, bios_dir=bios_dir, output_dir=out_dir,
                zip_contents=zip_contents,
                platform_name="testplat", platforms_dir=plat_dir,
            )
            self.assertIsNotNone(zip_path)
            with zipfile.ZipFile(zip_path) as zf:
                names = zf.namelist()
            self.assertIn("bios/scph5501.bin", names)
            self.assertIn("Custom", os.path.basename(zip_path))

    def test_143_from_md5_not_in_repo(self):
        """--from-md5 reports files in DB but missing from repo."""
        import tempfile
        import io
        import contextlib
        from generate_pack import generate_md5_pack

        db = {
            "files": {
                "sha1known": {
                    "name": "missing.bin", "md5": "md5known" + "0" * 25,
                    "sha1": "sha1known", "sha256": "sha256known",
                    "path": "/nonexistent/missing.bin",
                    "paths": ["Test/missing.bin"],
                },
            },
            "indexes": {
                "by_md5": {"md5known" + "0" * 25: "sha1known"},
                "by_crc32": {},
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = os.path.join(tmpdir, "dist")
            bios_dir = os.path.join(tmpdir, "bios")
            os.makedirs(bios_dir)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                result = generate_md5_pack(
                    hashes=[("md5", "md5known" + "0" * 25)],
                    db=db, bios_dir=bios_dir, output_dir=out_dir,
                    zip_contents={},
                )
            output = buf.getvalue()
            self.assertIn("NOT IN REPO", output)
            self.assertIsNone(result)


    def test_144_invalid_split_emulator(self):
        """--split + --emulator is rejected."""
        import subprocess
        result = subprocess.run(
            ["python", "scripts/generate_pack.py", "--emulator", "test", "--split"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error", result.stderr.lower())

    def test_145_invalid_from_md5_all(self):
        """--from-md5 + --all is rejected."""
        import subprocess
        result = subprocess.run(
            ["python", "scripts/generate_pack.py", "--all", "--from-md5", "abc123" + "0" * 26],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_146_invalid_from_md5_system(self):
        """--from-md5 + --system is rejected."""
        import subprocess
        result = subprocess.run(
            ["python", "scripts/generate_pack.py", "--system", "psx", "--from-md5", "abc123" + "0" * 26],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_147_invalid_group_by_without_split(self):
        """--group-by without --split is rejected."""
        import subprocess
        result = subprocess.run(
            ["python", "scripts/generate_pack.py", "--platform", "retroarch", "--group-by", "manufacturer"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_148_valid_platform_system(self):
        """--platform + --system is accepted (not rejected at validation stage)."""
        import argparse
        sys.path.insert(0, "scripts")
        # Build the same parser as generate_pack.main()
        parser = argparse.ArgumentParser()
        parser.add_argument("--platform", "-p")
        parser.add_argument("--all", action="store_true")
        parser.add_argument("--emulator", "-e")
        parser.add_argument("--system", "-s")
        parser.add_argument("--standalone", action="store_true")
        parser.add_argument("--split", action="store_true")
        parser.add_argument("--group-by", choices=["system", "manufacturer"], default="system")
        parser.add_argument("--target", "-t")
        parser.add_argument("--from-md5")
        parser.add_argument("--from-md5-file")
        parser.add_argument("--required-only", action="store_true")
        args = parser.parse_args(["--platform", "retroarch", "--system", "psx"])

        # Replicate validation logic from main()
        has_platform = bool(args.platform)
        has_all = args.all
        has_emulator = bool(args.emulator)
        has_system = bool(args.system)
        has_from_md5 = bool(args.from_md5 or args.from_md5_file)

        # These should NOT raise
        self.assertFalse(has_emulator and (has_platform or has_all or has_system))
        self.assertFalse(has_platform and has_all)
        self.assertTrue(has_platform or has_all or has_emulator or has_system or has_from_md5)
        # --platform + --system is a valid combination
        self.assertTrue(has_platform and has_system)

    # ── BizHawk scraper tests ──────────────────────────────────────

    def test_150_bizhawk_scraper_parse_firmware_and_option(self):
        """Parse FirmwareAndOption() one-liner pattern."""
        from scraper.bizhawk_scraper import parse_firmware_database
        fragment = '''
            FirmwareAndOption("DBEBD76A448447CB6E524AC3CB0FD19FC065D944", 256, "32X", "G", "32X_G_BIOS.BIN", "32x 68k BIOS");
            FirmwareAndOption("1E5B0B2441A4979B6966D942B20CC76C413B8C5E", 2048, "32X", "M", "32X_M_BIOS.BIN", "32x SH2 MASTER BIOS");
        '''
        records, files = parse_firmware_database(fragment)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["system"], "32X")
        self.assertEqual(records[0]["firmware_id"], "G")
        self.assertEqual(records[0]["sha1"], "DBEBD76A448447CB6E524AC3CB0FD19FC065D944")
        self.assertEqual(records[0]["name"], "32X_G_BIOS.BIN")
        self.assertEqual(records[0]["size"], 256)

    def test_151_bizhawk_scraper_parse_variable_refs(self):
        """Parse var = File() + Firmware() + Option() pattern."""
        from scraper.bizhawk_scraper import parse_firmware_database
        fragment = '''
            var gbaNormal = File("300C20DF6731A33952DED8C436F7F186D25D3492", 16384, "GBA_bios.rom", "Bios (World)");
            Firmware("GBA", "Bios", "Bios");
            Option("GBA", "Bios", in gbaNormal, FirmwareOptionStatus.Ideal);
        '''
        records, files = parse_firmware_database(fragment)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["system"], "GBA")
        self.assertEqual(records[0]["sha1"], "300C20DF6731A33952DED8C436F7F186D25D3492")
        self.assertEqual(records[0]["name"], "GBA_bios.rom")
        self.assertEqual(records[0]["status"], "Ideal")

    def test_152_bizhawk_scraper_skips_comments(self):
        """Commented-out blocks (PS2) are skipped."""
        from scraper.bizhawk_scraper import parse_firmware_database
        fragment = '''
            FirmwareAndOption("DBEBD76A448447CB6E524AC3CB0FD19FC065D944", 256, "32X", "G", "32X_G_BIOS.BIN", "32x 68k BIOS");
            /*
            Firmware("PS2", "BIOS", "PS2 Bios");
            Option("PS2", "BIOS", File("FBD54BFC020AF34008B317DCB80B812DD29B3759", 4194304, "ps2.bin", "PS2 Bios"));
            */
        '''
        records, files = parse_firmware_database(fragment)
        systems = {r["system"] for r in records}
        self.assertNotIn("PS2", systems)
        self.assertEqual(len(records), 1)

    def test_153_bizhawk_scraper_arithmetic_size(self):
        """Size expressions like 4 * 1024 * 1024 are evaluated."""
        from scraper.bizhawk_scraper import parse_firmware_database
        fragment = '''
            FirmwareAndOption("BF861922DCB78C316360E3E742F4F70FF63C9BC3", 4 * 1024 * 1024, "N64DD", "IPL_JPN", "64DD_IPL.bin", "N64DD JPN IPL");
        '''
        records, _ = parse_firmware_database(fragment)
        self.assertEqual(records[0]["size"], 4194304)

    def test_154_bizhawk_scraper_dummy_hash(self):
        """SHA1Checksum.Dummy entries get no sha1 field."""
        from scraper.bizhawk_scraper import parse_firmware_database
        fragment = '''
            FirmwareAndOption(SHA1Checksum.Dummy, 0, "3DS", "aes_keys", "aes_keys.txt", "AES Keys");
        '''
        records, _ = parse_firmware_database(fragment)
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0]["sha1"])

    def test_155_bizhawk_scraper_multi_option_picks_ideal(self):
        """When multiple options exist, Ideal is selected as canonical."""
        from scraper.bizhawk_scraper import parse_firmware_database
        fragment = '''
            var ss_100_j = File("2B8CB4F87580683EB4D760E4ED210813D667F0A2", 524288, "SAT_1.00-(J).bin", "Bios v1.00 (J)");
            var ss_101_j = File("DF94C5B4D47EB3CC404D88B33A8FDA237EAF4720", 524288, "SAT_1.01-(J).bin", "Bios v1.01 (J)");
            Firmware("SAT", "J", "Bios (J)");
            Option("SAT", "J", in ss_100_j);
            Option("SAT", "J", in ss_101_j, FirmwareOptionStatus.Ideal);
        '''
        records, _ = parse_firmware_database(fragment)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["sha1"], "DF94C5B4D47EB3CC404D88B33A8FDA237EAF4720")
        self.assertEqual(records[0]["name"], "SAT_1.01-(J).bin")

    def test_156_bizhawk_scraper_is_bad_excluded(self):
        """Files with isBad: true are not selected as canonical."""
        from scraper.bizhawk_scraper import parse_firmware_database
        fragment = '''
            var good = File("AAAA", 100, "good.bin", "Good");
            var bad = File("BBBB", 100, "bad.bin", "Bad", isBad: true);
            Firmware("TEST", "X", "Test");
            Option("TEST", "X", in bad);
            Option("TEST", "X", in good, FirmwareOptionStatus.Ideal);
        '''
        records, _ = parse_firmware_database(fragment)
        self.assertEqual(records[0]["name"], "good.bin")

    def test_157_path_conflict_helpers(self):
        """_has_path_conflict detects file/directory naming collisions."""
        from generate_pack import _has_path_conflict, _register_path

        seen_files: set[str] = set()
        seen_parents: set[str] = set()

        # Register system/SGB1.sfc as a file
        _register_path("system/SGB1.sfc", seen_files, seen_parents)

        # Adding system/SGB1.sfc/program.rom should conflict (parent is a file)
        self.assertTrue(_has_path_conflict("system/SGB1.sfc/program.rom",
                                           seen_files, seen_parents))

        # Adding system/other.bin should not conflict
        self.assertFalse(_has_path_conflict("system/other.bin",
                                            seen_files, seen_parents))

        # Reverse: register a nested path first, then check flat
        seen_files2: set[str] = set()
        seen_parents2: set[str] = set()
        _register_path("system/SGB2.sfc/program.rom", seen_files2, seen_parents2)

        # Adding system/SGB2.sfc as a file should conflict (it's a directory)
        self.assertTrue(_has_path_conflict("system/SGB2.sfc",
                                           seen_files2, seen_parents2))

        # Adding system/SGB2.sfc/boot.rom should not conflict (sibling in same dir)
        self.assertFalse(_has_path_conflict("system/SGB2.sfc/boot.rom",
                                            seen_files2, seen_parents2))

    def test_158_pack_skips_file_directory_conflict(self):
        """Pack generation skips entries that conflict with existing paths."""
        from generate_pack import generate_pack

        output_dir = os.path.join(self.root, "pack_conflict")
        os.makedirs(output_dir, exist_ok=True)

        # Platform declares SGB1.sfc as a flat file
        config = {
            "platform": "ConflictTest",
            "verification_mode": "existence",
            "base_destination": "system",
            "systems": {
                "test-sys": {
                    "files": [
                        {"name": "present_req.bin", "destination": "present_req.bin",
                         "required": True},
                    ],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "test_conflict.yml"), "w") as fh:
            yaml.dump(config, fh)

        # Create an emulator profile with a nested path that conflicts
        emu = {
            "emulator": "ConflictCore",
            "type": "libretro",
            "systems": ["test-sys"],
            "files": [
                {"name": "present_req.bin/nested.rom", "required": False},
            ],
        }
        with open(os.path.join(self.emulators_dir, "conflict_core.yml"), "w") as fh:
            yaml.dump(emu, fh)

        zip_path = generate_pack(
            "test_conflict", self.platforms_dir, self.db, self.bios_dir,
            output_dir, emulators_dir=self.emulators_dir,
        )
        self.assertIsNotNone(zip_path)
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
        # Flat file should be present
        self.assertTrue(any("present_req.bin" in n and "/" + "nested" not in n
                            for n in names))
        # Nested conflict should NOT be present
        self.assertFalse(any("nested.rom" in n for n in names))


    # ---------------------------------------------------------------
    # Archive cross-reference and descriptive name tests
    # ---------------------------------------------------------------

    def test_159_cross_ref_archive_in_repo(self):
        """Archived files group by archive; in_repo=True when archive exists."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        # test_archive.zip should appear as a single grouped entry
        archive_entries = [u for u in undeclared if u.get("archive") == "test_archive.zip"]
        self.assertEqual(len(archive_entries), 1)
        entry = archive_entries[0]
        self.assertTrue(entry["in_repo"])
        self.assertEqual(entry["name"], "test_archive.zip")
        self.assertEqual(entry["archive_file_count"], 2)
        self.assertTrue(entry["required"])  # at least one file is required

    def test_160_cross_ref_archive_missing(self):
        """Missing archive reported as single entry with in_repo=False."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        missing_entries = [u for u in undeclared if u.get("archive") == "missing_archive.zip"]
        self.assertEqual(len(missing_entries), 1)
        entry = missing_entries[0]
        self.assertFalse(entry["in_repo"])
        self.assertEqual(entry["name"], "missing_archive.zip")
        self.assertEqual(entry["archive_file_count"], 1)

    def test_161_cross_ref_archive_not_individual_roms(self):
        """Individual ROM names from archived files should NOT appear as separate entries."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        names = {u["name"] for u in undeclared}
        # Individual ROMs should NOT be in the undeclared list
        self.assertNotIn("rom_a.bin", names)
        self.assertNotIn("rom_b.bin", names)
        self.assertNotIn("missing_rom.bin", names)

    def test_162_cross_ref_descriptive_name_resolved_by_path(self):
        """Descriptive name with path: fallback resolves via path basename."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        desc_entries = {u["name"]: u for u in undeclared
                        if u["emulator"] == "TestDescriptive"}
        # "Descriptive BIOS Name" has path: "present_req.bin" which IS in by_name
        self.assertIn("Descriptive BIOS Name", desc_entries)
        self.assertTrue(desc_entries["Descriptive BIOS Name"]["in_repo"])
        # "Missing Descriptive" has path: "nonexistent_path.bin" which is NOT in by_name
        self.assertIn("Missing Descriptive", desc_entries)
        self.assertFalse(desc_entries["Missing Descriptive"]["in_repo"])

    def test_163_cross_ref_archive_declared_by_platform_skipped(self):
        """Archive files whose archive is declared by platform are skipped."""
        # Create a platform that declares test_archive.zip
        config = {
            "platform": "TestArchivePlatform",
            "verification_mode": "existence",
            "systems": {
                "console-a": {
                    "files": [
                        {"name": "test_archive.zip", "destination": "test_archive.zip",
                         "required": True},
                    ],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "test_archive_platform.yml"), "w") as fh:
            yaml.dump(config, fh)
        config = load_platform_config("test_archive_platform", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db, profiles)
        # test_archive.zip is declared → its archived ROMs should be skipped
        archive_entries = [u for u in undeclared if u.get("archive") == "test_archive.zip"]
        self.assertEqual(len(archive_entries), 0)

    def test_164_pack_extras_use_archive_name(self):
        """Pack extras for archived files use archive name, not individual ROM."""
        from generate_pack import _collect_emulator_extras
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        extras = _collect_emulator_extras(
            config, self.emulators_dir, self.db,
            set(), "", profiles,
        )
        extra_names = {e["name"] for e in extras}
        # Archive name should be present, not individual ROMs
        self.assertIn("test_archive.zip", extra_names)
        self.assertNotIn("rom_a.bin", extra_names)
        self.assertNotIn("rom_b.bin", extra_names)
        # Missing archive should NOT be in extras (in_repo=False)
        self.assertNotIn("missing_archive.zip", extra_names)


    def test_165_pack_extras_multi_dest_cross_ref(self):
        """Same file at different paths from two profiles produces both destinations."""
        from generate_pack import _collect_emulator_extras
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        extras = _collect_emulator_extras(
            config, self.emulators_dir, self.db,
            set(), "", profiles,
        )
        extra_dests = {e["destination"] for e in extras}
        # Root destination (from test_emu or test_root_core, no path)
        self.assertIn("present_req.bin", extra_dests)
        # Subdirectory destination (from test_subdir_core)
        self.assertIn("subcore/bios/present_req.bin", extra_dests)

    def test_166_pack_extras_multi_dest_platform_declared(self):
        """Profile with path different from platform destination adds alternative."""
        from generate_pack import _collect_emulator_extras
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        # Simulate platform already having present_req.bin at root
        seen = {"present_req.bin"}
        extras = _collect_emulator_extras(
            config, self.emulators_dir, self.db,
            seen, "", profiles,
        )
        extra_dests = {e["destination"] for e in extras}
        # Root is already in pack (in seen), should NOT be duplicated
        self.assertNotIn("present_req.bin", extra_dests)
        # Subdirectory destination should be added
        self.assertIn("subcore/bios/present_req.bin", extra_dests)

    def test_167_resolve_local_file_data_dir_fallback(self):
        """resolve_local_file finds files in data directories when not in bios/."""
        data_dir = os.path.join(self.root, "data", "test-data")
        os.makedirs(data_dir, exist_ok=True)
        data_file = os.path.join(data_dir, "data_only.bin")
        with open(data_file, "wb") as f:
            f.write(b"DATA_DIR_CONTENT")

        registry = {"test-data": {"local_cache": data_dir}}

        fe = {"name": "data_only.bin"}
        path, status = resolve_local_file(fe, self.db, data_dir_registry=registry)
        self.assertIsNotNone(path)
        self.assertEqual(os.path.basename(path), "data_only.bin")
        self.assertEqual(status, "data_dir")

    def test_168_generate_truth_basic(self):
        """generate_platform_truth resolves cores and builds system truth."""
        import yaml as _yaml

        profile = {
            "emulator": "TestCore",
            "type": "libretro",
            "systems": ["test-system"],
            "cores": ["testcore"],
            "files": [
                {
                    "name": "bios.bin",
                    "system": "test-system",
                    "required": True,
                    "sha1": "aabbccdd" * 5,
                    "md5": "11223344" * 4,
                    "size": 1024,
                    "path": "TestConsole/bios.bin",
                    "source_ref": "main.cpp:42",
                },
            ],
        }
        profile_path = os.path.join(self.emulators_dir, "testcore.yml")
        with open(profile_path, "w") as f:
            _yaml.dump(profile, f)

        # Clear profile cache so fresh load picks up our file
        from common import _emulator_profiles_cache
        _emulator_profiles_cache.clear()

        profiles = load_emulator_profiles(self.emulators_dir)
        registry = {
            "testplat": {
                "cores": ["testcore"],
            },
        }

        result = generate_platform_truth(
            "testplat", registry, profiles, db=None,
        )

        self.assertEqual(result["platform"], "testplat")
        self.assertTrue(result["generated"])
        self.assertIn("test-system", result["systems"])
        sys_files = result["systems"]["test-system"]["files"]
        self.assertEqual(len(sys_files), 1)
        fe = sys_files[0]
        self.assertEqual(fe["name"], "bios.bin")
        self.assertTrue(fe["required"])
        self.assertEqual(fe["sha1"], "aabbccdd" * 5)
        self.assertIn("testcore", fe["_cores"])
        self.assertIn("main.cpp:42", fe["_source_refs"])

    def test_169_generate_truth_mode_filtering(self):
        """generate_platform_truth excludes standalone-only files for all_libretro."""
        import yaml as _yaml
        from common import _emulator_profiles_cache

        profile = {
            "emulator": "DualMode",
            "type": "standalone + libretro",
            "systems": ["test-system"],
            "cores": ["dualmode"],
            "files": [
                {"name": "both.bin", "system": "test-system", "required": True,
                 "mode": "both"},
                {"name": "lr_only.bin", "system": "test-system", "required": True,
                 "mode": "libretro"},
                {"name": "sa_only.bin", "system": "test-system", "required": True,
                 "mode": "standalone"},
                {"name": "nomode.bin", "system": "test-system", "required": True},
            ],
        }
        with open(os.path.join(self.emulators_dir, "dualmode.yml"), "w") as f:
            _yaml.dump(profile, f)

        _emulator_profiles_cache.clear()
        profiles = load_emulator_profiles(self.emulators_dir)
        registry = {"testplat": {"cores": "all_libretro"}}

        result = generate_platform_truth("testplat", registry, profiles)
        names = {fe["name"] for fe in result["systems"]["test-system"]["files"]}

        self.assertIn("both.bin", names)
        self.assertIn("lr_only.bin", names)
        self.assertIn("nomode.bin", names)
        self.assertNotIn("sa_only.bin", names)

    def test_170_generate_truth_standalone_cores(self):
        """generate_platform_truth uses standalone mode for standalone_cores."""
        import yaml as _yaml
        from common import _emulator_profiles_cache

        profile = {
            "emulator": "DualCore",
            "type": "standalone + libretro",
            "systems": ["test-system"],
            "cores": ["dualcore"],
            "files": [
                {"name": "lr_file.bin", "system": "test-system", "required": True,
                 "mode": "libretro"},
                {"name": "sa_file.bin", "system": "test-system", "required": True,
                 "mode": "standalone"},
            ],
        }
        with open(os.path.join(self.emulators_dir, "dualcore.yml"), "w") as f:
            _yaml.dump(profile, f)

        _emulator_profiles_cache.clear()
        profiles = load_emulator_profiles(self.emulators_dir)
        registry = {
            "testplat": {
                "cores": ["dualcore"],
                "standalone_cores": ["dualcore"],
            },
        }

        result = generate_platform_truth("testplat", registry, profiles)
        names = {fe["name"] for fe in result["systems"]["test-system"]["files"]}

        self.assertIn("sa_file.bin", names)
        self.assertNotIn("lr_file.bin", names)

    def test_171_generate_truth_dedup_required_wins(self):
        """Dedup merges cores; required=True wins over required=False."""
        import yaml as _yaml
        from common import _emulator_profiles_cache

        core_a = {
            "emulator": "CoreA",
            "type": "libretro",
            "systems": ["test-system"],
            "cores": ["core_a"],
            "files": [
                {"name": "shared.bin", "system": "test-system",
                 "required": False, "source_ref": "a.cpp:10"},
            ],
        }
        core_b = {
            "emulator": "CoreB",
            "type": "libretro",
            "systems": ["test-system"],
            "cores": ["core_b"],
            "files": [
                {"name": "shared.bin", "system": "test-system",
                 "required": True, "source_ref": "b.cpp:20"},
            ],
        }
        for name, data in [("core_a", core_a), ("core_b", core_b)]:
            with open(os.path.join(self.emulators_dir, f"{name}.yml"), "w") as f:
                _yaml.dump(data, f)

        _emulator_profiles_cache.clear()
        profiles = load_emulator_profiles(self.emulators_dir)
        registry = {"testplat": {"cores": ["core_a", "core_b"]}}

        result = generate_platform_truth("testplat", registry, profiles)
        sys_files = result["systems"]["test-system"]["files"]
        self.assertEqual(len(sys_files), 1)

        fe = sys_files[0]
        self.assertEqual(fe["name"], "shared.bin")
        self.assertTrue(fe["required"])
        self.assertIn("core_a", fe["_cores"])
        self.assertIn("core_b", fe["_cores"])
        self.assertIn("a.cpp:10", fe["_source_refs"])
        self.assertIn("b.cpp:20", fe["_source_refs"])

    def test_172_generate_truth_coverage_metadata(self):
        """Coverage tracks profiled vs unprofiled cores."""
        import yaml as _yaml
        from common import _emulator_profiles_cache

        profile = {
            "emulator": "ProfiledCore",
            "type": "libretro",
            "systems": ["test-system"],
            "cores": ["profiled_core"],
            "files": [
                {"name": "fw.bin", "system": "test-system", "required": True},
            ],
        }
        with open(os.path.join(self.emulators_dir, "profiled_core.yml"), "w") as f:
            _yaml.dump(profile, f)

        _emulator_profiles_cache.clear()
        profiles = load_emulator_profiles(self.emulators_dir)
        registry = {"testplat": {"cores": ["profiled_core", "unprofiled_core"]}}

        result = generate_platform_truth("testplat", registry, profiles)
        cov = result["_coverage"]

        self.assertEqual(cov["cores_profiled"], 1)
        self.assertNotIn("unprofiled_core", [
            name for name in profiles if name == "unprofiled_core"
        ])
        # unprofiled_core has no profile YAML so resolve_platform_cores
        # won't include it; cores_resolved reflects only matched profiles
        self.assertEqual(cov["cores_resolved"], 1)
        self.assertNotIn("unprofiled_core", cov["cores_unprofiled"])

    def test_90_registry_install_metadata(self):
        """Registry install section is accessible."""
        import yaml
        with open("platforms/_registry.yml") as f:
            registry = yaml.safe_load(f)
        for name in ("retroarch", "batocera", "emudeck", "recalbox",
                      "retrobat", "retrodeck", "lakka", "romm", "bizhawk"):
            plat = registry["platforms"][name]
            self.assertIn("install", plat, f"{name} missing install section")
            self.assertIn("detect", plat["install"])
            self.assertIsInstance(plat["install"]["detect"], list)
            for hint in plat["install"]["detect"]:
                self.assertIn("os", hint)
        # EmuDeck has standalone_copies
        self.assertIn(
            "standalone_copies", registry["platforms"]["emudeck"]["install"],
        )

    def test_91_generate_manifest(self):
        """generate_manifest returns valid manifest dict with expected fields."""
        from generate_pack import generate_manifest

        # Create a minimal registry file for the test
        registry_path = os.path.join(self.platforms_dir, "_test_registry.yml")
        registry_data = {
            "platforms": {
                "test_existence": {
                    "install": {
                        "detect": [{"os": "linux", "method": "path_exists",
                                    "path": "/test/bios"}],
                    },
                },
            },
        }
        with open(registry_path, "w") as fh:
            yaml.dump(registry_data, fh)

        manifest = generate_manifest(
            "test_existence", self.platforms_dir, self.db, self.bios_dir,
            registry_path, emulators_dir=self.emulators_dir,
        )

        self.assertEqual(manifest["manifest_version"], 1)
        self.assertEqual(manifest["platform"], "test_existence")
        self.assertEqual(manifest["display_name"], "TestExistence")
        self.assertIn("generated", manifest)
        self.assertIn("files", manifest)
        self.assertIsInstance(manifest["files"], list)
        self.assertEqual(manifest["total_files"], len(manifest["files"]))
        self.assertGreater(len(manifest["files"]), 0)
        self.assertEqual(manifest["base_destination"], "system")
        self.assertEqual(manifest["detect"], registry_data["platforms"]["test_existence"]["install"]["detect"])

        for f in manifest["files"]:
            self.assertIn("dest", f)
            self.assertIn("sha1", f)
            self.assertIn("size", f)
            self.assertIn("repo_path", f)
            self.assertIn("cores", f)
            self.assertIsInstance(f["size"], int)
            self.assertGreater(len(f["sha1"]), 0)

    def test_92_manifest_matches_zip(self):
        """Manifest file destinations match ZIP contents (excluding metadata)."""
        from generate_pack import generate_manifest, generate_pack

        registry_path = os.path.join(self.platforms_dir, "_test_registry.yml")
        registry_data = {
            "platforms": {
                "test_existence": {
                    "install": {"detect": []},
                },
            },
        }
        with open(registry_path, "w") as fh:
            yaml.dump(registry_data, fh)

        # Generate ZIP
        output_dir = os.path.join(self.root, "pack_manifest_cmp")
        os.makedirs(output_dir, exist_ok=True)
        zip_path = generate_pack(
            "test_existence", self.platforms_dir, self.db, self.bios_dir,
            output_dir, emulators_dir=self.emulators_dir,
        )
        self.assertIsNotNone(zip_path)

        # Get ZIP file destinations (exclude metadata)
        with zipfile.ZipFile(zip_path) as zf:
            zip_names = {
                n for n in zf.namelist()
                if not n.startswith("INSTRUCTIONS_")
                and n != "manifest.json"
                and n != "README.txt"
            }

        # Generate manifest
        manifest = generate_manifest(
            "test_existence", self.platforms_dir, self.db, self.bios_dir,
            registry_path, emulators_dir=self.emulators_dir,
        )
        base = manifest.get("base_destination", "")
        manifest_dests = set()
        for f in manifest["files"]:
            d = f"{base}/{f['dest']}" if base else f["dest"]
            manifest_dests.add(d)

        self.assertEqual(manifest_dests, zip_names)


    # ---------------------------------------------------------------
    # install.py tests
    # ---------------------------------------------------------------

    def test_93_parse_retroarch_cfg(self):
        """Parse system_directory from retroarch.cfg."""
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from install import _parse_retroarch_system_dir
        cfg = os.path.join(self.root, "retroarch.cfg")
        # Quoted absolute path
        with open(cfg, "w") as f:
            f.write('system_directory = "/home/user/ra/system"\n')
        result = _parse_retroarch_system_dir(Path(cfg))
        self.assertEqual(result, Path("/home/user/ra/system"))
        # Default value
        with open(cfg, "w") as f:
            f.write('system_directory = "default"\n')
        result = _parse_retroarch_system_dir(Path(cfg))
        self.assertEqual(result, Path(self.root) / "system")
        # Unquoted
        with open(cfg, "w") as f:
            f.write('system_directory = /tmp/ra_system\n')
        result = _parse_retroarch_system_dir(Path(cfg))
        self.assertEqual(result, Path("/tmp/ra_system"))

    def test_94_parse_emudeck_settings(self):
        """Parse emulationPath from EmuDeck settings.sh."""
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from install import _parse_bash_var
        settings = os.path.join(self.root, "settings.sh")
        with open(settings, "w") as f:
            f.write('emulationPath="/home/deck/Emulation"\nromsPath="/home/deck/Emulation/roms"\n')
        result = _parse_bash_var(Path(settings), "emulationPath")
        self.assertEqual(result, "/home/deck/Emulation")

    def test_95_parse_ps1_var(self):
        """Parse $emulationPath from EmuDeck settings.ps1."""
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from install import _parse_ps1_var
        settings = os.path.join(self.root, "settings.ps1")
        with open(settings, "w") as f:
            f.write('$emulationPath="C:\\Emulation"\n')
        result = _parse_ps1_var(Path(settings), "$emulationPath")
        self.assertEqual(result, "C:\\Emulation")

    def test_96_target_filtering(self):
        """--target filters files by cores field."""
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from install import _filter_by_target
        files = [
            {"dest": "a.bin", "cores": None},
            {"dest": "b.bin", "cores": ["flycast", "redream"]},
            {"dest": "c.bin", "cores": ["dolphin"]},
        ]
        filtered = _filter_by_target(files, ["flycast", "snes9x"])
        dests = [f["dest"] for f in filtered]
        self.assertIn("a.bin", dests)
        self.assertIn("b.bin", dests)
        self.assertNotIn("c.bin", dests)

    def test_97_standalone_copies(self):
        """Standalone keys copied to existing emulator dirs."""
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from install import do_standalone_copies
        bios_dir = Path(self.root) / "bios"
        bios_dir.mkdir(exist_ok=True)
        (bios_dir / "prod.keys").write_bytes(b"KEYS")
        yuzu_dir = Path(self.root) / "yuzu_keys"
        yuzu_dir.mkdir()
        missing_dir = Path(self.root) / "nonexistent"
        manifest = {
            "base_destination": "bios",
            "standalone_copies": [{"file": "prod.keys", "targets": {"linux": [str(yuzu_dir), str(missing_dir)]}}]
        }
        copied, skipped = do_standalone_copies(manifest, bios_dir, "linux")
        self.assertEqual(copied, 1)
        self.assertEqual(skipped, 1)
        self.assertTrue((yuzu_dir / "prod.keys").exists())
        self.assertFalse((missing_dir / "prod.keys").exists())


    # ---------------------------------------------------------------
    # diff_platform_truth tests
    # ---------------------------------------------------------------

    def test_98_diff_truth_missing(self):
        """Truth has 2 files, scraped has 1 -> 1 missing with cores/source_refs."""
        truth = {"systems": {"test-sys": {
            "_coverage": {"cores_profiled": ["core_a"], "cores_unprofiled": []},
            "files": [
                {"name": "bios_a.bin", "required": True, "md5": "aaa",
                 "_cores": ["core_a"], "_source_refs": ["src/a.c:10"]},
                {"name": "bios_b.bin", "required": False, "md5": "bbb",
                 "_cores": ["core_a"], "_source_refs": ["src/b.c:20"]},
            ],
        }}}
        scraped = {"systems": {"test-sys": {
            "files": [{"name": "bios_a.bin", "md5": "aaa"}],
        }}}
        result = diff_platform_truth(truth, scraped)
        self.assertEqual(result["summary"]["total_missing"], 1)
        div = result["divergences"]["test-sys"]
        self.assertEqual(len(div["missing"]), 1)
        m = div["missing"][0]
        self.assertEqual(m["name"], "bios_b.bin")
        self.assertEqual(m["cores"], ["core_a"])
        self.assertEqual(m["source_refs"], ["src/b.c:20"])

    def test_99_diff_truth_extra_phantom(self):
        """All cores profiled, scraped has extra file -> extra_phantom."""
        truth = {"systems": {"test-sys": {
            "_coverage": {"cores_profiled": ["core_a"], "cores_unprofiled": []},
            "files": [
                {"name": "bios.bin", "md5": "aaa",
                 "_cores": ["core_a"], "_source_refs": []},
            ],
        }}}
        scraped = {"systems": {"test-sys": {
            "files": [
                {"name": "bios.bin", "md5": "aaa"},
                {"name": "phantom.bin", "md5": "zzz"},
            ],
        }}}
        result = diff_platform_truth(truth, scraped)
        self.assertEqual(result["summary"]["total_extra_phantom"], 1)
        div = result["divergences"]["test-sys"]
        self.assertEqual(len(div["extra_phantom"]), 1)
        self.assertEqual(div["extra_phantom"][0]["name"], "phantom.bin")

    def test_100_diff_truth_extra_unprofiled(self):
        """Some cores unprofiled, scraped has extra -> extra_unprofiled."""
        truth = {"systems": {"test-sys": {
            "_coverage": {"cores_profiled": ["core_a"],
                          "cores_unprofiled": ["core_b"]},
            "files": [
                {"name": "bios.bin", "md5": "aaa",
                 "_cores": ["core_a"], "_source_refs": []},
            ],
        }}}
        scraped = {"systems": {"test-sys": {
            "files": [
                {"name": "bios.bin", "md5": "aaa"},
                {"name": "extra.bin", "md5": "yyy"},
            ],
        }}}
        result = diff_platform_truth(truth, scraped)
        self.assertEqual(result["summary"]["total_extra_unprofiled"], 1)
        div = result["divergences"]["test-sys"]
        self.assertEqual(len(div["extra_unprofiled"]), 1)
        self.assertEqual(div["extra_unprofiled"][0]["name"], "extra.bin")

    def test_101_diff_truth_alias_matching(self):
        """Truth file with aliases, scraped uses alias -> not extra or missing."""
        truth = {"systems": {"test-sys": {
            "_coverage": {"cores_profiled": ["core_a"], "cores_unprofiled": []},
            "files": [
                {"name": "bios.bin", "md5": "aaa", "aliases": ["alt.bin"],
                 "_cores": ["core_a"], "_source_refs": []},
            ],
        }}}
        scraped = {"systems": {"test-sys": {
            "files": [{"name": "alt.bin", "md5": "aaa"}],
        }}}
        result = diff_platform_truth(truth, scraped)
        self.assertEqual(result["summary"]["total_missing"], 0)
        self.assertEqual(result["summary"]["total_extra_phantom"], 0)
        self.assertNotIn("test-sys", result.get("divergences", {}))

    def test_102_diff_truth_case_insensitive(self):
        """Truth 'BIOS.ROM', scraped 'bios.rom' -> match, no missing."""
        truth = {"systems": {"test-sys": {
            "_coverage": {"cores_profiled": ["core_a"], "cores_unprofiled": []},
            "files": [
                {"name": "BIOS.ROM", "md5": "aaa",
                 "_cores": ["core_a"], "_source_refs": []},
            ],
        }}}
        scraped = {"systems": {"test-sys": {
            "files": [{"name": "bios.rom", "md5": "aaa"}],
        }}}
        result = diff_platform_truth(truth, scraped)
        self.assertEqual(result["summary"]["total_missing"], 0)
        self.assertNotIn("test-sys", result.get("divergences", {}))

    def test_103_diff_truth_hash_mismatch(self):
        """Same file, different md5 -> hash_mismatch with truth_cores."""
        truth = {"systems": {"test-sys": {
            "_coverage": {"cores_profiled": ["core_a"], "cores_unprofiled": []},
            "files": [
                {"name": "bios.bin", "md5": "truth_hash",
                 "_cores": ["core_a", "core_b"],
                 "_source_refs": ["src/x.c:5"]},
            ],
        }}}
        scraped = {"systems": {"test-sys": {
            "files": [{"name": "bios.bin", "md5": "scraped_hash"}],
        }}}
        result = diff_platform_truth(truth, scraped)
        self.assertEqual(result["summary"]["total_hash_mismatch"], 1)
        div = result["divergences"]["test-sys"]
        self.assertEqual(len(div["hash_mismatch"]), 1)
        hm = div["hash_mismatch"][0]
        self.assertEqual(hm["name"], "bios.bin")
        self.assertEqual(hm["truth_cores"], ["core_a", "core_b"])
        self.assertEqual(hm["truth_md5"], "truth_hash")
        self.assertEqual(hm["scraped_md5"], "scraped_hash")


    # ---------------------------------------------------------------
    # native_id preservation
    # ---------------------------------------------------------------

    def test_native_id_preserved_in_platform_config(self):
        """load_platform_config preserves native_id at the system level."""
        config = {
            "platform": "TestNativeId",
            "verification_mode": "existence",
            "base_destination": "system",
            "systems": {
                "sony-playstation": {
                    "native_id": "Sony - PlayStation",
                    "files": [
                        {"name": "scph5501.bin", "destination": "scph5501.bin", "required": True},
                    ],
                },
                "nintendo-snes": {
                    "native_id": "snes",
                    "files": [
                        {"name": "bs-x.bin", "destination": "bs-x.bin", "required": False},
                    ],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "test_native_id.yml"), "w") as fh:
            yaml.dump(config, fh)

        loaded = load_platform_config("test_native_id", self.platforms_dir)
        psx = loaded["systems"]["sony-playstation"]
        self.assertEqual(psx["native_id"], "Sony - PlayStation")
        snes = loaded["systems"]["nintendo-snes"]
        self.assertEqual(snes["native_id"], "snes")


    # ---------------------------------------------------------------
    # Exporter: System.dat round-trip
    # ---------------------------------------------------------------

    def test_systemdat_exporter_round_trip(self):
        """Export truth data to System.dat and validate round-trip."""
        from exporter import discover_exporters
        from exporter.systemdat_exporter import Exporter as SystemDatExporter

        truth = {
            "platform": "retroarch",
            "systems": {
                "sony-playstation": {
                    "files": [
                        {
                            "name": "scph5501.bin",
                            "path": "scph5501.bin",
                            "size": 524288,
                            "md5": "490f666e1afb15ed6c63b88fc7571f2f",
                            "sha1": "b056ee5a4d65937e1a3a17e1e78f3258ea49c38e",
                            "crc32": "71af80b4",
                            "required": True,
                            "_cores": ["beetle_psx"],
                            "_source_refs": ["libretro.c:50"],
                        },
                    ],
                },
            },
        }
        scraped = {
            "systems": {
                "sony-playstation": {
                    "native_id": "Sony - PlayStation",
                    "files": [
                        {"name": "scph5501.bin", "destination": "scph5501.bin"},
                    ],
                },
            },
        }

        out_path = os.path.join(self.root, "System.dat")
        exporter = SystemDatExporter()
        exporter.export(truth, out_path, scraped_data=scraped)

        with open(out_path) as fh:
            content = fh.read()
        self.assertIn("Sony - PlayStation", content)
        self.assertIn("scph5501.bin", content)
        self.assertIn("b056ee5a4d65937e1a3a17e1e78f3258ea49c38e", content)
        self.assertIn('name "System.dat"', content)

        issues = exporter.validate(truth, out_path)
        self.assertEqual(issues, [])

        # Discovery finds the systemdat exporter
        exporters = discover_exporters()
        self.assertIn("retroarch", exporters)
        self.assertIs(exporters["retroarch"], SystemDatExporter)


if __name__ == "__main__":
    unittest.main()
