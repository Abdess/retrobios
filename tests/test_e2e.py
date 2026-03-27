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

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import yaml
from common import (
    _build_validation_index, build_zip_contents_index, check_file_validation,
    check_inside_zip, compute_hashes, filter_files_by_mode,
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

        # -- Build synthetic database --
        self.db = self._build_db()

        # -- Create platform YAMLs --
        self._create_existence_platform()
        self._create_md5_platform()
        self._create_shared_groups()
        self._create_inherited_platform()

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

        # Emulator with validation checks (size, crc32)
        emu_val = {
            "emulator": "TestValidation",
            "type": "libretro",
            "systems": ["console-a", "sys-md5"],
            "files": [
                # Size validation — correct size (16 bytes = len(b"PRESENT_REQUIRED"))
                {"name": "present_req.bin", "required": True,
                 "validation": ["size"], "size": 16},
                # Size validation — wrong expected size
                {"name": "present_opt.bin", "required": False,
                 "validation": ["size"], "size": 9999},
                # CRC32 validation — correct crc32
                {"name": "correct_hash.bin", "required": True,
                 "validation": ["crc32"], "crc32": "91d0b1d3"},
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


if __name__ == "__main__":
    unittest.main()
