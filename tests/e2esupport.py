"""Shared synthetic scenario of the end-to-end suites: BIOS files, database, platforms and profiles."""

from __future__ import annotations

import tests
import hashlib
import os
import shutil
import tempfile
import unittest
import zipfile
import yaml


def _h(data: bytes) -> dict:
    """Return sha1, md5, crc32 for test data."""
    return {
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "crc32": format(hashlib.new("crc32", data).digest()[0], "08x")
        if False
        else "",  # not needed for tests
    }


class E2EFixture(unittest.TestCase):
    """One synthetic repository exercising every code path, rebuilt for each test."""

    # ---------------------------------------------------------------
    # Fixture setup
    # ---------------------------------------------------------------

    def setUp(self):
        # Clear emulator profile cache to avoid stale data between tests
        from model.profiles import emulator_profiles_cache

        emulator_profiles_cache.clear()

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
        self._make_file(
            "leading_zero_crc.bin", b"LEADING_ZERO_CRC_12"
        )  # crc32=0179e92e

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
        self._make_zip(
            "test_archive.zip",
            {
                "rom_a.bin": b"ARCHIVE_ROM_A",
                "rom_b.bin": b"ARCHIVE_ROM_B",
            },
        )

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
            "path": path,
            "data": data,
            **h,
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
        by_name: dict[str, list[str]] = {}
        for key, info in self.files.items():
            name = os.path.basename(key)
            sha1 = info["sha1"]
            files_db[sha1] = {
                "path": info["path"],
                "md5": info["md5"],
                "name": name,
                "crc32": info.get("crc32", ""),
                "size": len(info["data"]),
            }
            by_md5[info["md5"]] = sha1
            by_name.setdefault(name, []).append(sha1)
        # Add alias name to by_name
        alias_sha1 = self.files["alias_target.bin"]["sha1"]
        by_name.setdefault("alias_alt.bin", []).append(alias_sha1)
        # Build by_path_suffix for regional variant resolution
        by_path_suffix: dict[str, list[str]] = {}
        for key, info in self.files.items():
            if "/" in key:
                # key is subdir/name, suffix is the subdir path
                by_path_suffix.setdefault(key, []).append(info["sha1"])
        return {
            "files": files_db,
            "indexes": {
                "by_md5": by_md5,
                "by_name": by_name,
                "by_crc32": {},
                "by_path_suffix": by_path_suffix,
            },
        }

    # ---------------------------------------------------------------
    # Platform YAML creators
    # ---------------------------------------------------------------

    def _create_existence_platform(self):
        config = {
            "platform": "TestExistence",
            "version": "9.1",
            "verification_mode": "existence",
            "base_destination": "system",
            "systems": {
                "console-a": {
                    "files": [
                        {
                            "name": "present_req.bin",
                            "destination": "present_req.bin",
                            "required": True,
                        },
                        {
                            "name": "missing_req.bin",
                            "destination": "missing_req.bin",
                            "required": True,
                        },
                        {
                            "name": "present_opt.bin",
                            "destination": "present_opt.bin",
                            "required": False,
                        },
                        {
                            "name": "missing_opt.bin",
                            "destination": "missing_opt.bin",
                            "required": False,
                        },
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
        composite_md5 = hashlib.md5(
            b"AAAA" + b"BBBB"
        ).hexdigest()  # sorted: a.rom, b.rom
        multi_wrong = "0000000000000000000000000000000"
        multi_right = f["multi.zip"]["inner_md5s"]["rom.bin"]
        truncated_md5 = f["truncated.bin"]["md5"][:29]  # shorter than 32 characters

        config = {
            "platform": "TestMD5",
            "verification_mode": "md5",
            "systems": {
                "sys-md5": {
                    "includes": ["test_shared"],
                    "files": [
                        # Correct hash
                        {
                            "name": "correct_hash.bin",
                            "destination": "correct_hash.bin",
                            "md5": f["correct_hash.bin"]["md5"],
                            "required": True,
                        },
                        # Wrong hash on disk ->untested
                        {
                            "name": "wrong_hash.bin",
                            "destination": "wrong_hash.bin",
                            "md5": "ffffffffffffffffffffffffffffffff",
                            "required": True,
                        },
                        # No MD5 ->OK (existence within md5 platform)
                        {
                            "name": "no_md5.bin",
                            "destination": "no_md5.bin",
                            "required": False,
                        },
                        # Missing required
                        {
                            "name": "gone_req.bin",
                            "destination": "gone_req.bin",
                            "md5": "abcd",
                            "required": True,
                        },
                        # Missing optional
                        {
                            "name": "gone_opt.bin",
                            "destination": "gone_opt.bin",
                            "md5": "abcd",
                            "required": False,
                        },
                        # zipped_file correct
                        {
                            "name": "good.zip",
                            "destination": "good.zip",
                            "md5": good_inner_md5,
                            "zipped_file": "inner.rom",
                            "required": True,
                        },
                        # zipped_file wrong inner
                        {
                            "name": "bad_inner.zip",
                            "destination": "bad_inner.zip",
                            "md5": bad_inner_md5,
                            "zipped_file": "inner.rom",
                            "required": False,
                        },
                        # zipped_file inner not found
                        {
                            "name": "missing_inner.zip",
                            "destination": "missing_inner.zip",
                            "md5": "abc",
                            "zipped_file": "nope.rom",
                            "required": False,
                        },
                        # md5_composite (Recalbox)
                        {
                            "name": "composite.zip",
                            "destination": "composite.zip",
                            "md5": composite_md5,
                            "required": True,
                        },
                        # Multi-hash comma-separated (Recalbox)
                        {
                            "name": "multi.zip",
                            "destination": "multi.zip",
                            "md5": f"{multi_wrong},{multi_right}",
                            "zipped_file": "rom.bin",
                            "required": True,
                        },
                        # MD5 shorter than 32 characters
                        {
                            "name": "truncated.bin",
                            "destination": "truncated.bin",
                            "md5": truncated_md5,
                            "required": True,
                        },
                        # Same destination from different entry ->worst status wins
                        {
                            "name": "correct_hash.bin",
                            "destination": "dedup_target.bin",
                            "md5": f["correct_hash.bin"]["md5"],
                            "required": True,
                        },
                        {
                            "name": "correct_hash.bin",
                            "destination": "dedup_target.bin",
                            "md5": "wrong_for_dedup_test",
                            "required": True,
                        },
                    ],
                    "data_directories": [
                        {"ref": "test-data-dir", "destination": "TestData"},
                    ],
                },
                "sys-renamed": {
                    "files": [
                        {
                            "name": "renamed_file.bin",
                            "destination": "renamed_file.bin",
                            "md5": f["correct_hash.bin"]["md5"],
                            "required": True,
                        },
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
                    {
                        "name": "shared_file.rom",
                        "destination": "shared_file.rom",
                        "required": False,
                    },
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
                        {
                            "name": "correct_hash.bin",
                            "destination": "correct_hash.bin",
                            "sha1": f["correct_hash.bin"]["sha1"],
                            "required": True,
                        },
                        {
                            "name": "wrong_hash.bin",
                            "destination": "wrong_hash.bin",
                            "sha1": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "required": True,
                        },
                        {
                            "name": "missing_sha1.bin",
                            "destination": "missing_sha1.bin",
                            "sha1": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                            "required": True,
                        },
                        {
                            "name": "optional_missing_sha1.bin",
                            "destination": "optional_missing_sha1.bin",
                            "sha1": "cccccccccccccccccccccccccccccccccccccccc",
                            "required": False,
                        },
                        {
                            "name": "no_md5.bin",
                            "destination": "no_md5.bin",
                            "required": True,
                        },
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
                {
                    "name": "alias_target.bin",
                    "required": False,
                    "aliases": ["alias_alt.bin"],
                },
                {
                    "name": "standalone_only.bin",
                    "required": False,
                    "mode": "standalone",
                },
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
        alias = {
            "emulator": "TestAlias",
            "type": "alias",
            "alias_of": "test_emu",
            "files": [],
        }
        with open(os.path.join(self.emulators_dir, "test_alias.yml"), "w") as fh:
            yaml.dump(alias, fh)

        # Emulator with data_dir that matches platform ->gaps suppressed
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
                {
                    "name": "missing_rom.bin",
                    "required": True,
                    "archive": "missing_archive.zip",
                },
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
                {
                    "name": "Descriptive BIOS Name",
                    "required": True,
                    "path": "present_req.bin",
                },
                {
                    "name": "Missing Descriptive",
                    "required": True,
                    "path": "nonexistent_path.bin",
                },
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
                # Size validation: correct size (16 bytes = len(b"PRESENT_REQUIRED"))
                {
                    "name": "present_req.bin",
                    "required": True,
                    "validation": ["size"],
                    "size": 16,
                    "source_ref": "test.c:10-20",
                },
                # Size validation: wrong expected size
                {
                    "name": "present_opt.bin",
                    "required": False,
                    "validation": ["size"],
                    "size": 9999,
                },
                # CRC32 validation: correct crc32
                {
                    "name": "correct_hash.bin",
                    "required": True,
                    "validation": ["crc32"],
                    "crc32": "91d0b1d3",
                    "source_ref": "hash.c:42",
                },
                # CRC32 validation: wrong crc32
                {
                    "name": "no_md5.bin",
                    "required": False,
                    "validation": ["crc32"],
                    "crc32": "deadbeef",
                },
                # CRC32 starting with '0' (regression: lstrip("0x") bug)
                {
                    "name": "leading_zero_crc.bin",
                    "required": True,
                    "validation": ["crc32"],
                    "crc32": "0179e92e",
                },
                # MD5 validation: correct md5
                {
                    "name": "correct_hash.bin",
                    "required": True,
                    "validation": ["md5"],
                    "md5": "4a8db431e3b1a1acacec60e3424c4ce8",
                },
                # SHA1 validation: correct sha1
                {
                    "name": "correct_hash.bin",
                    "required": True,
                    "validation": ["sha1"],
                    "sha1": "a2ab6c95c5bbd191b9e87e8f4e85205a47be5764",
                },
                # MD5 validation: wrong md5
                {
                    "name": "alias_target.bin",
                    "required": False,
                    "validation": ["md5"],
                    "md5": "0000000000000000000000000000dead",
                },
                # Adler32: known_hash_adler32 field
                {
                    "name": "present_req.bin",
                    "required": True,
                    "known_hash_adler32": None,
                },  # placeholder, set below
                # Min/max size range validation
                {
                    "name": "present_req.bin",
                    "required": True,
                    "validation": ["size"],
                    "min_size": 10,
                    "max_size": 100,
                },
                # Signature: crypto check we can't reproduce, but size applies
                {
                    "name": "correct_hash.bin",
                    "required": True,
                    "validation": ["size", "signature"],
                    "size": 17,
                },
            ],
        }
        # Compute the actual adler32 of present_req.bin for the test fixture
        import zlib as _zlib

        with open(self.files["present_req.bin"]["path"], "rb") as _f:
            _data = _f.read()
        _adler = format(_zlib.adler32(_data) & 0xFFFFFFFF, "08x")
        # Set the adler32 entry (the one with known_hash_adler32=None)
        for entry in emu_val["files"]:
            if (
                entry.get("known_hash_adler32") is None
                and "known_hash_adler32" in entry
            ):
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
                {
                    "name": "present_req.bin",
                    "required": True,
                    "path": "subcore/bios/present_req.bin",
                },
            ],
        }
        with open(os.path.join(self.emulators_dir, "test_subdir_core.yml"), "w") as fh:
            yaml.dump(emu_subdir, fh)

        # Emulator whose file is declared by platform under a different name
        # (e.g. gsplus ROM vs Batocera ROM1): hash-based matching should resolve
        emu_renamed = {
            "emulator": "TestRenamed",
            "type": "standalone",
            "systems": ["sys-renamed"],
            "files": [
                {"name": "correct_hash.bin", "required": True},
            ],
        }
        with open(os.path.join(self.emulators_dir, "test_renamed.yml"), "w") as fh:
            yaml.dump(emu_renamed, fh)

        # Agnostic profile (bios_mode: agnostic), skipped by find_undeclared_files
        emu_agnostic = {
            "emulator": "TestAgnostic",
            "type": "standalone",
            "bios_mode": "agnostic",
            "systems": ["console-a"],
            "files": [
                {
                    "name": "correct_hash.bin",
                    "required": True,
                    "min_size": 1,
                    "max_size": 999999,
                },
            ],
        }
        with open(os.path.join(self.emulators_dir, "test_agnostic.yml"), "w") as fh:
            yaml.dump(emu_agnostic, fh)

        # Mixed profile with per-file agnostic
        emu_mixed_agnostic = {
            "emulator": "TestMixedAgnostic",
            "type": "libretro",
            "systems": ["console-a"],
            "files": [
                {"name": "undeclared_req.bin", "required": True},
                {"name": "agnostic_file.bin", "required": True, "agnostic": True},
            ],
        }
        with open(
            os.path.join(self.emulators_dir, "test_mixed_agnostic.yml"), "w"
        ) as fh:
            yaml.dump(emu_mixed_agnostic, fh)
