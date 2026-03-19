"""Integration tests using synthetic YAML fixtures and real BIOS files.

Tests the full pipeline: load_platform_config -> resolve_local_file ->
verify_platform -> find_undeclared_files -> cross_reference, all with
real file I/O, real hashes, and real ZIP handling.
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
    compute_hashes,
    load_emulator_profiles,
    load_platform_config,
    md5sum,
    resolve_local_file,
)
from verify import (
    Severity,
    Status,
    find_undeclared_files,
    verify_platform,
)
from cross_reference import cross_reference, load_platform_files


# ---------------------------------------------------------------------------
# Helpers to build synthetic BIOS files with known hashes
# ---------------------------------------------------------------------------

def _make_file(directory: str, name: str, content: bytes) -> str:
    path = os.path.join(directory, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(content)
    return path


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def _make_zip(directory: str, zip_name: str, inner_name: str, inner_content: bytes) -> str:
    path = os.path.join(directory, zip_name)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(inner_name, inner_content)
    return path


def _build_db(files_dict: dict, aliases: dict | None = None) -> dict:
    """Build a minimal database.json structure from {sha1: {path, name, md5, size}}."""
    by_md5 = {}
    by_name: dict[str, list[str]] = {}
    by_crc32 = {}

    for sha1, info in files_dict.items():
        md5 = info.get("md5", "")
        name = info.get("name", "")
        crc32 = info.get("crc32", "")
        if md5:
            by_md5[md5] = sha1
        if name:
            by_name.setdefault(name, [])
            if sha1 not in by_name[name]:
                by_name[name].append(sha1)
        if crc32:
            by_crc32[crc32] = sha1

    # Merge alias names into by_name
    if aliases:
        for sha1, alias_list in aliases.items():
            for alias in alias_list:
                aname = alias if isinstance(alias, str) else alias.get("name", "")
                if aname:
                    by_name.setdefault(aname, [])
                    if sha1 not in by_name[aname]:
                        by_name[aname].append(sha1)

    return {
        "files": files_dict,
        "indexes": {
            "by_md5": by_md5,
            "by_name": by_name,
            "by_crc32": by_crc32,
        },
    }


# ---------------------------------------------------------------------------
# Fixture setup shared across integration tests
# ---------------------------------------------------------------------------

class FixtureMixin:
    """Creates all synthetic files and patches YAML fixtures with real hashes."""

    def _setup_fixtures(self):
        self.tmpdir = tempfile.mkdtemp(prefix="retrobios_test_")
        self.bios_dir = os.path.join(self.tmpdir, "bios")
        os.makedirs(self.bios_dir)

        # Fixture directories
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        self.platforms_dir = os.path.join(self.tmpdir, "platforms")
        self.emulators_dir = os.path.join(self.tmpdir, "emulators")
        os.makedirs(self.platforms_dir)
        os.makedirs(self.emulators_dir)

        # -- Synthetic BIOS files with deterministic content --
        self.content_a = b"\x01\x02\x03\x04"  # required_present / correct_hash
        self.content_b = b"\x05\x06\x07\x08"  # optional_present / no_md5_present
        self.content_c = b"\x09\x0a\x0b\x0c"  # wrong_hash (on-disk content differs from expected)
        self.content_inner = b"\x10\x11\x12\x13"  # ZIP inner ROM
        self.content_inner_bad = b"\x20\x21\x22\x23"  # ZIP inner ROM (wrong content)
        self.content_multi = b"\x30\x31\x32\x33"  # multi-hash / truncated

        # Create bios files
        self.path_a = _make_file(self.bios_dir, "required_present.bin", self.content_a)
        self.path_b = _make_file(self.bios_dir, "optional_present.bin", self.content_b)
        self.path_c = _make_file(self.bios_dir, "wrong_hash.bin", self.content_c)
        self.path_no_md5 = _make_file(self.bios_dir, "no_md5_present.bin", self.content_b)
        self.path_correct = _make_file(self.bios_dir, "correct_hash.bin", self.content_a)
        self.path_multi = _make_file(self.bios_dir, "multi_hash.bin", self.content_multi)
        self.path_trunc = _make_file(self.bios_dir, "truncated_md5.bin", self.content_multi)

        # Compute real hashes
        self.hashes_a = compute_hashes(self.path_a)
        self.hashes_b = compute_hashes(self.path_b)
        self.hashes_c = compute_hashes(self.path_c)
        self.hashes_multi = compute_hashes(self.path_multi)

        # ZIP with correct inner ROM
        self.zip_good = _make_zip(self.bios_dir, "test.zip", "inner.rom", self.content_inner)
        self.hashes_zip_good = compute_hashes(self.zip_good)
        self.inner_md5 = _md5(self.content_inner)

        # ZIP with wrong inner ROM
        self.zip_bad = _make_zip(self.bios_dir, "test_bad.zip", "inner.rom", self.content_inner_bad)
        self.hashes_zip_bad = compute_hashes(self.zip_bad)
        self.inner_bad_md5 = _md5(self.content_inner_bad)

        # ZIP for missing-inner test: same as good zip but entry references "not_there.rom"
        self.zip_missing_inner = _make_zip(
            self.bios_dir, "test_missing_inner.zip", "inner.rom", self.content_inner,
        )
        self.hashes_zip_missing_inner = compute_hashes(self.zip_missing_inner)

        # -- Build database --
        files_dict = {}
        for path in [
            self.path_a, self.path_b, self.path_c, self.path_no_md5,
            self.path_correct, self.path_multi, self.path_trunc,
            self.zip_good, self.zip_bad, self.zip_missing_inner,
        ]:
            h = compute_hashes(path)
            files_dict[h["sha1"]] = {
                "path": path,
                "name": os.path.basename(path),
                "md5": h["md5"],
                "crc32": h["crc32"],
                "size": os.path.getsize(path),
            }

        self.db = _build_db(files_dict)

        # -- Write patched YAML fixtures --
        self._write_existence_yaml()
        self._write_md5_yaml()
        self._write_inherit_yaml()
        self._write_shared_yaml()
        self._write_emulator_yamls()

        # Write database.json
        db_path = os.path.join(self.tmpdir, "database.json")
        with open(db_path, "w") as f:
            json.dump(self.db, f)
        self.db_path = db_path

    def _write_existence_yaml(self):
        import yaml
        config = {
            "platform": "TestExistence",
            "verification_mode": "existence",
            "base_destination": "system",
            "systems": {
                "test-system": {
                    "files": [
                        {
                            "name": "required_present.bin",
                            "destination": "required_present.bin",
                            "required": True,
                            "sha1": self.hashes_a["sha1"],
                        },
                        {
                            "name": "required_missing.bin",
                            "destination": "required_missing.bin",
                            "required": True,
                            "sha1": "0" * 40,
                        },
                        {
                            "name": "optional_present.bin",
                            "destination": "optional_present.bin",
                            "required": False,
                            "sha1": self.hashes_b["sha1"],
                        },
                        {
                            "name": "optional_missing.bin",
                            "destination": "optional_missing.bin",
                            "required": False,
                            "sha1": "0" * 40 + "1",
                        },
                    ]
                }
            },
        }
        with open(os.path.join(self.platforms_dir, "test_existence.yml"), "w") as f:
            yaml.dump(config, f, default_flow_style=False)

    def _write_md5_yaml(self):
        import yaml
        wrong_md5 = "a" * 32
        multi_md5 = f"{'f' * 32},{self.hashes_multi['md5']}"
        truncated_md5 = self.hashes_multi["md5"][:29]

        config = {
            "platform": "TestMD5",
            "verification_mode": "md5",
            "base_destination": "bios",
            "systems": {
                "test-system": {
                    "files": [
                        {
                            "name": "correct_hash.bin",
                            "destination": "correct_hash.bin",
                            "required": True,
                            "md5": self.hashes_a["md5"],
                        },
                        {
                            "name": "wrong_hash.bin",
                            "destination": "wrong_hash.bin",
                            "required": True,
                            "md5": wrong_md5,
                        },
                        {
                            "name": "no_md5_present.bin",
                            "destination": "no_md5_present.bin",
                            "required": True,
                        },
                        {
                            "name": "required_missing.bin",
                            "destination": "required_missing.bin",
                            "required": True,
                            "md5": "b" * 32,
                        },
                        {
                            "name": "optional_missing.bin",
                            "destination": "optional_missing.bin",
                            "required": False,
                            "md5": "c" * 32,
                        },
                    ]
                },
                "test-zip-system": {
                    "files": [
                        {
                            "name": "test.zip",
                            "destination": "test.zip",
                            "required": True,
                            "md5": self.inner_md5,
                            "zipped_file": "inner.rom",
                        },
                        {
                            "name": "test_bad.zip",
                            "destination": "test_bad.zip",
                            "required": True,
                            "md5": "e" * 32,
                            "zipped_file": "inner.rom",
                        },
                        {
                            "name": "test_missing_inner.zip",
                            "destination": "test_missing_inner.zip",
                            "required": True,
                            "md5": self.inner_md5,
                            "zipped_file": "not_there.rom",
                        },
                    ]
                },
                "test-recalbox-system": {
                    "files": [
                        {
                            "name": "multi_hash.bin",
                            "destination": "multi_hash.bin",
                            "required": True,
                            "md5": multi_md5,
                        },
                        {
                            "name": "truncated_md5.bin",
                            "destination": "truncated_md5.bin",
                            "required": True,
                            "md5": truncated_md5,
                        },
                    ]
                },
                "test-dedup-system": {
                    "files": [
                        {
                            "name": "correct_hash.bin",
                            "destination": "correct_hash.bin",
                            "required": True,
                            "md5": wrong_md5,
                        },
                    ]
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "test_md5.yml"), "w") as f:
            yaml.dump(config, f, default_flow_style=False)

    def _write_inherit_yaml(self):
        import yaml
        config = {
            "inherits": "test_md5",
            "platform": "TestInherited",
            "base_destination": "BIOS",
        }
        with open(os.path.join(self.platforms_dir, "test_inherit.yml"), "w") as f:
            yaml.dump(config, f, default_flow_style=False)

    def _write_shared_yaml(self):
        import yaml
        shared = {
            "shared_groups": {
                "test_group": [
                    {
                        "name": "shared_file.bin",
                        "sha1": "0" * 40,
                        "md5": "d" * 32,
                        "destination": "shared/shared_file.bin",
                        "required": False,
                    },
                ],
            },
        }
        with open(os.path.join(self.platforms_dir, "_shared.yml"), "w") as f:
            yaml.dump(shared, f, default_flow_style=False)

    def _write_emulator_yamls(self):
        import yaml
        emu_profile = {
            "emulator": "TestEmulator",
            "type": "standalone + libretro",
            "systems": ["test-system"],
            "files": [
                {
                    "name": "correct_hash.bin",
                    "required": True,
                    "aliases": ["alt1.bin", "alt2.bin"],
                },
                {
                    "name": "optional_standalone.rom",
                    "required": False,
                    "mode": "standalone",
                },
                {
                    "name": "undeclared.bin",
                    "required": True,
                },
            ],
        }
        alias_profile = {
            "emulator": "TestAlias",
            "type": "alias",
            "alias_of": "test_emu_with_aliases",
            "systems": ["test-system"],
            "files": [],
        }
        with open(os.path.join(self.emulators_dir, "test_emu_with_aliases.yml"), "w") as f:
            yaml.dump(emu_profile, f, default_flow_style=False)
        with open(os.path.join(self.emulators_dir, "test_emu_alias_only.yml"), "w") as f:
            yaml.dump(alias_profile, f, default_flow_style=False)

    def _teardown_fixtures(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Existence mode tests
# ---------------------------------------------------------------------------

class TestVerifyExistenceMode(FixtureMixin, unittest.TestCase):
    """Existence platform: verify_platform with real file resolution."""

    def setUp(self):
        self._setup_fixtures()

    def tearDown(self):
        self._teardown_fixtures()

    def test_existence_mode_counts(self):
        """Existence: 2 present (1 required OK, 1 optional OK), 2 missing."""
        config = load_platform_config("test_existence", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        self.assertEqual(result["verification_mode"], "existence")
        counts = result["severity_counts"]
        # required_present + optional_present = 2 OK
        self.assertEqual(counts[Severity.OK], 2)
        # required_missing = WARNING
        self.assertEqual(counts[Severity.WARNING], 1)
        # optional_missing = INFO
        self.assertEqual(counts[Severity.INFO], 1)
        self.assertEqual(result["total_files"], 4)

    def test_severity_counts_sum_to_total(self):
        config = load_platform_config("test_existence", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        total_from_counts = sum(result["severity_counts"].values())
        self.assertEqual(total_from_counts, result["total_files"])

    def test_required_field_propagated(self):
        config = load_platform_config("test_existence", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        for detail in result["details"]:
            if detail["name"] == "optional_present.bin":
                self.assertFalse(detail["required"])
            elif detail["name"] == "required_present.bin":
                self.assertTrue(detail["required"])


# ---------------------------------------------------------------------------
# MD5 mode tests
# ---------------------------------------------------------------------------

class TestVerifyMD5Mode(FixtureMixin, unittest.TestCase):
    """MD5 platform: verify_platform with hash checks, ZIPs, multi-hash."""

    def setUp(self):
        self._setup_fixtures()

    def tearDown(self):
        self._teardown_fixtures()

    def _get_result(self):
        config = load_platform_config("test_md5", self.platforms_dir)
        return verify_platform(config, self.db, self.emulators_dir)

    def _find_detail(self, result: dict, name: str, system: str | None = None) -> dict | None:
        for d in result["details"]:
            if d["name"] == name:
                if system is None or d.get("system") == system:
                    return d
        return None

    def test_md5_mode_correct_hash(self):
        result = self._get_result()
        detail = self._find_detail(result, "correct_hash.bin", system="test-system")
        self.assertIsNotNone(detail)
        self.assertEqual(detail["status"], Status.OK)

    def test_md5_mode_wrong_hash(self):
        result = self._get_result()
        detail = self._find_detail(result, "wrong_hash.bin")
        self.assertIsNotNone(detail)
        self.assertEqual(detail["status"], Status.UNTESTED)

    def test_md5_mode_no_md5_present(self):
        """File present with no expected MD5 in md5-mode platform = OK."""
        result = self._get_result()
        detail = self._find_detail(result, "no_md5_present.bin")
        self.assertIsNotNone(detail)
        self.assertEqual(detail["status"], Status.OK)

    def test_md5_mode_missing_required(self):
        result = self._get_result()
        detail = self._find_detail(result, "required_missing.bin")
        self.assertIsNotNone(detail)
        self.assertEqual(detail["status"], Status.MISSING)

    def test_md5_mode_missing_optional(self):
        result = self._get_result()
        detail = self._find_detail(result, "optional_missing.bin")
        self.assertIsNotNone(detail)
        self.assertEqual(detail["status"], Status.MISSING)
        self.assertFalse(detail["required"])

    def test_md5_severity_missing_required_is_critical(self):
        result = self._get_result()
        counts = result["severity_counts"]
        self.assertGreater(counts[Severity.CRITICAL], 0)

    def test_md5_severity_missing_optional_is_warning(self):
        """optional_missing -> WARNING severity in md5 mode."""
        result = self._get_result()
        # At least 1 WARNING for optional_missing + wrong_hash
        counts = result["severity_counts"]
        self.assertGreater(counts[Severity.WARNING], 0)

    def test_severity_counts_sum_to_total(self):
        result = self._get_result()
        total_from_counts = sum(result["severity_counts"].values())
        self.assertEqual(total_from_counts, result["total_files"])


# ---------------------------------------------------------------------------
# ZIP verification tests
# ---------------------------------------------------------------------------

class TestVerifyZippedFiles(FixtureMixin, unittest.TestCase):
    """zipped_file entries: inner ROM hash matching via check_inside_zip."""

    def setUp(self):
        self._setup_fixtures()

    def tearDown(self):
        self._teardown_fixtures()

    def _get_result(self):
        config = load_platform_config("test_md5", self.platforms_dir)
        return verify_platform(config, self.db, self.emulators_dir)

    def _find_detail(self, result: dict, name: str) -> dict | None:
        for d in result["details"]:
            if d["name"] == name:
                return d
        return None

    def test_zipped_file_correct_inner(self):
        """test.zip with inner.rom matching expected MD5 = OK."""
        result = self._get_result()
        detail = self._find_detail(result, "test.zip")
        self.assertIsNotNone(detail)
        self.assertEqual(detail["status"], Status.OK)

    def test_zipped_file_wrong_inner(self):
        """test_bad.zip with inner.rom not matching expected MD5."""
        result = self._get_result()
        detail = self._find_detail(result, "test_bad.zip")
        self.assertIsNotNone(detail)
        # Inner ROM exists but MD5 doesn't match the expected "e"*32
        self.assertIn(detail["status"], (Status.UNTESTED, Status.MISSING))

    def test_zipped_file_inner_not_found(self):
        """test_missing_inner.zip: zipped_file references not_there.rom which doesn't exist."""
        result = self._get_result()
        detail = self._find_detail(result, "test_missing_inner.zip")
        self.assertIsNotNone(detail)
        self.assertIn(detail["status"], (Status.UNTESTED, Status.MISSING))


# ---------------------------------------------------------------------------
# Multi-hash and truncated MD5 tests
# ---------------------------------------------------------------------------

class TestVerifyRecalboxEdgeCases(FixtureMixin, unittest.TestCase):
    """Comma-separated multi-hash and truncated 29-char MD5."""

    def setUp(self):
        self._setup_fixtures()

    def tearDown(self):
        self._teardown_fixtures()

    def _get_result(self):
        config = load_platform_config("test_md5", self.platforms_dir)
        return verify_platform(config, self.db, self.emulators_dir)

    def _find_detail(self, result: dict, name: str) -> dict | None:
        for d in result["details"]:
            if d["name"] == name:
                return d
        return None

    def test_multi_hash_recalbox(self):
        """Comma-separated MD5 list: any match = OK."""
        result = self._get_result()
        detail = self._find_detail(result, "multi_hash.bin")
        self.assertIsNotNone(detail)
        self.assertEqual(detail["status"], Status.OK)

    def test_truncated_md5_batocera(self):
        """29-char MD5 prefix match = OK."""
        result = self._get_result()
        detail = self._find_detail(result, "truncated_md5.bin")
        self.assertIsNotNone(detail)
        self.assertEqual(detail["status"], Status.OK)


# ---------------------------------------------------------------------------
# Same-destination worst-status aggregation
# ---------------------------------------------------------------------------

class TestWorstStatusAggregation(FixtureMixin, unittest.TestCase):
    """Two entries for same destination: worst status wins."""

    def setUp(self):
        self._setup_fixtures()

    def tearDown(self):
        self._teardown_fixtures()

    def test_same_dest_worst_status_wins(self):
        """correct_hash.bin: test-system has correct MD5, test-dedup-system has wrong MD5.
        Worst status (UNTESTED from wrong hash) should be the aggregated result."""
        config = load_platform_config("test_md5", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        # correct_hash.bin appears in both test-system (OK) and test-dedup-system (UNTESTED)
        # Worst status should be reflected in severity_counts
        # The destination "correct_hash.bin" should have the worst severity
        dest_severities = {}
        for detail in result["details"]:
            dest = detail.get("name", "")
            if dest == "correct_hash.bin":
                # At least one should be OK and another UNTESTED
                if detail.get("status") == Status.UNTESTED:
                    dest_severities["untested"] = True
                elif detail.get("status") == Status.OK:
                    dest_severities["ok"] = True

        # Both statuses should appear in details
        self.assertTrue(dest_severities.get("ok"), "Expected OK detail for correct_hash.bin")
        self.assertTrue(dest_severities.get("untested"), "Expected UNTESTED detail for correct_hash.bin")

        # But total_files should count correct_hash.bin only once (deduped by destination)
        dest_count = sum(
            1 for dest in result["severity_counts"].values()
        )
        # severity_counts is a dict of severity->count, total_files < len(details)
        self.assertLess(result["total_files"], len(result["details"]))


# ---------------------------------------------------------------------------
# Inheritance tests
# ---------------------------------------------------------------------------

class TestInheritance(FixtureMixin, unittest.TestCase):
    """Platform with inherits: loads parent files + own overrides."""

    def setUp(self):
        self._setup_fixtures()

    def tearDown(self):
        self._teardown_fixtures()

    def test_inherited_platform_loads_parent_systems(self):
        config = load_platform_config("test_inherit", self.platforms_dir)
        self.assertEqual(config["platform"], "TestInherited")
        self.assertEqual(config["base_destination"], "BIOS")
        # Should have inherited systems from test_md5
        self.assertIn("test-system", config.get("systems", {}))
        self.assertIn("test-zip-system", config.get("systems", {}))
        self.assertIn("test-recalbox-system", config.get("systems", {}))
        self.assertIn("test-dedup-system", config.get("systems", {}))

    def test_inherited_verification_mode(self):
        """Inherited platform keeps parent's verification_mode."""
        config = load_platform_config("test_inherit", self.platforms_dir)
        self.assertEqual(config["verification_mode"], "md5")

    def test_inherited_verify_produces_results(self):
        config = load_platform_config("test_inherit", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        self.assertEqual(result["platform"], "TestInherited")
        self.assertGreater(result["total_files"], 0)
        total_from_counts = sum(result["severity_counts"].values())
        self.assertEqual(total_from_counts, result["total_files"])


# ---------------------------------------------------------------------------
# Cross-reference / undeclared files tests
# ---------------------------------------------------------------------------

class TestCrossReference(FixtureMixin, unittest.TestCase):
    """find_undeclared_files and cross_reference with emulator profiles."""

    def setUp(self):
        self._setup_fixtures()

    def tearDown(self):
        self._teardown_fixtures()

    def test_cross_reference_finds_undeclared(self):
        """undeclared.bin from emulator profile not in platform config."""
        config = load_platform_config("test_md5", self.platforms_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db)
        names = [u["name"] for u in undeclared]
        self.assertIn("undeclared.bin", names)

    def test_cross_reference_skips_standalone(self):
        """mode: standalone files excluded from undeclared list."""
        config = load_platform_config("test_md5", self.platforms_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db)
        names = [u["name"] for u in undeclared]
        self.assertNotIn("optional_standalone.rom", names)

    def test_cross_reference_skips_alias_profiles(self):
        """type: alias emulator profiles are not loaded by default."""
        profiles = load_emulator_profiles(self.emulators_dir, skip_aliases=True)
        self.assertNotIn("test_emu_alias_only", profiles)
        self.assertIn("test_emu_with_aliases", profiles)

    def test_cross_reference_declared_not_in_undeclared(self):
        """correct_hash.bin is in platform config, not reported as undeclared."""
        config = load_platform_config("test_md5", self.platforms_dir)
        undeclared = find_undeclared_files(config, self.emulators_dir, self.db)
        names = [u["name"] for u in undeclared]
        self.assertNotIn("correct_hash.bin", names)

    def test_cross_reference_function(self):
        """cross_reference() produces gap report with expected structure."""
        profiles = load_emulator_profiles(self.emulators_dir)
        declared = {}
        for sys_id in ["test-system"]:
            declared[sys_id] = {"correct_hash.bin", "wrong_hash.bin", "no_md5_present.bin",
                                "required_missing.bin", "optional_missing.bin"}

        report = cross_reference(profiles, declared, self.db)
        self.assertIn("test_emu_with_aliases", report)
        emu_report = report["test_emu_with_aliases"]
        self.assertEqual(emu_report["emulator"], "TestEmulator")
        self.assertGreater(emu_report["total_files"], 0)
        gap_names = [g["name"] for g in emu_report["gap_details"]]
        self.assertIn("undeclared.bin", gap_names)
        # standalone excluded
        self.assertNotIn("optional_standalone.rom", gap_names)


# ---------------------------------------------------------------------------
# Alias resolution tests
# ---------------------------------------------------------------------------

class TestAliasResolution(FixtureMixin, unittest.TestCase):
    """File entries with aliases resolve via alternate names."""

    def setUp(self):
        self._setup_fixtures()
        # Add alias names to the database by_name index
        sha1_a = self.hashes_a["sha1"]
        self.db["indexes"]["by_name"]["alt1.bin"] = [sha1_a]
        self.db["indexes"]["by_name"]["alt2.bin"] = [sha1_a]

    def tearDown(self):
        self._teardown_fixtures()

    def test_alias_resolves_file(self):
        """File not found by primary name resolves via alias in by_name."""
        entry = {
            "name": "nonexistent_primary.bin",
            "aliases": ["alt1.bin"],
        }
        path, status = resolve_local_file(entry, self.db)
        self.assertIsNotNone(path)
        self.assertEqual(os.path.basename(path), "correct_hash.bin")

    def test_primary_name_preferred_over_alias(self):
        entry = {
            "name": "correct_hash.bin",
            "aliases": ["alt1.bin"],
        }
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "exact")
        self.assertEqual(os.path.basename(path), "correct_hash.bin")


# ---------------------------------------------------------------------------
# Pack consistency test
# ---------------------------------------------------------------------------

class TestPackConsistency(FixtureMixin, unittest.TestCase):
    """verify and pack produce consistent OK counts for the same platform."""

    def setUp(self):
        self._setup_fixtures()

    def tearDown(self):
        self._teardown_fixtures()

    def test_existence_ok_count_matches_present_files(self):
        """For existence mode, OK count should match files resolved on disk."""
        config = load_platform_config("test_existence", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)

        # Count how many files actually resolve
        resolved_count = 0
        for sys_id, system in config.get("systems", {}).items():
            for fe in system.get("files", []):
                path, status = resolve_local_file(fe, self.db)
                if path is not None:
                    resolved_count += 1

        # Deduplicate by destination (same logic as verify_platform)
        dest_resolved = set()
        for sys_id, system in config.get("systems", {}).items():
            for fe in system.get("files", []):
                path, status = resolve_local_file(fe, self.db)
                dest = fe.get("destination", fe.get("name", ""))
                if path is not None:
                    dest_resolved.add(dest)

        self.assertEqual(result["severity_counts"][Severity.OK], len(dest_resolved))


# ---------------------------------------------------------------------------
# Database.json fixture
# ---------------------------------------------------------------------------

class TestDatabaseFixture(FixtureMixin, unittest.TestCase):
    """Verify the synthetic database.json has correct structure and indexes."""

    def setUp(self):
        self._setup_fixtures()

    def tearDown(self):
        self._teardown_fixtures()

    def test_db_has_required_keys(self):
        self.assertIn("files", self.db)
        self.assertIn("indexes", self.db)
        self.assertIn("by_md5", self.db["indexes"])
        self.assertIn("by_name", self.db["indexes"])
        self.assertIn("by_crc32", self.db["indexes"])

    def test_db_sha1_keys_match(self):
        """Every SHA1 key in files is reachable via by_md5 or by_name."""
        by_md5 = self.db["indexes"]["by_md5"]
        by_name = self.db["indexes"]["by_name"]
        for sha1, info in self.db["files"].items():
            md5 = info.get("md5", "")
            name = info.get("name", "")
            found = False
            if md5 in by_md5 and by_md5[md5] == sha1:
                found = True
            if name in by_name and sha1 in by_name[name]:
                found = True
            self.assertTrue(found, f"SHA1 {sha1} not reachable via indexes")

    def test_db_file_paths_exist(self):
        for sha1, info in self.db["files"].items():
            path = info.get("path", "")
            self.assertTrue(os.path.exists(path), f"File missing: {path}")

    def test_db_hashes_match_disk(self):
        """MD5 in database matches actual file on disk."""
        for sha1, info in self.db["files"].items():
            actual = md5sum(info["path"])
            self.assertEqual(actual, info["md5"], f"MD5 mismatch for {info['path']}")

    def test_db_json_roundtrip(self):
        """database.json written to disk can be loaded back."""
        with open(self.db_path) as f:
            loaded = json.load(f)
        self.assertEqual(set(loaded["files"].keys()), set(self.db["files"].keys()))


# ---------------------------------------------------------------------------
# Shared groups test
# ---------------------------------------------------------------------------

class TestSharedGroups(FixtureMixin, unittest.TestCase):
    """_shared.yml groups injected via includes."""

    def setUp(self):
        self._setup_fixtures()

    def tearDown(self):
        self._teardown_fixtures()

    def test_shared_group_loaded(self):
        """_shared.yml exists and can be parsed."""
        import yaml
        shared_path = os.path.join(self.platforms_dir, "_shared.yml")
        self.assertTrue(os.path.exists(shared_path))
        with open(shared_path) as f:
            data = yaml.safe_load(f)
        self.assertIn("shared_groups", data)
        self.assertIn("test_group", data["shared_groups"])

    def test_includes_injects_shared_files(self):
        """Platform with includes: [test_group] gets shared_file.bin."""
        import yaml
        # Create a platform that uses includes
        config = {
            "platform": "TestWithShared",
            "verification_mode": "existence",
            "systems": {
                "test-shared-system": {
                    "includes": ["test_group"],
                    "files": [
                        {
                            "name": "local_file.bin",
                            "destination": "local_file.bin",
                            "required": True,
                            "sha1": "0" * 40,
                        },
                    ],
                }
            },
        }
        with open(os.path.join(self.platforms_dir, "test_with_shared.yml"), "w") as f:
            yaml.dump(config, f, default_flow_style=False)

        loaded = load_platform_config("test_with_shared", self.platforms_dir)
        files = loaded["systems"]["test-shared-system"]["files"]
        names = [fe["name"] for fe in files]
        self.assertIn("local_file.bin", names)
        self.assertIn("shared_file.bin", names)


if __name__ == "__main__":
    unittest.main()
