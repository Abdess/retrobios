"""End-to-end emulator mode verification and hardware target filtering."""

from __future__ import annotations

import tests
import contextlib
import hashlib
import io
import os
import unittest
import zipfile
import yaml
from core.ziptools import safe_extract_zip
from core.hashing import compute_hashes, parse_hash_list
from model.profiles import ProfileSelectionError, load_emulator_profiles
from model.platforms import load_platform_config
from resolve.localfile import resolve_local_file
from resolve.cores import resolve_platform_cores
from resolve.entryscope import filter_files_by_mode
from packs.verdicts import Severity, Status
from packs.gaps import find_undeclared_files
from packs.emulatorcheck import verify_emulator
from tests.e2esupport import E2EFixture


class TestE2EEmulatorMode(E2EFixture):
    """verify --emulator and --system, build modes and path hints."""

    def test_90_verify_emulator_basic(self):
        """verify_emulator returns correct counts for a profile with mixed present/missing."""
        result = verify_emulator(["test_emu"], self.emulators_dir, self.db)
        self.assertIn("test_emu", result["emulators"])
        # present_req.bin and alias_target.bin are present, others missing
        self.assertGreater(result["total_files"], 0)
        self.assertGreater(result["severity_counts"][Severity.OK], 0)

    def test_91_verify_emulator_standalone_filters(self):
        """Standalone mode includes mode:standalone files, excludes mode:libretro."""
        result_lr = verify_emulator(
            ["test_emu"], self.emulators_dir, self.db, standalone=False
        )
        result_sa = verify_emulator(
            ["test_emu"], self.emulators_dir, self.db, standalone=True
        )
        lr_names = {d["name"] for d in result_lr["details"]}
        sa_names = {d["name"] for d in result_sa["details"]}
        # standalone_only.bin should be in standalone, not libretro
        self.assertNotIn("standalone_only.bin", lr_names)
        self.assertIn("standalone_only.bin", sa_names)

    def test_102_resolve_dest_hint_disambiguates(self):
        """dest_hint resolves regional variants with same name to distinct files."""
        usa_path, usa_status = resolve_local_file(
            {"name": "BIOS.bin"},
            self.db,
            dest_hint="TestConsole/USA/BIOS.bin",
        )
        eur_path, eur_status = resolve_local_file(
            {"name": "BIOS.bin"},
            self.db,
            dest_hint="TestConsole/EUR/BIOS.bin",
        )
        self.assertIsNotNone(usa_path)
        self.assertIsNotNone(eur_path)
        self.assertEqual(usa_status, "path_exact")
        self.assertEqual(eur_status, "path_exact")
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
        with self.assertRaises(ProfileSelectionError):
            verify_emulator(["test_hle"], self.emulators_dir, self.db, standalone=True)

    def test_92b_verify_emulator_game_type_rejects_standalone(self):
        """Game-type profile rejects --standalone."""
        game = {
            "emulator": "TestGame",
            "type": "game",
            "systems": ["console-a"],
            "files": [],
        }
        with open(os.path.join(self.emulators_dir, "test_game.yml"), "w") as fh:
            yaml.dump(game, fh)
        with self.assertRaises(ProfileSelectionError):
            verify_emulator(["test_game"], self.emulators_dir, self.db, standalone=True)

    def test_93_verify_emulator_alias_selects_its_profile(self):
        """An alias verifies the profile it is an alias of."""
        with contextlib.redirect_stderr(io.StringIO()):
            via_alias = verify_emulator(["test_alias"], self.emulators_dir, self.db)
        direct = verify_emulator(["test_emu"], self.emulators_dir, self.db)
        self.assertEqual(via_alias["emulators"], direct["emulators"])
        self.assertEqual(via_alias["details"], direct["details"])

    def test_94_verify_emulator_launcher_rejected(self):
        """Launcher profile produces error."""
        with self.assertRaises(ProfileSelectionError):
            verify_emulator(["test_launcher"], self.emulators_dir, self.db)

    def test_95_verify_emulator_validation_applied(self):
        """Emulator mode applies validation checks as primary verification."""
        result = verify_emulator(["test_validation"], self.emulators_dir, self.db)
        # present_opt.bin has wrong size ->UNTESTED
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
            ["test_emu", "test_hle"],
            self.emulators_dir,
            self.db,
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

    def test_97b_a_data_directory_follows_its_build_mode(self):
        """A tree only the standalone build reads is no concern of the core."""
        profile = {
            "emulator": "ModeDirs",
            "type": "standalone + libretro",
            "cores": ["mode_dirs"],
            "systems": ["console-a"],
            "data_directories": [
                {"ref": "standalone-only-dir", "mode": "standalone"},
                {"ref": "shared-dir"},
            ],
            "files": [{"name": "present_req.bin", "required": True}],
        }
        with open(os.path.join(self.emulators_dir, "mode_dirs.yml"), "w") as fh:
            yaml.dump(profile, fh)
        as_core = verify_emulator(["mode_dirs"], self.emulators_dir, self.db)
        self.assertEqual(as_core.get("data_dir_notices", []), ["shared-dir"])
        alone = verify_emulator(
            ["mode_dirs"], self.emulators_dir, self.db, standalone=True
        )
        self.assertEqual(
            sorted(alone.get("data_dir_notices", [])),
            ["shared-dir", "standalone-only-dir"],
        )

    def test_97c_one_held_release_fills_a_slot_several_are_accepted_for(self):
        """Entries of one profile on one destination are alternatives.

        A profile lists each release the code accepts under a name (the
        shareware and the retail archive, told apart by size). Holding one
        is the slot filled: the releases not held are not gaps and must not
        drag the destination down to the worst status among them.
        """
        present = os.path.join(self.bios_dir, "present_req.bin")
        size = os.path.getsize(present)
        profile = {
            "emulator": "Releases",
            "type": "standalone",
            "cores": ["releases"],
            "systems": ["console-a"],
            "files": [
                {"name": "present_req.bin", "path": "game/present_req.bin",
                 "required": False, "size": size + 7, "validation": ["size"],
                 "description": "retail"},
                {"name": "present_req.bin", "path": "game/present_req.bin",
                 "required": False, "size": size, "validation": ["size"],
                 "description": "shareware"},
                {"name": "absent_everywhere.bin", "path": "game/absent.bin",
                 "required": False},
            ],
        }
        with open(os.path.join(self.emulators_dir, "releases.yml"), "w") as fh:
            yaml.dump(profile, fh)
        result = verify_emulator(
            ["releases"], self.emulators_dir, self.db, standalone=True
        )
        statuses = {d["name"]: d["status"] for d in result["details"]}
        self.assertEqual(statuses["present_req.bin"], "ok")
        self.assertEqual(statuses["absent_everywhere.bin"], "missing")
        self.assertEqual(
            sum(1 for d in result["details"] if d["name"] == "present_req.bin"), 1
        )
        self.assertEqual(result["total_files"], 2)

    def test_98_verify_emulator_validation_label(self):
        """Validation label reflects the checks used."""
        result = verify_emulator(["test_validation"], self.emulators_dir, self.db)
        # test_validation has crc32, md5, sha1, size ->all listed
        self.assertEqual(result["verification_mode"], "crc32+md5+sha1+signature+size")

    def test_99filter_files_by_mode(self):
        """filter_files_by_mode correctly filters standalone/libretro."""
        files = [
            {"name": "a.bin"},  # no mode ->both
            {"name": "b.bin", "mode": "libretro"},  # libretro only
            {"name": "c.bin", "mode": "standalone"},  # standalone only
            {"name": "d.bin", "mode": "both"},  # explicit both
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
            "emulator": "TestEmpty",
            "type": "libretro",
            "systems": ["console-a"],
            "files": [],
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
        """Missing required file in emulator mode ->WARNING severity."""
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
        empty_db = {
            "files": {},
            "indexes": {"by_md5": {}, "by_name": {}, "by_path_suffix": {}},
        }
        entry = {"name": "nonexistent.bin", "sha1": "abc123"}
        path, status = resolve_local_file(entry, empty_db)
        self.assertIsNone(path)
        self.assertEqual(status, "not_found")

    def test_106_parse_hash_list(self):
        """parse_hash_list normalizes comma-separated MD5s."""
        self.assertEqual(parse_hash_list(""), [])
        self.assertEqual(parse_hash_list("ABC123"), ["abc123"])
        self.assertEqual(parse_hash_list("abc, DEF , ghi"), ["abc", "def", "ghi"])
        self.assertEqual(parse_hash_list(",,,"), [])

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
            "cores": ["test_sa"],
            "standalone_cores": ["test_sa"],
            "systems": {
                "console-a": {
                    "files": [
                        {
                            "name": "present_req.bin",
                            "destination": "present_req.bin",
                            "required": True,
                        },
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
            "cores": ["test_sa"],
            "systems": ["console-a"],
            "files": [
                {
                    "name": "libretro_file.bin",
                    "path": "subdir/libretro_file.bin",
                    "standalone_path": "flat_file.bin",
                    "required": True,
                },
                {
                    "name": "standalone_only.bin",
                    "mode": "standalone",
                    "required": False,
                },
                {"name": "libretro_only.bin", "mode": "libretro", "required": False},
            ],
        }
        with open(
            os.path.join(self.emulators_dir, "test_standalone_emu.yml"), "w"
        ) as fh:
            yaml.dump(emu, fh)

        config = load_platform_config("test_standalone", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
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
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
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


class TestE2ETargets(E2EFixture):
    """Hardware target configuration and the core filtering it drives."""

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
        from model.targets import load_target_config

        cores = load_target_config("testplatform", "target-minimal", self.platforms_dir)
        self.assertEqual(cores, {"core_a"})

    def test_target_alias_resolution(self):
        self._write_target_fixtures()
        from model.targets import load_target_config

        cores = load_target_config("testplatform", "full", self.platforms_dir)
        self.assertEqual(cores, {"core_a", "core_b", "core_d"})

    def test_target_unknown_error(self):
        self._write_target_fixtures()
        from model.targets import load_target_config

        with self.assertRaises(ValueError) as ctx:
            load_target_config("testplatform", "nonexistent", self.platforms_dir)
        self.assertIn("target-full", str(ctx.exception))
        self.assertIn("target-minimal", str(ctx.exception))

    def test_target_override_add_remove(self):
        self._write_target_fixtures()
        from model.targets import load_target_config

        cores = load_target_config("testplatform", "full", self.platforms_dir)
        self.assertIn("core_d", cores)
        self.assertNotIn("core_c", cores)
        self.assertIn("core_a", cores)
        self.assertIn("core_b", cores)

    def test_target_default_override_reaches_every_target(self):
        """`_default` drops a name on every target, then the target adds its own."""
        self._write_target_fixtures()
        from model.targets import load_target_config

        targets_dir = os.path.join(self.platforms_dir, "targets")
        overrides = {
            "testplatform": {
                "targets": {
                    "_default": {"remove_cores": ["core_a"], "add_cores": ["core_z"]},
                    "target-full": {"aliases": ["full"], "add_cores": ["core_a"]},
                },
            },
        }
        with open(os.path.join(targets_dir, "_overrides.yml"), "w") as f:
            yaml.dump(overrides, f)
        self.assertEqual(
            load_target_config("testplatform", "target-minimal", self.platforms_dir),
            {"core_z"},
        )
        self.assertEqual(
            load_target_config("testplatform", "full", self.platforms_dir),
            {"core_a", "core_b", "core_c", "core_z"},
        )
        with self.assertRaises(ValueError):
            load_target_config("testplatform", "_default", self.platforms_dir)

    def test_target_single_target_noop(self):
        self._write_target_fixtures()
        from model.targets import load_target_config

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
        from model.targets import load_target_config

        parent = load_target_config(
            "testplatform", "target-minimal", self.platforms_dir
        )
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
        result = resolve_platform_cores(
            config, profiles, target_cores={"core_a", "core_b"}
        )
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
            yaml.dump(
                {
                    "emulator": "CoreA",
                    "type": "libretro",
                    "systems": ["sys1"],
                    "files": [{"name": "bios_a.bin", "required": True}],
                },
                f,
            )
        with open(core_b_path, "w") as f:
            yaml.dump(
                {
                    "emulator": "CoreB",
                    "type": "libretro",
                    "systems": ["sys1"],
                    "files": [{"name": "bios_b.bin", "required": True}],
                },
                f,
            )

        config = {"cores": "all_libretro", "systems": {"sys1": {"files": []}}}
        profiles = load_emulator_profiles(self.emulators_dir)

        # Without target: both cores' files are undeclared
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
        names = {u["name"] for u in undeclared}
        self.assertIn("bios_a.bin", names)
        self.assertIn("bios_b.bin", names)

        # With target filtering to core_a only
        undeclared = find_undeclared_files(
            config,
            self.emulators_dir,
            self.db,
            profiles,
            target_cores={"core_a"},
        )
        names = {u["name"] for u in undeclared}
        self.assertIn("bios_a.bin", names)
        self.assertNotIn("bios_b.bin", names)


if __name__ == "__main__":
    unittest.main()
