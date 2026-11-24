"""End-to-end resolution, platform verification, cross-reference and validation checks."""

from __future__ import annotations

import tests
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
import yaml
from core.ziptools import build_zip_contents_index, check_inside_zip
from core.hashing import md5_composite
from resolve.grouping import group_identical_platforms
from model.profiles import load_emulator_profiles
from model.platforms import load_platform_config
from resolve.localfile import resolve_local_file
from resolve.cores import resolve_platform_cores
from resolve.validation import build_validation_index, check_file_validation
from packs.verdicts import Severity, Status
from packs.gaps import find_exclusion_notes, find_undeclared_files
from packs.coverage import verify_platform
from tests.e2esupport import E2EFixture


class TestE2EResolution(E2EFixture):
    """Resolution, zip checks, platform verification, grouping and core resolution."""

    def test_01_resolve_sha1(self):
        entry = {
            "name": "present_req.bin",
            "sha1": self.files["present_req.bin"]["sha1"],
        }
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "sha1_exact")
        self.assertIn("present_req.bin", path)

    def test_02_resolve_md5(self):
        entry = {
            "name": "correct_hash.bin",
            "md5": self.files["correct_hash.bin"]["md5"],
        }
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "md5_exact")

    def test_03_resolve_name_no_md5(self):
        entry = {"name": "no_md5.bin"}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "name_exact")

    def test_04_resolve_alias(self):
        entry = {"name": "alias_alt.bin", "aliases": []}
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "name_exact")
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

    def test_07b_resolve_unsourceable_ignores_homonym(self):
        """An unsourceable entry takes content, never a file of the same name."""
        entry = {
            "name": "wrong_hash.bin",
            "md5": "ffffffffffffffffffffffffffffffff",
            "unsourceable": "ships inside a paid application package",
        }
        path, status = resolve_local_file(entry, self.db)
        self.assertIsNone(path)
        self.assertEqual(status, "not_found")

        entry = {"name": "no_md5.bin", "unsourceable": "written per title"}
        path, status = resolve_local_file(entry, self.db)
        self.assertIsNone(path)
        self.assertEqual(status, "not_found")

        # Collecting the real bytes still resolves it.
        entry = {
            "name": "present_req.bin",
            "sha1": self.files["present_req.bin"]["sha1"],
            "unsourceable": "ships inside a paid application package",
        }
        path, status = resolve_local_file(entry, self.db)
        self.assertEqual(status, "sha1_exact")
        self.assertIn("present_req.bin", path)

    def test_08_resolve_variants_deprioritized(self):
        entry = {"name": "present_req.bin"}
        path, status = resolve_local_file(entry, self.db)
        self.assertNotIn(".variants", path)

    def test_09_resolve_zip_contents(self):
        zc = build_zip_contents_index(self.db, Path(self.root))
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

    def test_20b_agnostic_core_fills_existence_slots(self):
        """An agnostic core on the platform serves a missing slot, as the pack does."""
        config = load_platform_config("test_existence", self.platforms_dir)
        result = verify_platform(config, self.db, self.emulators_dir)
        c = result["severity_counts"]
        self.assertEqual(c[Severity.OK], result["total_files"])

    def test_13_check_inside_zip_not_found(self):
        r = check_inside_zip(self.files["missing_inner.zip"]["path"], "nope.rom", "abc")
        self.assertEqual(r, "not_in_zip")

    def test_14_check_inside_zip_casefold(self):
        inner_md5 = self.files["good.zip"]["inner_md5s"]["inner.rom"]
        r = check_inside_zip(self.files["good.zip"]["path"], "INNER.ROM", inner_md5)
        self.assertEqual(r, "ok")

    def test_20_verify_existence_platform(self):
        config = load_platform_config("test_existence", self.platforms_dir)
        # Without the filename-agnostic core, which would serve the two
        # missing slots under existence (test_20b covers that case).
        profiles = {
            k: v for k, v in load_emulator_profiles(self.emulators_dir).items()
            if v.get("bios_mode") != "agnostic"
        }
        result = verify_platform(config, self.db, self.emulators_dir, emu_profiles=profiles)
        c = result["severity_counts"]
        total = result["total_files"]
        # 2 present (1 req + 1 opt), 2 missing (1 req WARNING + 1 opt INFO)
        self.assertEqual(c[Severity.OK], 2)
        self.assertEqual(c[Severity.WARNING], 1)  # required missing
        self.assertEqual(c[Severity.INFO], 1)  # optional missing
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

    def test_24b_a_held_group_member_makes_the_others_optional(self):
        """RetroBat's group: one file held is enough (batocera-systems/Program.cs)."""
        from model.platforms import _platform_config_cache

        with open(os.path.join(self.platforms_dir, "test_md5.yml")) as fh:
            config = yaml.safe_load(fh)
        held_md5 = next(
            f["md5"] for f in config["systems"]["sys-renamed"]["files"]
        )
        config["systems"] = {
            "sys-group": {"files": [
                {"name": "correct_hash.bin", "destination": "g/held.bin",
                 "md5": held_md5, "required": True, "group": "one"},
                {"name": "absent_alt.bin", "destination": "g/absent_alt.bin",
                 "md5": "0" * 32, "required": True, "group": "one"},
                {"name": "absent_a.bin", "destination": "g/absent_a.bin",
                 "md5": "1" * 32, "required": True, "group": "none"},
                {"name": "absent_b.bin", "destination": "g/absent_b.bin",
                 "md5": "2" * 32, "required": True, "group": "none"},
            ]},
        }
        with open(os.path.join(self.platforms_dir, "grouped_md5.yml"), "w") as fh:
            yaml.dump(config, fh)
        _platform_config_cache.clear()
        result = verify_platform(
            load_platform_config("grouped_md5", self.platforms_dir), self.db, self.emulators_dir
        )
        by_name = {d["name"]: d for d in result["details"]}
        self.assertEqual(by_name["correct_hash.bin"]["status"], Status.OK)
        self.assertIs(by_name["absent_alt.bin"]["required"], False)
        self.assertIs(by_name["absent_a.bin"]["required"], True)
        self.assertIs(by_name["absent_b.bin"]["required"], True)
        self.assertEqual(result["severity_counts"][Severity.CRITICAL], 2)

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
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
        names = {u["name"] for u in undeclared}
        self.assertIn("undeclared_req.bin", names)
        self.assertIn("undeclared_opt.bin", names)

    def test_41_cross_ref_skips_standalone(self):
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
        names = {u["name"] for u in undeclared}
        self.assertNotIn("standalone_only.bin", names)

    def test_42_cross_ref_skips_alias_profiles(self):
        profiles = load_emulator_profiles(self.emulators_dir)
        self.assertNotIn("test_alias", profiles)

    def test_42b_profile_hash_fields_load_as_str(self):
        """Unquoted digit-only hashes must load as strings, not YAML ints."""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "numcrc.yml").write_text(
                "emulator: NumCRC\n"
                "type: libretro\n"
                "files:\n"
                "  - name: kernal.bin\n"
                "    crc32: 70295038\n"
                "    md5: [12345678901234567890123456789012]\n"
            )
            profiles = load_emulator_profiles(tmp)
            entry = profiles["numcrc"]["files"][0]
        self.assertEqual(entry["crc32"], "70295038")
        self.assertEqual(entry["md5"], ["12345678901234567890123456789012"])

    def test_43_cross_ref_data_dir_does_not_suppress_files(self):
        config = load_platform_config("test_md5", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
        names = {u["name"] for u in undeclared}
        # dd_covered.bin is a file entry, not data_dir content: still undeclared
        self.assertIn("dd_covered.bin", names)

    def test_44_cross_ref_skips_launchers(self):
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
        names = {u["name"] for u in undeclared}
        # launcher_bios.bin from TestLauncher should NOT appear
        self.assertNotIn("launcher_bios.bin", names)

    def test_45_hle_fallback_downgrades_severity(self):
        """Missing file with hle_fallback=true ->INFO severity, not CRITICAL."""
        from packs.verdicts import Severity, compute_severity

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
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
        hle_files = {u["name"] for u in undeclared if u.get("hle_fallback")}
        self.assertIn("hle_missing.bin", hle_files)

    def test_50_platform_grouping_identical(self):
        groups = group_identical_platforms(
            ["test_existence", "test_inherited"], self.platforms_dir
        )
        # With flat ZIPs, base_destination no longer separates groups
        # Platforms with same files (regardless of base_dest) are grouped
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0][0]), 2)

    def test_51_platform_grouping_same(self):
        # Create two identical platforms
        for name in ("dup_a", "dup_b"):
            config = {
                "platform": name,
                "verification_mode": "existence",
                "systems": {
                    "s": {"files": [{"name": "x.bin", "destination": "x.bin"}]}
                },
            }
            with open(os.path.join(self.platforms_dir, f"{name}.yml"), "w") as fh:
                yaml.dump(config, fh)
        groups = group_identical_platforms(["dup_a", "dup_b"], self.platforms_dir)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0][0]), 2)

    def test_52_platform_grouping_splits_on_cores(self):
        """Same baseline, different emulators: the core files differ."""
        declared = {
            "cores_all": "all_libretro",
            "cores_all_too": "all_libretro",
            "cores_listed": ["retroarch", "openmsx"],
        }
        for name, cores in declared.items():
            config = {
                "platform": name,
                "verification_mode": "existence",
                "cores": cores,
                "systems": {
                    "s": {"files": [{"name": "x.bin", "destination": "x.bin"}]}
                },
            }
            with open(os.path.join(self.platforms_dir, f"{name}.yml"), "w") as fh:
                yaml.dump(config, fh)
        groups = group_identical_platforms(list(declared), self.platforms_dir)
        self.assertEqual(
            sorted(sorted(group) for group, _rep in groups),
            [["cores_all", "cores_all_too"], ["cores_listed"]],
        )

    def test_60_storage_external(self):
        from resolve.packfiles import resolve_file

        entry = {"name": "large.pup", "storage": "external"}
        path, status = resolve_file(entry, self.db, self.bios_dir)
        self.assertIsNone(path)
        self.assertEqual(status, "external")

    def test_61_storage_user_provided(self):
        from resolve.packfiles import resolve_file

        entry = {"name": "user.bin", "storage": "user_provided"}
        path, status = resolve_file(entry, self.db, self.bios_dir)
        self.assertIsNone(path)
        self.assertEqual(status, "user_provided")

    def test_resolve_cores_all_libretro(self):
        """all_libretro resolves to all libretro-type profiles, excludes alias/standalone."""
        config = {"cores": "all_libretro", "systems": {"nes": {"files": []}}}
        profiles = {
            "fceumm": {"type": "libretro", "systems": ["nes"], "files": []},
            "dolphin_standalone": {
                "type": "standalone",
                "systems": ["gc"],
                "files": [],
            },
            "gambatte": {"type": "pure_libretro", "systems": ["gb"], "files": []},
            "mednafen_psx_hw": {"type": "alias", "alias_of": "beetle_psx", "files": []},
        }
        result = resolve_platform_cores(config, profiles)
        self.assertEqual(result, {"fceumm", "gambatte"})

    def test_a_build_a_platform_compiles_is_reached_by_name(self):
        """Recalbox compiles libretro/mame at 0.258 and 0.278, but the buildbot
        RetroArch installs from does not, so all_libretro must not reach
        them while a platform naming them does."""
        profiles = {
            "mame": {"type": "standalone + libretro", "systems": ["arcade"], "files": []},
            "mame0278": {"type": "libretro", "built_by": ["recalbox"],
                         "cores": ["mame0278"], "systems": ["arcade"], "files": []},
        }
        everyone = {"cores": "all_libretro", "systems": {}}
        self.assertEqual(resolve_platform_cores(everyone, profiles), {"mame"})
        retroarch_plus = {"cores": ["retroarch"], "systems": {}}
        self.assertEqual(resolve_platform_cores(retroarch_plus, profiles), {"mame"})
        recalbox = {"cores": ["mame0278"], "systems": {}}
        self.assertEqual(resolve_platform_cores(recalbox, profiles), {"mame0278"})

    def test_a_platform_s_own_libretro_build_comes_with_its_retroarch(self):
        """ROCKNIX ships yabadabadoo with its RetroArch and names it nowhere
        else: a list naming retroarch takes the libretro builds whose
        built_by names that platform, and no other platform's."""
        profiles = {
            "yabause": {"type": "libretro", "systems": ["saturn"], "files": []},
            "yabadabadoo": {"type": "libretro", "built_by": ["rocknix"],
                            "systems": ["saturn"], "files": []},
        }
        rocknix = {"_key": "rocknix", "cores": ["retroarch"], "systems": {}}
        self.assertEqual(resolve_platform_cores(rocknix, profiles),
                         {"yabause", "yabadabadoo"})
        other = {"_key": "batocera", "cores": ["retroarch"], "systems": {}}
        self.assertEqual(resolve_platform_cores(other, profiles), {"yabause"})
        everyone = {"_key": "retroarch", "cores": "all_libretro", "systems": {}}
        self.assertEqual(resolve_platform_cores(everyone, profiles), {"yabause"})

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
            "systems": {"arcade": {"files": [{"name": "neogeo.zip", "md5": "abc"}]}},
        }
        profiles = {
            "fbneo": {
                "emulator": "FBNeo",
                "systems": ["snk-neogeo-mvs"],
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
        config = {"cores": ["desmume2015"], "systems": {"nds": {"files": []}}}
        profiles = {
            "desmume2015": {
                "emulator": "DeSmuME 2015",
                "type": "frozen_snapshot",
                "systems": ["nintendo-ds"],
                "files": [],
                "exclusion_note": "Frozen snapshot, code never loads BIOS",
            },
        }
        notes = find_exclusion_notes(config, self.emulators_dir, profiles)
        emu_names = [n["emulator"] for n in notes]
        self.assertIn("DeSmuME 2015", emu_names)


class TestE2EValidation(E2EFixture):
    """The validation index and the checks it applies."""

    def test_70_validation_index_built(self):
        """Validation index extracts checks from emulator profiles."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = build_validation_index(profiles)
        self.assertIn("present_req.bin", index)
        self.assertIn("size", index["present_req.bin"]["checks"])
        self.assertIn(16, {s for r in index["present_req.bin"]["rules"] for s in r["sizes"]})
        self.assertIn("correct_hash.bin", index)
        self.assertIn("crc32", index["correct_hash.bin"]["checks"])

    def test_71_validation_size_pass(self):
        """File with correct size passes validation."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = build_validation_index(profiles)
        path = self.files["present_req.bin"]["path"]
        reason = check_file_validation(path, "present_req.bin", index)
        self.assertIsNone(reason)

    def test_72_validation_size_fail(self):
        """File with wrong size fails validation."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = build_validation_index(profiles)
        path = self.files["present_opt.bin"]["path"]
        result = check_file_validation(path, "present_opt.bin", index)
        self.assertIsNotNone(result)
        reason, emus = result
        self.assertIn("size mismatch", reason)
        self.assertIsInstance(emus, list)

    def test_73_validation_crc32_pass(self):
        """File with correct CRC32 passes validation."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = build_validation_index(profiles)
        path = self.files["correct_hash.bin"]["path"]
        reason = check_file_validation(path, "correct_hash.bin", index)
        self.assertIsNone(reason)

    def test_74_validation_crc32_fail(self):
        """File with wrong CRC32 fails validation."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = build_validation_index(profiles)
        path = self.files["no_md5.bin"]["path"]
        result = check_file_validation(path, "no_md5.bin", index)
        self.assertIsNotNone(result)
        reason, emus = result
        self.assertIn("crc32 mismatch", reason)
        self.assertIsInstance(emus, list)

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
        index = build_validation_index(profiles)
        path = self.files["leading_zero_crc.bin"]["path"]
        reason = check_file_validation(path, "leading_zero_crc.bin", index)
        self.assertIsNone(reason)

    def test_78_validation_multi_size_accepted(self):
        """Multiple valid sizes from different profiles are collected as a set."""
        profiles = {
            "emu_a": {
                "type": "libretro",
                "files": [
                    {"name": "shared.bin", "validation": ["size"], "size": 512},
                ],
            },
            "emu_b": {
                "type": "libretro",
                "files": [
                    {"name": "shared.bin", "validation": ["size"], "size": 1024},
                ],
            },
        }
        index = build_validation_index(profiles)
        self.assertEqual([r["sizes"] for r in index["shared.bin"]["rules"]], [{512}, {1024}])

    def test_71b_validation_sizes_judged_per_entry(self):
        """One core's exact size is never bounded by another core's minimum:
        pooled, gsplus's 131072-byte Apple IIGS ROM fell under basiliskii's
        min_size and was refused."""
        import tempfile

        profiles = {
            "exact": {"type": "libretro", "files": [
                {"name": "ROM", "validation": ["size"], "size": [131072, 262144]}]},
            "ranged": {"type": "libretro", "files": [
                {"name": "ROM", "validation": ["size"], "min_size": 377670}]},
        }
        index = build_validation_index(profiles)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ROM")
            with open(path, "wb") as f:
                f.write(b"\0" * 131072)
            self.assertIsNone(check_file_validation(path, "ROM", index))
            with open(path, "wb") as f:
                f.write(b"\0" * 1000)
            reason, emus = check_file_validation(path, "ROM", index)
            self.assertIn("size", reason)
            self.assertEqual(emus, ["exact", "ranged"])

    def test_79_validation_md5_pass(self):
        """File with correct MD5 passes validation."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = build_validation_index(profiles)
        path = self.files["correct_hash.bin"]["path"]
        reason = check_file_validation(path, "correct_hash.bin", index)
        self.assertIsNone(reason)

    def test_80_validation_md5_fail(self):
        """File with wrong MD5 fails validation."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = build_validation_index(profiles)
        path = self.files["alias_target.bin"]["path"]
        result = check_file_validation(path, "alias_target.bin", index)
        self.assertIsNotNone(result)
        reason, emus = result
        self.assertIn("md5 mismatch", reason)
        self.assertIsInstance(emus, list)

    def test_81_validation_index_has_md5_sha1(self):
        """Validation index stores md5 and sha1 when declared."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = build_validation_index(profiles)
        self.assertIn("md5", index["correct_hash.bin"]["checks"])
        self.assertIn("sha1", index["correct_hash.bin"]["checks"])
        self.assertIsNotNone(index["correct_hash.bin"]["md5"])
        self.assertIsNotNone(index["correct_hash.bin"]["sha1"])

    def test_82_validation_adler32_pass(self):
        """File with correct adler32 passes validation."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = build_validation_index(profiles)
        path = self.files["present_req.bin"]["path"]
        reason = check_file_validation(path, "present_req.bin", index)
        self.assertIsNone(reason)

    def test_83_validation_min_max_size_pass(self):
        """File within min/max size range passes validation."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = build_validation_index(profiles)
        path = self.files["present_req.bin"]["path"]
        reason = check_file_validation(path, "present_req.bin", index)
        self.assertIsNone(reason)
        # Each entry keeps its own min/max
        rules = index["present_req.bin"]["rules"]
        self.assertIn((10, 100), {(r["min_size"], r["max_size"]) for r in rules})

    def test_84_validation_crypto_tracked(self):
        """Signature/crypto checks are tracked as non-reproducible."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = build_validation_index(profiles)
        # correct_hash.bin has [size, signature]
        self.assertIn("signature", index["correct_hash.bin"]["crypto_only"])
        # Size check still applies despite signature being non-reproducible
        path = self.files["correct_hash.bin"]["path"]
        reason = check_file_validation(path, "correct_hash.bin", index)
        self.assertIsNone(reason)  # size=16 matches

    def test_76_validation_no_effect_when_no_field(self):
        """Files without validation field are unaffected."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = build_validation_index(profiles)
        # wrong_hash.bin has no validation in any profile
        path = self.files["wrong_hash.bin"]["path"]
        reason = check_file_validation(path, "wrong_hash.bin", index)
        self.assertIsNone(reason)


if __name__ == "__main__":
    unittest.main()
