"""End-to-end ground truth reporting and pack narrowing options."""

from __future__ import annotations

import tests
from tests.sources import script_source
import contextlib
import io
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
import yaml
from model.profiles import load_emulator_profiles
from model.platforms import load_platform_config
from resolve.validation import build_validation_index
from packs.verdicts import Status
from packs.gaps import find_undeclared_files
from packs.emulatorcheck import verify_emulator
from packs.coverage import verify_platform
from tests.e2esupport import E2EFixture


class TestE2EGroundTruth(E2EFixture):
    """Per-emulator ground truth in the validation index and the reports."""

    # ---------------------------------------------------------------
    # Validation index per-emulator ground truth (Task: ground truth)
    # ---------------------------------------------------------------

    def test_111_validation_index_per_emulator(self):
        """Validation index includes per-emulator detail for ground truth."""
        profiles = load_emulator_profiles(self.emulators_dir)
        index = build_validation_index(profiles)
        entry = index["present_req.bin"]
        self.assertIn("per_emulator", entry)
        pe = entry["per_emulator"]
        self.assertIn("test_validation", pe)
        detail = pe["test_validation"]
        self.assertIn("size", detail["checks"])
        self.assertEqual(detail["expected"]["size"], 16)

    def test_112_build_ground_truth(self):
        """build_ground_truth returns per-emulator detail for a filename."""
        from resolve.validation import build_ground_truth

        profiles = load_emulator_profiles(self.emulators_dir)
        index = build_validation_index(profiles)
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
        from resolve.validation import build_ground_truth

        profiles = load_emulator_profiles(self.emulators_dir)
        index = build_validation_index(profiles)
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
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
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
        from packs.report import _format_ground_truth_aggregate

        gt = [
            {
                "emulator": "beetle_psx",
                "checks": ["md5"],
                "source_ref": "libretro.cpp:252",
                "expected": {"md5": "abc"},
            },
            {
                "emulator": "pcsx_rearmed",
                "checks": ["existence"],
                "source_ref": None,
                "expected": {},
            },
        ]
        line = _format_ground_truth_aggregate(gt)
        self.assertIn("beetle_psx", line)
        self.assertIn("[md5]", line)
        self.assertIn("pcsx_rearmed", line)
        self.assertIn("[existence]", line)

    def test_121_format_ground_truth_verbose(self):
        """Verbose format: one line per core with expected values and source ref."""
        from packs.report import _format_ground_truth_verbose

        gt = [
            {
                "emulator": "handy",
                "checks": ["size", "crc32"],
                "source_ref": "rom.h:48-49",
                "expected": {"size": 512, "crc32": "0d973c9d"},
            },
        ]
        lines = _format_ground_truth_verbose(gt)
        self.assertEqual(len(lines), 1)
        self.assertIn("handy", lines[0])
        self.assertIn("size=512", lines[0])
        self.assertIn("crc32=0d973c9d", lines[0])
        self.assertIn("[rom.h:48-49]", lines[0])

    def test_122_format_ground_truth_verbose_no_source_ref(self):
        """Verbose format omits bracket when source_ref is None."""
        from packs.report import _format_ground_truth_verbose

        gt = [
            {
                "emulator": "core_a",
                "checks": ["existence"],
                "source_ref": None,
                "expected": {},
            },
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
        # Simulate --json filtering (non-OK only): ground_truth must survive
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


class TestE2EPackOptions(E2EFixture):
    """Required-only, system, split and hash-list packs and their refusals."""

    def test_130_required_only_excludes_optional(self):
        """--required-only excludes files with required: false from pack."""
        from packs.platformpack import generate_pack

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
                        {
                            "name": "present_req.bin",
                            "destination": "present_req.bin",
                            "required": True,
                        },
                        {
                            "name": "present_opt.bin",
                            "destination": "present_opt.bin",
                            "required": False,
                        },
                    ],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "test_reqonly.yml"), "w") as fh:
            yaml.dump(config, fh)
        zip_path = generate_pack(
            "test_reqonly",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            output_dir,
            required_only=True,
        )
        self.assertIsNotNone(zip_path)
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
        self.assertTrue(any("present_req.bin" in n for n in names))
        self.assertFalse(any("present_opt.bin" in n for n in names))
        # Verify _Required tag in filename
        self.assertIn("_Required_", os.path.basename(zip_path))

    def test_130a_consistency_reads_what_the_builder_and_verify_write(self):
        """Step 5 compares the records the two tools write, not their wording.

        The builder's counts and verify's go through the files the pipeline
        reads, so a reworded line can no longer switch a comparison off.
        """
        from orchestrate.consistency import check_consistency
        from packs.packcounts import PackCounts, write_pack_counts
        from packs.platformpack import build_platform_pack
        from packs.verifyoutput import write_pack_destinations

        profiles = load_emulator_profiles(self.emulators_dir)
        output_dir = os.path.join(self.root, "counted")
        packs: list[tuple[str, list[str], PackCounts]] = []
        groups, group_results = [], []
        for platform in ("test_existence", "test_md5"):
            sink: list[PackCounts] = []
            build_platform_pack(
                platform, self.platforms_dir, self.db, self.bios_dir, output_dir,
                emulators_dir=self.emulators_dir, emu_profiles=profiles, counts=sink,
            )
            self.assertEqual(len(sink), 1)
            packs.append((platform, [platform], sink[0]))
            config = load_platform_config(platform, self.platforms_dir)
            result = verify_platform(config, self.db, self.emulators_dir, emu_profiles=profiles)
            groups.append(([platform], platform))
            group_results.append((result, [config.get("platform", platform)]))
        destinations = os.path.join(self.root, "destinations.json")
        counts = os.path.join(self.root, "counts.json")
        write_pack_destinations(destinations, groups, group_results)
        write_pack_counts(counts, packs)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertTrue(check_consistency(destinations, counts), out.getvalue())
        self.assertEqual(out.getvalue().count("== pack"), 2, out.getvalue())

        skewed = [(label, ids, PackCounts(**{**c.__dict__, "core_files": c.core_files + 1}))
                  for label, ids, c in packs]
        write_pack_counts(counts, skewed)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertFalse(check_consistency(destinations, counts))
        self.assertIn("MISMATCH core files", out.getvalue())

    def test_130b_existence_pack_reports_hash_mismatch(self):
        """Existence mode packs a mismatched file but prints the proof."""
        import contextlib
        import io

        from packs.platformpack import generate_pack

        output_dir = os.path.join(self.root, "pack_mismatch")
        os.makedirs(output_dir, exist_ok=True)
        config = {
            "platform": "MismatchTest",
            "verification_mode": "existence",
            "base_destination": "system",
            "systems": {
                "test-sys": {
                    "files": [
                        {
                            "name": "wrong_hash.bin",
                            "destination": "wrong_hash.bin",
                            "md5": "ffffffffffffffffffffffffffffffff",
                            "required": True,
                        },
                    ],
                },
            },
        }
        with open(os.path.join(self.platforms_dir, "test_mismatch.yml"), "w") as fh:
            yaml.dump(config, fh)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            zip_path = generate_pack(
                "test_mismatch",
                self.platforms_dir,
                self.db,
                self.bios_dir,
                output_dir,
                offline=True,
            )
        self.assertIsNotNone(zip_path)
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
        self.assertTrue(any("wrong_hash.bin" in n for n in names))
        report = out.getvalue()
        self.assertIn("DISCREPANCY", report)
        self.assertIn("declared hash ffffffffffffffffffffffffffffffff", report)

    def test_131_required_only_keeps_default_required(self):
        """--required-only keeps files with no required field (default = required)."""
        from packs.platformpack import generate_pack

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
            "test_reqdef",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            output_dir,
            required_only=True,
        )
        self.assertIsNotNone(zip_path)
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
        self.assertTrue(any("present_req.bin" in n for n in names))

    def test_132_platform_system_filter(self):
        """--platform + --system filters systems within a platform pack."""
        from packs.platformpack import generate_pack

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
            "test_sysfilter",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            output_dir,
            system_filter=["system-a"],
        )
        self.assertIsNotNone(zip_path)
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
        self.assertTrue(any("present_req.bin" in n for n in names))
        self.assertFalse(any("present_opt.bin" in n for n in names))

    def test_133_platform_system_filter_normalized(self):
        """norm_system_id normalization matches with manufacturer prefix."""
        from model.systems import norm_system_id

        self.assertEqual(
            norm_system_id("sony-playstation"),
            norm_system_id("playstation"),
        )

    def test_134_list_systems_platform_context(self):
        """list_platform_system_ids lists systems from a platform YAML."""
        import io

        from model.cliargs import list_platform_system_ids

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

            from core.hashing import compute_hashes

            ha = compute_hashes(file_a)
            hb = compute_hashes(file_b)

            db = {
                "files": {
                    ha["sha1"]: {
                        "name": "bios_a.bin",
                        "md5": ha["md5"],
                        "sha1": ha["sha1"],
                        "sha256": ha["sha256"],
                        "path": file_a,
                        "paths": [file_a],
                    },
                    hb["sha1"]: {
                        "name": "bios_b.bin",
                        "md5": hb["md5"],
                        "sha1": hb["sha1"],
                        "sha256": hb["sha256"],
                        "path": file_b,
                        "paths": [file_b],
                    },
                },
                "indexes": {
                    "by_md5": {ha["md5"]: ha["sha1"], hb["md5"]: hb["sha1"]},
                    "by_name": {"bios_a.bin": [ha["sha1"]], "bios_b.bin": [hb["sha1"]]},
                    "by_crc32": {},
                    "by_path_suffix": {},
                },
            }

            registry = {"platforms": {"splitplat": {"config": "splitplat.yml"}}}
            with open(os.path.join(plat_dir, "_registry.yml"), "w") as f:
                yaml.dump(registry, f)
            plat_cfg = {
                "platform": "SplitTest",
                "verification_mode": "existence",
                "systems": {
                    "test-system-a": {
                        "files": [{"name": "bios_a.bin", "sha1": ha["sha1"]}]
                    },
                    "test-system-b": {
                        "files": [{"name": "bios_b.bin", "sha1": hb["sha1"]}]
                    },
                },
            }
            with open(os.path.join(plat_dir, "splitplat.yml"), "w") as f:
                yaml.dump(plat_cfg, f)

            from core.ziptools import build_zip_contents_index
            from model.profiles import load_emulator_profiles
            from packs.platformpack import generate_split_packs

            zip_contents = build_zip_contents_index(db, Path(tmpdir))
            emu_profiles = load_emulator_profiles(emu_dir)

            zip_paths = generate_split_packs(
                "splitplat",
                plat_dir,
                db,
                os.path.join(tmpdir, "bios"),
                out_dir,
                emulators_dir=emu_dir,
                zip_contents=zip_contents,
                emu_profiles=emu_profiles,
                group_by="system",
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
        from model.systems import derive_manufacturer

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
        self.assertEqual(
            derive_manufacturer("arcade", {"manufacturer": "Various"}), "Other"
        )
        # Fallback
        self.assertEqual(derive_manufacturer("dos", {}), "Other")

    def test_137_group_systems_by_manufacturer(self):
        """_group_systems_by_manufacturer groups correctly."""
        from packs.platformpack import _group_systems_by_manufacturer

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
        from packs.hashinput import parse_hash_input

        # Plain MD5
        result = parse_hash_input("d8f1206299c48946e6ec5ef96d014eaa")
        self.assertEqual(result, [("md5", "d8f1206299c48946e6ec5ef96d014eaa")])
        # Comma-separated
        result = parse_hash_input(
            "d8f1206299c48946e6ec5ef96d014eaa,d8f1206299c48946e6ec5ef96d014eab"
        )
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
        from packs.hashinput import parse_hash_file

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
        """lookup_hashes returns the record of a known hash."""
        from resolve.packfiles import HashLookup, lookup_hashes

        db = {
            "files": {
                "sha1abc": {
                    "name": "test.bin",
                    "md5": "md5abc",
                    "sha1": "sha1abc",
                    "sha256": "sha256abc",
                    "path": "bios/Mfr/Console/test.bin",
                },
            },
            "indexes": {
                "by_md5": {"md5abc": "sha1abc"},
                "by_crc32": {},
            },
        }
        records = lookup_hashes([("md5", "md5abc")], db, "bios")
        # The record's path, the one field the schema gives it. A read of
        # "paths" printed nothing.
        self.assertEqual(records, [HashLookup(
            "md5", "md5abc", "sha1abc", "md5abc", "test.bin",
            "bios/Mfr/Console/test.bin", False,
        )])
        self.assertTrue(records[0].found)

    def test_140b_lookup_hashes_never_downloads_a_release_asset(self):
        """A release asset counted as held streamed the whole asset first."""
        from unittest import mock

        from resolve import packfiles

        path = "bios/Mfr/Console/big.zip"
        db = {
            "files": {"sha1big": {"name": "big.zip", "md5": "md5big",
                                  "sha1": "sha1big", "path": path}},
            "indexes": {"by_md5": {"md5big": "sha1big"}, "by_crc32": {}},
        }
        seen: list[bool] = []

        def fetch(_path, expected_sha1=None, offline=False):
            seen.append(offline)

        with mock.patch("model.largefiles.load_registered_paths", return_value=[path]), \
                mock.patch.object(packfiles, "fetch_large_file", side_effect=fetch), \
                mock.patch.dict(os.environ, {"RETROBIOS_OFFLINE": ""}), \
                mock.patch.object(packfiles, "OFFLINE", False):
            records = packfiles.lookup_hashes([("md5", "md5big")], db, "bios")
        self.assertTrue(records[0].in_repo)
        self.assertEqual(seen, [True])

    def test_141_lookup_hashes_not_found(self):
        """lookup_hashes reports unknown hashes, and the report counts them."""
        import contextlib
        import io

        from packs.hashlookup import print_hash_lookup
        from resolve.packfiles import lookup_hashes

        db = {"files": {}, "indexes": {"by_md5": {}, "by_crc32": {}}}
        unknown = "unknown123" + "0" * 22
        records = lookup_hashes([("md5", unknown)], db, "bios")
        self.assertEqual([r.found for r in records], [False])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            missing = print_hash_lookup(records)
        self.assertIn("NOT FOUND", buf.getvalue())
        # The CLI exited 0 on this, so a script read "found".
        self.assertEqual(missing, 1)

    def test_141b_lookup_report_names_the_file(self):
        """The printed report gives the file's hashes, name, path and presence."""
        import contextlib
        import io

        from packs.hashlookup import print_hash_lookup
        from resolve.packfiles import HashLookup

        record = HashLookup("md5", "md5abc", "sha1abc", "md5abc", "test.bin",
                            "bios/Mfr/Console/test.bin", True)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            missing = print_hash_lookup([record])
        self.assertEqual(buf.getvalue(), (
            "\nMD5: md5abc\n  SHA1: sha1abc\n  MD5:  md5abc\n  Name: test.bin\n"
            "  Path: bios/Mfr/Console/test.bin\n  In repo: YES\n"
        ))
        self.assertEqual(missing, 0)

    def test_142_from_md5_platform_pack(self):
        """--from-md5 with --platform generates correctly laid out ZIP."""
        import tempfile
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
            from core.hashing import compute_hashes

            h = compute_hashes(bios_file)

            db = {
                "files": {
                    h["sha1"]: {
                        "name": "scph5501.bin",
                        "md5": h["md5"],
                        "sha1": h["sha1"],
                        "sha256": h["sha256"],
                        "path": bios_file,
                        "paths": ["Sony/PS1/scph5501.bin"],
                    },
                },
                "indexes": {
                    "by_md5": {h["md5"]: h["sha1"]},
                    "by_name": {"scph5501.bin": [h["sha1"]]},
                    "by_crc32": {},
                    "by_path_suffix": {},
                },
            }

            registry = {"platforms": {"testplat": {"config": "testplat.yml"}}}
            with open(os.path.join(plat_dir, "_registry.yml"), "w") as f:
                yaml.dump(registry, f)
            plat_cfg = {
                "platform": "TestPlat",
                "verification_mode": "md5",
                "base_destination": "bios",
                "systems": {
                    "sony-playstation": {
                        "files": [
                            {
                                "name": "scph5501.bin",
                                "md5": h["md5"],
                                "destination": "scph5501.bin",
                            },
                        ]
                    }
                },
            }
            with open(os.path.join(plat_dir, "testplat.yml"), "w") as f:
                yaml.dump(plat_cfg, f)

            from core.ziptools import build_zip_contents_index
            from packs.md5pack import generate_md5_pack

            zip_contents = build_zip_contents_index(db, Path(tmpdir))

            zip_path = generate_md5_pack(
                hashes=[("md5", h["md5"])],
                db=db,
                bios_dir=bios_dir,
                output_dir=out_dir,
                zip_contents=zip_contents,
                platform_name="testplat",
                platforms_dir=plat_dir,
            ).zip_path
            self.assertIsNotNone(zip_path)
            with zipfile.ZipFile(zip_path) as zf:
                names = zf.namelist()
            self.assertIn("bios/scph5501.bin", names)
            self.assertIn("Custom", os.path.basename(zip_path))

            # A profile displayed under the platform's own name: BizHawk is
            # both. The two layouts must not write one file.
            emu_dir = os.path.join(tmpdir, "emulators-md5")
            os.makedirs(emu_dir)
            with open(os.path.join(emu_dir, "testplat.yml"), "w") as f:
                yaml.dump({
                    "emulator": "TestPlat", "type": "standalone",
                    "systems": ["sony-playstation"],
                    "files": [{"name": "scph5501.bin", "md5": h["md5"]}],
                }, f)
            emu_zip = generate_md5_pack(
                hashes=[("md5", h["md5"])],
                db=db,
                bios_dir=bios_dir,
                output_dir=out_dir,
                zip_contents=zip_contents,
                emulator_name="testplat",
                emulators_dir=emu_dir,
            ).zip_path
            self.assertIsNotNone(emu_zip)
            self.assertNotEqual(os.path.basename(emu_zip), os.path.basename(zip_path))
            self.assertTrue(os.path.exists(zip_path))
            with zipfile.ZipFile(emu_zip) as zf:
                self.assertIn("scph5501.bin", zf.namelist())

    def test_143_from_md5_not_in_repo(self):
        """--from-md5 reports files in DB but missing from repo."""
        import contextlib
        import io
        import tempfile

        from packs.md5pack import generate_md5_pack

        db = {
            "files": {
                "sha1known": {
                    "name": "missing.bin",
                    "md5": "md5known" + "0" * 25,
                    "sha1": "sha1known",
                    "sha256": "sha256known",
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
                outcome = generate_md5_pack(
                    hashes=[("md5", "md5known" + "0" * 25)],
                    db=db,
                    bios_dir=bios_dir,
                    output_dir=out_dir,
                    zip_contents={},
                )
            self.assertEqual(buf.getvalue(), "")
            self.assertEqual(outcome.not_in_repo, [("missing.bin", "md5known" + "0" * 25)])
            self.assertEqual((outcome.packed, outcome.not_in_db), ([], []))
            self.assertIsNone(outcome.zip_path)
            from packs.packmodes import print_hash_pack
            with contextlib.redirect_stdout(buf):
                print_hash_pack(outcome)
            self.assertIn("NOT IN REPO: missing.bin", buf.getvalue())

    def test_144_invalid_split_emulator(self):
        """--split + --emulator is rejected."""
        import subprocess

        result = subprocess.run(
            ["python", "scripts/generate_pack.py", "--emulator", "test", "--split"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error", result.stderr.lower())

    def test_145_invalid_from_md5_all(self):
        """--from-md5 + --all is rejected."""
        import subprocess

        result = subprocess.run(
            [
                "python",
                "scripts/generate_pack.py",
                "--all",
                "--from-md5",
                "abc123" + "0" * 26,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_146_invalid_from_md5_system(self):
        """--from-md5 + --system is rejected."""
        import subprocess

        result = subprocess.run(
            [
                "python",
                "scripts/generate_pack.py",
                "--system",
                "psx",
                "--from-md5",
                "abc123" + "0" * 26,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_147_invalid_group_by_without_split(self):
        """--group-by without --split is rejected."""
        import subprocess

        result = subprocess.run(
            [
                "python",
                "scripts/generate_pack.py",
                "--platform",
                "retroarch",
                "--group-by",
                "manufacturer",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_148_valid_platform_system(self):
        """--platform + --system is accepted (not rejected at validation stage)."""
        import argparse

        from model.cliargs import mode_conflicts

        def refused(**given: object) -> list[str]:
            args = argparse.Namespace(**{
                "platform": None, "all": False, "emulator": None, "system": None,
                "standalone": False, "target": None, "no_game_data": False, **given,
            })
            return [message for on, message in mode_conflicts(args) if on]

        self.assertEqual(refused(platform="retroarch", system="psx"), [])
        self.assertEqual(refused(all=True, system="psx"), [])
        self.assertEqual(refused(system="psx", standalone=True), [])
        # One table for verify and generate_pack: verify took --all --system
        # --standalone and dropped --standalone.
        self.assertTrue(refused(all=True, system="psx", standalone=True))
        self.assertTrue(refused(emulator="handy", system="psx"))
        self.assertTrue(refused(platform="retroarch", all=True))
        self.assertTrue(refused(system="psx", target="switch"))
        self.assertTrue(refused(emulator="handy", no_game_data=True))
        self.assertIn("Specify --platform, --all, --emulator, --system or --from-md5", [
            message for on, message in mode_conflicts(
                argparse.Namespace(platform=None, all=False, emulator=None, system=None,
                                   standalone=False),
                (("--from-md5", False),),
            ) if on
        ])
        for script in ("verify.py", "generate_pack.py"):
            self.assertIn("mode_conflicts(args", script_source(script), script)


if __name__ == "__main__":
    unittest.main()
