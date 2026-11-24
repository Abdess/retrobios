"""End-to-end scraper parsing, archive cross-reference, truth generation and manifests."""

from __future__ import annotations

import tests
import os
import unittest
import zipfile
import yaml
from model.profiles import load_emulator_profiles
from model.platforms import load_platform_config
from resolve.localfile import resolve_local_file
from resolve.truth import generate_platform_truth
from packs.gaps import find_undeclared_files
from tests.e2esupport import E2EFixture


class TestE2EBizHawkScraper(E2EFixture):
    """The BizHawk FirmwareDatabase.cs parser."""

    # BizHawk scraper tests

    def test_150_bizhawk_scraper_parse_firmware_and_option(self):
        """Parse FirmwareAndOption() one-liner pattern."""
        from scraper.bizhawk_scraper import parse_firmware_database

        fragment = """
            FirmwareAndOption("DBEBD76A448447CB6E524AC3CB0FD19FC065D944", 256, "32X", "G", "32X_G_BIOS.BIN", "32x 68k BIOS");
            FirmwareAndOption("1E5B0B2441A4979B6966D942B20CC76C413B8C5E", 2048, "32X", "M", "32X_M_BIOS.BIN", "32x SH2 MASTER BIOS");
        """
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

        fragment = """
            var gbaNormal = File("300C20DF6731A33952DED8C436F7F186D25D3492", 16384, "GBA_bios.rom", "Bios (World)");
            Firmware("GBA", "Bios", "Bios");
            Option("GBA", "Bios", in gbaNormal, FirmwareOptionStatus.Ideal);
        """
        records, files = parse_firmware_database(fragment)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["system"], "GBA")
        self.assertEqual(records[0]["sha1"], "300C20DF6731A33952DED8C436F7F186D25D3492")
        self.assertEqual(records[0]["name"], "GBA_bios.rom")
        self.assertEqual(records[0]["status"], "Ideal")

    def test_152_bizhawk_scraper_skips_comments(self):
        """Commented-out blocks (PS2) are skipped."""
        from scraper.bizhawk_scraper import parse_firmware_database

        fragment = """
            FirmwareAndOption("DBEBD76A448447CB6E524AC3CB0FD19FC065D944", 256, "32X", "G", "32X_G_BIOS.BIN", "32x 68k BIOS");
            /*
            Firmware("PS2", "BIOS", "PS2 Bios");
            Option("PS2", "BIOS", File("FBD54BFC020AF34008B317DCB80B812DD29B3759", 4194304, "ps2.bin", "PS2 Bios"));
            */
        """
        records, files = parse_firmware_database(fragment)
        systems = {r["system"] for r in records}
        self.assertNotIn("PS2", systems)
        self.assertEqual(len(records), 1)

    def test_152b_bizhawk_scraper_skips_line_comments(self):
        """FirmwareDatabase.cs 2.11.1 comments out two MSX options with //:
        read as live, they were listed required."""
        from scraper.bizhawk_scraper import parse_firmware_database

        fragment = """
            FirmwareAndOption("DBEBD76A448447CB6E524AC3CB0FD19FC065D944", 256, "32X", "G", "32X_G_BIOS.BIN", "see http://x");
            //FirmwareAndOption("E998F0C441F4F1800EF44E42CD1659150206CF79", 32768, "MSX", "bios_pal", "MSX_8020-20bios.rom", "MSX");
        """
        records, _ = parse_firmware_database(fragment)
        self.assertEqual([r["name"] for r in records], ["32X_G_BIOS.BIN"])

    def test_153_bizhawk_scraper_arithmetic_size(self):
        """Size expressions like 4 * 1024 * 1024 are evaluated."""
        from scraper.bizhawk_scraper import parse_firmware_database

        fragment = """
            FirmwareAndOption("BF861922DCB78C316360E3E742F4F70FF63C9BC3", 4 * 1024 * 1024, "N64DD", "IPL_JPN", "64DD_IPL.bin", "N64DD JPN IPL");
        """
        records, _ = parse_firmware_database(fragment)
        self.assertEqual(records[0]["size"], 4194304)

    def test_154_bizhawk_scraper_dummy_hash(self):
        """SHA1Checksum.Dummy entries get no sha1 field."""
        from scraper.bizhawk_scraper import parse_firmware_database

        fragment = """
            FirmwareAndOption(SHA1Checksum.Dummy, 0, "3DS", "aes_keys", "aes_keys.txt", "AES Keys");
        """
        records, _ = parse_firmware_database(fragment)
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0]["sha1"])

    def test_155_bizhawk_scraper_multi_option_picks_ideal(self):
        """When multiple options exist, Ideal is selected as canonical."""
        from scraper.bizhawk_scraper import parse_firmware_database

        fragment = """
            var ss_100_j = File("2B8CB4F87580683EB4D760E4ED210813D667F0A2", 524288, "SAT_1.00-(J).bin", "Bios v1.00 (J)");
            var ss_101_j = File("DF94C5B4D47EB3CC404D88B33A8FDA237EAF4720", 524288, "SAT_1.01-(J).bin", "Bios v1.01 (J)");
            Firmware("SAT", "J", "Bios (J)");
            Option("SAT", "J", in ss_100_j);
            Option("SAT", "J", in ss_101_j, FirmwareOptionStatus.Ideal);
        """
        records, _ = parse_firmware_database(fragment)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["sha1"], "DF94C5B4D47EB3CC404D88B33A8FDA237EAF4720")
        self.assertEqual(records[0]["name"], "SAT_1.01-(J).bin")

    def test_156_bizhawk_scraper_is_bad_excluded(self):
        """Files with isBad: true are not selected as canonical."""
        from scraper.bizhawk_scraper import parse_firmware_database

        fragment = """
            var good = File("AAAA", 100, "good.bin", "Good");
            var bad = File("BBBB", 100, "bad.bin", "Bad", isBad: true);
            Firmware("TEST", "X", "Test");
            Option("TEST", "X", in bad);
            Option("TEST", "X", in good, FirmwareOptionStatus.Ideal);
        """
        records, _ = parse_firmware_database(fragment)
        self.assertEqual(records[0]["name"], "good.bin")


class TestE2EPathConflicts(E2EFixture):
    """File and directory naming collisions in a pack."""

    def test_157_path_conflict_helpers(self):
        """has_path_conflict detects file/directory naming collisions."""
        from packs.paths import has_path_conflict, register_path

        seen_files: set[str] = set()
        seen_parents: set[str] = set()

        # Register system/SGB1.sfc as a file
        register_path("system/SGB1.sfc", seen_files, seen_parents)

        # Adding system/SGB1.sfc/program.rom should conflict (parent is a file)
        self.assertTrue(
            has_path_conflict("system/SGB1.sfc/program.rom", seen_files, seen_parents)
        )

        # Adding system/other.bin should not conflict
        self.assertFalse(
            has_path_conflict("system/other.bin", seen_files, seen_parents)
        )

        # Reverse: register a nested path first, then check flat
        seen_files2: set[str] = set()
        seen_parents2: set[str] = set()
        register_path("system/SGB2.sfc/program.rom", seen_files2, seen_parents2)

        # Adding system/SGB2.sfc as a file should conflict (it's a directory)
        self.assertTrue(
            has_path_conflict("system/SGB2.sfc", seen_files2, seen_parents2)
        )

        # Adding system/SGB2.sfc/boot.rom should not conflict (sibling in same dir)
        self.assertFalse(
            has_path_conflict("system/SGB2.sfc/boot.rom", seen_files2, seen_parents2)
        )

    def test_158_pack_skips_file_directory_conflict(self):
        """Pack generation skips entries that conflict with existing paths."""
        from packs.platformpack import generate_pack

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
                        {
                            "name": "present_req.bin",
                            "destination": "present_req.bin",
                            "required": True,
                        },
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
            "test_conflict",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            output_dir,
            emulators_dir=self.emulators_dir,
            offline=True,
        )
        self.assertIsNotNone(zip_path)
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
        # Flat file should be present
        self.assertTrue(
            any("present_req.bin" in n and "/" + "nested" not in n for n in names)
        )
        # Nested conflict should NOT be present
        self.assertFalse(any("nested.rom" in n for n in names))


class TestE2EArchiveCrossRef(E2EFixture):
    """Archive cross-reference, descriptive names and data directory fallback."""

    # ---------------------------------------------------------------
    # Archive cross-reference and descriptive name tests
    # ---------------------------------------------------------------

    def test_159_cross_ref_archive_in_repo(self):
        """Archived files group by archive, in_repo=True when archive exists."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
        # test_archive.zip should appear as a single grouped entry
        archive_entries = [
            u for u in undeclared if u.get("archive") == "test_archive.zip"
        ]
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
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
        missing_entries = [
            u for u in undeclared if u.get("archive") == "missing_archive.zip"
        ]
        self.assertEqual(len(missing_entries), 1)
        entry = missing_entries[0]
        self.assertFalse(entry["in_repo"])
        self.assertEqual(entry["name"], "missing_archive.zip")
        self.assertEqual(entry["archive_file_count"], 1)

    def test_161_cross_ref_archive_not_individual_roms(self):
        """Individual ROM names from archived files should NOT appear as separate entries."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
        names = {u["name"] for u in undeclared}
        # Individual ROMs should NOT be in the undeclared list
        self.assertNotIn("rom_a.bin", names)
        self.assertNotIn("rom_b.bin", names)
        self.assertNotIn("missing_rom.bin", names)

    def test_162_cross_ref_descriptive_name_resolved_by_path(self):
        """Descriptive name with path: fallback resolves via path basename."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
        desc_entries = {
            u["name"]: u for u in undeclared if u["emulator"] == "TestDescriptive"
        }
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
                        {
                            "name": "test_archive.zip",
                            "destination": "test_archive.zip",
                            "required": True,
                        },
                    ],
                },
            },
        }
        with open(
            os.path.join(self.platforms_dir, "test_archive_platform.yml"), "w"
        ) as fh:
            yaml.dump(config, fh)
        config = load_platform_config("test_archive_platform", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
        # test_archive.zip is declared ->its archived ROMs should be skipped
        archive_entries = [
            u for u in undeclared if u.get("archive") == "test_archive.zip"
        ]
        self.assertEqual(len(archive_entries), 0)

    def test_164_pack_extras_use_archive_name(self):
        """Pack extras for archived files use archive name, not individual ROM."""
        from packs.extras import collect_emulator_extras

        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        extras = collect_emulator_extras(
            config,
            self.emulators_dir,
            self.db,
            set(),
            "",
            profiles,
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
        from packs.extras import collect_emulator_extras

        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        extras = collect_emulator_extras(
            config,
            self.emulators_dir,
            self.db,
            set(),
            "",
            profiles,
        )
        extra_dests = {e["destination"] for e in extras}
        # Root destination (from test_emu or test_root_core, no path)
        self.assertIn("present_req.bin", extra_dests)
        # Subdirectory destination (from test_subdir_core)
        self.assertIn("subcore/bios/present_req.bin", extra_dests)

    def test_166_pack_extras_multi_dest_platform_declared(self):
        """Profile with path different from platform destination adds alternative."""
        from packs.extras import collect_emulator_extras

        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        # Simulate platform already having present_req.bin at root
        seen = {"present_req.bin"}
        extras = collect_emulator_extras(
            config,
            self.emulators_dir,
            self.db,
            seen,
            "",
            profiles,
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

    def test_167b_unsourceable_skips_data_dir_name_match(self):
        """The cache walk matches on filename, so unsourceable has to skip it."""
        data_dir = os.path.join(self.root, "data", "other-core")
        os.makedirs(data_dir, exist_ok=True)
        with open(os.path.join(data_dir, "shared_name.dat"), "wb") as f:
            f.write(b"ANOTHER CORE DEFINITIONS")

        registry = {"other-core": {"local_cache": data_dir}}

        fe = {"name": "shared_name.dat", "unsourceable": "ships inside the package"}
        path, status = resolve_local_file(fe, self.db, data_dir_registry=registry)
        self.assertIsNone(path)
        self.assertEqual(status, "not_found")

        # A declared hash is content proof, so the cache still answers for it.
        import hashlib

        digest = hashlib.sha1(b"ANOTHER CORE DEFINITIONS").hexdigest()
        fe = {
            "name": "shared_name.dat",
            "sha1": digest,
            "unsourceable": "ships inside the package",
        }
        path, status = resolve_local_file(fe, self.db, data_dir_registry=registry)
        self.assertIsNotNone(path)
        self.assertEqual(status, "data_dir_hash_exact")


class TestE2EGenerateTruth(E2EFixture):
    """generate_platform_truth over the synthetic profiles."""

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
        from model.profiles import emulator_profiles_cache

        emulator_profiles_cache.clear()

        profiles = load_emulator_profiles(self.emulators_dir)
        config = {"cores": ["testcore"]}

        result = generate_platform_truth(
            "testplat",
            config,
            {},
            profiles,
            db=None,
            data_registry={},
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
        from model.profiles import emulator_profiles_cache

        profile = {
            "emulator": "DualMode",
            "type": "standalone + libretro",
            "systems": ["test-system"],
            "cores": ["dualmode"],
            "files": [
                {
                    "name": "both.bin",
                    "system": "test-system",
                    "required": True,
                    "mode": "both",
                    "sha1": "aaaa",
                },
                {
                    "name": "lr_only.bin",
                    "system": "test-system",
                    "required": True,
                    "mode": "libretro",
                    "sha1": "bbbb",
                },
                {
                    "name": "sa_only.bin",
                    "system": "test-system",
                    "required": True,
                    "mode": "standalone",
                    "sha1": "cccc",
                },
                {"name": "nomode.bin", "system": "test-system", "required": True, "sha1": "dddd"},
            ],
        }
        with open(os.path.join(self.emulators_dir, "dualmode.yml"), "w") as f:
            _yaml.dump(profile, f)

        emulator_profiles_cache.clear()
        profiles = load_emulator_profiles(self.emulators_dir)
        config = {"cores": "all_libretro"}

        result = generate_platform_truth("testplat", config, {}, profiles, data_registry={})
        names = {fe["name"] for fe in result["systems"]["test-system"]["files"]}

        self.assertIn("both.bin", names)
        self.assertIn("lr_only.bin", names)
        self.assertIn("nomode.bin", names)
        self.assertNotIn("sa_only.bin", names)

    def test_170_generate_truth_standalone_cores(self):
        """generate_platform_truth uses standalone mode for standalone_cores."""
        import yaml as _yaml
        from model.profiles import emulator_profiles_cache

        profile = {
            "emulator": "DualCore",
            "type": "standalone + libretro",
            "systems": ["test-system"],
            "cores": ["dualcore"],
            "files": [
                {
                    "name": "lr_file.bin",
                    "system": "test-system",
                    "required": True,
                    "mode": "libretro",
                    "sha1": "aaaa",
                },
                {
                    "name": "sa_file.bin",
                    "system": "test-system",
                    "required": True,
                    "mode": "standalone",
                    "sha1": "bbbb",
                },
            ],
        }
        with open(os.path.join(self.emulators_dir, "dualcore.yml"), "w") as f:
            _yaml.dump(profile, f)

        emulator_profiles_cache.clear()
        profiles = load_emulator_profiles(self.emulators_dir)
        config = {
            "cores": ["dualcore"],
            "standalone_cores": ["dualcore"],
        }

        result = generate_platform_truth("testplat", config, {}, profiles, data_registry={})
        names = {fe["name"] for fe in result["systems"]["test-system"]["files"]}

        self.assertIn("sa_file.bin", names)
        self.assertNotIn("lr_file.bin", names)

    def test_171_generate_truth_dedup_required_wins(self):
        """Dedup merges cores and required=True wins over required=False."""
        import yaml as _yaml
        from model.profiles import emulator_profiles_cache

        core_a = {
            "emulator": "CoreA",
            "type": "libretro",
            "systems": ["test-system"],
            "cores": ["core_a"],
            "files": [
                {
                    "name": "shared.bin",
                    "system": "test-system",
                    "required": False,
                    "source_ref": "a.cpp:10",
                    "sha1": "aaaa",
                },
            ],
        }
        core_b = {
            "emulator": "CoreB",
            "type": "libretro",
            "systems": ["test-system"],
            "cores": ["core_b"],
            "files": [
                {
                    "name": "shared.bin",
                    "system": "test-system",
                    "required": True,
                    "source_ref": "b.cpp:20",
                    "sha1": "aaaa",
                },
            ],
        }
        for name, data in [("core_a", core_a), ("core_b", core_b)]:
            with open(os.path.join(self.emulators_dir, f"{name}.yml"), "w") as f:
                _yaml.dump(data, f)

        emulator_profiles_cache.clear()
        profiles = load_emulator_profiles(self.emulators_dir)
        config = {"cores": ["core_a", "core_b"]}

        result = generate_platform_truth("testplat", config, {}, profiles, data_registry={})
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
        from model.profiles import emulator_profiles_cache

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

        emulator_profiles_cache.clear()
        profiles = load_emulator_profiles(self.emulators_dir)
        config = {"cores": ["profiled_core", "unprofiled_core"]}

        result = generate_platform_truth("testplat", config, {}, profiles, data_registry={})
        cov = result["_coverage"]

        self.assertEqual(cov["cores_profiled"], 1)
        self.assertNotIn(
            "unprofiled_core", [name for name in profiles if name == "unprofiled_core"]
        )
        # unprofiled_core has no profile YAML so resolve_platform_cores
        # won't include it, so cores_resolved reflects only matched profiles
        self.assertEqual(cov["cores_resolved"], 1)
        self.assertNotIn("unprofiled_core", cov["cores_unprofiled"])


class TestE2EManifest(E2EFixture):
    """Install manifests and their agreement with the ZIP."""

    def test_90_registry_install_metadata(self):
        """Registry install section is accessible."""
        import yaml

        with open("platforms/_registry.yml") as f:
            registry = yaml.safe_load(f)
        for name in (
            "retroarch",
            "batocera",
            "emudeck",
            "recalbox",
            "retrobat",
            "retrodeck",
            "lakka",
            "romm",
            "bizhawk",
        ):
            plat = registry["platforms"][name]
            self.assertIn("install", plat, f"{name} missing install section")
            self.assertIn("detect", plat["install"])
            self.assertIsInstance(plat["install"]["detect"], list)
            for hint in plat["install"]["detect"]:
                self.assertIn("os", hint)
        # EmuDeck has standalone_copies
        self.assertIn(
            "standalone_copies",
            registry["platforms"]["emudeck"]["install"],
        )

    def test_91_manifest_required_only_drops_optional_files(self):
        """A manifest named _required must hold only the required files.

        The filename carried the narrowing while the content did not, so
        install.py fetched every optional file for a user who asked for the
        required set, and --all-variants wrote three manifests that duplicated
        their non-required twins.
        """
        from packs.manifest import generate_manifest

        registry_path = os.path.join(self.platforms_dir, "_test_registry.yml")
        with open(registry_path, "w") as fh:
            yaml.dump({"platforms": {"test_existence": {"install": {}}}}, fh)

        def names(required_only):
            manifest = generate_manifest(
                "test_existence",
                self.platforms_dir,
                self.db,
                self.bios_dir,
                registry_path,
                emulators_dir=self.emulators_dir,
                offline=True,
                required_only=required_only,
            )
            return {entry["dest"] for entry in manifest["files"]}

        every = names(False)
        required = names(True)
        self.assertIn("present_req.bin", every)
        self.assertIn("present_opt.bin", every)
        self.assertIn("present_req.bin", required)
        self.assertNotIn(
            "present_opt.bin",
            required,
            "an optional file reached a manifest built with required_only",
        )

    def test_91_generate_manifest(self):
        """generate_manifest returns valid manifest dict with expected fields."""
        from packs.manifest import generate_manifest

        # Create a minimal registry file for the test
        registry_path = os.path.join(self.platforms_dir, "_test_registry.yml")
        registry_data = {
            "platforms": {
                "test_existence": {
                    "install": {
                        "detect": [
                            {
                                "os": "linux",
                                "method": "path_exists",
                                "path": "/test/bios",
                            }
                        ],
                    },
                },
            },
        }
        with open(registry_path, "w") as fh:
            yaml.dump(registry_data, fh)

        manifest = generate_manifest(
            "test_existence",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            registry_path,
            emulators_dir=self.emulators_dir,
            offline=True,
        )

        self.assertEqual(manifest["manifest_version"], 2)
        self.assertEqual(manifest["regions"], [])
        self.assertEqual(manifest["platform"], "test_existence")
        self.assertEqual(manifest["display_name"], "TestExistence")
        self.assertIn("generated", manifest)
        self.assertIn("files", manifest)
        self.assertIsInstance(manifest["files"], list)
        self.assertEqual(manifest["total_files"], len(manifest["files"]))
        self.assertEqual(manifest["total_omitted"], len(manifest["omitted_files"]))
        self.assertGreater(len(manifest["files"]), 0)
        self.assertEqual(manifest["base_destination"], "system")
        self.assertEqual(
            manifest["detect"],
            registry_data["platforms"]["test_existence"]["install"]["detect"],
        )

        for f in manifest["files"]:
            self.assertIn("dest", f)
            self.assertIn("sha1", f)
            self.assertIn("size", f)
            self.assertIn("repo_path", f)
            self.assertIn("cores", f)
            self.assertIsInstance(f["size"], int)
            self.assertGreater(len(f["sha1"]), 0)

    def test_91_manifest_version_is_the_platform_list_version(self):
        """The manifest names the version of the list it was built from.

        It was the constant "1.0" for every platform, so the installer could
        not tell which Batocera or Recalbox release a list described. Two
        platforms of different versions show the value comes from each YAML.
        A YAML without one, an inheriting child included, is refused rather
        than written with a stand-in or its parent's version.
        """
        from model.platforms import _platform_config_cache
        from packs.manifest import generate_manifest

        registry_path = os.path.join(self.platforms_dir, "_test_registry_version.yml")
        with open(registry_path, "w") as fh:
            yaml.dump({"platforms": {}}, fh)
        with open(os.path.join(self.platforms_dir, "test_md5.yml")) as fh:
            config = yaml.safe_load(fh)
        config["version"] = "41"
        with open(os.path.join(self.platforms_dir, "versioned_md5.yml"), "w") as fh:
            yaml.dump(config, fh)
        del config["version"]
        with open(os.path.join(self.platforms_dir, "unversioned.yml"), "w") as fh:
            yaml.dump(config, fh)
        _platform_config_cache.clear()

        def version_of(name: str) -> str:
            return generate_manifest(
                name, self.platforms_dir, self.db, self.bios_dir, registry_path,
                emulators_dir=self.emulators_dir, offline=True,
            )["version"]

        self.assertEqual(version_of("test_existence"), "9.1")
        self.assertEqual(version_of("versioned_md5"), "41")
        for name in ("unversioned", "test_inherited"):
            with self.subTest(platform=name), \
                    self.assertRaisesRegex(ValueError, "records no version"):
                version_of(name)
        with open(os.path.join(self.platforms_dir, "test_inherited.yml")) as fh:
            child = yaml.safe_load(fh)
        child["version"] = "2"
        with open(os.path.join(self.platforms_dir, "test_inherited.yml"), "w") as fh:
            yaml.dump(child, fh)
        _platform_config_cache.clear()
        self.assertEqual(version_of("test_inherited"), "2")

    def test_91b_manifest_hash_points_at_a_fetchable_file(self):
        """A declared hash no local file carries must not blank repo_path.

        install.py builds its download URL from repo_path, so an upstream
        hash that resolves to nothing leaves the file unfetchable.
        """
        from packs.manifest import generate_manifest

        registry_path = os.path.join(self.platforms_dir, "_test_registry2.yml")
        with open(registry_path, "w") as fh:
            yaml.dump({"platforms": {"test_existence": {"install": {}}}}, fh)

        config_path = os.path.join(self.platforms_dir, "test_existence.yml")
        with open(config_path) as fh:
            config = yaml.safe_load(fh)
        for system in config.get("systems", {}).values():
            for entry in system.get("files", []):
                entry["sha1"] = "0" * 40  # upstream hash, absent from the repo
        with open(config_path, "w") as fh:
            yaml.dump(config, fh)
        from model.platforms import _platform_config_cache

        _platform_config_cache.clear()

        manifest = generate_manifest(
            "test_existence",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            registry_path,
            emulators_dir=self.emulators_dir,
            offline=True,
        )

        self.assertGreater(len(manifest["files"]), 0)
        self.assertGreater(len(manifest["omitted_files"]), 0)
        self.assertTrue(
            all(
                entry["reason"] in {"hash_mismatch", "not_found"}
                for entry in manifest["omitted_files"]
                if entry["cores"] is None
            )
        )
        for f in manifest["files"]:
            if f.get("release_asset"):
                continue
            self.assertTrue(
                f["repo_path"],
                f"{f['dest']} has no repo_path, install.py cannot fetch it",
            )
            self.assertNotEqual(f["sha1"], "0" * 40)

    def test_92_manifest_matches_zip(self):
        """Manifest file destinations match ZIP contents (excluding metadata)."""
        from packs.manifest import generate_manifest
        from packs.platformpack import generate_pack

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
            "test_existence",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            output_dir,
            emulators_dir=self.emulators_dir,
            offline=True,
        )
        self.assertIsNotNone(zip_path)

        # Get ZIP file destinations (exclude metadata)
        with zipfile.ZipFile(zip_path) as zf:
            zip_names = {
                n
                for n in zf.namelist()
                if not n.rsplit("/", 1)[-1].startswith(("INSTRUCTIONS_", "RENAMED_"))
                and n != "manifest.json"
                and n != "README.txt"
            }

        # Generate manifest
        manifest = generate_manifest(
            "test_existence",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            registry_path,
            emulators_dir=self.emulators_dir,
            offline=True,
        )
        # Detect flat vs nested ZIP to build expected paths
        base = manifest.get("base_destination", "")
        is_flat = bool(base) and not any(
            n.startswith(base + "/") for n in zip_names
        )
        manifest_dests = set()
        for f in manifest["files"]:
            if base and not is_flat:
                d = f"{base}/{f['dest']}"
            else:
                d = f["dest"]
            manifest_dests.add(d)

        self.assertEqual(manifest_dests, zip_names)


if __name__ == "__main__":
    unittest.main()
