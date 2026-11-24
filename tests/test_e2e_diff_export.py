"""End-to-end installer configuration, truth diff, exporters and registry merge."""

from __future__ import annotations

import tests
import os
import unittest
from pathlib import Path
import yaml
from model.declarations import expand_platform_declared_names
from model.profiles import load_emulator_profiles
from model.platforms import load_platform_config
from resolve.localfile import resolve_local_file
from resolve.platformdiff import diff_platform_truth
from resolve.truth import generate_platform_truth
from packs.gaps import find_undeclared_files
from tests.e2esupport import E2EFixture


class TestE2EInstallerConfig(E2EFixture):
    """install.py configuration parsing and standalone copies."""

    # ---------------------------------------------------------------
    # install.py tests
    # ---------------------------------------------------------------

    def test_93_parse_retroarch_cfg(self):
        """Parse system_directory from retroarch.cfg."""
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
            f.write("system_directory = /tmp/ra_system\n")
        result = _parse_retroarch_system_dir(Path(cfg))
        self.assertEqual(result, Path("/tmp/ra_system"))

    def test_94_parse_emudeck_settings(self):
        """Parse emulationPath from EmuDeck settings.sh."""
        from install import _parse_bash_var

        settings = os.path.join(self.root, "settings.sh")
        with open(settings, "w") as f:
            f.write(
                'emulationPath="/home/deck/Emulation"\nromsPath="/home/deck/Emulation/roms"\n'
            )
        result = _parse_bash_var(Path(settings), "emulationPath")
        self.assertEqual(result, "/home/deck/Emulation")

    def test_95_parse_ps1_var(self):
        """Parse $emulationPath from EmuDeck settings.ps1."""
        from install import _parse_ps1_var

        settings = os.path.join(self.root, "settings.ps1")
        with open(settings, "w") as f:
            f.write('$emulationPath="C:\\Emulation"\n')
        result = _parse_ps1_var(Path(settings), "$emulationPath")
        self.assertEqual(result, "C:\\Emulation")

    def test_96_target_filtering(self):
        """--target filters files by cores field."""
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
        from install import do_standalone_copies

        bios_dir = Path(self.root) / "bios"
        bios_dir.mkdir(exist_ok=True)
        (bios_dir / "prod.keys").write_bytes(b"KEYS")
        yuzu_dir = Path(self.root) / "yuzu_keys"
        yuzu_dir.mkdir()
        missing_dir = Path(self.root) / "nonexistent"
        manifest = {
            "base_destination": "bios",
            "files": [{"dest": "prod.keys"}],
            "standalone_copies": [
                {
                    "file": "prod.keys",
                    "targets": {"linux": [str(yuzu_dir), str(missing_dir)]},
                }
            ],
        }
        copied, skipped, _ = do_standalone_copies(manifest, bios_dir, "linux")
        self.assertEqual(copied, 1)
        self.assertEqual(skipped, 1)
        self.assertTrue((yuzu_dir / "prod.keys").exists())
        self.assertFalse((missing_dir / "prod.keys").exists())


class TestE2EDiffTruth(E2EFixture):
    """diff_platform_truth divergences."""

    # ---------------------------------------------------------------
    # diff_platform_truth tests
    # ---------------------------------------------------------------

    def test_98_diff_truth_missing(self):
        """Truth has 2 files, scraped has 1 -> 1 missing with cores/source_refs."""
        truth = {
            "systems": {
                "test-sys": {
                    "_coverage": {"cores_profiled": ["core_a"], "cores_unprofiled": []},
                    "files": [
                        {
                            "name": "bios_a.bin",
                            "required": True,
                            "md5": "aaa",
                            "_cores": ["core_a"],
                            "_source_refs": ["src/a.c:10"],
                        },
                        {
                            "name": "bios_b.bin",
                            "required": False,
                            "md5": "bbb",
                            "_cores": ["core_a"],
                            "_source_refs": ["src/b.c:20"],
                        },
                    ],
                }
            }
        }
        scraped = {
            "systems": {
                "test-sys": {
                    "files": [{"name": "bios_a.bin", "md5": "aaa"}],
                }
            }
        }
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
        truth = {
            "systems": {
                "test-sys": {
                    "_coverage": {"cores_profiled": ["core_a"], "cores_unprofiled": []},
                    "files": [
                        {
                            "name": "bios.bin",
                            "md5": "aaa",
                            "_cores": ["core_a"],
                            "_source_refs": [],
                        },
                    ],
                }
            }
        }
        scraped = {
            "systems": {
                "test-sys": {
                    "files": [
                        {"name": "bios.bin", "md5": "aaa"},
                        {"name": "phantom.bin", "md5": "zzz"},
                    ],
                }
            }
        }
        result = diff_platform_truth(truth, scraped)
        self.assertEqual(result["summary"]["total_extra_phantom"], 1)
        div = result["divergences"]["test-sys"]
        self.assertEqual(len(div["extra_phantom"]), 1)
        self.assertEqual(div["extra_phantom"][0]["name"], "phantom.bin")

    def test_100_diff_truth_extra_unprofiled(self):
        """Some cores unprofiled, scraped has extra -> extra_unprofiled."""
        truth = {
            "systems": {
                "test-sys": {
                    "_coverage": {
                        "cores_profiled": ["core_a"],
                        "cores_unprofiled": ["core_b"],
                    },
                    "files": [
                        {
                            "name": "bios.bin",
                            "md5": "aaa",
                            "_cores": ["core_a"],
                            "_source_refs": [],
                        },
                    ],
                }
            }
        }
        scraped = {
            "systems": {
                "test-sys": {
                    "files": [
                        {"name": "bios.bin", "md5": "aaa"},
                        {"name": "extra.bin", "md5": "yyy"},
                    ],
                }
            }
        }
        result = diff_platform_truth(truth, scraped)
        self.assertEqual(result["summary"]["total_extra_unprofiled"], 1)
        div = result["divergences"]["test-sys"]
        self.assertEqual(len(div["extra_unprofiled"]), 1)
        self.assertEqual(div["extra_unprofiled"][0]["name"], "extra.bin")

    def test_101_diff_truth_alias_matching(self):
        """Truth file with aliases, scraped uses alias -> not extra or missing."""
        truth = {
            "systems": {
                "test-sys": {
                    "_coverage": {"cores_profiled": ["core_a"], "cores_unprofiled": []},
                    "files": [
                        {
                            "name": "bios.bin",
                            "md5": "aaa",
                            "aliases": ["alt.bin"],
                            "_cores": ["core_a"],
                            "_source_refs": [],
                        },
                    ],
                }
            }
        }
        scraped = {
            "systems": {
                "test-sys": {
                    "files": [{"name": "alt.bin", "md5": "aaa"}],
                }
            }
        }
        result = diff_platform_truth(truth, scraped)
        self.assertEqual(result["summary"]["total_missing"], 0)
        self.assertEqual(result["summary"]["total_extra_phantom"], 0)
        self.assertNotIn("test-sys", result.get("divergences", {}))

    def test_102_diff_truth_case_insensitive(self):
        """Truth 'BIOS.ROM', scraped 'bios.rom' -> match, no missing."""
        truth = {
            "systems": {
                "test-sys": {
                    "_coverage": {"cores_profiled": ["core_a"], "cores_unprofiled": []},
                    "files": [
                        {
                            "name": "BIOS.ROM",
                            "md5": "aaa",
                            "_cores": ["core_a"],
                            "_source_refs": [],
                        },
                    ],
                }
            }
        }
        scraped = {
            "systems": {
                "test-sys": {
                    "files": [{"name": "bios.rom", "md5": "aaa"}],
                }
            }
        }
        result = diff_platform_truth(truth, scraped)
        self.assertEqual(result["summary"]["total_missing"], 0)
        self.assertNotIn("test-sys", result.get("divergences", {}))

    def test_103_diff_truth_hash_mismatch(self):
        """Same file, different md5 -> hash_mismatch with truth_cores."""
        truth = {
            "systems": {
                "test-sys": {
                    "_coverage": {"cores_profiled": ["core_a"], "cores_unprofiled": []},
                    "files": [
                        {
                            "name": "bios.bin",
                            "md5": "truth_hash",
                            "_cores": ["core_a", "core_b"],
                            "_source_refs": ["src/x.c:5"],
                        },
                    ],
                }
            }
        }
        scraped = {
            "systems": {
                "test-sys": {
                    "files": [{"name": "bios.bin", "md5": "scraped_hash"}],
                }
            }
        }
        result = diff_platform_truth(truth, scraped)
        self.assertEqual(result["summary"]["total_hash_mismatch"], 1)
        div = result["divergences"]["test-sys"]
        self.assertEqual(len(div["hash_mismatch"]), 1)
        hm = div["hash_mismatch"][0]
        self.assertEqual(hm["name"], "bios.bin")
        self.assertEqual(hm["truth_cores"], ["core_a", "core_b"])
        self.assertEqual(hm["truth_md5"], "truth_hash")
        self.assertEqual(hm["scraped_md5"], "scraped_hash")

    def test_104_diff_truth_normalized_system_ids(self):
        """Diff matches systems with different ID formats via normalization."""
        from resolve.platformdiff import diff_platform_truth

        truth = {
            "systems": {
                "sega-gamegear": {
                    "_coverage": {"cores_profiled": ["c"], "cores_unprofiled": []},
                    "files": [
                        {
                            "name": "bios.gg",
                            "required": True,
                            "md5": "a" * 32,
                            "_cores": ["c"],
                            "_source_refs": [],
                        },
                    ],
                },
            }
        }
        scraped = {
            "systems": {
                "sega-game-gear": {
                    "files": [
                        {"name": "bios.gg", "required": True, "md5": "a" * 32},
                    ],
                },
            }
        }

        result = diff_platform_truth(truth, scraped)
        self.assertEqual(result["summary"]["systems_uncovered"], 0)
        self.assertEqual(result["summary"]["total_missing"], 0)
        self.assertEqual(result["summary"]["systems_compared"], 1)


class TestE2EExporters(E2EFixture):
    """native_id preservation, the System.dat exporter and the truth diff chain."""

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
                        {
                            "name": "scph5501.bin",
                            "destination": "scph5501.bin",
                            "required": True,
                        },
                    ],
                },
                "nintendo-snes": {
                    "native_id": "snes",
                    "files": [
                        {
                            "name": "bs-x.bin",
                            "destination": "bs-x.bin",
                            "required": False,
                        },
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

        from resolve.reconcile import build_native_model

        systems, report = build_native_model(truth, scraped)
        exporter = SystemDatExporter()
        produced = exporter.render(systems, report, {}, scraped)
        content = produced["System.dat"]
        self.assertIn("Sony - PlayStation", content)
        self.assertIn("scph5501.bin", content)
        self.assertIn("b056ee5a4d65937e1a3a17e1e78f3258ea49c38e", content)
        self.assertIn('name "System"', content)
        self.assertIn("71AF80B4", content)  # CRC uppercase

        issues = exporter.validate(systems, produced)
        self.assertEqual(issues, [])

        # Discovery finds the systemdat exporter
        exporters = discover_exporters()
        self.assertIn("retroarch", exporters)
        self.assertIs(exporters["retroarch"], SystemDatExporter)

    def test_systemdat_exporter_numeric_crc(self):
        """Digit-only crc32 typed as int by YAML must not break the export."""
        from exporter.systemdat_exporter import Exporter as SystemDatExporter

        truth = {
            "platform": "retroarch",
            "systems": {
                "commodore-plus4": {
                    "files": [
                        {
                            "name": "kernal-318005-05.bin",
                            "path": "kernal-318005-05.bin",
                            "size": 16384,
                            "crc32": 70295038,
                            "required": False,
                        },
                    ],
                },
            },
        }

        from resolve.reconcile import build_native_model

        systems, report = build_native_model(truth, {"systems": {}})
        original = ('clrmamepro (\n\tname "System"\n)\n\ngame (\n\tname "System"\n'
                    '\tcomment "commodore-plus4"\n)\n')
        produced = SystemDatExporter().render(
            systems, report, {"System.dat": original}, {"systems": {}}
        )
        self.assertIn("crc 70295038", produced["System.dat"])

    # ---------------------------------------------------------------
    # Full truth + diff integration test
    # ---------------------------------------------------------------

    def test_truth_diff_integration(self):
        """Full chain: generate truth from profiles, diff against scraped data."""
        # Config: platform with two cores, only core_a has a profile
        config = {"cores": ["core_a", "core_b"]}
        registry_entry = {
            "hash_type": "md5",
            "verification_mode": "md5",
        }

        # Emulator profile for core_a with 2 files
        core_a_profile = {
            "emulator": "CoreA",
            "type": "libretro",
            "systems": ["test-system"],
            "files": [
                {
                    "name": "bios_a.bin",
                    "system": "test-system",
                    "required": True,
                    "md5": "a" * 32,
                    "sha1": "b" * 40,
                    "size": 1024,
                    "path": "bios_a.bin",
                    "source_ref": "src/a.c:10",
                },
                {
                    "name": "shared.bin",
                    "system": "test-system",
                    "required": True,
                    "md5": "c" * 32,
                    "path": "shared.bin",
                    "source_ref": "src/a.c:20",
                },
            ],
        }
        profile_path = os.path.join(self.emulators_dir, "core_a.yml")
        with open(profile_path, "w") as f:
            yaml.dump(core_a_profile, f)

        # No profile for core_b (unprofiled)
        # Clear cache so the new profile is picked up
        from model.profiles import emulator_profiles_cache

        emulator_profiles_cache.clear()
        profiles = load_emulator_profiles(self.emulators_dir)
        self.assertIn("core_a", profiles)
        self.assertNotIn("core_b", profiles)

        # Generate truth
        truth = generate_platform_truth(
            "testplat", config, registry_entry, profiles, db=None, data_registry={}
        )

        # Verify truth structure
        self.assertIn("test-system", truth["systems"])
        sys_files = truth["systems"]["test-system"]["files"]
        self.assertEqual(len(sys_files), 2)
        file_names = {f["name"] for f in sys_files}
        self.assertEqual(file_names, {"bios_a.bin", "shared.bin"})

        # Verify coverage metadata
        cov = truth["_coverage"]
        self.assertEqual(cov["cores_profiled"], 1)
        # core_b has no profile YAML, so resolve_platform_cores never
        # includes it, so cores_resolved reflects only matched profiles
        self.assertEqual(cov["cores_resolved"], 1)

        # Inject unprofiled info into system-level coverage for diff.
        # In production, core_b would be tracked as unprofiled by a
        # higher-level orchestrator that knows the declared core list.
        injected_cov = {
            "cores_profiled": ["core_a"],
            "cores_unprofiled": ["core_b"],
        }
        for sys_data in truth["systems"].values():
            sys_data["_coverage"] = injected_cov

        # Build scraped dict: shared.bin with wrong hash, phantom.bin extra,
        # bios_a.bin missing
        scraped = {
            "systems": {
                "test-system": {
                    "files": [
                        {
                            "name": "shared.bin",
                            "required": True,
                            "md5": "d" * 32,
                        },
                        {
                            "name": "phantom.bin",
                            "required": False,
                            "md5": "e" * 32,
                        },
                    ],
                },
            },
        }

        # Diff
        result = diff_platform_truth(truth, scraped)
        summary = result["summary"]

        # bios_a.bin not in scraped -> missing
        self.assertEqual(summary["total_missing"], 1)
        # shared.bin md5 mismatch (truth "c"*32 vs scraped "d"*32)
        self.assertEqual(summary["total_hash_mismatch"], 1)
        # phantom.bin extra, core_b unprofiled -> extra_unprofiled
        self.assertEqual(summary["total_extra_unprofiled"], 1)
        # Unprofiled cores present, so extras are unprofiled not phantom
        self.assertEqual(summary["total_extra_phantom"], 0)

        # Verify divergence details
        div = result["divergences"]["test-system"]
        self.assertEqual(div["missing"][0]["name"], "bios_a.bin")
        self.assertEqual(div["hash_mismatch"][0]["name"], "shared.bin")
        self.assertEqual(div["extra_unprofiled"][0]["name"], "phantom.bin")
        self.assertNotIn("extra_phantom", div)

    def test_173_cross_ref_hash_matching(self):
        """Platform file under different name matched by MD5 is not undeclared."""
        config = load_platform_config("test_md5", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
        names = {u["name"] for u in undeclared}
        # correct_hash.bin is declared by platform as renamed_file.bin with same MD5
        # hash-based matching should suppress it from undeclared
        self.assertNotIn("correct_hash.bin", names)

    def test_174_expand_platform_declared_names(self):
        """expand_platform_declared_names enriches with DB canonical names."""
        config = load_platform_config("test_md5", self.platforms_dir)
        result = expand_platform_declared_names(config, self.db)
        # renamed_file.bin is declared directly
        self.assertIn("renamed_file.bin", result)
        # correct_hash.bin is the DB canonical name for the same MD5
        self.assertIn("correct_hash.bin", result)


class TestE2ERegistryMerge(E2EFixture):
    """Registry merge, all_libretro expansion, agnostic profiles and exporter round trips."""

    # ---------------------------------------------------------------
    # Registry merge + all_libretro expansion + diff hash fallback
    # ---------------------------------------------------------------

    def test_175_registry_merge_cores(self):
        """load_platform_config merges cores from _registry.yml."""
        from model.platforms import _platform_config_cache

        # Platform YAML with 1 core
        config = {
            "platform": "TestMerge",
            "cores": ["core_a"],
            "systems": {"test-system": {"files": []}},
        }
        with open(os.path.join(self.platforms_dir, "testmerge.yml"), "w") as f:
            yaml.dump(config, f)

        # Registry with 2 cores (superset)
        registry = {
            "platforms": {
                "testmerge": {
                    "config": "testmerge.yml",
                    "cores": ["core_a", "core_b"],
                }
            }
        }
        with open(os.path.join(self.platforms_dir, "_registry.yml"), "w") as f:
            yaml.dump(registry, f)

        _platform_config_cache.clear()
        loaded = load_platform_config("testmerge", self.platforms_dir)
        cores = [str(c) for c in loaded["cores"]]
        self.assertIn("core_a", cores)
        self.assertIn("core_b", cores)

    def test_176_all_libretro_in_list(self):
        """resolve_platform_cores expands all_libretro/retroarch in a list."""
        from model.profiles import load_emulator_profiles
        from resolve.cores import resolve_platform_cores

        # Create a libretro profile and a standalone profile
        for name, ptype in [("lr_core", "libretro"), ("sa_core", "standalone")]:
            profile = {
                "emulator": name,
                "type": ptype,
                "cores": [name],
                "systems": ["test-system"],
                "files": [],
            }
            with open(os.path.join(self.emulators_dir, f"{name}.yml"), "w") as f:
                yaml.dump(profile, f)

        profiles = load_emulator_profiles(self.emulators_dir)

        # Config with retroarch + sa_core in cores list
        config = {"cores": ["retroarch", "sa_core"]}
        resolved = resolve_platform_cores(config, profiles)
        self.assertIn("lr_core", resolved)  # expanded via retroarch
        self.assertIn("sa_core", resolved)  # explicit

    def test_177_diff_hash_fallback_rename(self):
        """Diff detects platform renames via hash fallback."""
        from resolve.platformdiff import diff_platform_truth

        truth = {
            "systems": {
                "test-system": {
                    "_coverage": {"cores_profiled": ["c"], "cores_unprofiled": []},
                    "files": [
                        {
                            "name": "ROM",
                            "required": True,
                            "md5": "abcd1234" * 4,
                            "_cores": ["c"],
                            "_source_refs": [],
                        },
                    ],
                }
            }
        }
        scraped = {
            "systems": {
                "test-system": {
                    "files": [
                        {"name": "ROM1", "required": True, "md5": "abcd1234" * 4},
                    ],
                }
            }
        }

        result = diff_platform_truth(truth, scraped)
        # ROM and ROM1 share the same hash: a rename, not missing plus phantom
        self.assertEqual(result["summary"]["total_missing"], 0)
        self.assertEqual(result["summary"]["total_extra_phantom"], 0)

    def test_178_diff_system_normalization(self):
        """Diff matches systems with different IDs via normalization."""
        from resolve.platformdiff import diff_platform_truth

        truth = {
            "systems": {
                "sega-gamegear": {
                    "_coverage": {"cores_profiled": ["c"], "cores_unprofiled": []},
                    "files": [
                        {
                            "name": "bios.gg",
                            "required": True,
                            "md5": "a" * 32,
                            "_cores": ["c"],
                            "_source_refs": [],
                        },
                    ],
                },
            }
        }
        scraped = {
            "systems": {
                "sega-game-gear": {
                    "files": [
                        {"name": "bios.gg", "required": True, "md5": "a" * 32},
                    ],
                },
            }
        }

        result = diff_platform_truth(truth, scraped)
        self.assertEqual(result["summary"]["systems_uncovered"], 0)
        self.assertEqual(result["summary"]["total_missing"], 0)
        self.assertEqual(result["summary"]["systems_compared"], 1)

    def test_179_agnostic_profile_skipped_in_undeclared(self):
        """bios_mode: agnostic profiles are skipped entirely by find_undeclared_files."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
        emulators = {u["emulator"] for u in undeclared}
        # TestAgnostic should NOT appear in undeclared (bios_mode: agnostic)
        self.assertNotIn("TestAgnostic", emulators)

    def test_180_agnostic_file_skipped_in_undeclared(self):
        """Files with agnostic: true are skipped, others in same profile are not."""
        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
        names = {u["name"] for u in undeclared}
        # agnostic_file.bin should NOT be in undeclared (agnostic: true)
        self.assertNotIn("agnostic_file.bin", names)
        # undeclared_req.bin should still be in undeclared (not agnostic)
        self.assertIn("undeclared_req.bin", names)

    def test_181_agnostic_extras_scan(self):
        """Agnostic profiles add all matching DB files as extras."""
        from packs.extras import collect_emulator_extras

        config = load_platform_config("test_existence", self.platforms_dir)
        profiles = load_emulator_profiles(self.emulators_dir)
        extras = collect_emulator_extras(
            config,
            self.emulators_dir,
            self.db,
            set(),
            "system",
            profiles,
        )
        agnostic_extras = [
            e for e in extras if e.get("source_emulator") == "TestAgnostic"
        ]
        # Agnostic scan should find files in the same directory as correct_hash.bin
        self.assertTrue(len(agnostic_extras) > 0, "Agnostic scan should produce extras")
        # All agnostic extras should have agnostic_scan flag
        for e in agnostic_extras:
            self.assertTrue(e.get("agnostic_scan", False))

    def test_182_agnostic_rename_readme(self):
        """build_agnostic_rename_readme generates correct text."""
        from packs.readme import build_agnostic_rename_readme

        result = build_agnostic_rename_readme(
            "dsi_nand.bin",
            "DSi_Nand_AUS.bin",
            ["DSi_Nand_EUR.bin", "DSi_Nand_USA.bin"],
        )
        self.assertIn("dsi_nand.bin <- DSi_Nand_AUS.bin", result)
        self.assertIn("DSi_Nand_EUR.bin", result)
        self.assertIn("DSi_Nand_USA.bin", result)
        self.assertIn("rename it to: dsi_nand.bin", result)

    def test_183_agnostic_resolve_fallback(self):
        """resolve_local_file with agnostic fallback finds a system file."""
        file_entry = {
            "name": "nonexistent_agnostic.bin",
            "agnostic": True,
            "min_size": 1,
            "max_size": 999999,
            "agnostic_path_prefix": self.bios_dir + "/",
        }
        path, status = resolve_local_file(file_entry, self.db)
        self.assertIsNotNone(path)
        self.assertEqual(status, "agnostic_fallback")

    def test_179_batocera_exporter_round_trip(self):
        """Batocera exporter produces valid Python dict format."""
        from exporter.batocera_exporter import Exporter

        truth = {
            "systems": {
                "sony-playstation": {
                    "_coverage": {"cores_profiled": ["c"]},
                    "files": [
                        {
                            "name": "scph5501.bin",
                            "destination": "scph5501.bin",
                            "required": True,
                            "md5": "b" * 32,
                            "_cores": ["c"],
                            "_source_refs": [],
                        },
                    ],
                }
            }
        }
        scraped = {
            # The core the platform runs: an addition is written under it.
            "cores": ["c"],
            "systems": {
                "sony-playstation": {"native_id": "psx", "files": []},
            },
        }
        from resolve.reconcile import build_native_model

        # The systems dict is one block inside the checker Batocera runs, so
        # the exporter is handed the script it patches.
        skeleton = (
            "#!/usr/bin/env python\n"
            "systems = {\n"
            "}\n"
            "def checkBios(systems, prefix, filterROMs):\n"
            "    return {}\n"
        )
        systems, report = build_native_model(truth, scraped)
        exp = Exporter()
        produced = exp.render(
            systems, report, {"batocera-systems": skeleton}, scraped
        )
        content = produced["batocera-systems"]
        self.assertIn('"psx"', content)
        self.assertIn("scph5501.bin", content)
        self.assertIn("b" * 32, content)
        self.assertIn("def checkBios(", content)
        self.assertEqual(exp.validate(systems, produced), [])

    def test_180_recalbox_exporter_round_trip(self):
        """Recalbox exporter produces valid es_bios.xml."""
        from exporter.recalbox_exporter import Exporter

        truth = {
            "systems": {
                "sony-playstation": {
                    "_coverage": {"cores_profiled": ["c"]},
                    "files": [
                        {
                            "name": "scph5501.bin",
                            "destination": "scph5501.bin",
                            "required": True,
                            "md5": "b" * 32,
                            "_cores": ["c"],
                            "_source_refs": [],
                        },
                    ],
                }
            }
        }
        scraped = {
            # The core the platform runs: an addition is written under it.
            "cores": ["c"],
            "systems": {
                "sony-playstation": {"native_id": "psx", "files": []},
            },
        }
        from resolve.reconcile import build_native_model

        systems, report = build_native_model(truth, scraped)
        exp = Exporter()
        produced = exp.render(systems, report, {}, scraped)
        content = produced["es_bios.xml"]
        self.assertIn("<biosList", content)
        self.assertIn('platform="psx"', content)
        self.assertIn("fullname=", content)
        self.assertIn("scph5501.bin", content)
        # mandatory="true" is the default, not emitted (matching Recalbox format)
        self.assertNotIn('mandatory="false"', content)
        self.assertIn('core="libretro/c"', content)
        self.assertEqual(exp.validate(systems, produced), [])

    def test_181_retrobat_exporter_round_trip(self):
        """RetroBat exporter produces valid JSON."""
        import json as _json

        from exporter.retrobat_exporter import Exporter

        truth = {
            "systems": {
                "sony-playstation": {
                    "_coverage": {"cores_profiled": ["c"]},
                    "files": [
                        {
                            "name": "scph5501.bin",
                            "destination": "scph5501.bin",
                            "required": True,
                            "md5": "b" * 32,
                            "_cores": ["c"],
                            "_source_refs": [],
                        },
                    ],
                }
            }
        }
        scraped = {
            "systems": {
                "sony-playstation": {"native_id": "psx", "files": []},
            }
        }
        from resolve.reconcile import build_native_model

        systems, report = build_native_model(truth, scraped)
        exp = Exporter()
        produced = exp.render(systems, report, {}, scraped)
        data = _json.loads(produced["batocera-systems.json"])
        self.assertIn("psx", data)
        self.assertTrue(
            any("scph5501" in bf["file"] for bf in data["psx"]["biosFiles"])
        )
        self.assertEqual(exp.validate(systems, produced), [])

    def test_182_exporter_discovery(self):
        """All exporters are discovered by the plugin system."""
        from exporter import discover_exporters

        exporters = discover_exporters()
        self.assertIn("retroarch", exporters)
        self.assertIn("batocera", exporters)
        self.assertIn("recalbox", exporters)
        self.assertIn("retrobat", exporters)


if __name__ == "__main__":
    unittest.main()
