"""Regression tests for the holistic reliability and security audit."""

from __future__ import annotations

import ast
import contextlib
import hashlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parent.parent
TMP_ROOT = ROOT / "tmp" / "tests"
TMP_ROOT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import install
from scripts import pipeline, region, region_audit
from scripts.common import resolve_local_file, safe_extract_zip
from scripts.generate_pack import (
    _emulator_region_group,
    generate_target_manifests,
    verify_pack_against_platform,
)


class ReadmeRegressions(unittest.TestCase):
    """The README advertises commands; these must stay executable.

    Wording is the maintainer's, so nothing here asserts prose. What is
    asserted is that every flag and URL the README hands a reader is one the
    shipped scripts actually accept.
    """

    def _quick_install(self) -> str:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        return readme.split("## Quick Install", 1)[1].split(
            "## Download BIOS packs", 1
        )[0]

    def test_advertised_bootstrap_urls_are_the_shipped_ones(self):
        quick_install = self._quick_install()
        for script in ("install.sh", "install.ps1"):
            url = f"https://raw.githubusercontent.com/Abdess/retrobios/main/{script}"
            self.assertIn(url, quick_install, f"{script} bootstrap URL missing")
        self.assertIn(
            "https://raw.githubusercontent.com/Abdess/retrobios/main/install.py",
            (ROOT / "install.sh").read_text(encoding="utf-8"),
            "install.sh must fetch install.py from the ref the README advertises",
        )

    def test_advertised_installer_flags_exist(self):
        quick_install = self._quick_install()
        advertised = set(re.findall(r"(?<![\w-])--[a-z][a-z-]+", quick_install))
        parser_source = (ROOT / "install.py").read_text(encoding="utf-8")
        supported = set(re.findall(r'add_argument\(\s*"(--[a-z][a-z-]+)"', parser_source))
        unknown = advertised - supported
        self.assertEqual(unknown, set(), f"README advertises unknown flags: {unknown}")


class FaqRegressions(unittest.TestCase):
    """The FAQ states facts the code owns; these tie it back to the source.

    Three of its claims had drifted: a pinned MAME version, Adler-32
    attributed to Dolphin's IPL instead of its DSP ROMs, and a verbose
    per-emulator report described as the only way to catch a bad file on an
    existence platform. Readers act on all three.
    """

    _MAME_GENERATIONS = {
        "MAME 2000": "mame2000",
        "MAME 2003": "mame2003",
        "MAME 2009": "mame2009",
        "MAME 2010": "mame2010",
        "MAME 2015": "mame2015",
        "MAME 2016": "mame2016",
        "current MAME": "mame",
    }

    @staticmethod
    def _faq() -> str:
        return (ROOT / "wiki" / "faq.md").read_text(encoding="utf-8")

    @staticmethod
    def _profile(key: str) -> dict:
        with (ROOT / "emulators" / f"{key}.yml").open(encoding="utf-8") as handle:
            return yaml.safe_load(handle)

    def test_mame_versions_match_their_profiles(self):
        # The list is wrapped, so a label and its version can straddle a line.
        faq = " ".join(self._faq().split())
        for label, key in self._MAME_GENERATIONS.items():
            match = re.search(rf"{re.escape(label)} \(([^)]+)\)", faq)
            self.assertIsNotNone(match, f"FAQ no longer states a version for {label}")
            self.assertEqual(
                match.group(1),
                self._profile(key)["core_version"],
                f"FAQ version for {label} has drifted from emulators/{key}.yml",
            )

    def test_adler32_is_attributed_to_the_files_that_carry_it(self):
        dolphin = self._profile("dolphin")
        carriers = {
            f["name"] for f in dolphin["files"] if f.get("known_hash_adler32")
        }
        self.assertTrue(carriers, "dolphin.yml declares no Adler-32 hash")
        sentence = self._faq().split("Adler-32", 1)[1].split("\n\n", 1)[0]
        for name in carriers:
            self.assertIn(name, sentence, f"FAQ omits the Adler-32 file {name}")
        self.assertNotIn(
            "IPL.bin", carriers,
            "IPL.bin gained an Adler-32 hash; the docs say it has none",
        )
        for page in ("faq.md", "profiling.md"):
            text = (ROOT / "wiki" / page).read_text(encoding="utf-8")
            for line in text.splitlines():
                if "Adler-32" in line or "adler32" in line:
                    self.assertNotIn(
                        "IPL", line,
                        f"wiki/{page} ties Adler-32 back to IPL: {line.strip()}",
                    )

    def test_existence_platforms_are_not_told_the_verbose_report_is_the_only_check(self):
        self.assertIn(
            "DISCREPANCY",
            self._faq(),
            "the FAQ must name the check the platform report performs itself",
        )
        self.assertIn(
            'result["discrepancy"]',
            (ROOT / "scripts" / "verify.py").read_text(encoding="utf-8"),
            "verify.py no longer raises the discrepancy the FAQ advertises",
        )


class CatalogRatioRegressions(unittest.TestCase):
    """The catalog-matched count must read the same on every surface.

    The home page, the provenance page, the README and the stats export each
    used to count matches on their own. Two of them dropped the systems
    scope, so the site published 566 and 553 for the same quantity, one click
    apart, and the export paired the wider number with composition.systems as
    its denominator.
    """

    _SURFACES = ("scripts/generate_site.py", "scripts/generate_readme.py")

    def test_no_surface_counts_matches_on_its_own(self):
        for relative in self._SURFACES:
            tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
            inline = [
                node.lineno
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and getattr(node.func, "id", "") == "sum"
                and "provenance" in ast.dump(node)
            ]
            self.assertEqual(
                inline,
                [],
                f"{relative} counts provenance matches inline at {inline}; "
                "call common.count_catalog_matched instead",
            )

    def test_arcade_and_engine_data_stay_out_of_the_ratio(self):
        from scripts.common import compute_composition, count_catalog_matched

        db = {
            "files": {
                "a": {"path": "bios/Sony/PlayStation/scph5501.bin", "size": 1,
                      "provenance": {"redump": {}}},
                "b": {"path": "bios/Arcade/Arcade/neogeo.zip", "size": 1,
                      "provenance": {"no-intro": {}}},
                "c": {"path": "bios/ScummVM/soundfonts/Roland.sf2", "size": 1,
                      "provenance": {"tosec": {}}},
                "d": {"path": "bios/Sega/Saturn/sega_101.bin", "size": 1},
            }
        }
        self.assertEqual(count_catalog_matched(db), 1)
        self.assertEqual(compute_composition(db)["systems"]["files"], 2)

    def test_readme_ratio_matches_the_database(self):
        from scripts.common import compute_composition, count_catalog_matched, load_database

        database = ROOT / "database.json"
        if not database.exists():
            self.skipTest("database.json not generated")
        db = load_database(str(database))
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        match = re.search(
            r"\*\*([\d,]+) of ([\d,]+) system files\*\* matched to", readme
        )
        self.assertIsNotNone(match, "README no longer states the catalog ratio")
        matched, total = (int(g.replace(",", "")) for g in match.groups())
        self.assertEqual(matched, count_catalog_matched(db))
        self.assertEqual(total, compute_composition(db)["systems"]["files"])


class PipelineRegressions(unittest.TestCase):
    def test_pack_parser_removes_source_metadata(self):
        output = "\n".join(
            [
                "Generating pack for RetroArch [source=full]...",
                "  3 files packed (2 baseline + 1 from cores), 2/2 files OK",
            ]
        )
        self.assertEqual(pipeline.parse_pack_counts(output), {"RetroArch": (2, 2)})

    def test_missing_pack_is_a_consistency_failure(self):
        verify = "RetroArch: 2/2 OK"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(pipeline.check_consistency(verify, ""))

    def test_display_name_matches_compact_registry_id(self):
        verify = "MiSTer FPGA: 65/65 OK [md5]"
        pack = "\n".join(
            [
                "Generating pack for misterfpga [source=full]...",
                "  pack.zip: 65 files packed (65 baseline + 0 from cores), "
                "65/65 files OK [md5]",
            ]
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(pipeline.check_consistency(verify, pack))

    def test_native_existence_and_strict_pack_exclusions_are_consistent(self):
        verify = "RetroArch: 3/3 present [existence]"
        pack = "\n".join(
            [
                "Generating pack for RetroArch [source=full]...",
                "  pack.zip: 2 files packed (2 baseline + 0 from cores), "
                "2/3 files OK, 1 unsafe excluded [existence]",
            ]
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(pipeline.check_consistency(verify, pack))
        self.assertEqual(pipeline.parse_pack_exclusions(pack), {"RetroArch": 1})

    def test_unaccounted_pack_omission_is_a_consistency_failure(self):
        verify = "RetroArch: 3/3 present [existence]"
        pack = "\n".join(
            [
                "Generating pack for RetroArch [source=full]...",
                "  pack.zip: 1 files packed (1 baseline + 0 from cores), "
                "1/3 files OK, 1 unsafe excluded, 1 missing [existence]",
            ]
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(pipeline.check_consistency(verify, pack))

    def test_every_refresh_failure_reaches_pipeline_exit_status(self):
        for failed_label in (
            "2/8 refresh data directories",
            "2a refresh MAME hashes",
            "2a2 refresh FBNeo hashes",
        ):
            with self.subTest(failed_label=failed_label):
                def fake_run(_command, label):
                    return label != failed_label, "RetroArch: 1/1 OK\n"

                argv = ["pipeline.py", "--skip-packs", "--skip-docs"]
                with (
                    mock.patch.object(sys, "argv", argv),
                    mock.patch.object(pipeline, "run", side_effect=fake_run),
                    contextlib.redirect_stdout(io.StringIO()),
                    self.assertRaises(SystemExit) as raised,
                ):
                    pipeline.main()
                self.assertEqual(raised.exception.code, 1)


class ResolverRegressions(unittest.TestCase):
    def _database(self, entries: dict[str, Path], suffix: str | None = None) -> dict:
        files = {}
        by_name: dict[str, list[str]] = {}
        by_suffix: dict[str, list[str]] = {}
        for name, path in entries.items():
            payload = path.read_bytes()
            sha1 = hashlib.sha1(payload).hexdigest()
            md5 = hashlib.md5(payload).hexdigest()
            sha256 = hashlib.sha256(payload).hexdigest()
            files[sha1] = {
                "path": str(path),
                "name": name,
                "size": len(payload),
                "md5": md5,
                "sha256": sha256,
                "crc32": "00000000",
            }
            by_name.setdefault(name, []).append(sha1)
            if suffix and name == "firmware.bin":
                by_suffix.setdefault(suffix, []).append(sha1)
        return {
            "files": files,
            "indexes": {
                "by_name": by_name,
                "by_md5": {entry["md5"]: sha1 for sha1, entry in files.items()},
                "by_sha256": {
                    entry["sha256"]: sha1 for sha1, entry in files.items()
                },
                "by_crc32": {},
                "by_path_suffix": by_suffix,
            },
        }

    def test_hash_identity_wins_over_wrong_destination_hint(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            wrong = root / "wrong" / "firmware.bin"
            correct = root / "correct" / "firmware.bin"
            wrong.parent.mkdir()
            correct.parent.mkdir()
            wrong.write_bytes(b"wrong")
            correct.write_bytes(b"correct")
            db = self._database(
                {"firmware.bin": wrong, "correct-name.bin": correct},
                suffix="Console/USA/firmware.bin",
            )
            expected = hashlib.sha1(b"correct").hexdigest()
            path, status = resolve_local_file(
                {"name": "firmware.bin", "sha1": expected},
                db,
                dest_hint="Console/USA/firmware.bin",
            )
            self.assertEqual(path, str(correct))
            self.assertEqual(status, "sha1_exact")

    def test_name_cannot_mask_a_declared_hash_mismatch(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            path = Path(directory) / "firmware.bin"
            path.write_bytes(b"wrong")
            db = self._database({"firmware.bin": path})
            resolved, status = resolve_local_file(
                {"name": "firmware.bin", "sha1": "f" * 40}, db
            )
            self.assertEqual(resolved, str(path))
            self.assertEqual(status, "hash_mismatch")


class PackExclusionRegressions(unittest.TestCase):
    def test_slug_platform_core_requirement_uses_the_generated_destination(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            platforms = root / "platforms"
            platforms.mkdir()
            core_payload = root / "extra.bin"
            core_payload.write_bytes(b"mapped core payload")
            core_sha1 = hashlib.sha1(core_payload.read_bytes()).hexdigest()
            core_md5 = hashlib.md5(core_payload.read_bytes()).hexdigest()
            database = {
                "files": {
                    core_sha1: {
                        "name": "extra.bin",
                        "path": str(core_payload),
                        "md5": core_md5,
                        "size": core_payload.stat().st_size,
                    }
                },
                "indexes": {
                    "by_name": {"extra.bin": [core_sha1]},
                    "by_md5": {core_md5: core_sha1},
                    "by_sha256": {},
                    "by_crc32": {},
                    "by_path_suffix": {},
                },
            }
            config = {
                "platform": "Slug platform",
                "base_destination": "bios",
                "verification_mode": "existence",
                "cores": ["core_a"],
                "systems": {
                    "console-a": {
                        "files": [
                            {
                                "name": "base-a.bin",
                                "destination": "slug-a/base-a.bin",
                            }
                        ]
                    },
                    "console-b": {
                        "files": [
                            {
                                "name": "base-b.bin",
                                "destination": "slug-b/base-b.bin",
                            }
                        ]
                    },
                },
            }
            (platforms / "slug.yml").write_text(
                yaml.safe_dump(config), encoding="utf-8"
            )
            profiles = {
                "core_a": {
                    "emulator": "Core A",
                    "type": "libretro",
                    "systems": ["console-a"],
                    "files": [
                        {
                            "name": "extra.bin",
                            "path": "extra.bin",
                            "sha1": core_sha1,
                        }
                    ],
                }
            }
            pack = root / "pack.zip"
            with zipfile.ZipFile(pack, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("slug-a/base-a.bin", b"baseline a")
                archive.writestr("slug-b/base-b.bin", b"baseline b")
                archive.writestr("slug-a/extra.bin", core_payload.read_bytes())

            result = verify_pack_against_platform(
                str(pack),
                "slug",
                str(platforms),
                db=database,
                emu_profiles=profiles,
            )
            self.assertTrue(result[0], result[3])
            self.assertEqual(result[3], [])
            self.assertEqual(result[6:8], (1, 1))

    def _mismatch_fixture(self, root: Path, mode: str) -> tuple[dict, Path]:
        """A platform declaring a hash the only local payload contradicts."""
        platforms = root / "platforms"
        platforms.mkdir()
        payload = root / "firmware.bin"
        payload.write_bytes(b"wrong local variant")
        sha1 = hashlib.sha1(payload.read_bytes()).hexdigest()
        md5 = hashlib.md5(payload.read_bytes()).hexdigest()
        database = {
            "files": {
                sha1: {
                    "name": "firmware.bin",
                    "path": str(payload),
                    "md5": md5,
                    "size": payload.stat().st_size,
                }
            },
            "indexes": {
                "by_name": {"firmware.bin": [sha1]},
                "by_md5": {md5: sha1},
                "by_sha256": {},
                "by_crc32": {},
                "by_path_suffix": {},
            },
        }
        config = {
            "platform": f"Platform {mode}",
            "verification_mode": mode,
            "systems": {
                "console": {
                    "files": [
                        {
                            "name": "firmware.bin",
                            "destination": "firmware.bin",
                            "sha1": "f" * 40,
                        }
                    ]
                }
            },
        }
        (platforms / "plat.yml").write_text(yaml.safe_dump(config), encoding="utf-8")
        return database, platforms

    def test_hash_platform_accounts_for_an_unsafe_exclusion(self):
        """A platform that reads the bytes would reject the local payload."""
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            database, platforms = self._mismatch_fixture(root, "md5")
            pack = root / "pack.zip"
            with zipfile.ZipFile(pack, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("README.txt", "safe subset")

            result = verify_pack_against_platform(
                str(pack),
                "plat",
                str(platforms),
                db=database,
                emu_profiles={},
            )
            self.assertTrue(result[0], result[3])
            self.assertEqual(result[3], [])
            self.assertEqual(result[8], 1)

    def test_existence_platform_never_withholds_over_a_declared_hash(self):
        """RetroArch and friends only look for the filename.

        An upstream hash the local dump contradicts must not remove a file the
        frontend would have loaded, so its absence stays a conformance error.
        """
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            database, platforms = self._mismatch_fixture(root, "existence")
            pack = root / "pack.zip"
            with zipfile.ZipFile(pack, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("README.txt", "no firmware")

            result = verify_pack_against_platform(
                str(pack),
                "plat",
                str(platforms),
                db=database,
                emu_profiles={},
            )
            self.assertFalse(result[0])
            self.assertTrue(any("baseline missing" in e for e in result[3]), result[3])
            self.assertEqual(result[8], 0)

    def test_unexplained_missing_file_still_fails_conformance(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            platforms = root / "platforms"
            platforms.mkdir()
            config = {
                "platform": "Missing",
                "verification_mode": "existence",
                "systems": {
                    "console": {
                        "files": [
                            {"name": "absent.bin", "destination": "absent.bin"}
                        ]
                    }
                },
            }
            (platforms / "missing.yml").write_text(
                yaml.safe_dump(config), encoding="utf-8"
            )
            pack = root / "pack.zip"
            with zipfile.ZipFile(pack, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("README.txt", "incomplete")
            database = {
                "files": {},
                "indexes": {
                    "by_name": {},
                    "by_md5": {},
                    "by_sha256": {},
                    "by_crc32": {},
                    "by_path_suffix": {},
                },
            }

            result = verify_pack_against_platform(
                str(pack),
                "missing",
                str(platforms),
                db=database,
                emu_profiles={},
            )
            self.assertFalse(result[0])
            self.assertTrue(any("baseline missing" in error for error in result[3]))


class RegionRegressions(unittest.TestCase):
    def test_tagged_and_untagged_same_path_is_preserved(self):
        profiles = {
            "tagged": {
                "type": "libretro",
                "files": [
                    {"name": "bios.bin", "path": "sys/bios.bin", "region": ["japan"]}
                ],
            },
            "untagged": {
                "type": "libretro",
                "files": [{"name": "bios.bin", "path": "sys/bios.bin"}],
            },
        }
        index = region.build_region_index(profiles)
        self.assertEqual(region.lookup_regions(index, "sys/bios.bin", "bios.bin"), set())
        drops = region.resolve_region_drops(
            {"system": [("sys/bios.bin", "bios.bin")]},
            index,
            ["north-america"],
        )
        self.assertEqual(drops, set())

    def test_world_candidate_beats_unmatched_regional_fallback(self):
        profiles = {
            "core": {
                "type": "libretro",
                "files": [
                    {"name": "ntsc.bin", "region": ["world"]},
                    {"name": "pal.bin", "region": ["europe"]},
                ],
            }
        }
        index = region.build_region_index(profiles)
        groups = {"system": [("ntsc.bin", "ntsc.bin"), ("pal.bin", "pal.bin")]}
        self.assertEqual(
            region.resolve_region_drops(groups, index, ["north-america"]),
            {"pal.bin"},
        )
        self.assertEqual(region.resolve_region_drops(groups, index, ["europe"]), set())

    def test_multi_system_emulator_uses_separate_region_groups(self):
        profile = {"systems": ["odyssey2", "videopac"]}
        north_america = _emulator_region_group(
            "o2em", profile, {"name": "o2rom.bin", "system": "odyssey2"}
        )
        europe = _emulator_region_group(
            "o2em", profile, {"name": "c52.bin", "system": "videopac"}
        )
        self.assertNotEqual(north_america, europe)

    def test_region_audit_accepts_list_valued_md5(self):
        sha1 = "a" * 40
        md5 = "b" * 32
        db = {
            "files": {sha1: {}},
            "indexes": {"by_md5": {md5: sha1}, "by_name": {}},
        }
        self.assertEqual(
            region_audit.resolve_sha1({"name": "bios.bin", "md5": [md5]}, db),
            sha1,
        )


class ArchiveSecurityRegressions(unittest.TestCase):
    def _zip_path(self, directory: Path, name: str = "archive.zip") -> Path:
        return directory / name

    def test_member_count_limit_is_enforced(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("one.bin", b"1")
                handle.writestr("two.bin", b"2")
            with self.assertRaisesRegex(ValueError, "members"):
                safe_extract_zip(str(archive), str(root / "out"), max_members=1)

    def test_symlink_member_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            link = zipfile.ZipInfo("link")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr(link, "target")
            with self.assertRaisesRegex(ValueError, "link or special"):
                safe_extract_zip(str(archive), str(root / "out"))

    def test_windows_separator_is_a_path_not_a_rejection(self):
        """Archives written on Windows store a backslash separator.

        download.py feeds third-party archives to this function, so a legal
        Windows path must extract into a subdirectory instead of failing.
        """
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("sub\\rom.bin", b"payload")
            out = root / "out"
            safe_extract_zip(str(archive), str(out))
            self.assertEqual((out / "sub" / "rom.bin").read_bytes(), b"payload")

    def test_windows_separator_cannot_smuggle_traversal(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("..\\escaped.bin", b"payload")
            with self.assertRaisesRegex(ValueError, "traversal"):
                safe_extract_zip(str(archive), str(root / "out"))

    def test_high_ratio_method_is_bounded_by_size_not_ratio(self):
        """bzip2 legitimately exceeds the DEFLATE ceiling."""
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_BZIP2) as handle:
                handle.writestr("zeros.bin", bytes(4_000_000))
            out = root / "out"
            safe_extract_zip(str(archive), str(out))
            self.assertEqual((out / "zeros.bin").stat().st_size, 4_000_000)

    def test_compression_ratio_limit_is_enforced(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
                handle.writestr("zeros.bin", bytes(16_384))
            with self.assertRaisesRegex(ValueError, "compression ratio"):
                safe_extract_zip(
                    str(archive), str(root / "out"), max_compression_ratio=2
                )


class InstallerBoundaryRegressions(unittest.TestCase):
    def _manifest(self, dest: str) -> dict:
        return {
            "manifest_version": 2,
            "platform": "retroarch",
            "files": [
                {
                    "dest": dest,
                    "size": 1,
                    "sha1": "a" * 40,
                    "sha256": "b" * 64,
                    "repo_path": "bios/test.bin",
                    "cores": None,
                }
            ],
            "standalone_copies": [],
        }

    def test_manifest_destination_traversal_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsafe"):
            install._validate_manifest(self._manifest("../escape"), "retroarch")

    def test_manifest_repo_source_is_confined_to_bios(self):
        manifest = self._manifest("safe.bin")
        manifest["files"][0]["repo_path"] = "scripts/pipeline.py"
        with self.assertRaisesRegex(ValueError, "outside bios"):
            install._validate_manifest(manifest, "retroarch")

    def test_omitted_destination_cannot_overlap_a_download(self):
        manifest = self._manifest("safe.bin")
        manifest["omitted_files"] = [
            {
                "dest": "safe.bin",
                "name": "safe.bin",
                "system": "console",
                "required": True,
                "reason": "hash_mismatch",
                "cores": None,
            }
        ]
        manifest["total_omitted"] = 1
        with self.assertRaisesRegex(ValueError, "conflicting omitted"):
            install._validate_manifest(manifest, "retroarch")

    def test_omitted_destination_traversal_is_rejected(self):
        manifest = self._manifest("safe.bin")
        manifest["omitted_files"] = [
            {
                "dest": "../unsafe.bin",
                "name": "unsafe.bin",
                "system": "console",
                "required": True,
                "reason": "hash_mismatch",
                "cores": None,
            }
        ]
        manifest["total_omitted"] = 1
        with self.assertRaisesRegex(ValueError, "unsafe"):
            install._validate_manifest(manifest, "retroarch")

    def test_target_schema_accepts_the_null_the_generator_emits(self):
        """The schema and generate_target_manifests must agree on null.

        A target with no core list is written as null; a schema that rejects
        it turns a valid manifest into a CI failure.
        """
        from jsonschema import Draft202012Validator

        schema = json.loads(
            (ROOT / "schemas" / "target-manifest.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validator = Draft202012Validator(schema)
        document = {"windows": None, "switch": ["a5200"]}
        self.assertEqual(list(validator.iter_errors(document)), [])

    def test_pack_manifests_are_read_from_inside_the_archive(self):
        """generate_pack writes manifest.json into the ZIP, not beside it.

        A filesystem glob over dist/ matches nothing and reports success
        without validating a single document.
        """
        import validate_schemas

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            dist = Path(directory)
            broken = {
                "schema_version": 1,
                "version": 1,
                "generator": "retrobios generate_pack.py",
                "generated": "2026-08-10T00:00:00Z",
                "files": [{"path": "a.bin", "sha1": "nope", "md5": "nope",
                           "size": 1, "status": "verified", "name": "a.bin"}],
                "summary": {"total_files": 1, "verified": 1, "untracked": 0,
                            "errors": 0},
                "errors": [],
            }
            with zipfile.ZipFile(dist / "Pack.zip", "w") as archive:
                archive.writestr("manifest.json", json.dumps(broken))

            errors = validate_schemas._validate_pack_manifests(dist)
            self.assertTrue(errors, "an invalid in-archive manifest must be reported")
            self.assertTrue(any("sha1" in message for message in errors), errors)

    def test_null_core_list_keeps_the_other_targets(self):
        """A target without a core inventory must not void the manifest.

        generate_target_manifests emits null for a target that publishes no
        core list; rejecting the document would silently disable --target for
        every target on that platform.
        """
        normalized = install._validate_targets({"windows": None, "switch": ["a5200"]})
        self.assertIsNone(normalized["windows"]["cores"])
        self.assertEqual(normalized["switch"]["cores"], ["a5200"])

    def test_legacy_target_lists_are_normalized(self):
        self.assertEqual(
            install._validate_targets({"rpi4": ["core-a", "core-b"]}),
            {"rpi4": {"cores": ["core-a", "core-b"]}},
        )


class TargetManifestRegressions(unittest.TestCase):
    def test_yaml_scalar_core_is_rejected_instead_of_leaking_to_json(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            source = root / "source"
            output = root / "output"
            source.mkdir()
            (source / "platform.yml").write_text(
                "targets:\n  device:\n    cores: [81, valid-core]\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "non-empty strings"):
                generate_target_manifests(str(source), str(output))


class CheckoutCompletenessRegressions(unittest.TestCase):
    """Coverage is resolved against the disk, so the checkout must be whole.

    Files over 50 MB and the data directory caches are gitignored. A job that
    regenerates the README or the site without restoring them counts those
    files as missing and publishes a coverage the collection does not have.
    """

    def _steps(self, workflow: str, job: str) -> list[dict]:
        data = yaml.safe_load((ROOT / ".github" / "workflows" / workflow).read_text())
        return data["jobs"][job]["steps"]

    def _index(self, steps: list[dict], needle: str) -> int:
        for position, step in enumerate(steps):
            if needle in step.get("name", "") or needle in str(step.get("run", "")):
                return position
        self.fail(f"no step matching {needle!r}")

    def test_site_deploy_completes_the_checkout_before_generating(self):
        steps = self._steps("deploy-site.yml", "build")
        generate = self._index(steps, "Generate site")
        self.assertLess(self._index(steps, "restore_large_files.py"), generate)
        self.assertLess(self._index(steps, "refresh_data_dirs.py"), generate)

    def test_restore_matches_assets_by_content_not_by_name(self):
        from scripts.restore_large_files import restore

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            cache = root / "cache"
            cache.mkdir()
            payload = b"firmware bytes"
            (cache / "renamed-asset.bin").write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            (root / ".gitignore").write_text("bios/Sony/big.pup\n", encoding="utf-8")
            (root / "database.json").write_text(
                json.dumps({"files": {sha1: {"path": "bios/Sony/big.pup"}}}),
                encoding="utf-8",
            )
            cwd = os.getcwd()
            os.chdir(root)
            try:
                self.assertEqual(restore(str(cache), "database.json", ".gitignore"), 1)
                self.assertEqual((root / "bios/Sony/big.pup").read_bytes(), payload)
                # A path already in the checkout is never overwritten.
                self.assertEqual(restore(str(cache), "database.json", ".gitignore"), 0)
            finally:
                os.chdir(cwd)

    def test_restore_leaves_tracked_paths_alone(self):
        from scripts.restore_large_files import restore

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            cache = root / "cache"
            cache.mkdir()
            payload = b"tracked bytes"
            (cache / "asset.bin").write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            (root / ".gitignore").write_text("bios/other.bin\n", encoding="utf-8")
            (root / "database.json").write_text(
                json.dumps({"files": {sha1: {"path": "bios/tracked.bin"}}}),
                encoding="utf-8",
            )
            cwd = os.getcwd()
            os.chdir(root)
            try:
                self.assertEqual(restore(str(cache), "database.json", ".gitignore"), 0)
                self.assertFalse((root / "bios/tracked.bin").exists())
            finally:
                os.chdir(cwd)


class EveryManifestEntryIsFetchable(unittest.TestCase):
    """An install manifest may not list a file the installer cannot get.

    install.py fetches a file either from its repo_path or from a release
    asset. An entry carrying neither is a line in the download list that can
    only ever fail. It happened when resolution landed on a file the database
    does not index, so the hash was computed but the repo lookup came back
    empty and the entry shipped anyway.
    """

    def test_committed_manifests_all_have_a_source(self):
        manifests = sorted((ROOT / "install").glob("*.json"))
        self.assertTrue(manifests, "no install manifests to check")
        for path in manifests:
            with self.subTest(manifest=path.name):
                data = json.loads(path.read_text())
                orphans = [
                    entry["dest"]
                    for entry in data.get("files", [])
                    if not entry.get("repo_path") and not entry.get("release_asset")
                ]
                self.assertEqual(
                    orphans, [], f"{path.name} lists unfetchable files: {orphans[:3]}"
                )

    def test_an_unresolvable_file_is_recorded_as_omitted(self):
        """The reason must be one install.py knows how to report."""
        allowed = {"hash_mismatch", "not_found", "external", "user_provided"}
        for path in sorted((ROOT / "install").glob("*.json")):
            with self.subTest(manifest=path.name):
                data = json.loads(path.read_text())
                for entry in data.get("omitted_files", []):
                    self.assertIn(entry.get("reason"), allowed)


class PreservedBytesAreNeverNormalised(unittest.TestCase):
    """git must not rewrite a preserved file's line endings.

    SHA1 is the primary key of this collection. Git for Windows sets
    core.autocrlf=true by default, so without an attribute saying otherwise a
    clone there rewrites every file git guesses is text -- shaders, .ini,
    .txt and .dat assets under bios/ -- and each one arrives with a different
    hash from the one published here.
    """

    def _attr(self, path: str) -> str:
        import subprocess

        out = subprocess.run(
            ["git", "check-attr", "text", "--", path],
            capture_output=True, text=True, cwd=ROOT,
        ).stdout
        return out.rsplit(":", 1)[-1].strip()

    def test_gitattributes_exists(self):
        self.assertTrue(
            (ROOT / ".gitattributes").is_file(),
            "without it git guesses, and guesses wrong on Windows",
        )

    def test_collection_paths_are_exempt_from_normalisation(self):
        for path in (
            "bios/Sony/PlayStation/scph5501.bin",
            "bios/Other/j2me-loader/color.fsh",
            "data/anything.txt",
            "data/dolphin-sys/config.json",
        ):
            with self.subTest(path=path):
                self.assertEqual(self._attr(path), "unset", f"{path} may be rewritten")

    def test_generated_artefacts_stay_lf(self):
        for path in (
            "database.json",
            "scripts/dedup.py",
            "README.md",
            "provenance/redump.json",
        ):
            with self.subTest(path=path):
                self.assertEqual(self._attr(path), "set")


class FreshnessGuardMechanics(unittest.TestCase):
    """write_if_changed is what makes `git diff --exit-code` a real check.

    deploy-site.yml regenerates README.md and CONTRIBUTING.md and then fails
    if git sees a change. That is only a staleness check because a run which
    moves nothing but the clock leaves the file untouched; if the comparison
    missed a timestamp form, the guard would fail on every run and stop
    meaning anything.
    """

    def setUp(self):
        from common import write_if_changed

        self.write_if_changed = write_if_changed
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "page.md")

    def tearDown(self):
        self._tmp.cleanup()

    def test_a_new_file_is_written(self):
        self.assertTrue(self.write_if_changed(self.path, "body\n"))
        with open(self.path) as handle:
            self.assertEqual(handle.read(), "body\n")

    def test_identical_content_is_not_rewritten(self):
        self.write_if_changed(self.path, "body\n")
        self.assertFalse(self.write_if_changed(self.path, "body\n"))

    def test_real_change_is_written(self):
        self.write_if_changed(self.path, "body\n")
        self.assertTrue(self.write_if_changed(self.path, "other\n"))

    def test_every_timestamp_form_is_ignored_on_its_own(self):
        forms = [
            '{{"generated_at": "{}"}}',
            '{{"imported_at": "{}"}}',
            "*Auto-generated on {}*",
            "*Generated on {}*",
            '<div class="rb-timestamp">Generated on {}.</div>',
        ]
        for form in forms:
            with self.subTest(form=form):
                first = form.format("2026-01-01T00:00:00Z")
                second = form.format("2026-09-09T09:09:09Z")
                self.write_if_changed(self.path, first)
                self.assertFalse(
                    self.write_if_changed(self.path, second),
                    f"a clock-only change rewrote the file for {form!r}",
                )

    def test_a_change_beside_a_moving_timestamp_is_still_written(self):
        self.write_if_changed(self.path, "count: 1\n*Generated on A*\n")
        self.assertTrue(
            self.write_if_changed(self.path, "count: 2\n*Generated on B*\n")
        )

    def test_the_written_file_keeps_the_new_timestamp_when_content_changed(self):
        self.write_if_changed(self.path, "count: 1\n*Generated on A*\n")
        self.write_if_changed(self.path, "count: 2\n*Generated on B*\n")
        with open(self.path) as handle:
            self.assertIn("Generated on B", handle.read())


if __name__ == "__main__":
    unittest.main()


class ScriptsImportThreeWays(unittest.TestCase):
    """A script is run directly, run as a module, and imported as a package.

    The three do not agree on what is on the path: only the first form adds
    the scripts directory. Adding the package marker without the bootstrap
    made `import scripts.common` fail on the first sibling import it reached.
    """

    def _run(self, *args: str):
        import subprocess

        return subprocess.run(
            [sys.executable, *args],
            capture_output=True, text=True, cwd=str(ROOT), timeout=300,
        )

    def test_imported_as_a_package(self):
        result = self._run(
            "-c", "import scripts.common, scripts.verify, scripts.generate_pack"
        )
        self.assertEqual(result.returncode, 0, result.stderr[-400:])

    def test_run_as_a_module(self):
        result = self._run("-m", "scripts.scraper.libretro_scraper", "--help")
        self.assertEqual(result.returncode, 0, result.stderr[-400:])

    def test_run_as_a_script(self):
        result = self._run("scripts/list_platforms.py")
        self.assertEqual(result.returncode, 0, result.stderr[-400:])


class ContributorsSurviveAFailedRequest(unittest.TestCase):
    """The one part of the README that comes from the network.

    A refused or rate-limited request left the list empty, which deleted the
    section from a published README. It happened during a pipeline run and
    the result was committed, after which the freshness check regenerated the
    section and failed on the difference. Losing the list is a worse answer
    than publishing a stale one.
    """

    def _block(self, text: str):
        import tempfile

        sys.path.insert(0, str(ROOT / "scripts"))
        from generate_readme import _existing_contributor_block

        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as handle:
            handle.write(text)
            name = handle.name
        try:
            return _existing_contributor_block(name)
        finally:
            os.unlink(name)

    def test_a_published_list_is_read_back(self):
        text = (
            "# Title\n\n## Contributors\n\n"
            '<a href="https://github.com/a"><img src="x" alt="a"></a>\n'
            '<a href="https://github.com/b"><img src="y" alt="b"></a>\n\n'
            "## Community tools\n\nsomething else\n"
        )
        block = self._block(text)
        self.assertEqual(block[0], "## Contributors")
        self.assertIn('alt="a"', "\n".join(block))
        self.assertIn('alt="b"', "\n".join(block))
        self.assertNotIn("Community tools", "\n".join(block))
        self.assertNotIn("something else", "\n".join(block))

    def test_a_readme_without_the_section_yields_nothing(self):
        self.assertEqual(self._block("# Title\n\n## Other\n\ntext\n"), [])

    def test_an_unreadable_file_yields_nothing(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        from generate_readme import _existing_contributor_block

        self.assertEqual(_existing_contributor_block("/nonexistent/README.md"), [])

    def test_the_committed_readme_still_carries_its_contributors(self):
        """Regenerating offline must never be the reason this disappears."""
        text = (ROOT / "README.md").read_text()
        if "## Contributors" not in text:
            self.skipTest("README carries no contributors section")
        self.assertGreater(
            text.count('<a href="https://github.com/'), 0,
            "the section is present but empty",
        )


class ModuleConstantsDeclaredOnce(unittest.TestCase):
    """Splitting common.py into modules emitted some constants twice.

    The values matched, so nothing broke, but the second assignment orphans
    the comment written above the first and leaves two lines to keep in step
    the day a value changes.
    """

    @staticmethod
    def _redeclared(path: Path) -> list[str]:
        seen: dict[str, str] = {}
        again = []
        for node in ast.parse(path.read_text()).body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            value = ast.unparse(node.value)
            if seen.get(target.id) == value:
                again.append(target.id)
            seen[target.id] = value
        return again

    def test_no_module_assigns_the_same_constant_twice(self):
        offenders = {}
        for path in sorted(ROOT.glob("scripts/**/*.py")) + [ROOT / "install.py"]:
            again = self._redeclared(path)
            if again:
                offenders[path.name] = again
        self.assertEqual(offenders, {})
