"""Tests for the hash merge module."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import tempfile
import unittest
from pathlib import Path

import yaml

from scripts.scraper._hash_merge import (
    _build_source_ref,
    compute_diff,
    merge_fbneo_profile,
    merge_mame_profile,
)


def _write_yaml(path: Path, data: dict) -> str:
    p = str(path)
    with open(p, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    return p


def _write_json(path: Path, data: dict) -> str:
    p = str(path)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return p


def _make_mame_profile(**overrides: object) -> dict:
    base = {
        "emulator": "MAME",
        "core_version": "0.285",
        "files": [
            {
                "name": "neogeo.zip",
                "required": True,
                "category": "bios_zip",
                "system": "snk-neogeo-mvs",
                "source_ref": "src/mame/neogeo/neogeo.cpp:2400",
                "contents": [
                    {
                        "name": "sp-s2.sp1",
                        "size": 131072,
                        "crc32": "oldcrc32",
                        "description": "Europe MVS (Ver. 2)",
                    },
                ],
            },
        ],
    }
    base.update(overrides)
    return base


def _make_mame_hashes(**overrides: object) -> dict:
    base = {
        "source": "mamedev/mame",
        "version": "0.286",
        "commit": "abc123",
        "fetched_at": "2026-03-30T12:00:00Z",
        "bios_sets": {
            "neogeo": {
                "source_file": "src/mame/neogeo/neogeo.cpp",
                "source_line": 2432,
                "roms": [
                    {
                        "name": "sp-s2.sp1",
                        "size": 131072,
                        "crc32": "9036d879",
                        "sha1": "4f834c55",
                        "region": "mainbios",
                        "bios_label": "euro",
                        "bios_description": "Europe MVS (Ver. 2)",
                    },
                ],
            },
        },
    }
    base.update(overrides)
    return base


def _make_fbneo_profile(**overrides: object) -> dict:
    base = {
        "emulator": "FinalBurn Neo",
        "core_version": "v1.0.0.02",
        "files": [
            {
                "name": "sp-s2.sp1",
                "archive": "neogeo.zip",
                "system": "snk-neogeo-mvs",
                "required": True,
                "size": 131072,
                "crc32": "oldcrc32",
                "source_ref": "src/burn/drv/neogeo/d_neogeo.cpp:1605",
            },
            {
                "name": "hiscore.dat",
                "required": False,
            },
        ],
    }
    base.update(overrides)
    return base


def _make_fbneo_hashes(**overrides: object) -> dict:
    base = {
        "source": "finalburnneo/FBNeo",
        "version": "v1.0.0.03",
        "commit": "def456",
        "fetched_at": "2026-03-30T12:00:00Z",
        "bios_sets": {
            "neogeo": {
                "source_file": "src/burn/drv/neogeo/d_neogeo.cpp",
                "source_line": 1604,
                "roms": [
                    {
                        "name": "sp-s2.sp1",
                        "size": 131072,
                        "crc32": "9036d879",
                        "sha1": "aabbccdd",
                    },
                ],
            },
        },
    }
    base.update(overrides)
    return base


class TestMameMerge(unittest.TestCase):
    """Tests for merge_mame_profile."""

    def test_merge_updates_contents(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "mame.yml", _make_mame_profile())
            hashes_path = _write_json(p / "hashes.json", _make_mame_hashes())

            result = merge_mame_profile(profile_path, hashes_path)

            bios_files = [f for f in result["files"] if f.get("category") == "bios_zip"]
            self.assertEqual(len(bios_files), 1)
            contents = bios_files[0]["contents"]
            self.assertEqual(contents[0]["crc32"], "9036d879")
            self.assertEqual(contents[0]["sha1"], "4f834c55")
            self.assertEqual(contents[0]["description"], "Europe MVS (Ver. 2)")

    def test_merge_preserves_manual_fields(self) -> None:
        profile = _make_mame_profile()
        profile["files"][0]["note"] = "manually curated note"
        profile["files"][0]["system"] = "snk-neogeo-mvs"
        profile["files"][0]["required"] = False

        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "mame.yml", profile)
            hashes_path = _write_json(p / "hashes.json", _make_mame_hashes())

            result = merge_mame_profile(profile_path, hashes_path)

            entry = [f for f in result["files"] if f.get("category") == "bios_zip"][0]
            self.assertEqual(entry["note"], "manually curated note")
            self.assertEqual(entry["system"], "snk-neogeo-mvs")
            self.assertFalse(entry["required"])

    def test_merge_sets_required_false_for_a_set_the_machine_runs_without(self) -> None:
        profile = _make_mame_profile()
        profile["files"].append({
            "name": "mac2bios.zip", "required": True, "category": "bios_zip",
            "note": "kept",
        })
        hashes = _make_mame_hashes()
        hashes["bios_sets"]["mac2bios"] = {
            "source_file": "src/mame/seta/macs.cpp", "source_line": 776,
            "roms": [], "required": False,
        }
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "mame.yml", profile)
            hashes_path = _write_json(p / "hashes.json", hashes)

            diff = compute_diff(profile_path, hashes_path, mode="mame")
            self.assertIn("mac2bios", diff["updated"])

            result = merge_mame_profile(profile_path, hashes_path)
            entry = next(f for f in result["files"] if f["name"] == "mac2bios.zip")
            self.assertFalse(entry["required"])
            self.assertEqual(entry["note"], "kept")

    def test_written_profile_carries_the_settled_required(self) -> None:
        """The text patcher rewrote contents and source_ref but left required."""
        hashes = _make_mame_hashes()
        hashes["bios_sets"] = {"mac2bios": {
            "source_file": "src/mame/seta/macs.cpp", "source_line": 776,
            "roms": [], "required": False,
        }}
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = str(p / "mame.yml")
            Path(profile_path).write_text(
                'emulator: MAME\ncore_version: "0.289"\nfiles:\n'
                "  - name: mac2bios.zip\n    required: true\n    category: bios_zip\n"
                '    source_ref: "upstream src/mame/seta/macs.cpp:776"\n',
                encoding="utf-8",
            )
            hashes_path = _write_json(p / "hashes.json", hashes)
            merge_mame_profile(profile_path, hashes_path, write=True)
            written = yaml.safe_load(Path(profile_path).read_text(encoding="utf-8"))
        entry = next(f for f in written["files"] if f["name"] == "mac2bios.zip")
        self.assertIs(entry["required"], False)

    def test_merge_keeps_a_curated_false_over_a_fatal_set(self) -> None:
        profile = _make_mame_profile()
        profile["files"][0]["required"] = False
        hashes = _make_mame_hashes()
        hashes["bios_sets"]["neogeo"]["required"] = True
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "mame.yml", profile)
            hashes_path = _write_json(p / "hashes.json", hashes)
            result = merge_mame_profile(profile_path, hashes_path)
            entry = next(f for f in result["files"] if f["name"] == "neogeo.zip")
            self.assertFalse(entry["required"])

    def test_merge_restores_required_once_an_undumped_set_is_dumped(self) -> None:
        profile = _make_mame_profile()
        profile["files"].append({
            "name": "recel.zip", "required": False, "category": "bios_zip",
            "contents": [],
        })
        hashes = _make_mame_hashes()
        hashes["bios_sets"]["recel"] = {
            "source_file": "src/mame/pinball/recel.cpp", "source_line": 546,
            "roms": [{"name": "a2361.b1", "size": 1024, "crc32": "eeb8f3f0"}],
            "required": True,
        }
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "mame.yml", profile)
            hashes_path = _write_json(p / "hashes.json", hashes)
            result = merge_mame_profile(profile_path, hashes_path)
            entry = next(f for f in result["files"] if f["name"] == "recel.zip")
            self.assertTrue(entry["required"])

    def test_merge_adds_new_bios_set(self) -> None:
        hashes = _make_mame_hashes()
        hashes["bios_sets"]["pgm"] = {
            "source_file": "src/mame/igs/pgm.cpp",
            "source_line": 5515,
            "roms": [
                {"name": "pgm_t01s.rom", "size": 2097152, "crc32": "1a7123a0"},
            ],
        }

        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "mame.yml", _make_mame_profile())
            hashes_path = _write_json(p / "hashes.json", hashes)

            result = merge_mame_profile(profile_path, hashes_path)

            bios_files = [f for f in result["files"] if f.get("category") == "bios_zip"]
            names = {f["name"] for f in bios_files}
            self.assertIn("pgm.zip", names)

            pgm = next(f for f in bios_files if f["name"] == "pgm.zip")
            self.assertIsNone(pgm["system"])
            self.assertTrue(pgm["required"])
            self.assertEqual(pgm["category"], "bios_zip")

    def test_numeric_looking_rom_name_survives_the_write(self) -> None:
        """MAME ships ROMs named 01 and 23. Bare YAML turns them into numbers.

        The manager set loads "01", but written unquoted it re-parses as the
        integer 1 and the profile stops naming the file the driver opens.
        """
        from scripts.scraper._hash_merge import (
            _append_new_entries,
            _format_contents,
        )

        contents = [
            {"name": "01", "description": "ROM bank 0-1", "size": 8192,
             "crc32": "702f4cf5"},
            {"name": "23", "description": "ROM bank 2-3", "size": 8192,
             "crc32": "46489d88"},
        ]
        document = yaml.safe_load(
            "files:\n  - name: manager.zip\n" + _format_contents(contents)
        )
        names = [rom["name"] for rom in document["files"][0]["contents"]]
        self.assertEqual(names, ["01", "23"])
        for name in names:
            self.assertIsInstance(name, str)

        original = "emulator: MAME\nfiles:\n  - name: neogeo.zip\n"
        appended = _append_new_entries(
            original,
            [{
                "name": "manager.zip",
                "required": False,
                "category": "bios_zip",
                "source_ref": "src/mame/vtech/crvision.cpp:955-959",
                "contents": contents,
            }],
            original,
        )
        entry = next(
            f
            for f in yaml.safe_load(appended)["files"]
            if f["name"] == "manager.zip"
        )
        self.assertEqual(
            [rom["name"] for rom in entry["contents"]], ["01", "23"]
        )

    def test_merge_preserves_non_bios_files(self) -> None:
        profile = _make_mame_profile()
        profile["files"].append({"name": "hiscore.dat", "required": False})

        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "mame.yml", profile)
            hashes_path = _write_json(p / "hashes.json", _make_mame_hashes())

            result = merge_mame_profile(profile_path, hashes_path)

            non_bios = [f for f in result["files"] if f.get("category") != "bios_zip"]
            self.assertEqual(len(non_bios), 1)
            self.assertEqual(non_bios[0]["name"], "hiscore.dat")

    def test_merge_keeps_unmatched_bios_set(self) -> None:
        """Entries not in scraper scope stay untouched (no _upstream_removed)."""
        hashes = _make_mame_hashes()
        hashes["bios_sets"] = {}  # nothing from scraper

        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "mame.yml", _make_mame_profile())
            hashes_path = _write_json(p / "hashes.json", hashes)

            result = merge_mame_profile(profile_path, hashes_path)

            bios_files = [f for f in result["files"] if f.get("category") == "bios_zip"]
            self.assertEqual(len(bios_files), 1)
            self.assertNotIn("_upstream_removed", bios_files[0])
            self.assertEqual(bios_files[0]["name"], "neogeo.zip")

    def test_merge_updates_core_version(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "mame.yml", _make_mame_profile())
            hashes_path = _write_json(p / "hashes.json", _make_mame_hashes())

            result = merge_mame_profile(profile_path, hashes_path)

            self.assertEqual(result["core_version"], "0.286")

    def test_merge_backup_created(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "mame.yml", _make_mame_profile())
            hashes_path = _write_json(p / "hashes.json", _make_mame_hashes())

            merge_mame_profile(profile_path, hashes_path, write=True)

            backup = p / "mame.old.yml"
            self.assertTrue(backup.exists())

            with open(backup, encoding="utf-8") as f:
                old = yaml.safe_load(f)
            self.assertEqual(old["core_version"], "0.285")

    def test_merge_updates_source_ref(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "mame.yml", _make_mame_profile())
            hashes_path = _write_json(p / "hashes.json", _make_mame_hashes())

            result = merge_mame_profile(profile_path, hashes_path)

            entry = [f for f in result["files"] if f.get("category") == "bios_zip"][0]
            self.assertEqual(entry["source_ref"], "src/mame/neogeo/neogeo.cpp:2432")


class TheMamePinMovesWithItsRefs(unittest.TestCase):
    """The refs the merge writes are line numbers of the scraped release:
    leaving upstream_commit on an older revision made the profile cite lines
    its declared revision does not hold (pgm.cpp:5548 is a comment there)."""

    def _merged_text(self, **profile_overrides) -> str:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(
                p / "mame.yml", _make_mame_profile(**profile_overrides)
            )
            hashes_path = _write_json(
                p / "hashes.json", _make_mame_hashes(commit="f" * 40)
            )
            merge_mame_profile(profile_path, hashes_path, write=True)
            return Path(profile_path).read_text(encoding="utf-8")

    def test_the_upstream_pin_follows_the_release(self):
        text = self._merged_text(
            upstream="https://github.com/mamedev/mame", upstream_commit="a" * 40
        )
        written = yaml.safe_load(text)
        self.assertEqual(written["upstream_commit"], "f" * 40)
        self.assertEqual(written["core_version"], "0.286")

    def test_a_fork_keeps_its_own_pin(self):
        text = self._merged_text(
            upstream="https://github.com/example/fork", upstream_commit="a" * 40
        )
        self.assertEqual(yaml.safe_load(text)["upstream_commit"], "a" * 40)


class TheScraperClonesTheReleaseItLabels(unittest.TestCase):
    """Cloning master and labelling it with the latest release tag gave
    master's line numbers and hashes under the release's name."""

    def test_clone_and_version_come_from_one_tag(self):
        from unittest import mock

        from scripts.scraper import mame_hash_scraper as scraper

        calls: list[list[str]] = []
        with mock.patch.object(scraper, "_get_release_tag", return_value="mame0289"), \
                mock.patch.object(scraper, "_run_git",
                                  side_effect=lambda args, cwd=None: calls.append(args)), \
                mock.patch.object(scraper, "parse_mame_source_tree",
                                  return_value={"neogeo": {"roms": []}}), \
                mock.patch.object(scraper, "_get_commit", return_value="c" * 40), \
                mock.patch.object(scraper, "_write_cache"), \
                mock.patch.object(scraper, "_cleanup"), \
                mock.patch.object(scraper, "_load_cache", return_value={}), \
                mock.patch.object(scraper, "_is_stale", return_value=True):
            data = scraper._fetch_hashes(force=True)
        clone = next(args for args in calls if args[0] == "clone")
        self.assertEqual(clone[clone.index("--branch") + 1], "mame0289")
        self.assertEqual(data["version"], "0.289")
        self.assertEqual(data["commit"], "c" * 40)


class AReleaseProfileDescribesItsOwnRelease(unittest.TestCase):
    """Recalbox builds libretro/mame at 0.258 and at 0.278, but the current
    MAME profile described neither. A release profile carries that
    release's sets and pins, and keeps the system the current profile
    gives a set."""

    def test_sets_pins_and_systems(self):
        from scripts.scraper.mame_hash_scraper import release_profile

        bios_sets = {
            "neogeo": {"source_file": "src/mame/neogeo/neogeo.cpp", "source_line": 10,
                       "roms": [{"name": "sp-s2.sp1", "size": 131072, "crc32": "9036d879"}]},
            "newset": {"source_file": "src/mame/x/x.cpp", "source_line": 5, "roms": []},
        }
        reference = {"systems": ["snk-neogeo-mvs"], "files": [
            {"name": "neogeo.zip", "category": "bios_zip", "system": "snk-neogeo-mvs",
             "required": True},
            {"name": "gone.zip", "category": "bios_zip", "system": "x"},
        ]}
        profile = release_profile(
            "mame0278", bios_sets, "a" * 40, "b" * 40, ["mame0278"], reference,
            ["recalbox"],
        )
        self.assertEqual(profile["core_version"], "0.278")
        self.assertEqual(profile["upstream"], "https://github.com/mamedev/mame/tree/mame0278")
        self.assertEqual((profile["upstream_commit"], profile["source_commit"]),
                         ("a" * 40, "b" * 40))
        self.assertEqual(profile["cores"], ["mame0278"])
        self.assertEqual(profile["built_by"], ["recalbox"])
        # libretro/mame HEAD is a later release: the profile is judged
        # against the revision the platform builds.
        self.assertIn("recalbox builds libretro/mame", profile["pin_frozen"])
        files = {f["name"]: f for f in profile["files"]}
        self.assertEqual(sorted(files), ["neogeo.zip", "newset.zip"])
        self.assertEqual(files["neogeo.zip"]["system"], "snk-neogeo-mvs")
        self.assertNotIn("system", files["newset.zip"])
        self.assertEqual(files["neogeo.zip"]["source_ref"], "upstream src/mame/neogeo/neogeo.cpp:10")
        # The libretro build reads <system>/mame/bios, never the system root.
        self.assertEqual(files["neogeo.zip"]["path"], "mame/bios/neogeo.zip")

    def test_a_set_the_release_runs_without_is_not_required(self):
        """recel is undumped at 0.258: the current profile's true does not apply."""
        from scripts.scraper.mame_hash_scraper import release_profile

        bios_sets = {
            "recel": {"source_file": "src/mame/pinball/recel.cpp", "source_line": 505,
                      "roms": [], "required": False},
            "neogeo": {"source_file": "src/mame/neogeo/neogeo.cpp", "source_line": 10,
                       "roms": [{"name": "sp-s2.sp1", "size": 131072, "crc32": "9036d879"}],
                       "required": True},
        }
        reference = {"files": [
            {"name": "recel.zip", "category": "bios_zip", "required": True,
             "contents": [{"name": "a2361.b1", "size": 1024, "crc32": "eeb8f3f0"}]},
            {"name": "neogeo.zip", "category": "bios_zip", "required": True},
        ]}
        profile = release_profile(
            "mame0258", bios_sets, "a" * 40, "b" * 40, ["mame0258"], reference,
            ["recalbox"],
        )
        files = {f["name"]: f for f in profile["files"]}
        self.assertFalse(files["recel.zip"]["required"])
        self.assertTrue(files["neogeo.zip"]["required"])

    def test_a_release_profile_is_left_out_of_the_current_refresh(self):
        from scripts.scraper.mame_hash_scraper import _find_mame_profiles

        names = {path.name for path in _find_mame_profiles()}
        self.assertIn("mame.yml", names)
        self.assertFalse({"mame0258.yml", "mame0278.yml"} & names)

    def test_a_pinned_build_of_the_mame_tree_is_left_out(self):
        """pSxMAME builds mamedev/mame at 0.133: refreshed, it would carry 0.289 refs."""
        from scripts.scraper.mame_hash_scraper import _find_mame_profiles

        self.assertNotIn("psxmame.yml", {path.name for path in _find_mame_profiles()})


class TestFbneoMerge(unittest.TestCase):
    """Tests for merge_fbneo_profile."""

    def test_merge_updates_rom_entries(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "fbneo.yml", _make_fbneo_profile())
            hashes_path = _write_json(p / "hashes.json", _make_fbneo_hashes())

            result = merge_fbneo_profile(profile_path, hashes_path)

            archive_files = [f for f in result["files"] if "archive" in f]
            self.assertEqual(len(archive_files), 1)
            self.assertEqual(archive_files[0]["crc32"], "9036d879")
            self.assertEqual(archive_files[0]["system"], "snk-neogeo-mvs")

    def test_merge_adds_new_roms(self) -> None:
        hashes = _make_fbneo_hashes()
        hashes["bios_sets"]["neogeo"]["roms"].append(
            {
                "name": "sp-s3.sp1",
                "size": 131072,
                "crc32": "91b64be3",
            }
        )

        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "fbneo.yml", _make_fbneo_profile())
            hashes_path = _write_json(p / "hashes.json", hashes)

            result = merge_fbneo_profile(profile_path, hashes_path)

            archive_files = [f for f in result["files"] if "archive" in f]
            self.assertEqual(len(archive_files), 2)
            new_rom = next(f for f in archive_files if f["name"] == "sp-s3.sp1")
            self.assertEqual(new_rom["archive"], "neogeo.zip")
            self.assertTrue(new_rom["required"])

    def test_merge_preserves_non_archive_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "fbneo.yml", _make_fbneo_profile())
            hashes_path = _write_json(p / "hashes.json", _make_fbneo_hashes())

            result = merge_fbneo_profile(profile_path, hashes_path)

            non_archive = [f for f in result["files"] if "archive" not in f]
            self.assertEqual(len(non_archive), 1)
            self.assertEqual(non_archive[0]["name"], "hiscore.dat")

    def test_merge_keeps_unmatched_roms(self) -> None:
        """Entries not in scraper scope stay untouched (no _upstream_removed)."""
        hashes = _make_fbneo_hashes()
        hashes["bios_sets"] = {}

        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "fbneo.yml", _make_fbneo_profile())
            hashes_path = _write_json(p / "hashes.json", hashes)

            result = merge_fbneo_profile(profile_path, hashes_path)

            archive_files = [f for f in result["files"] if "archive" in f]
            self.assertEqual(len(archive_files), 1)
            self.assertNotIn("_upstream_removed", archive_files[0])

    def test_merge_leaves_core_version_to_the_pin(self) -> None:
        # The hashes are read at finalburnneo/FBNeo's tip, which the
        # profile's libretro/FBNeo pin does not name: the version stays the
        # one version_basis reads at that pin.
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "fbneo.yml", _make_fbneo_profile())
            hashes_path = _write_json(p / "hashes.json", _make_fbneo_hashes())

            result = merge_fbneo_profile(profile_path, hashes_path)

            self.assertEqual(result["core_version"], "v1.0.0.02")


class TestDiff(unittest.TestCase):
    """Tests for compute_diff."""

    def test_diff_mame_detects_changes(self) -> None:
        hashes = _make_mame_hashes()
        hashes["bios_sets"]["pgm"] = {
            "source_file": "src/mame/igs/pgm.cpp",
            "source_line": 5515,
            "roms": [
                {"name": "pgm_t01s.rom", "size": 2097152, "crc32": "1a7123a0"},
            ],
        }

        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "mame.yml", _make_mame_profile())
            hashes_path = _write_json(p / "hashes.json", hashes)

            diff = compute_diff(profile_path, hashes_path, mode="mame")

            self.assertIn("pgm", diff["added"])
            self.assertIn("neogeo", diff["updated"])
            self.assertEqual(len(diff["removed"]), 0)
            self.assertEqual(diff["unchanged"], 0)

    def test_diff_mame_out_of_scope(self) -> None:
        """Items in profile but not in scraper output = out of scope, not removed."""
        hashes = _make_mame_hashes()
        hashes["bios_sets"] = {}

        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "mame.yml", _make_mame_profile())
            hashes_path = _write_json(p / "hashes.json", hashes)

            diff = compute_diff(profile_path, hashes_path, mode="mame")

            self.assertEqual(diff["removed"], [])
            self.assertEqual(diff["out_of_scope"], 1)
            self.assertEqual(len(diff["added"]), 0)

    def test_diff_fbneo_detects_changes(self) -> None:
        hashes = _make_fbneo_hashes()
        hashes["bios_sets"]["neogeo"]["roms"].append(
            {
                "name": "sp-s3.sp1",
                "size": 131072,
                "crc32": "91b64be3",
            }
        )

        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "fbneo.yml", _make_fbneo_profile())
            hashes_path = _write_json(p / "hashes.json", hashes)

            diff = compute_diff(profile_path, hashes_path, mode="fbneo")

            self.assertIn("neogeo.zip:sp-s3.sp1", diff["added"])
            self.assertIn("neogeo.zip:sp-s2.sp1", diff["updated"])
            self.assertEqual(len(diff["removed"]), 0)

    def test_diff_fbneo_unchanged(self) -> None:
        profile = _make_fbneo_profile()
        profile["files"][0]["crc32"] = "9036d879"
        profile["files"][0]["size"] = 131072

        hashes = _make_fbneo_hashes()

        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "fbneo.yml", profile)
            hashes_path = _write_json(p / "hashes.json", hashes)

            diff = compute_diff(profile_path, hashes_path, mode="fbneo")

            self.assertEqual(diff["unchanged"], 1)
            self.assertEqual(len(diff["added"]), 0)
            self.assertEqual(len(diff["updated"]), 0)

    def test_diff_fbneo_keeps_a_per_rom_ref(self) -> None:
        """The scraper knows the driver line, while a curated ref knows its ROM."""
        profile = _make_fbneo_profile()
        profile["files"][0]["crc32"] = "9036d879"
        profile["files"][0]["size"] = 131072
        profile["files"][0]["source_ref"] = "src/burn/drv/neogeo/d_neogeo.cpp:1615"

        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "fbneo.yml", profile)
            hashes_path = _write_json(p / "hashes.json", _make_fbneo_hashes())
            diff = compute_diff(profile_path, hashes_path, mode="fbneo")
            self.assertEqual(len(diff["updated"]), 0)
            self.assertEqual(diff["unchanged"], 1)


class TestSourceRefDrift(unittest.TestCase):
    """A set whose ROMs are unchanged but whose driver line moved is an update."""

    HASHES = {
        "version": "0.289",
        "bios_sets": {
            "neogeo": {
                "source_file": "src/mame/snk/neogeo.cpp",
                "source_line": 2500,
                "roms": [
                    {"name": "sp-s2.sp1", "size": 131072, "crc32": "9036d879",
                     "sha1": "4f5ed7105b7128794654ce82b51723e16e389543"},
                ],
            }
        },
    }

    def _profile(self, source_ref):
        return {
            "emulator": "MAME",
            "core_version": "0.287",
            "files": [
                {
                    "name": "neogeo.zip",
                    "category": "bios_zip",
                    "source_ref": source_ref,
                    "contents": [
                        {"name": "sp-s2.sp1", "size": 131072, "crc32": "9036d879",
                         "sha1": "4f5ed7105b7128794654ce82b51723e16e389543"},
                    ],
                }
            ],
        }

    def _diff(self, source_ref):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prof = _write_yaml(root / "p.yml", self._profile(source_ref))
            hashes = root / "h.json"
            hashes.write_text(json.dumps(self.HASHES), encoding="utf-8")
            return compute_diff(prof, str(hashes), mode="mame")

    def test_a_moved_line_counts_as_an_update(self):
        diff = self._diff("src/mame/snk/neogeo.cpp:2428")
        self.assertEqual(diff["updated"], ["neogeo"])
        self.assertEqual(diff["unchanged"], 0)

    def test_an_identical_ref_stays_unchanged(self):
        expected = _build_source_ref(self.HASHES["bios_sets"]["neogeo"])
        diff = self._diff(expected)
        self.assertEqual(diff["updated"], [])
        self.assertEqual(diff["unchanged"], 1)

class TestDerivativeVersion(unittest.TestCase):
    """Only MAME itself is relabelled with the upstream version."""

    HASHES = {
        "version": "0.289",
        "bios_sets": {
            "cdibios": {
                "source_file": "src/mame/philips/cdi.cpp",
                "source_line": 484,
                "roms": [
                    {"name": "cdi200.rom", "size": 262144, "crc32": "40c4e6b9",
                     "sha1": "d5e9e75bec84e93ea67d0e3f0b8b7e0b6f7d0f5f"},
                ],
            }
        },
    }

    def _run(self, add_new, version="Git"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prof = _write_yaml(root / "p.yml", {
                "emulator": "SAME CDi",
                "core_version": version,
                "files": [{"name": "cdibios.zip", "category": "bios_zip",
                           "source_ref": "old.cpp:1", "contents": []}],
            })
            hashes = root / "h.json"
            hashes.write_text(json.dumps(self.HASHES), encoding="utf-8")
            return merge_mame_profile(
                prof, str(hashes), write=False, add_new=add_new
            )

    def test_a_derivative_keeps_its_own_version(self):
        self.assertEqual(self._run(add_new=False)["core_version"], "Git")
        self.assertEqual(self._run(add_new=True)["core_version"], "Git")

    def test_a_profile_labelled_with_a_mame_release_follows_it(self):
        merged = self._run(add_new=False, version="0.287")
        self.assertEqual(merged["core_version"], "0.289")

    def test_the_ref_is_refreshed_either_way(self):
        for add_new in (False, True):
            entry = self._run(add_new)["files"][0]
            self.assertEqual(entry["source_ref"], "src/mame/philips/cdi.cpp:484")


class AnUnreadableCloneStopsTheScrape(unittest.TestCase):
    """_get_commit swallowed a failed rev-parse and returned "": cached for a
    day, the merge then advanced core_version and the refs while
    upstream_commit stayed on the previous release."""

    def test_no_empty_commit_reaches_the_cache(self):
        import subprocess
        from unittest import mock

        from scripts.scraper import mame_hash_scraper as scraper

        failing = subprocess.CalledProcessError(128, ["git", "rev-parse", "HEAD"])
        with mock.patch.object(scraper, "_run_git", side_effect=failing):
            with self.assertRaises(RuntimeError):
                scraper._get_commit()
        empty = subprocess.CompletedProcess(["git"], 0, stdout="\n", stderr="")
        with mock.patch.object(scraper, "_run_git", return_value=empty):
            with self.assertRaises(RuntimeError):
                scraper._get_commit()



class WritersPutTheValuesOnDisk(unittest.TestCase):
    """No test read back what the writers wrote. The FBNeo writer advanced
    core_version and never patched a changed crc32, and a broken MAME
    patcher would have done the same without a failing test. These
    fixtures use the layout the profiles use (entries indented two)."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=Path(__file__).resolve().parents[1] / "tmp"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, True))

    def test_fbneo_writes_a_changed_crc32(self):
        profile = self.dir / "fbneo.yml"
        profile.write_text(
            'emulator: FBNeo\ncore_version: "v1.0.0.02"\nfiles:\n'
            '  - name: "sp-s2.sp1"\n    archive: neogeo.zip\n    required: false\n'
            '    size: 131072  # 0x20000\n    crc32: "00000000"\n'
            '    note: "MVS Asia/Europe ver. 5"\n    source_ref: "src/burn/drv/neogeo/d_neogeo.cpp:1625"\n',
            encoding="utf-8",
        )
        hashes = _write_json(self.dir / "h.json", {
            "version": "v1.0.0.03",
            "bios_sets": {"neogeo": {"source_file": "src/burn/drv/neogeo/d_neogeo.cpp",
                                     "source_line": 1625,
                                     "roms": [{"name": "sp-s2.sp1", "size": 131072,
                                               "crc32": "9036d879"}]}},
        })
        merge_fbneo_profile(str(profile), hashes, write=True, add_new=False)
        written = yaml.safe_load(profile.read_text(encoding="utf-8"))
        entry = written["files"][0]
        self.assertEqual(written["core_version"], "v1.0.0.02")
        self.assertEqual(entry["crc32"], "9036d879")
        self.assertEqual(entry["note"], "MVS Asia/Europe ver. 5")
        self.assertEqual(entry["source_ref"], "src/burn/drv/neogeo/d_neogeo.cpp:1625")
        self.assertIn("size: 131072  # 0x20000", profile.read_text(encoding="utf-8"))

    def test_mame_writes_member_values(self):
        profile = self.dir / "mame.yml"
        profile.write_text(
            'emulator: MAME\ncore_version: "0.285"\nfiles:\n'
            '  - name: neogeo.zip\n    required: true\n    category: bios_zip\n'
            '    system: snk-neogeo-mvs\n    source_ref: "src/mame/neogeo/neogeo.cpp:2400"\n'
            '    contents:\n      - name: sp-s2.sp1\n        size: 131072\n'
            '        crc32: oldcrc32\n        description: Europe MVS (Ver. 2)\n',
            encoding="utf-8",
        )
        hashes = _write_json(self.dir / "h.json", _make_mame_hashes())
        merge_mame_profile(str(profile), hashes, write=True)
        written = yaml.safe_load(profile.read_text(encoding="utf-8"))
        member = written["files"][0]["contents"][0]
        self.assertEqual(member["crc32"], "9036d879")


class OneCloneDirectoryPerRun(unittest.TestCase):
    """Two runs shared tmp/mame: the second removed and recloned it at
    another release while the first parsed it, and the first wrote 0.289
    sets into a 0.278 profile."""

    def test_the_clone_directory_names_the_process(self):
        import os

        from scripts.scraper import fbneo_hash_scraper, mame_hash_scraper

        for clone in (mame_hash_scraper._CLONE_DIR, fbneo_hash_scraper.CLONE_DIR):
            with self.subTest(clone=clone.name):
                self.assertTrue(clone.name.endswith(f"-{os.getpid()}"))


class ABrokenProfileStopsTheRefresh(unittest.TestCase):
    """A profile with a YAML error left the list in silence: the refresh
    printed 'no matching emulator profiles found' and exited 0."""

    def test_both_scrapers_name_it(self):
        from unittest import mock

        from scripts.scraper import fbneo_hash_scraper, mame_hash_scraper

        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "fbneo.yml").write_text("files: [\n  - name: a\n")
            for module, attr, finder in (
                (fbneo_hash_scraper, "EMULATORS_DIR", "_find_fbneo_profiles"),
                (mame_hash_scraper, "_EMULATORS_DIR", "_find_mame_profiles"),
            ):
                with self.subTest(scraper=module.__name__), \
                        mock.patch.object(module, attr, Path(directory)), \
                        self.assertRaises(RuntimeError) as caught:
                    getattr(module, finder)()
                self.assertIn("fbneo.yml", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
