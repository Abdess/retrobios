"""Tests for the hash merge module."""

from __future__ import annotations

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

    def test_merge_updates_core_version(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            profile_path = _write_yaml(p / "fbneo.yml", _make_fbneo_profile())
            hashes_path = _write_json(p / "hashes.json", _make_fbneo_hashes())

            result = merge_fbneo_profile(profile_path, hashes_path)

            self.assertEqual(result["core_version"], "v1.0.0.03")


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


if __name__ == "__main__":
    unittest.main()

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

