#!/usr/bin/env python3
"""Deduplication, which permanently deletes files from the collection.

dedup.py is the only script here that removes BIOS files, and it had no
tests: the sole guard was remembering to pass --dry-run. These pin the rules
it must never get wrong, above all the directories where two identical files
are both load-bearing.
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import dedup  # noqa: E402


class _Bios(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.bios = Path(self._tmp.name) / "bios"
        self.bios.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, relative: str, data: bytes = b"IDENTICAL PAYLOAD") -> Path:
        path = self.bios / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def run_dedup(self, dry_run: bool = False) -> dict:
        with contextlib.redirect_stdout(io.StringIO()):
            return dedup.deduplicate(str(self.bios), dry_run=dry_run)

    def existing(self) -> set[str]:
        return {
            str(p.relative_to(self.bios))
            for p in self.bios.rglob("*")
            if p.is_file()
        }


class ProtectedDirectories(_Bios):
    """RPG Maker and ScummVM reference files by exact name and path.

    Collapsing two identical copies there breaks the reference that the
    removed path served, which is why those directories are excluded from
    deduplication.
    """

    def test_rpg_maker_copies_both_survive(self):
        self.write("RPG Maker/GameA/System/font.png")
        self.write("RPG Maker/GameB/System/font.png")
        self.run_dedup()
        self.assertEqual(len(self.existing()), 2, "a NODEDUP copy was removed")

    def test_scummvm_copies_both_survive(self):
        self.write("ScummVM/monkey/monkey.tbl")
        self.write("ScummVM/monkey2/monkey.tbl")
        self.run_dedup()
        self.assertEqual(len(self.existing()), 2)

    def test_a_protected_copy_does_not_drag_an_outside_copy_away(self):
        self.write("RPG Maker/GameA/System/shared.dat")
        self.write("Sony/PlayStation/shared.dat")
        self.run_dedup()
        self.assertIn("RPG Maker/GameA/System/shared.dat", self.existing())


class TrueDuplicates(_Bios):
    def test_the_same_name_in_two_directories_collapses_to_one(self):
        self.write("Arcade/MAME/naomi.zip")
        self.write("Sega/Dreamcast/naomi.zip")
        results = self.run_dedup()
        self.assertEqual(len(self.existing()), 1)
        removed = [r for entry in results.values() for r in entry["removed"]]
        self.assertEqual(len(removed), 1)

    def test_the_shorter_path_is_kept(self):
        self.write("Sony/PS/bios.bin")
        self.write("Sony/PS/deeply/nested/bios.bin")
        self.run_dedup()
        self.assertEqual(self.existing(), {"Sony/PS/bios.bin"})

    def test_a_variant_loses_to_the_primary(self):
        self.write("Sony/PS/scph.bin")
        self.write("Sony/PS/.variants/scph.bin")
        self.run_dedup()
        self.assertEqual(self.existing(), {"Sony/PS/scph.bin"})

    def test_different_content_under_one_name_is_never_touched(self):
        self.write("Sony/PS/a.bin", b"CONTENT ONE")
        self.write("Sega/Saturn/a.bin", b"CONTENT TWO")
        self.run_dedup()
        self.assertEqual(len(self.existing()), 2)

    def test_a_lone_file_is_left_alone(self):
        self.write("Sony/PS/only.bin")
        self.assertEqual(self.run_dedup(), {})
        self.assertEqual(len(self.existing()), 1)


class DifferentNamesSameContent(_Bios):
    def test_outside_mame_every_name_is_kept(self):
        """Two emulators may each look for their own spelling."""
        self.write("Nintendo/N64/64DD_IPL_US.n64")
        self.write("Nintendo/N64/IPL_USA.n64")
        self.run_dedup()
        self.assertEqual(len(self.existing()), 2)

    def test_mame_zip_clones_collapse_and_are_recorded(self):
        self.write("Arcade/MAME/bbc_m87.zip")
        self.write("Arcade/MAME/bbc_24bbc.zip")
        self.run_dedup()
        survivors = self.existing()
        self.assertEqual(len(survivors), 1, f"expected one canonical, got {survivors}")

    def test_identically_named_mame_zips_keep_the_shortest_name(self):
        self.write("Arcade/MAME/aaa_long_name.zip")
        self.write("Arcade/MAME/bbb.zip")
        self.run_dedup()
        self.assertEqual(self.existing(), {"Arcade/MAME/bbb.zip"})

    def test_a_non_zip_in_mame_is_not_treated_as_a_clone(self):
        self.write("Arcade/MAME/rom_one.bin")
        self.write("Arcade/MAME/rom_two.bin")
        self.run_dedup()
        self.assertEqual(len(self.existing()), 2)


class DryRun(_Bios):
    def test_dry_run_deletes_nothing(self):
        self.write("Arcade/MAME/naomi.zip")
        self.write("Sega/Dreamcast/naomi.zip")
        before = self.existing()
        results = self.run_dedup(dry_run=True)
        self.assertEqual(self.existing(), before, "dry run removed a file")
        self.assertTrue(
            any(entry["removed"] for entry in results.values()),
            "dry run should still report what it would remove",
        )

    def test_dry_run_reports_the_same_plan_the_real_run_executes(self):
        self.write("Arcade/MAME/naomi.zip")
        self.write("Sega/Dreamcast/naomi.zip")
        planned = {
            r for entry in self.run_dedup(dry_run=True).values()
            for r in entry["removed"]
        }
        done = {
            r for entry in self.run_dedup(dry_run=False).values()
            for r in entry["removed"]
        }
        self.assertEqual(planned, done)


class EmptyVariantCleanup(_Bios):
    def test_an_emptied_variants_directory_is_removed(self):
        self.write("Sony/PS/scph.bin")
        self.write("Sony/PS/.variants/scph.bin")
        self.run_dedup()
        self.assertFalse((self.bios / "Sony" / "PS" / ".variants").exists())

    def test_a_variants_directory_still_holding_a_file_stays(self):
        self.write("Sony/PS/scph.bin")
        self.write("Sony/PS/.variants/scph.bin")
        self.write("Sony/PS/.variants/other.bin", b"DIFFERENT")
        self.run_dedup()
        self.assertTrue((self.bios / "Sony" / "PS" / ".variants").is_dir())


class CloneMapSurvivesASecondRun(_Bios):
    """The clone map must not be destroyed by running dedup again.

    A clone group is only discovered while both copies are on disk, and the
    run then deletes the clone. Rewriting the file with just what this run saw
    therefore drops every mapping an earlier run recorded, and the canonical
    zip stops answering to the names it was standing in for. One real run took
    the map from 69 entries to 1.
    """

    def setUp(self):
        super().setUp()
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._cwd)
        super().tearDown()

    def _map(self) -> dict:
        import json

        path = Path(self._tmp.name) / "_mame_clones.json"
        return json.loads(path.read_text()) if path.exists() else {}

    def test_a_recorded_mapping_survives_a_later_run(self):
        self.write("Arcade/MAME/bbc_m87.zip")
        self.write("Arcade/MAME/bbc_24bbc.zip")
        self.run_dedup()
        first = self._map()
        self.assertTrue(first, "first run recorded no clone map")

        # Second run: the clones are gone, so nothing new is found.
        self.write("Arcade/MAME/other_a.zip", b"OTHER CONTENT")
        self.write("Arcade/MAME/other_b.zip", b"OTHER CONTENT")
        self.run_dedup()
        second = self._map()
        for canonical, entry in first.items():
            self.assertIn(canonical, second, f"{canonical} was dropped")
            self.assertEqual(entry["clones"], second[canonical]["clones"])

    def test_a_new_group_is_added_beside_the_existing_ones(self):
        self.write("Arcade/MAME/bbc_m87.zip")
        self.write("Arcade/MAME/bbc_24bbc.zip")
        self.run_dedup()
        before = set(self._map())
        self.write("Arcade/MAME/new_a.zip", b"NEW CONTENT")
        self.write("Arcade/MAME/new_b.zip", b"NEW CONTENT")
        self.run_dedup()
        self.assertTrue(set(self._map()) > before, "the new group was not added")

    def test_a_dry_run_never_writes_the_map(self):
        self.write("Arcade/MAME/bbc_m87.zip")
        self.write("Arcade/MAME/bbc_24bbc.zip")
        self.run_dedup(dry_run=True)
        self.assertEqual(self._map(), {})


class PathPriority(unittest.TestCase):
    def test_shorter_paths_sort_first(self):
        short = dedup.path_priority("bios/Sony/PS/a.bin")
        deep = dedup.path_priority("bios/Sony/PS/x/y/z/a.bin")
        self.assertLess(short, deep)

    def test_a_variant_sorts_after_a_primary(self):
        primary = dedup.path_priority("bios/Sony/PS/a.bin")
        variant = dedup.path_priority("bios/Sony/PS/.variants/a.bin")
        self.assertLess(primary, variant)

    def test_protected_directories_are_recognised(self):
        self.assertTrue(dedup._in_nodedup_dir("bios/RPG Maker/x/font.png"))
        self.assertTrue(dedup._in_nodedup_dir("bios/ScummVM/x/monkey.tbl"))
        self.assertFalse(dedup._in_nodedup_dir("bios/Sony/PlayStation/scph.bin"))


if __name__ == "__main__":
    unittest.main()
