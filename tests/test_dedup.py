#!/usr/bin/env python3
"""Deduplication, which permanently deletes files from the collection.

dedup.py is the only script here that removes BIOS files, and it had no
tests: the sole guard was remembering to pass --dry-run. These pin the rules
it must never get wrong, above all the directories where two identical files
are both load-bearing.
"""

from __future__ import annotations

import tests

import os
import tempfile
import unittest
from pathlib import Path

from collection import clonemap, dedup, deduptext, duplicates
from collection.scan import primary_rank, scan_bios_dir
from model import nodedup


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

    def run_dedup(self, dry_run: bool = False) -> dedup.DedupResult:
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
        removed = [r for entry in results.groups.values() for r in entry.removed]
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

    def test_a_variant_under_another_name_loses_to_the_file_holding_its_bytes(self):
        # .variants/scph1001.bin.649895ef held the bytes of scph1001_v20.bin:
        # the content was answered twice and the index kept one at random.
        self.write("Sony/PS/scph1001_v20.bin")
        self.write("Sony/PS/.variants/scph1001.bin.649895ef")
        self.run_dedup()
        self.assertEqual(self.existing(), {"Sony/PS/scph1001_v20.bin"})

    def test_two_variants_of_one_content_keep_one(self):
        # msx.rom.a317e6b4 and MSX.ROM.e998f0c4 differ only by casing and
        # suffix, and nothing outside .variants/ holds the bytes in this tree.
        self.write("Microsoft/MSX/.variants/msx.rom.a317e6b4")
        self.write("Microsoft/MSX/.variants/MSX.ROM.e998f0c4")
        self.run_dedup()
        self.assertEqual(len(self.existing()), 1)

    def test_a_variant_of_other_bytes_stays(self):
        self.write("Sony/PS/scph1001.bin", b"PRIMARY")
        self.write("Sony/PS/.variants/scph1001.bin.649895ef", b"ALTERNATE")
        self.run_dedup()
        self.assertEqual(len(self.existing()), 2)

    def test_different_content_under_one_name_is_never_touched(self):
        self.write("Sony/PS/a.bin", b"CONTENT ONE")
        self.write("Sega/Saturn/a.bin", b"CONTENT TWO")
        self.run_dedup()
        self.assertEqual(len(self.existing()), 2)

    def report(self) -> str:
        result = dedup.deduplicate(str(self.bios), dry_run=True)
        return "\n".join(deduptext.report_lines(result))

    def test_a_removed_variant_is_not_reported_as_a_mame_clone(self):
        # The run printed "MAME clones: ['x.bin.1234']" for a variant copy,
        # a name the clone map never records.
        self.write("Sony/PS/x.bin")
        self.write("Sony/PS/.variants/x.bin.1234")
        report = self.report()
        self.assertNotIn("MAME clones", report)
        self.assertIn("Would remove 1 copies", report)

    def test_another_name_kept_beside_the_canonical_is_named_as_kept(self):
        self.write("Nintendo/N64DD/64DD_IPL_US.n64")
        self.write("Nintendo/N64DD/x/64DD_IPL_US.n64")
        self.write("Nintendo/N64DD/IPL_USA.n64")
        report = self.report()
        self.assertNotIn("MAME clones", report)
        self.assertIn("Kept under other names: ['IPL_USA.n64']", report)

    def test_a_device_clone_is_still_reported_as_one(self):
        self.write("Arcade/MAME/a.zip")
        self.write("Arcade/MAME/abc.zip")
        report = self.report()
        self.assertIn("MAME clones: ['abc.zip']", report)
        self.assertNotIn("Kept under other names", report)

    def test_a_lone_file_is_left_alone(self):
        self.write("Sony/PS/only.bin")
        self.assertEqual(self.run_dedup().groups, {})
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
            any(entry.removed for entry in results.groups.values()),
            "dry run should still report what it would remove",
        )

    def test_dry_run_reports_the_same_plan_the_real_run_executes(self):
        self.write("Arcade/MAME/naomi.zip")
        self.write("Sega/Dreamcast/naomi.zip")
        planned = {
            r for entry in self.run_dedup(dry_run=True).groups.values()
            for r in entry.removed
        }
        done = {
            r for entry in self.run_dedup(dry_run=False).groups.values()
            for r in entry.removed
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

    def test_the_map_is_written_beside_the_scanned_tree_not_the_cwd(self):
        """A test or a run from another directory must not touch the repo's map.

        The map was written to the working directory. The test suite runs
        from the repo root, so a fixture scan of a temporary tree rewrote the
        committed _mame_clones.json with two fixture entries, and a later
        rewrite left 2 of its 71 parents.
        """
        elsewhere = Path(self._tmp.name) / "elsewhere"
        elsewhere.mkdir()
        os.chdir(elsewhere)
        self.write("Arcade/MAME/bbc_m87.zip")
        self.write("Arcade/MAME/bbc_24bbc.zip")
        self.run_dedup()
        self.assertFalse((elsewhere / "_mame_clones.json").exists())
        self.assertIn("bbc_m87.zip", self._map())

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


class PrimaryRank(unittest.TestCase):
    BIOS = Path("bios")

    def rank(self, relative: str) -> tuple:
        return primary_rank(self.BIOS / relative, self.BIOS)

    def test_equal_copies_follow_the_walk_order(self):
        self.assertLess(self.rank("Sony/PS/a.bin"), self.rank("Sony/PS/x/y/z/a.bin"))

    def test_a_variant_sorts_after_a_primary(self):
        self.assertLess(self.rank("Sony/PS/zz/a.bin"), self.rank("Sony/PS/.variants/a.bin"))

    def test_an_emulator_tree_sorts_after_a_machine_folder(self):
        self.assertLess(
            self.rank("Sega/Master System/sms.rom"), self.rank("Other/zesarux/sms.rom")
        )

    def test_protected_directories_are_recognised(self):
        self.assertTrue(nodedup.in_nodedup_dir("bios/RPG Maker/x/font.png"))
        self.assertTrue(nodedup.in_nodedup_dir("bios/ScummVM/x/monkey.tbl"))
        self.assertFalse(nodedup.in_nodedup_dir("bios/Sony/PlayStation/scph.bin"))


class DedupKeepsTheIndexedCopy(_Bios):
    """The dedup removed bios/Sega/Master System/sms.rom, the copy the index
    names, and kept ZEsarUX's, a tree the resolver sets aside as another
    emulator's: two rules chose the primary of one content."""

    def assert_kept_is_primary(self, *relatives: str) -> None:
        for relative in relatives:
            self.write(relative)
        files, _aliases, _cache = scan_bios_dir(self.bios, {}, True)
        (indexed,) = (entry["path"] for entry in files.values())
        self.run_dedup()
        (kept,) = self.existing()
        self.assertEqual(f"bios/{kept}", indexed)

    def test_a_machine_folder_wins_over_an_emulator_tree(self):
        self.assert_kept_is_primary("Other/zesarux/sms.rom", "Sega/Master System/sms.rom")

    def test_a_primary_wins_over_a_variant(self):
        self.assert_kept_is_primary("Sony/PS/zz/scph.bin", "Sony/PS/.variants/scph.bin")

    def test_equal_copies_keep_the_first_walked(self):
        self.assert_kept_is_primary("Arcade/MAME/naomi.zip", "Sega/Dreamcast/naomi.zip")


class OnlyCollectionFilesAreCandidates(_Bios):
    """The dedup walked bios/.cache/ and hidden files, which the database
    scan leaves out, and the shared rank could keep that copy: a real run
    deleted the only copy the index, manifests and packs knew."""

    def test_a_copy_under_a_skipped_directory_is_never_kept(self):
        self.write("Sony/PlayStation/scph1001.bin")
        self.write(".cache/scph1001.bin")
        result = self.run_dedup(dry_run=True)
        self.assertEqual(result.groups, {})

    def test_the_dedup_walks_the_files_the_scan_indexes(self):
        for relative in ("Sony/PS/a.bin", ".cache/a.bin", "Sony/.hidden.bin",
                         "Sony/PS/.variants/a.bin.1234"):
            self.write(relative)
        files, aliases, _cache = scan_bios_dir(self.bios, {}, True)
        indexed = {entry["path"] for entry in files.values()} | {
            alias["path"] for group in aliases.values() for alias in group
        }
        walked = {
            os.path.relpath(path, self.bios.parent)
            for paths in duplicates.scan_duplicates(str(self.bios)).values()
            for path in paths
        }
        self.assertEqual(walked, indexed)


@unittest.skipIf(os.name == "nt" or os.geteuid() == 0, "needs POSIX permissions")
class AFailedRemovalIsReported(_Bios):
    """A copy that os.remove refused was printed as a warning, counted as
    removed by its group line, and the command exited 0 and asked for a
    database rebuild."""

    def setUp(self):
        super().setUp()
        self.write("A/f.bin")
        self.locked = self.write("B/X/f.bin").parent
        self.locked.chmod(0o555)

    def tearDown(self):
        self.locked.chmod(0o755)
        super().tearDown()

    def test_the_failure_is_in_the_result_not_in_removed(self):
        result = self.run_dedup()
        (group,) = result.groups.values()
        self.assertEqual(group.removed, [])
        self.assertEqual([f.path for f in group.failed], [str(self.locked / "f.bin")])
        self.assertEqual(result.total_removed, 0)

    def test_the_report_counts_what_was_removed(self):
        report = "\n".join(deduptext.report_lines(self.run_dedup()))
        self.assertIn("WARNING: cannot remove", report)
        self.assertIn("Removed 0 copies", report)
        self.assertNotIn("Removed 1 copies", report)

    def test_the_command_exits_non_zero_without_the_rebuild_hint(self):
        import contextlib
        import io
        import sys
        from unittest import mock

        import dedup as command

        out, err = io.StringIO(), io.StringIO()
        argv = ["dedup.py", "--bios-dir", str(self.bios)]
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = command.main()
        self.assertEqual(code, 1)
        self.assertIn("1 copies could not be removed", err.getvalue())
        self.assertNotIn("generate_db.py", out.getvalue())


class TheNoDedupListIsPinned(unittest.TestCase):
    """Every directory the dedup must leave alone, with the reason written
    beside it in model/nodedup.py. Only RPG Maker and ScummVM were tested, so a merge
    that dropped c64-emu would have the name step serve the C128 keymap to
    three machines again, with the suite green."""

    def test_every_tree_read_by_path_stays_undeduplicated(self):
        from scripts.model.nodedup import NODEDUP_DIRS

        expected = {
            "RPG Maker", "ScummVM", "tzdata", "c64-emu", "PinMAME", "BBK",
            "C-Dogs SDL", "Ikemen GO", "Theme Hospital", "TheXTech", "Softdisk",
        }
        self.assertEqual(expected - set(NODEDUP_DIRS), set())


class OnlyFilesSharingASizeAreHashed(_Bios):
    """Equal files have equal sizes. Hashing all 9 442 files with five
    digests took 33 s for 278 groups that a sha1 of the 4 543 files sharing
    a size finds the same."""

    def test_a_file_alone_at_its_size_is_not_read(self):
        from unittest import mock

        self.write("A/one.bin")
        self.write("B/one.bin")
        self.write("C/other.bin", b"a payload of its own length")
        self.write("D/same_size.bin", b"IDENTICAL PAYLOAX")
        calls: list[tuple[str, frozenset | None]] = []
        real = duplicates.compute_hashes

        def spy(path, algorithms=None, cache=True):
            calls.append((os.path.relpath(path, self.bios), algorithms))
            return real(path, algorithms, cache)

        with mock.patch.object(duplicates, "compute_hashes", spy):
            groups = duplicates.scan_duplicates(str(self.bios))
        self.assertEqual(
            sorted(path for path, _algos in calls),
            sorted(os.path.join(*p.split("/")) for p in ("A/one.bin", "B/one.bin", "D/same_size.bin")),
        )
        self.assertTrue(all(algos == frozenset({"sha1"}) for _path, algos in calls))
        multi = [paths for paths in groups.values() if len(paths) > 1]
        self.assertEqual(len(multi), 1)
        self.assertEqual(sorted(os.path.relpath(p, self.bios) for p in multi[0]),
                         sorted(os.path.join(*p.split("/")) for p in ("A/one.bin", "B/one.bin")))



class CloneChainsCollapse(unittest.TestCase):
    """A later run removed sys68k_cpu21.zip as a copy of sys68k_cpu20.zip
    while the map still named it canonical for five clones: those clones
    pointed at a file that no longer existed."""

    def test_clones_follow_to_the_canonical_that_exists(self):
        chain = {
            "cpu20.zip": {"clones": ["cpu21.zip"], "sha1": "a", "total_copies": 1},
            "cpu21.zip": {"clones": ["cpu21a.zip", "cpu21b.zip"], "sha1": "a", "total_copies": 2},
        }
        self.assertEqual(clonemap.collapse_clone_chains(chain), {
            "cpu20.zip": {"clones": ["cpu21.zip", "cpu21a.zip", "cpu21b.zip"],
                          "sha1": "a", "total_copies": 3},
        })

    def test_a_loop_is_refused(self):
        loop = {"a.zip": {"clones": ["b.zip"]}, "b.zip": {"clones": ["a.zip"]}}
        with self.assertRaises(ValueError):
            clonemap.collapse_clone_chains(loop)


if __name__ == "__main__":
    unittest.main()
