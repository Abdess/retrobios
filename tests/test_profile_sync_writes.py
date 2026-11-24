"""Tests for the profile_sync writes: line edits, recale, dry run, bump (no network)."""

from __future__ import annotations

import tests

import argparse
import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

import profile_sync
from profiling import anchoring
from profiling import bump
from profiling import citations as profiling_citations
from profiling import realign
from profiling import rebase
from profiling import resolver
from profiling import run as profiling_run
from profiling.reports import (
    CitedSource,
    EntryReport,
    ProfileReport,
    SkipKind,
)
from profiling.anchoring import PartResult
from profiling.yamledit import (
    YamlWriteError,
    apply_edit,
    backfill_commit,
    find_field_line,
    insert_after_line,
    replace_field_line,
)
from profiling.bump import bump_commit
from profiling.rebase import Recale, rebase_refs
from model.sourceref import RefPart
from core import upstream
from core import forgehttp
from tests.profilesyncsupport import PROSE_SAMPLE, SAMPLE, _SAMPLE_REPO
from tests.profilesyncsupport import setUpModule as setUpModule
from tests.profilesyncsupport import tearDownModule as tearDownModule


_UPSTREAM_REPO = upstream.parse_repo("https://gitlab.com/u/n")


class TestLineEdits(unittest.TestCase):
    def test_insert_after_profiled_date(self):
        out = insert_after_line(SAMPLE, "profiled_date", 'source_commit: "abc"')
        lines = out.splitlines()
        index = lines.index('profiled_date: "2026-03-29"')
        self.assertEqual(lines[index + 1], 'source_commit: "abc"')

    def test_insert_ignores_indented_occurrence_in_prose(self):
        out = insert_after_line(SAMPLE, "profiled_date", 'source_commit: "abc"')
        self.assertEqual(out.count("source_commit"), 1)

    def test_replace_targets_the_matching_value(self):
        out, _ = replace_field_line(SAMPLE, "source_ref", "b.c:5", "b.c:9")
        self.assertIn('source_ref: "b.c:9"', out)
        self.assertIn('source_ref: "a.c:10-12"', out)

    def test_replace_refuses_an_absent_value(self):
        with self.assertRaises(YamlWriteError):
            replace_field_line(SAMPLE, "source_ref", "not-there", "x")

    def test_cursor_skips_earlier_lines(self):
        index = find_field_line(SAMPLE, "source_ref", "a.c:10-12")
        with self.assertRaises(YamlWriteError):
            find_field_line(SAMPLE, "source_ref", "a.c:10-12", index + 1)

    def test_escaped_quotes_are_matched_as_parsed(self):
        # etlegacy writes (FS_FOpenFileRead \\"pak0.pk3\\") inside a
        # double-quoted source_ref: the line kept its backslashes and never
        # equalled the parsed value, so the recale was refused.
        value = 'files.c:5076 (FS_FOpenFileRead "pak0.pk3")'
        text = SAMPLE.replace('"b.c:5"', '"files.c:5076 (FS_FOpenFileRead \\"pak0.pk3\\")"')
        self.assertEqual(yaml.safe_load(text)["files"][1]["source_ref"], value)
        moved = value.replace("5076", "5080")
        out, _ = replace_field_line(text, "source_ref", value, moved)
        self.assertEqual(yaml.safe_load(out)["files"][1]["source_ref"], moved)

    def test_source_ref_outside_files_does_not_shift_the_match(self):
        text = SAMPLE.replace(
            "files:",
            "data_directories:\n"
            '  - key: "assets"\n'
            '    source_ref: "elsewhere.c:1"\n'
            "\nfiles:",
            1,
        )
        out, _ = replace_field_line(text, "source_ref", "b.c:5", "b.c:9")
        self.assertIn('source_ref: "b.c:9"', out)
        self.assertIn('source_ref: "elsewhere.c:1"', out)


class TestApplyEdit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.yml"
        self.path.write_text(SAMPLE, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_backfill_writes_commit_and_preserves_comments(self):
        self.assertTrue(backfill_commit(self.path, "abc123"))
        text = self.path.read_text(encoding="utf-8")
        self.assertIn('source_commit: "abc123"', text)
        self.assertIn("A note mentioning", text)
        self.assertEqual(yaml.safe_load(text)["source_commit"], "abc123")

    def test_backfill_skips_when_already_present(self):
        backfill_commit(self.path, "abc123")
        self.assertFalse(backfill_commit(self.path, "def456"))

    def test_guard_restores_file_on_structural_drift(self):
        expected = yaml.safe_load(SAMPLE)
        broken = SAMPLE.replace("emulator: Test", "emulator: Other")
        with self.assertRaises(YamlWriteError):
            apply_edit(self.path, broken, expected)
        self.assertEqual(self.path.read_text(encoding="utf-8"), SAMPLE)

    def test_guard_accepts_single_field_change(self):
        expected = yaml.safe_load(SAMPLE)
        expected["source_commit"] = "abc"
        new_text = insert_after_line(SAMPLE, "profiled_date", 'source_commit: "abc"')
        apply_edit(self.path, new_text, expected)
        self.assertEqual(
            yaml.safe_load(self.path.read_text())["source_commit"], "abc"
        )


class TestRebaseRefs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.yml"
        self.path.write_text(SAMPLE, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def _report(self, entries):
        return ProfileReport(
            name="p", repo="o/n", pin="pin", head="head", entries=entries, counts={}
        )

    def test_shifted_range_is_rewritten(self):
        part = PartResult(RefPart("a.c", 10, 12), "SHIFTED", None, 20, 22, [])
        applied = rebase_refs(
            self.path,
            self._report([EntryReport("a.bin", "a.c:10-12", "SHIFTED", [part])]),
        ).applied
        self.assertEqual(applied, ["a.c:10-12 -> a.c:20-22"])
        self.assertIn('source_ref: "a.c:20-22"', self.path.read_text())

    def test_renamed_path_is_rewritten(self):
        part = PartResult(RefPart("a.c", 10, 12), "RENAMED", "src/a.c", 10, 12, [])
        rebase_refs(
            self.path,
            self._report([EntryReport("a.bin", "a.c:10-12", "RENAMED", [part])]),
        )
        self.assertIn('source_ref: "src/a.c:10-12"', self.path.read_text())

    def test_changed_is_never_touched(self):
        part = PartResult(RefPart("b.c", 5, 5), "CHANGED", None, 9, 9, [])
        self.assertEqual(
            rebase_refs(
                self.path,
                self._report([EntryReport("b.bin", "b.c:5", "CHANGED", [part])]),
            ).applied,
            [],
        )
        self.assertIn('source_ref: "b.c:5"', self.path.read_text())

    def test_ambiguous_is_never_touched(self):
        part = PartResult(RefPart("b.c", 5, 5), "AMBIGUOUS", None, None, None, [3, 9])
        self.assertEqual(
            rebase_refs(
                self.path,
                self._report([EntryReport("b.bin", "b.c:5", "AMBIGUOUS", [part])]),
            ).applied,
            [],
        )

    def test_a_pin_on_a_superseded_tag_is_never_rebased(self):
        part = PartResult(
            RefPart("a.c", 10, 12, "a.c:10-12"), "RENAMED", "src/a.c", 20, 22, []
        )
        report = self._report(
            [EntryReport("a.bin", "a.c:10-12", "RENAMED", [part])]
        )
        report.counts = {"RENAMED": 1}
        report.pinned_tag = "v1.6.0"
        self.assertEqual(rebase_refs(self.path, report), Recale())
        self.assertEqual(rebase_refs(self.path, report, accept_changed=True), Recale())
        self.assertIn('source_ref: "a.c:10-12"', self.path.read_text())

    def test_nothing_is_rebased_while_a_ref_needs_review(self):
        shifted = PartResult(RefPart("a.c", 10, 12), "SHIFTED", None, 20, 22, [])
        report = self._report(
            [EntryReport("a.bin", "a.c:10-12", "SHIFTED", [shifted])]
        )
        report.counts = {"SHIFTED": 1, "CHANGED": 1}
        self.assertEqual(rebase_refs(self.path, report), Recale())
        self.assertIn('source_ref: "a.c:10-12"', self.path.read_text())

    def test_accept_changed_recales_a_reviewed_diff(self):
        part = PartResult(RefPart("a.c", 10, 12), "CHANGED", None, 30, 32, [])
        report = self._report(
            [EntryReport("a.bin", "a.c:10-12", "CHANGED", [part])]
        )
        report.counts = {"CHANGED": 1}
        self.assertEqual(rebase_refs(self.path, report), Recale())
        applied = rebase_refs(self.path, report, accept_changed=True).applied
        self.assertEqual(applied, ["a.c:10-12 -> a.c:30-32"])

    def test_accept_changed_does_not_cover_gone(self):
        part = PartResult(RefPart("a.c", 10, 12), "CHANGED", None, 30, 32, [])
        report = self._report(
            [EntryReport("a.bin", "a.c:10-12", "CHANGED", [part])]
        )
        report.counts = {"CHANGED": 1, "GONE": 1}
        self.assertEqual(rebase_refs(self.path, report, accept_changed=True), Recale())

    def test_accept_changed_is_refused_on_every_profile(self):
        args = profile_sync.build_parser().parse_args(["--all", "--accept-changed"])
        self.assertTrue(args.accept_changed)
        self.assertIsNone(args.emulator)

    def test_annotated_ref_keeps_its_prose_when_rewritten(self):
        self.path.write_text(
            SAMPLE.replace('"a.c:10-12"', '"a.c:10-12 (loads the kernel)"'),
            encoding="utf-8",
        )
        part = PartResult(
            RefPart("a.c", 10, 12, "a.c:10-12 (loads the kernel)"),
            "SHIFTED", None, 20, 22, [],
        )
        applied = rebase_refs(
            self.path,
            self._report(
                [
                    EntryReport(
                        "a.bin", "a.c:10-12 (loads the kernel)", "SHIFTED", [part]
                    )
                ]
            ),
        ).applied
        self.assertEqual(len(applied), 1)
        text = self.path.read_text()
        self.assertIn('source_ref: "a.c:20-22 (loads the kernel)"', text)

    def test_a_chunk_that_is_only_prose_blocks_the_rewrite(self):
        self.assertFalse(rebase._is_rewritable("a.c:1, (just a note)"))
        self.assertTrue(rebase._is_rewritable("a.c:1 (note), b.c:2"))

    def test_mode_keyed_ref_is_never_rewritten(self):
        part = PartResult(RefPart("a.c", 10, 12), "SHIFTED", None, 20, 22, [])
        applied = rebase_refs(
            self.path,
            self._report(
                [EntryReport("a.bin [libretro]", "a.c:10-12", "SHIFTED", [part])]
            ),
        ).applied
        self.assertEqual(applied, [])

    def test_shifted_part_beside_changed_part_is_rebased(self):
        shifted = PartResult(RefPart("a.c", 10, 12), "SHIFTED", None, 20, 22, [])
        changed = PartResult(RefPart("b.c", 5, 5), "CHANGED", None, 9, 9, [])
        rebase_refs(
            self.path,
            self._report(
                [
                    EntryReport("a.bin", "a.c:10-12", "SHIFTED", [shifted]),
                    EntryReport("b.bin", "b.c:5", "CHANGED", [changed]),
                ]
            ),
        )
        text = self.path.read_text()
        self.assertIn('source_ref: "a.c:20-22"', text)
        self.assertIn('source_ref: "b.c:5"', text)


class TestWriteDryRun(unittest.TestCase):
    """--dry-run has to plan a write, not stay silent about it.

    --backfill-commits and --realign-prose have always reported what they
    would write. --rebase-refs and --bump-commit accepted the flag and said
    nothing, so the only way to read the plan was to let it happen.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.path = self.dir / "p.yml"
        self.path.write_text(SAMPLE, encoding="utf-8")
        # Profiles live in a repository: git answers "no history" for an
        # untracked file, where outside one it answers nothing at all.
        subprocess.run(["git", "init", "-q"], cwd=self.dir, check=True)
        # The cited files gained nothing since the pin in these fixtures.
        from unittest import mock

        def nothing_gained(profile, report, *_):
            report.new_files, report.new_hashes = [], []

        self._detection = mock.patch.object(
            profiling_run, "_attach_detection", side_effect=nothing_gained
        )
        self._detection.start()

    def tearDown(self):
        self._detection.stop()
        self.tmp.cleanup()

    def test_a_file_gained_since_the_pin_holds_the_bump(self):
        # mame2003_plus's zn.c gained two G-NET BIOS sets around refs that
        # only shifted.
        from unittest import mock

        def gained(profile, report, *_):
            report.new_files = [{"path": "a.c", "name": "coh3002t.zip", "since_pin": True}]
            report.new_hashes = []

        before = self.path.read_text()
        with mock.patch.object(profiling_run, "_attach_detection", side_effect=gained), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self._run(self._args(rebase_refs=True, dry_run=False), self._shifted())
        self.assertEqual(self.path.read_text(), before)
        self.assertIn("coh3002t.zip", err.getvalue())
        with mock.patch.object(profiling_run, "_attach_detection", side_effect=gained):
            self._run(self._args(rebase_refs=True, dry_run=False, accept_changed=True), self._shifted())
        self.assertIn('source_commit: "newhead"', self.path.read_text())

    def test_an_upstream_that_moved_is_read_while_the_port_sits_on_head(self):
        """geolith cites jg.c in its upstream: with the port on HEAD the guard
        looked at the port alone and let upstream_commit move unread."""
        from unittest import mock

        seen = []

        def gained(profile, report, *_):
            seen.append(True)
            report.new_files = [{"path": "jg.c", "name": "new.rom", "since_pin": True}]
            report.new_hashes = []

        report = self._shifted()
        report.head = report.pin
        report.cited_sources = [
            CitedSource("a.c", _SAMPLE_REPO, "pin", "pin", True),
            CitedSource("jg.c", _UPSTREAM_REPO, "uppin", "uphead"),
        ]
        args = self._args(rebase_refs=True, dry_run=False)
        with mock.patch.object(profiling_run, "_attach_detection", side_effect=gained), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertTrue(profiling_run._gained_since_pin(args, "p", {}, report))
        self.assertEqual(seen, [True])
        self.assertIn("new.rom", err.getvalue())

    def test_a_repository_held_on_its_tag_does_not_hold_the_bump(self):
        """GroovyMAME's upstream sits on mame0289 and the bump leaves it there:
        what mamedev HEAD added to a cited driver is no reason to refuse."""
        from unittest import mock

        def gained(profile, report, *_):
            report.new_files = [{"path": "neogeo.cpp", "name": "x.zip", "since_pin": True}]
            report.new_hashes = [{"path": "neogeo.cpp", "kind": "md5", "value": "0" * 32}]

        report = self._shifted()
        report.cited_sources = [
            CitedSource("a.c", _SAMPLE_REPO, "pin", "newhead"),
            CitedSource("neogeo.cpp", _UPSTREAM_REPO, "tag", "uphead", True),
        ]
        args = self._args(rebase_refs=True, dry_run=False)
        with mock.patch.object(profiling_run, "_attach_detection", side_effect=gained):
            self.assertFalse(profiling_run._gained_since_pin(args, "p", {}, report))

    def _args(self, **over):
        base = dict(
            emulators_dir=str(self.dir), backfill_commits=False,
            rebase_refs=False, bump_commit=False, accept_changed=False,
            dry_run=True, cache_dir=str(self.dir), offline=True,
        )
        base.update(over)
        return argparse.Namespace(**base)

    def _run(self, args, report, sample=SAMPLE):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            profiling_run._apply_writes(
                args, "p", yaml.safe_load(sample), report
            )
        return buffer.getvalue()

    def _shifted(self):
        part = PartResult(
            RefPart("a.c", 10, 12, "a.c:10-12"), "SHIFTED", None, 30, 32, []
        )
        return ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[EntryReport("a.bin", "a.c:10-12", "SHIFTED", [part])],
            counts={"SHIFTED": 1},
            cited_sources=[CitedSource("a.c", _SAMPLE_REPO, "pin", "newhead")],
        )

    def test_a_prose_read_that_fails_leaves_the_profile_as_it_was(self):
        """The bumped profile was promoted before the prose under its new pin
        was read. Offline, an uncached cited file raised NotCachedError past
        the restore and the profile kept a pin the guard would refuse."""
        from unittest import mock

        before = self.path.read_bytes()
        cold = forgehttp.NotCachedError("x.c not cached")
        with mock.patch.object(profiling_run, "realign_prose", side_effect=[[], cold]), \
                self.assertRaises(forgehttp.NotCachedError):
            self._run(self._args(rebase_refs=True, dry_run=False), self._shifted())
        self.assertEqual(self.path.read_bytes(), before)

    def test_a_write_pass_names_a_profile_the_cache_cannot_answer(self):
        """--rebase-refs --offline on a profile whose cited files were never
        cached ended the whole pass on a NotCachedError traceback."""
        from unittest import mock

        before = self.path.read_bytes()
        skipped = ProfileReport(name="p", entries=[], counts={}, skipped="offline: not cached",
                                skip_kind=SkipKind.OFFLINE)
        cold = forgehttp.NotCachedError("o/n@pin:a.c is not in the offline cache")
        reports: list[ProfileReport] = []
        failed: set[str] = set()
        with mock.patch.object(profiling_run, "_build_full_report", return_value=skipped), \
                mock.patch.object(profiling_run, "realign_prose", side_effect=cold), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            profiling_run.read_one_profile(
                self._args(rebase_refs=True), "p", yaml.safe_load(SAMPLE), reports, failed, True,
                set(),
            )
        self.assertEqual(reports, [skipped])
        self.assertEqual(failed, {"p"})
        self.assertIn("p: not written: o/n@pin:a.c is not in the offline cache", err.getvalue())
        self.assertEqual(self.path.read_bytes(), before)

    def test_a_recale_held_by_the_bump_names_the_bump_refusal(self):
        """The pass guessed why the pin would not follow and named the prose
        on a profile bump_commit had refused for the build a platform ships."""
        sample = SAMPLE + "built_by: [recalbox]\n"
        self.path.write_text(sample, encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self._run(self._args(rebase_refs=True, dry_run=False), self._shifted(), sample)
        self.assertEqual(self.path.read_text(), sample)
        self.assertIn(
            "p: refs recaled but the pin will not follow, so nothing was written: "
            "pinned to the build recalbox ships, advanced by hand",
            err.getvalue(),
        )
        self.assertNotIn("prose", err.getvalue())

    def test_rebase_states_the_move_and_leaves_the_file(self):
        before = self.path.read_text()
        output = self._run(self._args(rebase_refs=True), self._shifted())
        self.assertIn("would recale", output)
        self.assertIn("a.c:10-12 -> a.c:30-32", output)
        self.assertEqual(self.path.read_text(), before)

    def test_a_pin_already_at_head_is_not_announced(self):
        """A write that changes nothing must not be reported as one.

        126 of 232 announced bumps on the corpus rewrote the pin to the
        value it already held, so the plan overstated the work by more than
        double and no reader could tell which entries meant anything.
        """
        part = PartResult(
            RefPart("a.c", 10, 12, "a.c:10-12"), "ANCHORED", None, 10, 12, []
        )
        self.path.write_text(
            insert_after_line(SAMPLE, "profiled_date", 'source_commit: "newhead"'),
            encoding="utf-8",
        )
        report = ProfileReport(
            name="p", repo="o/n", pin="newhead", head="newhead",
            entries=[EntryReport("a.bin", "a.c:10-12", "ANCHORED", [part])],
            counts={"ANCHORED": 1},
        )
        self.assertFalse(bump_commit(self.path, report).moved)
        self.assertEqual(self._run(self._args(bump_commit=True), report), "")

    def test_two_writing_pins_give_two_readings(self):
        """vitaquake2: written at one pin, re-pinned under the same text. Each
        pin is a reading, and a run settles when every reading agrees."""
        revisions = [
            ("c2", {"source_commit": "pin2", "notes": "x"}),
            ("c1", {"source_commit": "pin1", "notes": "x"}),
        ]
        repo = object()
        readings, ambiguous = realign._writing_pairs(
            {"source_commit": "pin2"}, [("source", "", repo)], revisions, "c1"
        )
        self.assertEqual(readings, [[(repo, "pin1", "pin2")], []])
        self.assertTrue(ambiguous)

    def test_a_confirmed_pin_settles_the_readings(self):
        """fixnes: doOpenFDSBIOS lived under four pins and was exact at the
        last. With nothing to record that reading, the bump was refused for
        good. prose_written_at names the pin and the readings collapse."""
        revisions = [
            ("c2", {"source_commit": "pin2", "notes": "x"}),
            ("c1", {"source_commit": "pin1", "notes": "x"}),
        ]
        repo = object()
        readings, _ambiguous = realign._writing_pairs(
            {"source_commit": "pin2", "prose_written_at": "pin2"},
            [("source", "", repo)], revisions, "c1",
        )
        self.assertEqual(readings, [[]])
        later, _ = realign._writing_pairs(
            {"source_commit": "pin3", "prose_written_at": "pin2"},
            [("source", "", repo)], revisions, "c1",
        )
        self.assertEqual(later, [[(repo, "pin2", "pin3")]])

    def test_a_confirmed_pin_outside_the_history_changes_nothing(self):
        revisions = [
            ("c2", {"source_commit": "pin2", "notes": "x"}),
            ("c1", {"source_commit": "pin1", "notes": "x"}),
        ]
        repo = object()
        readings, ambiguous = realign._writing_pairs(
            {"source_commit": "pin2", "prose_written_at": "elsewhere"},
            [("source", "", repo)], revisions, "c1",
        )
        self.assertEqual(readings, [[(repo, "pin1", "pin2")], []])
        self.assertTrue(ambiguous)

    def test_a_pin_keyed_by_build_mode_is_read_for_its_mode(self):
        """eka2l1 pins a dict per build: read as a string, it gave no
        repository and its prose was never judged."""
        revisions = [
            ("c2", {"source_commit": {"libretro": "new", "standalone": "s"}}),
            ("c1", {"source_commit": {"libretro": "old", "standalone": "s"}}),
        ]
        repo = object()
        readings, _ambiguous = realign._writing_pairs(
            {"source_commit": {"libretro": "new", "standalone": "s"}},
            [("source", "libretro", repo)], revisions, "c1",
        )
        self.assertIn([(repo, "old", "new")], readings)

    def test_a_pin_of_another_repository_is_no_writing_pin(self):
        """xenia-edge: source_commit named the has207/xenia-edge sha until it
        became a dict whose libretro key pins a GitLab port. Read for that
        mode, the old string passed for a pin of the port that moved under
        unchanged prose, and the bump stayed refused for good."""
        edge = "https://github.com/has207/xenia-edge"
        port = "https://gitlab.com/x/xenia-libretro"
        modes = {"standalone": edge, "libretro": port}
        revisions = [
            ("c2", {"source": modes, "notes": "x",
                    "source_commit": {"standalone": "e1", "libretro": "p1"}}),
            ("c1", {"source": edge, "notes": "x", "source_commit": "e1"}),
        ]
        document = dict(revisions[0][1])
        repos = [("source", mode, upstream.parse_repo(url))
                 for mode, url in modes.items()]
        readings, ambiguous = realign._writing_pairs(
            document, repos, revisions, "c1"
        )
        self.assertEqual(readings, [[]])
        self.assertEqual(ambiguous, [])

    def test_stale_prose_holds_the_pin(self):
        """boom3: a note written at an older pin is not anchored from this one."""
        before = self.path.read_text()
        part = PartResult(
            RefPart("a.c", 10, 12, "a.c:10-12"), "ANCHORED", None, 10, 12, []
        )
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[EntryReport("a.bin", "a.c:10-12", "ANCHORED", [part])],
            counts={"ANCHORED": 1},
        )
        stale = ["read again: notes: FileSystem.cpp:2125 (pin moved under this text)"]
        errors = io.StringIO()
        with mock.patch.object(profiling_run, "realign_prose", return_value=stale), \
                contextlib.redirect_stderr(errors):
            output = self._run(self._args(bump_commit=True, dry_run=False), report)
        self.assertNotIn("source_commit ->", output)
        self.assertIn("older pin", errors.getvalue())
        self.assertEqual(self.path.read_text(), before)

    def test_bump_states_the_pin_and_leaves_the_file(self):
        before = self.path.read_text()
        part = PartResult(
            RefPart("a.c", 10, 12, "a.c:10-12"), "ANCHORED", None, 10, 12, []
        )
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[EntryReport("a.bin", "a.c:10-12", "ANCHORED", [part])],
            counts={"ANCHORED": 1},
        )
        output = self._run(self._args(bump_commit=True), report)
        self.assertIn("would set source_commit -> newhead", output)
        self.assertEqual(self.path.read_text(), before)

    def test_a_bump_that_moves_only_upstream_says_so(self):
        """rustation: source_commit already at HEAD, the write added
        upstream_commit, and the dry run announced the source_commit it
        already held."""
        self.path.write_text(
            self.path.read_text().replace(
                'profiled_date: "2026-03-29"',
                'profiled_date: "2026-03-29"\nsource_commit: "newhead"',
            )
        )
        part = PartResult(
            RefPart("a.c", 10, 12, "a.c:10-12"), "ANCHORED", None, 10, 12, []
        )
        report = ProfileReport(
            name="p", repo="o/n", pin="newhead", head="newhead",
            entries=[EntryReport("a.bin", "a.c:10-12", "ANCHORED", [part])],
            counts={"ANCHORED": 1}, upstream_pin="oldup", upstream_head="uphead",
        )
        output = self._run(self._args(bump_commit=True), report)
        self.assertIn("would set upstream_commit -> uphead", output)
        self.assertNotIn("source_commit ->", output)

    def test_writes_still_happen_without_the_flag(self):
        output = self._run(
            self._args(rebase_refs=True, dry_run=False), self._shifted()
        )
        self.assertNotIn("would", output)
        self.assertIn('source_ref: "a.c:30-32"', self.path.read_text())

    def test_a_recale_carries_the_pin(self):
        """Refs rewritten for HEAD describe HEAD, so the pin follows in the
        same write. Left behind, the profile named one revision and cited
        another, and the next pass read the new refs at the old pin."""
        output = self._run(
            self._args(rebase_refs=True, dry_run=False), self._shifted()
        )
        self.assertIn("source_commit -> newhead", output)
        self.assertIn('source_commit: "newhead"', self.path.read_text())

    def test_a_recale_the_pin_cannot_follow_writes_nothing(self):
        """One ref recales, another is CHANGED and unread: neither the refs
        nor the pin move, and the file is left as it was."""
        before = self.path.read_text()
        shifted = PartResult(
            RefPart("a.c", 10, 12, "a.c:10-12"), "SHIFTED", None, 30, 32, []
        )
        changed = PartResult(RefPart("b.c", 5, 5, "b.c:5"), "CHANGED", None, 7, 7, [])
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[
                EntryReport("a.bin", "a.c:10-12", "SHIFTED", [shifted]),
                EntryReport("b.bin", "b.c:5", "CHANGED", [changed]),
            ],
            counts={"SHIFTED": 1, "CHANGED": 1},
        )
        output = self._run(self._args(rebase_refs=True, dry_run=False), report)
        self.assertNotIn("source_commit", output)
        self.assertEqual(self.path.read_text(), before)

    def test_a_bump_that_leaves_stale_prose_is_rolled_back(self):
        """dolphin-mmjr2, hatari, xenios: the bump moved upstream_commit only,
        and prose the report had judged in the fork fell under the new
        upstream pin. The guard had read it under the old pins."""
        from unittest import mock

        before = self.path.read_text()
        answers = iter([[], ["notes: a.c:10 (a.c:10 changed)"]])
        with mock.patch.object(
            profiling_run, "realign_prose", side_effect=lambda *a, **k: next(answers)
        ), contextlib.redirect_stderr(io.StringIO()) as err:
            self._run(self._args(rebase_refs=True, dry_run=False), self._shifted())
        self.assertEqual(self.path.read_text(), before)
        self.assertIn("nothing was written", err.getvalue())

    def test_a_planned_bump_reads_the_prose_the_rebase_would_have_left(self):
        """The pin is blocked by prose until the rebase moves it.

        Planning the bump against the file on disk would report a refusal
        that the real run, where the rebase lands first, never produces.
        """
        self.path.write_text(PROSE_SAMPLE, encoding="utf-8")
        before = self.path.read_text()
        part = PartResult(RefPart("a.c", 10, 10, "10"), "SHIFTED", None, 14, 14, [])
        entry = EntryReport(
            "notes", "a.c:10", "SHIFTED", [part], "prose", "notes"
        )
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[entry], counts={"SHIFTED": 1},
        )
        self.assertEqual(
            rebase.pending_recale(report, False, before), 1,
            "the prose still describes the pinned revision",
        )
        output = self._run(
            self._args(rebase_refs=True, bump_commit=True), report, PROSE_SAMPLE
        )
        self.assertIn("would recale", output)
        self.assertIn("would set source_commit -> newhead", output)
        self.assertEqual(self.path.read_text(), before)


class TestProseSpacingIsNotADifference(unittest.TestCase):
    """A recale keeps the author's spacing, so the check has to allow for it.

    run_after_moves renders `a.c:228,1439-1443` while the writer leaves the
    sentence as written, `a.c:228, 1439-1443`. Comparing the two literally
    made the run look unwritten, so bump_commit refused for ever: mariani
    was held back by three of them.
    """

    def test_a_written_run_counts_as_written_whatever_the_spacing(self):
        self.assertEqual(
            profiling_citations.citation_key("src/Harddisk.cpp:228, 1439-1443"),
            profiling_citations.citation_key("src/Harddisk.cpp:228,1439-1443"),
        )

    def test_different_citations_still_differ(self):
        self.assertNotEqual(
            profiling_citations.citation_key("a.c:1, 2"),
            profiling_citations.citation_key("a.c:1, 3"),
        )

    def test_a_path_change_still_differs(self):
        self.assertNotEqual(
            profiling_citations.citation_key("a.c:1"),
            profiling_citations.citation_key("src/a.c:1"),
        )


class TestLargeFileCeiling(unittest.TestCase):
    """The fallback mapping bails above a ceiling, and it sits high enough.

    openbor.c is the largest file any profile cites, 55k lines against 57k
    at HEAD, and the ref that mattered mapped only once the ceiling cleared
    it. The guard stays so a pathological pair cannot stall a sweep.
    """

    def test_a_pair_over_the_ceiling_is_not_diffed(self):
        big = ["x"] * (anchoring.MAX_MATCH_LINES + 1)
        result = anchoring._map_changed(big, big, 1, 2)
        self.assertEqual(result.status, "CHANGED")
        self.assertIn("over", result.reason)

    def test_a_pair_under_the_ceiling_is_mapped(self):
        pin = ["a", "subject", "b"]
        head = ["pad", "pad", "a", "subject", "b"]
        result = anchoring._map_changed(pin, head, 2, 2)
        self.assertIsNotNone(result.start, "a small pair has to be diffed")
        self.assertNotIn("over", result.reason or "")

    def test_the_ceiling_clears_the_largest_file_any_profile_cites(self):
        self.assertGreater(
            anchoring.MAX_MATCH_LINES, 57000,
            "openbor.c is 57k lines at HEAD and its ref has to map",
        )


class TestRebaseWaitsForThePin(unittest.TestCase):
    """Recaling refs the pin cannot follow manufactures the desync.

    An annotated ref is never rewritten, because regenerating it would drop
    the author's prose, so its parts stay on the pinned line numbers and
    bump_commit refuses. Moving the other refs anyway leaves the profile
    describing two revisions at once, which is the state the all-or-nothing
    rule exists to prevent. mariani was left in it.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.yml"
        self.path.write_text(SAMPLE, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def _report(self, entries, counts):
        return ProfileReport(
            name="p", repo="o/n", pin="pin", head="head",
            entries=entries, counts=counts,
        )

    def test_nothing_moves_while_an_annotated_ref_holds_the_pin(self):
        movable = PartResult(RefPart("a.c", 10, 12), "SHIFTED", None, 30, 32, [])
        stuck = PartResult(
            RefPart("b.c", 5, 5, "b.c:5"), "SHIFTED", None, 9, 9, []
        )
        report = self._report(
            [
                EntryReport("a.bin", "a.c:10-12", "SHIFTED", [movable]),
                EntryReport("b.bin", "b.c:5, (just a note)", "SHIFTED", [stuck]),
            ],
            {"SHIFTED": 2},
        )
        self.assertTrue(rebase.pending_recale(report))
        blocker = "b.bin: b.c:5, (just a note) (annotated, a rewrite would drop the annotation)"
        self.assertEqual(rebase_refs(self.path, report), Recale(refused=[blocker]))
        self.assertIn('source_ref: "a.c:10-12"', self.path.read_text())
        # --bump-commit alone names the same ref instead of staying silent.
        bump = bump_commit(self.path, report)
        self.assertFalse(bump.moved)
        self.assertEqual(bump.refusal, f"pin not advanced, cannot move {blocker}")

    def test_asking_for_both_writes_nothing_when_the_pin_cannot_follow(self):
        """The pass is atomic: refs and pin move together or not at all."""
        movable = PartResult(RefPart("a.c", 10, 12), "SHIFTED", None, 30, 32, [])
        report = self._report(
            [EntryReport("a.bin", "a.c:10-12", "SHIFTED", [movable])],
            {"SHIFTED": 1},
        )
        report.head = None  # bump_commit refuses without a head
        before = self.path.read_text()
        args = argparse.Namespace(
            emulators_dir=str(self.path.parent), backfill_commits=False,
            rebase_refs=True, bump_commit=True, accept_changed=False,
            dry_run=False, cache_dir=str(self.path.parent), offline=True,
        )
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            profiling_run._apply_writes(args, "p", yaml.safe_load(SAMPLE), report)
        self.assertEqual(self.path.read_text(), before)
        self.assertIn("nothing was written", err.getvalue())
        self.assertNotIn("a.c:30-32", out.getvalue())

    def test_a_profile_the_pin_can_follow_still_moves(self):
        movable = PartResult(RefPart("a.c", 10, 12), "SHIFTED", None, 30, 32, [])
        report = self._report(
            [EntryReport("a.bin", "a.c:10-12", "SHIFTED", [movable])],
            {"SHIFTED": 1},
        )
        self.assertFalse(rebase.pending_recale(report))
        self.assertEqual(rebase_refs(self.path, report).applied, ["a.c:10-12 -> a.c:30-32"])

    def test_chained_shifts_are_judged_at_their_own_entry(self):
        # tr1x: cut2 508->531, cut3 531->552, cut4 552->575. Once written,
        # cut3 and cut4 read as pending on the values cut2 and cut3 took.
        text = (
            'emulator: Test\nsource: "https://github.com/o/n"\n'
            'source_commit: "pin"\nfiles:\n'
            + "".join(
                f'  - name: "cut{n}.mp3"\n    source_ref: "g.json5:{line}"\n'
                for n, line in ((2, 508), (3, 531), (4, 552))
            )
        )
        self.path.write_text(text, encoding="utf-8")
        entries = [
            EntryReport(
                f"cut{n}.mp3", f"g.json5:{old}", "SHIFTED",
                [PartResult(RefPart("g.json5", old, old), "SHIFTED", None, new, new, [])],
                "ref", f"files[cut{n}.mp3].source_ref",
            )
            for n, old, new in ((2, 508, 531), (3, 531, 552), (4, 552, 575))
        ]
        report = self._report(entries, {"SHIFTED": 3})
        self.assertEqual(len(rebase_refs(self.path, report).applied), 3)
        written = self.path.read_text()
        self.assertIn('source_ref: "g.json5:575"', written)
        self.assertEqual(
            rebase.pending_recale(report, text=written), 0
        )


class TestBumpCommit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.yml"
        self.path.write_text(SAMPLE, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_refused_when_a_ref_could_not_move(self):
        part = PartResult(
            RefPart("a.c", 10, 12, "a.c:10-12"), "SHIFTED", None, 30, 32, []
        )
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[
                EntryReport("a.bin", "a.c:10-12, (just a note)", "SHIFTED", [part])
            ],
            counts={"SHIFTED": 1},
        )
        self.assertEqual(rebase.pending_recale(report), 1)
        self.assertFalse(bump_commit(self.path, report).moved)

    def test_a_profile_citing_nothing_advances(self):
        # anarch's pin sat behind HEAD through every bulk advance: the
        # report skips a profile with no source_ref, and the skip blocked it.
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead", entries=[], counts={},
            skipped=resolver.NO_SOURCE_REF, skip_kind=SkipKind.NO_SOURCE_REF,
        )
        report.upstream_head, report.upstream_pin = "uphead", "uppin"
        self.assertTrue(bump_commit(self.path, report).moved)
        text = self.path.read_text(encoding="utf-8")
        self.assertIn("newhead", text)
        # Nothing was compared upstream, so its pin is not written.
        self.assertNotIn("uphead", text)

    def test_a_profile_one_platform_ships_waits_for_its_build(self):
        """KNULLI alone ships advanced_drastic and builds its
        advanced_drastic.mk version. A bulk advance moved fheroes2 and
        supertux past the build EmuELEC then pinned, and a pin ahead of the
        one build a platform ships describes nothing anyone runs."""
        root = Path(__file__).resolve().parents[1]
        path = Path(self.tmp.name) / "advanced_drastic.yml"
        path.write_text(
            SAMPLE.replace(
                "\nnotes:", "\ntype: standalone\ncores: [advanced_drastic]\n\nnotes:", 1),
            encoding="utf-8",
        )
        report = ProfileReport(
            name="advanced_drastic", repo="o/n", pin="pin", head="newhead", entries=[],
            counts={}, skipped=resolver.NO_SOURCE_REF, skip_kind=SkipKind.NO_SOURCE_REF,
        )
        platforms = str(root / "platforms")
        self.assertEqual(
            bump.shipping_platforms("advanced_drastic", self.tmp.name, platforms),
            ["knulli"],
        )
        refused = bump_commit(path, report, platforms_dir=platforms)
        self.assertFalse(refused.moved)
        self.assertIn("only knulli ships it", refused.refusal or "")
        path.write_text(
            path.read_text(encoding="utf-8")
            + 'pin_follows: "KNULLI builds the branch tip"\n',
            encoding="utf-8",
        )
        self.assertTrue(bump_commit(path, report, platforms_dir=platforms).moved)

    def test_any_other_skip_still_holds_the_pin(self):
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead", entries=[], counts={},
            skipped="rate limited: gitlab.com", skip_kind=SkipKind.RATE_LIMITED,
        )
        self.assertFalse(bump_commit(self.path, report).moved)

    def test_accepted_when_nothing_had_to_move(self):
        part = PartResult(
            RefPart("a.c", 10, 12, "a.c:10-12"), "ANCHORED", None, 10, 12, []
        )
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[
                EntryReport("a.bin", "a.c:10-12, (just a note)", "ANCHORED", [part])
            ],
            counts={"ANCHORED": 1},
        )
        self.assertEqual(rebase.pending_recale(report), 0)
        self.assertTrue(bump_commit(self.path, report).moved)

    def test_refused_on_a_build_a_platform_compiles(self):
        # mame0258 documents the MAME Recalbox builds: libretro/mame HEAD
        # is a later release, and every ref still anchors there.
        self.path.write_text(SAMPLE + "built_by: [recalbox]\n", encoding="utf-8")
        part = PartResult(
            RefPart("a.c", 10, 12, "a.c:10-12"), "ANCHORED", None, 10, 12, []
        )
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[
                EntryReport("a.bin", "a.c:10-12, (just a note)", "ANCHORED", [part])
            ],
            counts={"ANCHORED": 1},
        )
        refused = bump_commit(self.path, report)
        self.assertFalse(refused.moved)
        self.assertIn("recalbox ships, advanced by hand", refused.refusal or "")
        self.assertNotIn("newhead", self.path.read_text())

    def test_a_build_of_the_branch_tip_follows_it(self):
        # RetroPie builds AdvanceMAME from the tip of master
        # (advmame.sh:16, 39-41): HEAD is the build it ships.
        self.path.write_text(
            SAMPLE + "built_by: [retropie]\n"
            + 'pin_follows: "RetroPie builds the branch tip"\n',
            encoding="utf-8",
        )
        part = PartResult(
            RefPart("a.c", 10, 12, "a.c:10-12"), "ANCHORED", None, 10, 12, []
        )
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[
                EntryReport("a.bin", "a.c:10-12, (just a note)", "ANCHORED", [part])
            ],
            counts={"ANCHORED": 1},
        )
        self.assertTrue(bump_commit(self.path, report).moved)
        self.assertIn("newhead", self.path.read_text())

    def test_a_config_read_at_the_pin_follows_it(self):
        # RetroPie reads advmame.rc at the build it installs, the pin: the
        # config_reads revision is the pin, and moves with it.
        pin = "a" * 40
        self.path.write_text(
            SAMPLE.replace('profiled_date: "2026-03-29"\n',
                           f'profiled_date: "2026-03-29"\nsource_commit: "{pin}"\n', 1)
            + "built_by: [retropie]\n"
            + 'pin_follows: "RetroPie builds the branch tip"\n'
            + "config_reads:\n"
            + '  - file: "advmame.rc"\n'
            + "    platforms: [retropie]\n"
            + f'    revision: "{pin}"\n'
            + '    source_ref: "a.c:10-12"\n'
            + "  - file: \"other.rc\"\n"
            + "    platforms: [emuelec]\n"
            + f'    revision: "{"b" * 40}"\n'
            + '    source_ref: "a.c:10-12"\n',
            encoding="utf-8",
        )
        part = PartResult(
            RefPart("a.c", 10, 12, "a.c:10-12"), "ANCHORED", None, 10, 12, []
        )
        head = "c" * 40
        report = ProfileReport(
            name="p", repo="o/n", pin=pin, head=head,
            entries=[EntryReport("a.bin", "a.c:10-12", "ANCHORED", [part])],
            counts={"ANCHORED": 1},
        )
        self.assertTrue(bump_commit(self.path, report).moved)
        document = yaml.safe_load(self.path.read_text(encoding="utf-8"))
        self.assertEqual(document["source_commit"], head)
        self.assertEqual([r["revision"] for r in document["config_reads"]], [head, "b" * 40])

    def test_refused_when_no_ref_reads_the_pinned_repository(self):
        """gam4980: every bare libretro.c ref anchored in upstream, and the
        bump wrote the fork's HEAD over refs that never described it."""
        def report(repo):
            part = PartResult(
                RefPart("libretro.c", 10, 12, "libretro.c:10-12"), "ANCHORED",
                None, 10, 12, [], None, repo,
            )
            return ProfileReport(
                name="p", repo="fork/n", repos=["fork/n", "up/n"], pin="pin",
                head="newhead",
                entries=[EntryReport("a.bin", "libretro.c:10-12", "ANCHORED", [part])],
                counts={"ANCHORED": 1},
            )
        self.assertFalse(bump_commit(self.path, report("up/n")).moved)
        self.assertNotIn("newhead", self.path.read_text())
        self.assertTrue(bump_commit(self.path, report(None)).moved)

    def test_a_bump_alone_waits_for_the_recale(self):
        """lrps2 at 0 to review with two SHIFTED parts: --bump-commit run
        alone wrote the new pin over refs still on the old lines."""
        part = PartResult(RefPart("a.c", 10, 12, "a.c:10-12"), "SHIFTED", None, 30, 32, [])
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[EntryReport("a.bin", "a.c:10-12", "SHIFTED", [part])],
            counts={"SHIFTED": 1},
        )
        self.assertFalse(bump_commit(self.path, report).moved)
        self.assertNotIn("newhead", self.path.read_text())
        self.assertEqual(rebase_refs(self.path, report).applied, ["a.c:10-12 -> a.c:30-32"])
        self.assertTrue(bump_commit(self.path, report).moved)

    def test_an_upstream_on_its_release_tag_stays_there(self):
        """GroovyMAME's upstream_commit is the mame0289 tag it merged: a bump
        of the port must not carry it to mamedev HEAD, another program."""
        part = PartResult(
            RefPart("a.c", 10, 12, "a.c:10-12"), "ANCHORED", None, 10, 12, []
        )
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[EntryReport("a.bin", "a.c:10-12", "ANCHORED", [part])],
            counts={"ANCHORED": 1},
            upstream_pin="uptag", upstream_head="uphead",
            upstream_origin="upstream_commit", upstream_tag="mame0289",
        )
        self.assertTrue(bump_commit(self.path, report).moved)
        written = yaml.safe_load(self.path.read_text())
        self.assertEqual(written["source_commit"], "newhead")
        self.assertNotIn("upstream_commit", written)

    def test_upstream_pin_moves_with_source_pin(self):
        """A recale onto upstream HEAD lines must advance upstream_commit too."""
        part = PartResult(
            RefPart("a.c", 10, 12, "a.c:10-12"), "ANCHORED", None, 10, 12, []
        )
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[EntryReport("a.bin", "a.c:10-12", "ANCHORED", [part])],
            counts={"ANCHORED": 1},
            upstream_pin="uppin", upstream_head="uphead", upstream_origin="upstream_commit",
        )
        self.assertTrue(bump_commit(self.path, report).moved)
        written = yaml.safe_load(self.path.read_text())
        self.assertEqual(written["source_commit"], "newhead")
        self.assertEqual(written["upstream_commit"], "uphead")

    def test_refused_for_a_pin_keyed_by_build_mode(self):
        """mesence, supermodel, xemu: str(dict) never matched a line."""
        text = self.path.read_text(encoding="utf-8")
        self.path.write_text(
            "source_commit:\n  standalone: \"aaa\"\n  libretro: \"bbb\"\n"
            + "\n".join(
                line for line in text.splitlines() if not line.startswith("source_commit")
            )
            + "\n",
            encoding="utf-8",
        )
        report = ProfileReport(
            name="p", repo="o/n", pin="aaa", head="newhead",
            entries=[], counts={"ANCHORED": 1},
        )
        before = self.path.read_text(encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(bump_commit(self.path, report).moved)
        self.assertEqual(self.path.read_text(encoding="utf-8"), before)

    def test_refused_when_pinned_to_a_superseded_tag(self):
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[], counts={"ANCHORED": 3}, pinned_tag="v1.6.0",
        )
        self.assertFalse(bump_commit(self.path, report).moved)

    def test_refused_while_a_changed_remains(self):
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[], counts={"CHANGED": 1},
        )
        self.assertFalse(bump_commit(self.path, report).moved)

    def test_accepted_when_everything_anchors(self):
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[], counts={"ANCHORED": 3, "SHIFTED": 1},
        )
        self.assertTrue(bump_commit(self.path, report).moved)
        self.assertEqual(
            yaml.safe_load(self.path.read_text())["source_commit"], "newhead"
        )


class TestCollapsingMoves(unittest.TestCase):
    """A recale never folds two parts of one ref onto the same line."""

    def test_a_move_onto_a_sibling_part_goes_to_review(self):
        sha = PartResult(RefPart("mt32emu.h", 5112, 5112, "upstream mt32emu.h:5112", "upstream"),
                         "ANCHORED", None, None, None, [])
        info = PartResult(RefPart("mt32emu.h", 5129, 5129, "source mt32emu.h:5129", "source"),
                          "MOVED", None, 5112, 5112, [5112])
        result = anchoring.refuse_collapsing_moves([sha, info])
        self.assertEqual([p.status for p in result], ["ANCHORED", "AMBIGUOUS"])

    def test_a_move_to_a_free_line_is_kept(self):
        first = PartResult(RefPart("a.c", 5, 5, "a.c:5"), "ANCHORED", None, None, None, [])
        moved = PartResult(RefPart("a.c", 9, 9, "a.c:9"), "MOVED", None, 12, 12, [12])
        result = anchoring.refuse_collapsing_moves([first, moved])
        self.assertEqual(result[1].status, "MOVED")


if __name__ == "__main__":
    unittest.main()
