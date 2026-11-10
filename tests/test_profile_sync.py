"""Tests for the profile synchronisation tool (no network)."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import argparse
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import profile_sync
from profile_sync import (
    EntryReport,
    PartResult,
    ProfileReport,
    RefPart,
    VersionReport,
    YamlWriteError,
    anchor_block,
    anchor_part,
    apply_edit,
    backfill_commit,
    build_parser,
    build_report,
    bump_commit,
    check_version,
    collect_citations,
    collect_tokens,
    declared_hashes,
    declared_names,
    detect_new_files,
    drift_score,
    fetch_plan,
    find_field_line,
    format_markdown,
    format_report,
    insert_after_line,
    parse_source_ref,
    rebase_refs,
    replace_field_line,
    report_to_dict,
    resolve_rename,
    select_profiles,
    select_repo,
    split_source_ref,
    tree_diff,
    unified_for_path,
    version_warning,
    watch_hashes,
    worst_status,
)
import upstream
import version_basis
from upstream import CompareResult, FileChange


def _version_read_as_written(profile, cache_dir, offline, profiles=None, recompute=False):
    """bump_commit reads core_version again at the new pin. These fixtures
    have no forge behind them, so the version reads as written here:
    tests/test_version_basis.py holds the reading and the refusals."""
    stated = version_basis.declared(profile, "")
    return [version_basis.Reading("", "file", stated, stated, "fixture", version_basis.MATCH)]


_VERSION_AS_WRITTEN = mock.patch.object(version_basis, "check", _version_read_as_written)


def setUpModule():
    _VERSION_AS_WRITTEN.start()


def tearDownModule():
    _VERSION_AS_WRITTEN.stop()


class TestParseSourceRef(unittest.TestCase):
    def test_path_with_single_line(self):
        self.assertEqual(
            parse_source_ref("src/core/bios.cpp:258"),
            ("src/core/bios.cpp", 258, 258),
        )

    def test_path_with_line_range(self):
        self.assertEqual(
            parse_source_ref("Machines/Utility/ROMCatalogue.cpp:123-129"),
            ("Machines/Utility/ROMCatalogue.cpp", 123, 129),
        )

    def test_path_without_line(self):
        self.assertEqual(
            parse_source_ref("FirmwareDatabase.cs"),
            ("FirmwareDatabase.cs", None, None),
        )


class TestSplitSourceRef(unittest.TestCase):
    def test_single_part(self):
        parts = split_source_ref("a.c:1-3")
        self.assertEqual(len(parts), 1)
        self.assertEqual(
            (parts[0].path, parts[0].start, parts[0].end), ("a.c", 1, 3)
        )

    def test_multiple_parts(self):
        parts = split_source_ref("a.c:1-3, b.c:9, c.h")
        self.assertEqual([p.path for p in parts], ["a.c", "b.c", "c.h"])
        self.assertIsNone(parts[2].start)

    def test_empty_ref(self):
        self.assertEqual(split_source_ref(""), [])

    def test_bare_range_continues_the_previous_file(self):
        parts = split_source_ref("src/geo.c:234-243, 273-285")
        self.assertEqual(
            [(p.path, p.start, p.end) for p in parts],
            [("src/geo.c", 234, 243), ("src/geo.c", 273, 285)],
        )

    def test_bare_single_line_continues_the_previous_file(self):
        parts = split_source_ref("HW_.cpp:2813,2820")
        self.assertEqual(
            [(p.path, p.start, p.end) for p in parts],
            [("HW_.cpp", 2813, 2813), ("HW_.cpp", 2820, 2820)],
        )

    def test_bare_range_carries_across_several_continuations(self):
        parts = split_source_ref("a.c:1-2, 5-6, 9")
        self.assertEqual([p.path for p in parts], ["a.c", "a.c", "a.c"])
        self.assertEqual(parts[2].start, 9)

    def test_continuation_stops_at_a_new_path(self):
        parts = split_source_ref("a.c:1-2, 5-6, b.c:3, 8")
        self.assertEqual(
            [(p.path, p.start) for p in parts],
            [("a.c", 1), ("a.c", 5), ("b.c", 3), ("b.c", 8)],
        )

    def test_semicolon_separates_parts(self):
        parts = split_source_ref("a.c:1-2; b.c:3")
        self.assertEqual([(p.path, p.start) for p in parts], [("a.c", 1), ("b.c", 3)])

    def test_parenthetical_annotation_is_dropped(self):
        parts = split_source_ref("mia/system/game-gear.cpp:8 (//optional)")
        self.assertEqual(
            (parts[0].path, parts[0].start),
            ("mia/system/game-gear.cpp", 8),
        )

    def test_annotations_between_parts(self):
        parts = split_source_ref(
            "src/emulator.cpp:234 (path check); src/core/aes.cpp:13-92 (loadKeys)"
        )
        self.assertEqual(
            [(p.path, p.start, p.end) for p in parts],
            [("src/emulator.cpp", 234, 234), ("src/core/aes.cpp", 13, 92)],
        )

    def test_annotation_containing_a_separator_is_not_split(self):
        parts = split_source_ref(
            "libretro.cpp:944-951 (system_dir + name, then fopen), core.c:12"
        )
        self.assertEqual(
            [(p.path, p.start) for p in parts],
            [("libretro.cpp", 944), ("core.c", 12)],
        )

    def test_trailing_prose_after_a_location_is_dropped(self):
        parts = split_source_ref("libretro/libretro.cpp:1520-1521 candidates_a1200")
        self.assertEqual(
            (parts[0].path, parts[0].start, parts[0].end),
            ("libretro/libretro.cpp", 1520, 1521),
        )

    def test_bare_range_followed_by_prose_still_continues(self):
        parts = split_source_ref("a.c:10-12, 151-156 load loop")
        self.assertEqual(
            [(p.path, p.start, p.end) for p in parts],
            [("a.c", 10, 12), ("a.c", 151, 156)],
        )

    def test_external_project_citation_is_kept_whole(self):
        parts = split_source_ref("munt ROMInfo.cpp")
        self.assertEqual(parts[0].path, "munt ROMInfo.cpp")

    def test_leading_colon_continues_the_previous_file(self):
        parts = split_source_ref("sms_mapper.c:12, :61, :162-170")
        self.assertEqual(
            [(p.path, p.start, p.end) for p in parts],
            [("sms_mapper.c", 12, 12), ("sms_mapper.c", 61, 61),
             ("sms_mapper.c", 162, 170)],
        )

    def test_leading_colon_with_annotations(self):
        parts = split_source_ref(
            "genesis.rs:41-51 (read), :256-262 (bios_path_for_region)"
        )
        self.assertEqual(
            [(p.path, p.start, p.end) for p in parts],
            [("genesis.rs", 41, 51), ("genesis.rs", 256, 262)],
        )

    def test_leading_bare_range_stays_a_path(self):
        parts = split_source_ref("273-285")
        self.assertEqual(parts[0].path, "273-285")


class TestCollectTokens(unittest.TestCase):
    def test_hashes_preferred_over_name(self):
        entry = {
            "name": "kernal.bin",
            "sha1": "6C4FA9465F6091B174DF27DFE679499DF447503C",
            "crc32": "789c8cc5",
        }
        tokens = collect_tokens(entry)
        self.assertIn("6c4fa9465f6091b174df27dfe679499df447503c", tokens)
        self.assertIn("789c8cc5", tokens)
        self.assertNotIn("kernal.bin", tokens)

    def test_name_fallback_without_hashes(self):
        self.assertEqual(collect_tokens({"name": "GC/USA/IPL.bin"}), ["ipl.bin"])

    def test_adler_prefix_stripped(self):
        self.assertEqual(
            collect_tokens({"known_hash_adler32": "0x4f1f6f5c"}), ["4f1f6f5c"]
        )

    def test_hash_lists(self):
        self.assertEqual(
            collect_tokens({"md5": ["AABB", "ccdd"]}), ["aabb", "ccdd"]
        )


class TestSourceMirror(unittest.TestCase):
    """A profile whose forge is gone can name a mirror and stay checkable.

    Nothing else recovers yuzu, suyu or citron: their trees exist, the host
    that served them does not. The mirror is consulted last so a live
    primary always decides attribution.
    """

    def test_mirror_is_declared_after_source_and_upstream(self):
        profile = {
            "source": "https://github.com/o/port",
            "upstream": "https://github.com/o/up",
            "source_mirror": "https://codeberg.org/o/mirror",
        }
        self.assertEqual(
            [url for _, _, url in profile_sync.declared_repositories(profile)],
            [
                "https://github.com/o/port",
                "https://github.com/o/up",
                "https://codeberg.org/o/mirror",
            ],
        )

    def test_mirror_alone_is_enough(self):
        profile = {"source_mirror": "https://codeberg.org/o/mirror"}
        self.assertEqual(
            profile_sync.declared_repositories(profile),
            [("source_mirror", "", "https://codeberg.org/o/mirror")],
        )

    def test_the_mirror_reads_the_source_pin(self):
        """eden's mirror was judged from profiled_date while source_commit,
        which bumps advance, named another revision."""
        profile = {
            "source": "https://git.eden-emu.dev/o/port",
            "source_mirror": "https://codeberg.org/o/mirror",
            "source_commit": "d16735f5",
            "profiled_date": "2026-03-26",
            "source_branch": "dev",
        }
        calls = []

        def head(repo, cache_dir, offline, branch=None):
            calls.append(("head", repo.host, branch))
            return None if repo.host == "git.eden-emu.dev" else "tip"

        def at(*args, **kwargs):
            raise AssertionError("a declared pin needs no date lookup")

        with mock.patch.object(profile_sync.upstream, "resolve_head", head), \
                mock.patch.object(profile_sync.upstream, "resolve_commit_at", at):
            views = profile_sync.select_views(profile, "unused", True)
        self.assertEqual([(v.repo.host, v.pin) for v in views],
                         [("codeberg.org", "d16735f5")])
        self.assertIn(("head", "codeberg.org", "dev"), calls)

    def test_a_repository_the_cache_never_read_stops_the_profile(self):
        """xenios offline with no cached tip of XeniOS's preview branch kept
        has207/xenia-edge alone and judged XeniOS's files there: GONE,
        "written against HEAD", 21 refs to review instead of 1."""
        import tempfile

        profile = {
            "source": "https://github.com/xenios-jp/XeniOS",
            "source_branch": "preview",
            "upstream": "https://github.com/has207/xenia-edge",
            "source_commit": "87b176a",
            "upstream_commit": "07021f0",
        }
        with tempfile.TemporaryDirectory() as cache:
            with self.assertRaises(profile_sync.upstream.NotCachedError):
                profile_sync.select_views(profile, cache, True)

    def test_a_profile_without_a_mirror_is_unchanged(self):
        profile = {"source": "https://github.com/o/port"}
        self.assertEqual(
            profile_sync.declared_repositories(profile),
            [("source", "", "https://github.com/o/port")],
        )


class TestGoneUpstreamIsNotAnError(unittest.TestCase):
    """A withdrawn forge is reported once, in its own bucket.

    yuzu and suyu answer 451, citron's host no longer resolves. Printing
    that on stderr every pass is noise nobody can act on, and counting it
    with real upstream failures hides the forges that are merely having a
    bad minute.
    """

    def test_a_gone_forge_is_skipped_not_errored(self):
        report = ProfileReport(
            name="yuzu", entries=[], counts={},
            skipped="upstream gone: https://host/x: HTTP 451, withdrawn for legal reasons",
        )
        self.assertEqual(report.needs_review(), 0)
        self.assertTrue(report.skipped.startswith("upstream gone:"))

    def test_gone_and_failing_forges_land_in_different_buckets(self):
        gone = ProfileReport(name="a", entries=[], counts={},
                             skipped="upstream gone: h: HTTP 451, withdrawn for legal reasons")
        failing = ProfileReport(name="b", entries=[], counts={},
                                skipped="upstream error: h: HTTP 403")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            profile_sync._print_elided([gone, failing], 0)
        out = buffer.getvalue()
        self.assertIn("upstream gone", out)
        self.assertIn("upstream error", out)

    def test_triage_names_an_orphaned_pin_and_a_moved_repository(self):
        """pcem's only problem was an upstream_commit off its dev branch, and
        the triage line read "1 to review" like any drift."""
        report = ProfileReport(
            name="pcem", entries=[], counts={"UNCHECKED": 2},
            orphaned=["sarah-walker-pcem/pcem: pin 25b54e3f is no ancestor of 4606fb1e"],
            moved_repos=["a/b answers as c/b (renamed or transferred)"],
        )
        self.assertEqual(
            profile_sync.triage_state(report),
            "2 to review, 1 orphaned pin, 1 repository moved, 2 unchecked",
        )


class TestWorstStatus(unittest.TestCase):
    def test_gone_beats_everything(self):
        self.assertEqual(worst_status(["ANCHORED", "GONE", "SHIFTED"]), "GONE")

    def test_changed_beats_ambiguous(self):
        self.assertEqual(worst_status(["AMBIGUOUS", "CHANGED"]), "CHANGED")

    def test_all_anchored(self):
        self.assertEqual(worst_status(["ANCHORED", "ANCHORED"]), "ANCHORED")

    def test_empty(self):
        self.assertEqual(worst_status([]), "ANCHORED")


class TestAnchorBlock(unittest.TestCase):
    def test_a_range_ending_past_the_file_is_gone(self):
        """dolphin cited NANDImporter.cpp:239-323 in a 317-line file. The
        part inside the file anchored, and the ref read as sound."""
        lines = [f"line {n}" for n in range(1, 11)]
        self.assertEqual(anchor_block(lines, list(lines), 8, 14).status, "GONE")
        self.assertEqual(anchor_block(lines, list(lines), 8, 10).status, "ANCHORED")

    def test_anchored_same_position(self):
        lines = ["a", "target", "b"]
        result = anchor_block(lines, list(lines), 2, 2)
        self.assertEqual(result.status, "ANCHORED")
        self.assertEqual((result.start, result.end), (2, 2))

    def test_shifted_when_block_moved(self):
        pin = ["a", "target line", "b"]
        head = ["x", "y", "z", "a", "target line", "b"]
        result = anchor_block(pin, head, 2, 2)
        self.assertEqual(result.status, "SHIFTED")
        self.assertEqual((result.start, result.end), (5, 5))

    def test_shifted_on_whitespace_only_change(self):
        self.assertEqual(
            anchor_block(["  value = 1"], ["\t\tvalue = 1"], 1, 1).status, "ANCHORED"
        )

    def test_range_preserved_when_shifted(self):
        pin = ["p", "one", "two", "three", "q"]
        head = ["x", "x", "p", "one", "two", "three", "q"]
        result = anchor_block(pin, head, 2, 4)
        self.assertEqual((result.status, result.start, result.end), ("SHIFTED", 4, 6))

    def test_widening_disambiguates_duplicate_line(self):
        pin = ["header A", "dup", "tail A", "header B", "dup", "tail B"]
        head = ["pad", "header A", "dup", "tail A", "header B", "dup", "tail B"]
        result = anchor_block(pin, head, 5, 5)
        self.assertEqual((result.status, result.start), ("SHIFTED", 6))

    def test_ambiguous_when_widening_never_resolves(self):
        result = anchor_block(["dup"] * 400, ["dup"] * 400, 5, 5)
        self.assertEqual(result.status, "AMBIGUOUS")
        self.assertGreater(len(result.candidates), 1)

    def test_changed_maps_to_new_range(self):
        pin = ["a", "b", "value = 1", "c", "d"]
        head = ["a", "b", "value = 2", "c", "d"]
        result = anchor_block(pin, head, 3, 3)
        self.assertEqual(result.status, "CHANGED")
        self.assertEqual(result.start, 3)

    def test_rows_edited_in_place_keep_their_own_line(self):
        rows = [f'{{"ipl{i}", 0x{i:02x}}}' for i in range(8)]
        pin = ["a", "b", *rows, "z"]
        head = ["a", "b", *[row + ", false" for row in rows], "z"]
        for line in (3, 5, 10):
            result = anchor_block(pin, head, line, line)
            self.assertEqual(result.status, "CHANGED")
            self.assertEqual(result.start, line)

    def test_a_file_rewritten_line_for_line_is_changed_not_gone(self):
        # fheroes2 version.txt:1 went from 1.0.11 to 1.1.17. With no
        # unchanged line left the file read GONE and held the whole recale.
        result = anchor_block(["1.0.11"], ["1.1.17"], 1, 1)
        self.assertEqual((result.status, result.start, result.end), ("CHANGED", 1, 1))
        result = anchor_block(["a = 1", "b = 2"], ["a = 3", "b = 4"], 2, 2)
        self.assertEqual((result.status, result.start), ("CHANGED", 2))

    def test_gone_when_content_vanished(self):
        result = anchor_block(["a", "unique marker", "b"], ["x"] * 200, 2, 2)
        self.assertEqual(result.status, "GONE")

    def test_gone_when_start_beyond_pin_file(self):
        self.assertEqual(anchor_block(["a"], ["a"], 50, 50).status, "GONE")

    def test_blank_cited_range_is_changed(self):
        result = anchor_block(["a", "", "b"], ["a", "", "b"], 2, 2)
        self.assertEqual(result.status, "CHANGED")

    def test_a_file_past_the_cap_skips_mapping_with_reason(self):
        size = profile_sync.MAX_MATCH_LINES + 1
        pin = [f"line {i}" for i in range(size)]
        head = [f"other {i}" for i in range(size)]
        result = anchor_block(pin, head, 10, 10)
        self.assertEqual(result.status, "CHANGED")
        self.assertIn(str(profile_sync.MAX_MATCH_LINES), result.reason)
        self.assertIsNone(result.start)

    def test_a_thirty_thousand_line_file_is_still_mapped(self):
        pin = [f"line {i}" for i in range(30000)]
        head = ["pad"] + pin[:-1]
        result = anchor_block(pin, head, 10, 10)
        self.assertEqual(result.status, "SHIFTED")
        self.assertEqual(result.start, 11)


def _part(path, old, new, status):
    return PartResult(RefPart(path, old, old), status, None, new, new, [])


def _ambiguous(path, old, candidates):
    return PartResult(
        RefPart(path, old, old), "AMBIGUOUS", None, None, None, candidates
    )


class TestVerifyAtPin(unittest.TestCase):
    """A tag-pinned profile is judged on self-consistency, not on HEAD."""

    LINES = ["pad", "pad", 'ROM_LOAD("bios.bin", CRC(deadbeef))', "pad"]

    def test_a_range_ending_past_the_file_is_gone(self):
        """mame cited casloopy.cpp:2105-2462 in a 2105-line file."""
        part = RefPart("a.c", 3, 9, "a.c:3-9")
        self.assertEqual(
            profile_sync.verify_at_pin(part, self.LINES, ["deadbeef"]).status, "GONE"
        )

    def test_declared_value_present(self):
        part = RefPart("a.c", 3, 3, "a.c:3")
        self.assertEqual(
            profile_sync.verify_at_pin(part, self.LINES, ["deadbeef"]).status,
            "ANCHORED",
        )

    def test_value_found_within_the_context_window(self):
        part = RefPart("a.c", 1, 1, "a.c:1")
        self.assertEqual(
            profile_sync.verify_at_pin(part, self.LINES, ["deadbeef"]).status,
            "ANCHORED",
        )

    def test_declared_value_absent_from_the_whole_file(self):
        part = RefPart("a.c", 1, 1, "a.c:1")
        result = profile_sync.verify_at_pin(part, self.LINES, ["cafebabe"])
        self.assertEqual(result.status, "ANCHORED")

    def test_declared_value_carried_by_another_line(self):
        lines = ["load()", "", "", "", "", "", 'rom("cafebabe")']
        part = RefPart("a.c", 1, 1, "a.c:1")
        result = profile_sync.verify_at_pin(
            part, lines, ["cafebabe"], ["cafebabe"]
        )
        self.assertEqual(result.status, "MOVED")
        self.assertEqual(result.start, 7)

    def test_a_part_annotated_for_another_version(self):
        """ti99sim cites v0.0.11 beside its v0.16.0 pin."""
        other = RefPart("src/sdl/main.cpp", 407, 411, "src/sdl/main.cpp:407-411 (v0.0.11)")
        same = RefPart("src/core/ti994a.cpp", 122, 131, "src/core/ti994a.cpp:122-131 (v0.16.0)")
        self.assertEqual(profile_sync.cites_another_version(other, "0.16.0"), "0.0.11")
        self.assertIsNone(profile_sync.cites_another_version(same, "0.16.0"))
        self.assertIsNone(profile_sync.cites_another_version(same, {"libretro": "v0.16.0"}))

    def test_a_profile_with_a_repository_names_a_revision(self):
        """redream declared libretro/redream, a repository that never
        existed, with no pin and no date: profile_sync skipped it and no
        revision answered for the files Batocera, RetroBat and KNULLI ship."""
        import yaml

        root = Path(__file__).resolve().parents[1] / "emulators"
        unpinned = [
            path.stem
            for path in sorted(root.glob("*.yml"))
            if (profile := yaml.safe_load(path.read_text(encoding="utf-8")) or {})
            and (profile.get("source") or profile.get("upstream"))
            and not any(
                profile.get(key)
                for key in ("source_commit", "upstream_commit", "profiled_date")
            )
        ]
        self.assertEqual(unpinned, [])

    def test_a_profile_citing_versions_documents_its_own(self):
        """ti99sim's core_version went null while doc/CHANGES.html at its pin
        reads 0.16.0: every (v0.16.0) part then read as another version, and
        the profile reported 0 to review with nothing checked."""
        import yaml

        root = Path(__file__).resolve().parents[1] / "emulators"
        silent = []
        for path in sorted(root.glob("*.yml")):
            profile = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            refs = " ".join(
                str(entry.get("source_ref") or "") for entry in profile.get("files") or []
            )
            if not profile_sync._VERSION_NOTE_RE.search(refs):
                continue
            declared = profile.get("core_version")
            values = declared.values() if isinstance(declared, dict) else [declared]
            if not any(values):
                silent.append(path.stem)
        self.assertEqual(silent, [])

    def test_a_name_stem_elsewhere_does_not_move_a_ref(self):
        """linapple cites the PRAVETS82 option, and the stem also names an install line."""
        lines = ['option(ENABLE_ROM_CLONE_PRAVETS "" OFF)', "", "", "", "", "",
                 "", "", "", "", "", "", "res/roms/pravets82.rom"]
        part = RefPart("CMakeLists.txt", 1, 1, "CMakeLists.txt:1")
        result = profile_sync.verify_at_pin(
            part, lines, ["0123456789abcdef0123456789abcdef", "pravets82"],
            ["0123456789abcdef0123456789abcdef"],
        )
        self.assertEqual(result.status, "ANCHORED")

    def test_declared_value_on_several_lines_is_ambiguous(self):
        lines = ["load()", "", "", "", 'a("cafebabe")', "", 'b("cafebabe")']
        part = RefPart("a.c", 1, 1, "a.c:1")
        result = profile_sync.verify_at_pin(
            part, lines, ["cafebabe"], ["cafebabe"]
        )
        self.assertEqual(result.status, "AMBIGUOUS")

    def test_one_anchored_part_settles_the_others(self):
        parts = [
            profile_sync.PartResult(
                RefPart("a.c", 1, 1, "a.c:1"), "ANCHORED", None, None, None, []
            ),
            profile_sync.PartResult(
                RefPart("a.c", 9, 9, "a.c:9"), "AMBIGUOUS", None, None, None, [1, 2]
            ),
        ]
        settled = profile_sync.reconcile_self_check(parts)
        self.assertEqual([p.status for p in settled], ["ANCHORED", "ANCHORED"])

    def test_an_absent_part_survives_reconciliation(self):
        parts = [
            profile_sync.PartResult(
                RefPart("a.c", 1, 1, "a.c:1"), "ANCHORED", None, None, None, []
            ),
            profile_sync.PartResult(
                RefPart("b.c", 9, 9, "b.c:9"), "GONE", None, None, None, []
            ),
        ]
        settled = profile_sync.reconcile_self_check(parts)
        self.assertEqual([p.status for p in settled], ["ANCHORED", "GONE"])

    def test_nothing_anchored_leaves_the_verdicts_alone(self):
        parts = [
            profile_sync.PartResult(
                RefPart("a.c", 1, 1, "a.c:1"), "MOVED", None, 5, 5, [5]
            ),
        ]
        self.assertEqual(
            [p.status for p in profile_sync.reconcile_self_check(parts)], ["MOVED"]
        )

    def test_external_citation_is_out_of_reach_at_the_pin_too(self):
        part = RefPart("munt ROMInfo.cpp", 1, 1, "munt ROMInfo.cpp:1")
        result = profile_sync.verify_at_pin(part, None, ["cafebabe"])
        self.assertEqual(result.status, "EXTERNAL")

    def test_a_name_fragment_elsewhere_is_not_evidence(self):
        # Only a hash is unique enough to prove a ref points elsewhere.
        lines = ["load()", "", "", "", "", "", "tyrian2.c line"]
        part = RefPart("a.c", 1, 1, "a.c:1")
        result = profile_sync.verify_at_pin(part, lines, ["tyrian2"], [])
        self.assertEqual(result.status, "ANCHORED")

    def test_missing_file(self):
        part = RefPart("a.c", 1, 1, "a.c:1")
        self.assertEqual(
            profile_sync.verify_at_pin(part, None, ["deadbeef"]).status, "GONE"
        )

    def test_an_entry_with_nothing_to_look_for_is_unchecked_not_anchored(self):
        """race's analysis.npbios entry carries a `filename:` and no hash: at a
        pin equal to HEAD its ref was reported anchored while the cited block
        had been deleted upstream. No token means no verdict."""
        part = RefPart("a.c", 3, 3, "a.c:3")
        result = profile_sync.verify_at_pin(part, self.LINES, [])
        self.assertEqual(result.status, "UNCHECKED")
        self.assertNotIn("UNCHECKED", profile_sync.REVIEW_STATUSES)
        self.assertEqual(profile_sync.worst_status(["ANCHORED", "UNCHECKED"]), "UNCHECKED")
        self.assertEqual(profile_sync.worst_status(["UNCHECKED", "SHIFTED"]), "SHIFTED")

    def test_line_beyond_the_file(self):
        part = RefPart("a.c", 99, 99, "a.c:99")
        self.assertEqual(
            profile_sync.verify_at_pin(part, self.LINES, ["deadbeef"]).status, "GONE"
        )

    def test_a_ref_without_a_line_is_accepted(self):
        part = RefPart("a.c", None, None, "a.c")
        self.assertEqual(
            profile_sync.verify_at_pin(part, self.LINES, ["deadbeef"]).status,
            "ANCHORED",
        )

    def test_an_entry_declaring_nothing_is_accepted_but_not_called_anchored(self):
        # Nothing to re-read, so no review is demanded, but the verdict says
        # that nothing was checked rather than claiming the ref anchors.
        part = RefPart("a.c", 1, 1, "a.c:1")
        result = profile_sync.verify_at_pin(part, self.LINES, [])
        self.assertEqual(result.status, "UNCHECKED")
        self.assertNotIn(result.status, profile_sync.REVIEW_STATUSES)


class TestExternalCitation(unittest.TestCase):
    def test_project_name_then_file(self):
        self.assertTrue(profile_sync.is_external_citation("munt ROMInfo.cpp"))
        self.assertTrue(
            profile_sync.is_external_citation("Nuked-SC55-CLAP rom_io.cpp")
        )
        self.assertTrue(
            profile_sync.is_external_citation("EmuDeck emuDeckares.sh")
        )

    def test_a_file_without_an_extension_is_still_a_citation(self):
        """A repository carries files with no dot in their name.

        The pattern required a dotted extension, so `Makefile:36-37` and
        `README:27` were never collected and rotted unnoticed while every
        dotted citation was anchored.
        """
        for text in ("Makefile:36-37", "src/Makefile:36", "README:27",
                     "configure:120"):
            with self.subTest(text=text):
                match = profile_sync.PROSE_CITE_RE.search(text)
                self.assertIsNotNone(match, text)
                self.assertEqual(match.group("path"), text.split(":")[0])

    def test_a_constant_or_an_address_is_not_a_citation(self):
        """Widening the pattern to any dotless word swallows these."""
        for text in ("ALTERNATEROMS:23", "F000:12", "C000:4"):
            with self.subTest(text=text):
                self.assertIsNone(profile_sync.PROSE_CITE_RE.search(text), text)

    def test_plain_paths_are_not_citations(self):
        for path in ("src/midi/mt32.cpp", "libretro.c", "a/b/c.h"):
            self.assertFalse(profile_sync.is_external_citation(path), path)

    def test_a_path_with_a_directory_prefix_is_not_a_citation(self):
        self.assertFalse(
            profile_sync.is_external_citation("src/dir file.cpp")
        )

    def test_a_filename_prefix_is_not_a_citation(self):
        self.assertFalse(profile_sync.is_external_citation("main.cpp note"))

    def test_external_part_is_reported_not_reviewed(self):
        result = anchor_part(
            RefPart("munt ROMInfo.cpp", 59, 59),
            make_fetch({}),
            renamer(CompareResult([], False)),
        )
        self.assertEqual(result.status, "EXTERNAL")
        self.assertNotIn("EXTERNAL", profile_sync.REVIEW_STATUSES)


class TestBinaryCitation(unittest.TestCase):
    """A ref read by disassembly has no source path to anchor."""

    def test_hex_address_is_binary(self):
        self.assertTrue(profile_sync.is_binary_citation(
            "BAM.dll 1.5-408 .text:0x100c3960-0x100c3a97"
        ))
        self.assertTrue(profile_sync.is_binary_citation("libmain.so LoadNES 0x3bb49"))

    def test_binary_suffix_followed_by_words_is_binary(self):
        self.assertTrue(profile_sync.is_binary_citation("BAM-Tracker.exe import directory"))

    def test_section_name_is_binary(self):
        self.assertTrue(profile_sync.is_binary_citation(".rdata dialog filter"))

    def test_bare_library_name_is_binary(self):
        self.assertTrue(profile_sync.is_binary_citation("DesktopKinect.dll"))
        self.assertFalse(profile_sync.is_binary_citation("Makefile"))

    def test_a_source_path_is_not_binary(self):
        for path in ("src/foo.c", "libs/libCg.so", "Source/Core/hook.c", "resources/font.h"):
            self.assertFalse(profile_sync.is_binary_citation(path), path)

    def test_binary_part_is_reported_not_reviewed(self):
        result = anchor_part(
            RefPart("BAM.dll 1.5-408 .text:0x10031bbb", None, None),
            make_fetch({}),
            renamer(CompareResult([], False)),
        )
        self.assertEqual(result.status, "BINARY")
        self.assertNotIn("BINARY", profile_sync.REVIEW_STATUSES)

    def test_binary_part_at_the_pin(self):
        part = RefPart("ModelImporter.exe import directory", None, None, "")
        self.assertEqual(profile_sync.verify_at_pin(part, None, []).status, "BINARY")


class TestRepoWord(unittest.TestCase):
    """A leading word naming a declared repository is a location, not a project."""

    def test_declared_repository_word_is_stripped(self):
        self.assertEqual(
            profile_sync.strip_repo_word("BAM_FPloader FPLoader.cpp", {"bam_fploader"}),
            "FPLoader.cpp",
        )

    def test_release_version_after_the_repository_word_is_dropped(self):
        self.assertEqual(
            profile_sync.strip_repo_word(
                "ArcadeFlashWeb v1.0.2 flash/flash.html", {"arcadeflashweb"}
            ),
            "flash/flash.html",
        )

    def test_undeclared_project_word_stays(self):
        self.assertEqual(
            profile_sync.strip_repo_word("munt ROMInfo.cpp", {"bam_fploader"}),
            "munt ROMInfo.cpp",
        )

    def test_a_directory_prefix_is_not_a_project_word(self):
        self.assertEqual(
            profile_sync.strip_repo_word("src/dir file.cpp", {"src/dir"}),
            "src/dir file.cpp",
        )


class TestNarrowByCited(unittest.TestCase):
    """A bare filename carried by two trees follows the tree the profile cites."""

    MATCHES = [
        "BasiliskII/src/include/version.h",
        "SheepShaver/src/include/version.h",
    ]

    def test_deepest_cited_directory_wins(self):
        self.assertEqual(
            profile_sync.narrow_by_cited(self.MATCHES, {"SheepShaver", "SheepShaver/src"}),
            ["SheepShaver/src/include/version.h"],
        )

    def test_equal_depth_keeps_both(self):
        matches = [
            "SheepShaver/src/EthernetDriver/cpu_emulation.h",
            "SheepShaver/src/include/cpu_emulation.h",
        ]
        self.assertEqual(
            profile_sync.narrow_by_cited(matches, {"SheepShaver/src"}), matches
        )

    def test_nothing_cited_keeps_all(self):
        self.assertEqual(profile_sync.narrow_by_cited(self.MATCHES, set()), self.MATCHES)

    def test_depth_counts_components_not_characters(self):
        matches = [
            "SheepShaver/src/Unix/configure.ac",
            "SheepShaver/src/Windows/configure.ac",
        ]
        cited = {"SheepShaver", "SheepShaver/src", "SheepShaver/src/Unix", "SheepShaver/src/Windows"}
        self.assertEqual(profile_sync.narrow_by_cited(matches, cited), matches)


class TestSymlinkTarget(unittest.TestCase):
    """A one-line blob naming a same-named file is a link to follow."""

    def test_relative_link_resolves_from_the_link_directory(self):
        self.assertEqual(
            profile_sync.symlink_target(
                "SheepShaver/src/Unix/ether_unix.cpp",
                ["../../../BasiliskII/src/Unix/ether_unix.cpp"],
            ),
            "BasiliskII/src/Unix/ether_unix.cpp",
        )

    def test_a_real_one_line_file_is_not_a_link(self):
        self.assertIsNone(profile_sync.symlink_target("a/VERSION", ["1.2.3"]))
        self.assertIsNone(profile_sync.symlink_target("a/x.c", ["int main() { return 0; }"]))
        self.assertIsNone(profile_sync.symlink_target("a/x.c", ["../other.c"]))

    def test_a_link_leaving_the_tree_is_ignored(self):
        self.assertIsNone(profile_sync.symlink_target("x.c", ["../../x.c"]))


class TestAnchorTokens(unittest.TestCase):
    def test_archive_members_supply_the_content_values(self):
        tokens = profile_sync._anchor_tokens(
            {"name": "esh.zip", "contents": [{"crc32": "c14f36b3"}]}
        )
        # The set name stays: a MAME ref cites the machine declaration, which
        # carries the name and no hash.
        self.assertEqual(tokens, ["c14f36b3", "esh"])

    def test_a_hashless_archive_still_falls_back_to_its_stem(self):
        tokens = profile_sync._anchor_tokens(
            {"name": "esh.zip", "contents": [{"name": "rom.u1"}]}
        )
        self.assertIn("esh", tokens)

    def test_archive_stem_is_searched_too(self):
        tokens = profile_sync._anchor_tokens({"name": "stvbios.zip"})
        self.assertIn("stvbios.zip", tokens)
        self.assertIn("stvbios", tokens)

    def test_hashes_still_win(self):
        tokens = profile_sync._anchor_tokens(
            {"name": "a.zip", "sha1": "AABB" * 10}
        )
        self.assertIn("aabb" * 10, tokens)

    def test_very_short_stem_is_skipped(self):
        self.assertNotIn("ab", profile_sync._anchor_tokens({"name": "ab.zip"}))


class TestNudgeToDeclared(unittest.TestCase):
    LINES = ["pad"] * 20 + ["ROM_START( stvbios )"] + ["pad"] * 20

    def test_moves_onto_the_declared_value(self):
        self.assertEqual(
            profile_sync.nudge_to_declared(self.LINES, 19, 19, ["stvbios"]),
            (21, 21),
        )

    def test_range_length_is_kept(self):
        lines = [""] * 20 + ["ROM_START( stvbios )"] + ["pad"] * 20
        self.assertEqual(
            profile_sync.nudge_to_declared(lines, 17, 19, ["stvbios"]),
            (21, 23),
        )

    def test_a_range_over_code_cites_that_code(self):
        """ymir's 598-618 cited load_rom_cartridge(). Nudged onto the file
        table beside it, a rewritten function read SHIFTED, not CHANGED."""
        lines = ["void load_rom_cartridge() {"] + ["  code();"] * 19 + ["}", "kKOF95Files"]
        self.assertIsNone(profile_sync.nudge_to_declared(lines, 1, 21, ["kkof95files"]))

    def test_nothing_when_already_on_target(self):
        self.assertIsNone(
            profile_sync.nudge_to_declared(self.LINES, 21, 21, ["stvbios"])
        )

    def test_nothing_beyond_the_window(self):
        lines = ["pad"] * 500 + ["ROM_START( stvbios )"]
        self.assertIsNone(profile_sync.nudge_to_declared(lines, 1, 1, ["stvbios"]))

    def test_nothing_without_tokens(self):
        self.assertIsNone(profile_sync.nudge_to_declared(self.LINES, 19, 19, []))

    def test_nothing_when_the_value_is_absent(self):
        self.assertIsNone(
            profile_sync.nudge_to_declared(self.LINES, 19, 19, ["absent"])
        )

    def test_adjacent_duplicates_are_refused(self):
        lines = ["pad"] * 20 + ["stvbios a", "stvbios b"] + ["pad"] * 20
        self.assertIsNone(
            profile_sync.nudge_to_declared(lines, 19, 19, ["stvbios"])
        )


class TestDominantShift(unittest.TestCase):
    def test_shift_needs_enough_support(self):
        parts = [_part("a.c", 10, 30, "SHIFTED"), _part("a.c", 20, 40, "SHIFTED")]
        self.assertEqual(profile_sync.dominant_shifts(parts), {})

    def test_shift_is_taken_from_resolved_anchors(self):
        parts = [_part("a.c", i, i + 20, "SHIFTED") for i in (10, 20, 30)]
        self.assertEqual(profile_sync.dominant_shifts(parts), {"a.c": 20})

    def test_ambiguous_parts_do_not_vote(self):
        parts = [_part("a.c", i, i + 20, "SHIFTED") for i in (10, 20, 30)]
        parts.append(_ambiguous("a.c", 40, [99, 500]))
        self.assertEqual(profile_sync.dominant_shifts(parts), {"a.c": 20})

    def test_candidate_matching_the_shift_is_selected(self):
        part = _ambiguous("a.c", 1624, [1644, 1790, 1834])
        settled = profile_sync.resolve_by_shift(part, {"a.c": 20})
        self.assertEqual(settled.status, "SHIFTED")
        self.assertEqual(settled.start, 1644)
        self.assertIn("+20", settled.reason)

    def test_no_candidate_matches_the_shift(self):
        part = _ambiguous("a.c", 1624, [1790, 1834])
        self.assertEqual(profile_sync.resolve_by_shift(part, {"a.c": 20}).status,
                         "AMBIGUOUS")

    def test_two_candidates_on_the_shift_stay_ambiguous(self):
        part = _ambiguous("a.c", 1624, [1644, 1644])
        self.assertEqual(profile_sync.resolve_by_shift(part, {"a.c": 20}).status,
                         "AMBIGUOUS")

    def test_range_length_is_preserved(self):
        part = PartResult(
            RefPart("a.c", 100, 104), "AMBIGUOUS", None, None, None, [120]
        )
        settled = profile_sync.resolve_by_shift(part, {"a.c": 20})
        self.assertEqual((settled.start, settled.end), (120, 124))

    def test_file_without_a_known_shift_is_untouched(self):
        part = _ambiguous("b.c", 10, [30])
        self.assertEqual(profile_sync.resolve_by_shift(part, {"a.c": 20}).status,
                         "AMBIGUOUS")


PIN = profile_sync.PIN
HEAD = profile_sync.HEAD


def make_fetch(files: dict[tuple[str, str], list[str]]):
    # The real fetch takes the cited line too, so that a path carried by two
    # repositories is attributed to the one whose revision is not blank there.
    return lambda sha, path, start=None, tokens=(): files.get((sha, path))


def renamer(result: CompareResult, head_paths=()):
    return lambda path: resolve_rename(result, path, head_paths)


class TestResolveRename(unittest.TestCase):
    def test_uses_comparison_when_available(self):
        result = CompareResult([FileChange("renamed", "new.c", "old.c")], False)
        self.assertEqual(resolve_rename(result, "old.c")[0], "new.c")

    def test_basename_fallback_when_truncated(self):
        result = CompareResult(
            [
                FileChange("added", "a/b/driver.cpp", None),
                FileChange("added", "z/other.cpp", None),
            ],
            True,
        )
        found, candidates = resolve_rename(result, "src/driver.cpp")
        self.assertEqual(found, "a/b/driver.cpp")
        self.assertEqual(candidates, [])

    def test_basename_fallback_ambiguous(self):
        result = CompareResult(
            [
                FileChange("added", "a/driver.cpp", None),
                FileChange("added", "b/driver.cpp", None),
            ],
            True,
        )
        found, candidates = resolve_rename(result, "src/driver.cpp")
        self.assertIsNone(found)
        self.assertEqual(len(candidates), 2)

    def test_nothing_found(self):
        self.assertEqual(resolve_rename(CompareResult([], False), "x.c"), (None, []))

    def test_head_tree_wins_over_comparison_files(self):
        result = CompareResult([FileChange("added", "wrong/a.c", None)], True)
        found, _ = resolve_rename(result, "old/a.c", ["src/a.c", "docs/readme.md"])
        self.assertEqual(found, "src/a.c")

    def test_stem_fallback_when_extension_changed(self):
        result = CompareResult([], True)
        found, _ = resolve_rename(
            result, "libretro.cpp", ["libretro.c", "libretro_cbs.h", "other.c"]
        )
        self.assertEqual(found, "libretro.c")

    def test_same_directory_breaks_a_stem_tie(self):
        found, _ = resolve_rename(
            CompareResult([], True),
            "libretro.cpp",
            ["libretro-common/include/libretro.h", "libretro.c"],
        )
        self.assertEqual(found, "libretro.c")

    def test_an_implementation_wins_over_a_header(self):
        found, _ = resolve_rename(
            CompareResult([], True), "src/a.cpp", ["src/a.c", "src/a.h"]
        )
        self.assertEqual(found, "src/a.c")

    def test_a_header_ref_picks_the_header(self):
        found, _ = resolve_rename(
            CompareResult([], True), "src/a.hpp", ["src/a.c", "src/a.h"]
        )
        self.assertEqual(found, "src/a.h")

    def test_two_implementations_stay_ambiguous(self):
        found, candidates = resolve_rename(
            CompareResult([], True), "src/a.cpp", ["one/a.c", "two/a.cc"]
        )
        self.assertIsNone(found)
        self.assertEqual(len(candidates), 2)

    def test_stem_fallback_ambiguous_across_directories(self):
        found, candidates = resolve_rename(
            CompareResult([], True), "src/driver.cpp", ["a/driver.c", "b/driver.cc"]
        )
        self.assertIsNone(found)
        self.assertEqual(len(candidates), 2)


class TestAnchorPart(unittest.TestCase):
    def test_anchored(self):
        fetch = make_fetch({(PIN, "a.c"): ["x", "hit"], (HEAD, "a.c"): ["x", "hit"]})
        result = anchor_part(
            RefPart("a.c", 2, 2), fetch, renamer(CompareResult([], False))
        )
        self.assertEqual(result.status, "ANCHORED")

    def test_path_only_ref_present_at_head(self):
        fetch = make_fetch({(PIN, "a.c"): ["x"], (HEAD, "a.c"): ["y"]})
        result = anchor_part(
            RefPart("a.c", None, None), fetch, renamer(CompareResult([], False))
        )
        self.assertEqual(result.status, "ANCHORED")

    def test_path_only_ref_absent_at_head(self):
        fetch = make_fetch({(PIN, "a.c"): ["x"]})
        result = anchor_part(
            RefPart("a.c", None, None), fetch, renamer(CompareResult([], False))
        )
        self.assertEqual(result.status, "GONE")

    def test_renamed_then_anchored_at_new_path(self):
        fetch = make_fetch(
            {(PIN, "old.c"): ["x", "hit"], (HEAD, "new.c"): ["x", "hit"]}
        )
        comparison = CompareResult([FileChange("renamed", "new.c", "old.c")], False)
        result = anchor_part(RefPart("old.c", 2, 2), fetch, renamer(comparison))
        self.assertEqual(result.status, "RENAMED")
        self.assertEqual(result.new_path, "new.c")
        self.assertEqual(result.start, 2)

    def test_bare_filename_resolves_at_both_revisions(self):
        fetch = make_fetch(
            {
                (PIN, "src/midi/mt32.cpp"): ["x", "hit"],
                (HEAD, "src/midi/mt32.cpp"): ["x", "hit"],
            }
        )
        comparison = CompareResult([], True)
        result = anchor_part(
            RefPart("mt32.cpp", 2, 2),
            fetch,
            renamer(comparison, ["src/midi/mt32.cpp"]),
        )
        self.assertEqual(result.status, "RENAMED")
        self.assertEqual(result.new_path, "src/midi/mt32.cpp")
        self.assertEqual(result.start, 2)

    def test_genuine_rename_still_reads_the_pin_at_the_old_path(self):
        fetch = make_fetch(
            {(PIN, "old.c"): ["x", "hit"], (HEAD, "new.c"): ["pad", "x", "hit"]}
        )
        comparison = CompareResult([FileChange("renamed", "new.c", "old.c")], False)
        result = anchor_part(RefPart("old.c", 2, 2), fetch, renamer(comparison))
        self.assertEqual(result.status, "RENAMED")
        self.assertEqual(result.start, 3)

    def test_gone_when_pin_file_missing(self):
        result = anchor_part(
            RefPart("a.c", 1, 1), make_fetch({}), renamer(CompareResult([], False))
        )
        self.assertEqual(result.status, "GONE")

    def test_ambiguous_rename_candidates_reported(self):
        fetch = make_fetch({(PIN, "src/d.cpp"): ["x"]})
        comparison = CompareResult(
            [
                FileChange("added", "a/d.cpp", None),
                FileChange("added", "b/d.cpp", None),
            ],
            True,
        )
        result = anchor_part(RefPart("src/d.cpp", 1, 1), fetch, renamer(comparison))
        self.assertEqual(result.status, "AMBIGUOUS")
        self.assertIsNotNone(result.reason)

    def test_rename_resolver_is_not_called_when_file_is_present(self):
        calls = []

        def getter(path):
            calls.append(path)
            return None, []

        fetch = make_fetch({(PIN, "a.c"): ["x"], (HEAD, "a.c"): ["x"]})
        anchor_part(RefPart("a.c", 1, 1), fetch, getter)
        self.assertEqual(calls, [])

    def test_gone_carries_a_reason(self):
        result = anchor_part(
            RefPart("a.c", 1, 1), make_fetch({}), renamer(CompareResult([], False))
        )
        self.assertIn("no rename found", result.reason)


class TestMovedStatus(unittest.TestCase):
    """A changed range whose subject is provably inside it can be followed."""

    def test_declared_value_inside_the_new_range_gives_moved(self):
        fetch = make_fetch({
            (PIN, "a.c"): ["ctx", 'load("bios.bin", 0x1000)', "tail"],
            (HEAD, "a.c"): ["pad", "ctx", 'load("bios.bin", 0x2000, flags)', "tail"],
        })
        result = anchor_part(
            RefPart("a.c", 2, 2, "a.c:2"),
            fetch,
            renamer(CompareResult([], False)),
            None,
            ["bios.bin"],
        )
        self.assertEqual(result.status, "MOVED")
        self.assertEqual(result.start, 3)
        self.assertIn("declared value present", result.reason)

    def test_value_absent_from_the_new_range_stays_changed(self):
        fetch = make_fetch({
            (PIN, "a.c"): ["x", 'load("bios.bin")'],
            (HEAD, "a.c"): ["x", 'load("other.bin")'],
        })
        result = anchor_part(
            RefPart("a.c", 2, 2, "a.c:2"),
            fetch,
            renamer(CompareResult([], False)),
            None,
            ["bios.bin"],
        )
        self.assertEqual(result.status, "CHANGED")

    def test_a_unique_occurrence_at_head_is_followed(self):
        fetch = make_fetch({
            (PIN, "a.c"): ["unique marker"],
            (HEAD, "a.c"): ["x"] * 40 + ['load("bios.bin")'] + ["y"] * 40,
        })
        result = anchor_part(
            RefPart("a.c", 1, 1, "a.c:1"),
            fetch,
            renamer(CompareResult([], False)),
            None,
            ["bios.bin"],
        )
        self.assertEqual(result.status, "MOVED")
        self.assertEqual(result.start, 41)
        self.assertIn("occurs once", result.reason)

    def test_several_occurrences_are_left_alone(self):
        fetch = make_fetch({
            (PIN, "a.c"): ["unique marker"],
            (HEAD, "a.c"): ['load("bios.bin")', 'reload("bios.bin")'],
        })
        result = anchor_part(
            RefPart("a.c", 1, 1, "a.c:1"),
            fetch,
            renamer(CompareResult([], False)),
            None,
            ["bios.bin"],
        )
        self.assertEqual(result.status, "GONE")

    def test_moved_is_mechanically_recalable(self):
        self.assertIn("MOVED", profile_sync.REBASE_STATUSES)
        self.assertNotIn("MOVED", profile_sync.REVIEW_STATUSES)

    def test_moved_ranks_below_ambiguous(self):
        self.assertEqual(worst_status(["MOVED", "AMBIGUOUS"]), "AMBIGUOUS")
        self.assertEqual(worst_status(["MOVED", "SHIFTED"]), "MOVED")


class TestSelectRepo(unittest.TestCase):
    def test_source_wins_over_upstream(self):
        repo = select_repo(
            {
                "source": "https://github.com/libretro/beetle-psx-libretro",
                "upstream": "https://mednafen.github.io/",
            }
        )
        self.assertEqual(repo.name, "beetle-psx-libretro")

    def test_falls_back_to_upstream(self):
        repo = select_repo(
            {
                "source": "https://www.mamedev.org/",
                "upstream": "https://github.com/mamedev/mame",
            }
        )
        self.assertEqual(repo.name, "mame")

    def test_none_when_no_supported_host(self):
        self.assertIsNone(select_repo({"source": "https://www.6809.org.uk/"}))

    def test_source_keyed_by_mode_without_upstream(self):
        repo = select_repo(
            {
                "source": {
                    "standalone": "https://github.com/UZDoom/UZDoom",
                    "libretro": "https://github.com/libretro/uzdoom",
                },
            }
        )
        self.assertEqual(repo.name, "UZDoom")


class TestBuildReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.files: dict[tuple[str, str], list[str]] = {}
        self._orig = (
            profile_sync.upstream.fetch_file,
            profile_sync.upstream.resolve_head,
            profile_sync.upstream.resolve_commit_at,
            profile_sync.upstream.compare,
            profile_sync.upstream.list_tree,
            profile_sync.upstream.list_tags,
            profile_sync.upstream.resolve_tag_commit,
            profile_sync.upstream.tag_commit,
            profile_sync.upstream._http_json,
            profile_sync.upstream._http_text,
            profile_sync.upstream.list_gitlinks,
            profile_sync.upstream.current_slug,
            profile_sync.upstream.fork_base,
            profile_sync.upstream.ancestry,
        )
        # Pin and tip are unrelated shas in these fixtures: no ancestry.
        profile_sync.upstream.ancestry = lambda *a, **k: None
        self.fork_bases: dict[str, str] = {}
        profile_sync.upstream.fork_base = (
            lambda repo, sha, fork, fork_sha, cache_dir, offline=False:
            self.fork_bases.get(fork_sha)
        )
        self.current_slugs: dict[str, str] = {}
        profile_sync.upstream.current_slug = (
            lambda repo, cache_dir, offline=False: self.current_slugs.get(
                repo.slug, repo.slug
            )
        )
        self.tags: list[str] = []
        self.gitlinks: dict[str, dict[str, str]] = {}
        profile_sync.upstream.list_gitlinks = (
            lambda repo, sha, cache_dir, offline=False: self.gitlinks.get(sha, {})
        )
        self.tag_commits: dict[str, str] = {}
        # Any code path reaching the HTTP layer is a leak, not a slow test.
        def _no_network(url):
            raise AssertionError(f"test reached the network: {url}")

        profile_sync.upstream._http_json = _no_network
        profile_sync.upstream._http_text = _no_network
        profile_sync.upstream.list_tags = (
            lambda repo, cache, offline=False: self.tags
        )
        profile_sync.upstream.resolve_tag_commit = (
            lambda repo, tag, cache, offline=False: self.tag_commits.get(tag)
        )
        profile_sync.upstream.tag_commit = (
            lambda repo, tag, cache, offline=False: self.tag_commits.get(tag)
        )
        profile_sync.upstream.list_tree = (
            lambda repo, sha, cache_dir, offline=False: (
                sorted({path for _, path in self.files}), False
            )
        )
        profile_sync.upstream.fetch_file = (
            lambda repo, sha, path, cache_dir, offline=False: self.files.get(
                (sha, path)
            )
        )
        profile_sync.upstream.resolve_head = (
            lambda repo, cache_dir, offline=False, branch=None, fresh=False: "headsha"
        )
        profile_sync.upstream.resolve_commit_at = (
            lambda repo, date, cache_dir, offline=False, branch=None: "pinsha"
        )
        profile_sync.upstream.compare = (
            lambda repo, base, head, cache_dir, offline=False: CompareResult([], False)
        )

    def tearDown(self):
        (
            profile_sync.upstream.fetch_file,
            profile_sync.upstream.resolve_head,
            profile_sync.upstream.resolve_commit_at,
            profile_sync.upstream.compare,
            profile_sync.upstream.list_tree,
            profile_sync.upstream.list_tags,
            profile_sync.upstream.resolve_tag_commit,
            profile_sync.upstream.tag_commit,
            profile_sync.upstream._http_json,
            profile_sync.upstream._http_text,
            profile_sync.upstream.list_gitlinks,
            profile_sync.upstream.current_slug,
            profile_sync.upstream.fork_base,
            profile_sync.upstream.ancestry,
        ) = self._orig
        self.tmp.cleanup()

    def _profile(self, refs):
        return {
            "emulator": "Test",
            "source": "https://github.com/o/n",
            "profiled_date": "2026-03-29",
            "files": [
                {"name": f"f{i}.bin", "source_ref": ref}
                for i, ref in enumerate(refs)
            ],
        }

    def test_a_renamed_repository_is_review_work(self):
        """AloysHF/NicaiEmu answers as AloysHF/CoolbarEmu: the redirect was
        followed in silence and the profile read as up to date."""
        self.files[("pinsha", "a.c")] = ["x", "y"]
        self.files[("headsha", "a.c")] = ["x", "y"]
        self.current_slugs["o/n"] = "o/renamed"
        report = build_report("test", self._profile(["a.c:2"]), self.dir)
        self.assertEqual(len(report.moved_repos), 1)
        self.assertIn("o/renamed", report.moved_repos[0])
        self.assertGreaterEqual(report.needs_review(), 1)
        self.assertIn("moved repository", profile_sync.format_report(report))

    def test_a_repository_under_its_own_name_is_not_moved(self):
        self.files[("pinsha", "a.c")] = ["x", "y"]
        self.files[("headsha", "a.c")] = ["x", "y"]
        self.current_slugs["o/n"] = "O/N"
        report = build_report("test", self._profile(["a.c:2"]), self.dir)
        self.assertEqual(report.moved_repos, [])

    def test_a_refusing_forge_reads_as_unread_not_gone(self):
        """git.eden-emu.dev answers 403 to scripts: the muted repository's
        citations read "absent at HEAD" for files that exist."""
        def refuse(repo, sha, path, cache_dir, offline=False):
            raise profile_sync.upstream.UpstreamError(f"{path}: HTTP 403")

        profile_sync.upstream.fetch_file = refuse
        with contextlib.redirect_stderr(io.StringIO()):
            report = build_report("test", self._profile(["a.c:2"]), self.dir)
        statuses = [p.status for e in report.entries for p in e.parts]
        self.assertEqual(statuses, ["UNCHECKED"])
        self.assertIn("refused", report.entries[0].parts[0].reason)

    def test_a_truncated_head_tree_is_not_an_absence(self):
        """git.eden-emu.dev truncates the HEAD tree: fs_paths.h, cited bare,
        was reported GONE though it lives under src/common/fs/."""
        self.files[("pinsha", "fs_paths.h")] = ["x", "hit"]
        profile_sync.upstream.list_tree = (
            lambda repo, sha, cache_dir, offline=False: (["other.c"], True)
        )
        with contextlib.redirect_stderr(io.StringIO()):
            report = build_report("test", self._profile(["fs_paths.h:2"]), self.dir)
        part = report.entries[0].parts[0]
        self.assertEqual(part.status, "AMBIGUOUS")
        self.assertIn("truncated", part.reason)

    def test_counts_by_status(self):
        self.files[("pinsha", "a.c")] = ["x", "hit", "y"]
        self.files[("headsha", "a.c")] = ["pad", "x", "hit", "y"]
        report = build_report("test", self._profile(["a.c:2"]), self.dir)
        self.assertEqual(report.pin, "pinsha")
        self.assertEqual(report.head, "headsha")
        self.assertEqual(report.host, "github.com")
        self.assertEqual(report.counts["SHIFTED"], 1)

    def test_entry_takes_worst_part_status(self):
        self.files[("pinsha", "a.c")] = ["x", "hit"]
        self.files[("headsha", "a.c")] = ["x", "hit"]
        self.files[("pinsha", "b.c")] = ["gone marker"]
        self.files[("headsha", "b.c")] = ["z"] * 100
        report = build_report("test", self._profile(["a.c:2, b.c:1"]), self.dir)
        self.assertEqual(report.entries[0].status, "GONE")

    def test_existing_source_commit_is_used(self):
        profile = self._profile(["a.c:1"])
        profile["source_commit"] = "pinned"
        self.files[("pinned", "a.c")] = ["x"]
        self.files[("headsha", "a.c")] = ["x"]
        report = build_report("test", profile, self.dir)
        self.assertEqual(report.pin, "pinned")
        self.assertEqual(report.pin_origin, "source_commit")

    def test_unsupported_host_is_skipped_with_reason(self):
        report = build_report(
            "test", {"emulator": "T", "source": "https://www.6809.org.uk/"}, self.dir
        )
        self.assertIn("unsupported host", report.skipped)
        self.assertEqual(report.unread, ["https://www.6809.org.uk/"])

    def test_unsupported_source_is_named_when_upstream_answers(self):
        profile = self._profile(["a.c:1"])
        profile["source"] = "https://forge.example.invalid/o/n"
        profile["upstream"] = "https://github.com/o/n"
        self.files[("pinsha", "a.c")] = ["x"]
        self.files[("headsha", "a.c")] = ["x"]
        report = build_report("test", profile, self.dir)
        self.assertIsNone(report.skipped)
        self.assertEqual(report.unread, ["https://forge.example.invalid/o/n"])
        self.assertIn(
            "not read (unsupported host): https://forge.example.invalid/o/n",
            format_report(report),
        )

    def test_profile_without_refs_is_reported_not_empty(self):
        profile = {
            "emulator": "T",
            "source": "https://github.com/o/n",
            "profiled_date": "2026-03-29",
            "files": [{"name": "a.bin"}],
        }
        report = build_report("test", profile, self.dir)
        self.assertEqual(report.entries, [])
        self.assertEqual(report.skipped, "no source_ref")

    def test_profile_without_refs_still_resolves_its_pin(self):
        profile = {
            "emulator": "T",
            "source": "https://github.com/o/n",
            "profiled_date": "2026-03-29",
            "files": [{"name": "a.bin"}],
        }
        report = build_report("test", profile, self.dir)
        self.assertEqual(report.pin, "pinsha")
        self.assertEqual(report.head, "headsha")
        self.assertEqual(report.needs_review(), 0)

    def _two_repo_profile(self, refs):
        profile = self._profile(refs)
        profile["upstream"] = "https://gitlab.com/g/p"
        return profile

    def test_path_absent_from_source_resolves_against_upstream(self):
        self.files[("pinsha", "src/a.c")] = ["x", "hit"]
        self.files[("headsha", "src/a.c")] = ["x", "hit"]
        report = build_report(
            "test", self._two_repo_profile(["src/a.c:2"]), self.dir
        )
        self.assertEqual(report.entries[0].status, "ANCHORED")
        self.assertEqual(report.repos, ["o/n", "g/p"])

    def test_part_records_the_repository_that_carries_it(self):
        self.files[("pinsha", "only_here.c")] = ["x", "hit"]
        self.files[("headsha", "only_here.c")] = ["x", "hit"]
        report = build_report(
            "test", self._two_repo_profile(["only_here.c:2"]), self.dir
        )
        part = report.entries[0].parts[0]
        self.assertIsNotNone(part.head_url)

    def test_single_repo_profile_lists_one_slug(self):
        self.files[("pinsha", "a.c")] = ["x"]
        self.files[("headsha", "a.c")] = ["x"]
        report = build_report("test", self._profile(["a.c:1"]), self.dir)
        self.assertEqual(report.repos, ["o/n"])

    def test_upstream_commit_pins_the_second_repository(self):
        profile = self._two_repo_profile(["a.c:1"])
        profile["upstream_commit"] = "upinned"
        self.files[("pinsha", "a.c")] = ["x"]
        self.files[("headsha", "a.c")] = ["x"]
        report = build_report("test", profile, self.dir)
        self.assertEqual(report.pin, "pinsha")
        self.assertEqual(report.repos, ["o/n", "g/p"])

    def test_repo_name_prefix_is_stripped_as_a_last_resort(self):
        self.files[("pinsha", "Source/HW_.cpp")] = ["x", "hit"]
        self.files[("headsha", "Source/HW_.cpp")] = ["x", "hit"]
        report = build_report(
            "test", self._profile(["n/Source/HW_.cpp:2"]), self.dir
        )
        part = report.entries[0].parts[0]
        self.assertEqual(part.status, "RENAMED")
        self.assertEqual(part.new_path, "Source/HW_.cpp")

    def test_declared_path_wins_over_the_stripped_one(self):
        self.files[("pinsha", "n/a.c")] = ["x", "declared"]
        self.files[("headsha", "n/a.c")] = ["x", "declared"]
        self.files[("pinsha", "a.c")] = ["x", "stripped"]
        self.files[("headsha", "a.c")] = ["x", "stripped"]
        report = build_report("test", self._profile(["n/a.c:2"]), self.dir)
        part = report.entries[0].parts[0]
        self.assertEqual(part.status, "ANCHORED")
        self.assertIsNone(part.new_path)

    def test_unknown_prefix_resolves_by_basename_not_by_stripping(self):
        self.files[("pinsha", "a.c")] = ["x", "hit"]
        self.files[("headsha", "a.c")] = ["x", "hit"]
        report = build_report("test", self._profile(["other/a.c:2"]), self.dir)
        part = report.entries[0].parts[0]
        self.assertEqual(part.status, "RENAMED")
        self.assertEqual(part.new_path, "a.c")

    def test_basename_absent_everywhere_stays_gone(self):
        self.files[("pinsha", "a.c")] = ["x", "hit"]
        self.files[("headsha", "a.c")] = ["x", "hit"]
        report = build_report("test", self._profile(["other/absent.c:2"]), self.dir)
        self.assertEqual(report.entries[0].parts[0].status, "GONE")

    def test_rename_is_searched_in_every_declared_repository(self):
        self.files[("pinsha", "deep/src/stv.c")] = ["x", "hit"]
        self.files[("headsha", "deep/src/stv.c")] = ["x", "hit"]
        report = build_report(
            "test", self._two_repo_profile(["ctrl/src/stv.c:2"]), self.dir
        )
        part = report.entries[0].parts[0]
        self.assertEqual(part.status, "RENAMED")
        self.assertEqual(part.new_path, "deep/src/stv.c")

    def _versioned(self, version):
        profile = self._profile(["a.c:2"])
        profile["core_version"] = version
        return profile

    def test_a_pin_equal_to_head_is_checked_for_self_consistency(self):
        # The value sits on another line, so the ref demonstrably points wrong.
        self.files[("headsha", "a.c")] = [
            "x", "unrelated", "", "", "", "", 'rom("deadbeef")',
        ]
        profile = self._profile(["a.c:2"])
        profile["source_commit"] = "headsha"
        profile["files"][0]["crc32"] = "deadbeef"
        report = build_report("test", profile, self.dir)
        self.assertEqual(report.entries[0].status, "MOVED")

    def test_a_value_absent_from_the_whole_file_is_not_held_against_the_ref(self):
        # A ref citing loading logic never spells the value out, so its absence
        # is not evidence that the ref is stale.
        self.files[("headsha", "a.c")] = ["x", "load_bios(path);"]
        profile = self._profile(["a.c:2"])
        profile["source_commit"] = "headsha"
        profile["files"][0]["crc32"] = "deadbeef"
        report = build_report("test", profile, self.dir)
        self.assertEqual(report.entries[0].status, "ANCHORED")

    def test_a_pin_equal_to_head_accepts_a_ref_on_its_value(self):
        self.files[("headsha", "a.c")] = ["x", 'rom("deadbeef")']
        profile = self._profile(["a.c:2"])
        profile["source_commit"] = "headsha"
        profile["files"][0]["crc32"] = "deadbeef"
        report = build_report("test", profile, self.dir)
        self.assertEqual(report.entries[0].status, "ANCHORED")

    def test_the_repository_with_a_subject_owns_a_shared_path(self):
        # A port and its upstream can both carry a path, but only one holds the
        # cited subject, and a blank line is never a citation.
        self.files[("portpin", "src/a.cpp")] = ["x", "", "y"]
        self.files[("uppin", "src/a.cpp")] = ["x", "GAME(1985, bubsys", "y"]
        self.files[("headsha", "src/a.cpp")] = ["x", "GAME(1985, bubsys", "y"]
        profile = {
            "emulator": "MAME",
            "source": "https://github.com/libretro/mame",
            "upstream": "https://github.com/mamedev/mame",
            "source_commit": "portpin",
            "upstream_commit": "uppin",
            "files": [{"name": "bubsys.zip", "source_ref": "src/a.cpp:2"}],
        }
        report = build_report("mame", profile, self.dir)
        self.assertEqual(report.entries[0].status, "ANCHORED")

    def test_a_blank_first_line_does_not_hand_the_ref_to_the_upstream(self):
        """lrps2's VMManager.cpp:418-431 opens on a blank line in the fork it
        was written for. Scored 0, the upstream (418 unrelated, not blank)
        took the ref and its code decided the rebase target."""
        self.files[("portpin", "src/a.cpp")] = ["x", "", "load_patches();", "y"]
        self.files[("porthead", "src/a.cpp")] = ["", "load_patches();", "y", "w"]
        self.files[("uppin", "src/a.cpp")] = ["x", "discord_init();", "pine();", "z"]
        self.files[("uphead", "src/a.cpp")] = ["a", "b", "x", "discord_init();", "pine();", "z"]
        heads = {"libretro/ps2": "porthead", "PCSX2/pcsx2": "uphead"}
        profile_sync.upstream.resolve_head = (
            lambda repo, cache, offline=False, branch=None: heads[repo.slug]
        )
        profile = {
            "emulator": "LRPS2",
            "source": "https://github.com/libretro/ps2",
            "upstream": "https://github.com/PCSX2/pcsx2",
            "source_commit": "portpin",
            "upstream_commit": "uppin",
            "files": [{"name": "cheats_ni.zip", "source_ref": "src/a.cpp:2-3"}],
        }
        report = profile_sync.report_to_dict(build_report("lrps2", profile, self.dir))
        part = report["entries"][0]["parts"][0]
        # Moved by -1 in the fork, the block's real target. The upstream's
        # +2 shift of unrelated code is not it.
        self.assertIsNone(part["repo"])
        self.assertEqual((part["status"], part["start"]), ("SHIFTED", 1))

    def test_a_declared_branch_is_followed_for_head(self):
        seen = {}

        def _head(repo, cache_dir, offline=False, branch=None):
            seen[repo.slug] = branch
            return "headsha"

        profile_sync.upstream.resolve_head = _head
        profile = self._profile(["a.c:1"])
        profile["upstream"] = "https://github.com/o/up"
        profile["source_branch"] = "libretro"
        build_report("test", profile, self.dir)
        # Only the port carries the branch. The upstream keeps its own tip.
        self.assertEqual(seen["o/n"], "libretro")
        self.assertIsNone(seen["o/up"])

    def test_the_subject_beats_a_merely_non_blank_line(self):
        # A fork whose tree is offset holds a real but unrelated statement at
        # the cited line. The repository carrying the subject wins.
        self.files[("portpin", "src/a.cpp")] = ["x", "GAME(1997, drgw2100c", "y"]
        self.files[("uppin", "src/a.cpp")] = ["x", "GAME(1997, pgm,", "y"]
        self.files[("headsha", "src/a.cpp")] = ["x", "GAME(1997, pgm,", "y"]
        profile = {
            "emulator": "MAME",
            "source": "https://github.com/libretro/mame",
            "upstream": "https://github.com/mamedev/mame",
            "source_commit": "portpin",
            "upstream_commit": "uppin",
            "files": [{"name": "pgm.zip", "source_ref": "src/a.cpp:2"}],
        }
        report = build_report("mame", profile, self.dir)
        self.assertEqual(report.entries[0].status, "ANCHORED")

    def test_a_ref_is_broken_only_when_it_fails_everywhere(self):
        # Both repositories carry the path with the same delimited token on the
        # cited line, so no single attribution is right. The ref anchors in one
        # of them and that settles it.
        self.files[("portpin", "src/a.cpp")] = ["x", "GAME(1997, drgw, pgm,", "y"]
        self.files[("porthead", "src/a.cpp")] = ["x", "", "y"]
        self.files[("uppin", "src/a.cpp")] = ["x", "GAME(1997, pgm, 0, pgm,", "y"]
        self.files[("uphead", "src/a.cpp")] = ["x", "GAME(1997, pgm, 0, pgm,", "y"]

        heads = {"o/port": "porthead", "o/up": "uphead"}
        profile_sync.upstream.resolve_head = (
            lambda repo, cache, offline=False, branch=None: heads[repo.slug]
        )
        profile = {
            "emulator": "MAME",
            "source": "https://github.com/o/port",
            "upstream": "https://github.com/o/up",
            "source_commit": "portpin",
            "upstream_commit": "uppin",
            "files": [{"name": "pgm.zip", "source_ref": "src/a.cpp:2"}],
        }
        report = build_report("mame", profile, self.dir)
        self.assertEqual(report.entries[0].status, "ANCHORED")

    def test_self_check_reads_every_repository_before_calling_a_range_gone(self):
        # hatari: the port's src/paths.c runs 365 lines, the upstream's 345,
        # and a source_ref attributes the path to the upstream. With both on
        # HEAD, prose citing the port's 305-356 was read in the upstream file
        # alone and reported beyond its end.
        self.files[("porthead", "src/p.c")] = [f"port {i}" for i in range(8)]
        self.files[("uphead", "src/p.c")] = ["a", "load x.bin", "c", "d", "e"]
        heads = {"o/port": "porthead", "o/up": "uphead"}
        profile_sync.upstream.resolve_head = (
            lambda repo, cache, offline=False, branch=None: heads[repo.slug]
        )
        profile = {
            "emulator": "Port",
            "source": "https://github.com/o/port",
            "upstream": "https://github.com/o/up",
            "source_commit": "porthead",
            "upstream_commit": "uphead",
            "notes": "The port reads its own file (src/p.c:4-7).",
            "files": [{"name": "x.bin", "source_ref": "upstream src/p.c:2"}],
        }
        report = build_report("port", profile, self.dir)
        prose = next(e for e in report.entries if e.kind == "prose")
        self.assertNotEqual(prose.parts[0].status, "GONE")
        self.assertEqual(report.needs_review(), 0)

    def test_an_emptied_upstream_does_not_hide_the_ports_change(self):
        # dosbox-pure moved to Codeberg and emptied its GitHub repository.
        # The rename search run for that repository picked up the port's
        # .info, .sln and .vcxproj sharing the file's root, and that
        # AMBIGUOUS outranked the port's own CHANGED.
        pin_lines = ["a", "scan the system folder", "for ROM.BIN", "c"]
        self.files[("portpin", "core.cpp")] = list(pin_lines)
        self.files[("porthead", "core.cpp")] = ["a", "scan every folder", "for nothing", "c"]
        self.files[("uppin", "core.cpp")] = list(pin_lines)
        for name in ("core.info", "core.sln", "core.vcxproj"):
            self.files[("porthead", name)] = ["x"]
        heads = {"o/port": "porthead", "o/up": "uphead"}
        profile_sync.upstream.resolve_head = (
            lambda repo, cache, offline=False, branch=None: heads[repo.slug]
        )
        profile_sync.upstream.list_tree = (
            lambda repo, sha, cache_dir, offline=False: (
                sorted(path for revision, path in self.files if revision == sha), False
            )
        )
        profile = {
            "emulator": "Pure",
            "source": "https://github.com/o/port",
            "upstream": "https://github.com/o/up",
            "source_commit": "portpin",
            "upstream_commit": "uppin",
            "notes": "The scan accepts it (core.cpp:2-3).",
            "files": [],
        }
        report = build_report("pure", profile, self.dir)
        self.assertEqual([e.status for e in report.entries], ["CHANGED"])

    def test_a_tie_reports_the_owning_repository(self):
        # Both repositories call the ref GONE. mamedev, which the citation is
        # attributed to, says why: the ref was written against HEAD. The port
        # only says the range runs past its file.
        self.files[("portpin", "src/stv.cpp")] = ["x"]
        self.files[("porthead", "src/stv.cpp")] = ["x"]
        self.files[("uppin", "src/stv.cpp")] = ["x"]
        self.files[("uphead", "src/stv.cpp")] = ["x", "y", "GAME( 1996, stvbios,"]
        heads = {"o/port": "porthead", "o/up": "uphead"}
        profile_sync.upstream.resolve_head = (
            lambda repo, cache, offline=False, branch=None: heads[repo.slug]
        )
        profile = {
            "emulator": "MAME",
            "source": "https://github.com/o/port",
            "upstream": "https://github.com/o/up",
            "source_commit": "portpin",
            "upstream_commit": "uppin",
            "files": [{"name": "stvbios.zip", "source_ref": "src/stv.cpp:3"}],
        }
        report = build_report("mame", profile, self.dir)
        entry = report.entries[0]
        self.assertEqual(entry.status, "GONE")
        self.assertIn("written against HEAD", entry.parts[0].reason)

    def test_a_pin_off_the_tracked_history_is_reported(self):
        # advancemame's master was rewritten: its pin still answered, from
        # the forge's orphaned objects, and every ref read ANCHORED.
        self.files[("pinsha", "a.c")] = ["x", "hit"]
        self.files[("headsha", "a.c")] = ["x", "hit"]
        profile_sync.upstream.compare = (
            lambda repo, base, head, cache_dir, offline=False: CompareResult([], False, True)
        )
        report = build_report("test", self._profile(["a.c:2"]), self.dir)
        self.assertEqual(len(report.orphaned), 1)
        self.assertGreater(report.needs_review(), 0)
        self.assertIn("orphaned pin", profile_sync.format_report(report))

    def test_a_frozen_tag_is_off_the_branch_on_purpose(self):
        self.files[("pinsha", "a.c")] = ["x", "hit"]
        self.files[("headsha", "a.c")] = ["x", "hit"]
        self.tag_commits = {"v1.6.0": "pinsha"}
        profile_sync.upstream.compare = (
            lambda repo, base, head, cache_dir, offline=False: CompareResult([], False, True)
        )
        report = build_report("test", self._versioned("1.6.0"), self.dir)
        self.assertEqual(report.orphaned, [])

    def test_pin_on_the_declared_version_tag_is_flagged(self):
        self.files[("pinsha", "a.c")] = ["x", "hit"]
        self.files[("headsha", "a.c")] = ["x", "hit"]
        self.tag_commits = {"v1.6.0": "pinsha"}
        report = build_report("test", self._versioned("1.6.0"), self.dir)
        self.assertEqual(report.pinned_tag, "v1.6.0")

    def test_a_bare_version_spelling_is_tried(self):
        self.files[("pinsha", "a.c")] = ["x", "hit"]
        self.files[("headsha", "a.c")] = ["x", "hit"]
        self.tag_commits = {"0.78": "pinsha"}
        report = build_report("test", self._versioned("v0.78"), self.dir)
        self.assertEqual(report.pinned_tag, "0.78")

    def test_an_upstream_on_its_release_tag_does_not_freeze_the_port(self):
        """GroovyMAME declares 0.289 and its upstream_commit is the mame0289
        tag. Reading that as a frozen profile stopped every comparison and
        bump of the port, which keeps moving. The upstream is read at its tag,
        the port against its HEAD."""
        self.files[("portpin", "src/p.c")] = ["x", "load p.bin", "y"]
        self.files[("porthead", "src/p.c")] = ["x", "load p.bin", "y"]
        self.files[("uppin", "src/u.c")] = ["x", "ROM_LOAD(u.bin)", "y"]
        self.files[("uphead", "src/u.c")] = ["x", "", "", "", "y"]
        heads = {"o/port": "porthead", "o/up": "uphead"}
        profile_sync.upstream.resolve_head = (
            lambda repo, cache, offline=False, branch=None: heads[repo.slug]
        )
        # A tag off the tracked branch is not an orphaned pin.
        profile_sync.upstream.compare = (
            lambda repo, base, head, cache_dir, offline=False: CompareResult(
                [], False, repo.slug == "o/up"
            )
        )
        self.tag_commits = {"0.289": "uppin"}
        profile = {
            "emulator": "Port",
            "source": "https://github.com/o/port",
            "upstream": "https://github.com/o/up",
            "source_commit": "portpin",
            "upstream_commit": "uppin",
            "core_version": "0.289",
            "files": [
                {"name": "p.bin", "source_ref": "source src/p.c:2"},
                {"name": "u.bin", "source_ref": "upstream src/u.c:2"},
            ],
        }
        report = build_report("port", profile, self.dir)
        self.assertIsNone(report.pinned_tag)
        self.assertEqual(report.upstream_tag, "0.289")
        self.assertEqual(report.orphaned, [])
        self.assertEqual(
            [entry.status for entry in report.entries], ["ANCHORED", "ANCHORED"]
        )
        self.assertIn(
            "upstream pinned to tag 0.289", profile_sync.format_report(report)
        )

    def test_a_tag_pointing_elsewhere_is_not_flagged(self):
        self.files[("pinsha", "a.c")] = ["x", "hit"]
        self.files[("headsha", "a.c")] = ["x", "hit"]
        self.tag_commits = {"v1.6.0": "somethingelse"}
        report = build_report("test", self._versioned("1.6.0"), self.dir)
        self.assertIsNone(report.pinned_tag)

    def test_prose_version_is_not_looked_up(self):
        self.assertEqual(profile_sync.version_tag_candidates("SVN (2015 snapshot)"), [])
        self.assertEqual(profile_sync.version_tag_candidates(""), [])

    def test_pin_equal_to_head_is_never_flagged(self):
        self.files[("pinsha", "a.c")] = ["x", "hit"]
        self.files[("headsha", "a.c")] = ["x", "hit"]
        self.tag_commits = {"v1.6.0": "pinsha"}
        profile = self._versioned("1.6.0")
        profile["source_commit"] = "headsha"
        report = build_report("test", profile, self.dir)
        self.assertIsNone(report.pinned_tag)

    def test_missing_date_and_commit_is_skipped(self):
        report = build_report(
            "test",
            {
                "emulator": "T",
                "source": "https://github.com/o/n",
                "files": [{"name": "a", "source_ref": "a.c:1"}],
            },
            self.dir,
        )
        self.assertIn("no source_commit", report.skipped)


def _sample_report():
    shifted = PartResult(RefPart("a.c", 2, 4), "SHIFTED", None, 10, 12, [])
    changed = PartResult(RefPart("b.c", 5, 5), "CHANGED", None, 7, 7, [])
    return ProfileReport(
        name="demo",
        repo="o/n",
        host="github.com",
        pin="pinsha0000",
        pin_origin="profiled_date 2026-03-29",
        head="headsha000",
        entries=[
            EntryReport("f0.bin", "a.c:2-4", "SHIFTED", [shifted]),
            EntryReport("f1.bin", "b.c:5", "CHANGED", [changed]),
        ],
        counts={"SHIFTED": 1, "CHANGED": 1},
    )


class TestDeclaredDeadUpstream(TestBuildReport):
    """A forge that is gone can be stated, which closes the question.

    yuzu and suyu were withdrawn, citron's domain was taken by a squatter.
    Leaving those profiles to fail every pass reports an open problem where
    there is a settled fact. Declaring it records the death, and the guard is
    that a declaration must stop being true the moment the forge answers.
    """

    def _profile_with(self, note):
        profile = self._profile(["a.c:1"])
        profile["upstream_gone"] = note
        return profile

    def test_a_declared_death_is_reported_as_declared(self):
        def boom(*a, **k):
            raise profile_sync.upstream.GoneError("https://h/x: HTTP 451")

        profile_sync.upstream.resolve_head = boom
        report = build_report(
            "test", self._profile_with("withdrawn, HTTP 451"), self.dir
        )
        self.assertIsNotNone(report.skipped)
        self.assertIn("declared", report.skipped)
        self.assertIn("withdrawn, HTTP 451", report.skipped)
        self.assertEqual(report.needs_review(), 0)

    def test_any_refusal_of_a_declared_dead_forge_agrees(self):
        # citron's taken domain now resolves and fails TLS.
        def tls(*a, **k):
            raise profile_sync.upstream.UpstreamError("TLSV1_UNRECOGNIZED_NAME")

        profile_sync.upstream.resolve_head = tls
        report = build_report("test", self._profile_with("domain taken"), self.dir)
        self.assertIn("declared", report.skipped)

    def test_a_declaration_the_forge_contradicts_is_reported(self):
        """The forge answered: the declaration has outlived its truth."""
        self.files[("pinsha", "a.c")] = ["hit"]
        self.files[("headsha", "a.c")] = ["hit"]
        report = build_report(
            "test", self._profile_with("withdrawn, HTTP 451"), self.dir
        )
        self.assertIsNotNone(report.skipped)
        self.assertIn("answers", report.skipped)

    def test_an_undeclared_death_is_unchanged(self):
        def boom(*a, **k):
            raise profile_sync.upstream.GoneError("https://h/x: HTTP 451")

        profile_sync.upstream.resolve_head = boom
        with self.assertRaises(profile_sync.upstream.GoneError):
            build_report("test", self._profile(["a.c:1"]), self.dir)


class TestRefsAheadOfTheirPin(TestBuildReport):
    """Say when a ref describes HEAD and the pin still names an older tree.

    Reprofiling against HEAD and forgetting to advance source_commit leaves
    the profile describing two revisions at once. The symptom was "pin
    revision missing", which reads as code that vanished and sends the
    reader hunting for a move that never happened. The cause is the pin.
    """

    def test_present_at_head_and_absent_at_the_pin_names_the_pin(self):
        self.files[("headsha", "a.c")] = ["x", "the cited line", "y"]
        report = build_report("test", self._profile(["a.c:2"]), self.dir)
        part = report.entries[0].parts[0]
        self.assertEqual(part.status, "GONE")
        self.assertEqual(
            part.reason, "written against HEAD, pin names an older revision"
        )

    def test_a_range_past_the_pin_file_but_inside_head_names_the_pin(self):
        """nestopia's shape: the file is there, the line is not yet.

        Palette and database loads sat at 2041 and 2063, which is where HEAD
        carries them. The pinned revision was four hundred lines shorter.
        """
        self.files[("pinsha", "a.c")] = ["x"] * 10
        self.files[("headsha", "a.c")] = ["x"] * 40 + ["the cited line"] + ["y"]
        report = build_report("test", self._profile(["a.c:41"]), self.dir)
        part = report.entries[0].parts[0]
        self.assertEqual(part.status, "GONE")
        self.assertEqual(
            part.reason, "written against HEAD, pin names an older revision"
        )

    def test_a_range_beyond_head_is_still_just_missing(self):
        """Not every pin miss is a stale pin, only one that fits HEAD."""
        self.files[("headsha", "a.c")] = ["x"]
        report = build_report("test", self._profile(["a.c:40"]), self.dir)
        part = report.entries[0].parts[0]
        self.assertEqual(part.status, "GONE")
        self.assertNotEqual(
            part.reason, "written against HEAD, pin names an older revision"
        )

    def test_a_file_missing_from_both_is_unchanged(self):
        report = build_report("test", self._profile(["ghost.c:2"]), self.dir)
        self.assertEqual(report.entries[0].parts[0].status, "GONE")


class TestBareNameResolvedAtThePin(TestBuildReport):
    """A bare filename belongs to the revision the ref was written against.

    Resolution searched the HEAD tree only, so a file that moved between the
    pin and HEAD was resolved to its HEAD path and then read at the pin,
    where that path does not exist yet: the ref reported GONE for the one
    reason it should never report, its own success at HEAD. linapple cites
    Memory.cpp, src/Memory.cpp at its pin and src/apple2/Memory.cpp today.
    """

    def _tree_per_revision(self):
        def list_tree(repo, sha, cache_dir, offline=False):
            return sorted({path for rev, path in self.files if rev == sha}), False

        profile_sync.upstream.list_tree = list_tree

    def test_a_bare_name_follows_the_file_that_moved_after_the_pin(self):
        self._tree_per_revision()
        self.files[("pinsha", "src/Memory.cpp")] = ["x", "the cited line", "y"]
        self.files[("headsha", "src/apple2/Memory.cpp")] = [
            "pad", "x", "the cited line", "y",
        ]
        report = build_report("test", self._profile(["Memory.cpp:2"]), self.dir)
        part = report.entries[0].parts[0]
        self.assertNotEqual(
            part.status, "GONE",
            "the bare name resolved at HEAD and was then read at the pin",
        )
        self.assertEqual(part.new_path, "src/apple2/Memory.cpp")

    def test_a_bare_name_present_at_both_revisions_resolves_once(self):
        """A resolved bare name reads RENAMED so the recale writes the path."""
        self._tree_per_revision()
        self.files[("pinsha", "src/New.cpp")] = ["x", "the cited line"]
        self.files[("headsha", "src/New.cpp")] = ["x", "the cited line"]
        report = build_report("test", self._profile(["New.cpp:2"]), self.dir)
        part = report.entries[0].parts[0]
        self.assertEqual(part.status, "RENAMED")
        self.assertEqual(part.new_path, "src/New.cpp")


class TestFormatReport(unittest.TestCase):
    def test_header_shows_both_revisions(self):
        text = format_report(_sample_report())
        self.assertIn("pinsha0", text)
        self.assertIn("headsha", text)

    def test_shifted_shows_new_range(self):
        self.assertIn("10-12", format_report(_sample_report()))

    def test_anchored_does_not_repeat_its_range(self):
        part = PartResult(RefPart("a.c", 2, 4), "ANCHORED", None, 2, 4, [])
        report = ProfileReport(
            name="d", repo="o/n", host="github.com", pin="p" * 10, head="h" * 10,
            pin_origin="source_commit",
            entries=[EntryReport("f.bin", "a.c:2-4", "ANCHORED", [part])],
            counts={"ANCHORED": 1},
        )
        self.assertEqual(format_report(report).count("2-4"), 2)

    def test_review_count_in_summary(self):
        self.assertIn("1 to review", format_report(_sample_report()))

    def test_skipped_profile_states_reason(self):
        text = format_report(ProfileReport(name="x", skipped="no source_ref"))
        self.assertIn("no source_ref", text)

    def test_skipped_profile_still_shows_a_known_pin(self):
        text = format_report(
            ProfileReport(
                name="x",
                pin="pinsha0000",
                head="headsha000",
                pin_origin="profiled_date 2026-03-29",
                skipped="no source_ref",
            )
        )
        self.assertIn("pinsha0", text)
        self.assertIn("no source_ref", text)

    def test_changed_only_hides_clean_entries(self):
        text = format_report(_sample_report(), changed_only=True)
        self.assertIn("b.c:5", text)
        self.assertNotIn("a.c:2-4", text)


class TestRunResilience(unittest.TestCase):
    """One unreachable forge must not abandon the other profiles."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._orig = profile_sync.upstream.resolve_commit_at
        self.seen: list[str] = []

        def flaky(repo, date, cache_dir, offline=False, branch=None):
            self.seen.append(repo.slug)
            if repo.slug == "o/bad":
                raise profile_sync.upstream.UpstreamError("HTTP 401")
            return "pinsha"

        profile_sync.upstream.resolve_commit_at = flaky

    def tearDown(self):
        profile_sync.upstream.resolve_commit_at = self._orig
        self.tmp.cleanup()

    def test_upstream_error_becomes_a_skip(self):
        profile = {
            "emulator": "T",
            "source": "https://github.com/o/bad",
            "profiled_date": "2026-03-29",
            "files": [{"name": "a.bin", "source_ref": "a.c:1"}],
        }
        with self.assertRaises(profile_sync.upstream.UpstreamError):
            build_report("bad", profile, self.tmp.name)

    def test_rate_limit_still_propagates(self):
        def limited(repo, date, cache_dir, offline=False, branch=None):
            raise profile_sync.upstream.RateLimitError("HTTP 403")

        profile_sync.upstream.resolve_commit_at = limited
        profile = {
            "emulator": "T",
            "source": "https://github.com/o/n",
            "profiled_date": "2026-03-29",
            "files": [{"name": "a.bin", "source_ref": "a.c:1"}],
        }
        with self.assertRaises(profile_sync.upstream.RateLimitError):
            build_report("x", profile, self.tmp.name)


class TestElidedSummary(unittest.TestCase):
    def test_groups_untouched_profiles_by_reason(self):
        reports = [
            ProfileReport(name="a", entries=[], counts={"CHANGED": 1}),
            ProfileReport(name="b", entries=[], counts={}, skipped="no source_ref"),
            ProfileReport(name="c", entries=[], counts={}, skipped="no source_ref"),
            ProfileReport(name="d", entries=[], counts={"ANCHORED": 4}),
        ]
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            profile_sync._print_elided(reports, printed=1)
        text = buffer.getvalue()
        self.assertIn("3 non listes", text)
        self.assertIn("2  no source_ref", text)
        self.assertIn("1  nothing to review", text)

    def test_silent_when_everything_was_listed(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            profile_sync._print_elided(
                [ProfileReport(name="a", entries=[], counts={"GONE": 1})], printed=1
            )
        self.assertEqual(buffer.getvalue(), "")


class TestExtrasSurviveARefusingForge(unittest.TestCase):
    """A pass over every profile used to die on the first forge answering
    403 to the detection reads, after the ref report had already muted it."""

    def _args(self):
        return argparse.Namespace(
            check_version=False, detect_new_files=True, watch_hashes=False,
            full_diff=False, tree_diff=False, cache_dir="x", offline=False,
            ref=None, context=3,
        )

    def _profile(self):
        return {"emulator": "T", "source": "https://github.com/o/n", "files": []}

    def test_a_refusal_is_printed_on_the_profile_not_raised(self):
        original = upstream.fetch_file

        def refuse(*_args, **_kwargs):
            raise upstream.UpstreamError("https://x/y: HTTP 403")

        upstream.fetch_file = refuse
        try:
            report = _sample_report()
            profile_sync._attach_detection(self._args(), self._profile(), report)
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                profile_sync._print_extras(self._args(), self._profile(), report)
        finally:
            upstream.fetch_file = original
        self.assertEqual(report.detection_skipped, "https://x/y: HTTP 403")
        self.assertIn("extras skipped: https://x/y: HTTP 403", buffer.getvalue())

    def test_detection_lands_on_the_report(self):
        """A name the pinned file already carried is listed, but only a name
        the pin did not carry is new since the pin."""
        files = {
            "pinsha0000": ['load("old.rom");'],
            "headsha000": ['load("old.rom");', 'load("added.rom"); /* 0xdeadbeef */'],
        }
        original = upstream.fetch_file
        upstream.fetch_file = lambda repo, rev, path, *a, **k: files[rev]
        args = self._args()
        args.watch_hashes = True
        report = _sample_report()
        try:
            profile_sync._attach_detection(args, self._profile(), report)
        finally:
            upstream.fetch_file = original
        by_name = {(i["path"], i["name"]): i["since_pin"] for i in report.new_files}
        self.assertEqual(
            by_name,
            {("a.c", "old.rom"): False, ("a.c", "added.rom"): True,
             ("b.c", "old.rom"): False, ("b.c", "added.rom"): True},
        )
        self.assertIn(
            {"path": "a.c", "kind": "crc32", "value": "deadbeef"}, report.new_hashes
        )

    def test_a_quota_signal_still_stops_the_pass(self):
        original = upstream.fetch_file

        def quota(*_args, **_kwargs):
            raise upstream.RateLimitError("quota")

        upstream.fetch_file = quota
        try:
            with self.assertRaises(upstream.RateLimitError):
                profile_sync._attach_detection(
                    self._args(), self._profile(), _sample_report()
                )
        finally:
            upstream.fetch_file = original


class TestReportToDict(unittest.TestCase):
    def test_round_trips_through_json(self):
        payload = report_to_dict(_sample_report())
        self.assertEqual(json.loads(json.dumps(payload))["counts"]["CHANGED"], 1)

    def test_parts_are_serialisable(self):
        payload = report_to_dict(_sample_report())
        self.assertEqual(payload["entries"][0]["parts"][0]["status"], "SHIFTED")

    def test_markdown_lists_every_profile(self):
        text = format_markdown([_sample_report()])
        self.assertIn("demo", text)


class TestFetchPlan(unittest.TestCase):
    def test_only_entries_needing_review(self):
        urls = fetch_plan(_sample_report())
        self.assertEqual(len(urls), 1)
        self.assertIn("b.c", urls[0])

    def test_url_carries_head_revision(self):
        self.assertIn("headsha000", fetch_plan(_sample_report())[0])

    def test_url_uses_the_recorded_host(self):
        report = _sample_report()
        report.host = "codeberg.org"
        self.assertIn("codeberg.org", fetch_plan(report)[0])

    def test_empty_when_nothing_to_review(self):
        report = _sample_report()
        report.entries = [report.entries[0]]
        report.counts = {"SHIFTED": 1}
        self.assertEqual(fetch_plan(report), [])


PROFILES = {
    "alpha": {
        "emulator": "A",
        "type": "libretro",
        "systems": ["sony-playstation"],
        "profiled_date": "2026-03-01",
    },
    "beta": {
        "emulator": "B",
        "type": "standalone",
        "systems": ["nintendo-64"],
        "profiled_date": "2026-08-01",
    },
    "gamma": {
        "emulator": "C",
        "type": "alias",
        "systems": ["sony-playstation"],
        "profiled_date": "2026-03-01",
    },
}


def _args(**kwargs):
    argv = []
    for key, value in kwargs.items():
        flag = "--" + key.replace("_", "-")
        if value is True:
            argv.append(flag)
        elif isinstance(value, list):
            for item in value:
                argv.extend([flag, str(item)])
        else:
            argv.extend([flag, str(value)])
    return build_parser().parse_args(argv)


class TestSelectProfiles(unittest.TestCase):
    def test_single_emulator(self):
        self.assertEqual(
            list(select_profiles(PROFILES, _args(emulator="alpha"))), ["alpha"]
        )

    def test_emulator_repeats(self):
        # A stored --emulator kept only the last of several.
        self.assertEqual(
            list(select_profiles(PROFILES, _args(emulator=["alpha", "beta", "alpha"]))),
            ["alpha", "beta"],
        )

    def test_all_excludes_aliases(self):
        self.assertEqual(
            sorted(select_profiles(PROFILES, _args(all=True))), ["alpha", "beta"]
        )

    def test_filter_by_system(self):
        self.assertEqual(
            list(
                select_profiles(
                    PROFILES, _args(all=True, system="sony-playstation")
                )
            ),
            ["alpha"],
        )

    def test_filter_by_type(self):
        self.assertEqual(
            list(select_profiles(PROFILES, _args(all=True, type="standalone"))),
            ["beta"],
        )

    def test_stale_before(self):
        self.assertEqual(
            list(
                select_profiles(PROFILES, _args(all=True, stale_before="2026-06-01"))
            ),
            ["alpha"],
        )

    def test_limit(self):
        self.assertEqual(len(select_profiles(PROFILES, _args(all=True, limit=1))), 1)

    def test_unknown_emulator_raises(self):
        with self.assertRaises(SystemExit):
            select_profiles(PROFILES, _args(emulator="nope"))


SAMPLE = '''emulator: Test
source: "https://github.com/o/n"
profiled_date: "2026-03-29"

notes: >
  A note mentioning profiled_date: "1999-01-01" inside prose.

files:
  - name: "a.bin"
    source_ref: "a.c:10-12"
  - name: "b.bin"
    source_ref: "b.c:5"
'''


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
        )
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
            ),
            [],
        )
        self.assertIn('source_ref: "b.c:5"', self.path.read_text())

    def test_ambiguous_is_never_touched(self):
        part = PartResult(RefPart("b.c", 5, 5), "AMBIGUOUS", None, None, None, [3, 9])
        self.assertEqual(
            rebase_refs(
                self.path,
                self._report([EntryReport("b.bin", "b.c:5", "AMBIGUOUS", [part])]),
            ),
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
        self.assertEqual(rebase_refs(self.path, report), [])
        self.assertEqual(rebase_refs(self.path, report, accept_changed=True), [])
        self.assertIn('source_ref: "a.c:10-12"', self.path.read_text())

    def test_nothing_is_rebased_while_a_ref_needs_review(self):
        shifted = PartResult(RefPart("a.c", 10, 12), "SHIFTED", None, 20, 22, [])
        report = self._report(
            [EntryReport("a.bin", "a.c:10-12", "SHIFTED", [shifted])]
        )
        report.counts = {"SHIFTED": 1, "CHANGED": 1}
        self.assertEqual(rebase_refs(self.path, report), [])
        self.assertIn('source_ref: "a.c:10-12"', self.path.read_text())

    def test_accept_changed_recales_a_reviewed_diff(self):
        part = PartResult(RefPart("a.c", 10, 12), "CHANGED", None, 30, 32, [])
        report = self._report(
            [EntryReport("a.bin", "a.c:10-12", "CHANGED", [part])]
        )
        report.counts = {"CHANGED": 1}
        self.assertEqual(rebase_refs(self.path, report), [])
        applied = rebase_refs(self.path, report, accept_changed=True)
        self.assertEqual(applied, ["a.c:10-12 -> a.c:30-32"])

    def test_accept_changed_does_not_cover_gone(self):
        part = PartResult(RefPart("a.c", 10, 12), "CHANGED", None, 30, 32, [])
        report = self._report(
            [EntryReport("a.bin", "a.c:10-12", "CHANGED", [part])]
        )
        report.counts = {"CHANGED": 1, "GONE": 1}
        self.assertEqual(rebase_refs(self.path, report, accept_changed=True), [])

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
        )
        self.assertEqual(len(applied), 1)
        text = self.path.read_text()
        self.assertIn('source_ref: "a.c:20-22 (loads the kernel)"', text)

    def test_a_chunk_that_is_only_prose_blocks_the_rewrite(self):
        self.assertFalse(profile_sync._is_rewritable("a.c:1, (just a note)"))
        self.assertTrue(profile_sync._is_rewritable("a.c:1 (note), b.c:2"))

    def test_mode_keyed_ref_is_never_rewritten(self):
        part = PartResult(RefPart("a.c", 10, 12), "SHIFTED", None, 20, 22, [])
        applied = rebase_refs(
            self.path,
            self._report(
                [EntryReport("a.bin [libretro]", "a.c:10-12", "SHIFTED", [part])]
            ),
        )
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
        from unittest import mock  # noqa: PLC0415

        def nothing_gained(args, profile, report):
            report.new_files, report.new_hashes = [], []

        self._detection = mock.patch.object(
            profile_sync, "_attach_detection", side_effect=nothing_gained
        )
        self._detection.start()

    def tearDown(self):
        self._detection.stop()
        self.tmp.cleanup()

    def test_a_file_gained_since_the_pin_holds_the_bump(self):
        # mame2003_plus's zn.c gained two G-NET BIOS sets around refs that
        # only shifted.
        from unittest import mock  # noqa: PLC0415

        def gained(args, profile, report):
            report.new_files = [{"path": "zn.c", "name": "coh3002t.zip", "since_pin": True}]
            report.new_hashes = []

        before = self.path.read_text()
        with mock.patch.object(profile_sync, "_attach_detection", side_effect=gained), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self._run(self._args(rebase_refs=True, dry_run=False), self._shifted())
        self.assertEqual(self.path.read_text(), before)
        self.assertIn("coh3002t.zip", err.getvalue())
        with mock.patch.object(profile_sync, "_attach_detection", side_effect=gained):
            self._run(self._args(rebase_refs=True, dry_run=False, accept_changed=True), self._shifted())
        self.assertIn('source_commit: "newhead"', self.path.read_text())

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
            profile_sync._apply_writes(
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
        )

    def test_a_prose_read_that_fails_leaves_the_profile_as_it_was(self):
        """The bumped profile was promoted before the prose under its new pin
        was read. Offline, an uncached cited file raised NotCachedError past
        the restore and the profile kept a pin the guard would refuse."""
        from unittest import mock  # noqa: PLC0415

        before = self.path.read_bytes()
        cold = profile_sync.upstream.NotCachedError("x.c not cached")
        with mock.patch.object(profile_sync, "realign_prose", side_effect=[[], cold]), \
                self.assertRaises(profile_sync.upstream.NotCachedError):
            self._run(self._args(rebase_refs=True, dry_run=False), self._shifted())
        self.assertEqual(self.path.read_bytes(), before)

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
        self.assertFalse(bump_commit(self.path, report))
        self.assertEqual(self._run(self._args(bump_commit=True), report), "")

    def test_two_writing_pins_give_two_readings(self):
        """vitaquake2: written at one pin, re-pinned under the same text. Each
        pin is a reading, and a run settles when every reading agrees."""
        revisions = [
            ("c2", {"source_commit": "pin2", "notes": "x"}),
            ("c1", {"source_commit": "pin1", "notes": "x"}),
        ]
        repo = object()
        readings, ambiguous = profile_sync._writing_pairs(
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
        readings, _ambiguous = profile_sync._writing_pairs(
            {"source_commit": "pin2", "prose_written_at": "pin2"},
            [("source", "", repo)], revisions, "c1",
        )
        self.assertEqual(readings, [[]])
        later, _ = profile_sync._writing_pairs(
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
        readings, ambiguous = profile_sync._writing_pairs(
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
        readings, _ambiguous = profile_sync._writing_pairs(
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
        repos = [("source", mode, profile_sync.upstream.parse_repo(url))
                 for mode, url in modes.items()]
        readings, ambiguous = profile_sync._writing_pairs(
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
        with mock.patch.object(profile_sync, "realign_prose", return_value=stale), \
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
            profile_sync, "realign_prose", side_effect=lambda *a, **k: next(answers)
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
            profile_sync.pending_recale(report, False, before), 1,
            "the prose still describes the pinned revision",
        )
        output = self._run(
            self._args(rebase_refs=True, bump_commit=True), report, PROSE_SAMPLE
        )
        self.assertIn("would recale", output)
        self.assertIn("would set source_commit -> newhead", output)
        self.assertEqual(self.path.read_text(), before)


class AKeyedProfileJudgesEachBuildInItsOwnTree(TestBuildReport):
    """xenia-edge's standalone emulator.cc block moved down 4 lines while
    the libretro tree, at HEAD, carried the same path offset: the best
    outcome across repositories reported ANCHORED and the move went unseen."""

    def _keyed(self, mode=None):
        entry = {"name": "f.bin", "source_ref": "a.c:2"}
        if mode:
            entry["mode"] = mode
        return {
            "emulator": "Test",
            "source": {"standalone": "https://github.com/o/edge",
                       "libretro": "https://github.com/o/port"},
            "upstream": "https://github.com/o/edge",
            "source_commit": {"standalone": "spin", "libretro": "lpin"},
            "files": [entry],
        }

    def _two_builds(self):
        trees = {
            ("o/edge", "spin", "a.c"): ["x", "f.bin cited"],
            ("o/edge", "shead", "a.c"): ["pad", "pad", "x", "f.bin cited"],
            ("o/port", "lpin", "a.c"): ["y", "f.bin cited"],
        }
        heads = {"o/edge": "shead", "o/port": "lpin"}
        profile_sync.upstream.fetch_file = (
            lambda repo, sha, path, cache_dir, offline=False:
            trees.get((repo.slug, sha, path))
        )
        profile_sync.upstream.resolve_head = (
            lambda repo, cache_dir, offline=False, branch=None, fresh=False:
            heads[repo.slug]
        )

    def _status(self, profile):
        self._two_builds()
        report = build_report("test", profile, self.dir)
        return report.entries[0].parts[0].status

    def test_a_part_naming_no_build_is_the_first_builds(self):
        self.assertEqual(self._status(self._keyed()), "SHIFTED")

    def test_an_entry_of_one_mode_is_read_in_that_build(self):
        self.assertEqual(self._status(self._keyed("standalone")), "SHIFTED")
        self.assertNotEqual(self._status(self._keyed("libretro")), "SHIFTED")


class TestDeliberatelyFrozenPin(TestBuildReport):
    """A pin held on purpose is judged against itself, like a frozen tag.

    nethersx2-turnip-classic documents the shim rules of the revision it
    pins and says so: recaling would repoint its refs at rules the classic
    build never had. Without a way to say the freeze is deliberate, it
    reports the same drift every pass and nobody can act on it.
    """

    def _frozen(self, reason="the classic build is this revision"):
        profile = self._profile(["a.c:2"])
        profile["source_commit"] = "pinned"
        profile["pin_frozen"] = reason
        return profile

    def test_a_frozen_pin_is_checked_against_itself(self):
        self.files[("pinned", "a.c")] = ["x", "the cited line"]
        self.files[("headsha", "a.c")] = ["y"] * 40
        report = build_report("test", self._frozen(), self.dir)
        self.assertTrue(report.pinned_tag)
        self.assertEqual(report.entries[0].parts[0].status, "ANCHORED")

    def test_a_frozen_profile_is_never_recaled(self):
        self.files[("pinned", "a.c")] = ["x", "the cited line"]
        report = build_report("test", self._frozen(), self.dir)
        path = Path(self.dir) / "p.yml"
        path.write_text(SAMPLE, encoding="utf-8")
        self.assertEqual(rebase_refs(path, report), [])
        self.assertFalse(bump_commit(path, report))

    def test_the_builds_platforms_hold_say_so(self):
        # reicast is the commit Recalbox's reicast.mk builds, 789 commits
        # behind master. Compared to HEAD it showed eight refs to review that
        # nobody could act on.
        from common import load_emulator_profiles  # noqa: PLC0415

        root = Path(__file__).resolve().parents[1] / "emulators"
        profiles = load_emulator_profiles(str(root))
        for name in ("reicast", "fbalpha2019", "supermodel-legacy"):
            with self.subTest(profile=name):
                self.assertTrue(str(profiles[name].get("pin_frozen") or "").strip())

    def test_a_frozen_build_files_its_content_with_the_build_that_follows(self):
        # AloysHF/NicaiEmu became AloysHF/CoolbarEmu (PR #78). The buildbot
        # still serves nicaiemu_libretro, built from 4c9b73f7, beside
        # coolbaremu_libretro. Both read the same .cbe archives, yet the two
        # profiles named two systems and two build types, so --system for
        # either missed the other core.
        # A frozen revision whose tree lacks a build the live one documents
        # keeps its own type: DuckStation 56ac3d6c has no libretro frontend
        # under src/, only duckstation-nogui and duckstation-qt.
        # RetroPie builds ppsspp-1.5.4 as PPSSPPSDL alone: the frozen build
        # is the standalone half of a project that also ships a core.
        builds_differ = {("duckstation-legacy", "duckstation"), ("ppsspp-1.5.4", "ppsspp")}
        from common import load_emulator_profiles  # noqa: PLC0415

        root = Path(__file__).resolve().parents[1] / "emulators"
        profiles = load_emulator_profiles(str(root))
        by_source: dict[str, list[str]] = {}
        for name, profile in profiles.items():
            source = profile.get("source")
            if isinstance(source, str):
                by_source.setdefault(source.rstrip("/").lower(), []).append(name)
        # A version a platform builds (built_by: mame0258, mame2014) is not
        # the same program as the repository's other cores: mame2015-libretro
        # builds mame2014, mess2015 and cdi2015, three system sets. And a
        # live build can add a system its frozen revision lacked
        # (advancemame's coh1002v, after advmame-1.4), so the frozen one's
        # systems are a subset, not an equal set. A live build can also drop
        # a system upstream deleted: advancemame removed its Hyper Neo Geo 64
        # driver in dff25b6ee7, which advmame-1.4 still carries.
        removed_upstream = {("advmame-1.4", "advancemame"): {"hyper-neogeo64"}}
        pairs = 0
        for names in by_source.values():
            frozen = [
                n for n in names
                if str(profiles[n].get("pin_frozen") or "").strip()
                and not profiles[n].get("built_by")
            ]
            live = [
                n for n in names
                if n not in frozen and not str(profiles[n].get("pin_frozen") or "").strip()
            ]
            for old in frozen:
                for new in live:
                    pairs += 1
                    with self.subTest(frozen=old, live=new):
                        self.assertLessEqual(
                            set(profiles[old].get("systems") or [])
                            - removed_upstream.get((old, new), set()),
                            set(profiles[new].get("systems") or []),
                        )
                        if (old, new) not in builds_differ:
                            self.assertEqual(profiles[old].get("type"), profiles[new].get("type"))
        self.assertGreaterEqual(pairs, 3)

    def test_an_ordinary_profile_is_unaffected(self):
        self.files[("pinsha", "a.c")] = ["x", "hit"]
        self.files[("headsha", "a.c")] = ["pad", "x", "hit"]
        report = build_report("test", self._profile(["a.c:2"]), self.dir)
        self.assertFalse(report.pinned_tag)


class TestProseSpacingIsNotADifference(unittest.TestCase):
    """A recale keeps the author's spacing, so the check has to allow for it.

    _run_after_moves renders `a.c:228,1439-1443` while the writer leaves the
    sentence as written, `a.c:228, 1439-1443`. Comparing the two literally
    made the run look unwritten, so bump_commit refused for ever: mariani
    was held back by three of them.
    """

    def test_a_written_run_counts_as_written_whatever_the_spacing(self):
        self.assertEqual(
            profile_sync._citation_key("src/Harddisk.cpp:228, 1439-1443"),
            profile_sync._citation_key("src/Harddisk.cpp:228,1439-1443"),
        )

    def test_different_citations_still_differ(self):
        self.assertNotEqual(
            profile_sync._citation_key("a.c:1, 2"),
            profile_sync._citation_key("a.c:1, 3"),
        )

    def test_a_path_change_still_differs(self):
        self.assertNotEqual(
            profile_sync._citation_key("a.c:1"),
            profile_sync._citation_key("src/a.c:1"),
        )


class TestLargeFileCeiling(unittest.TestCase):
    """The fallback mapping bails above a ceiling, and it sits high enough.

    openbor.c is the largest file any profile cites, 55k lines against 57k
    at HEAD, and the ref that mattered mapped only once the ceiling cleared
    it. The guard stays so a pathological pair cannot stall a sweep.
    """

    def test_a_pair_over_the_ceiling_is_not_diffed(self):
        big = ["x"] * (profile_sync.MAX_MATCH_LINES + 1)
        result = profile_sync._map_changed(big, big, 1, 2)
        self.assertEqual(result.status, "CHANGED")
        self.assertIn("over", result.reason)

    def test_a_pair_under_the_ceiling_is_mapped(self):
        pin = ["a", "subject", "b"]
        head = ["pad", "pad", "a", "subject", "b"]
        result = profile_sync._map_changed(pin, head, 2, 2)
        self.assertIsNotNone(result.start, "a small pair has to be diffed")
        self.assertNotIn("over", result.reason or "")

    def test_the_ceiling_clears_the_largest_file_any_profile_cites(self):
        self.assertGreater(
            profile_sync.MAX_MATCH_LINES, 57000,
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
        self.assertTrue(profile_sync.pending_recale(report))
        self.assertEqual(rebase_refs(self.path, report), [])
        self.assertIn('source_ref: "a.c:10-12"', self.path.read_text())

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
            profile_sync._apply_writes(args, "p", yaml.safe_load(SAMPLE), report)
        self.assertEqual(self.path.read_text(), before)
        self.assertIn("nothing was written", err.getvalue())
        self.assertNotIn("a.c:30-32", out.getvalue())

    def test_a_profile_the_pin_can_follow_still_moves(self):
        movable = PartResult(RefPart("a.c", 10, 12), "SHIFTED", None, 30, 32, [])
        report = self._report(
            [EntryReport("a.bin", "a.c:10-12", "SHIFTED", [movable])],
            {"SHIFTED": 1},
        )
        self.assertFalse(profile_sync.pending_recale(report))
        self.assertEqual(rebase_refs(self.path, report), ["a.c:10-12 -> a.c:30-32"])

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
        self.assertEqual(len(rebase_refs(self.path, report)), 3)
        written = self.path.read_text()
        self.assertIn('source_ref: "g.json5:575"', written)
        self.assertEqual(
            profile_sync.pending_recale(report, text=written), 0
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
        self.assertEqual(profile_sync.pending_recale(report), 1)
        self.assertFalse(bump_commit(self.path, report))

    def test_a_profile_citing_nothing_advances(self):
        # anarch's pin sat behind HEAD through every bulk advance: the
        # report skips a profile with no source_ref, and the skip blocked it.
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead", entries=[], counts={},
            skipped=profile_sync.NO_SOURCE_REF,
        )
        report.upstream_head, report.upstream_pin = "uphead", "uppin"
        self.assertTrue(bump_commit(self.path, report))
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
            counts={}, skipped=profile_sync.NO_SOURCE_REF,
        )
        platforms = str(root / "platforms")
        self.assertEqual(
            profile_sync.shipping_platforms("advanced_drastic", self.tmp.name, platforms),
            ["knulli"],
        )
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertFalse(bump_commit(path, report, platforms_dir=platforms))
        self.assertIn("only knulli ships it", err.getvalue())
        path.write_text(
            path.read_text(encoding="utf-8")
            + 'pin_follows: "KNULLI builds the branch tip"\n',
            encoding="utf-8",
        )
        self.assertTrue(bump_commit(path, report, platforms_dir=platforms))

    def test_any_other_skip_still_holds_the_pin(self):
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead", entries=[], counts={},
            skipped="rate limited: gitlab.com",
        )
        self.assertFalse(bump_commit(self.path, report))

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
        self.assertEqual(profile_sync.pending_recale(report), 0)
        self.assertTrue(bump_commit(self.path, report))

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
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(bump_commit(self.path, report))
        self.assertNotIn("newhead", self.path.read_text())

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
        self.assertFalse(bump_commit(self.path, report("up/n")))
        self.assertNotIn("newhead", self.path.read_text())
        self.assertTrue(bump_commit(self.path, report(None)))

    def test_a_bump_alone_waits_for_the_recale(self):
        """lrps2 at 0 to review with two SHIFTED parts: --bump-commit run
        alone wrote the new pin over refs still on the old lines."""
        part = PartResult(RefPart("a.c", 10, 12, "a.c:10-12"), "SHIFTED", None, 30, 32, [])
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[EntryReport("a.bin", "a.c:10-12", "SHIFTED", [part])],
            counts={"SHIFTED": 1},
        )
        self.assertFalse(bump_commit(self.path, report))
        self.assertNotIn("newhead", self.path.read_text())
        self.assertEqual(rebase_refs(self.path, report), ["a.c:10-12 -> a.c:30-32"])
        self.assertTrue(bump_commit(self.path, report))

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
        self.assertTrue(bump_commit(self.path, report))
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
        self.assertTrue(bump_commit(self.path, report))
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
            self.assertFalse(bump_commit(self.path, report))
        self.assertEqual(self.path.read_text(encoding="utf-8"), before)

    def test_refused_when_pinned_to_a_superseded_tag(self):
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[], counts={"ANCHORED": 3}, pinned_tag="v1.6.0",
        )
        self.assertFalse(bump_commit(self.path, report))

    def test_refused_while_a_changed_remains(self):
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[], counts={"CHANGED": 1},
        )
        self.assertFalse(bump_commit(self.path, report))

    def test_accepted_when_everything_anchors(self):
        report = ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[], counts={"ANCHORED": 3, "SHIFTED": 1},
        )
        self.assertTrue(bump_commit(self.path, report))
        self.assertEqual(
            yaml.safe_load(self.path.read_text())["source_commit"], "newhead"
        )


class TestCheckVersion(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.repo = profile_sync.upstream.parse_repo("https://github.com/o/n")
        self._orig = (
            profile_sync.upstream.latest_release,
            profile_sync.upstream.list_tags,
            profile_sync.upstream.resolve_tag_commit,
            profile_sync.upstream.tag_commit,
        )
        profile_sync.upstream.latest_release = (
            lambda repo, cache, offline=False: profile_sync.upstream.Release(
                "v3.1.2", "2026-06-14", False
            )
        )
        profile_sync.upstream.list_tags = (
            lambda repo, cache, offline=False: ["v3.1.2", "v3.0.0"]
        )
        profile_sync.upstream.resolve_tag_commit = (
            lambda repo, tag, cache, offline=False: (
                "tagsha" if tag == "v3.0.0" else None
            )
        )
        profile_sync.upstream.tag_commit = profile_sync.upstream.resolve_tag_commit

    def tearDown(self):
        (
            profile_sync.upstream.latest_release,
            profile_sync.upstream.list_tags,
            profile_sync.upstream.resolve_tag_commit,
            profile_sync.upstream.tag_commit,
        ) = self._orig
        self.tmp.cleanup()

    def test_reports_declared_and_latest(self):
        result = check_version({"core_version": "v3.0.0"}, self.repo, self.dir, False)
        self.assertEqual(result.declared, "v3.0.0")
        self.assertEqual(result.latest_release, "v3.1.2")
        self.assertEqual(result.release_date, "2026-06-14")

    def test_detects_declared_version_is_a_tag(self):
        result = check_version({"core_version": "v3.0.0"}, self.repo, self.dir, False)
        self.assertTrue(result.tag_matches_declared)
        self.assertEqual(result.tag_commit, "tagsha")

    def test_declared_version_not_a_tag(self):
        result = check_version({"core_version": "5.2"}, self.repo, self.dir, False)
        self.assertFalse(result.tag_matches_declared)
        self.assertIsNone(result.tag_commit)

    def test_none_without_core_version(self):
        self.assertIsNone(check_version({}, self.repo, self.dir, False))

    def test_warning_when_tag_commit_differs_from_pin(self):
        result = check_version({"core_version": "v3.0.0"}, self.repo, self.dir, False)
        self.assertIsNotNone(version_warning(result, "otherpin"))

    def test_no_warning_when_tag_commit_matches_pin(self):
        result = check_version({"core_version": "v3.0.0"}, self.repo, self.dir, False)
        self.assertIsNone(version_warning(result, "tagsha"))

    def test_warning_says_which_side_of_the_tag_the_pin_is(self):
        # 52 warnings read alike: a build after its release and a pin older
        # than the release it claims could not be told apart.
        result = check_version({"core_version": "v3.0.0"}, self.repo, self.dir, False)
        self.assertIn("4 commits after the tag", version_warning(result, "p", (4, 0)))
        self.assertIn("core_version is later than the code",
                      version_warning(result, "p", (0, 9)))
        self.assertIn("off the tag's history", version_warning(result, "p", (2, 3)))

    def test_warning_names_a_release_the_pin_already_contains(self):
        result = check_version({"core_version": "v3.0.0"}, self.repo, self.dir, False)
        warning = version_warning(result, "tagsha", None, "v3.1.0")
        self.assertIn("already contains release v3.1.0", warning)


class APassedReleaseIsNewerThanTheTag(unittest.TestCase):
    """pcsx2x6 declares tag v0.2.22 while its latest published release is
    v0.2.20: the pin holds v0.2.20 without core_version being older."""

    def test_a_release_older_than_the_declared_tag_is_not_passed(self):
        from unittest import mock  # noqa: PLC0415

        version = profile_sync.VersionReport(
            "v0.2.22", "v0.2.22", "v0.2.20", "2026-07-25", True, "tag22"
        )
        args = argparse.Namespace(cache_dir="c", offline=True)
        with mock.patch.object(profile_sync.upstream, "tag_commit", return_value="rel20"), \
                mock.patch.object(profile_sync.upstream, "ancestry", return_value=(5, 0)):
            self.assertIsNone(profile_sync._passed_release(args, "repo", version, "pin"))


class ANewerReleaseThanTheTag(unittest.TestCase):
    """armsx2 sat on its 2.8 tag while 2.9 was out, and read as clean."""

    def _newer(self, after_tag, after_pin):
        from unittest import mock  # noqa: PLC0415

        version = profile_sync.VersionReport("2.8", "2.9", "2.9", "2026-10-01", True, "tag28")
        args = argparse.Namespace(cache_dir="c", offline=True)
        answers = iter([after_tag, after_pin])
        with mock.patch.object(profile_sync.upstream, "tag_commit", return_value="rel29"), \
                mock.patch.object(profile_sync.upstream, "ancestry", side_effect=lambda *a, **k: next(answers)):
            return profile_sync._newer_release(args, "repo", version, "tag28")

    def test_a_later_release_is_named(self):
        self.assertEqual(self._newer((12, 0), (12, 0)), "2.9")

    def test_an_older_or_unrelated_release_is_not(self):
        self.assertIsNone(self._newer((0, 5), (0, 5)))
        self.assertIsNone(self._newer((3, 4), (3, 4)))


class AProjectThatOnlyTags(unittest.TestCase):
    """eightyone sat on v1.2 and higan on 106 while v1.3 and v107 were tagged:
    with no release published, nothing compared them."""

    def test_a_version_tag_stands_in_for_the_missing_release(self):
        version = profile_sync.VersionReport("v1.2", "v1.3", None, None, True, "tag12")
        self.assertEqual(profile_sync.published_version(version), "v1.3")
        for tag in ("v107", "1.1d", "v9.0-6", "2.55"):
            version = profile_sync.VersionReport("x", tag, None, None, False, None)
            self.assertEqual(profile_sync.published_version(version), tag)

    def test_a_nightly_tag_does_not(self):
        for tag in ("latest-nightly", "continuous", "nightly-20261001"):
            version = profile_sync.VersionReport("v1.2", tag, None, None, True, "t")
            self.assertIsNone(profile_sync.published_version(version))

    def test_a_release_wins_over_a_newer_tag(self):
        version = profile_sync.VersionReport("1.0", "1.2", "1.1", "2026-01-01", True, "t")
        self.assertEqual(profile_sync.published_version(version), "1.1")

    def test_a_newer_tag_is_named(self):
        from unittest import mock  # noqa: PLC0415

        version = profile_sync.VersionReport("v1.2", "v1.3", None, None, True, "tag12")
        args = argparse.Namespace(cache_dir="c", offline=True)
        with mock.patch.object(profile_sync.upstream, "tag_commit", return_value="tag13"), \
                mock.patch.object(profile_sync.upstream, "ancestry", return_value=(7, 0)):
            self.assertEqual(profile_sync._newer_release(args, "repo", version, "tag12"), "v1.3")


class APassedReleaseUnderAnUntaggedVersion(unittest.TestCase):
    """parallel-launcher declared 9.0.5, a name no tag carries, and its HEAD
    already held release v9.0-6: the missing tag silenced the warning."""

    def test_the_passed_release_is_named_without_a_declared_tag(self):
        version = profile_sync.VersionReport("9.0.5", "v9.0-6", "v9.0-6", "2026-08-08", False, None)
        warning = version_warning(version, "head", None, "v9.0-6")
        self.assertIn("already contains release v9.0-6", warning)

    def test_only_a_higher_number_counts_without_a_tag(self):
        from unittest import mock  # noqa: PLC0415

        args = argparse.Namespace(cache_dir="c", offline=True)
        cases = {("9.0.5", "v9.0-6"): "v9.0-6", ("1.61", "1.53"): None,
                 ("v0.1-12070", "latest"): None, ("Git", "v2.7"): None, ("5.2", "v5.2"): None,
                 ("v1", "v1.0"): None, ("0.83", "20120302"): None, ("0.160", "v1.4.1"): None,
                 ("0.0.35", "v0.0.43"): "v0.0.43", ("106", "v107"): "v107", ("v1", "20170424"): None}
        for (declared, release), expected in cases.items():
            version = profile_sync.VersionReport(declared, release, release, "d", False, None)
            with self.subTest(declared=declared, release=release), \
                    mock.patch.object(profile_sync.upstream, "tag_commit", return_value="rel"), \
                    mock.patch.object(profile_sync.upstream, "ancestry", return_value=(3, 0)):
                self.assertEqual(profile_sync._passed_release(args, "repo", version, "pin"), expected)

    def test_no_tag_and_nothing_passed_stays_quiet(self):
        version = profile_sync.VersionReport("9.0.5", None, None, None, False, None)
        self.assertIsNone(version_warning(version, "head"))


class TestAncestry(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = profile_sync.upstream._http_json

    def tearDown(self):
        profile_sync.upstream._http_json = self.saved
        self.tmp.cleanup()

    def test_github_answers_both_directions_at_once(self):
        calls = []

        def answer(url):
            calls.append(url)
            return {"ahead_by": 3, "behind_by": 0}

        profile_sync.upstream._http_json = answer
        repo = profile_sync.upstream.parse_repo("https://github.com/o/n")
        self.assertEqual(
            profile_sync.upstream.ancestry(repo, "tag", "pin", self.tmp.name), (3, 0)
        )
        self.assertEqual(len(calls), 1)

    def test_gitlab_is_asked_both_ways(self):
        def answer(url):
            forward = "from=tag&to=pin" in url
            return {"commits": [{}] * (0 if forward else 5)}

        profile_sync.upstream._http_json = answer
        repo = profile_sync.upstream.parse_repo("https://gitlab.com/o/n")
        self.assertEqual(
            profile_sync.upstream.ancestry(repo, "tag", "pin", self.tmp.name), (0, 5)
        )


HASH_PROFILE = {
    "files": [
        {
            "name": "scph5500.bin",
            "sha1": "B05DEF971D8EC59F346F2D9AC21FB742E3EB6917",
            "aliases": ["SCPH-5500.bin"],
        },
        {"name": "gba_bios.bin", "md5": "a860e8c0b6d573d191e4ec7db1b1e4f6"},
    ]
}


class TestDeclared(unittest.TestCase):
    def test_names_include_aliases_casefolded(self):
        names = declared_names(HASH_PROFILE)
        self.assertIn("scph5500.bin", names)
        self.assertIn("scph-5500.bin", names)

    def test_hashes_lowercased(self):
        self.assertIn(
            "b05def971d8ec59f346f2d9ac21fb742e3eb6917", declared_hashes(HASH_PROFILE)
        )


class TestDetectNewFiles(unittest.TestCase):
    def test_finds_undeclared_filename(self):
        lines = ['load("scph5500.bin");', 'load("scph7001.bin");']
        found, elided = detect_new_files(lines, declared_names(HASH_PROFILE))
        self.assertEqual(found, [(2, "scph7001.bin")])
        self.assertEqual(elided, 0)

    def test_ignores_declared_alias(self):
        found, _ = detect_new_files(
            ['open("SCPH-5500.bin")'], declared_names(HASH_PROFILE)
        )
        self.assertEqual(found, [])

    def test_cap_reports_elided_count(self):
        lines = [f'load("rom{i}.bin");' for i in range(40)]
        found, elided = detect_new_files(lines, set(), cap=25)
        self.assertEqual(len(found), 25)
        self.assertEqual(elided, 15)

    def test_source_file_extensions_are_not_matched(self):
        found, _ = detect_new_files(['#include "driver.cpp"'], set())
        self.assertEqual(found, [])

    def test_a_printf_conversion_is_not_part_of_the_name(self):
        # sdl2trs src/trs_options.c:864-866 builds "%slevel2.rom" and the
        # report named slevel2.rom.
        lines = [
            'snprintf(romfile1, sizeof(romfile1), "%slevel2.rom", ROM_PATH);',
            'snprintf(name, 64, "%02dcart.bin", slot);',
        ]
        found, _ = detect_new_files(lines, set(), path="src/trs_options.c")
        self.assertEqual(found, [(1, "level2.rom"), (2, "cart.bin")])

    def test_a_quoted_name_with_spaces_is_read_whole(self):
        # virtualjaguar libretro.c:5815-5816 opens "Jaguar CD BIOS.rom",
        # reported as BIOS.rom. A sentence still yields the name it holds.
        lines = [
            'snprintf(path, n, "%s%c%s", dir, slash, "Jaguar CD BIOS.rom");',
            'log("Please insert bios.bin first");',
            'message(STATUS "Packing patches.zip")',
            '#define ROM ".bin.hex.iii.rom"',
        ]
        found, _ = detect_new_files(lines, set(), path="libretro.c")
        self.assertEqual(
            found,
            [(1, "Jaguar CD BIOS.rom"), (2, "bios.bin"), (3, "patches.zip")],
        )

    def test_an_identifier_in_code_is_not_a_file(self):
        # pcee2 reads config keys EE.bios and IOP.bios and a field psm_s.pal.
        lines = [
            "cfg.EE.bios = load(path);",
            "if (psm_s.pal) {",
            "// loads boot.rom from the system directory",
            'open("ipl.rom");',
        ]
        found, _ = detect_new_files(lines, set(), path="src/core/config.cpp")
        self.assertEqual(found, [(3, "boot.rom"), (4, "ipl.rom")])
        found, _ = detect_new_files(["Copy EE.bios here"], set(), path="README.md")
        self.assertEqual(found, [(1, "EE.bios")])


class TestWatchHashes(unittest.TestCase):
    def test_finds_new_sha1(self):
        added = ['+  { "x.bin", "0123456789abcdef0123456789abcdef01234567" },']
        found = watch_hashes(added, declared_hashes(HASH_PROFILE))
        self.assertEqual(found[0][1], "0123456789abcdef0123456789abcdef01234567")

    def test_ignores_declared_hash(self):
        added = ["+  b05def971d8ec59f346f2d9ac21fb742e3eb6917"]
        self.assertEqual(watch_hashes(added, declared_hashes(HASH_PROFILE)), [])

    def test_crc32_needs_a_filename_on_the_line(self):
        self.assertEqual(watch_hashes(["+  mask = 0xdeadbeef;"], set()), [])
        found = watch_hashes(['+  { "a.rom", 0xdeadbeef }'], set())
        self.assertEqual(found[0][1], "deadbeef")


class TestUnifiedForPath(unittest.TestCase):
    def test_produces_a_hunk(self):
        out = unified_for_path(["a", "b"], ["a", "c"], "f.c", 1)
        self.assertIn("-b", out)
        self.assertIn("+c", out)
        self.assertIn("f.c", out)

    def test_identical_files_produce_nothing(self):
        self.assertEqual(unified_for_path(["a"], ["a"], "f.c", 3), "")


class TestTreeDiff(unittest.TestCase):
    def test_filters_to_ref_directories(self):
        result = CompareResult(
            [
                FileChange("added", "src/new.cpp", None),
                FileChange("added", "docs/readme.md", None),
            ],
            False,
        )
        self.assertEqual(tree_diff(result, {"src"}), ["added  src/new.cpp"])

    def test_rename_shows_both_paths(self):
        result = CompareResult([FileChange("renamed", "src/b.c", "src/a.c")], False)
        self.assertEqual(tree_diff(result, {"src"}), ["renamed  src/a.c -> src/b.c"])

    def test_repository_root_is_a_directory(self):
        result = CompareResult(
            [
                FileChange("modified", "libretro.c", None),
                FileChange("modified", "deps/lightning/lib/jit_arm.c", None),
            ],
            False,
        )
        self.assertEqual(tree_diff(result, {""}), ["modified  libretro.c"])

    def test_empty_ref_dirs_show_everything(self):
        result = CompareResult([FileChange("modified", "a/b.c", None)], False)
        self.assertEqual(tree_diff(result, set()), ["modified  a/b.c"])

    def test_truncation_is_announced(self):
        result = CompareResult([FileChange("added", "src/a.c", None)], True)
        self.assertIn("truncated", "\n".join(tree_diff(result, {"src"})))


class TestDriftScore(unittest.TestCase):
    def test_review_statuses_dominate(self):
        heavy = ProfileReport(name="a", entries=[], counts={"GONE": 1})
        light = ProfileReport(name="b", entries=[], counts={"SHIFTED": 20})
        self.assertGreater(drift_score(heavy, None, 0), drift_score(light, None, 0))

    def test_version_mismatch_adds_weight(self):
        report = ProfileReport(name="a", entries=[], counts={})
        stale = VersionReport("v1.0", "v2.0", "v2.0", "2026-06-01", False, None)
        current = VersionReport("v2.0", "v2.0", "v2.0", "2026-06-01", True, None)
        self.assertGreater(
            drift_score(report, stale, 0), drift_score(report, current, 0)
        )

    def test_commit_count_is_a_light_signal(self):
        report = ProfileReport(name="a", entries=[], counts={})
        self.assertGreater(drift_score(report, None, 100), drift_score(report, None, 0))

    def test_clean_profile_scores_zero(self):
        report = ProfileReport(name="a", entries=[], counts={"ANCHORED": 5})
        self.assertEqual(drift_score(report, None, 0), 0)

    def test_a_pin_to_set_again_outranks_a_gone_ref(self):
        """pcem ranked last at 0 with "1 to review, 1 orphaned pin": its
        upstream_commit had left every branch of a force-pushed repository."""
        gone = ProfileReport(name="a", entries=[], counts={"GONE": 1})
        orphaned = ProfileReport(name="pcem", entries=[], counts={},
                                 orphaned=["upstream_commit 25b54e3f"])
        moved = ProfileReport(name="m", entries=[], counts={},
                              moved_repos=["a/b answers as c/b"])
        for report in (orphaned, moved):
            with self.subTest(name=report.name):
                self.assertGreater(drift_score(report, None, 0), drift_score(gone, None, 0))


class TestCollectCitations(unittest.TestCase):
    def test_files_refs_in_document_order(self):
        document = {
            "files": [
                {"name": "a.bin", "source_ref": "a.c:1"},
                {"name": "b.bin"},
                {"name": "c.bin", "source_ref": "c.c:3"},
            ],
        }
        refs = [c for c in collect_citations(document) if c.kind == "ref"]
        self.assertEqual([c.ref for c in refs], ["a.c:1", "c.c:3"])
        self.assertEqual(refs[0].field, "files[a.bin].source_ref")
        self.assertIs(refs[0].entry, document["files"][0])

    def test_data_directories_refs_are_citations_too(self):
        document = {
            "data_directories": [
                {"key": "sys", "source_ref": "loader.cpp:44"},
            ],
        }
        refs = collect_citations(document)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0].kind, "ref")
        self.assertEqual(refs[0].ref, "loader.cpp:44")

    def test_mode_keyed_ref_keeps_its_label(self):
        document = {
            "files": [
                {
                    "name": "a.bin",
                    "source_ref": {"standalone": "a.c:1", "libretro": "b.c:2"},
                },
            ],
        }
        refs = collect_citations(document)
        self.assertEqual(
            [(c.label, c.ref) for c in refs],
            [("standalone", "a.c:1"), ("libretro", "b.c:2")],
        )

    def test_notes_citation_with_continuation_run(self):
        document = {
            "notes": "The reset path (main.c:112,1624-1633) runs first.\n",
        }
        prose = collect_citations(document)
        self.assertEqual(len(prose), 1)
        self.assertEqual(prose[0].kind, "prose")
        self.assertEqual(prose[0].field, "notes")
        self.assertEqual(prose[0].ref, "main.c:112,1624-1633")
        self.assertEqual(
            [(p.path, p.start, p.end) for p in prose[0].parts],
            [("main.c", 112, 112), ("main.c", 1624, 1633)],
        )

    def test_a_semicolon_separates_citations_like_a_comma(self):
        # lynx-emu: `...:112; mednafen src/lynx/system.cpp:86-93` cites the
        # mednafen upstream, not the fork the profile was read from.
        for line in (
            "see Lynx.emu/src/lynx/system.cpp:112; mednafen src/lynx/system.cpp:86-93",
            "see Lynx.emu/src/lynx/system.cpp:112, mednafen src/lynx/system.cpp:86-93",
            "see Lynx.emu/src/lynx/system.cpp:112. mednafen src/lynx/system.cpp:86-93",
        ):
            with self.subTest(line=line):
                start = line.index("src/lynx/system.cpp:86")
                self.assertTrue(profile_sync._prose_external(line, start))
        line = "boot; then src/lynx/system.cpp:86"
        self.assertFalse(profile_sync._prose_external(line, line.index("src/")))

    def test_spans_locate_the_tokens_on_the_line(self):
        document = {"notes": "See main.c:112,1624-1633 for the boot path.\n"}
        citation = collect_citations(document)[0]
        line = document["notes"].splitlines()[citation.line]
        self.assertEqual(line[slice(*citation.path_span)], "main.c")
        self.assertEqual(
            [line[lo:hi] for lo, hi in citation.spans], ["112", "1624-1633"]
        )

    def test_comma_space_is_prose_not_a_continuation(self):
        document = {"notes": "x.c:100, 200 files are read.\n"}
        citation = collect_citations(document)[0]
        self.assertEqual(citation.ref, "x.c:100")

    def test_a_url_port_is_not_a_citation(self):
        document = {"notes": "Served from https://example.com:8080/path.\n"}
        self.assertEqual(collect_citations(document), [])

    def test_version_and_ratio_text_is_not_a_citation(self):
        document = {"notes": "Since v1.6.0:123 the ratio 16:9 applies.\n"}
        self.assertEqual(collect_citations(document), [])

    def test_nested_note_and_exclusion_note_are_scanned(self):
        document = {
            "exclusion_note": "Loaded by hook.c:655 at boot.",
            "files": [
                {"name": "a.bin", "note": "Table at data.rs:12-20."},
            ],
        }
        fields = {c.field for c in collect_citations(document)}
        self.assertEqual(fields, {"exclusion_note", "files[a.bin].note"})

    def test_string_inside_a_list_is_scanned(self):
        document = {
            "analysis": {"entries": ["checked in geo.c:234-243"]},
        }
        citation = collect_citations(document)[0]
        self.assertEqual(citation.field, "analysis.entries[0]")
        self.assertEqual(citation.ref, "geo.c:234-243")

    def test_whole_value_pseudo_ref_is_a_prose_citation(self):
        document = {"analysis": {"upstream_ref": "src/a.c:12-20"}}
        citation = collect_citations(document)[0]
        self.assertEqual(citation.kind, "prose")
        self.assertEqual(citation.ref, "src/a.c:12-20")

    def test_two_runs_on_one_line_stay_separate(self):
        document = {"notes": "hook.c:655-709 and hook.c:874-928 serve it.\n"}
        refs = [c.ref for c in collect_citations(document)]
        self.assertEqual(refs, ["hook.c:655-709", "hook.c:874-928"])

    def test_trailing_comma_stays_prose(self):
        document = {"notes": "boot (pif.c:252-260,\nthen the response).\n"}
        citation = collect_citations(document)[0]
        self.assertEqual(citation.ref, "pif.c:252-260")

    def test_continuation_ending_a_sentence_is_kept(self):
        document = {"notes": "It reads b.c:2,8-9. Then it boots.\n"}
        citation = collect_citations(document)[0]
        self.assertEqual(citation.ref, "b.c:2,8-9")

    def test_decimal_number_is_not_a_continuation(self):
        document = {"notes": "Set at x.c:1,2.5 percent of the frame.\n"}
        citation = collect_citations(document)[0]
        self.assertEqual(citation.ref, "x.c:1")

    def test_dotfile_keeps_its_leading_dot(self):
        document = {"notes": "Built by CI (.gitlab-ci.yml:306) nightly.\n"}
        citation = collect_citations(document)[0]
        self.assertEqual(citation.ref, ".gitlab-ci.yml:306")
        self.assertEqual(citation.parts[0].path, ".gitlab-ci.yml")
        line = document["notes"].splitlines()[0]
        self.assertEqual(line[slice(*citation.path_span)], ".gitlab-ci.yml")

    def test_sentence_dot_is_not_a_dotfile(self):
        document = {"notes": "It runs on boot.data.c:12 is the table.\n"}
        citation = collect_citations(document)[0]
        self.assertEqual(citation.parts[0].path, "boot.data.c")

    def test_external_project_prefix_keeps_its_word(self):
        """The project word travels with the path, the source_ref convention.

        Dropping the run left m64plus-fz's `rice Config.cpp` unchecked
        although its declared repository vendors the plugin.
        """
        document = {
            "notes": "ref: mt32_model.cpp:36-97, munt ROMInfo.cpp:206-213\n"
        }
        citations = collect_citations(document)
        self.assertEqual(
            [c.ref for c in citations],
            ["mt32_model.cpp:36-97", "ROMInfo.cpp:206-213"],
        )
        self.assertEqual(citations[1].parts[0].path, "munt ROMInfo.cpp")
        self.assertTrue(profile_sync.is_external_citation("munt ROMInfo.cpp"))

    def test_project_word_ending_the_line_before_marks_the_path_external(self):
        # genesis_plus_gx_expanded wrapped `(Batocera` and
        # `package/batocera/...mk:7` one line apart in its notes, and the
        # path was read against the declared repository: 1 to review.
        document = {
            "notes": "Batocera builds it at a0b5a033\n(Batocera\n"
            "package/batocera/emulators/gpgx.mk:7), the same tree.\n"
        }
        citation = collect_citations(document)[0]
        self.assertEqual(
            citation.parts[0].path, "Batocera package/batocera/emulators/gpgx.mk"
        )
        self.assertTrue(profile_sync.is_external_citation(citation.parts[0].path))
        sentence = {"notes": "It is read by the file\nsrc/gpgx.c:7 at boot.\n"}
        self.assertEqual(collect_citations(sentence)[0].parts[0].path, "src/gpgx.c")

    def test_project_word_resolves_inside_a_declared_tree(self):
        tree = [
            "mupen64plus-video-rice/upstream/src/Config.cpp",
            "mupen64plus-video-gln64/src/Config.cpp",
            "mupen64plus-core/upstream/src/device/pif/bootrom_hle.c",
        ]
        resolve = profile_sync.resolve_project_word
        self.assertEqual(
            resolve("rice Config.cpp", [tree]),
            "mupen64plus-video-rice/upstream/src/Config.cpp",
        )
        self.assertEqual(
            resolve("mupen64plus-core device/pif/bootrom_hle.c", [tree]),
            "mupen64plus-core/upstream/src/device/pif/bootrom_hle.c",
        )
        self.assertIsNone(resolve("munt ROMInfo.cpp", [tree]))
        self.assertIsNone(resolve("mupen64plus Config.cpp", [tree]))

    def test_project_word_resolves_inside_a_submodule(self):
        """idtech4a++ and starship cite files of a submodule. The declared
        tree holds only the gitlink, so the parts stayed external and moved
        unchecked with every bump."""
        links = ["Q3E/src/main/jni/xash3d/xash3d-fwgs", "tools/Torch", "libs/zlib"]
        resolve = profile_sync.resolve_through_gitlinks
        self.assertEqual(
            resolve("xash3d-fwgs filesystem/filesystem.c", [links]),
            "Q3E/src/main/jni/xash3d/xash3d-fwgs/filesystem/filesystem.c",
        )
        self.assertEqual(
            resolve("Torch src/Companion.cpp", [links]), "tools/Torch/src/Companion.cpp"
        )
        self.assertIsNone(resolve("munt ROMInfo.cpp", [links]))
        self.assertIsNone(resolve("lib x.c", [["a/lib1", "b/lib2"]]))

    def test_a_submodule_file_is_read_at_its_pinned_commit(self):
        port = upstream.make_repo("github.com", "glKarin", "com.n0n3m4.diii4a")
        files = {
            (port.slug, "p1", ".gitmodules"): [
                '[submodule "Q3E/src/main/jni/xash3d/xash3d-fwgs"]',
                "\tpath = Q3E/src/main/jni/xash3d/xash3d-fwgs",
                "\turl = ../xash3d-fwgs.git",
            ],
            ("glKarin/xash3d-fwgs", "s1", "filesystem/filesystem.c"): ["getenv(x)"],
        }

        def fetch(repo, sha, path, *_):
            return files.get((repo.slug, sha, path))

        with mock.patch.object(upstream, "fetch_file", side_effect=fetch), \
                mock.patch.object(
                    upstream, "list_gitlinks",
                    return_value={"Q3E/src/main/jni/xash3d/xash3d-fwgs": "s1"},
                ):
            target = upstream.through_gitlink(
                port, "p1",
                "Q3E/src/main/jni/xash3d/xash3d-fwgs/filesystem/filesystem.c", "c",
            )
        self.assertEqual(
            (target[0].slug, target[1], target[2]),
            ("glKarin/xash3d-fwgs", "s1", "filesystem/filesystem.c"),
        )

    def test_run_is_rendered_with_its_written_path(self):
        parts = [RefPart("mupen64plus-video-rice/upstream/src/Config.cpp", 38, 38, "38")]
        self.assertEqual(
            profile_sync._run_after_moves(parts, {0: (40, 40, None)}, "Config.cpp:38"),
            "Config.cpp:40",
        )

    def test_linking_word_is_not_a_project(self):
        document = {"notes": "It boots, in libretro.cpp:12 as shown.\n"}
        refs = [c.ref for c in collect_citations(document)]
        self.assertEqual(refs, ["libretro.cpp:12"])

    def test_spaced_range_continuation_is_part_of_the_run(self):
        document = {
            "notes": "ref: soundcanvas.cpp:55-71, 80-147, Ext plugin.cpp:23\n"
        }
        citations = collect_citations(document)
        self.assertEqual(len(citations), 2)
        self.assertEqual(citations[1].parts[0].path, "Ext plugin.cpp")
        self.assertEqual(citations[0].ref, "soundcanvas.cpp:55-71, 80-147")
        self.assertEqual(
            [(p.start, p.end) for p in citations[0].parts],
            [(55, 71), (80, 147)],
        )

    def test_spaced_lone_number_stays_prose(self):
        document = {"notes": "It reads x.c:100, 200 files at boot.\n"}
        citation = collect_citations(document)[0]
        self.assertEqual(citation.ref, "x.c:100")

    def test_spaced_lone_number_closing_the_citation_joins_the_run(self):
        # vkquake wrote `(Quake/bgmusic.c:29, 321).` and cemu a list of ten
        # lines of .gitlab-ci.yml: only the first number was ever compared.
        cases = {
            "music (Quake/bgmusic.c:29, 321).\n": [(29, 29), (321, 321)],
            "(ref: a/b.cpp:1586-1633, 2646).\n": [(1586, 1633), (2646, 2646)],
            "jobs in .gitlab-ci.yml:110, 116, 139-140\n": [
                (110, 110), (116, 116), (139, 140)
            ],
            "read at x.c:5, 6; then y\n": [(5, 5), (6, 6)],
        }
        for text, spans in cases.items():
            citation = collect_citations({"notes": text})[0]
            self.assertEqual(
                [(p.start, p.end) for p in citation.parts], spans, text
            )
            line = text.splitlines()[0]
            self.assertEqual(
                [line[lo:hi] for lo, hi in citation.spans],
                [p.raw for p in citation.parts],
            )

    def test_spaced_number_list_followed_by_a_word_stays_prose(self):
        for text in (
            "It reads x.c:5, 6, 7 players at once.\n",
            "It reads x.c:5, 6 and 7 at once.\n",
            "Lines 3, 4 and 5, version 2, 3 players.\n",
        ):
            refs = [c.ref for c in collect_citations({"notes": text})]
            self.assertEqual(refs, ["x.c:5"] if "x.c" in text else [], text)

    def test_declared_repository_name_is_not_external(self):
        document = {
            "upstream": "https://github.com/o/mednafen",
            "notes": "ref: geo.c:1-2, mednafen src/lynx/rom.cpp:55-74\n",
        }
        refs = [c.ref for c in collect_citations(document)]
        self.assertEqual(refs, ["geo.c:1-2", "src/lynx/rom.cpp:55-74"])

    def test_punctuation_before_the_path_is_not_a_project(self):
        document = {"notes": "loads it (-framefile); singe_utils.cpp:35-42\n"}
        refs = [c.ref for c in collect_citations(document)]
        self.assertEqual(refs, ["singe_utils.cpp:35-42"])

    def test_the_word_upstream_is_prose(self):
        document = {"notes": "same shape (upstream retro_host.c:196-198).\n"}
        refs = [c.ref for c in collect_citations(document)]
        self.assertEqual(refs, ["retro_host.c:196-198"])


class TestCitationSurfaceGuard(unittest.TestCase):
    def test_no_consumer_rederives_source_ref(self):
        """collect_citations is the only reader of source_ref values.

        A consumer keying on the field name reopens the gap this closes:
        citations outside its list rot while the pin advances. The walker
        matches the key once. Everything else goes through the collector.
        """
        source = Path(profile_sync.__file__).read_text(encoding="utf-8")
        self.assertNotIn('.get("source_ref")', source)
        self.assertEqual(source.count('== "source_ref"'), 1)


PROSE_SAMPLE = '''emulator: Test
source: "https://github.com/o/n"
profiled_date: "2026-03-29"
source_commit: "pin"

notes: |
  The loader appends dc/ to the system directory (a.c:10) and reads
  both ranges (b.c:2,8-9) on boot.

files:
  - name: "a.bin"
    source_ref: "a.c:10-12"
'''

# One run written twice in a folded scalar: no physical line carries the
# folded sentence, and the run alone is not unique.
FOLDED_TWICE = PROSE_SAMPLE.replace(
    "files:",
    "twice: >\n  Read at (q.c:7) first\n  and again at (q.c:7) later.\nfiles:",
)


class TestRebaseProse(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.yml"
        self.path.write_text(PROSE_SAMPLE, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def _report(self, entries, counts=None):
        return ProfileReport(
            name="p", repo="o/n", pin="pin", head="head",
            entries=entries, counts=counts or {},
        )

    def _prose_entry(self, ref, parts, field="notes"):
        status = worst_status([p.status for p in parts])
        return EntryReport(field, ref, status, parts, "prose", field)

    def test_shifted_prose_run_moves_and_the_sentence_stays(self):
        part = PartResult(RefPart("a.c", 10, 10, "10"), "SHIFTED", None, 14, 14, [])
        applied = rebase_refs(
            self.path, self._report([self._prose_entry("a.c:10", [part])])
        )
        self.assertEqual(applied, ["notes: a.c:10 -> a.c:14"])
        text = self.path.read_text()
        self.assertIn("system directory (a.c:14) and reads", text)
        self.assertEqual(
            yaml.safe_load(text)["notes"].count("a.c:14"), 1
        )

    def test_continuation_ranges_move_together(self):
        parts = [
            PartResult(RefPart("b.c", 2, 2, "2"), "SHIFTED", None, 5, 5, []),
            PartResult(RefPart("b.c", 8, 9, "8-9"), "SHIFTED", None, 11, 12, []),
        ]
        applied = rebase_refs(
            self.path, self._report([self._prose_entry("b.c:2,8-9", parts)])
        )
        self.assertEqual(applied, ["notes: b.c:2,8-9 -> b.c:5,11-12"])
        self.assertIn("both ranges (b.c:5,11-12) on boot", self.path.read_text())

    def test_prose_and_structured_move_in_one_pass(self):
        prose = PartResult(RefPart("a.c", 10, 10, "10"), "SHIFTED", None, 14, 14, [])
        structured = PartResult(RefPart("a.c", 10, 12), "SHIFTED", None, 14, 16, [])
        applied = rebase_refs(
            self.path,
            self._report([
                self._prose_entry("a.c:10", [prose]),
                EntryReport("a.bin", "a.c:10-12", "SHIFTED", [structured]),
            ]),
        )
        self.assertEqual(len(applied), 2)
        text = self.path.read_text()
        self.assertIn('source_ref: "a.c:14-16"', text)
        self.assertIn("(a.c:14)", text)

    def test_review_status_blocks_prose_too(self):
        part = PartResult(RefPart("a.c", 10, 10, "10"), "SHIFTED", None, 14, 14, [])
        report = self._report(
            [self._prose_entry("a.c:10", [part])], counts={"GONE": 1}
        )
        self.assertEqual(rebase_refs(self.path, report), [])
        self.assertIn("(a.c:10)", self.path.read_text())

    def test_ambiguous_sentence_location_is_left_alone(self):
        self.path.write_text(FOLDED_TWICE, encoding="utf-8")
        part = PartResult(RefPart("q.c", 7, 7, "7"), "SHIFTED", None, 9, 9, [])
        applied = rebase_refs(
            self.path, self._report([self._prose_entry("q.c:7", [part], "twice")])
        )
        self.assertEqual(applied, [])
        self.assertEqual(self.path.read_text(), FOLDED_TWICE)

    def test_one_sentence_in_two_fields_moves_in_both(self):
        # emucorex cites CMakeLists.txt:706 in notes and in exclusion_note on
        # identical lines: neither was unique in the file, one was left, and
        # the pin refused to follow.
        text = PROSE_SAMPLE.replace(
            "files:",
            'quirks: |\n  The loader appends dc/ to the system directory '
            '(a.c:10) and reads\n  nothing else.\nfiles:',
        )
        self.path.write_text(text, encoding="utf-8")
        part = PartResult(RefPart("a.c", 10, 10, "10"), "SHIFTED", None, 14, 14, [])
        report = self._report([
            self._prose_entry("a.c:10", [part]),
            self._prose_entry("a.c:10", [part], "quirks"),
        ])
        self.assertEqual(
            rebase_refs(self.path, report),
            ["notes: a.c:10 -> a.c:14", "quirks: a.c:10 -> a.c:14"],
        )
        written = self.path.read_text()
        self.assertEqual(written, text.replace("(a.c:10)", "(a.c:14)"))
        self.assertEqual(profile_sync.pending_recale(report, text=written), 0)
        self.assertTrue(bump_commit(self.path, report))

    def test_a_refused_recale_names_the_citation_and_writes_nothing(self):
        # The structured ref could move, the prose could not: the run
        # printed nothing, wrote nothing, and the pin stayed.
        self.path.write_text(FOLDED_TWICE, encoding="utf-8")
        prose = PartResult(RefPart("q.c", 7, 7, "7"), "SHIFTED", None, 9, 9, [])
        structured = PartResult(RefPart("a.c", 10, 12), "SHIFTED", None, 14, 16, [])
        report = self._report([
            self._prose_entry("q.c:7", [prose], "twice"),
            EntryReport("a.bin", "a.c:10-12", "SHIFTED", [structured]),
        ])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(rebase_refs(self.path, report), [])
        self.assertIn(
            "p: not recaled, cannot move twice: q.c:7 (0 lines carry its sentence)",
            err.getvalue(),
        )
        self.assertEqual(self.path.read_text(), FOLDED_TWICE)

    def test_folded_scalar_moves_through_its_run_token(self):
        text = PROSE_SAMPLE.replace(
            "files:",
            "quirk_note: >\n  Loaded beside the card\n  (q.c:7). Checked"
            " later.\nfiles:",
        )
        self.path.write_text(text, encoding="utf-8")
        part = PartResult(RefPart("q.c", 7, 7, "7"), "SHIFTED", None, 9, 9, [])
        applied = rebase_refs(
            self.path,
            self._report([self._prose_entry("q.c:7", [part], "quirk_note")]),
        )
        self.assertEqual(applied, ["quirk_note: q.c:7 -> q.c:9"])
        content = self.path.read_text()
        self.assertIn("(q.c:9). Checked", content)
        self.assertIn(
            "(q.c:9).", yaml.safe_load(content)["quirk_note"]
        )

    def test_folded_rename_keeps_the_separator_as_written(self):
        # boom3 cites libretro.cpp:1635-1643, 2384-2405 in a folded note.
        # The rename rewrote the run as one token without the space, and
        # the written document no longer matched the intended one.
        text = PROSE_SAMPLE.replace(
            "files:",
            "quirk_note: >\n  Passes fs_game\n  (q.c:10-12, 30-40). Checked"
            " later.\nfiles:",
        )
        self.path.write_text(text, encoding="utf-8")
        parts = [
            PartResult(RefPart("q.c", 10, 12, "10-12"), "RENAMED", "src/q.c", 20, 22, []),
            PartResult(RefPart("q.c", 30, 40, "30-40"), "RENAMED", "src/q.c", 50, 60, []),
        ]
        applied = rebase_refs(
            self.path,
            self._report([self._prose_entry("q.c:10-12, 30-40", parts, "quirk_note")]),
        )
        self.assertEqual(
            applied, ["quirk_note: q.c:10-12, 30-40 -> src/q.c:20-22, 50-60"]
        )
        self.assertIn(
            "(src/q.c:20-22, 50-60).",
            yaml.safe_load(self.path.read_text())["quirk_note"],
        )

    def test_parts_disagreeing_on_the_new_file_do_not_move(self):
        parts = [
            PartResult(RefPart("b.c", 2, 2, "2"), "RENAMED", "src/b.c", 5, 5, []),
            PartResult(RefPart("b.c", 8, 9, "8-9"), "RENAMED", "old/b.c", 11, 12, []),
        ]
        applied = rebase_refs(
            self.path, self._report([self._prose_entry("b.c:2,8-9", parts)])
        )
        self.assertEqual(applied, [])

    def test_renamed_prose_path_is_rewritten(self):
        part = PartResult(
            RefPart("a.c", 10, 10, "10"), "RENAMED", "src/a.c", 14, 14, []
        )
        applied = rebase_refs(
            self.path, self._report([self._prose_entry("a.c:10", [part])])
        )
        self.assertEqual(applied, ["notes: a.c:10 -> src/a.c:14"])
        self.assertIn("(src/a.c:14)", self.path.read_text())


class TestPendingProse(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.yml"
        self.path.write_text(PROSE_SAMPLE, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def _report(self, parts):
        status = worst_status([p.status for p in parts])
        entry = EntryReport("notes", "a.c:10", status, parts, "prose", "notes")
        return ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[entry], counts={status: 1},
        )

    def test_moved_prose_still_in_the_file_blocks_the_pin(self):
        part = PartResult(RefPart("a.c", 10, 10, "10"), "SHIFTED", None, 14, 14, [])
        report = self._report([part])
        text = self.path.read_text()
        self.assertEqual(profile_sync.pending_recale(report, text=text), 1)
        self.assertFalse(bump_commit(self.path, report))
        self.assertEqual(
            yaml.safe_load(self.path.read_text())["source_commit"], "pin"
        )

    def test_recaled_prose_lets_the_pin_advance(self):
        part = PartResult(RefPart("a.c", 10, 10, "10"), "SHIFTED", None, 14, 14, [])
        report = self._report([part])
        rebase_refs(self.path, report)
        self.assertTrue(bump_commit(self.path, report))
        self.assertEqual(
            yaml.safe_load(self.path.read_text())["source_commit"], "newhead"
        )

    def test_anchored_prose_never_blocks(self):
        part = PartResult(RefPart("a.c", 10, 10, "10"), "ANCHORED", None, None, None, [])
        report = self._report([part])
        self.assertEqual(
            profile_sync.pending_recale(report, text=self.path.read_text()), 0
        )
        self.assertTrue(bump_commit(self.path, report))

    def test_unwritable_prose_blocks_the_pin(self):
        self.path.write_text(FOLDED_TWICE, encoding="utf-8")
        part = PartResult(RefPart("q.c", 7, 7, "7"), "SHIFTED", None, 9, 9, [])
        report = self._report([part])
        report.entries[0] = EntryReport(
            "twice", "q.c:7", "SHIFTED", [part], "prose", "twice"
        )
        self.assertEqual(rebase_refs(self.path, report), [])
        self.assertFalse(bump_commit(self.path, report))


class TestWrappedProse(unittest.TestCase):
    """A literal block keeps its breaks: gearcoleco wrote `(libretro.cpp:`
    and put its four ranges on the next line, which the scan never read."""

    TEXT = PROSE_SAMPLE.replace(
        "files:",
        "adam: |\n  Loaded by the ADAM entry points (libretro.cpp:\n"
        "  2372-2373, 2429-2433) and by c.c:5-6,\n  40-41 at boot.\n"
        "  The data root is set in s.cpp:\n    1. -datadir\nfiles:",
    )

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.yml"
        self.path.write_text(self.TEXT, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_both_wraps_are_read_whole(self):
        runs = {
            c.ref: c.wrapped
            for c in profile_sync.collect_citations(yaml.safe_load(self.TEXT))
            if c.field == "adam"
        }
        self.assertEqual(
            runs,
            {"libretro.cpp:2372-2373, 2429-2433": True, "c.c:5-6, 40-41": True},
        )

    def test_a_break_before_the_colon_is_read_whole(self):
        # jgenesis wrote `(frontend/.../config.rs` then `:76-78,95-99)` on the
        # next line, and the citation was never collected.
        text = PROSE_SAMPLE.replace(
            "files:",
            "cfg: |\n  Read from the config (src/config.rs\n  :76-78,95-99) at start.\nfiles:",
        )
        runs = {
            c.ref: c.wrapped
            for c in profile_sync.collect_citations(yaml.safe_load(text))
            if c.field == "cfg"
        }
        self.assertEqual(runs, {"src/config.rs:76-78,95-99": True})

    def _report(self, ref, parts):
        return ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[EntryReport("adam", ref, "SHIFTED", parts, "prose", "adam")],
            counts={"SHIFTED": 1},
        )

    def test_a_wrapped_run_moves_on_both_lines_and_the_pin_follows(self):
        # gearcoleco put its four ranges on the line after `libretro.cpp:`,
        # and the run held the pin with nothing written and nothing said.
        parts = [
            PartResult(RefPart("libretro.cpp", 2372, 2373, "2372-2373"),
                       "SHIFTED", None, 2381, 2382, []),
            PartResult(RefPart("libretro.cpp", 2429, 2433, "2429-2433"),
                       "SHIFTED", None, 2438, 2442, []),
        ]
        report = self._report("libretro.cpp:2372-2373, 2429-2433", parts)
        self.assertEqual(len(rebase_refs(self.path, report)), 1)
        text = self.path.read_text()
        self.assertIn("(libretro.cpp:\n  2381-2382, 2438-2442) and by", text)
        self.assertTrue(bump_commit(self.path, report))

    def test_a_break_before_the_colon_moves_the_next_line(self):
        # playdiaemu wrote `.../src/content.rs` and `:111-199` one line apart.
        text = PROSE_SAMPLE.replace(
            "files:",
            "adam: |\n  ZIP archives from the game path (src/content.rs\n"
            "  :111-199). No other file is opened.\nfiles:",
        )
        self.path.write_text(text, encoding="utf-8")
        part = PartResult(RefPart("src/content.rs", 111, 199, "111-199"),
                          "CHANGED", None, 111, 204, [])
        report = self._report("src/content.rs:111-199", [part])
        report.counts = {"CHANGED": 1}
        self.assertEqual(
            rebase_refs(self.path, report, accept_changed=True),
            ["adam: src/content.rs:111-199 -> src/content.rs:111-204"],
        )
        self.assertIn("(src/content.rs\n  :111-204). No", self.path.read_text())
        self.assertTrue(bump_commit(self.path, report, accept_changed=True))


class TestOpcodeCache(unittest.TestCase):
    """The diff cache was keyed by id() of lists anchor_block builds and frees
    on return: a later pair at the same addresses read another file's
    opcodes, and a CHANGED ref could be mapped onto the wrong line."""

    def test_each_pair_gets_its_own_diff(self):
        import difflib

        for n in range(200):
            pin = [f"line {n} {i}" for i in range(n % 7 + 2)]
            head = [f"line {n} {i}" for i in range(n % 5 + 1)] + [f"new {n}"]
            expected = difflib.SequenceMatcher(
                None, pin, head, autojunk=False
            ).get_opcodes()
            self.assertEqual(profile_sync._opcodes(list(pin), list(head)), expected)


class TestCommentCitations(unittest.TestCase):
    """The loader drops comments: zesarux's `# rom_load switch,
    src/cpu.c:3212-3451` stayed on the old lines under a new pin."""

    TEXT = PROSE_SAMPLE.replace(
        "files:",
        "# rom_load switch, src/cpu.c:3212-3451\n"
        "quirk: |\n  # not a comment x.c:5 inside a block\n"
        "label: \"quoted # y.c:7\"\n"
        "files:",
    ).replace('source_ref: "a.c:10-12"', 'source_ref: "a.c:10-12"  # see z.c:9')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.yml"
        self.path.write_text(self.TEXT, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_comments_only(self):
        found = [c.ref for c in profile_sync.comment_citations(self.TEXT)]
        self.assertEqual(found, ["src/cpu.c:3212-3451", "z.c:9"])
        document = yaml.safe_load(self.TEXT)
        self.assertNotIn(
            "src/cpu.c:3212-3451",
            [c.ref for c in profile_sync.collect_citations(document)],
        )
        self.assertIn(
            "src/cpu.c:3212-3451",
            [c.ref for c in profile_sync.collect_citations(document, self.TEXT)],
        )

    def _report(self, index, part):
        field = profile_sync.comment_citations(self.TEXT)[index].field
        return ProfileReport(
            name="p", repo="o/n", pin="pin", head="newhead",
            entries=[EntryReport("comment", f"{part.part.path}:{part.part.raw}",
                                 part.status, [part], "prose", field)],
            counts={part.status: 1},
        )

    def test_a_comment_run_moves_and_the_pin_follows(self):
        # amiarcadia `# da.h:3-5` and mame2003_plus `core_options.c:223-236`
        # held the pin, and --rebase-refs wrote nothing and said nothing.
        part = PartResult(RefPart("src/cpu.c", 3212, 3451, "3212-3451"),
                          "SHIFTED", None, 3268, 3507, [])
        report = self._report(0, part)
        self.assertEqual(
            rebase_refs(self.path, report),
            ["comment line 10: src/cpu.c:3212-3451 -> src/cpu.c:3268-3507"],
        )
        self.assertEqual(
            self.path.read_text(),
            self.TEXT.replace("src/cpu.c:3212-3451", "src/cpu.c:3268-3507"),
        )
        self.assertTrue(bump_commit(self.path, report))

    def test_a_renamed_comment_path_is_rewritten(self):
        # bennugd `libretro.c:887-910` in a comment: RENAMED to
        # libretro/libretro.c, same lines, and nothing moved.
        part = PartResult(RefPart("z.c", 9, 9, "9"), "RENAMED", "src/z.c", 9, 9, [])
        report = self._report(1, part)
        self.assertEqual(
            rebase_refs(self.path, report), ["comment line 16: z.c:9 -> src/z.c:9"]
        )
        self.assertIn('"a.c:10-12"  # see src/z.c:9', self.path.read_text())
        self.assertTrue(bump_commit(self.path, report))


class TestRealignProse(unittest.TestCase):
    """A prose scalar written under an older pin realigns from that pin."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.path = self.dir / "p.yml"
        self.files: dict[tuple[str, str], list[str]] = {}
        self._orig = (
            profile_sync.upstream.fetch_file,
            profile_sync.upstream.list_tree,
        )
        profile_sync.upstream.fetch_file = (
            lambda repo, sha, path, cache_dir, offline=False: self.files.get(
                (sha, path)
            )
        )
        profile_sync.upstream.list_tree = (
            lambda repo, sha, cache_dir, offline=False: (
                sorted({p for _, p in self.files}), False
            )
        )

    def tearDown(self):
        (
            profile_sync.upstream.fetch_file,
            profile_sync.upstream.list_tree,
        ) = self._orig
        self.tmp.cleanup()

    def _git(self, *argv):
        subprocess.run(
            ["git", "-c", "commit.gpgsign=false", *argv],
            cwd=self.dir, capture_output=True, check=True,
        )

    def _commit(self, text, message):
        self.path.write_text(text, encoding="utf-8")
        self._git("add", "p.yml")
        self._git("commit", "-m", message)

    def _repo_with_advanced_pin(self):
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        written = PROSE_SAMPLE.replace('"pin"', '"oldpin"')
        self._commit(written, "profile")
        # The pin advances in the working tree, the text stays committed.
        self.path.write_text(PROSE_SAMPLE, encoding="utf-8")

    def test_run_realigns_from_the_writing_pin(self):
        self._repo_with_advanced_pin()
        # At the writing pin line 10 is the subject. At the current pin the
        # same content sits on line 14. Anchoring from the current pin would
        # track whatever occupies line 10 there instead.
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        self.files[("oldpin", "b.c")] = ["p", "two", "q", "r", "s", "t", "u", "eight", "nine"]
        self.files[("pin", "b.c")] = ["p", "two", "q", "r", "s", "t", "u", "eight", "nine"]
        messages = profile_sync.realign_prose(self.path, self.tmp.name)
        self.assertIn("notes: a.c:10 -> a.c:14", messages)
        text = self.path.read_text()
        self.assertIn("(a.c:14)", text)
        self.assertIn("(b.c:2,8-9)", text)
        self.assertEqual(
            yaml.safe_load(text)["source_commit"], "pin",
        )

    def test_two_entries_sharing_a_name_keep_their_own_history(self):
        # supermodel declares Games.xml once per build mode. Both notes
        # answered to files[Games.xml].note, and the history of the libretro
        # note decided where the standalone note was written.
        sample = (
            'emulator: Test\n'
            'source: "https://github.com/o/n"\n'
            'source_commit: "oldpin"\n'
            'files:\n'
            '  - name: "Games.xml"\n'
            '    mode: standalone\n'
            '    note: "Parsed at startup (a.c:10)."\n'
            '  - name: "Games.xml"\n'
            '    mode: libretro\n'
            '    note: "Read through the VFS (b.c:2)."\n'
        )
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        self._commit(sample, "profile")
        # The pin advances and the libretro note is rewritten, uncommitted.
        self.path.write_text(
            sample.replace('"oldpin"', '"pin"').replace("(b.c:2)", "(b.c:5)"),
            encoding="utf-8",
        )
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        self.files[("pin", "b.c")] = ["p"] * 4 + ["read"]
        messages = profile_sync.realign_prose(self.path, self.tmp.name, dry_run=True)
        self.assertEqual(
            messages,
            ["would recale files[Games.xml@standalone].note: a.c:10 -> a.c:14"],
        )

    def test_pin_moved_under_committed_text_is_not_guessed(self):
        """A committed pin change under the same text may be a correction.

        vitaquake2 kept its notes while 38fc9331 re-pinned it onto the
        revision those notes described. Realigning from the first pin moved
        correct citations onto unrelated code.
        """
        self._repo_with_advanced_pin()
        self._commit(PROSE_SAMPLE, "put the pin on the revision the refs describe")
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")
        before = self.path.read_text()
        messages = profile_sync.realign_prose(self.path, self.tmp.name)
        self.assertTrue(
            any("pin moved under this text" in m for m in messages), messages
        )
        self.assertEqual(self.path.read_text(), before)

    def test_rewording_around_citations_keeps_the_writing_pin(self):
        """Punctuation edited in a note after a bump is not a new writing.

        Keyed on the whole text, the rewording commit became the writing
        revision, its pin was current, and the bump that had left the
        citations behind was no longer reported.
        """
        self._repo_with_advanced_pin()
        self._commit(PROSE_SAMPLE, "advance the pin")
        self._commit(
            PROSE_SAMPLE.replace("on boot.", "at boot."), "reword the note"
        )
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")
        messages = profile_sync.realign_prose(self.path, self.tmp.name, dry_run=True)
        self.assertTrue(
            any("pin moved under this text" in m for m in messages), messages
        )

    def test_a_citation_corrected_beside_another_dates_only_itself(self):
        """idtech4a++ advanced its pin in the commit that corrected two
        citations of its notes by hand. Dated per field, the untouched
        Game.java:69-72 took that commit's current pin and was never
        offered again, though its lines had moved."""
        self._repo_with_advanced_pin()
        self._commit(
            PROSE_SAMPLE.replace("(b.c:2,8-9)", "(b.c:3,9-10)"),
            "advance the pin, b.c corrected by hand",
        )
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        self.files[("pin", "b.c")] = list("pqrstuvwxyz")
        messages = profile_sync.realign_prose(self.path, self.tmp.name, dry_run=True)
        flagged = [m for m in messages if "a.c:10" in m]
        self.assertTrue(flagged, messages)
        self.assertFalse([m for m in messages if "b.c:" in m], messages)

    def test_a_source_declared_gone_is_read_through_its_mirror(self):
        """teknogods/TeknoParrotUI answers 404. Read there, every citation
        written under the old pin was absent and blocked the profile."""
        self._repo_with_advanced_pin()
        self._commit(
            PROSE_SAMPLE.replace(
                'source_commit: "pin"\n',
                'source_commit: "pin"\n'
                'upstream_gone: "o/n answers 404."\n'
                'source_mirror: "https://github.com/m/n"\n',
            ),
            "advance the pin, declare the forge gone",
        )
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")
        served = profile_sync.upstream.fetch_file
        profile_sync.upstream.fetch_file = (
            lambda repo, sha, path, cache_dir, offline=False: (
                served(repo, sha, path, cache_dir, offline)
                if repo.slug == "m/n" else None
            )
        )
        messages = profile_sync.realign_prose(self.path, self.tmp.name, dry_run=True)
        # b.c did not move between the two pins: nothing to read again.
        self.assertFalse([m for m in messages if "b.c:" in m], messages)

    def test_a_citation_in_an_unmoved_upstream_needs_no_reading(self):
        """nethersx2 cites AetherSX2 files that only its upstream carries,
        at an upstream pin that never moved. The port's pin did move under
        the text, and the reading through the port called each file absent
        while the other said nothing: thirteen disagreements on every run."""
        sample = (
            'emulator: Test\n'
            'source: "https://github.com/o/port"\n'
            'upstream: "https://github.com/o/up"\n'
            'source_commit: "oldpin"\n'
            'upstream_commit: "uppin"\n'
            'notes: |\n'
            '  The BIOS check lives upstream (up.c:5).\n'
        )
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        self._commit(sample, "profile")
        self._commit(sample.replace('"oldpin"', '"pin"'), "advance the port")
        self.files[("uppin", "up.c")] = ["a", "b", "c", "d", "check bios"]
        before = self.path.read_text()
        messages = profile_sync.realign_prose(self.path, self.tmp.name, dry_run=True)
        self.assertFalse(
            any("readings disagree" in m for m in messages), messages
        )
        self.assertEqual(self.path.read_text(), before)

    def test_dry_run_writes_nothing(self):
        self._repo_with_advanced_pin()
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")
        messages = profile_sync.realign_prose(
            self.path, self.tmp.name, dry_run=True
        )
        self.assertTrue(any("would recale" in m for m in messages))
        self.assertIn("(a.c:10)", self.path.read_text())

    def test_an_unreadable_history_blocks_rather_than_passes(self):
        """git failing (no repository, dubious ownership) read as "nothing
        written under an older pin" and let a bump through."""
        self.path.write_text(PROSE_SAMPLE, encoding="utf-8")
        messages = profile_sync.realign_prose(self.path, self.tmp.name, dry_run=True)
        self.assertEqual(messages, ["read again: p.yml: git history unreadable"])

    def test_an_unreadable_revision_stops_the_move(self):
        self._repo_with_advanced_pin()
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        with mock.patch.object(profile_sync, "_git_file_at", return_value=None):
            messages = profile_sync.realign_prose(self.path, self.tmp.name)
        self.assertTrue(messages)
        self.assertTrue(all(m.startswith("read again: notes:") for m in messages))
        self.assertIn("(a.c:10)", self.path.read_text())

    def _repo_with_a_broken_revision(self, broken_pin: str):
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        written = PROSE_SAMPLE.replace('"pin"', '"oldpin"')
        self._commit(written, "profile")
        broken = PROSE_SAMPLE.replace('"pin"', f'"{broken_pin}"')
        self._commit(broken + "files: [\n", "invalid yaml")
        self._commit(written, "repair")
        self.path.write_text(PROSE_SAMPLE, encoding="utf-8")
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["x"] * 13 + ["subject"]
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")

    def test_a_revision_that_does_not_parse_is_passed_over(self):
        """lindbergh-loader committed invalid YAML once, repaired the same
        day under the same pin. Every older note was reported unreadable
        and the recale stayed refused for good."""
        self._repo_with_a_broken_revision("oldpin")
        messages = profile_sync.realign_prose(self.path, self.tmp.name, dry_run=True)
        self.assertFalse(any("unreadable" in m for m in messages), messages)
        self.assertTrue(any("would recale" in m for m in messages), messages)

    def test_a_revision_that_does_not_parse_still_blocks_when_it_can_matter(self):
        """The pins differ across the gap and the note's citations changed:
        the text may have come in there under either pin."""
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        self._commit(
            PROSE_SAMPLE.replace('"pin"', '"older"').replace("a.c:10", "a.c:3"),
            "profile",
        )
        self._commit(PROSE_SAMPLE + "files: [\n", "invalid yaml")
        self._commit(PROSE_SAMPLE.replace('"pin"', '"oldpin"'), "repair")
        self.path.write_text(PROSE_SAMPLE, encoding="utf-8")
        messages = profile_sync.realign_prose(self.path, self.tmp.name, dry_run=True)
        self.assertTrue(any("unreadable" in m for m in messages), messages)

    def test_a_deleted_namesake_is_not_the_profiles_history(self):
        """mupen64plus.yml was renamed away in March, and a new standalone
        profile took the name in October. The deletion commit holds no file,
        so the older revisions were read as a gap and every note reported
        unreadable."""
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        self._commit(
            PROSE_SAMPLE.replace('"pin"', '"older"').replace("a.c:10", "a.c:3"),
            "old profile",
        )
        self._git("rm", "-q", "p.yml")
        self._git("commit", "-m", "rename away")
        self._commit(PROSE_SAMPLE, "new profile")
        self.files[("pin", "a.c")] = ["x"] * 9 + ["subject"]
        self.assertEqual(
            profile_sync.realign_prose(self.path, self.tmp.name, dry_run=True), []
        )

    def test_scalar_written_at_the_current_pin_is_left_alone(self):
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        self._commit(PROSE_SAMPLE, "profile")
        self.files[("pin", "a.c")] = ["x"] * 9 + ["subject"]
        self.assertEqual(
            profile_sync.realign_prose(self.path, self.tmp.name), []
        )

    def test_range_lost_between_the_pins_is_reported_not_moved(self):
        self._repo_with_advanced_pin()
        self.files[("oldpin", "a.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "a.c")] = ["y"] * 20
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")
        messages = profile_sync.realign_prose(self.path, self.tmp.name)
        self.assertTrue(any("read again" in m for m in messages))
        self.assertIn("(a.c:10)", self.path.read_text())

    def test_unreadable_tree_is_not_an_absence(self):
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        base = PROSE_SAMPLE.replace("(a.c:10)", "(deep.c:10)")
        self._commit(base.replace('"pin"', '"oldpin"'), "profile")
        self.path.write_text(base, encoding="utf-8")
        profile_sync.upstream.list_tree = (
            lambda repo, sha, cache_dir, offline=False: ([], True)
        )
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")
        messages = profile_sync.realign_prose(self.path, self.tmp.name)
        self.assertTrue(
            any("tree unreadable" in m for m in messages), messages
        )
        self.assertFalse(any("absent at the writing" in m for m in messages))

    def test_several_paths_carrying_the_name_stay_unclear(self):
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        base = PROSE_SAMPLE.replace("(a.c:10)", "(deep.c:10)")
        self._commit(base.replace('"pin"', '"oldpin"'), "profile")
        self.path.write_text(base, encoding="utf-8")
        self.files[("oldpin", "src/deep.c")] = ["x"]
        self.files[("oldpin", "contrib/deep.c")] = ["y"]
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")
        messages = profile_sync.realign_prose(self.path, self.tmp.name)
        self.assertTrue(
            any("2 paths carry the name" in m for m in messages), messages
        )

    def test_bare_filename_resolves_through_the_tree(self):
        self._git("init", "-q")
        self._git("config", "user.email", "t@t")
        self._git("config", "user.name", "t")
        base = PROSE_SAMPLE.replace("(a.c:10)", "(deep.c:10)")
        self._commit(base.replace('"pin"', '"oldpin"'), "profile")
        self.path.write_text(base, encoding="utf-8")
        self.files[("oldpin", "src/deep.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "src/deep.c")] = ["x"] * 13 + ["subject"]
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")
        messages = profile_sync.realign_prose(self.path, self.tmp.name)
        self.assertIn("notes: deep.c:10 -> deep.c:14", messages)
        self.assertIn("(deep.c:14)", self.path.read_text())


class TestRateLimitEndsOneProfile(unittest.TestCase):
    """git.libretro.com answered 429 on cemu's tree and the pass over 647
    profiles stopped with a traceback and no report at all."""

    def test_the_pass_goes_on_and_fails(self):
        from unittest import mock

        def build(name, *_args, **_kwargs):
            if name == "cemu":
                raise profile_sync.upstream.RateLimitError(
                    "https://git.libretro.com/x: HTTP 429", "git.libretro.com"
                )
            return ProfileReport(name=name, counts={"CHANGED": 1})

        out, err = io.StringIO(), io.StringIO()
        saved = sys.argv
        try:
            sys.argv = ["profile_sync.py", "--all", "--json"]
            with mock.patch.object(profile_sync, "load_emulator_profiles", return_value={}), \
                    mock.patch.object(profile_sync, "select_profiles",
                                      return_value={"cemu": {}, "after": {}}), \
                    mock.patch.object(profile_sync, "_check_quota"), \
                    mock.patch.object(profile_sync, "build_report", side_effect=build), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                with self.assertRaises(SystemExit) as caught:
                    profile_sync.main()
        finally:
            sys.argv = saved
        self.assertEqual(caught.exception.code, 1)
        by_name = {r["name"]: r for r in json.loads(out.getvalue())}
        self.assertEqual(by_name["cemu"]["skipped"], "rate limited: git.libretro.com")
        self.assertEqual(by_name["after"]["needs_review"], 1)


class AWriteRefreshesTheSourcePaths(unittest.TestCase):
    """Each bump left website/src/data/source-paths.json behind its pins and
    the site's freshness test red until someone ran sitesources by hand."""

    def _args(self, **kw):
        base = {"dry_run": False, "offline": False, "emulators_dir": "emulators"}
        return argparse.Namespace(**{**base, **kw})

    def test_only_a_real_online_write_refreshes(self):
        from unittest import mock  # noqa: PLC0415

        import sitesources  # noqa: PLC0415

        with mock.patch.object(sitesources, "build_source_paths", return_value=({}, [])) as built, \
                mock.patch.dict(os.environ, {"RETROBIOS_OFFLINE": ""}), \
                mock.patch.object(profile_sync, "load_emulator_profiles", return_value={}), \
                mock.patch("common.write_if_changed") as written, \
                contextlib.redirect_stderr(io.StringIO()):
            profile_sync._WRITTEN.clear()
            profile_sync._refresh_source_paths(self._args())
            self.assertFalse(built.called)
            profile_sync._WRITTEN.add("x")
            profile_sync._refresh_source_paths(self._args(dry_run=True))
            self.assertFalse(built.called)
            profile_sync._refresh_source_paths(self._args())
            self.assertTrue(built.called and written.called)
            profile_sync._WRITTEN.clear()


    def test_the_record_reads_the_pins_just_written(self):
        # The loader caches by directory and the run had loaded the profiles
        # before writing them: the record kept the pins it had replaced.
        from unittest import mock  # noqa: PLC0415

        import common  # noqa: PLC0415
        import sitesources  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "p.yml"
            profile.write_text('emulator: P\nsource_commit: "old"\n', encoding="utf-8")
            common._emulator_profiles_cache.clear()
            self.addCleanup(common._emulator_profiles_cache.clear)
            common.load_emulator_profiles(tmp, skip_aliases=False)
            profile.write_text('emulator: P\nsource_commit: "new"\n', encoding="utf-8")
            with mock.patch.object(sitesources, "build_source_paths", return_value=({}, [])) as built, \
                    mock.patch.dict(os.environ, {"RETROBIOS_OFFLINE": ""}), \
                    mock.patch("common.write_if_changed"), \
                    contextlib.redirect_stderr(io.StringIO()), \
                    contextlib.redirect_stdout(io.StringIO()):
                profile_sync._WRITTEN.add("p")
                self.addCleanup(profile_sync._WRITTEN.clear)
                profile_sync._refresh_source_paths(self._args(emulators_dir=tmp))
            self.assertEqual(built.call_args[0][0]["p"]["source_commit"], "new")

class AnUnreadTreeKeepsItsRecord(unittest.TestCase):
    """sitesources --fetch, rate-limited by GitLab, dropped about twenty
    trees it never read from source-paths.json."""

    def test_unread_trees_carry_over(self):
        import sitesources  # noqa: PLC0415

        kept = sitesources.keep_unread(
            {"a@1": ["x.c"]}, ["b@2", "c@3"], {"b@2": ["y.c"], "a@1": ["old.c"]}
        )
        # c@3 was never read: recorded empty, it confirms no path.
        self.assertEqual(kept, {"a@1": ["x.c"], "b@2": ["y.c"], "c@3": []})


class FreshRefusesOffline(unittest.TestCase):
    def test_the_pair_is_refused(self):
        saved = sys.argv
        try:
            sys.argv = ["profile_sync.py", "--all", "--fresh", "--offline"]
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                profile_sync.main()
        finally:
            sys.argv = saved
        self.assertEqual(caught.exception.code, 1)


class TestOutputModesApplyTheirFlags(unittest.TestCase):
    """--changed-only narrows --json too. Extras are refused off the text report."""

    def _main(self, *argv):
        from unittest import mock

        clean = ProfileReport(name="clean")
        drift = ProfileReport(name="drift", counts={"CHANGED": 1})
        reports = {"clean": clean, "drift": drift}
        out, err = io.StringIO(), io.StringIO()
        saved = sys.argv
        try:
            sys.argv = ["profile_sync.py", "--all", *argv]
            with mock.patch.object(profile_sync, "load_emulator_profiles", return_value={}), \
                    mock.patch.object(profile_sync, "select_profiles",
                                      return_value={"clean": {}, "drift": {}}), \
                    mock.patch.object(profile_sync, "_check_quota"), \
                    mock.patch.object(profile_sync, "build_report",
                                      side_effect=lambda name, *a, **k: reports[name]), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    profile_sync.main()
                    code = 0
                except SystemExit as exc:
                    code = exc.code
        finally:
            sys.argv = saved
        return code, out.getvalue(), err.getvalue()

    def test_changed_only_narrows_json(self):
        code, out, _ = self._main("--changed-only", "--json")
        self.assertEqual(code, 0)
        self.assertEqual([r["name"] for r in json.loads(out)], ["drift"])

    def test_strict_fails_on_refs_to_review(self):
        """A new profile whose refs miss their value used to pass CI green."""
        code, out, _ = self._main("--changed-only", "--strict")
        self.assertEqual(code, 1)
        self.assertIn("drift", out)

    def test_strict_passes_when_nothing_is_to_review(self):
        from unittest import mock

        with mock.patch.object(ProfileReport, "needs_review", return_value=0):
            code, _, _ = self._main("--strict")
        self.assertEqual(code, 0)

    def test_strict_fails_on_prose_that_blocks_the_pin(self):
        """blastem read "0 to review" while its prose refused every bump."""
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            for name in ("clean", "drift"):
                (Path(tmp) / f"{name}.yml").write_text("emulator: x\n")
            stale = {"clean": ["read again: notes: a.c:5 (pin moved)"], "drift": []}
            with mock.patch.object(
                profile_sync, "realign_prose",
                side_effect=lambda path, *a, **k: stale[path.stem],
            ):
                code, out, _ = self._main(
                    "--changed-only", "--strict", "--emulators-dir", tmp,
                )
        self.assertEqual(code, 1)
        self.assertIn("clean", out)
        self.assertIn("prose under an older pin", out)

    def test_diffs_are_refused_with_json(self):
        code, _, err = self._main("--json", "--full-diff")
        self.assertEqual(code, 1)
        self.assertIn("--full-diff", err)

    def test_markdown_refuses_detection(self):
        code, _, err = self._main("--markdown", "--detect-new-files")
        self.assertEqual(code, 1)
        self.assertIn("--detect-new-files", err)

    def test_json_carries_detection(self):
        """check_freshness reads --json: a new upstream file or hash printed
        only in the text report stayed a human reading."""
        from unittest import mock

        def detect(args, profile, report):
            report.new_files = [
                {"path": "a.c", "line": 3, "name": "new.rom", "since_pin": True}
            ]
            report.new_hashes = [{"path": "a.c", "kind": "md5", "value": "0" * 32}]

        with mock.patch.object(profile_sync, "_attach_detection", side_effect=detect):
            code, out, err = self._main("--json", "--detect-new-files", "--watch-hashes")
        self.assertEqual(code, 0, err)
        rows = json.loads(out)
        self.assertEqual(rows[0]["new_files"][0]["name"], "new.rom")
        self.assertTrue(rows[0]["new_files"][0]["since_pin"])
        self.assertEqual(rows[0]["new_hashes"][0]["kind"], "md5")

    def test_json_carries_the_version_check(self):
        """check_freshness asks for --json --check-version: refused, its
        profile row read an empty report as unreadable on every run."""
        code, out, err = self._main("--json", "--check-version")
        self.assertEqual(code, 0, err)
        rows = json.loads(out)
        self.assertTrue(all("version" in row and "page_version" in row for row in rows))

    def test_rankings_refuse_the_version_check(self):
        code, _, err = self._main("--triage", "--check-version")
        self.assertEqual(code, 1)
        self.assertIn("--check-version", err)

    def test_a_profile_the_forge_failed_is_listed_and_fails_the_run(self):
        """Dropped by --changed-only, a 502 read as nothing to review."""
        from unittest import mock

        def build(name, *args, **kwargs):
            if name == "drift":
                raise profile_sync.upstream.UpstreamError("https://x: HTTP 502")
            return ProfileReport(name=name)

        out = io.StringIO()
        saved = sys.argv
        try:
            sys.argv = ["profile_sync.py", "--all", "--changed-only", "--json"]
            with mock.patch.object(profile_sync, "load_emulator_profiles", return_value={}), \
                    mock.patch.object(profile_sync, "select_profiles",
                                      return_value={"clean": {}, "drift": {}}), \
                    mock.patch.object(profile_sync, "_check_quota"), \
                    mock.patch.object(profile_sync, "build_report", side_effect=build), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    profile_sync.main()
        finally:
            sys.argv = saved
        self.assertEqual(caught.exception.code, 1)
        (row,) = json.loads(out.getvalue())
        self.assertEqual(row["name"], "drift")
        self.assertIn("upstream error", row["skipped"])


class TestReconcilePerFile(unittest.TestCase):
    def test_an_anchored_part_settles_only_its_own_file(self):
        anchored = PartResult(RefPart("libretro.c", 5, 5, "5"), "ANCHORED", None, None, None, [])
        same = PartResult(RefPart("libretro.c", 9, 9, "9"), "AMBIGUOUS", None, None, None, [])
        other = PartResult(RefPart("jg.c", 229, 230, "229-230"), "AMBIGUOUS", None, None, None, [])
        result = profile_sync.reconcile_self_check([anchored, same, other])
        self.assertEqual([p.status for p in result], ["ANCHORED", "ANCHORED", "AMBIGUOUS"])

    def test_a_settled_part_keeps_the_repository_of_its_anchor(self):
        anchored = PartResult(RefPart("mt32emu.h", 5112, 5112, "5112"), "ANCHORED",
                              None, None, None, [], repo="schelling/dosbox-pure")
        same = PartResult(RefPart("mt32emu.h", 5129, 5129, "5129"), "MOVED",
                          None, 5112, 5112, [5112])
        result = profile_sync.reconcile_self_check([anchored, same])
        self.assertEqual(result[1].status, "ANCHORED")
        self.assertEqual(result[1].repo, "schelling/dosbox-pure")

    def test_a_compared_part_is_never_rewritten(self):
        anchored = PartResult(RefPart("a.c", 5, 5, "5"), "ANCHORED", None, None, None, [])
        shifted = PartResult(RefPart("a.c", 9, 9, "9"), "SHIFTED", None, 12, 12, [])
        result = profile_sync.reconcile_self_check([anchored, shifted], [True, False])
        self.assertEqual(result[1].status, "SHIFTED")


class TestCollapsingMoves(unittest.TestCase):
    """A recale never folds two parts of one ref onto the same line."""

    def test_a_move_onto_a_sibling_part_goes_to_review(self):
        sha = PartResult(RefPart("mt32emu.h", 5112, 5112, "upstream mt32emu.h:5112", "upstream"),
                         "ANCHORED", None, None, None, [])
        info = PartResult(RefPart("mt32emu.h", 5129, 5129, "source mt32emu.h:5129", "source"),
                          "MOVED", None, 5112, 5112, [5112])
        result = profile_sync.refuse_collapsing_moves([sha, info])
        self.assertEqual([p.status for p in result], ["ANCHORED", "AMBIGUOUS"])

    def test_a_move_to_a_free_line_is_kept(self):
        first = PartResult(RefPart("a.c", 5, 5, "a.c:5"), "ANCHORED", None, None, None, [])
        moved = PartResult(RefPart("a.c", 9, 9, "a.c:9"), "MOVED", None, 12, 12, [12])
        result = profile_sync.refuse_collapsing_moves([first, moved])
        self.assertEqual(result[1].status, "MOVED")


class TestRealignFlagMatrix(unittest.TestCase):
    """--realign-prose applies a flag or refuses it, never swallows it."""

    def _run(self, *extra):
        argv = ["profile_sync.py", "--emulator", "x", "--realign-prose", *extra]
        stderr = io.StringIO()
        saved = sys.argv
        try:
            sys.argv = argv
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as caught:
                    profile_sync.main()
        finally:
            sys.argv = saved
        return caught.exception.code, stderr.getvalue()

    def test_output_flags_are_refused(self):
        for flag in (
            "--json", "--markdown", "--fetch-plan", "--triage",
            "--changed-only", "--strict", "--check-version", "--detect-new-files",
            "--watch-hashes", "--full-diff", "--tree-diff",
            "--accept-changed",
        ):
            code, err = self._run(flag)
            self.assertEqual(code, 1, flag)
            self.assertIn("does not apply", err, flag)

    def test_write_flags_are_refused(self):
        for flag in ("--rebase-refs", "--bump-commit", "--backfill-commits"):
            code, err = self._run(flag)
            self.assertEqual(code, 1, flag)
            self.assertIn("runs alone", err, flag)


class TestBuildReportProse(TestBuildReport):
    """Prose citations run through the same anchoring as source_refs."""

    def test_notes_citation_is_anchored_and_counted(self):
        profile = self._profile(["a.c:2"])
        profile["notes"] = "The loader reads it (a.c:2).\n"
        self.files[("pinsha", "a.c")] = ["x", "hit", "y"]
        self.files[("headsha", "a.c")] = ["pad", "x", "hit", "y"]
        report = build_report("test", profile, self.dir)
        self.assertEqual(report.counts["SHIFTED"], 2)
        prose = [e for e in report.entries if e.kind == "prose"]
        self.assertEqual(len(prose), 1)
        self.assertEqual(prose[0].name, "notes")
        self.assertEqual(prose[0].field, "notes")
        self.assertEqual(prose[0].parts[0].start, 3)

    def test_gone_prose_citation_needs_review(self):
        profile = self._profile(["a.c:2"])
        profile["notes"] = "Written by lost.c:9 at boot.\n"
        self.files[("pinsha", "a.c")] = ["x", "hit"]
        self.files[("headsha", "a.c")] = ["x", "hit"]
        report = build_report("test", profile, self.dir)
        self.assertEqual(report.counts.get("GONE"), 1)
        self.assertEqual(report.needs_review(), 1)

    def test_prose_only_profile_is_not_skipped(self):
        profile = {
            "emulator": "T",
            "source": "https://github.com/o/n",
            "profiled_date": "2026-03-29",
            "notes": "Boot path in a.c:2.\n",
        }
        self.files[("pinsha", "a.c")] = ["x", "hit"]
        self.files[("headsha", "a.c")] = ["x", "hit"]
        report = build_report("test", profile, self.dir)
        self.assertIsNone(report.skipped)
        self.assertEqual(report.entries[0].kind, "prose")


class TestEmulatorsDirStatus(unittest.TestCase):
    """git was asked from the current directory and its exit code ignored:
    a profile tree in another repository, or in none, read as clean, and
    --rebase-refs wrote over uncommitted profiles."""

    def _git(self, *args: str, cwd: str) -> None:
        subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)

    def test_a_tree_in_another_repository_answers_for_itself(self):
        with tempfile.TemporaryDirectory() as root:
            self._git("init", "-q", cwd=root)
            Path(root, "a.yml").write_text("emulator: a\n")
            self.assertTrue(profile_sync.emulators_dir_is_dirty(root))

    def test_only_the_selected_profiles_count(self):
        # A loop of --emulator X --rebase-refs refused every profile after
        # the first one it wrote.
        with tempfile.TemporaryDirectory() as root:
            self._git("init", "-q", cwd=root)
            Path(root, "a.yml").write_text("emulator: a\n")
            Path(root, "b.yml").write_text("emulator: b\n")
            self._git("add", "a.yml", "b.yml", cwd=root)
            self._git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "p", cwd=root)
            Path(root, "a.yml").write_text("emulator: a2\n")
            self.assertTrue(profile_sync.emulators_dir_is_dirty(root, ["a"]))
            self.assertFalse(profile_sync.emulators_dir_is_dirty(root, ["b"]))

    def test_the_refusal_names_the_changed_profile(self):
        """One profile changed by another session among ~375 refused the
        whole run without saying which."""
        with tempfile.TemporaryDirectory() as root:
            self._git("init", "-q", cwd=root)
            for name in "abc":
                Path(root, f"{name}.yml").write_text(f"emulator: {name}\n")
            self._git("add", "a.yml", "b.yml", "c.yml", cwd=root)
            self._git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "p", cwd=root)
            Path(root, "b.yml").write_text("emulator: b2\n")
            self.assertEqual(profile_sync.emulators_dir_is_dirty(root, ["a", "b", "c"]),
                             ["b.yml"])
            err = io.StringIO()
            with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
                profile_sync._refuse_dirty_tree(root, ["a", "b", "c"])
        self.assertIn("b.yml has uncommitted changes", err.getvalue())
        self.assertNotIn("a.yml", err.getvalue())

    def test_a_tree_outside_any_repository_is_not_clean(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.dict(
            os.environ, {"GIT_CEILING_DIRECTORIES": str(Path(root).parent)}
        ):
            with self.assertRaises(RuntimeError):
                profile_sync.emulators_dir_is_dirty(root)


class UpstreamVendoredAsASubmodule(unittest.TestCase):
    """libretro/TIC-80 builds nesbox/TIC-80 through its `core` submodule, and
    tic80's upstream_commit is that submodule's commit. Compared to nesbox's
    own HEAD it reported changes the shipped core never had, and a bump would
    have moved upstream_commit past what libretro builds."""

    def _views(self, links: dict) -> list:
        from unittest import mock  # noqa: PLC0415

        repo_s, repo_u = object(), object()
        views = [
            profile_sync.RepoView(repo_s, "src-pin", "src-head", "source_commit", "source"),
            profile_sync.RepoView(repo_u, "sub-old", "nesbox-tip", "upstream_commit", "upstream"),
        ]
        with mock.patch.object(
            profile_sync.upstream, "list_gitlinks",
            side_effect=lambda repo, sha, *a, **k: links.get(sha, {}),
        ):
            return profile_sync._follow_submodule(views, "cache", True)

    def test_the_upstream_head_is_what_the_port_head_builds(self):
        views = self._views({"src-pin": {"core": "sub-old"}, "src-head": {"core": "sub-new"}})
        self.assertEqual(views[1].head, "sub-new")
        self.assertEqual(views[0].head, "src-head")

    def test_an_upstream_the_port_does_not_vendor_keeps_its_tip(self):
        views = self._views({"src-pin": {"deps/zlib": "other"}, "src-head": {}})
        self.assertEqual(views[1].head, "nesbox-tip")


class AMirrorOutlivesAGoneSource(unittest.TestCase):
    """yuzu's source answers 451. select_views stopped on it and never read
    the source_mirror declared after it, so the profile stayed unchecked."""

    def test_the_mirror_is_read_when_the_source_is_gone(self):
        from unittest import mock  # noqa: PLC0415

        gone_repo = profile_sync.upstream.make_repo("github.com", "yuzu-emu-mirror", "yuzu")
        mirror = profile_sync.upstream.make_repo("github.com", "fork", "yuzu")

        def head(repo, cache_dir, offline=False, branch=None):
            if repo == gone_repo:
                raise profile_sync.upstream.GoneError("HTTP 451")
            return "mirror-head"

        profile = {
            "source": "https://github.com/yuzu-emu-mirror/yuzu",
            "source_mirror": "https://github.com/fork/yuzu",
            "source_commit": "pin",
        }
        with mock.patch.object(profile_sync.upstream, "resolve_head", side_effect=head), \
                mock.patch.object(profile_sync, "resolve_pin", return_value=("pin", "source_commit")):
            views = profile_sync.select_views(profile, "cache", True)
        self.assertEqual([(v.repo, v.field) for v in views], [(mirror, "source_mirror")])


class AHeldUpstreamStaysOnItsPin(unittest.TestCase):
    """aps3e vendors RPCS3 1f080485 and yaps2 PCSX2 342db515: a bump moved
    upstream_commit to the upstream HEAD neither port carries."""

    def test_the_upstream_view_is_read_at_its_pin(self):
        views = [
            profile_sync.RepoView("fork", "p", "h", "source_commit", "source"),
            profile_sync.RepoView("up", "vendored", "tip", "upstream_commit", "upstream"),
        ]
        held = profile_sync._hold_upstream({"upstream_frozen": "vendored tree"}, views)
        self.assertEqual((held[0].head, held[1].head), ("h", "vendored"))
        self.assertEqual(profile_sync._hold_upstream({}, views), views)


class RealignReadsThePathAsWritten(unittest.TestCase):
    """hatarib cites hatari/src/tos.c, a path of hatariB. When only
    upstream_commit moved, realign stripped the hatari/ prefix, read
    hatari/hatari's src/tos.c and proposed moving a correct citation."""

    def test_an_unmoved_repository_carrying_the_path_keeps_it(self):
        from unittest import mock  # noqa: PLC0415

        fork = profile_sync.upstream.make_repo("github.com", "b", "hatariB")
        up = profile_sync.upstream.make_repo("github.com", "hatari", "hatari")
        trees = {(fork, "fork-pin"): {"hatari/src/tos.c"},
                 (up, "old"): {"src/tos.c"}, (up, "new"): {"src/tos.c"}}

        def fetch(repo, sha, path, *a, **k):
            return ["line"] * 40 if path in trees.get((repo, sha), set()) else None

        part = profile_sync.RefPart("hatari/src/tos.c", 10, 10, "10")
        with mock.patch.object(profile_sync.upstream, "fetch_file", side_effect=fetch), \
                mock.patch.object(profile_sync, "_resolve_at",
                                  return_value=("found", ("src/tos.c", ["x"] * 40))):
            result = profile_sync._realign_part(
                part, [(up, "old", "new")], "cache", True,
                pinned=[(fork, "fork-pin"), (up, "new")],
            )
        self.assertIsNone(result)


class RealignGivesASharedPathToTheFirstRepository(unittest.TestCase):
    """freej2me-plus and hex007/freej2me both hold src/libretro/: with only
    upstream_commit moved, the fork's citations were read in upstream."""

    def test_the_source_declared_first_keeps_it(self):
        from unittest import mock  # noqa: PLC0415

        fork = profile_sync.upstream.make_repo("github.com", "t", "freej2me-plus")
        up = profile_sync.upstream.make_repo("github.com", "hex007", "freej2me")
        part = profile_sync.RefPart("src/libretro/freej2me_libretro.c", 39, 46, "39-46")
        with mock.patch.object(
            profile_sync.upstream, "fetch_file", return_value=["line"] * 99
        ), mock.patch.object(
            profile_sync, "_resolve_at", return_value=("found", (part.path, ["x"] * 99))
        ):
            result = profile_sync._realign_part(
                part, [(up, "eb4ac87", "8b9bc8a")], "cache", True,
                pinned=[(fork, "3933e75"), (up, "8b9bc8a")],
            )
        self.assertIsNone(result)


class UpstreamForkedByThePort(unittest.TestCase):
    """snes9x, kronos and np2kai pinned upstream_commit on the merge base of
    upstream with the fork. Compared to upstream's own HEAD, a bump moved it
    past anything the port carries."""

    def _views(self, base, ancestry=None):
        from unittest import mock  # noqa: PLC0415

        fork = profile_sync.upstream.make_repo("github.com", "f", "port")
        self.up = profile_sync.upstream.make_repo("github.com", "o", "up")
        self.fork = fork
        views = [
            profile_sync.RepoView(fork, "src-pin", "src-head", "source_commit", "source"),
            profile_sync.RepoView(self.up, "old-base", "up-tip", "upstream_commit", "upstream"),
        ]
        with mock.patch.object(
            profile_sync.upstream, "fork_base", return_value=base
        ) as asked, mock.patch.object(
            profile_sync.upstream, "ancestry", return_value=ancestry
        ):
            followed = profile_sync._follow_fork_base(views, "cache", True)
        return followed, asked

    def test_the_upstream_head_is_the_fork_base(self):
        views, asked = self._views("new-base")
        self.assertEqual(views[1].head, "new-base")
        self.assertEqual(
            asked.call_args.args[:4], (self.up, "up-tip", self.fork, "src-head")
        )

    def test_a_port_outside_the_network_keeps_the_tip(self):
        views, _ = self._views(None)
        self.assertEqual(views[1].head, "up-tip")

    def test_a_pin_newer_than_the_base_keeps_the_tip(self):
        """melonds documents the Qt standalone from melonDS-emu/melonDS: its
        upstream_commit is 825 commits past the merge base with the libretro
        fork, and reading its refs at the 2021 base reported them CHANGED."""
        views, _ = self._views("old-merge", ancestry=(825, 0))
        self.assertEqual(views[1].head, "up-tip")

    def test_a_pin_behind_the_base_follows_it(self):
        views, _ = self._views("new-base", ancestry=(0, 12))
        self.assertEqual(views[1].head, "new-base")


class ACachedTipOlderThanThePin(TestBuildReport):
    """scummvm-standalone was pinned on 6f7b060d while the cached tip was
    77d80d7, its ancestor: a bump would have moved the pin backwards."""

    def test_the_tip_is_asked_again(self):
        profile_sync.upstream.ancestry = lambda *a, **k: (0, 3)
        profile_sync.upstream.resolve_head = (
            lambda repo, cache_dir, offline=False, branch=None, fresh=False:
            "newtip" if fresh else "staletip"
        )
        self.files[("pinsha", "a.c")] = ["x", "hit"]
        self.files[("newtip", "a.c")] = ["x", "hit"]
        report = build_report("test", self._profile(["a.c:2"]), self.dir)
        self.assertEqual(report.head, "newtip")


class OfflineCacheMissIsNotGone(TestBuildReport):
    """Offline, a file the cache never stored came back as None and the
    report read "GONE (absent at HEAD, no rename found)" for files that
    exist. The miss now stops the profile as unverified."""

    def test_an_uncached_file_is_not_reported_gone(self):
        def cold(repo, sha, path, cache_dir, offline=False):
            raise profile_sync.upstream.NotCachedError(f"{path} not cached")

        profile_sync.upstream.fetch_file = cold
        with self.assertRaises(profile_sync.upstream.NotCachedError):
            build_report("test", self._profile(["a.c:2"]), self.dir, offline=True)



class TestSelectionNamesWhatMatchedNothing(unittest.TestCase):
    """`--all --system atari-lynxx` printed nothing and exited 0, which read
    as "no Lynx profile needs a re-read", and `--emulator handyy` offered no
    suggestion."""

    PROFILES = {
        "handy": {"type": "libretro", "systems": ["atari-lynx"]},
        "mednafen_lynx": {"type": "libretro", "systems": ["atari-lynx"]},
    }

    def _args(self, **values):
        base = {"emulator": None, "changed": False, "added": False,
                "system": None, "type_": None, "stale_before": None,
                "limit": None}
        return argparse.Namespace(**{**base, **values})

    def test_a_misspelt_system_stops_and_suggests(self):
        with self.assertRaises(SystemExit) as caught:
            profile_sync.select_profiles(self.PROFILES, self._args(system="atari-lynxx"))
        self.assertIn("atari-lynx", str(caught.exception.code))

    def test_a_misspelt_emulator_suggests(self):
        with self.assertRaises(SystemExit) as caught:
            profile_sync.select_profiles(self.PROFILES, self._args(emulator="handyy"))
        self.assertIn("Close matches: handy", str(caught.exception.code))

    def test_a_matching_filter_selects(self):
        selected = profile_sync.select_profiles(self.PROFILES, self._args(system="atari-lynx"))
        self.assertEqual(sorted(selected), ["handy", "mednafen_lynx"])

    def test_system_matches_as_the_listing_does(self):
        """verify.py --list-systems printed `saturn`, which selected 1 profile
        of 11 because 10 declare sega-saturn."""
        profiles = {
            "a": {"type": "libretro", "systems": ["sega-saturn"]},
            "b": {"type": "libretro", "systems": ["saturn"]},
        }
        for spelling in ("saturn", "sega-saturn"):
            selected = profile_sync.select_profiles(profiles, self._args(system=spelling))
            self.assertEqual(sorted(selected), ["a", "b"])

    def test_the_hint_counts_what_the_listing_prints(self):
        profiles = {
            "a": {"type": "libretro", "systems": ["sega-saturn"]},
            "b": {"type": "libretro", "systems": ["saturn"]},
            "c": {"type": "libretro", "systems": ["atari-lynx"]},
        }
        with self.assertRaises(SystemExit) as caught:
            profile_sync.select_profiles(profiles, self._args(system="nothing"))
        self.assertIn("Known: atari-lynx, sega-saturn.", str(caught.exception.code))



class TestTreeUrlIntoADirectory(unittest.TestCase):
    """`.../libretro-samples/tree/master/tests/cruzes` took the whole tail as
    the branch. Nothing resolved and cruzes was skipped as having no pin."""

    def test_candidates_are_prefixes_shortest_first(self):
        self.assertEqual(
            profile_sync.branch_candidates(
                "https://github.com/libretro/libretro-samples/tree/master/tests/cruzes"
            ),
            ["master", "master/tests", "master/tests/cruzes"],
        )
        self.assertEqual(profile_sync.branch_candidates("https://github.com/o/r"), [])

    def test_the_first_resolving_prefix_is_the_branch(self):
        from unittest import mock

        asked = []

        def head(repo, cache, offline=False, branch=None):
            asked.append(branch)
            return "tipsha" if branch == "master" else None

        profile = {"source": "https://github.com/libretro/libretro-samples/tree/master/tests/cruzes",
                   "source_commit": "pinsha"}
        with mock.patch.object(profile_sync.upstream, "resolve_head", side_effect=head):
            views = profile_sync.select_views(profile, ".cache", True)
        self.assertEqual([(v.pin, v.head) for v in views], [("pinsha", "tipsha")])
        self.assertEqual(asked[0], "master")



class TestAnUnansweringRepository(unittest.TestCase):
    """pyxel declares source_commit, yet the skip read "no source_commit":
    its repository answers 404. A declared upstream_gone was honoured only
    when the forge raised GoneError, never on a plain non-answer."""

    def _report(self, profile):
        from unittest import mock

        with mock.patch.object(profile_sync, "select_views", return_value=[]):
            return profile_sync.build_report("p", profile, ".cache", True)

    def test_a_declared_pin_names_the_repository(self):
        report = self._report({"source": "https://github.com/o/r", "source_commit": "abc",
                               "files": [{"name": "a", "source_ref": "a.c:1"}]})
        self.assertIn("no declared repository answers", report.skipped)

    def test_a_declared_gone_upstream_is_honoured(self):
        report = self._report({"source": "https://github.com/o/r", "source_commit": "abc",
                               "upstream_gone": "404 since 2026-10-18",
                               "files": [{"name": "a", "source_ref": "a.c:1"}]})
        self.assertEqual(report.skipped, "upstream gone (declared): 404 since 2026-10-18")


class TheUnknownProfileHintCountsTheListing(unittest.TestCase):
    """profile_sync said "verify.py --list-emulators lists all 553" for a
    listing of 530: the alias and test profiles it counted are not listed."""

    def test_the_count_matches(self):
        import subprocess  # noqa: PLC0415

        root = Path(__file__).resolve().parents[1]
        hint = subprocess.run(
            [sys.executable, "scripts/profile_sync.py", "--emulator", "no-such-profile"],
            cwd=root, capture_output=True, text=True, timeout=120, check=False,
        )
        listing = subprocess.run(
            [sys.executable, "scripts/verify.py", "--list-emulators"],
            cwd=root, capture_output=True, text=True, timeout=120, check=False,
        ).stdout
        count = len([line for line in listing.splitlines() if line.strip()])
        self.assertIn(f"lists all {count}.", hint.stderr + hint.stdout)


class StrictRefusesAnUncheckableProfile(unittest.TestCase):
    """A new profile whose repository answered 404, or with no pin at all,
    was skipped with empty counts and --strict passed it in CI."""

    def test_defects_are_told_from_the_profiles_nature(self):
        from profile_sync import ProfileReport

        def report(reason):
            return ProfileReport(name="p", entries=[], counts={}, skipped=reason)

        self.assertTrue(report("no declared repository answers (moved)").uncheckable())
        self.assertTrue(report(
            "no source_commit and no resolvable profiled_date on any declared repository"
        ).uncheckable())
        self.assertFalse(report("unsupported host: https://example.org").uncheckable())
        self.assertFalse(report("upstream gone (declared): taken down").uncheckable())
        self.assertFalse(report("no source_ref").uncheckable())


class AnOffForgeProfileWatchesItsReleasePage(unittest.TestCase):
    """Profiles of projects outside any forge were skipped as an unsupported
    host, and a new release of Altirra or mednafen went unseen."""

    def test_the_page_version_is_read(self):
        from unittest import mock

        profile = {"emulator": "Altirra", "core_version": "4.40", "version_source": {
            "url": "https://example.test/altirra", "pattern": r"Altirra (\d+\.\d+) released",
        }}
        with mock.patch.object(profile_sync.upstream, "fetch_page",
                               return_value="<p>Altirra 4.50 released</p>"):
            self.assertEqual(profile_sync.page_version(profile, "cache", False), "4.50")


class ARecaleKeepsTheRepositoryWord(unittest.TestCase):
    """`stella src/a.c:120` says the lines are in the stella repository. The
    path is read without the word, and a recale wrote it back without it."""

    def test_the_word_stays_in_front_of_the_new_span(self):
        from sourceref import split_source_ref

        for raw, expected in (
            ("stella src/a.c:120-130", "stella src/a.c:140-150"),
            ("stella src/a.c:120 (the table)", "stella src/a.c:140-150 (the table)"),
            ("src/a.c:120", "src/a.c:140-150"),
        ):
            with self.subTest(raw=raw):
                p = split_source_ref(raw)[0]
                part = profile_sync.RefPart(
                    profile_sync.strip_repo_word(p.path, {"stella"}), p.start, p.end, p.raw)
                result = profile_sync.PartResult(part, "SHIFTED", None, 140, 150, [], "")
                self.assertEqual(profile_sync._rendered_part(result), expected)


class EachCitationNamesTheCodeThatAsks(unittest.TestCase):
    """A profile reading a libretro core and the original emulator cited both
    trees alike, and readers could not tell which code asked for a file."""

    setUp = TestBuildReport.setUp
    tearDown = TestBuildReport.tearDown
    MD5 = "0123456789abcdef0123456789abcdef"
    TEXT = (
        'emulator: T\n'
        'source: "https://github.com/libretro/a5200"\n'
        'upstream: "https://github.com/alekmaul/a5200"\n'
        'source_commit: "pins"\n'
        'upstream_commit: "pinu"\n'
        'files:\n'
        '  - name: 5200.rom\n'
        f'    md5: {MD5}\n'
        '    source_ref: "{ref}"\n'
    )

    def _attribute(self, ref: str) -> str:
        trees = {
            "libretro/a5200": {"emu/memory.c": ["x", f"rom {self.MD5}"],
                               "libretro.c": [f"load {self.MD5}"]},
            "alekmaul/a5200": {"emu/memory.c": ["y", f"rom {self.MD5}"]},
        }
        profile_sync.upstream.fetch_file = (
            lambda repo, sha, path, cache_dir, offline=False:
            trees.get(repo.slug, {}).get(path)
        )
        profile_sync.upstream.list_tree = (
            lambda repo, sha, cache_dir, offline=False: (sorted(trees[repo.slug]), False)
        )
        profile_sync.upstream.resolve_head = (
            lambda repo, cache_dir, offline=False, branch=None:
            "pins" if repo.owner == "libretro" else "pinu"
        )
        path = Path(self.dir) / "t.yml"
        path.write_text(self.TEXT.replace("{ref}", ref), encoding="utf-8")
        profile = yaml.safe_load(path.read_text(encoding="utf-8"))
        with contextlib.redirect_stderr(io.StringIO()):
            report = build_report("t", profile, self.dir, text=path.read_text())
        profile_sync.attribute_refs(path, report, profile)
        return yaml.safe_load(path.read_text(encoding="utf-8"))["files"][0]["source_ref"]

    def test_emulator_code_the_port_carries_is_the_emulators(self):
        self.assertEqual(self._attribute("emu/memory.c:2, libretro.c:1"),
                         "upstream emu/memory.c:2, source libretro.c:1")

    def test_a_written_role_is_followed(self):
        self.assertEqual(self._attribute("source emu/memory.c:2"), "source emu/memory.c:2")


class ARoleIsReadPerPart(unittest.TestCase):
    """The role a part writes (`source a.c:3`) was stored per path, first met
    first kept: hypseus-singe's `upstream lair.cpp` decided where every later
    `source lair.cpp` was read, and correct refs were reported MOVED."""

    setUp = TestBuildReport.setUp
    tearDown = TestBuildReport.tearDown
    MD5A = "0123456789abcdef0123456789abcdef"
    MD5B = "fedcba9876543210fedcba9876543210"

    def _report(self, files: str, notes: str = "") -> ProfileReport:
        # The port inserted two lines above its copy of the table since its
        # pin, while the original sits on HEAD with the same table.
        trees = {
            ("libretro/x", "pins"): {"a.c": ["pad", "pad", f"rom {self.MD5B}"]},
            ("libretro/x", "heads"): {"a.c": ["pad", "pad", "new", "new",
                                              f"rom {self.MD5B}"]},
            ("alek/x", "pinu"): {"a.c": [f"rom {self.MD5A}", "x",
                                         f"rom {self.MD5B}"]},
        }
        profile_sync.upstream.fetch_file = (
            lambda repo, sha, path, cache_dir, offline=False:
            trees.get((repo.slug, sha), {}).get(path)
        )
        profile_sync.upstream.list_tree = (
            lambda repo, sha, cache_dir, offline=False:
            (sorted(trees.get((repo.slug, sha), {})), False)
        )
        profile_sync.upstream.resolve_head = (
            lambda repo, cache_dir, offline=False, branch=None:
            "heads" if repo.owner == "libretro" else "pinu"
        )
        profile_sync.upstream.compare = (
            lambda repo, base, head, cache_dir, offline=False:
            profile_sync.CompareResult([], False)
        )
        text = (
            'emulator: T\n'
            'source: "https://github.com/libretro/x"\n'
            'upstream: "https://github.com/alek/x"\n'
            'source_commit: "pins"\n'
            'upstream_commit: "pinu"\n'
            + (f"notes: |\n  {notes}\n" if notes else "")
            + "files:\n" + files
        )
        profile = yaml.safe_load(text)
        with contextlib.redirect_stderr(io.StringIO()):
            return build_report("t", profile, self.dir, text=text)

    def test_a_part_naming_its_repository_is_judged_there(self):
        report = self._report(
            "  - name: a.rom\n"
            f"    md5: {self.MD5A}\n"
            '    source_ref: "upstream a.c:1"\n'
            "  - name: b.rom\n"
            f"    md5: {self.MD5B}\n"
            '    source_ref: "source a.c:3"\n'
        )
        parts = {e.name: e.parts[0] for e in report.entries}
        self.assertEqual(parts["a.rom"].status, "ANCHORED")
        self.assertEqual(parts["a.rom"].repo, "alek/x")
        # Read in the original, where line 3 still holds the table, the
        # port's own move went unseen.
        self.assertEqual(parts["b.rom"].status, "SHIFTED")
        self.assertEqual(parts["b.rom"].start, 5)
        self.assertIsNone(parts["b.rom"].repo)

    def test_a_prose_source_word_is_a_role_not_a_project(self):
        report = self._report(
            "  - name: b.rom\n"
            f"    md5: {self.MD5B}\n"
            '    source_ref: "source a.c:3"\n',
            notes="ref: source a.c:3, more",
        )
        prose = [e for e in report.entries if e.kind == "prose"]
        self.assertEqual(len(prose), 1)
        self.assertNotEqual(prose[0].parts[0].status, "EXTERNAL")
        self.assertEqual(prose[0].parts[0].part.role, "source")

    def test_a_prose_upstream_word_names_the_repository(self):
        report = self._report(
            "  - name: b.rom\n"
            f"    md5: {self.MD5B}\n"
            '    source_ref: "source a.c:3"\n',
            notes="the original reads it (upstream a.c:1).",
        )
        prose = [e for e in report.entries if e.kind == "prose"]
        self.assertEqual(prose[0].parts[0].part.role, "upstream")
        self.assertEqual(prose[0].parts[0].repo, "alek/x")

    def test_the_prose_grammar_keeps_the_role(self):
        from sourceref import _prose_runs

        runs = list(_prose_runs(
            "# ref: source src/a.cpp:1656-1685, 1709-1738, upstream b.c:5"
        ))
        roles = [(p.path, p.role) for run in runs for p in run[3]]
        self.assertEqual(roles, [
            ("src/a.cpp", "source"), ("src/a.cpp", "source"), ("b.c", "upstream"),
        ])

    def test_an_abbreviated_location_reads_in_the_file_named_last(self):
        """devilutionx writes `Source/engine/assets.cpp:` then `(:507)` for
        each loader, and its pin moved under five uncollected numbers."""
        from sourceref import _prose_runs

        text = (
            "Load order is defined in Source/engine/assets.cpp:\n"
            "  LoadCoreArchives() (:507) - devilutionx.mpq, fonts.mpq\n"
            "  LoadLanguageArchive() (:523) - <lang>.mpq\n"
            "Startup (src/port/Engine.cpp:65-127) loads sf64.o2r (:72, :88-89),\n"
            "falls back at :90-106. Wrapped (code/q_shared.h\n"
            ":44,65) and lightspark's (tools/errorgen:20).\n"
        )
        cited = [
            (p.path, p.start, p.end) for run in _prose_runs(text) for p in run[3]
        ]
        self.assertEqual(cited, [
            ("Source/engine/assets.cpp", 507, 507),
            ("Source/engine/assets.cpp", 523, 523),
            ("src/port/Engine.cpp", 65, 127),
            ("src/port/Engine.cpp", 72, 72),
            ("src/port/Engine.cpp", 88, 89),
            ("src/port/Engine.cpp", 90, 106),
            ("code/q_shared.h", 44, 44),
            ("code/q_shared.h", 65, 65),
            ("tools/errorgen", 20, 20),
        ])

    def test_an_abbreviated_location_needs_a_file_before_it(self):
        from sourceref import _prose_runs

        self.assertEqual(list(_prose_runs("read at boot (:507), devilutionx.mpq")), [])


class AnOnlinePassSaysWhereItIs(unittest.TestCase):
    """`--all --triage` online printed nothing for 15 minutes, and Ctrl-C
    left no ranking at all, while --offline answered in three."""

    def _main(self, *argv: str, stop_after: int | None = None):
        calls = []

        def build(_args, name, _profile, _path, _failed):
            if stop_after is not None and len(calls) == stop_after:
                raise KeyboardInterrupt
            calls.append(name)
            return ProfileReport(name=name, entries=[], counts={})

        out, err = io.StringIO(), io.StringIO()
        saved = sys.argv
        try:
            sys.argv = ["profile_sync.py", "--all", "--triage", *argv]
            with mock.patch.object(profile_sync, "_build_full_report", side_effect=build), \
                    mock.patch.object(profile_sync, "_check_quota"), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                    self.assertRaises(SystemExit) as caught:
                profile_sync.main()
                raise SystemExit(0)
        finally:
            sys.argv = saved
        return caught.exception.code, out.getvalue(), err.getvalue()

    def test_ctrl_c_prints_the_ranking_of_what_was_read(self):
        code, out, err = self._main("--offline", stop_after=3)
        self.assertEqual(code, 130)
        self.assertEqual(out.splitlines()[-1], "3 profiles, 0 with something to review")
        self.assertIn("interrupted after 3 of", err)

    def test_an_online_pass_names_its_size_and_the_offline_mode(self):
        _code, _out, err = self._main("--limit", "2")
        self.assertIn("reading 2 profiles against their forges", err)
        self.assertIn("--offline answers from the cache alone", err)

    def test_a_progress_line_at_each_interval(self):
        clock = iter([0.0, 10.0, profile_sync.PROGRESS_SECONDS + 1, 40.0])
        err = io.StringIO()
        with mock.patch.object(profile_sync.time, "monotonic", lambda: next(clock)), \
                contextlib.redirect_stderr(err):
            progress = profile_sync._Progress(9, "read", quiet=False)
            for done, name in enumerate(("a", "b", "c")):
                progress.step(done, name)
        self.assertEqual(err.getvalue(), "read: 1 of 9, at b\n")


class TheTriageCountsWhatBlocksThePin(unittest.TestCase):
    """Prose written under an older pin refuses the recale and the bump, yet
    the triage, --changed-only and --strict read "0 to review" on blastem,
    xenia-edge and lindbergh-loader. And one stderr notice per profile put
    254 lines above an unlabelled ranking."""

    def _report(self, name: str, paths: int, stale: list[str] | None = None):
        entries = [
            EntryReport(f"f{i}", f"d/{i}.c:1", "ANCHORED", [
                PartResult(RefPart(f"d/{i}.c", 1, 1, "1"), "ANCHORED",
                           None, None, None, [])
            ])
            for i in range(paths)
        ]
        return ProfileReport(
            name=name, pin="p", head="h", entries=entries,
            counts={"ANCHORED": paths}, stale_prose=stale,
        )

    def test_stale_prose_is_review_work(self):
        report = self._report("b", 1, ["read again: notes: a.c:5 (pin moved)"])
        self.assertEqual(report.needs_review(), 1)
        self.assertIn("prose under an older pin", format_report(report))
        self.assertEqual(report_to_dict(report)["needs_review"], 1)

    def test_the_ranking_is_labelled_and_the_sampling_said_once(self):
        reports = [
            self._report("clean", 7),
            self._report("stuck", 7, ["read again: notes: a.c:5 (pin moved)"]),
        ]
        selected = {r.name: {"source": "https://github.com/o/n"} for r in reports}
        args = argparse.Namespace(cache_dir="unused", offline=True)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(profile_sync, "check_version", return_value=None), \
                mock.patch.object(profile_sync.upstream, "commits_touching",
                                  return_value=0), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            profile_sync._print_triage(args, selected, reports)
        lines = out.getvalue().splitlines()
        self.assertIn("profile", lines[0])
        self.assertIn("stuck", lines[1])
        self.assertIn("1 to review, 1 prose under an older pin", lines[1])
        self.assertIn("0 to review", lines[2])
        self.assertEqual(lines[-1], "2 profiles, 1 with something to review")
        self.assertEqual(len(err.getvalue().splitlines()), 1, err.getvalue())

    def test_an_uncheckable_profile_ranks_first_and_counts(self):
        """simple64 and teknoparrot answered 404 and --strict failed on them,
        while the triage put them at 0 under the clean profiles."""
        gone = ProfileReport(
            name="gone", pin="p", skipped="no declared repository answers (o/n)",
        )
        reports = [self._report("clean", 1), gone]
        selected = {r.name: {"source": "https://github.com/o/n"} for r in reports}
        args = argparse.Namespace(cache_dir="unused", offline=True)
        out = io.StringIO()
        with mock.patch.object(profile_sync, "check_version", return_value=None), \
                mock.patch.object(profile_sync.upstream, "commits_touching",
                                  return_value=0), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            profile_sync._print_triage(args, selected, reports)
        lines = out.getvalue().splitlines()
        self.assertIn("gone", lines[1])
        self.assertEqual(lines[-1], "2 profiles, 1 with something to review")


class TestBranchProfiles(unittest.TestCase):
    """--changed and --added name the profiles a branch brings, not by hand."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self._cwd = os.getcwd()
        self.addCleanup(os.chdir, self._cwd)
        os.chdir(self.root)
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        self.env = env
        self._git("init", "-q", "-b", "main")
        (self.root / "emulators").mkdir()
        (self.root / "emulators" / "kept.yml").write_text("a: 1\n")
        (self.root / "emulators" / "edited.yml").write_text("a: 1\n")
        self._git("add", "emulators")
        self._git("commit", "-q", "--no-verify", "-m", "base")
        self._git("checkout", "-q", "-b", "topic")
        (self.root / "emulators" / "edited.yml").write_text("a: 2\n")
        (self.root / "emulators" / "new.yml").write_text("a: 1\n")
        self._git("add", "emulators")
        self._git("commit", "-q", "--no-verify", "-m", "topic")
        (self.root / "emulators" / "draft.yml").write_text("a: 1\n")
        (self.root / "emulators" / "notes.txt").write_text("x\n")

    def _git(self, *args):
        subprocess.run(["git", *args], cwd=self.root, env=self.env, check=True)

    def test_changed_takes_added_edited_and_uncommitted(self):
        self.assertEqual(
            profile_sync.branch_profiles("emulators", "main", added_only=False),
            ["draft", "edited", "new"],
        )

    def test_added_leaves_edited_profiles_out(self):
        self.assertEqual(
            profile_sync.branch_profiles("emulators", "main", added_only=True),
            ["draft", "new"],
        )

    def test_an_unfetched_base_says_to_fetch(self):
        """`--base upstream/main` with upstream added and never fetched
        stopped on git's "Not a valid object name" and no next step."""
        with self.assertRaises(SystemExit) as raised:
            profile_sync.branch_profiles("emulators", "upstream/main", added_only=True)
        self.assertIn("git fetch upstream", str(raised.exception))

    def test_the_flag_selects_those_profiles(self):
        args = profile_sync.build_parser().parse_args(["--changed", "--base", "main"])
        profiles = {"kept": {}, "edited": {}, "new": {}, "draft": {}}
        self.assertEqual(
            list(profile_sync.select_profiles(profiles, args)),
            ["draft", "edited", "new"],
        )

    def test_a_fork_clone_compares_with_the_project(self):
        """origin is the fork, pushed: origin/main is HEAD, and the default
        base found nothing to check while the PR's CI failed."""
        base = subprocess.run(
            ["git", "rev-parse", "main"], cwd=self.root, capture_output=True,
            text=True, check=True,
        ).stdout.strip()
        self._git("remote", "add", "origin", "https://github.com/someone/retrobios")
        self._git("remote", "add", "upstream", "https://github.com/Abdess/retrobios")
        self._git("update-ref", "refs/remotes/origin/main", "HEAD")
        self._git("update-ref", "refs/remotes/upstream/main", base)
        args = profile_sync.build_parser().parse_args(["--changed"])
        profiles = {"kept": {}, "edited": {}, "new": {}, "draft": {}}
        self.assertEqual(
            list(profile_sync.select_profiles(profiles, args)),
            ["draft", "edited", "new"],
        )


class TestBranchCheckIsWired(unittest.TestCase):
    """CONTRIBUTING and CI name the branch's profiles through the flag."""

    def test_contributing_and_ci_use_the_flags(self):
        root = Path(__file__).resolve().parents[1]
        sys.path.insert(0, str(root / "scripts"))
        import generate_readme  # noqa: PLC0415

        text = generate_readme.generate_contributing()
        self.assertIn("profile_sync.py --added --strict", text)
        # The default base is fetched by the tool: a documented upstream
        # remote failed every clone that had origin alone.
        self.assertNotIn("--base upstream/main", text)
        self.assertNotIn("remote add upstream", text)
        self.assertNotIn("--emulator NAME --strict", text)
        workflow = (root / ".github" / "workflows" / "validate.yml").read_text()
        self.assertIn("profile_sync.py --added --base", workflow)
        self.assertNotIn('--emulator "$name"', workflow)


if __name__ == "__main__":
    unittest.main()
