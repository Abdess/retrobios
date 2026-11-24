"""Tests for source_ref parsing and anchoring in profile_sync (no network)."""

from __future__ import annotations

import tests

import contextlib
import io
import unittest
from pathlib import Path
from unittest import mock

from profiling import anchoring
from profiling import citations as profiling_citations
from profiling import reports as profiling_reports
from profiling import repos as profiling_repos
from profiling import run as profiling_run
from model import sourceref
from profiling.reports import (
    ProfileReport,
    SkipKind,
)
from profiling.anchoring import PartResult, anchor_block, anchor_part, resolve_rename, worst_status
from profiling.citations import collect_tokens
from profiling.repos import select_repo
from model.sourceref import RefPart, parse_source_ref, split_source_ref
from core import upstream
from core import forgehttp
from core.upstreamtree import CompareResult, FileChange
from tests.profilesyncsupport import setUpModule as setUpModule
from tests.profilesyncsupport import tearDownModule as tearDownModule


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
            [url for _, _, url in profiling_repos.declared_repositories(profile)],
            [
                "https://github.com/o/port",
                "https://github.com/o/up",
                "https://codeberg.org/o/mirror",
            ],
        )

    def test_mirror_alone_is_enough(self):
        profile = {"source_mirror": "https://codeberg.org/o/mirror"}
        self.assertEqual(
            profiling_repos.declared_repositories(profile),
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

        with mock.patch.object(upstream, "resolve_head", head), \
                mock.patch.object(upstream, "resolve_commit_at", at):
            views = profiling_repos.select_views(profile, "unused", True)
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
        with tempfile.TemporaryDirectory() as cache, self.assertRaises(forgehttp.NotCachedError):
            profiling_repos.select_views(profile, cache, True)

    def test_a_profile_without_a_mirror_is_unchanged(self):
        profile = {"source": "https://github.com/o/port"}
        self.assertEqual(
            profiling_repos.declared_repositories(profile),
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
            skip_kind=SkipKind.GONE,
        )
        self.assertEqual(report.needs_review(), 0)
        self.assertTrue(report.skipped.startswith("upstream gone:"))

    def test_gone_and_failing_forges_land_in_different_buckets(self):
        gone = ProfileReport(name="a", entries=[], counts={},
                             skipped="upstream gone: h: HTTP 451, withdrawn for legal reasons",
                             skip_kind=SkipKind.GONE)
        failing = ProfileReport(name="b", entries=[], counts={},
                                skipped="upstream error: h: HTTP 403",
                                skip_kind=SkipKind.UPSTREAM_ERROR)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            profiling_run._print_elided([gone, failing], 0)
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
            profiling_reports.triage_state(report),
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
        size = anchoring.MAX_MATCH_LINES + 1
        pin = [f"line {i}" for i in range(size)]
        head = [f"other {i}" for i in range(size)]
        result = anchor_block(pin, head, 10, 10)
        self.assertEqual(result.status, "CHANGED")
        self.assertIn(str(anchoring.MAX_MATCH_LINES), result.reason)
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
            anchoring.verify_at_pin(part, self.LINES, ["deadbeef"]).status, "GONE"
        )

    def test_declared_value_present(self):
        part = RefPart("a.c", 3, 3, "a.c:3")
        self.assertEqual(
            anchoring.verify_at_pin(part, self.LINES, ["deadbeef"]).status,
            "ANCHORED",
        )

    def test_value_found_within_the_context_window(self):
        part = RefPart("a.c", 1, 1, "a.c:1")
        self.assertEqual(
            anchoring.verify_at_pin(part, self.LINES, ["deadbeef"]).status,
            "ANCHORED",
        )

    def test_declared_value_absent_from_the_whole_file(self):
        part = RefPart("a.c", 1, 1, "a.c:1")
        result = anchoring.verify_at_pin(part, self.LINES, ["cafebabe"])
        self.assertEqual(result.status, "ANCHORED")

    def test_declared_value_carried_by_another_line(self):
        lines = ["load()", "", "", "", "", "", 'rom("cafebabe")']
        part = RefPart("a.c", 1, 1, "a.c:1")
        result = anchoring.verify_at_pin(
            part, lines, ["cafebabe"], ["cafebabe"]
        )
        self.assertEqual(result.status, "MOVED")
        self.assertEqual(result.start, 7)

    def test_a_part_annotated_for_another_version(self):
        """ti99sim cites v0.0.11 beside its v0.16.0 pin."""
        other = RefPart("src/sdl/main.cpp", 407, 411, "src/sdl/main.cpp:407-411 (v0.0.11)")
        same = RefPart("src/core/ti994a.cpp", 122, 131, "src/core/ti994a.cpp:122-131 (v0.16.0)")
        self.assertEqual(profiling_citations.cites_another_version(other, "0.16.0"), "0.0.11")
        self.assertIsNone(profiling_citations.cites_another_version(same, "0.16.0"))
        self.assertIsNone(profiling_citations.cites_another_version(same, {"libretro": "v0.16.0"}))

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
            if not profiling_citations._VERSION_NOTE_RE.search(refs):
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
        result = anchoring.verify_at_pin(
            part, lines, ["0123456789abcdef0123456789abcdef", "pravets82"],
            ["0123456789abcdef0123456789abcdef"],
        )
        self.assertEqual(result.status, "ANCHORED")

    def test_declared_value_on_several_lines_is_ambiguous(self):
        lines = ["load()", "", "", "", 'a("cafebabe")', "", 'b("cafebabe")']
        part = RefPart("a.c", 1, 1, "a.c:1")
        result = anchoring.verify_at_pin(
            part, lines, ["cafebabe"], ["cafebabe"]
        )
        self.assertEqual(result.status, "AMBIGUOUS")

    def test_one_anchored_part_settles_the_others(self):
        parts = [
            anchoring.PartResult(
                RefPart("a.c", 1, 1, "a.c:1"), "ANCHORED", None, None, None, []
            ),
            anchoring.PartResult(
                RefPart("a.c", 9, 9, "a.c:9"), "AMBIGUOUS", None, None, None, [1, 2]
            ),
        ]
        settled = anchoring.reconcile_self_check(parts)
        self.assertEqual([p.status for p in settled], ["ANCHORED", "ANCHORED"])

    def test_an_absent_part_survives_reconciliation(self):
        parts = [
            anchoring.PartResult(
                RefPart("a.c", 1, 1, "a.c:1"), "ANCHORED", None, None, None, []
            ),
            anchoring.PartResult(
                RefPart("b.c", 9, 9, "b.c:9"), "GONE", None, None, None, []
            ),
        ]
        settled = anchoring.reconcile_self_check(parts)
        self.assertEqual([p.status for p in settled], ["ANCHORED", "GONE"])

    def test_nothing_anchored_leaves_the_verdicts_alone(self):
        parts = [
            anchoring.PartResult(
                RefPart("a.c", 1, 1, "a.c:1"), "MOVED", None, 5, 5, [5]
            ),
        ]
        self.assertEqual(
            [p.status for p in anchoring.reconcile_self_check(parts)], ["MOVED"]
        )

    def test_external_citation_is_out_of_reach_at_the_pin_too(self):
        part = RefPart("munt ROMInfo.cpp", 1, 1, "munt ROMInfo.cpp:1")
        result = anchoring.verify_at_pin(part, None, ["cafebabe"])
        self.assertEqual(result.status, "EXTERNAL")

    def test_a_name_fragment_elsewhere_is_not_evidence(self):
        # Only a hash is unique enough to prove a ref points elsewhere.
        lines = ["load()", "", "", "", "", "", "tyrian2.c line"]
        part = RefPart("a.c", 1, 1, "a.c:1")
        result = anchoring.verify_at_pin(part, lines, ["tyrian2"], [])
        self.assertEqual(result.status, "ANCHORED")

    def test_missing_file(self):
        part = RefPart("a.c", 1, 1, "a.c:1")
        self.assertEqual(
            anchoring.verify_at_pin(part, None, ["deadbeef"]).status, "GONE"
        )

    def test_an_entry_with_nothing_to_look_for_is_unchecked_not_anchored(self):
        """race's analysis.npbios entry carries a `filename:` and no hash: at a
        pin equal to HEAD its ref was reported anchored while the cited block
        had been deleted upstream. No token means no verdict."""
        part = RefPart("a.c", 3, 3, "a.c:3")
        result = anchoring.verify_at_pin(part, self.LINES, [])
        self.assertEqual(result.status, "UNCHECKED")
        self.assertNotIn("UNCHECKED", anchoring.REVIEW_STATUSES)
        self.assertEqual(anchoring.worst_status(["ANCHORED", "UNCHECKED"]), "UNCHECKED")
        self.assertEqual(anchoring.worst_status(["UNCHECKED", "SHIFTED"]), "SHIFTED")

    def test_line_beyond_the_file(self):
        part = RefPart("a.c", 99, 99, "a.c:99")
        self.assertEqual(
            anchoring.verify_at_pin(part, self.LINES, ["deadbeef"]).status, "GONE"
        )

    def test_a_ref_without_a_line_is_accepted(self):
        part = RefPart("a.c", None, None, "a.c")
        self.assertEqual(
            anchoring.verify_at_pin(part, self.LINES, ["deadbeef"]).status,
            "ANCHORED",
        )

    def test_an_entry_declaring_nothing_is_accepted_but_not_called_anchored(self):
        # Nothing to re-read, so no review is demanded, but the verdict says
        # that nothing was checked rather than claiming the ref anchors.
        part = RefPart("a.c", 1, 1, "a.c:1")
        result = anchoring.verify_at_pin(part, self.LINES, [])
        self.assertEqual(result.status, "UNCHECKED")
        self.assertNotIn(result.status, anchoring.REVIEW_STATUSES)


class TestExternalCitation(unittest.TestCase):
    def test_project_name_then_file(self):
        self.assertTrue(profiling_citations.is_external_citation("munt ROMInfo.cpp"))
        self.assertTrue(
            profiling_citations.is_external_citation("Nuked-SC55-CLAP rom_io.cpp")
        )
        self.assertTrue(
            profiling_citations.is_external_citation("EmuDeck emuDeckares.sh")
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
                match = sourceref.PROSE_CITE_RE.search(text)
                self.assertIsNotNone(match, text)
                self.assertEqual(match.group("path"), text.split(":")[0])

    def test_a_constant_or_an_address_is_not_a_citation(self):
        """Widening the pattern to any dotless word swallows these."""
        for text in ("ALTERNATEROMS:23", "F000:12", "C000:4"):
            with self.subTest(text=text):
                self.assertIsNone(sourceref.PROSE_CITE_RE.search(text), text)

    def test_plain_paths_are_not_citations(self):
        for path in ("src/midi/mt32.cpp", "libretro.c", "a/b/c.h"):
            self.assertFalse(profiling_citations.is_external_citation(path), path)

    def test_a_path_with_a_directory_prefix_is_not_a_citation(self):
        self.assertFalse(
            profiling_citations.is_external_citation("src/dir file.cpp")
        )

    def test_a_filename_prefix_is_not_a_citation(self):
        self.assertFalse(profiling_citations.is_external_citation("main.cpp note"))

    def test_external_part_is_reported_not_reviewed(self):
        result = anchor_part(
            RefPart("munt ROMInfo.cpp", 59, 59),
            make_fetch({}),
            renamer(CompareResult([], False)),
        )
        self.assertEqual(result.status, "EXTERNAL")
        self.assertNotIn("EXTERNAL", anchoring.REVIEW_STATUSES)


class TestBinaryCitation(unittest.TestCase):
    """A ref read by disassembly has no source path to anchor."""

    def test_hex_address_is_binary(self):
        self.assertTrue(sourceref.is_binary_citation(
            "BAM.dll 1.5-408 .text:0x100c3960-0x100c3a97"
        ))
        self.assertTrue(sourceref.is_binary_citation("libmain.so LoadNES 0x3bb49"))

    def test_binary_suffix_followed_by_words_is_binary(self):
        self.assertTrue(sourceref.is_binary_citation("BAM-Tracker.exe import directory"))

    def test_section_name_is_binary(self):
        self.assertTrue(sourceref.is_binary_citation(".rdata dialog filter"))

    def test_bare_library_name_is_binary(self):
        self.assertTrue(sourceref.is_binary_citation("DesktopKinect.dll"))
        self.assertFalse(sourceref.is_binary_citation("Makefile"))

    def test_a_source_path_is_not_binary(self):
        for path in ("src/foo.c", "libs/libCg.so", "Source/Core/hook.c", "resources/font.h"):
            self.assertFalse(sourceref.is_binary_citation(path), path)

    def test_binary_part_is_reported_not_reviewed(self):
        result = anchor_part(
            RefPart("BAM.dll 1.5-408 .text:0x10031bbb", None, None),
            make_fetch({}),
            renamer(CompareResult([], False)),
        )
        self.assertEqual(result.status, "BINARY")
        self.assertNotIn("BINARY", anchoring.REVIEW_STATUSES)

    def test_binary_part_at_the_pin(self):
        part = RefPart("ModelImporter.exe import directory", None, None, "")
        self.assertEqual(anchoring.verify_at_pin(part, None, []).status, "BINARY")


class TestRepoWord(unittest.TestCase):
    """A leading word naming a declared repository is a location, not a project."""

    def test_declared_repository_word_is_stripped(self):
        self.assertEqual(
            profiling_citations.strip_repo_word("BAM_FPloader FPLoader.cpp", {"bam_fploader"}),
            "FPLoader.cpp",
        )

    def test_release_version_after_the_repository_word_is_dropped(self):
        self.assertEqual(
            profiling_citations.strip_repo_word(
                "ArcadeFlashWeb v1.0.2 flash/flash.html", {"arcadeflashweb"}
            ),
            "flash/flash.html",
        )

    def test_undeclared_project_word_stays(self):
        self.assertEqual(
            profiling_citations.strip_repo_word("munt ROMInfo.cpp", {"bam_fploader"}),
            "munt ROMInfo.cpp",
        )

    def test_a_directory_prefix_is_not_a_project_word(self):
        self.assertEqual(
            profiling_citations.strip_repo_word("src/dir file.cpp", {"src/dir"}),
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
            profiling_citations.narrow_by_cited(self.MATCHES, {"SheepShaver", "SheepShaver/src"}),
            ["SheepShaver/src/include/version.h"],
        )

    def test_equal_depth_keeps_both(self):
        matches = [
            "SheepShaver/src/EthernetDriver/cpu_emulation.h",
            "SheepShaver/src/include/cpu_emulation.h",
        ]
        self.assertEqual(
            profiling_citations.narrow_by_cited(matches, {"SheepShaver/src"}), matches
        )

    def test_nothing_cited_keeps_all(self):
        self.assertEqual(profiling_citations.narrow_by_cited(self.MATCHES, set()), self.MATCHES)

    def test_depth_counts_components_not_characters(self):
        matches = [
            "SheepShaver/src/Unix/configure.ac",
            "SheepShaver/src/Windows/configure.ac",
        ]
        cited = {"SheepShaver", "SheepShaver/src", "SheepShaver/src/Unix", "SheepShaver/src/Windows"}
        self.assertEqual(profiling_citations.narrow_by_cited(matches, cited), matches)


class TestSymlinkTarget(unittest.TestCase):
    """A one-line blob naming a same-named file is a link to follow."""

    def test_relative_link_resolves_from_the_link_directory(self):
        self.assertEqual(
            profiling_citations.symlink_target(
                "SheepShaver/src/Unix/ether_unix.cpp",
                ["../../../BasiliskII/src/Unix/ether_unix.cpp"],
            ),
            "BasiliskII/src/Unix/ether_unix.cpp",
        )

    def test_a_real_one_line_file_is_not_a_link(self):
        self.assertIsNone(profiling_citations.symlink_target("a/VERSION", ["1.2.3"]))
        self.assertIsNone(profiling_citations.symlink_target("a/x.c", ["int main() { return 0; }"]))
        self.assertIsNone(profiling_citations.symlink_target("a/x.c", ["../other.c"]))

    def test_a_link_leaving_the_tree_is_ignored(self):
        self.assertIsNone(profiling_citations.symlink_target("x.c", ["../../x.c"]))


class TestAnchorTokens(unittest.TestCase):
    def test_archive_members_supply_the_content_values(self):
        tokens = profiling_citations.anchor_tokens(
            {"name": "esh.zip", "contents": [{"crc32": "c14f36b3"}]}
        )
        # The set name stays: a MAME ref cites the machine declaration, which
        # carries the name and no hash.
        self.assertEqual(tokens, ["c14f36b3", "esh"])

    def test_a_hashless_archive_still_falls_back_to_its_stem(self):
        tokens = profiling_citations.anchor_tokens(
            {"name": "esh.zip", "contents": [{"name": "rom.u1"}]}
        )
        self.assertIn("esh", tokens)

    def test_archive_stem_is_searched_too(self):
        tokens = profiling_citations.anchor_tokens({"name": "stvbios.zip"})
        self.assertIn("stvbios.zip", tokens)
        self.assertIn("stvbios", tokens)

    def test_hashes_still_win(self):
        tokens = profiling_citations.anchor_tokens(
            {"name": "a.zip", "sha1": "AABB" * 10}
        )
        self.assertIn("aabb" * 10, tokens)

    def test_very_short_stem_is_skipped(self):
        self.assertNotIn("ab", profiling_citations.anchor_tokens({"name": "ab.zip"}))


class TestNudgeToDeclared(unittest.TestCase):
    LINES = ["pad"] * 20 + ["ROM_START( stvbios )"] + ["pad"] * 20

    def test_moves_onto_the_declared_value(self):
        self.assertEqual(
            anchoring.nudge_to_declared(self.LINES, 19, 19, ["stvbios"]),
            (21, 21),
        )

    def test_range_length_is_kept(self):
        lines = [""] * 20 + ["ROM_START( stvbios )"] + ["pad"] * 20
        self.assertEqual(
            anchoring.nudge_to_declared(lines, 17, 19, ["stvbios"]),
            (21, 23),
        )

    def test_a_range_over_code_cites_that_code(self):
        """ymir's 598-618 cited load_rom_cartridge(). Nudged onto the file
        table beside it, a rewritten function read SHIFTED, not CHANGED."""
        lines = ["void load_rom_cartridge() {"] + ["  code();"] * 19 + ["}", "kKOF95Files"]
        self.assertIsNone(anchoring.nudge_to_declared(lines, 1, 21, ["kkof95files"]))

    def test_nothing_when_already_on_target(self):
        self.assertIsNone(
            anchoring.nudge_to_declared(self.LINES, 21, 21, ["stvbios"])
        )

    def test_nothing_beyond_the_window(self):
        lines = ["pad"] * 500 + ["ROM_START( stvbios )"]
        self.assertIsNone(anchoring.nudge_to_declared(lines, 1, 1, ["stvbios"]))

    def test_nothing_without_tokens(self):
        self.assertIsNone(anchoring.nudge_to_declared(self.LINES, 19, 19, []))

    def test_nothing_when_the_value_is_absent(self):
        self.assertIsNone(
            anchoring.nudge_to_declared(self.LINES, 19, 19, ["absent"])
        )

    def test_adjacent_duplicates_are_refused(self):
        lines = ["pad"] * 20 + ["stvbios a", "stvbios b"] + ["pad"] * 20
        self.assertIsNone(
            anchoring.nudge_to_declared(lines, 19, 19, ["stvbios"])
        )


class TestDominantShift(unittest.TestCase):
    def test_shift_needs_enough_support(self):
        parts = [_part("a.c", 10, 30, "SHIFTED"), _part("a.c", 20, 40, "SHIFTED")]
        self.assertEqual(anchoring.dominant_shifts(parts), {})

    def test_shift_is_taken_from_resolved_anchors(self):
        parts = [_part("a.c", i, i + 20, "SHIFTED") for i in (10, 20, 30)]
        self.assertEqual(anchoring.dominant_shifts(parts), {"a.c": 20})

    def test_ambiguous_parts_do_not_vote(self):
        parts = [_part("a.c", i, i + 20, "SHIFTED") for i in (10, 20, 30)]
        parts.append(_ambiguous("a.c", 40, [99, 500]))
        self.assertEqual(anchoring.dominant_shifts(parts), {"a.c": 20})

    def test_candidate_matching_the_shift_is_selected(self):
        part = _ambiguous("a.c", 1624, [1644, 1790, 1834])
        settled = anchoring.resolve_by_shift(part, {"a.c": 20})
        self.assertEqual(settled.status, "SHIFTED")
        self.assertEqual(settled.start, 1644)
        self.assertIn("+20", settled.reason)

    def test_no_candidate_matches_the_shift(self):
        part = _ambiguous("a.c", 1624, [1790, 1834])
        self.assertEqual(anchoring.resolve_by_shift(part, {"a.c": 20}).status,
                         "AMBIGUOUS")

    def test_two_candidates_on_the_shift_stay_ambiguous(self):
        part = _ambiguous("a.c", 1624, [1644, 1644])
        self.assertEqual(anchoring.resolve_by_shift(part, {"a.c": 20}).status,
                         "AMBIGUOUS")

    def test_range_length_is_preserved(self):
        part = PartResult(
            RefPart("a.c", 100, 104), "AMBIGUOUS", None, None, None, [120]
        )
        settled = anchoring.resolve_by_shift(part, {"a.c": 20})
        self.assertEqual((settled.start, settled.end), (120, 124))

    def test_file_without_a_known_shift_is_untouched(self):
        part = _ambiguous("b.c", 10, [30])
        self.assertEqual(anchoring.resolve_by_shift(part, {"a.c": 20}).status,
                         "AMBIGUOUS")


PIN = profiling_repos.PIN


HEAD = profiling_repos.HEAD


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
        self.assertIn("MOVED", anchoring.REBASE_STATUSES)
        self.assertNotIn("MOVED", anchoring.REVIEW_STATUSES)

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


class TestReconcilePerFile(unittest.TestCase):
    def test_an_anchored_part_settles_only_its_own_file(self):
        anchored = PartResult(RefPart("libretro.c", 5, 5, "5"), "ANCHORED", None, None, None, [])
        same = PartResult(RefPart("libretro.c", 9, 9, "9"), "AMBIGUOUS", None, None, None, [])
        other = PartResult(RefPart("jg.c", 229, 230, "229-230"), "AMBIGUOUS", None, None, None, [])
        result = anchoring.reconcile_self_check([anchored, same, other])
        self.assertEqual([p.status for p in result], ["ANCHORED", "ANCHORED", "AMBIGUOUS"])

    def test_a_settled_part_keeps_the_repository_of_its_anchor(self):
        anchored = PartResult(RefPart("mt32emu.h", 5112, 5112, "5112"), "ANCHORED",
                              None, None, None, [], repo="schelling/dosbox-pure")
        same = PartResult(RefPart("mt32emu.h", 5129, 5129, "5129"), "MOVED",
                          None, 5112, 5112, [5112])
        result = anchoring.reconcile_self_check([anchored, same])
        self.assertEqual(result[1].status, "ANCHORED")
        self.assertEqual(result[1].repo, "schelling/dosbox-pure")

    def test_a_compared_part_is_never_rewritten(self):
        anchored = PartResult(RefPart("a.c", 5, 5, "5"), "ANCHORED", None, None, None, [])
        shifted = PartResult(RefPart("a.c", 9, 9, "9"), "SHIFTED", None, 12, 12, [])
        result = anchoring.reconcile_self_check([anchored, shifted], [True, False])
        self.assertEqual(result[1].status, "SHIFTED")


if __name__ == "__main__":
    unittest.main()
