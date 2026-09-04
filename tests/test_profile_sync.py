"""Tests for the profile synchronisation tool (no network)."""

from __future__ import annotations

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
from upstream import CompareResult, FileChange


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

    def test_an_entry_declaring_nothing_is_accepted(self):
        part = RefPart("a.c", 1, 1, "a.c:1")
        self.assertEqual(
            profile_sync.verify_at_pin(part, self.LINES, []).status, "ANCHORED"
        )


class TestExternalCitation(unittest.TestCase):
    def test_project_name_then_file(self):
        self.assertTrue(profile_sync.is_external_citation("munt ROMInfo.cpp"))
        self.assertTrue(
            profile_sync.is_external_citation("Nuked-SC55-CLAP rom_io.cpp")
        )
        self.assertTrue(
            profile_sync.is_external_citation("EmuDeck emuDeckares.sh")
        )

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
        self.assertEqual(
            profile_sync.nudge_to_declared(self.LINES, 19, 22, ["stvbios"]),
            (21, 24),
        )

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
        )
        self.tags: list[str] = []
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
            lambda repo, cache_dir, offline=False, branch=None: "headsha"
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
        # A ref citing loading logic never spells the value out; its absence
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
        # A port and its upstream can both carry a path; only one holds the
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
        # Only the port carries the branch; the upstream keeps its own tip.
        self.assertEqual(seen["o/n"], "libretro")
        self.assertIsNone(seen["o/up"])

    def test_the_subject_beats_a_merely_non_blank_line(self):
        # A fork whose tree is offset holds a real but unrelated statement at
        # the cited line; the repository carrying the subject wins.
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
        # cited line, so no single attribution is right; the ref anchors in one
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
        self.assertIn("1 demandent une relecture", format_report(_sample_report()))

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
        else:
            argv.extend([flag, str(value)])
    return build_parser().parse_args(argv)


class TestSelectProfiles(unittest.TestCase):
    def test_single_emulator(self):
        self.assertEqual(
            list(select_profiles(PROFILES, _args(emulator="alpha"))), ["alpha"]
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

    def tearDown(self):
        self.tmp.cleanup()

    def _args(self, **over):
        base = dict(
            emulators_dir=str(self.dir), backfill_commits=False,
            rebase_refs=False, bump_commit=False, accept_changed=False,
            dry_run=True,
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

    def test_writes_still_happen_without_the_flag(self):
        output = self._run(
            self._args(rebase_refs=True, dry_run=False), self._shifted()
        )
        self.assertNotIn("would", output)
        self.assertIn('source_ref: "a.c:30-32"', self.path.read_text())

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

    def test_external_project_prefix_is_skipped(self):
        document = {
            "notes": "ref: mt32_model.cpp:36-97, munt ROMInfo.cpp:206-213\n"
        }
        refs = [c.ref for c in collect_citations(document)]
        self.assertEqual(refs, ["mt32_model.cpp:36-97"])

    def test_linking_word_is_not_a_project(self):
        document = {"notes": "It boots, in libretro.cpp:12 as shown.\n"}
        refs = [c.ref for c in collect_citations(document)]
        self.assertEqual(refs, ["libretro.cpp:12"])

    def test_spaced_range_continuation_is_part_of_the_run(self):
        document = {
            "notes": "ref: soundcanvas.cpp:55-71, 80-147, Ext plugin.cpp:23\n"
        }
        citations = collect_citations(document)
        self.assertEqual(len(citations), 1)
        self.assertEqual(citations[0].ref, "soundcanvas.cpp:55-71, 80-147")
        self.assertEqual(
            [(p.start, p.end) for p in citations[0].parts],
            [(55, 71), (80, 147)],
        )

    def test_spaced_lone_number_stays_prose(self):
        document = {"notes": "It reads x.c:100, 200 files at boot.\n"}
        citation = collect_citations(document)[0]
        self.assertEqual(citation.ref, "x.c:100")

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
        matches the key once; everything else goes through the collector.
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
        text = PROSE_SAMPLE.replace(
            "files:",
            'quirks: |\n  The loader appends dc/ to the system directory '
            '(a.c:10) and reads\n  nothing else.\nfiles:',
        )
        self.path.write_text(text, encoding="utf-8")
        part = PartResult(RefPart("a.c", 10, 10, "10"), "SHIFTED", None, 14, 14, [])
        applied = rebase_refs(
            self.path, self._report([self._prose_entry("a.c:10", [part])])
        )
        self.assertEqual(applied, [])
        self.assertEqual(self.path.read_text(), text)

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
        text = PROSE_SAMPLE.replace(
            "files:",
            'quirks: |\n  The loader appends dc/ to the system directory '
            '(a.c:10) and reads\n  nothing else.\nfiles:',
        )
        self.path.write_text(text, encoding="utf-8")
        part = PartResult(RefPart("a.c", 10, 10, "10"), "SHIFTED", None, 14, 14, [])
        report = self._report([part])
        self.assertEqual(rebase_refs(self.path, report), [])
        self.assertFalse(bump_commit(self.path, report))


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
        self._commit(PROSE_SAMPLE, "advance pin")

    def test_run_realigns_from_the_writing_pin(self):
        self._repo_with_advanced_pin()
        # At the writing pin line 10 is the subject; at the current pin the
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
        self._commit(base, "advance pin")
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
        self._commit(base, "advance pin")
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
        self._commit(base, "advance pin")
        self.files[("oldpin", "src/deep.c")] = ["x"] * 9 + ["subject"]
        self.files[("pin", "src/deep.c")] = ["x"] * 13 + ["subject"]
        self.files[("oldpin", "b.c")] = list("pqrstuvwx")
        self.files[("pin", "b.c")] = list("pqrstuvwx")
        messages = profile_sync.realign_prose(self.path, self.tmp.name)
        self.assertIn("notes: deep.c:10 -> deep.c:14", messages)
        self.assertIn("(deep.c:14)", self.path.read_text())


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
            "--changed-only", "--check-version", "--detect-new-files",
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


if __name__ == "__main__":
    unittest.main()
