"""Tests for the profile_sync report: building, formatting, roles per part (no network)."""

from __future__ import annotations

import tests

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import yaml

from profiling import rebase
from profiling import reports as profiling_reports
from profiling import repos as profiling_repos
from profiling import run as profiling_run
from profiling.reports import (
    EntryReport,
    ProfileReport,
    SkipKind,
    format_markdown,
    format_report,
    report_to_dict,
)
from profiling.anchoring import PartResult
from profiling.resolver import build_report
from profiling.bump import bump_commit
from profiling.rebase import rebase_refs
from model.sourceref import RefPart
from core import upstream
from core import forgehttp
from core import upstreamtree
from core.upstreamtree import CompareResult
from tests.profilesyncsupport import SAMPLE, _sample_report
from tests.profilesyncsupport import setUpModule as setUpModule
from tests.profilesyncsupport import tearDownModule as tearDownModule


class TestBuildReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.files: dict[tuple[str, str], list[str]] = {}
        self._orig = (
            upstream.fetch_file,
            upstream.resolve_head,
            upstream.resolve_commit_at,
            upstreamtree.compare,
            upstreamtree.list_tree,
            upstream.list_tags,
            upstream.resolve_tag_commit,
            upstream.tag_commit,
            forgehttp.http_json,
            forgehttp.http_text,
            upstreamtree.list_gitlinks,
            upstream.current_slug,
            upstreamtree.fork_base,
            upstreamtree.ancestry,
        )
        # Pin and tip are unrelated shas in these fixtures: no ancestry.
        upstreamtree.ancestry = lambda *a, **k: None
        self.fork_bases: dict[str, str] = {}
        upstreamtree.fork_base = (
            lambda repo, sha, fork, fork_sha, cache_dir, offline=False:
            self.fork_bases.get(fork_sha)
        )
        self.current_slugs: dict[str, str] = {}
        upstream.current_slug = (
            lambda repo, cache_dir, offline=False: self.current_slugs.get(
                repo.slug, repo.slug
            )
        )
        self.tags: list[str] = []
        self.gitlinks: dict[str, dict[str, str]] = {}
        upstreamtree.list_gitlinks = (
            lambda repo, sha, cache_dir, offline=False: self.gitlinks.get(sha, {})
        )
        self.tag_commits: dict[str, str] = {}
        # Any code path reaching the HTTP layer is a leak, not a slow test.
        def _no_network(url):
            raise AssertionError(f"test reached the network: {url}")

        forgehttp.http_json = _no_network
        forgehttp.http_text = _no_network
        upstream.list_tags = (
            lambda repo, cache, offline=False: self.tags
        )
        upstream.resolve_tag_commit = (
            lambda repo, tag, cache, offline=False: self.tag_commits.get(tag)
        )
        upstream.tag_commit = (
            lambda repo, tag, cache, offline=False: self.tag_commits.get(tag)
        )
        upstreamtree.list_tree = (
            lambda repo, sha, cache_dir, offline=False: (
                sorted({path for _, path in self.files}), False
            )
        )
        upstream.fetch_file = (
            lambda repo, sha, path, cache_dir, offline=False: self.files.get(
                (sha, path)
            )
        )
        upstream.resolve_head = (
            lambda repo, cache_dir, offline=False, branch=None, fresh=False: "headsha"
        )
        upstream.resolve_commit_at = (
            lambda repo, date, cache_dir, offline=False, branch=None: "pinsha"
        )
        upstreamtree.compare = (
            lambda repo, base, head, cache_dir, offline=False: CompareResult([], False)
        )

    def tearDown(self):
        (
            upstream.fetch_file,
            upstream.resolve_head,
            upstream.resolve_commit_at,
            upstreamtree.compare,
            upstreamtree.list_tree,
            upstream.list_tags,
            upstream.resolve_tag_commit,
            upstream.tag_commit,
            forgehttp.http_json,
            forgehttp.http_text,
            upstreamtree.list_gitlinks,
            upstream.current_slug,
            upstreamtree.fork_base,
            upstreamtree.ancestry,
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
        self.assertIn("moved repository", profiling_reports.format_report(report))

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
            raise forgehttp.UpstreamError(f"{path}: HTTP 403")

        upstream.fetch_file = refuse
        with contextlib.redirect_stderr(io.StringIO()):
            report = build_report("test", self._profile(["a.c:2"]), self.dir)
        statuses = [p.status for e in report.entries for p in e.parts]
        self.assertEqual(statuses, ["UNCHECKED"])
        self.assertIn("refused", report.entries[0].parts[0].reason)

    def test_a_truncated_head_tree_is_not_an_absence(self):
        """git.eden-emu.dev truncates the HEAD tree: fs_paths.h, cited bare,
        was reported GONE though it lives under src/common/fs/."""
        self.files[("pinsha", "fs_paths.h")] = ["x", "hit"]
        upstreamtree.list_tree = (
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
        upstream.resolve_head = (
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
        report = profiling_reports.report_to_dict(build_report("lrps2", profile, self.dir))
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

        upstream.resolve_head = _head
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
        upstream.resolve_head = (
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

    def test_each_cited_path_keeps_the_repository_it_was_settled_in(self):
        # geolith cites jg.c in its GitLab upstream and src/geo.c in the
        # port: detection read every path in the port and skipped jg.c.
        self.files[("portpin", "src/geo.c")] = ["x", "load bios.bin"]
        self.files[("porthead", "src/geo.c")] = ["x", "load bios.bin"]
        self.files[("uppin", "jg.c")] = ["y", "load bios.bin"]
        self.files[("uphead", "jg.c")] = ["pad", "y", "load bios.bin"]
        heads = {"o/port": "porthead", "o/up": "uphead"}
        upstream.resolve_head = (
            lambda repo, cache, offline=False, branch=None: heads[repo.slug]
        )
        profile = {
            "emulator": "Geolith",
            "source": "https://github.com/o/port",
            "upstream": "https://github.com/o/up",
            "source_commit": "portpin",
            "upstream_commit": "uppin",
            "files": [
                {"name": "bios.bin", "source_ref": "src/geo.c:2"},
                {"name": "bios.bin", "source_ref": "jg.c:2"},
            ],
        }
        report = build_report("geolith", profile, self.dir)
        self.assertEqual(
            [(s.path, s.repo.slug, s.pin, s.head) for s in report.cited_sources],
            [("jg.c", "o/up", "uppin", "uphead"),
             ("src/geo.c", "o/port", "portpin", "porthead")],
        )
        self.assertNotIn("cited_sources", report_to_dict(report))

    def test_self_check_reads_every_repository_before_calling_a_range_gone(self):
        # hatari: the port's src/paths.c runs 365 lines, the upstream's 345,
        # and a source_ref attributes the path to the upstream. With both on
        # HEAD, prose citing the port's 305-356 was read in the upstream file
        # alone and reported beyond its end.
        self.files[("porthead", "src/p.c")] = [f"port {i}" for i in range(8)]
        self.files[("uphead", "src/p.c")] = ["a", "load x.bin", "c", "d", "e"]
        heads = {"o/port": "porthead", "o/up": "uphead"}
        upstream.resolve_head = (
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
        upstream.resolve_head = (
            lambda repo, cache, offline=False, branch=None: heads[repo.slug]
        )
        upstreamtree.list_tree = (
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
        upstream.resolve_head = (
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
        upstreamtree.compare = (
            lambda repo, base, head, cache_dir, offline=False: CompareResult([], False, True)
        )
        report = build_report("test", self._profile(["a.c:2"]), self.dir)
        self.assertEqual(len(report.orphaned), 1)
        self.assertGreater(report.needs_review(), 0)
        self.assertIn("orphaned pin", profiling_reports.format_report(report))

    def test_a_frozen_tag_is_off_the_branch_on_purpose(self):
        self.files[("pinsha", "a.c")] = ["x", "hit"]
        self.files[("headsha", "a.c")] = ["x", "hit"]
        self.tag_commits = {"v1.6.0": "pinsha"}
        upstreamtree.compare = (
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
        upstream.resolve_head = (
            lambda repo, cache, offline=False, branch=None: heads[repo.slug]
        )
        # A tag off the tracked branch is not an orphaned pin.
        upstreamtree.compare = (
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
            "upstream pinned to tag 0.289", profiling_reports.format_report(report)
        )

    def test_a_tag_pointing_elsewhere_is_not_flagged(self):
        self.files[("pinsha", "a.c")] = ["x", "hit"]
        self.files[("headsha", "a.c")] = ["x", "hit"]
        self.tag_commits = {"v1.6.0": "somethingelse"}
        report = build_report("test", self._versioned("1.6.0"), self.dir)
        self.assertIsNone(report.pinned_tag)

    def test_prose_version_is_not_looked_up(self):
        self.assertEqual(profiling_repos.version_tag_candidates("SVN (2015 snapshot)"), [])
        self.assertEqual(profiling_repos.version_tag_candidates(""), [])

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
            raise forgehttp.GoneError("https://h/x: HTTP 451")

        upstream.resolve_head = boom
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
            raise forgehttp.UpstreamError("TLSV1_UNRECOGNIZED_NAME")

        upstream.resolve_head = tls
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
            raise forgehttp.GoneError("https://h/x: HTTP 451")

        upstream.resolve_head = boom
        with self.assertRaises(forgehttp.GoneError):
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

        upstreamtree.list_tree = list_tree

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
        self._orig = upstream.resolve_commit_at
        self.seen: list[str] = []

        def flaky(repo, date, cache_dir, offline=False, branch=None):
            self.seen.append(repo.slug)
            if repo.slug == "o/bad":
                raise forgehttp.UpstreamError("HTTP 401")
            return "pinsha"

        upstream.resolve_commit_at = flaky

    def tearDown(self):
        upstream.resolve_commit_at = self._orig
        self.tmp.cleanup()

    def test_upstream_error_becomes_a_skip(self):
        profile = {
            "emulator": "T",
            "source": "https://github.com/o/bad",
            "profiled_date": "2026-03-29",
            "files": [{"name": "a.bin", "source_ref": "a.c:1"}],
        }
        with self.assertRaises(forgehttp.UpstreamError):
            build_report("bad", profile, self.tmp.name)

    def test_rate_limit_still_propagates(self):
        def limited(repo, date, cache_dir, offline=False, branch=None):
            raise forgehttp.RateLimitError("HTTP 403")

        upstream.resolve_commit_at = limited
        profile = {
            "emulator": "T",
            "source": "https://github.com/o/n",
            "profiled_date": "2026-03-29",
            "files": [{"name": "a.bin", "source_ref": "a.c:1"}],
        }
        with self.assertRaises(forgehttp.RateLimitError):
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
            profiling_run._print_elided(reports, printed=1)
        text = buffer.getvalue()
        self.assertIn("3 non listes", text)
        self.assertIn("2  no source_ref", text)
        self.assertIn("1  nothing to review", text)

    def test_silent_when_everything_was_listed(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            profiling_run._print_elided(
                [ProfileReport(name="a", entries=[], counts={"GONE": 1})], printed=1
            )
        self.assertEqual(buffer.getvalue(), "")


class TestExtrasSurviveARefusingForge(unittest.TestCase):
    """A pass over every profile used to die on the first forge answering
    403 to the detection reads, after the ref report had already muted it."""

    def _profile(self):
        return {"emulator": "T", "source": "https://github.com/o/n", "files": []}

    def test_a_refusal_is_printed_on_the_profile_not_raised(self):
        original = upstream.fetch_file

        def refuse(*_args, **_kwargs):
            raise forgehttp.UpstreamError("https://x/y: HTTP 403")

        upstream.fetch_file = refuse
        try:
            report = _sample_report()
            profiling_run._attach_detection(self._profile(), report, "x", False, True, False)
        finally:
            upstream.fetch_file = original
        self.assertEqual(report.detection_skipped, "https://x/y: HTTP 403")
        self.assertIn("extras skipped: https://x/y: HTTP 403", format_report(report))

    def test_detection_lands_on_the_report(self):
        """A name the pinned file already carried is listed, but only a name
        the pin did not carry is new since the pin."""
        files = {
            "pinsha0000": ['load("old.rom");'],
            "headsha000": ['load("old.rom");', 'load("added.rom"); /* 0xdeadbeef */'],
        }
        original = upstream.fetch_file
        upstream.fetch_file = lambda repo, rev, path, *a, **k: files[rev]
        report = _sample_report()
        try:
            profiling_run._attach_detection(self._profile(), report, "x", False, True, True)
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
            raise forgehttp.RateLimitError("quota")

        upstream.fetch_file = quota
        try:
            with self.assertRaises(forgehttp.RateLimitError):
                profiling_run._attach_detection(
                    self._profile(), _sample_report(), "x", False, True, False
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

    def test_carries_one_attention_verdict(self):
        """check_freshness rebuilt the verdict from single keys and dropped
        version_warning and detection_skipped: the report gives it once."""
        report = _sample_report()
        report.version_warning = "core_version 1.0 names tag commit aaaaaaa"
        report.detection_skipped = "HTTP 403"
        kinds = [(r["kind"], r["level"]) for r in report_to_dict(report)["attention"]]
        self.assertEqual(kinds, [
            ("review", "stale"), ("version", "stale"), ("detection_skipped", "unknown"),
        ])

    def test_strict_kinds_keep_review_and_uncheckable(self):
        from profiling.reports import STRICT_KINDS, ProfileReport

        self.assertTrue(_sample_report().fails(STRICT_KINDS))
        dead = ProfileReport("x", skipped="no declared repository answers",
                             skip_kind=SkipKind.UNANSWERED)
        self.assertTrue(dead.fails(STRICT_KINDS))
        warned = ProfileReport("y", pin="a", head="a", version_warning="behind")
        self.assertFalse(warned.fails(STRICT_KINDS))

    def test_markdown_lists_every_profile(self):
        text = format_markdown([_sample_report()])
        self.assertIn("demo", text)


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
        upstream.fetch_file = (
            lambda repo, sha, path, cache_dir, offline=False:
            trees.get((repo.slug, sha, path))
        )
        upstream.resolve_head = (
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
        self.assertEqual(rebase_refs(path, report).applied, [])
        self.assertFalse(bump_commit(path, report).moved)

    def test_the_builds_platforms_hold_say_so(self):
        # reicast is the commit Recalbox's reicast.mk builds, 789 commits
        # behind master. Compared to HEAD it showed eight refs to review that
        # nobody could act on.
        from model.profiles import load_emulator_profiles

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
        from model.profiles import load_emulator_profiles

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
        # a system upstream deleted: AdvanceMAME removed its Hyper Neo Geo 64
        # driver in dff25b6ee7, which advmame-1.4 and advancemame (AmberELEC's
        # 0f6a767) still carry.
        removed_upstream = {
            ("advmame-1.4", "advancemame"): {"hyper-neogeo64"},
            ("advmame-1.4", "advmame"): {"hyper-neogeo64"},
            ("advancemame", "advmame"): {"hyper-neogeo64"},
        }
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


class ACachedTipOlderThanThePin(TestBuildReport):
    """scummvm-standalone was pinned on 6f7b060d while the cached tip was
    77d80d7, its ancestor: a bump would have moved the pin backwards."""

    def test_the_tip_is_asked_again(self):
        upstreamtree.ancestry = lambda *a, **k: (0, 3)
        upstream.resolve_head = (
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
            raise forgehttp.NotCachedError(f"{path} not cached")

        upstream.fetch_file = cold
        with self.assertRaises(forgehttp.NotCachedError):
            build_report("test", self._profile(["a.c:2"]), self.dir, offline=True)


class EachCitationNamesTheCodeThatAsks(unittest.TestCase):
    """A profile reading a libretro core and the original emulator cited both
    trees alike, and readers could not tell which code asked for a file."""

    dir: str
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
        upstream.fetch_file = (
            lambda repo, sha, path, cache_dir, offline=False:
            trees.get(repo.slug, {}).get(path)
        )
        upstreamtree.list_tree = (
            lambda repo, sha, cache_dir, offline=False: (sorted(trees[repo.slug]), False)
        )
        upstream.resolve_head = (
            lambda repo, cache_dir, offline=False, branch=None:
            "pins" if repo.owner == "libretro" else "pinu"
        )
        path = Path(self.dir) / "t.yml"
        path.write_text(self.TEXT.replace("{ref}", ref), encoding="utf-8")
        profile = yaml.safe_load(path.read_text(encoding="utf-8"))
        with contextlib.redirect_stderr(io.StringIO()):
            report = build_report("t", profile, self.dir, text=path.read_text())
        rebase.attribute_refs(path, report, profile)
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

    dir: str
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
        upstream.fetch_file = (
            lambda repo, sha, path, cache_dir, offline=False:
            trees.get((repo.slug, sha), {}).get(path)
        )
        upstreamtree.list_tree = (
            lambda repo, sha, cache_dir, offline=False:
            (sorted(trees.get((repo.slug, sha), {})), False)
        )
        upstream.resolve_head = (
            lambda repo, cache_dir, offline=False, branch=None:
            "heads" if repo.owner == "libretro" else "pinu"
        )
        upstreamtree.compare = (
            lambda repo, base, head, cache_dir, offline=False:
            upstreamtree.CompareResult([], False)
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
        from model.sourceref import prose_runs

        runs = list(prose_runs(
            "# ref: source src/a.cpp:1656-1685, 1709-1738, upstream b.c:5"
        ))
        roles = [(p.path, p.role) for run in runs for p in run[3]]
        self.assertEqual(roles, [
            ("src/a.cpp", "source"), ("src/a.cpp", "source"), ("b.c", "upstream"),
        ])

    def test_an_abbreviated_location_reads_in_the_file_named_last(self):
        """devilutionx writes `Source/engine/assets.cpp:` then `(:507)` for
        each loader, and its pin moved under five uncollected numbers."""
        from model.sourceref import prose_runs

        text = (
            "Load order is defined in Source/engine/assets.cpp:\n"
            "  LoadCoreArchives() (:507) - devilutionx.mpq, fonts.mpq\n"
            "  LoadLanguageArchive() (:523) - <lang>.mpq\n"
            "Startup (src/port/Engine.cpp:65-127) loads sf64.o2r (:72, :88-89),\n"
            "falls back at :90-106. Wrapped (code/q_shared.h\n"
            ":44,65) and lightspark's (tools/errorgen:20).\n"
        )
        cited = [
            (p.path, p.start, p.end) for run in prose_runs(text) for p in run[3]
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
        from model.sourceref import prose_runs

        self.assertEqual(list(prose_runs("read at boot (:507), devilutionx.mpq")), [])


if __name__ == "__main__":
    unittest.main()
