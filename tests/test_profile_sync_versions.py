"""Tests for the profile_sync version check, new file detection and drift score (no network)."""

from __future__ import annotations

import tests

import tempfile
import unittest

from profiling import versions
from profiling.reports import (
    ProfileReport,
)
from profiling.versions import VersionReport, check_version, version_warning
from profiling.detection import (
    declared_hashes,
    declared_names,
    detect_new_files,
    tree_diff,
    unified_for_path,
    watch_hashes,
)
from profiling.triage import drift_score
from core import upstream
from core import forgehttp
from core import upstreamtree
from profiling import versionbasis
from core.upstreamtree import CompareResult, FileChange
from tests.profilesyncsupport import setUpModule as setUpModule
from tests.profilesyncsupport import tearDownModule as tearDownModule


class TestCheckVersion(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.repo = upstream.parse_repo("https://github.com/o/n")
        self._orig = (
            upstream.latest_release,
            upstream.list_tags,
            upstream.resolve_tag_commit,
            upstream.tag_commit,
        )
        upstream.latest_release = (
            lambda repo, cache, offline=False: upstream.Release(
                "v3.1.2", "2026-06-14", False
            )
        )
        upstream.list_tags = (
            lambda repo, cache, offline=False: ["v3.1.2", "v3.0.0"]
        )
        upstream.resolve_tag_commit = (
            lambda repo, tag, cache, offline=False: (
                "tagsha" if tag == "v3.0.0" else None
            )
        )
        upstream.tag_commit = upstream.resolve_tag_commit

    def _check(self, declared, tag=None):
        named = versionbasis.VersionTag("", declared, tag or declared, 0, self.repo, "source")
        return check_version(named, self.dir, False)

    def tearDown(self):
        (
            upstream.latest_release,
            upstream.list_tags,
            upstream.resolve_tag_commit,
            upstream.tag_commit,
        ) = self._orig
        self.tmp.cleanup()

    def test_reports_declared_and_latest(self):
        result = self._check("v3.0.0")
        self.assertEqual(result.declared, "v3.0.0")
        self.assertEqual(result.latest_release, "v3.1.2")
        self.assertEqual(result.release_date, "2026-06-14")

    def test_detects_declared_version_is_a_tag(self):
        result = self._check("v3.0.0")
        self.assertTrue(result.tag_matches_declared)
        self.assertEqual(result.tag_commit, "tagsha")

    def test_declared_version_not_a_tag(self):
        result = self._check("5.2")
        self.assertFalse(result.tag_matches_declared)
        self.assertIsNone(result.tag_commit)

    def test_none_without_core_version(self):
        self.assertIsNone(self._check(""))

    def test_warning_when_tag_commit_differs_from_pin(self):
        result = self._check("v3.0.0")
        self.assertIsNotNone(version_warning(result, "otherpin"))

    def test_no_warning_when_tag_commit_matches_pin(self):
        result = self._check("v3.0.0")
        self.assertIsNone(version_warning(result, "tagsha"))

    def test_warning_says_which_side_of_the_tag_the_pin_is(self):
        # 52 warnings read alike: a build after its release and a pin older
        # than the release it claims could not be told apart.
        result = self._check("v3.0.0")
        self.assertIn("4 commits after the tag", version_warning(result, "p", (4, 0)))
        self.assertIn("core_version is later than the code",
                      version_warning(result, "p", (0, 9)))
        self.assertIn("off the tag's history", version_warning(result, "p", (2, 3)))

    def test_warning_names_a_release_the_pin_already_contains(self):
        result = self._check("v3.0.0")
        warning = version_warning(result, "tagsha", None, "v3.1.0")
        self.assertIn("already contains release v3.1.0", warning)


class APassedReleaseIsNewerThanTheTag(unittest.TestCase):
    """pcsx2x6 declares tag v0.2.22 while its latest published release is
    v0.2.20: the pin holds v0.2.20 without core_version being older."""

    def test_a_release_older_than_the_declared_tag_is_not_passed(self):
        from unittest import mock

        version = versions.VersionReport(
            "v0.2.22", "v0.2.22", "v0.2.20", "2026-07-25", True, "tag22"
        )
        with mock.patch.object(upstream, "tag_commit", return_value="rel20"), \
                mock.patch.object(upstreamtree, "ancestry", return_value=(5, 0)):
            self.assertIsNone(versions.latest_passed_release("repo", version, "pin", "c", True))


class ANewerReleaseThanTheTag(unittest.TestCase):
    """armsx2 sat on its 2.8 tag while 2.9 was out, and read as clean."""

    def _newer(self, after_tag, after_pin):
        from unittest import mock

        version = versions.VersionReport("2.8", "2.9", "2.9", "2026-10-01", True, "tag28")
        answers = iter([after_tag, after_pin])
        with mock.patch.object(upstream, "tag_commit", return_value="rel29"), \
                mock.patch.object(upstreamtree, "ancestry", side_effect=lambda *a, **k: next(answers)):
            return versions.newer_release("repo", version, "tag28", "c", True)

    def test_a_later_release_is_named(self):
        self.assertEqual(self._newer((12, 0), (12, 0)), "2.9")

    def test_an_older_or_unrelated_release_is_not(self):
        self.assertIsNone(self._newer((0, 5), (0, 5)))
        self.assertIsNone(self._newer((3, 4), (3, 4)))


class AProjectThatOnlyTags(unittest.TestCase):
    """eightyone sat on v1.2 and higan on 106 while v1.3 and v107 were tagged:
    with no release published, nothing compared them."""

    def test_a_version_tag_stands_in_for_the_missing_release(self):
        version = versions.VersionReport("v1.2", "v1.3", None, None, True, "tag12")
        self.assertEqual(versions.published_version(version), "v1.3")
        for tag in ("v107", "1.1d", "v9.0-6", "2.55"):
            version = versions.VersionReport("x", tag, None, None, False, None)
            self.assertEqual(versions.published_version(version), tag)

    def test_a_nightly_tag_does_not(self):
        for tag in ("latest-nightly", "continuous", "nightly-20261001"):
            version = versions.VersionReport("v1.2", tag, None, None, True, "t")
            self.assertIsNone(versions.published_version(version))

    def test_a_release_wins_over_a_newer_tag(self):
        version = versions.VersionReport("1.0", "1.2", "1.1", "2026-01-01", True, "t")
        self.assertEqual(versions.published_version(version), "1.1")

    def test_a_newer_tag_is_named(self):
        from unittest import mock

        version = versions.VersionReport("v1.2", "v1.3", None, None, True, "tag12")
        with mock.patch.object(upstream, "tag_commit", return_value="tag13"), \
                mock.patch.object(upstreamtree, "ancestry", return_value=(7, 0)):
            self.assertEqual(versions.newer_release("repo", version, "tag12", "c", True), "v1.3")


class APassedReleaseUnderAnUntaggedVersion(unittest.TestCase):
    """parallel-launcher declared 9.0.5, a name no tag carries, and its HEAD
    already held release v9.0-6: the missing tag silenced the warning."""

    def test_the_passed_release_is_named_without_a_declared_tag(self):
        version = versions.VersionReport("9.0.5", "v9.0-6", "v9.0-6", "2026-08-08", False, None)
        warning = version_warning(version, "head", None, "v9.0-6")
        self.assertIn("already contains release v9.0-6", warning)

    def test_only_a_higher_number_counts_without_a_tag(self):
        from unittest import mock

        cases = {("9.0.5", "v9.0-6"): "v9.0-6", ("1.61", "1.53"): None,
                 ("v0.1-12070", "latest"): None, ("Git", "v2.7"): None, ("5.2", "v5.2"): None,
                 ("v1", "v1.0"): None, ("0.83", "20120302"): None, ("0.160", "v1.4.1"): None,
                 ("0.0.35", "v0.0.43"): "v0.0.43", ("106", "v107"): "v107", ("v1", "20170424"): None}
        for (declared, release), expected in cases.items():
            version = versions.VersionReport(declared, release, release, "d", False, None)
            with self.subTest(declared=declared, release=release), \
                    mock.patch.object(upstream, "tag_commit", return_value="rel"), \
                    mock.patch.object(upstreamtree, "ancestry", return_value=(3, 0)):
                self.assertEqual(versions.latest_passed_release("repo", version, "pin", "c", True), expected)

    def test_no_tag_and_nothing_passed_stays_quiet(self):
        version = versions.VersionReport("9.0.5", None, None, None, False, None)
        self.assertIsNone(version_warning(version, "head"))


@tests.ONLINE
class TestAncestry(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = forgehttp.http_json

    def tearDown(self):
        forgehttp.http_json = self.saved
        self.tmp.cleanup()

    def test_github_answers_both_directions_at_once(self):
        calls = []

        def answer(url):
            calls.append(url)
            return {"ahead_by": 3, "behind_by": 0}

        forgehttp.http_json = answer
        repo = upstream.parse_repo("https://github.com/o/n")
        self.assertEqual(
            upstreamtree.ancestry(repo, "tag", "pin", self.tmp.name), (3, 0)
        )
        self.assertEqual(len(calls), 1)

    def test_gitlab_is_asked_both_ways(self):
        def answer(url):
            forward = "from=tag&to=pin" in url
            return {"commits": [{}] * (0 if forward else 5)}

        forgehttp.http_json = answer
        repo = upstream.parse_repo("https://gitlab.com/o/n")
        self.assertEqual(
            upstreamtree.ancestry(repo, "tag", "pin", self.tmp.name), (0, 5)
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
        self.assertGreater(drift_score(heavy, [], 0), drift_score(light, [], 0))

    def test_version_mismatch_adds_weight(self):
        report = ProfileReport(name="a", entries=[], counts={})
        stale = VersionReport("v1.0", "v2.0", "v2.0", "2026-06-01", False, None)
        current = VersionReport("v2.0", "v2.0", "v2.0", "2026-06-01", True, None)
        self.assertGreater(
            drift_score(report, [stale], 0), drift_score(report, [current], 0)
        )

    def test_commit_count_is_a_light_signal(self):
        report = ProfileReport(name="a", entries=[], counts={})
        self.assertGreater(drift_score(report, [], 100), drift_score(report, [], 0))

    def test_clean_profile_scores_zero(self):
        report = ProfileReport(name="a", entries=[], counts={"ANCHORED": 5})
        self.assertEqual(drift_score(report, [], 0), 0)

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
                self.assertGreater(drift_score(report, [], 0), drift_score(gone, [], 0))


if __name__ == "__main__":
    unittest.main()
