"""Tests for the profile_sync command: selection, output modes, records, triage (no network)."""

from __future__ import annotations

import tests

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

import profile_sync
from profiling import reports as profiling_reports
from profiling import run as profiling_run
from profiling import sourcepaths as profiling_sourcepaths
from profiling import worktree as profiling_worktree
from profiling import triage
from profiling import quota as profiling_quota
from profiling import selection as profiling_selection
from model import profiles as model_profiles
from profiling.reports import (
    CitedSource,
    EntryReport,
    ProfileReport,
    SkipKind,
    fetch_plan,
    format_report,
    report_to_dict,
)
from profiling.anchoring import PartResult
from profiling.yamledit import (
    YamlWriteError,
)
from profile_sync import build_parser
from profiling.selection import select_profiles
from model.sourceref import RefPart
from core import upstream
from core import forgehttp
from tests.profilesyncsupport import _SAMPLE_REPO, _sample_report
from tests.profilesyncsupport import setUpModule as setUpModule
from tests.profilesyncsupport import tearDownModule as tearDownModule


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


class TestRateLimitEndsOneProfile(unittest.TestCase):
    """git.libretro.com answered 429 on cemu's tree and the pass over 647
    profiles stopped with a traceback and no report at all."""

    def test_the_pass_goes_on_and_fails(self):
        from unittest import mock

        def build(name, *_args, **_kwargs):
            if name == "cemu":
                raise forgehttp.RateLimitError(
                    "https://git.libretro.com/x: HTTP 429", "git.libretro.com"
                )
            return ProfileReport(name=name, counts={"CHANGED": 1})

        out, err = io.StringIO(), io.StringIO()
        saved = sys.argv
        try:
            sys.argv = ["profile_sync.py", "--all", "--json"]
            with mock.patch.object(model_profiles, "load_emulator_profiles", return_value={}), \
                    mock.patch.object(profiling_selection, "select_profiles",
                                      return_value={"cemu": {}, "after": {}}), \
                    mock.patch.object(profiling_quota, "check_quota"), \
                    mock.patch.object(profiling_run, "build_report", side_effect=build), \
                    contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err), \
                    self.assertRaises(SystemExit) as caught:
                profile_sync.main()
        finally:
            sys.argv = saved
        self.assertEqual(caught.exception.code, 1)
        by_name = {r["name"]: r for r in json.loads(out.getvalue())}
        self.assertEqual(by_name["cemu"]["skipped"], "rate limited: git.libretro.com")
        self.assertEqual(by_name["after"]["needs_review"], 1)


class AWriteRefreshesTheSourcePaths(unittest.TestCase):
    """Each bump left website/src/data/source-paths.json behind its pins and
    the site's freshness test red until someone ran site_sources by hand."""

    def _args(self, **kw):
        base = {
            "dry_run": False, "offline": False,
            "emulators_dir": str(profiling_sourcepaths.REPO_ROOT / "emulators"), "cache_dir": ".cache/upstream",
        }
        return argparse.Namespace(**{**base, **kw})

    def test_only_a_real_online_write_refreshes(self):
        from unittest import mock

        from sitegen import sources

        with mock.patch.object(sources, "build_source_paths", return_value=({}, [])) as built, \
                mock.patch.dict(os.environ, {"RETROBIOS_OFFLINE": ""}), \
                mock.patch.object(profiling_sourcepaths, "load_emulator_profiles", return_value={}), \
                mock.patch.object(sources, "write_if_changed") as written, \
                contextlib.redirect_stderr(io.StringIO()):
            profiling_sourcepaths.refresh_source_paths(self._args(), set())
            self.assertFalse(built.called)
            profiling_sourcepaths.refresh_source_paths(self._args(dry_run=True), {"x"})
            self.assertFalse(built.called)
            profiling_sourcepaths.refresh_source_paths(self._args(), {"x"})
            self.assertTrue(built.called and written.called)


    def test_the_record_reads_the_pins_just_written(self):
        # The loader caches by directory and the run had loaded the profiles
        # before writing them: the record kept the pins it had replaced.
        from unittest import mock

        from model.profiles import emulator_profiles_cache
        from sitegen import sources

        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "p.yml"
            profile.write_text('emulator: P\nsource_commit: "old"\n', encoding="utf-8")
            emulator_profiles_cache.clear()
            self.addCleanup(emulator_profiles_cache.clear)
            model_profiles.load_emulator_profiles(tmp, skip_aliases=False)
            profile.write_text('emulator: P\nsource_commit: "new"\n', encoding="utf-8")
            with mock.patch.object(sources, "build_source_paths", return_value=({}, [])) as built, \
                    mock.patch.dict(os.environ, {"RETROBIOS_OFFLINE": ""}), \
                    mock.patch.object(profiling_sourcepaths, "REPO_ROOT", Path(tmp).parent), \
                    mock.patch.object(profiling_sourcepaths, "EMULATORS_DIR", Path(tmp).name), \
                    mock.patch.object(sources, "write_if_changed"), \
                    contextlib.redirect_stderr(io.StringIO()), \
                    contextlib.redirect_stdout(io.StringIO()):
                profiling_sourcepaths.refresh_source_paths(self._args(emulators_dir=tmp), {"p"})
            self.assertEqual(built.call_args[0][0]["p"]["source_commit"], "new")

    def test_another_profile_tree_leaves_the_record_alone(self):
        # Rebuilt from a one-profile copy, the record went from 701 trees to 1.
        from unittest import mock

        from sitegen import sources

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(sources, "refresh_record") as refreshed, \
                mock.patch.dict(os.environ, {"RETROBIOS_OFFLINE": ""}), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            profiling_sourcepaths.refresh_source_paths(self._args(emulators_dir=tmp), {"p"})
        self.assertFalse(refreshed.called)
        self.assertIn(f"site_sources.py --fetch --emulators-dir {tmp}", err.getvalue())

    def test_the_run_cache_and_the_record_path_are_passed(self):
        from unittest import mock

        from sitegen import sources

        with mock.patch.object(sources, "refresh_record", return_value=({}, [])) as refreshed, \
                mock.patch.dict(os.environ, {"RETROBIOS_OFFLINE": ""}), \
                mock.patch.object(profiling_sourcepaths, "load_emulator_profiles", return_value={}), \
                contextlib.redirect_stderr(io.StringIO()):
            profiling_sourcepaths.refresh_source_paths(self._args(cache_dir="tmp/c"), {"x"})
        self.assertEqual(refreshed.call_args.args[1], [Path("tmp/c")])
        self.assertEqual(refreshed.call_args.kwargs["output"], sources.SOURCE_PATHS)

    def test_the_record_waits_for_a_run_holding_the_repository(self):
        """profile_sync rewrote source-paths.json without the repository
        hold site_sources takes, in the middle of a pipeline run."""
        from unittest import mock

        from core.artifacts import ArtifactLockBusy
        from sitegen import sources

        busy = mock.MagicMock()
        busy.__enter__.side_effect = ArtifactLockBusy("another run is writing")
        with mock.patch.object(sources, "repository_output_lock", return_value=busy) as lock, \
                mock.patch.object(sources, "build_source_paths") as built, \
                mock.patch.dict(os.environ, {"RETROBIOS_OFFLINE": ""}), \
                mock.patch.object(profiling_sourcepaths, "load_emulator_profiles", return_value={}), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            profiling_sourcepaths.refresh_source_paths(self._args(), {"x"})
        lock.assert_called_once_with(str(sources.SOURCE_PATHS))
        self.assertFalse(built.called)
        self.assertIn("site_sources.py --fetch", err.getvalue())


class EveryWriterIsRecorded(unittest.TestCase):
    """--backfill-commits wrote a pin without saying so: the record of cited
    source paths then lacked the tree that pin names."""

    def test_a_backfilled_pin_is_a_write(self):
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "p.yml"
            path.write_text('emulator: P\nprofiled_date: "2026-01-01"\n', encoding="utf-8")
            args = argparse.Namespace(
                emulators_dir=tmp, backfill_commits=True, rebase_refs=False,
                bump_commit=False, dry_run=False,
            )
            report = ProfileReport(name="p", entries=[], counts={}, pin="abcdef0")
            written: set[str] = set()
            with mock.patch.object(profiling_run, "_build_full_report", return_value=report), \
                    contextlib.redirect_stdout(io.StringIO()):
                profiling_run.read_one_profile(
                    args, "p", yaml.safe_load(path.read_text()), [], set(), True, written,
                )
            self.assertIn('source_commit: "abcdef0"', path.read_text())
        self.assertEqual(written, {"p"})

    def test_a_write_put_back_is_not_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "p.yml"
            path.write_text("emulator: P\n", encoding="utf-8")
            written: set[str] = set()
            with profiling_sourcepaths.record_write(path, "p", written):
                path.write_text("emulator: Q\n", encoding="utf-8")
                path.write_text("emulator: P\n", encoding="utf-8")
            self.assertEqual(written, set())
            with self.assertRaises(YamlWriteError), \
                    profiling_sourcepaths.record_write(path, "p", written):
                path.write_text("emulator: Q\n", encoding="utf-8")
                raise YamlWriteError("a later write refused")
        self.assertEqual(written, {"p"})


class AnUnreadTreeKeepsItsRecord(unittest.TestCase):
    """site_sources --fetch, rate-limited by GitLab, dropped about twenty
    trees it never read from source-paths.json."""

    def test_unread_trees_carry_over(self):
        from sitegen import sources

        kept = sources.keep_unread(
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
            with mock.patch.object(model_profiles, "load_emulator_profiles", return_value={}), \
                    mock.patch.object(profiling_selection, "select_profiles",
                                      return_value={"clean": {}, "drift": {}}), \
                    mock.patch.object(profiling_quota, "check_quota"), \
                    mock.patch.object(profiling_run, "build_report",
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
                profiling_run, "realign_prose",
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

    def test_markdown_carries_detection(self):
        """Detection lives on the report, and the markdown document embeds
        each report's text: refusing the pair left the finding unwritten."""
        from unittest import mock

        def detect(profile, report, *_):
            report.new_files = [
                {"path": "a.c", "line": 3, "name": "new.rom", "since_pin": True}
            ]
            report.new_hashes = [{"path": "a.c", "kind": "md5", "value": "0" * 32}]

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(profiling_run, "_attach_detection", side_effect=detect):
            code, _, err = self._main(
                "--markdown", "--detect-new-files", "--watch-hashes", "--report-dir", tmp,
            )
            self.assertEqual(code, 0, err)
            document = next(Path(tmp).glob("profile-sync-*.md")).read_text(encoding="utf-8")
        self.assertIn("  new file: a.c:3  new.rom", document)
        self.assertIn(f"  new md5: a.c  {'0' * 32}", document)

    def test_rankings_refuse_detection(self):
        code, _, err = self._main("--triage", "--detect-new-files")
        self.assertEqual(code, 1)
        self.assertIn("--detect-new-files", err)

    def test_json_carries_detection(self):
        """check_freshness reads --json: a new upstream file or hash printed
        only in the text report stayed a human reading."""
        from unittest import mock

        def detect(profile, report, *_):
            report.new_files = [
                {"path": "a.c", "line": 3, "name": "new.rom", "since_pin": True}
            ]
            report.new_hashes = [{"path": "a.c", "kind": "md5", "value": "0" * 32}]

        with mock.patch.object(profiling_run, "_attach_detection", side_effect=detect):
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

    def test_json_carries_the_ranking(self):
        """--json --triage printed the plain report: no score, no order."""
        code, out, err = self._main("--json", "--triage")
        self.assertEqual(code, 0, err)
        rows = json.loads(out)
        self.assertEqual([r["name"] for r in rows], ["drift", "clean"])
        self.assertEqual([r["drift_score"] for r in rows], [30, 0])
        self.assertIsNone(rows[0]["drift_refused"])

    def test_the_ranking_as_json_carries_the_version_check(self):
        code, out, err = self._main("--json", "--triage", "--check-version")
        self.assertEqual(code, 0, err)
        self.assertTrue(all("version" in row for row in json.loads(out)))

    def test_two_outputs_are_refused(self):
        for pair in (("--json", "--markdown"), ("--markdown", "--triage"),
                     ("--json", "--fetch-plan"), ("--fetch-plan", "--triage")):
            code, out, err = self._main(*pair)
            self.assertEqual(code, 1, pair)
            self.assertIn("separate outputs", err, pair)
            self.assertEqual(out, "", pair)

    def test_a_profile_the_forge_failed_is_listed_and_fails_the_run(self):
        """Dropped by --changed-only, a 502 read as nothing to review."""
        from unittest import mock

        def build(name, *args, **kwargs):
            if name == "drift":
                raise forgehttp.UpstreamError("https://x: HTTP 502")
            return ProfileReport(name=name)

        out = io.StringIO()
        saved = sys.argv
        try:
            sys.argv = ["profile_sync.py", "--all", "--changed-only", "--json"]
            with mock.patch.object(model_profiles, "load_emulator_profiles", return_value={}), \
                    mock.patch.object(profiling_selection, "select_profiles",
                                      return_value={"clean": {}, "drift": {}}), \
                    mock.patch.object(profiling_quota, "check_quota"), \
                    mock.patch.object(profiling_run, "build_report", side_effect=build), \
                    contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as caught:
                profile_sync.main()
        finally:
            sys.argv = saved
        self.assertEqual(caught.exception.code, 1)
        (row,) = json.loads(out.getvalue())
        self.assertEqual(row["name"], "drift")
        self.assertIn("upstream error", row["skipped"])


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
            self.assertTrue(profiling_worktree.emulators_dir_is_dirty(root))

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
            self.assertTrue(profiling_worktree.emulators_dir_is_dirty(root, ["a"]))
            self.assertFalse(profiling_worktree.emulators_dir_is_dirty(root, ["b"]))

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
            self.assertEqual(profiling_worktree.emulators_dir_is_dirty(root, ["a", "b", "c"]),
                             ["b.yml"])
            err = io.StringIO()
            with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
                profiling_worktree.refuse_dirty_tree(root, ["a", "b", "c"])
        self.assertIn("b.yml has uncommitted changes", err.getvalue())
        self.assertNotIn("a.yml", err.getvalue())

    def test_a_tree_outside_any_repository_is_not_clean(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.dict(
            os.environ, {"GIT_CEILING_DIRECTORIES": str(Path(root).parent)}
        ), self.assertRaises(RuntimeError):
            profiling_worktree.emulators_dir_is_dirty(root)


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
            select_profiles(self.PROFILES, self._args(system="atari-lynxx"))
        self.assertIn("atari-lynx", str(caught.exception.code))

    def test_a_misspelt_emulator_suggests(self):
        with self.assertRaises(SystemExit) as caught:
            select_profiles(self.PROFILES, self._args(emulator="handyy"))
        self.assertIn("Close matches: handy", str(caught.exception.code))

    def test_a_matching_filter_selects(self):
        selected = select_profiles(self.PROFILES, self._args(system="atari-lynx"))
        self.assertEqual(sorted(selected), ["handy", "mednafen_lynx"])

    def test_system_matches_as_the_listing_does(self):
        """verify.py --list-systems printed `saturn`, which selected 1 profile
        of 11 because 10 declare sega-saturn."""
        profiles = {
            "a": {"type": "libretro", "systems": ["sega-saturn"]},
            "b": {"type": "libretro", "systems": ["saturn"]},
        }
        for spelling in ("saturn", "sega-saturn"):
            selected = select_profiles(profiles, self._args(system=spelling))
            self.assertEqual(sorted(selected), ["a", "b"])

    def test_the_hint_counts_what_the_listing_prints(self):
        profiles = {
            "a": {"type": "libretro", "systems": ["sega-saturn"]},
            "b": {"type": "libretro", "systems": ["saturn"]},
            "c": {"type": "libretro", "systems": ["atari-lynx"]},
        }
        with self.assertRaises(SystemExit) as caught:
            select_profiles(profiles, self._args(system="nothing"))
        self.assertIn("Known: atari-lynx, sega-saturn.", str(caught.exception.code))


class TheUnknownProfileHintCountsTheListing(unittest.TestCase):
    """profile_sync said "verify.py --list-emulators lists all 553" for a
    listing of 530: the alias and test profiles it counted are not listed."""

    def test_the_count_matches(self):
        import subprocess

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
        def report(kind):
            return ProfileReport(name="p", entries=[], counts={}, skipped="any words",
                                 skip_kind=kind)

        self.assertTrue(report(SkipKind.UNANSWERED).uncheckable())
        self.assertTrue(report(SkipKind.GONE).uncheckable())
        self.assertTrue(report(SkipKind.GONE_CONTRADICTED).uncheckable())
        self.assertFalse(report(SkipKind.UNSUPPORTED_HOST).uncheckable())
        self.assertFalse(report(SkipKind.GONE_DECLARED).uncheckable())
        self.assertFalse(report(SkipKind.NO_SOURCE_REF).uncheckable())
        self.assertFalse(report(SkipKind.OFFLINE).uncheckable())

    def test_a_forge_failing_this_time_is_unread_in_the_json_too(self):
        """profile_sync exited 1 on a forge answering 500 or 429 while its
        JSON row carried no attention, so check_freshness --profiles showed
        SKIPPED and exited 0."""
        for kind in (SkipKind.UPSTREAM_ERROR, SkipKind.RATE_LIMITED):
            report = ProfileReport(name="p", skipped="x", skip_kind=kind)
            self.assertTrue(report.unreached())
            self.assertEqual(
                [(r.kind, r.level) for r in report.attention()],
                [("unreached", profiling_reports.UNKNOWN_LEVEL)],
            )
            self.assertNotIn("skip_kind", report_to_dict(report))
        self.assertFalse(ProfileReport(name="p", skipped="x",
                                       skip_kind=SkipKind.OFFLINE).unreached())


class AnOnlinePassSaysWhereItIs(unittest.TestCase):
    """`--all --triage` online printed nothing for 15 minutes, and Ctrl-C
    left no ranking at all, while --offline answered in three."""

    def _main(self, *argv: str, stop_after: int | None = None):
        calls: list[str] = []

        def build(_args, name, _profile, _path, _failed):
            if stop_after is not None and len(calls) == stop_after:
                raise KeyboardInterrupt
            calls.append(name)
            return ProfileReport(name=name, entries=[], counts={})

        out, err = io.StringIO(), io.StringIO()
        saved = sys.argv
        try:
            sys.argv = ["profile_sync.py", "--all", "--triage", *argv]
            with mock.patch.object(profiling_run, "_build_full_report", side_effect=build), \
                    mock.patch.object(profiling_quota, "check_quota"), \
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
        clock = iter([0.0, 10.0, triage.PROGRESS_SECONDS + 1, 40.0])
        err = io.StringIO()
        with mock.patch.object(triage.time, "monotonic", lambda: next(clock)), \
                contextlib.redirect_stderr(err):
            progress = triage.Progress(9, "read", quiet=False)
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
            cited_sources=[
                CitedSource(f"d/{i}.c", _SAMPLE_REPO, "p", "h") for i in range(paths)
            ],
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
        with mock.patch.object(triage, "check_version", return_value=None), \
                mock.patch.object(upstream, "commits_touching",
                                  return_value=0), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            triage.print_triage(args, selected, reports)
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
            skip_kind=SkipKind.UNANSWERED,
        )
        reports = [self._report("clean", 1), gone]
        selected = {r.name: {"source": "https://github.com/o/n"} for r in reports}
        args = argparse.Namespace(cache_dir="unused", offline=True)
        out = io.StringIO()
        with mock.patch.object(triage, "check_version", return_value=None), \
                mock.patch.object(upstream, "commits_touching",
                                  return_value=0), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            triage.print_triage(args, selected, reports)
        lines = out.getvalue().splitlines()
        self.assertIn("gone", lines[1])
        self.assertEqual(lines[-1], "2 profiles, 1 with something to review")


if __name__ == "__main__":
    unittest.main()
