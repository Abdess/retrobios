"""Tests for the repositories profile_sync reads: submodules, mirrors, forks, branches, roles (no network)."""

from __future__ import annotations

import tests

import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import profile_sync
from profiling import anchoring
from profiling import citations as profiling_citations
from profiling import realign
from profiling import reports as profiling_reports
from profiling import repos as profiling_repos
from profiling import resolver
from profiling import reportinputs
from profiling import worktree as profiling_worktree
from profiling import versions
from model import sourceref
from profiling.reports import (
    ProfileReport,
    format_report,
    report_to_dict,
)
from profiling.selection import select_profiles
from tests.sources import script_source
from core import upstream
from core import forgehttp
from core import upstreamtree
from tests.profilesyncsupport import setUpModule as setUpModule
from tests.profilesyncsupport import tearDownModule as tearDownModule


class UpstreamVendoredAsASubmodule(unittest.TestCase):
    """libretro/TIC-80 builds nesbox/TIC-80 through its `core` submodule, and
    tic80's upstream_commit is that submodule's commit. Compared to nesbox's
    own HEAD it reported changes the shipped core never had, and a bump would
    have moved upstream_commit past what libretro builds."""

    def _views(self, links: dict) -> list:
        from unittest import mock

        repo_s, repo_u = object(), object()
        views = [
            profiling_repos.RepoView(repo_s, "src-pin", "src-head", "source_commit", "source"),
            profiling_repos.RepoView(repo_u, "sub-old", "nesbox-tip", "upstream_commit", "upstream"),
        ]
        with mock.patch.object(
            upstreamtree, "list_gitlinks",
            side_effect=lambda repo, sha, *a, **k: links.get(sha, {}),
        ):
            return profiling_repos._follow_submodule(views, "cache", True)

    def test_the_upstream_head_is_what_the_port_head_builds(self):
        views = self._views({"src-pin": {"core": "sub-old"}, "src-head": {"core": "sub-new"}})
        self.assertEqual(views[1].head, "sub-new")
        self.assertEqual(views[0].head, "src-head")

    def test_an_upstream_the_port_does_not_vendor_keeps_its_tip(self):
        views = self._views({"src-pin": {"deps/zlib": "other"}, "src-head": {}})
        self.assertEqual(views[1].head, "nesbox-tip")

    def test_a_truncated_port_tree_is_not_read_as_no_submodule(self):
        """A partial listing kept nesbox's tip, the commit a bump must not
        move upstream_commit to."""
        views = [
            profiling_repos.RepoView(object(), "src-pin", "src-head", "source_commit", "source"),
            profiling_repos.RepoView(object(), "sub-old", "nesbox-tip", "upstream_commit", "upstream"),
        ]
        with mock.patch.object(
            upstreamtree, "list_gitlinks",
            side_effect=forgehttp.TruncatedListingError("tree listing truncated"),
        ), self.assertRaises(forgehttp.TruncatedListingError):
            profiling_repos._follow_submodule(views, "cache", True)


class TruncatedGitlinksInTheResolver(unittest.TestCase):
    """A read-only report goes on past a partial listing, and says so."""

    def test_the_lost_tree_yields_no_link_and_the_next_is_read(self):
        from types import SimpleNamespace

        views = [SimpleNamespace(repo="a", pin="p1"), SimpleNamespace(repo="b", pin="p2")]
        state = SimpleNamespace(views=views, cache_dir="c", offline=True, name="demo")

        def links(repo, sha, *_args):
            if repo == "a":
                raise forgehttp.TruncatedListingError("a@p1: tree listing truncated")
            return {"sub": "s"}

        with mock.patch.object(upstreamtree, "list_gitlinks", side_effect=links), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            found = [list(paths) for paths in resolver._Resolver.gitlinks_in_order(state)]
        self.assertEqual(found, [[], ["sub"]])
        self.assertIn("submodule paths unknown", err.getvalue())


class AMirrorOutlivesAGoneSource(unittest.TestCase):
    """yuzu's source answers 451. select_views stopped on it and never read
    the source_mirror declared after it, so the profile stayed unchecked."""

    def test_the_mirror_is_read_when_the_source_is_gone(self):
        from unittest import mock

        gone_repo = upstream.make_repo("github.com", "yuzu-emu-mirror", "yuzu")
        mirror = upstream.make_repo("github.com", "fork", "yuzu")

        def head(repo, cache_dir, offline=False, branch=None):
            if repo == gone_repo:
                raise forgehttp.GoneError("HTTP 451")
            return "mirror-head"

        profile = {
            "source": "https://github.com/yuzu-emu-mirror/yuzu",
            "source_mirror": "https://github.com/fork/yuzu",
            "source_commit": "pin",
        }
        with mock.patch.object(upstream, "resolve_head", side_effect=head), \
                mock.patch.object(profiling_repos, "resolve_pin", return_value=("pin", "source_commit")):
            views = profiling_repos.select_views(profile, "cache", True)
        self.assertEqual([(v.repo, v.field) for v in views], [(mirror, "source_mirror")])

    def test_the_mirror_takes_the_gone_source_place_before_the_upstream(self):
        """Read last, the mirror ranked after a live upstream, while the
        prose pass and the site read it in the source's place."""
        from unittest import mock

        gone_repo = upstream.make_repo("github.com", "gone", "emu")
        mirror = upstream.make_repo("github.com", "fork", "emu")
        live = upstream.make_repo("github.com", "up", "emu")

        def head(repo, cache_dir, offline=False, branch=None):
            if repo == gone_repo:
                raise forgehttp.GoneError("HTTP 404")
            return "tip"

        profile = {
            "source": "https://github.com/gone/emu",
            "upstream": "https://github.com/up/emu",
            "source_mirror": "https://github.com/fork/emu",
            "source_commit": "pin",
            "upstream_gone": "gone/emu answers 404",
        }
        with mock.patch.object(upstream, "resolve_head", side_effect=head), \
                mock.patch.object(profiling_repos, "resolve_pin", return_value=("pin", "c")):
            views = profiling_repos.select_views(profile, "cache", True)
        self.assertEqual([(v.repo, v.field) for v in views],
                         [(mirror, "source_mirror"), (live, "upstream")])

    def test_the_gone_source_is_still_asked(self):
        """A forge answering again contradicts upstream_gone, so it is asked."""
        from unittest import mock

        asked = []

        def head(repo, cache_dir, offline=False, branch=None):
            asked.append(repo.slug)
            return "tip"

        profile = {
            "source": "https://github.com/gone/emu",
            "source_mirror": "https://github.com/fork/emu",
            "source_commit": "pin",
            "upstream_gone": "gone/emu answers 404",
        }
        with mock.patch.object(upstream, "resolve_head", side_effect=head), \
                mock.patch.object(profiling_repos, "resolve_pin", return_value=("pin", "c")):
            views = profiling_repos.select_views(profile, "cache", True)
        self.assertEqual(asked[0], "gone/emu")
        self.assertEqual(views[0].field, "source")


class AHeldUpstreamStaysOnItsPin(unittest.TestCase):
    """aps3e vendors RPCS3 1f080485 and yaps2 PCSX2 342db515: a bump moved
    upstream_commit to the upstream HEAD neither port carries."""

    def test_the_upstream_view_is_read_at_its_pin(self):
        views = [
            profiling_repos.RepoView("fork", "p", "h", "source_commit", "source"),
            profiling_repos.RepoView("up", "vendored", "tip", "upstream_commit", "upstream"),
        ]
        held = profiling_repos._hold_upstream({"upstream_frozen": "vendored tree"}, views)
        self.assertEqual((held[0].head, held[1].head), ("h", "vendored"))
        self.assertEqual(profiling_repos._hold_upstream({}, views), views)


class RealignReadsThePathAsWritten(unittest.TestCase):
    """hatarib cites hatari/src/tos.c, a path of hatariB. When only
    upstream_commit moved, realign stripped the hatari/ prefix, read
    hatari/hatari's src/tos.c and proposed moving a correct citation."""

    def test_an_unmoved_repository_carrying_the_path_keeps_it(self):
        from unittest import mock

        fork = upstream.make_repo("github.com", "b", "hatariB")
        up = upstream.make_repo("github.com", "hatari", "hatari")
        trees = {(fork, "fork-pin"): {"hatari/src/tos.c"},
                 (up, "old"): {"src/tos.c"}, (up, "new"): {"src/tos.c"}}

        def fetch(repo, sha, path, *a, **k):
            return ["line"] * 40 if path in trees.get((repo, sha), set()) else None

        part = sourceref.RefPart("hatari/src/tos.c", 10, 10, "10")
        with mock.patch.object(upstream, "fetch_file", side_effect=fetch), \
                mock.patch.object(realign, "_resolve_at",
                                  return_value=("found", ("src/tos.c", ["x"] * 40))):
            result = realign._realign_part(
                part, [(up, "old", "new")], "cache", True,
                pinned=[(fork, "fork-pin"), (up, "new")],
            )
        self.assertIsNone(result)


class RealignGivesASharedPathToTheFirstRepository(unittest.TestCase):
    """freej2me-plus and hex007/freej2me both hold src/libretro/: with only
    upstream_commit moved, the fork's citations were read in upstream."""

    def test_the_source_declared_first_keeps_it(self):
        from unittest import mock

        fork = upstream.make_repo("github.com", "t", "freej2me-plus")
        up = upstream.make_repo("github.com", "hex007", "freej2me")
        part = sourceref.RefPart("src/libretro/freej2me_libretro.c", 39, 46, "39-46")
        with mock.patch.object(
            upstream, "fetch_file", return_value=["line"] * 99
        ), mock.patch.object(
            realign, "_resolve_at", return_value=("found", (part.path, ["x"] * 99))
        ):
            result = realign._realign_part(
                part, [(up, "eb4ac87", "8b9bc8a")], "cache", True,
                pinned=[(fork, "3933e75"), (up, "8b9bc8a")],
            )
        self.assertIsNone(result)


class RealignObeysTheRoleWord(unittest.TestCase):
    """retrodream cites `(upstream retro_host.c:196-198)` beside the fork's
    retro_host.c. With both pins moved and both trees carrying the file,
    realign read the upstream citation in the fork, declared first."""

    def _realign(self, role):
        from unittest import mock

        fork = upstream.make_repo("github.com", "f", "retrodream")
        up = upstream.make_repo("github.com", "o", "dreamcast")
        body = [f"line {n}" for n in range(1, 41)]
        trees = {
            (fork, "f-old"): body, (fork, "f-new"): ["pad"] * 5 + body,
            (up, "u-old"): body, (up, "u-new"): body,
        }

        def fetch(repo, sha, path, *a, **k):
            return trees.get((repo, sha)) if path == "retro_host.c" else None

        part = sourceref.RefPart("retro_host.c", 20, 22, "20-22", role)
        with mock.patch.object(upstream, "fetch_file", side_effect=fetch):
            return realign._realign_part(
                part, [(fork, "f-old", "f-new"), (up, "u-old", "u-new")], "cache", True,
                pinned=[(fork, "f-new"), (up, "u-new")],
                declared={fork: ("source", ""), up: ("upstream", "")},
            )

    def test_an_upstream_part_is_read_in_upstream(self):
        self.assertIsNone(self._realign("upstream"))

    def test_a_part_naming_no_repository_stays_with_the_first_declared(self):
        self.assertEqual(self._realign(""), ("ok", (25, 27)))

    def test_attribution_and_realign_share_the_order(self):
        """The resolver and realign order repositories by one function."""
        source = script_source("profile_sync.py")
        self.assertEqual(source.count("def owner_order("), 1)
        self.assertIn("owner_order(self.views", source)
        self.assertIn("owner_order(pairs, part.role", source)


class UpstreamForkedByThePort(unittest.TestCase):
    """snes9x, kronos and np2kai pinned upstream_commit on the merge base of
    upstream with the fork. Compared to upstream's own HEAD, a bump moved it
    past anything the port carries."""

    def _views(self, base, ancestry=None):
        from unittest import mock

        fork = upstream.make_repo("github.com", "f", "port")
        self.up = upstream.make_repo("github.com", "o", "up")
        self.fork = fork
        views = [
            profiling_repos.RepoView(fork, "src-pin", "src-head", "source_commit", "source"),
            profiling_repos.RepoView(self.up, "old-base", "up-tip", "upstream_commit", "upstream"),
        ]
        with mock.patch.object(
            upstreamtree, "fork_base", return_value=base
        ) as asked, mock.patch.object(
            upstreamtree, "ancestry", return_value=ancestry
        ):
            followed = profiling_repos._follow_fork_base(views, "cache", True)
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


class TestTreeUrlIntoADirectory(unittest.TestCase):
    """`.../libretro-samples/tree/master/tests/cruzes` took the whole tail as
    the branch. Nothing resolved and cruzes was skipped as having no pin."""

    def test_candidates_are_prefixes_shortest_first(self):
        self.assertEqual(
            profiling_repos.branch_candidates(
                "https://github.com/libretro/libretro-samples/tree/master/tests/cruzes"
            ),
            ["master", "master/tests", "master/tests/cruzes"],
        )
        self.assertEqual(profiling_repos.branch_candidates("https://github.com/o/r"), [])

    def test_the_first_resolving_prefix_is_the_branch(self):
        from unittest import mock

        asked = []

        def head(repo, cache, offline=False, branch=None):
            asked.append(branch)
            return "tipsha" if branch == "master" else None

        profile = {"source": "https://github.com/libretro/libretro-samples/tree/master/tests/cruzes",
                   "source_commit": "pinsha"}
        with mock.patch.object(upstream, "resolve_head", side_effect=head):
            views = profiling_repos.select_views(profile, ".cache", True)
        self.assertEqual([(v.pin, v.head) for v in views], [("pinsha", "tipsha")])
        self.assertEqual(asked[0], "master")


class TestAnUnansweringRepository(unittest.TestCase):
    """pyxel declares source_commit, yet the skip read "no source_commit":
    its repository answers 404. A declared upstream_gone was honoured only
    when the forge raised GoneError, never on a plain non-answer."""

    def _report(self, profile):
        from unittest import mock

        with mock.patch.object(reportinputs, "select_views", return_value=[]):
            return resolver.build_report("p", profile, ".cache", True)

    def test_a_declared_pin_names_the_repository(self):
        report = self._report({"source": "https://github.com/o/r", "source_commit": "abc",
                               "files": [{"name": "a", "source_ref": "a.c:1"}]})
        self.assertIn("no declared repository answers", report.skipped)

    def test_a_declared_gone_upstream_is_honoured(self):
        report = self._report({"source": "https://github.com/o/r", "source_commit": "abc",
                               "upstream_gone": "404 since 2026-10-18",
                               "files": [{"name": "a", "source_ref": "a.c:1"}]})
        self.assertEqual(report.skipped, "upstream gone (declared): 404 since 2026-10-18")


class AnOffForgeProfileWatchesItsReleasePage(unittest.TestCase):
    """Profiles of projects outside any forge were skipped as an unsupported
    host, and a new release of Altirra or mednafen went unseen."""

    def test_the_page_version_is_read(self):
        from unittest import mock

        profile = {"emulator": "Altirra", "core_version": "4.40", "version_source": {
            "url": "https://example.test/altirra", "pattern": r"Altirra (\d+\.\d+) released",
        }}
        with mock.patch.object(upstream, "fetch_page",
                               return_value="<p>Altirra 4.50 released</p>"):
            self.assertEqual(versions.page_version(profile, "cache", False), ("4.50", None))

    def test_an_unread_page_says_why(self):
        """A fetch error, an uncached page, a 404 and a pattern miss all
        came back None, the error only printed: the JSON could not tell a
        moved release page from a profile without one."""
        from unittest import mock

        profile = {"emulator": "Altirra", "version_source": {
            "url": "https://example.test/altirra", "pattern": r"Altirra (\d+\.\d+) released",
        }}
        answers = [
            (forgehttp.NotCachedError("cold"), "not cached offline"),
            (None, "page absent"),
            ("<p>nothing here</p>", "pattern not found"),
            (forgehttp.UpstreamError("HTTP 500"), "https://example.test/altirra: HTTP 500"),
        ]
        for answer, reason in answers:
            effect = {"side_effect": answer} if isinstance(answer, Exception) else {"return_value": answer}
            with self.subTest(reason=reason), \
                    mock.patch.object(upstream, "fetch_page", **effect), \
                    mock.patch("sys.stderr") as stderr:
                self.assertEqual(versions.page_version(profile, "cache", True), (None, reason))
                stderr.write.assert_not_called()

    def test_an_uncached_page_offline_is_not_an_absent_one(self):
        with tempfile.TemporaryDirectory() as cache, self.assertRaises(forgehttp.NotCachedError):
            upstream.fetch_page("https://example.invalid/never-cached", cache, True)

    def test_the_reason_reaches_the_json_and_the_text(self):
        report = ProfileReport(name="altirra", entries=[], counts={}, skipped="unsupported host: x",
                               declared_version="4.40", page_version_unread="page absent",
                               version_unread="tag ancestry unread: refused")
        payload = report_to_dict(report)
        self.assertEqual(payload["page_version_unread"], "page absent")
        self.assertEqual(payload["version_unread"], "tag ancestry unread: refused")
        text = format_report(report)
        self.assertIn("announced unreadable (page absent)", text)
        self.assertIn("tag ancestry unread: refused", text)


class ARecaleKeepsTheRepositoryWord(unittest.TestCase):
    """`stella src/a.c:120` says the lines are in the stella repository. The
    path is read without the word, and a recale wrote it back without it."""

    def test_the_word_stays_in_front_of_the_new_span(self):
        from model.sourceref import split_source_ref

        for raw, expected in (
            ("stella src/a.c:120-130", "stella src/a.c:140-150"),
            ("stella src/a.c:120 (the table)", "stella src/a.c:140-150 (the table)"),
            ("src/a.c:120", "src/a.c:140-150"),
        ):
            with self.subTest(raw=raw):
                p = split_source_ref(raw)[0]
                part = sourceref.RefPart(
                    profiling_citations.strip_repo_word(p.path, {"stella"}), p.start, p.end, p.raw)
                result = anchoring.PartResult(part, "SHIFTED", None, 140, 150, [], "")
                self.assertEqual(profiling_reports.rendered_part(result), expected)


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
            profiling_worktree.branch_profiles("emulators", "main", added_only=False),
            ["draft", "edited", "new"],
        )

    def test_added_leaves_edited_profiles_out(self):
        self.assertEqual(
            profiling_worktree.branch_profiles("emulators", "main", added_only=True),
            ["draft", "new"],
        )

    def test_an_unfetched_base_says_to_fetch(self):
        """`--base upstream/main` with upstream added and never fetched
        stopped on git's "Not a valid object name" and no next step."""
        with self.assertRaises(SystemExit) as raised:
            profiling_worktree.branch_profiles("emulators", "upstream/main", added_only=True)
        self.assertIn("git fetch upstream", str(raised.exception))

    def test_the_flag_selects_those_profiles(self):
        args = profile_sync.build_parser().parse_args(["--changed", "--base", "main"])
        profiles = {"kept": {}, "edited": {}, "new": {}, "draft": {}}
        self.assertEqual(
            list(select_profiles(profiles, args)),
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
            list(select_profiles(profiles, args)),
            ["draft", "edited", "new"],
        )


class TestBranchCheckIsWired(unittest.TestCase):
    """CONTRIBUTING and CI name the branch's profiles through the flag."""

    def test_contributing_and_ci_use_the_flags(self):
        root = Path(__file__).resolve().parents[1]
        from sitegen import readme

        text = readme.generate_contributing()
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
