"""Tests for the upstream repository access module (no network)."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import http.client
import os
import sys
import tempfile
import socket
import unittest
from unittest import mock
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import upstream
from upstream import make_repo, parse_repo, raw_url


def _no_network(url: str):
    """Any call reaching here is a leak: the suite must stay offline."""
    raise AssertionError(f"test reached the network: {url}")


class _Body:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self) -> bytes:
        return self._payload


def _http_error(code: int, headers=None) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://host/x", code, "msg", headers, None)


class TestParseRepo(unittest.TestCase):
    def test_github(self):
        repo = parse_repo("https://github.com/libretro/beetle-psx-libretro")
        self.assertEqual(repo.family, "github")
        self.assertEqual(repo.owner, "libretro")
        self.assertEqual(repo.name, "beetle-psx-libretro")

    def test_github_trailing_git_and_slash(self):
        self.assertEqual(
            parse_repo("https://github.com/mamedev/mame.git/"),
            parse_repo("https://github.com/mamedev/mame"),
        )

    def test_gitlab(self):
        repo = parse_repo("https://gitlab.com/recalbox/recalbox")
        self.assertEqual(repo.family, "gitlab")

    def test_gitlab_subgroup_keeps_the_whole_namespace(self):
        repo = parse_repo(
            "https://gitlab.com/recalbox/packages/standalone/rb5000/-/tree/main"
        )
        self.assertEqual(repo.owner, "recalbox/packages/standalone")
        self.assertEqual(repo.name, "rb5000")
        self.assertEqual(
            raw_url(repo, "abc123", "source/Engine.cpp"),
            "https://gitlab.com/recalbox/packages/standalone/rb5000"
            "/-/raw/abc123/source/Engine.cpp",
        )

    def test_voidpoint_is_a_gitlab(self):
        """eduke32 and fury were skipped as an unsupported host."""
        repo = parse_repo("https://voidpoint.io/terminx/eduke32")
        self.assertEqual(repo.family, "gitlab")
        self.assertEqual(repo.api_base, "https://voidpoint.io/api/v4")
        self.assertEqual(
            raw_url(repo, "abc123", "source/build/src/build.cpp"),
            "https://voidpoint.io/terminx/eduke32/-/raw/abc123/source/build/src/build.cpp",
        )

    def test_libretro_gitlab_is_a_gitlab(self):
        repo = parse_repo("https://git.libretro.com/libretro/wqxemu.git")
        self.assertEqual(repo.family, "gitlab")
        self.assertEqual(repo.api_base, "https://git.libretro.com/api/v4")
        self.assertEqual(repo.slug, "libretro/wqxemu")

    def test_codeberg_is_forgejo(self):
        self.assertEqual(parse_repo("https://codeberg.org/a/b").family, "forgejo")

    def test_known_forgejo_instances(self):
        for url in (
            "https://git.citron-emu.org/citron/emu",
            "https://git.eden-emu.dev/eden-emu/eden",
            "https://git.ryujinx.app/projects/Kenji-NX",
        ):
            self.assertEqual(parse_repo(url).family, "forgejo")

    def test_unsupported_host(self):
        self.assertIsNone(parse_repo("https://sourceforge.net/projects/vice"))

    def test_non_repository_url(self):
        self.assertIsNone(parse_repo("https://mednafen.github.io/"))

    def test_empty(self):
        self.assertIsNone(parse_repo(""))


class TestRawUrl(unittest.TestCase):
    def test_github_raw(self):
        repo = parse_repo("https://github.com/libretro/x")
        self.assertEqual(
            raw_url(repo, "abc123", "src/main.cpp"),
            "https://raw.githubusercontent.com/libretro/x/abc123/src/main.cpp",
        )

    def test_gitlab_raw(self):
        repo = parse_repo("https://gitlab.com/g/p")
        self.assertEqual(
            raw_url(repo, "abc123", "a.c"),
            "https://gitlab.com/g/p/-/raw/abc123/a.c",
        )

    def test_forgejo_raw(self):
        repo = parse_repo("https://codeberg.org/g/p")
        self.assertEqual(
            raw_url(repo, "abc123", "a.c"),
            "https://codeberg.org/g/p/raw/commit/abc123/a.c",
        )

    def test_forgejo_fetches_through_the_api(self):
        # git.ngram.ca serves an HTML proof-of-work page on /raw/commit,
        # which fetch_file would have cached as the file's lines.
        import upstream

        repo = parse_repo("https://git.ngram.ca/mirrors/Ryujinx")
        self.assertEqual(
            upstream.content_url(repo, "abc123", "src/a b.cs"),
            "https://git.ngram.ca/api/v1/repos/mirrors/Ryujinx/raw/src/a%20b.cs?ref=abc123",
        )
        github = parse_repo("https://github.com/o/n")
        self.assertEqual(
            upstream.content_url(github, "s", "a.c"), raw_url(github, "s", "a.c")
        )

    def test_path_is_quoted(self):
        repo = parse_repo("https://github.com/o/n")
        self.assertIn("src/a%20b.cpp", raw_url(repo, "s", "src/a b.cpp"))


class TestMakeRepo(unittest.TestCase):
    def test_rebuilds_a_known_host(self):
        self.assertEqual(
            make_repo("github.com", "o", "n"), parse_repo("https://github.com/o/n")
        )

    def test_unknown_host_returns_none(self):
        self.assertIsNone(make_repo("example.invalid", "o", "n"))


class TestTokenScope(unittest.TestCase):
    """GITHUB_TOKEN must never reach a forge other than GitHub."""

    def setUp(self):
        self._orig = os.environ.get("GITHUB_TOKEN")
        os.environ["GITHUB_TOKEN"] = "gho_secret"

    def tearDown(self):
        if self._orig is None:
            os.environ.pop("GITHUB_TOKEN", None)
        else:
            os.environ["GITHUB_TOKEN"] = self._orig

    def test_sent_to_github_api(self):
        h = upstream._headers("https://api.github.com/repos/o/n/commits")
        self.assertEqual(h["Authorization"], "token gho_secret")

    def test_sent_to_github_raw(self):
        h = upstream._headers("https://raw.githubusercontent.com/o/n/sha/a.c")
        self.assertIn("Authorization", h)

    def test_withheld_from_codeberg(self):
        h = upstream._headers("https://codeberg.org/api/v1/repos/o/n/commits")
        self.assertNotIn("Authorization", h)

    def test_withheld_from_gitlab(self):
        h = upstream._headers("https://gitlab.com/api/v4/projects/x/repository/commits")
        self.assertNotIn("Authorization", h)

    def test_withheld_from_forgejo_instances(self):
        for host in ("git.citron-emu.org", "git.eden-emu.dev", "git.ryujinx.app"):
            h = upstream._headers(f"https://{host}/api/v1/repos/o/n/commits")
            self.assertNotIn("Authorization", h, host)

    def test_withheld_from_a_lookalike_host(self):
        h = upstream._headers("https://github.com.evil.example/repos/o/n")
        self.assertNotIn("Authorization", h)

    def test_absent_token_adds_no_header(self):
        os.environ.pop("GITHUB_TOKEN", None)
        h = upstream._headers("https://api.github.com/repos/o/n")
        self.assertNotIn("Authorization", h)


class TestHttpFailure(unittest.TestCase):
    """Only an actual quota signal may abort a whole run."""

    def test_429_is_a_rate_limit(self):
        self.assertIsInstance(
            upstream._http_failure("u", _http_error(429)), upstream.RateLimitError
        )

    def test_429_names_the_wait_the_forge_asks_for(self):
        failure = upstream._http_failure("u", _http_error(429, {"Retry-After": "1833"}))
        self.assertIn("retry after 1833 s", str(failure))

    def test_403_with_exhausted_quota_is_a_rate_limit(self):
        exc = _http_error(403, {"X-RateLimit-Remaining": "0"})
        self.assertIsInstance(
            upstream._http_failure("u", exc), upstream.RateLimitError
        )

    def test_403_with_quota_left_is_not(self):
        exc = _http_error(403, {"X-RateLimit-Remaining": "4970"})
        failure = upstream._http_failure("u", exc)
        self.assertIsInstance(failure, upstream.UpstreamError)
        self.assertNotIsInstance(failure, upstream.RateLimitError)

    def test_bare_403_from_a_forge_is_not_a_rate_limit(self):
        failure = upstream._http_failure("u", _http_error(403))
        self.assertIsInstance(failure, upstream.UpstreamError)
        self.assertNotIsInstance(failure, upstream.RateLimitError)

    def test_525_is_a_plain_upstream_error(self):
        failure = upstream._http_failure("u", _http_error(525))
        self.assertIsInstance(failure, upstream.UpstreamError)
        self.assertNotIsInstance(failure, upstream.RateLimitError)


class TestFetchRetry(unittest.TestCase):
    """Transient network failures are retried, definitive answers are not."""

    def setUp(self):
        self._orig = (urllib.request.urlopen, upstream._sleep)
        self.slept: list[float] = []
        upstream._sleep = self.slept.append
        upstream._exhausted_hosts.clear()

    def tearDown(self):
        urllib.request.urlopen, upstream._sleep = self._orig
        upstream._exhausted_hosts.clear()

    def _serve(self, outcomes):
        self.calls = 0

        def opener(req, timeout=None):
            outcome = outcomes[min(self.calls, len(outcomes) - 1)]
            self.calls += 1
            if isinstance(outcome, Exception):
                raise outcome
            return contextlib.nullcontext(_Body(outcome))

        urllib.request.urlopen = opener

    def test_dropped_connection_is_retried_then_succeeds(self):
        dropped = http.client.RemoteDisconnected("closed")
        self._serve([dropped, b"payload"])
        self.assertEqual(upstream._fetch("https://host/x"), b"payload")
        self.assertEqual(self.calls, 2)
        self.assertEqual(len(self.slept), 1)

    def test_retries_are_bounded(self):
        self._serve([http.client.RemoteDisconnected("closed")])
        with self.assertRaises(upstream.UpstreamError):
            upstream._fetch("https://host/x")
        self.assertEqual(self.calls, upstream.RETRIES)

    def test_server_error_is_retried(self):
        self._serve([_http_error(503)])
        with self.assertRaises(upstream.UpstreamError):
            upstream._fetch("https://host/x")
        self.assertEqual(self.calls, upstream.RETRIES)

    def test_forbidden_is_not_retried(self):
        self._serve([_http_error(403)])
        with self.assertRaises(upstream.UpstreamError):
            upstream._fetch("https://host/x")
        self.assertEqual(self.calls, 1)

    def test_missing_file_is_not_retried(self):
        self._serve([_http_error(404)])
        self.assertIsNone(upstream._fetch("https://host/x"))
        self.assertEqual(self.calls, 1)

    @staticmethod
    def _limited(retry_after: str | None = None) -> urllib.error.HTTPError:
        import email.message  # noqa: PLC0415

        headers = email.message.Message()
        if retry_after is not None:
            headers["Retry-After"] = retry_after
        return _http_error(429, headers)

    def test_rate_limit_is_waited_out(self):
        # git.libretro.com answered 429 on cemu's tree a few hundred
        # requests into a pass, and the whole pass stopped.
        self._serve([self._limited("7"), self._limited(), b"payload"])
        self.assertEqual(upstream._fetch("https://host/x"), b"payload")
        self.assertEqual(self.slept, [7.0, upstream.RATE_LIMIT_WAITS[1]])

    def test_lasting_rate_limit_mutes_the_host_only(self):
        self._serve([self._limited()])
        with self.assertRaises(upstream.RateLimitError) as caught:
            upstream._fetch("https://host/x")
        self.assertEqual(caught.exception.host, "host")
        self.assertEqual(self.calls, len(upstream.RATE_LIMIT_WAITS) + 1)
        # The same host is not asked again, another one still is.
        with self.assertRaises(upstream.RateLimitError):
            upstream._fetch("https://host/y")
        self.assertEqual(self.calls, len(upstream.RATE_LIMIT_WAITS) + 1)
        self._serve([b"other"])
        self.assertEqual(upstream._fetch("https://other/x"), b"other")

    def test_long_retry_after_is_not_waited(self):
        self._serve([self._limited(str(int(upstream.RATE_LIMIT_WAIT_CAP) + 1))])
        with self.assertRaises(upstream.RateLimitError):
            upstream._fetch("https://host/x")
        self.assertEqual((self.calls, self.slept), (1, []))

    def test_exhausted_github_quota_is_not_waited(self):
        import email.message  # noqa: PLC0415

        headers = email.message.Message()
        headers["X-RateLimit-Remaining"] = "0"
        self._serve([_http_error(403, headers)])
        with self.assertRaises(upstream.RateLimitError):
            upstream._fetch("https://host/x")
        self.assertEqual((self.calls, self.slept), (1, []))


class TestGoneUpstream(unittest.TestCase):
    """A forge that will not come back is a fact, not a failure to retry.

    yuzu and suyu answer 451, citron's host no longer resolves. Retrying
    those three times with backoff costs a minute per pass and still ends
    in the same place, and calling them errors buries the profiles that
    have something to say.
    """

    def setUp(self):
        self._orig = (urllib.request.urlopen, upstream._sleep)
        self.slept: list[float] = []
        upstream._sleep = self.slept.append
        self.calls = 0

    def tearDown(self):
        urllib.request.urlopen, upstream._sleep = self._orig

    def _serve(self, outcome):
        def opener(req, timeout=None):
            self.calls += 1
            raise outcome

        urllib.request.urlopen = opener

    def test_legal_takedown_is_gone_and_not_retried(self):
        self._serve(_http_error(451))
        with self.assertRaises(upstream.GoneError):
            upstream._fetch("https://host/x")
        self.assertEqual(self.calls, 1)
        self.assertEqual(self.slept, [])

    def test_http_gone_is_gone(self):
        self._serve(_http_error(410))
        with self.assertRaises(upstream.GoneError):
            upstream._fetch("https://host/x")
        self.assertEqual(self.calls, 1)

    def test_unresolvable_host_is_gone_and_not_retried(self):
        self._serve(urllib.error.URLError(
            socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        ))
        with mock.patch.object(upstream, "_resolver_answers", return_value=True):
            with self.assertRaises(upstream.GoneError):
                upstream._fetch("https://host/x")
        self.assertEqual(self.calls, 1)
        self.assertEqual(self.slept, [])

    def test_a_local_resolver_outage_is_not_gone(self):
        """With DNS down here, every forge looked gone and profile_sync
        listed nothing to review, exiting 0."""
        for errno, resolver in ((socket.EAI_NONAME, False), (socket.EAI_AGAIN, True)):
            with self.subTest(errno=errno, resolver=resolver):
                self._serve(urllib.error.URLError(socket.gaierror(errno, "no")))
                with mock.patch.object(upstream, "_resolver_answers", return_value=resolver):
                    with self.assertRaises(upstream.UpstreamError) as caught:
                        upstream._fetch("https://host/x")
                self.assertNotIsInstance(caught.exception, upstream.GoneError)

    def test_a_gone_error_is_still_an_upstream_error(self):
        self._serve(_http_error(451))
        with self.assertRaises(upstream.UpstreamError):
            upstream._fetch("https://host/x")

    def test_refused_request_is_not_gone(self):
        """403 is a forge refusing a request, which anti-bot filters do."""
        self._serve(_http_error(403))
        with self.assertRaises(upstream.UpstreamError) as caught:
            upstream._fetch("https://host/x")
        self.assertNotIsInstance(caught.exception, upstream.GoneError)

    def test_a_dropped_connection_is_not_gone(self):
        self._serve(http.client.RemoteDisconnected("closed"))
        with self.assertRaises(upstream.UpstreamError) as caught:
            upstream._fetch("https://host/x")
        self.assertNotIsInstance(caught.exception, upstream.GoneError)
        self.assertEqual(self.calls, upstream.RETRIES)


class TestCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.repo = parse_repo("https://github.com/o/n")
        self.calls: list[str] = []
        self._orig = (upstream._http_text, upstream._http_json)
        upstream._http_text = self._fake
        upstream._http_json = _no_network

    def tearDown(self):
        upstream._http_text, upstream._http_json = self._orig
        self.tmp.cleanup()

    def _fake(self, url: str) -> str | None:
        self.calls.append(url)
        return "line one\nline two\n"

    def test_path_includes_host_slug_and_sha(self):
        p = upstream.cache_path(self.dir, self.repo, "abc123", "src/a.cpp")
        self.assertIn("github.com", str(p))
        self.assertIn("o", str(p))
        self.assertIn("abc123", str(p))

    def test_path_is_contained_in_cache_dir(self):
        p = upstream.cache_path(self.dir, self.repo, "abc", "../../escape.c")
        self.assertTrue(str(p.resolve()).startswith(str(Path(self.dir).resolve())))

    def test_fetch_then_cache_hit(self):
        first = upstream.fetch_file(self.repo, "abc", "a.c", self.dir)
        second = upstream.fetch_file(self.repo, "abc", "a.c", self.dir)
        self.assertEqual(first, ["line one", "line two"])
        self.assertEqual(second, first)
        self.assertEqual(len(self.calls), 1)

    def test_offline_miss_is_not_absence(self):
        # Returning None made profile_sync report an existing file as GONE.
        with self.assertRaises(upstream.NotCachedError):
            upstream.fetch_file(self.repo, "abc", "a.c", self.dir, offline=True)
        self.assertEqual(self.calls, [])

    def test_offline_cached_absence_stays_absence(self):
        upstream.write_cache(
            upstream.cache_path(self.dir, self.repo, "abc", "gone.c"), upstream.ABSENT
        )
        self.assertIsNone(
            upstream.fetch_file(self.repo, "abc", "gone.c", self.dir, offline=True)
        )
        self.assertEqual(self.calls, [])

    def test_offline_hit_serves_cache(self):
        upstream.fetch_file(self.repo, "abc", "a.c", self.dir)
        self.calls.clear()
        self.assertEqual(
            upstream.fetch_file(self.repo, "abc", "a.c", self.dir, offline=True),
            ["line one", "line two"],
        )
        self.assertEqual(self.calls, [])

    def test_missing_file_is_cached_as_absent(self):
        upstream._http_text = lambda url: None
        self.assertIsNone(upstream.fetch_file(self.repo, "abc", "gone.c", self.dir))
        self.assertIsNone(
            upstream.fetch_file(self.repo, "abc", "gone.c", self.dir, offline=True)
        )

    def test_write_leaves_no_temporary_behind(self):
        target = Path(self.dir) / "sub" / "f.txt"
        upstream.write_cache(target, "payload")
        self.assertEqual(target.read_text(encoding="utf-8"), "payload")
        siblings = list(target.parent.iterdir())
        self.assertEqual([p.name for p in siblings], ["f.txt"])


class TestCacheCollision(unittest.TestCase):
    def test_a_file_where_a_directory_is_needed_skips_the_write(self):
        # A profile citing both a directory and files inside it caches the
        # directory as a file first, and that must not break the files.
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            (base / "C64DTV").write_text("", encoding="utf-8")
            upstream.write_cache(base / "C64DTV" / "basic.bin", "data")
            self.assertTrue((base / "C64DTV").is_file())


class TestRevisions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.repo = parse_repo("https://github.com/o/n")
        self.responses: dict[str, object] = {}
        self.calls: list[str] = []
        self._orig = (upstream._http_json, upstream._http_text)
        upstream._http_json = self._fake
        upstream._http_text = _no_network

    def tearDown(self):
        upstream._http_json, upstream._http_text = self._orig
        self.tmp.cleanup()

    def _fake(self, url: str):
        self.calls.append(url)
        for fragment, payload in self.responses.items():
            if fragment in url:
                return payload
        return None

    def test_resolve_head_github(self):
        self.responses["/commits"] = [{"sha": "deadbeef"}]
        self.assertEqual(upstream.resolve_head(self.repo, self.dir), "deadbeef")

    def test_resolve_head_gitlab_uses_id(self):
        repo = parse_repo("https://gitlab.com/g/p")
        self.responses["/repository/commits"] = [{"id": "cafe"}]
        self.assertEqual(upstream.resolve_head(repo, self.dir), "cafe")

    def test_resolve_commit_at_passes_date(self):
        self.responses["/commits"] = [{"sha": "abc"}]
        self.assertEqual(
            upstream.resolve_commit_at(self.repo, "2026-03-29", self.dir), "abc"
        )
        self.assertIn("2026-03-29", self.calls[0])

    def test_an_uncached_tip_offline_is_unknown_not_absent(self):
        """xenios-jp/XeniOS was dropped offline, its preview tip never
        cached, and its citations were judged against the other repository."""
        with self.assertRaises(upstream.NotCachedError):
            upstream.resolve_head(self.repo, self.dir, offline=True, branch="preview")
        with self.assertRaises(upstream.NotCachedError):
            upstream.resolve_commit_at(self.repo, "2026-03-29", self.dir, offline=True)
        self.assertEqual(self.calls, [])

    def test_a_cached_absence_offline_is_still_absent(self):
        self.assertIsNone(upstream.resolve_head(self.repo, self.dir, branch="gone"))
        self.assertIsNone(
            upstream.resolve_head(self.repo, self.dir, offline=True, branch="gone")
        )

    def test_api_response_is_cached(self):
        self.responses["/commits"] = [{"sha": "abc"}]
        upstream.resolve_commit_at(self.repo, "2026-03-29", self.dir)
        upstream.resolve_commit_at(self.repo, "2026-03-29", self.dir)
        self.assertEqual(len(self.calls), 1)

    def test_a_branch_tip_is_refreshed_once_stale(self):
        import os as _os
        import hashlib as _hashlib
        self.responses["/commits"] = [{"sha": "old"}]
        self.assertEqual(upstream.resolve_head(self.repo, self.dir), "old")
        url = upstream._commits_url(self.repo, None, None)
        cached = (
            Path(self.dir) / "_api"
            / f"{_hashlib.sha256(url.encode()).hexdigest()}.json"
        )
        stale = _os.path.getmtime(cached) - upstream.MOVING_TTL - 1
        _os.utime(cached, (stale, stale))
        self.responses["/commits"] = [{"sha": "new"}]
        self.assertEqual(upstream.resolve_head(self.repo, self.dir), "new")
        self.assertEqual(len(self.calls), 2)

    def test_a_stale_tip_still_serves_offline(self):
        import os as _os
        import hashlib as _hashlib
        self.responses["/commits"] = [{"sha": "old"}]
        upstream.resolve_head(self.repo, self.dir)
        url = upstream._commits_url(self.repo, None, None)
        cached = (
            Path(self.dir) / "_api"
            / f"{_hashlib.sha256(url.encode()).hexdigest()}.json"
        )
        stale = _os.path.getmtime(cached) - upstream.MOVING_TTL - 1
        _os.utime(cached, (stale, stale))
        self.assertEqual(upstream.resolve_head(self.repo, self.dir, offline=True), "old")
        self.assertEqual(len(self.calls), 1)

    def test_a_dated_lookup_is_cached_for_good(self):
        import os as _os
        import hashlib as _hashlib
        self.responses["/commits"] = [{"sha": "abc"}]
        upstream.resolve_commit_at(self.repo, "2026-03-29", self.dir)
        url = upstream._commits_url(self.repo, "2026-03-29", None)
        cached = (
            Path(self.dir) / "_api"
            / f"{_hashlib.sha256(url.encode()).hexdigest()}.json"
        )
        _os.utime(cached, (0, 0))
        upstream.resolve_commit_at(self.repo, "2026-03-29", self.dir)
        self.assertEqual(len(self.calls), 1)

    def test_empty_history_returns_none(self):
        self.responses["/commits"] = []
        self.assertIsNone(upstream.resolve_head(self.repo, self.dir))

    def test_list_tags(self):
        self.responses["/tags"] = [{"name": "v1.2"}, {"name": "v1.1"}]
        self.assertEqual(upstream.list_tags(self.repo, self.dir), ["v1.2", "v1.1"])

    def test_resolve_tag_commit(self):
        self.responses["/tags"] = [{"name": "v1.2", "commit": {"sha": "tagsha"}}]
        self.assertEqual(
            upstream.resolve_tag_commit(self.repo, "v1.2", self.dir), "tagsha"
        )

    def test_latest_release(self):
        self.responses["/releases/latest"] = {
            "tag_name": "v3.0.0",
            "published_at": "2026-06-14T10:00:00Z",
            "prerelease": False,
        }
        rel = upstream.latest_release(self.repo, self.dir)
        self.assertEqual(rel.tag, "v3.0.0")
        self.assertEqual(rel.date, "2026-06-14")
        self.assertFalse(rel.is_prerelease)

    def test_missing_release_returns_none(self):
        self.assertIsNone(upstream.latest_release(self.repo, self.dir))

    def test_rate_limit_propagates(self):
        def boom(url: str):
            raise upstream.RateLimitError("quota")

        upstream._http_json = boom
        with self.assertRaises(upstream.RateLimitError):
            upstream.resolve_head(self.repo, self.dir)


class TestCompare(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.repo = parse_repo("https://github.com/o/n")
        self.payload: object = None
        self._orig = (upstream._http_json, upstream._http_text)
        upstream._http_json = lambda url: self.payload
        upstream._http_text = _no_network

    def tearDown(self):
        upstream._http_json, upstream._http_text = self._orig
        self.tmp.cleanup()

    def test_list_directory_reads_one_tree(self):
        seen: list[str] = []

        def answer(url):
            seen.append(url)
            return {
                "truncated": False,
                "tree": [
                    {"path": "b.xml", "type": "blob"},
                    {"path": "a.xml", "type": "blob"},
                    {"path": "sub", "type": "tree"},
                ],
            }

        upstream._http_json = answer
        self.assertEqual(
            upstream.list_directory(self.repo, "abc", "hash/", self.dir), ["a.xml", "b.xml"]
        )
        self.assertTrue(seen[0].endswith("/repos/o/n/git/trees/abc:hash"))
        # Cached: offline, the same answer without a request.
        self.assertEqual(
            upstream.list_directory(self.repo, "abc", "hash", self.dir, offline=True),
            ["a.xml", "b.xml"],
        )
        self.assertEqual(len(seen), 1)
        upstream._http_json = lambda url: {"truncated": True, "tree": []}
        self.assertIsNone(upstream.list_directory(self.repo, "def", "hash", self.dir))
        gitlab = parse_repo("https://gitlab.com/o/n")
        self.assertIsNone(upstream.list_directory(gitlab, "abc", "hash", self.dir))

    def test_renamed_file_carries_previous_path(self):
        self.payload = {
            "files": [
                {
                    "status": "renamed",
                    "filename": "src/new.cpp",
                    "previous_filename": "old.cpp",
                },
                {"status": "modified", "filename": "a.c"},
            ]
        }
        result = upstream.compare(self.repo, "a", "b", self.dir)
        self.assertFalse(result.truncated)
        self.assertEqual(upstream.find_renamed(result, "old.cpp"), "src/new.cpp")

    def test_no_rename_returns_none(self):
        self.payload = {"files": [{"status": "modified", "filename": "a.c"}]}
        result = upstream.compare(self.repo, "a", "b", self.dir)
        self.assertIsNone(upstream.find_renamed(result, "old.cpp"))

    def test_truncated_at_github_cap(self):
        self.payload = {
            "files": [
                {"status": "modified", "filename": f"f{i}.c"} for i in range(300)
            ]
        }
        self.assertTrue(upstream.compare(self.repo, "a", "b", self.dir).truncated)

    def test_missing_comparison_is_empty_and_truncated(self):
        self.payload = None
        result = upstream.compare(self.repo, "a", "b", self.dir)
        self.assertEqual(result.files, [])
        self.assertTrue(result.truncated)

    def test_gitlab_diffs_shape(self):
        repo = parse_repo("https://gitlab.com/g/p")
        self.payload = {
            "diffs": [
                {
                    "new_path": "new.c",
                    "old_path": "old.c",
                    "renamed_file": True,
                    "new_file": False,
                    "deleted_file": False,
                }
            ]
        }
        result = upstream.compare(repo, "a", "b", self.dir)
        self.assertEqual(upstream.find_renamed(result, "old.c"), "new.c")

    def test_commits_touching_counts_the_commits_after_the_pin(self):
        """Listing from the pin counted its history: freeintv's pin on HEAD
        scored 26 commits of drift."""
        served = {
            "commits/base": {"commit": {"committer": {"date": "2026-01-01T00:00:00Z"}}},
        }
        listing = [{"sha": "1"}, {"sha": "2"}, {"sha": "base"}]
        seen: list[str] = []

        def answer(url):
            seen.append(url)
            for key, value in served.items():
                if url.endswith(key):
                    return value
            return listing

        upstream._http_json = answer
        self.assertEqual(
            upstream.commits_touching(self.repo, "a.c", "base", self.dir, head="tip"), 2
        )
        self.assertTrue(any("since=2026-01-01" in url for url in seen))
        self.assertEqual(
            upstream.commits_touching(self.repo, "a.c", "tip", self.dir, head="tip"), 0
        )

    def test_commits_touching_is_recounted_once_stale(self):
        """The list grows with every push: cached for good, the triage drift
        score stayed at what the first run counted."""
        import os as _os

        served = {
            "commits/base": {"commit": {"committer": {"date": "2026-01-01T00:00:00Z"}}},
        }
        listing = [{"sha": "1"}]

        def answer(url):
            for key, value in served.items():
                if url.endswith(key):
                    return value
            return list(listing)

        upstream._http_json = answer
        self.assertEqual(upstream.commits_touching(self.repo, "a.c", "base", self.dir), 1)
        for cached in (Path(self.dir) / "_api").glob("*.json"):
            stale = _os.path.getmtime(cached) - upstream.MOVING_TTL - 1
            _os.utime(cached, (stale, stale))
        listing.extend([{"sha": "2"}, {"sha": "3"}])
        self.assertEqual(upstream.commits_touching(self.repo, "a.c", "base", self.dir), 3)

    def test_a_missing_tag_is_asked_again_once_stale(self):
        """A profile written on release day asked for v2.0 before it was
        pushed. The 404 was cached for good and the profile was never seen
        as frozen on its tag."""
        import os as _os

        answers: list = [None]

        def answer(url):
            return answers[-1]

        upstream._http_json = answer
        self.assertIsNone(upstream.tag_commit(self.repo, "v2.0", self.dir))
        for cached in (Path(self.dir) / "_api").glob("*.json"):
            stale = _os.path.getmtime(cached) - upstream.MOVING_TTL - 1
            _os.utime(cached, (stale, stale))
        answers.append({"object": {"type": "commit", "sha": "rel"}})
        self.assertEqual(upstream.tag_commit(self.repo, "v2.0", self.dir), "rel")
        # Found, the answer is kept however old it gets.
        for cached in (Path(self.dir) / "_api").glob("*.json"):
            _os.utime(cached, (0, 0))
        answers.append({"object": {"type": "commit", "sha": "moved"}})
        self.assertEqual(upstream.tag_commit(self.repo, "v2.0", self.dir), "rel")


class TestGitlabTree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.repo = upstream.parse_repo("https://gitlab.com/g/p")
        self.pages: dict[int, object] = {}
        self._orig = (upstream._http_json, upstream._http_text)

        def fake(url):
            page = int(url.rsplit("page=", 1)[1])
            payload = self.pages.get(page)
            if payload == "boom":
                raise upstream.UpstreamError(url)
            return payload

        upstream._http_json = fake

    def tearDown(self):
        upstream._http_json, upstream._http_text = self._orig
        self.tmp.cleanup()

    def _blobs(self, *names):
        return [{"type": "blob", "path": name} for name in names]

    def test_single_page_is_complete(self):
        self.pages[1] = self._blobs("src/a.c", "src/b.c") + [
            {"type": "tree", "path": "src"}
        ]
        paths, truncated = upstream.list_tree(self.repo, "sha", self.dir)
        self.assertEqual(paths, ["src/a.c", "src/b.c"])
        self.assertFalse(truncated)

    def test_pages_accumulate_until_a_short_one(self):
        self.pages[1] = self._blobs(
            *[f"f{i}.c" for i in range(upstream.TREE_PAGE_SIZE)]
        )
        self.pages[2] = self._blobs("last.c")
        paths, truncated = upstream.list_tree(self.repo, "sha", self.dir)
        self.assertEqual(len(paths), upstream.TREE_PAGE_SIZE + 1)
        self.assertIn("last.c", paths)
        self.assertFalse(truncated)

    def test_unreadable_page_reports_truncation(self):
        self.pages[1] = self._blobs(
            *[f"f{i}.c" for i in range(upstream.TREE_PAGE_SIZE)]
        )
        self.pages[2] = None
        paths, truncated = upstream.list_tree(self.repo, "sha", self.dir)
        self.assertEqual(len(paths), upstream.TREE_PAGE_SIZE)
        self.assertTrue(truncated)


class TestGiteaCommitAt(unittest.TestCase):
    """Gitea and Forgejo ignore `until` and answer with the tip: the date
    pin of a Codeberg view was the tip of the day of the first fetch."""

    PAGES = {
        1: [{"sha": f"t{i}", "commit": {"committer": {"date": "2026-07-04T10:00:00+02:00"}}}
            for i in range(50)],
        2: [
            {"sha": "late", "commit": {"committer": {"date": "2026-03-24T05:00:00+02:00"}}},
            {"sha": "pin", "commit": {"committer": {"date": "2026-03-17T19:49:15+08:00"}}},
        ],
    }

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.urls: list[str] = []
        original = upstream._http_json

        def fake(url):
            self.urls.append(url)
            self.assertNotIn("until=", url)
            page = int(url.rsplit("page=", 1)[1])
            return self.PAGES.get(page, [])

        upstream._http_json = fake
        self.addCleanup(setattr, upstream, "_http_json", original)

    def test_the_first_commit_by_the_cutoff(self):
        repo = parse_repo("https://codeberg.org/iyzsong/gam4980")
        sha = upstream.resolve_commit_at(repo, "2026-03-23", self.tmp.name)
        self.assertEqual(sha, "pin")
        self.assertEqual(len(self.urls), 2)

    def test_a_date_before_the_history_resolves_nothing(self):
        repo = parse_repo("https://codeberg.org/iyzsong/gam4980")
        self.assertIsNone(
            upstream.resolve_commit_at(repo, "2020-01-01", self.tmp.name)
        )



class TestCurrentSlug(unittest.TestCase):
    """The name a forge answers under, read from the repository payload."""

    def test_github_and_gitlab_payloads(self):
        answers = {
            "https://api.github.com/repos/AloysHF/NicaiEmu": {
                "full_name": "AloysHF/CoolbarEmu"
            },
            "https://gitlab.com/api/v4/projects/g%2Fsub%2Fp": {
                "path_with_namespace": "g/sub/p"
            },
        }
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(upstream, "_http_json", side_effect=answers.get):
            github = parse_repo("https://github.com/AloysHF/NicaiEmu")
            gitlab = parse_repo("https://gitlab.com/g/sub/p")
            self.assertEqual(upstream.current_slug(github, tmp), "AloysHF/CoolbarEmu")
            self.assertEqual(upstream.current_slug(gitlab, tmp), "g/sub/p")
            self.assertIsNone(
                upstream.current_slug(parse_repo("https://github.com/a/b"), tmp)
            )



class TestNewestTag(unittest.TestCase):
    """GitHub's REST tag list is sorted by name: nesoid lists 2.5 before
    2.5-4, so the first entry was reported as the latest tag."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = make_repo("github.com", "o", "n")
        self.saved = (upstream._github_graphql, upstream.list_tags)
        upstream.list_tags = lambda repo, cache, offline=False: ["2.5", "2.5-4"]

    def tearDown(self):
        upstream._github_graphql, upstream.list_tags = self.saved
        self.tmp.cleanup()

    def test_commit_date_order_wins(self):
        upstream._github_graphql = lambda *a: {
            "data": {"repository": {"refs": {"nodes": [{"name": "2.5-4"}]}}}
        }
        self.assertEqual(upstream.newest_tag(self.repo, self.tmp.name), "2.5-4")

    def test_without_a_token_the_forge_order_stays(self):
        upstream._github_graphql = lambda *a: None
        self.assertEqual(upstream.newest_tag(self.repo, self.tmp.name), "2.5")


class TestNamedTagCommit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = upstream._http_json

    def tearDown(self):
        upstream._http_json = self.saved
        self.tmp.cleanup()

    def test_gitlab_tag_is_asked_by_name(self):
        asked = []

        def answer(url):
            asked.append(url)
            return {"name": "1.2.35", "commit": {"id": "c74fc36"}}

        upstream._http_json = answer
        repo = parse_repo("https://gitlab.com/jengun/sdltrs")
        self.assertEqual(upstream.tag_commit(repo, "1.2.35", self.tmp.name), "c74fc36")
        self.assertTrue(asked[0].endswith("/repository/tags/1.2.35"))


class TestForkBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = upstream._http_json

    def tearDown(self):
        upstream._http_json = self.saved
        self.tmp.cleanup()

    def test_the_merge_base_github_names(self):
        asked = []

        def answer(url):
            asked.append(url)
            return {"merge_base_commit": {"sha": "base"}, "status": "diverged"}

        upstream._http_json = answer
        up, fork = make_repo("github.com", "o", "up"), make_repo("github.com", "f", "port")
        self.assertEqual(upstream.fork_base(up, "tip", fork, "head", self.tmp.name), "base")
        self.assertTrue(asked[0].endswith("/repos/o/up/compare/tip...f:port:head"))

    def test_no_network_is_none(self):
        upstream._http_json = lambda url: None
        up, fork = make_repo("github.com", "o", "up"), make_repo("github.com", "f", "port")
        self.assertIsNone(upstream.fork_base(up, "tip", fork, "head", self.tmp.name))


def _tarball(files: dict[str, str]) -> bytes:
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class TestGitlabDirectoryArchive(unittest.TestCase):
    """One archive request fills the per-file cache of a GitLab directory."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = parse_repo("https://gitlab.com/g/p")
        top = "p-abc-sys/"
        self.body = _tarball({
            top + "sys/a/system.ini": "[system]\n",
            top + "sys/b/system.ini": "[core.x]\n",
            top + "other/c.txt": "outside",
        })

    def test_files_land_in_the_cache_fetch_file_reads(self):
        calls = []
        with mock.patch.object(upstream, "_fetch", side_effect=lambda url: calls.append(url) or self.body):
            held = upstream.cache_gitlab_directory(self.repo, "abc", "sys", self.tmp.name)
        self.assertEqual(held, {"sys/a/system.ini", "sys/b/system.ini"})
        self.assertEqual(len(calls), 1)
        self.assertIn("archive.tar.gz?sha=abc&path=sys", calls[0])
        with mock.patch.object(upstream, "_http_text", side_effect=_no_network):
            lines = upstream.fetch_file(self.repo, "abc", "sys/b/system.ini", self.tmp.name, offline=True)
        self.assertEqual(lines, ["[core.x]"])

    def test_a_second_run_reads_the_index_offline(self):
        with mock.patch.object(upstream, "_fetch", return_value=self.body):
            upstream.cache_gitlab_directory(self.repo, "abc", "sys", self.tmp.name)
        with mock.patch.object(upstream, "_fetch", side_effect=_no_network):
            held = upstream.cache_gitlab_directory(self.repo, "abc", "sys", self.tmp.name, offline=True)
        self.assertEqual(held, {"sys/a/system.ini", "sys/b/system.ini"})

    def test_offline_without_index_knows_nothing(self):
        with mock.patch.object(upstream, "_fetch", side_effect=_no_network):
            self.assertIsNone(upstream.cache_gitlab_directory(self.repo, "abc", "sys", self.tmp.name, offline=True))

    def test_other_forges_are_left_to_per_file_reads(self):
        github = parse_repo("https://github.com/o/r")
        with mock.patch.object(upstream, "_fetch", side_effect=_no_network):
            self.assertIsNone(upstream.cache_gitlab_directory(github, "abc", "sys", self.tmp.name))

    def test_a_refused_api_falls_back_to_git(self):
        refused = upstream.RateLimitError("429", "gitlab.com")
        with mock.patch.object(upstream, "_fetch", side_effect=refused), \
                mock.patch.object(upstream, "_sparse_git_files", return_value={"sys/a/system.ini": "x"}) as git:
            held = upstream.cache_gitlab_directory(self.repo, "abc", "sys", self.tmp.name)
        self.assertEqual(held, {"sys/a/system.ini"})
        git.assert_called_once()

    def test_an_empty_archive_is_an_error_not_an_empty_directory(self):
        with mock.patch.object(upstream, "_fetch", return_value=_tarball({"p/other/x": "y"})):
            with self.assertRaises(upstream.UpstreamError):
                upstream.cache_gitlab_directory(self.repo, "abc", "sys", self.tmp.name)


if __name__ == "__main__":
    unittest.main()
