"""Tests for the upstream repository access module (no network)."""

from __future__ import annotations

import contextlib
import http.client
import os
import sys
import tempfile
import unittest
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

    def test_codeberg_is_forgejo(self):
        self.assertEqual(parse_repo("https://codeberg.org/a/b").family, "forgejo")

    def test_known_forgejo_instances(self):
        for url in (
            "https://git.citron-emu.org/citron/emu",
            "https://git.eden-emu.dev/eden-emu/eden",
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
        for host in ("git.citron-emu.org", "git.eden-emu.dev"):
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

    def tearDown(self):
        urllib.request.urlopen, upstream._sleep = self._orig

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

    def test_rate_limit_is_not_retried(self):
        self._serve([_http_error(429)])
        with self.assertRaises(upstream.RateLimitError):
            upstream._fetch("https://host/x")
        self.assertEqual(self.calls, 1)


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

    def test_offline_miss_returns_none_without_request(self):
        self.assertIsNone(
            upstream.fetch_file(self.repo, "abc", "a.c", self.dir, offline=True)
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
        # directory as a file first; that must not break the files.
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

    def test_api_response_is_cached(self):
        self.responses["/commits"] = [{"sha": "abc"}]
        upstream.resolve_commit_at(self.repo, "2026-03-29", self.dir)
        upstream.resolve_commit_at(self.repo, "2026-03-29", self.dir)
        self.assertEqual(len(self.calls), 1)

    def test_offline_without_cache_returns_none(self):
        self.assertIsNone(upstream.resolve_head(self.repo, self.dir, offline=True))
        self.assertEqual(self.calls, [])

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

    def test_commits_touching_counts_entries(self):
        self.payload = [{"sha": "1"}, {"sha": "2"}, {"sha": "3"}]
        self.assertEqual(
            upstream.commits_touching(self.repo, "a.c", "base", self.dir), 3
        )


if __name__ == "__main__":
    unittest.main()
