"""The scrapers' shared network helpers and the source revision reader (no network)."""

from __future__ import annotations

import tests

import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import yaml

from model.sourcerevision import (
    parse_source,
    platform_revision,
    required_revision,
    scraped_revision,
    source_revision,
)
from scraper import base_scraper
from scraper.base_scraper import (
    FetchError,
    download,
    fetch_bytes,
    fetch_github_latest_version,
    fetch_present,
    forge_headers,
    github_tree,
    submodule_commit,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
TMP_ROOT = REPO_ROOT / "tmp"
SHA = "0123456789abcdef0123456789abcdef01234567"


class _Response(io.BytesIO):
    def __init__(self, body: bytes, headers: dict[str, str] | None = None) -> None:
        super().__init__(body)
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _answer(*replies: object):
    """An urlopen that gives each reply in turn: bytes, a dict body or an
    HTTP status to raise."""
    pending = list(replies)
    seen: list[object] = []

    def urlopen(request, timeout=None):
        seen.append(request)
        reply = pending.pop(0)
        if isinstance(reply, int):
            raise urllib.error.HTTPError(request.full_url, reply, "status", {}, None)
        if isinstance(reply, (dict, list)):
            reply = json.dumps(reply).encode()
        return _Response(reply, {"Content-Disposition": 'attachment; filename="a.zip"'})

    urlopen.seen = seen
    return urlopen


class SourceRevisionReadsEveryShape(unittest.TestCase):
    SHAPES = {
        f"https://raw.githubusercontent.com/o/r/{SHA}/dir/file.json": SHA,
        f"https://raw.githubusercontent.com/o/r/{SHA}": SHA,
        "https://github.com/o/r/blob/v2/src/f.cs": "v2",
        f"https://github.com/o/r/tree/{SHA}": SHA,
        f"https://github.com/o/r/tree/{SHA}/": SHA,
        "https://gitlab.com/g/sub/r/-/raw/10.1.1/a/b.xml": "10.1.1",
        "https://gitlab.com/g/r/-/blob/main/a.txt": "main",
        "https://gitlab.com/g/r/-/tree/v1": "v1",
        "https://gitlab.com/g/r/-/archive/v1/r-v1.tar.gz": "v1",
        f"https://codeload.github.com/o/r/tar.gz/{SHA}": SHA,
        "https://codeload.github.com/o/r/zip/v3": "v3",
    }

    def test_each_url_shape(self):
        for url, revision in self.SHAPES.items():
            with self.subTest(url=url):
                self.assertEqual(source_revision(url), revision)

    def test_a_url_without_a_revision(self):
        for url in ("https://github.com/emulatorjs/emulatorjs", "https://example.org/x",
                    "https://github.com.example/o/r/blob/v2/f"):
            with self.subTest(url=url):
                self.assertEqual(source_revision(url), "")

    def test_every_registered_platform_names_its_revision(self):
        """The target scrapers raised for RetroDECK and NextUI, whose tree
        URLs carry no path after the commit, while the exporter answered."""
        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        checked = 0
        for name in registry["platforms"]:
            path = REPO_ROOT / "platforms" / f"{name}.yml"
            source = (yaml.safe_load(path.read_text()) or {}).get("source") if path.is_file() else None
            if not source:
                continue
            with self.subTest(platform=name):
                self.assertTrue(source_revision(source), source)
                self.assertEqual(platform_revision(path), source_revision(source))
                checked += 1
        self.assertGreater(checked, 15)

    def test_a_repository_and_a_commit_can_be_required(self):
        url = f"https://raw.githubusercontent.com/o/r/{SHA}/f"
        self.assertEqual(required_revision(url, "o/r", commit=True), SHA)
        for bad in (
            lambda: required_revision(url, "o/other"),
            lambda: required_revision("https://raw.githubusercontent.com/o/r/main/f", commit=True),
            lambda: required_revision("https://example.org/f"),
        ):
            with self.assertRaises(ValueError):
                bad()

    def test_a_gitlab_group_is_the_owner(self):
        parsed = parse_source("https://gitlab.com/g/sub/proj/-/raw/v1/a/b.xml")
        self.assertEqual((parsed.host, parsed.slug, parsed.rev, parsed.path),
                         ("gitlab.com", "g/sub/proj", "v1", "a/b.xml"))
        archive = parse_source("https://gitlab.com/o/r/-/archive/10.1/r-10.1.tar.gz")
        self.assertEqual((archive.slug, archive.rev, archive.path), ("o/r", "10.1", ""))

    def test_a_repository_is_compared_without_case(self):
        """Forge owner and repository names ignore case: check_freshness read
        them so, the scrapers' required_revision did not."""
        url = "https://raw.githubusercontent.com/ROCKNIX/distribution/20250101/f"
        self.assertEqual(required_revision(url, "rocknix/distribution"), "20250101")
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            path = Path(tmp, "p.yml")
            path.write_text(f"source: {url}\n")
            self.assertEqual(scraped_revision(path, "rocknix/Distribution"), "20250101")
            self.assertEqual(scraped_revision(path, "rocknix/other"), "")
            self.assertEqual(scraped_revision(Path(tmp, "absent.yml")), "")

    def test_a_platform_without_a_revision_raises(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            path = Path(tmp, "p.yml")
            path.write_text("source: https://github.com/emulatorjs/emulatorjs\n")
            with self.assertRaises(RuntimeError):
                platform_revision(path)


class TheTokenGoesToGitHubOnly(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {"GITHUB_TOKEN": "t0k"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_api_and_raw_hosts(self):
        for url in ("https://api.github.com/repos/o/r", "https://raw.githubusercontent.com/o/r/x/f"):
            self.assertEqual(forge_headers(url)["Authorization"], "Bearer t0k")

    def test_other_hosts(self):
        for url in ("https://github.com/o/r/releases/download/v1/a.zip",
                    "https://gitlab.com/api/v4/projects/1",
                    "https://evil.example/?u=api.github.com",
                    "https://api.github.com.evil.example/x"):
            with self.subTest(url=url):
                self.assertNotIn("Authorization", forge_headers(url))

    def test_every_fetch_carries_it(self):
        opener = _answer(b"x")
        with mock.patch("urllib.request.urlopen", opener):
            fetch_bytes("https://api.github.com/repos/o/r")
        self.assertEqual(opener.seen[0].get_header("Authorization"), "Bearer t0k")


class FetchFailures(unittest.TestCase):
    def test_the_status_is_kept(self):
        with mock.patch("urllib.request.urlopen", _answer(403)), \
                self.assertRaises(FetchError) as caught:
            fetch_bytes("https://x.example/f")
        self.assertEqual(caught.exception.status, 403)
        self.assertIsInstance(caught.exception, ConnectionError)

    def test_only_a_404_is_absent(self):
        with mock.patch("urllib.request.urlopen", _answer(404)):
            self.assertIsNone(fetch_present("https://x.example/f"))
        with mock.patch("urllib.request.urlopen", _answer(503, 503, 503, 503, 503)), \
                mock.patch("time.sleep"), self.assertRaises(FetchError):
            fetch_present("https://x.example/f")

    def test_a_body_over_the_cap_raises(self):
        with mock.patch("urllib.request.urlopen", _answer(b"x" * 10)), \
                self.assertRaises(ValueError):
            fetch_bytes("https://x.example/f", max_bytes=5)


class GitHubAnswers(unittest.TestCase):
    def test_a_truncated_tree_raises(self):
        with mock.patch("urllib.request.urlopen", _answer({"tree": [], "truncated": True})), \
                self.assertRaises(RuntimeError):
            github_tree("o/r", "v1")

    def test_a_body_that_is_no_tree_raises(self):
        with mock.patch("urllib.request.urlopen", _answer([])), self.assertRaises(RuntimeError):
            github_tree("o/r", "v1")

    def test_the_tree_entries(self):
        tree = {"tree": [{"path": "a", "type": "blob"}, {"type": "blob"}], "truncated": False}
        opener = _answer(tree)
        with mock.patch("urllib.request.urlopen", opener):
            self.assertEqual(github_tree("o/r", "v1", recursive=False), [tree["tree"][0]])
        self.assertTrue(opener.seen[0].full_url.endswith("/git/trees/v1"))

    def test_a_directory_is_not_a_submodule(self):
        """A directory's contents answer has a sha too, the sha of a tree."""
        with mock.patch("urllib.request.urlopen", _answer({"type": "dir", "sha": SHA})), \
                self.assertRaises(RuntimeError):
            submodule_commit("o/r", "sub", "v1")
        with mock.patch("urllib.request.urlopen", _answer({"type": "submodule", "sha": SHA})):
            self.assertEqual(submodule_commit("o/r", "sub", "v1"), SHA)

    def test_a_release_without_a_tag_raises(self):
        for body in ({}, {"tag_name": 5}, [], {"tag_name": ""}):
            with self.subTest(body=body), mock.patch("urllib.request.urlopen", _answer(body)), \
                    self.assertRaises(RuntimeError):
                fetch_github_latest_version("o/r")
        with mock.patch("urllib.request.urlopen", _answer({"tag_name": "v9"})):
            self.assertEqual(fetch_github_latest_version("o/r"), "v9")


class Downloads(unittest.TestCase):
    def test_written_whole_with_its_disposition(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            target = Path(tmp, "sub", "a.zip")
            with mock.patch("urllib.request.urlopen", _answer(503, b"payload")), \
                    mock.patch("time.sleep"):
                disposition = download("https://x.example/a.zip", target)
            self.assertEqual(target.read_bytes(), b"payload")
            self.assertIn("a.zip", disposition)
            self.assertEqual(sorted(p.name for p in target.parent.iterdir()), ["a.zip"])

    def test_a_failure_leaves_nothing(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            target = Path(tmp, "a.zip")
            with mock.patch("urllib.request.urlopen", _answer(403)), \
                    self.assertRaises(FetchError):
                download("https://x.example/a.zip", target)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_an_existing_file_is_kept_when_asked(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            target = Path(tmp, "a.zip")
            target.write_bytes(b"cached")
            with mock.patch("urllib.request.urlopen", _answer(403)):
                self.assertEqual(download("https://x.example/a.zip", target, skip_existing=True), "")
            self.assertEqual(target.read_bytes(), b"cached")


class OneImplementationPerJob(unittest.TestCase):
    """Each job had its own copy: a revision reader in six modules, a
    release lookup in four, a tree listing in seven."""

    def test_no_scraper_keeps_its_own_copy(self):
        scraper_dir = REPO_ROOT / "scripts" / "scraper"
        needles = ("def launcher_revision", "releases/latest", "urlopen(", "?recursive=1",
                   "def _download")
        found = [
            f"{path.relative_to(scraper_dir)}: {needle}"
            for path in sorted(scraper_dir.rglob("*.py"))
            if path.name != "base_scraper.py"
            for needle in needles
            if needle in path.read_text(encoding="utf-8")
        ]
        # buildbot_system asks for ETags with HEAD requests, which no shared
        # helper sends. MinUI reads through a fetch its tests replace, and
        # hands the answer to tree_entries.
        self.assertEqual(found, ["buildbot_system.py: urlopen(", "minui_scraper.py: ?recursive=1"])

    def test_the_target_package_reads_through_the_platform_helpers(self):
        from scraper import targets

        self.assertIs(targets.fetch_text, base_scraper.fetch_text)
        self.assertIs(targets.forge_headers, base_scraper.forge_headers)


if __name__ == "__main__":
    unittest.main()
