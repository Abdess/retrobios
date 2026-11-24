"""Data directory refreshes that other sessions can run at the same time.

Two refreshes of one key shared a fixed `<key>.previous` name and a
non-atomic existence test, so the second tree landed inside the first as
`extract/`. Staging in /tmp turned the swap into a 228 MB copy, and the
version file was truncated in place, where a concurrent reader died on an
empty JSON document.
"""

from __future__ import annotations

import tests

import io
import json
import shutil
import tarfile
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from packs import datadirs
from model.registry import load_data_dir_registry, load_versions
from packs.archive import Placed
from packs.datadirextract import extract_tar_subtree, extract_zip_tree
from packs.datatrees import data_directory_members

REPO_ROOT = Path(__file__).resolve().parents[1]


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buffer.getvalue()


class _Response(io.BytesIO):
    headers: dict[str, str] = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@tests.ONLINE
class RefreshConcurrency(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cache = self.root / "data" / "pak"
        self.versions = str(self.root / "data" / ".versions.json")

    def test_tree_is_swapped_in_by_rename(self):
        payload = _zip_bytes({"a.bin": b"new"})
        self.cache.mkdir(parents=True)
        (self.cache / "a.bin").write_bytes(b"old")
        with mock.patch.object(
            datadirs.urllib.request, "urlopen", lambda *a, **k: _Response(payload)
        ), mock.patch.object(
            shutil, "move", side_effect=AssertionError("copy across filesystems")
        ):
            count = datadirs._download_and_extract_zip("https://x/pak.zip", str(self.cache))
        self.assertEqual(count, 1)
        self.assertEqual((self.cache / "a.bin").read_bytes(), b"new")
        leftovers = [p.name for p in self.cache.parent.iterdir() if p.name != "pak"]
        self.assertEqual(leftovers, [])

    def test_a_refused_archive_leaves_no_cache(self):
        archive = self.root / "pak.zip"
        archive.write_bytes(_zip_bytes({"a.bin": b"a", "..\\escape.bin": b"x"}))
        with self.assertRaises(ValueError):
            datadirs._download_and_extract_zip(archive.as_uri(), str(self.cache))
        self.assertFalse(self.cache.exists())

    def test_refresh_holds_the_directory_lock(self):
        import fcntl

        payload = _zip_bytes({"a.bin": b"x"})
        lock_path = self.cache.with_name(".pak.lock")
        seen: list[bool] = []

        def fake_urlopen(*a, **k):
            with open(lock_path, "w") as handle:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    seen.append(True)
                else:
                    fcntl.flock(handle, fcntl.LOCK_UN)
                    seen.append(False)
            return _Response(payload)

        entry = {"source_type": "zip", "source_url": "https://x/pak.zip",
                 "local_cache": str(self.cache)}
        with mock.patch.object(datadirs.urllib.request, "urlopen", fake_urlopen), \
                mock.patch.object(datadirs, "_get_remote_etag", return_value="e1"):
            self.assertTrue(
                datadirs.refresh_entry("pak", entry, force=True)
            )
        self.assertEqual(seen, [True])

    def test_the_archive_size_is_recorded_without_replacing_the_tree(self):
        """The installer announces a tree's download as the archive's size:
        a tarball extracted to 10 KB is a download of 21 MB. A tree current
        before the size was kept is measured, its files left as they are."""
        payload = _zip_bytes({"a.bin": b"x" * 100})
        entry = {"source_type": "zip", "source_url": "https://x/pak.zip",
                 "local_cache": str(self.cache)}
        with mock.patch.object(datadirs.urllib.request, "urlopen",
                               lambda *a, **k: _Response(payload)), \
                mock.patch.object(datadirs, "_get_remote_etag", return_value="e1"):
            self.assertTrue(datadirs.refresh_entry("pak", entry))
            self.assertEqual(load_versions(self.versions)["pak"]["archive_size"],
                             len(payload))
            datadirs._record_version("pak", {"sha": "e1"}, self.versions)
            (self.cache / "a.bin").write_bytes(b"kept")
            self.assertFalse(datadirs.refresh_entry("pak", entry))
        self.assertEqual(load_versions(self.versions)["pak"],
                         {"sha": "e1", "archive_size": len(payload)})
        self.assertEqual((self.cache / "a.bin").read_bytes(), b"kept")

    def test_a_current_tree_is_not_waited_for(self):
        """A pipeline reads every tree for its whole run. A build beside it
        waited on the exclusive lock before asking the remote, which would
        have answered that nothing changed."""
        import fcntl

        self.cache.mkdir(parents=True)
        datadirs._record_version("pak", {"sha": "e1", "archive_size": 1}, self.versions)
        entry = {"source_type": "zip", "source_url": "https://x/pak.zip",
                 "local_cache": str(self.cache)}
        result: list = []
        with open(self.cache.with_name(".pak.lock"), "a") as reader, \
                mock.patch.object(datadirs, "_get_remote_etag", return_value="e1"):
            fcntl.flock(reader, fcntl.LOCK_SH)
            worker = threading.Thread(target=lambda: result.append(
                datadirs.refresh_entry("pak", entry)
            ), daemon=True)
            worker.start()
            worker.join(timeout=20)
            finished = not worker.is_alive()
            fcntl.flock(reader, fcntl.LOCK_UN)
        worker.join(timeout=20)
        self.assertTrue(finished, "the refresh waited for a reader")
        self.assertEqual(result, [False])

    def test_a_waiting_refresh_names_the_lock_and_the_way_around(self):
        """"waiting for data/dolphin-sys: another run holds it" named
        neither the lock nor its holder, and the build waited unbounded."""
        import fcntl

        self.cache.mkdir(parents=True)
        lock_path = self.cache.with_name(".pak.lock")
        entered = threading.Event()

        def refresh() -> None:
            with datadirs.cache_lock(self.cache):
                entered.set()

        with open(lock_path, "a") as reader, self.assertLogs(datadirs.log, "WARNING") as logs:
            fcntl.flock(reader, fcntl.LOCK_SH)
            worker = threading.Thread(target=refresh, daemon=True)
            worker.start()
            for _ in range(200):
                if logs.records:
                    break
                worker.join(timeout=0.05)
            self.assertFalse(entered.is_set())
            fcntl.flock(reader, fcntl.LOCK_UN)
            worker.join(timeout=20)
        self.assertTrue(entered.is_set())
        message = logs.records[0].getMessage()
        self.assertIn(f"lsof {lock_path}", message)
        self.assertIn("--no-refresh-data", message)

    def test_version_file_is_never_left_truncated(self):
        Path(self.versions).parent.mkdir(parents=True)
        Path(self.versions).write_text(json.dumps({"keep": {"sha": "1"}}))
        with mock.patch("core.artifacts.os.replace", side_effect=OSError("disk full")), \
                self.assertRaises(OSError):
            datadirs._save_versions({"keep": {"sha": "2"}}, self.versions)
        self.assertEqual(json.loads(Path(self.versions).read_text()), {"keep": {"sha": "1"}})

    def test_concurrent_writers_keep_each_other(self):
        keys = [f"k{i}" for i in range(16)]
        threads = [
            threading.Thread(
                target=datadirs._record_version, args=(k, {"sha": k}, self.versions)
            )
            for k in keys
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(load_versions(self.versions)), sorted(keys))


class PackWalkHoldsTheCache(unittest.TestCase):
    def test_a_refresh_waits_for_the_walk(self):
        import fcntl


        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "data" / "sdlpal"
            cache.mkdir(parents=True)
            (cache / "a.mkf").write_bytes(b"a")
            (cache / "b.mkf").write_bytes(b"b")
            systems = {"s": {"data_directories": [{"ref": "sdlpal", "destination": "sdlpal"}]}}
            registry = {"sdlpal": {"local_cache": str(cache)}}
            walk = data_directory_members(systems, registry, "p", "", Placed(False))
            next(walk)
            with open(cache.with_name(".sdlpal.lock"), "a") as handle, self.assertRaises(
                BlockingIOError
            ):
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            list(walk)
            with open(cache.with_name(".sdlpal.lock"), "a") as handle:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(handle, fcntl.LOCK_UN)

class EmulatorPackHoldsTheCache(unittest.TestCase):
    def test_the_walk_holds_a_shared_lock(self):
        import fcntl

        from packs.datatrees import pack_data_tree

        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "data" / "scummvm"
            cache.mkdir(parents=True)
            (cache / "a.dat").write_bytes(b"a")
            held: list[bool] = []

            def member(_zf, _src, _dest, executable=None):
                with open(cache.with_name(".scummvm.lock"), "a") as handle:
                    try:
                        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        held.append(True)
                    else:
                        fcntl.flock(handle, fcntl.LOCK_UN)
                        held.append(False)

            with mock.patch("packs.datatrees.add_pack_member", member):
                pack_data_tree(None, str(cache), "scummvm", Placed(True))
            self.assertEqual(held, [True])


class AWaitIsAnnounced(unittest.TestCase):
    def test_a_held_tree_is_named_before_the_wait(self):
        """A pipeline holds every tree for its run: the refresh beside it
        waited with nothing on screen."""
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "probe"
            taken = threading.Event()

            def second_run() -> None:
                with datadirs.cache_lock(cache):
                    taken.set()

            with self.assertLogs(datadirs.log, "WARNING") as logs:
                with datadirs.cache_lock(cache):
                    worker = threading.Thread(target=second_run)
                    worker.start()
                    for _ in range(100):
                        if logs.output:
                            break
                        threading.Event().wait(0.05)
                    self.assertFalse(taken.is_set())
                worker.join(10)
            self.assertTrue(taken.is_set())
            self.assertIn("waiting for", logs.output[0])
            self.assertIn("probe", logs.output[0])


class DryRunReport(unittest.TestCase):
    """What a dry run says: why each entry would be fetched, and how many."""

    def test_a_quoted_etag_is_cut_without_its_quotes(self):
        self.assertEqual(datadirs._short_tag('"0x8DF0B72EB52A1C0"'), "0x8DF0B72EB5")
        self.assertEqual(datadirs._short_tag('W/"2685251384"'), "2685251384")
        self.assertEqual(datadirs._short_tag(None), "none")

    def test_the_remote_tag_is_shown_beside_the_cached_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            versions = Path(tmp) / ".versions.json"
            versions.write_text(json.dumps({"k": {"etag": '"2725165595"', "archive_size": 1}}))
            (Path(tmp) / "k").mkdir()
            entry = {"source_type": "zip", "source_url": "https://x.invalid/a.zip",
                     "local_cache": str(Path(tmp) / "k")}
            with mock.patch.object(datadirs, "_get_remote_etag", return_value='"2685251384"'), \
                    self.assertLogs(datadirs.log, "INFO") as logs:
                self.assertTrue(datadirs.refresh_entry("k", entry, dry_run=True))
        self.assertIn("cached: 2725165595, remote: 2685251384", logs.output[0])

    def test_a_run_ends_on_its_counts(self):
        self.assertEqual(
            datadirs.summarize({"a": True, "b": False, "c": False}, dry_run=True),
            "3 entries: 1 would refresh, 2 up to date",
        )
        self.assertEqual(
            datadirs.summarize({"a": True, "b": None}, dry_run=False),
            "2 entries: 1 refreshed, 0 up to date, 1 failed",
        )


class TheManifestCarriesTheArchiveSize(unittest.TestCase):
    """The size refresh_data_dirs recorded reaches the install list, which
    the installer announces as the tree's download."""

    def test_recorded_size_is_written_and_an_unrecorded_one_left_out(self):
        from packs.datatrees import manifest_data_directories

        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "data"
            for ref in ("pak", "old"):
                (data / ref).mkdir(parents=True)
                (data / ref / "a.bin").write_bytes(b"abc")
            (data / ".versions.json").write_text(json.dumps(
                {"pak": {"sha": "e1", "archive_size": 21_360_579}, "old": {"sha": "e2"}}))
            registry = {ref: {"source_type": "zip", "source_url": f"https://x/{ref}.zip",
                              "local_cache": str(data / ref)} for ref in ("pak", "old")}
            members = [(str(data / ref / "a.bin"), f"{ref}/a.bin") for ref in ("pak", "old")]
            refs = {f"{ref}/a.bin": (ref, ("s",), ref, True) for ref in ("pak", "old")}
            listed = {entry["ref"]: entry for entry in
                      manifest_data_directories(members, refs, registry, "")}
        self.assertEqual(listed["pak"]["archive_size"], 21_360_579)
        self.assertNotIn("archive_size", listed["old"])
        self.assertNotIn("optional", listed["pak"])


class ASourceThatMovesIsPinnedOrFollowed(unittest.TestCase):
    """The PPSSPP list pinned the bytes of a buildbot nightly: six days after
    the buildbot rebuilt it, 49 of its 169 files were refused on every
    install. A source with a revision is listed at the commit it was fetched
    at. One with none is marked rolling, and the installer follows it."""

    COMMIT = "c" * 40

    def _listed(self, registry: dict, versions: dict) -> dict[str, dict]:
        from packs.datatrees import manifest_data_directories

        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "data"
            for ref, entry in registry.items():
                (data / ref).mkdir(parents=True)
                (data / ref / "a.bin").write_bytes(b"abc")
                entry["local_cache"] = str(data / ref)
            (data / ".versions.json").write_text(json.dumps(versions))
            members = [(str(data / ref / "a.bin"), f"{ref}/a.bin") for ref in registry]
            refs = {f"{ref}/a.bin": (ref, ("s",), ref, True) for ref in registry}
            return {entry["ref"]: entry for entry in
                    manifest_data_directories(members, refs, registry, "")}

    def test_a_branch_is_listed_at_the_commit_it_was_fetched_at(self):
        listed = self._listed(
            {"git": {"source_type": "tarball", "version": "master",
                     "source_url": "https://github.com/o/r/archive/{version}.tar.gz",
                     "source_path": "r-{version}/dat"},
             "nightly": {"source_type": "zip",
                         "source_url": "https://buildbot.libretro.com/assets/system/P.zip"},
             "unrecorded": {"source_type": "zip", "version": "master",
                            "source_url": "https://github.com/o/u/archive/{version}.zip"}},
            {"git": {"sha": self.COMMIT, "version": "master"},
             "nightly": {"sha": '"1261709225"', "version": "master"}})
        self.assertEqual(listed["git"]["url"], f"https://github.com/o/r/archive/{self.COMMIT}.tar.gz")
        self.assertEqual(listed["git"]["source_path"], f"r-{self.COMMIT}/dat")
        self.assertNotIn("rolling", listed["git"])
        self.assertIs(listed["nightly"]["rolling"], True)
        # No commit recorded: the branch's name is all the list can carry.
        self.assertIs(listed["unrecorded"]["rolling"], True)

    def test_a_branch_is_fetched_at_the_commit_it_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            versions = str(Path(tmp) / ".versions.json")
            entry = {"source_type": "zip", "version": "master", "strip_components": 1,
                     "source_url": "https://github.com/o/r/archive/{version}.zip",
                     "local_cache": str(Path(tmp) / "r")}
            fetched: list[str] = []

            def extract(url, *args, **kwargs):
                fetched.append(url)
                return 1

            with mock.patch.object(datadirs, "get_remote_sha", return_value=self.COMMIT), \
                    mock.patch.object(datadirs, "_get_remote_etag",
                                      side_effect=AssertionError("an ETag for a revision")), \
                    mock.patch.object(datadirs, "_download_and_extract_zip", extract):
                self.assertTrue(datadirs.refresh_entry("r", entry, force=True))
            self.assertEqual(fetched, [f"https://github.com/o/r/archive/{self.COMMIT}.zip"])
            self.assertEqual(load_versions(versions)["r"],
                             {"sha": self.COMMIT, "version": "master"})

    def test_the_record_lives_beside_the_tree(self):
        """A registry whose caches sit outside data/ wrote their commits to
        ./data/.versions.json: the manifest read nothing beside the tree and
        listed the branch by name, and the real data/ tree of the same key
        was recorded at a commit it did not hold."""
        from packs.datatrees import manifest_data_directories
        from sitegen.lookup import data_directory_revisions

        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "x" / "data" / "r"
            entry = {"source_type": "zip", "version": "master",
                     "source_url": "https://github.com/o/r/archive/{version}.zip",
                     "local_cache": str(cache)}

            def extract(url, local_cache, *args, **kwargs):
                Path(local_cache).mkdir(parents=True)
                (Path(local_cache) / "a.bin").write_bytes(b"abc")
                return 1

            with mock.patch.object(datadirs, "get_remote_sha", return_value=self.COMMIT), \
                    mock.patch.object(datadirs, "_download_and_extract_zip", extract):
                self.assertTrue(datadirs.refresh_entry("r", entry, force=True))
            self.assertEqual(load_versions(cache.parent / ".versions.json")["r"]["sha"],
                             self.COMMIT)
            listed = manifest_data_directories(
                [(str(cache / "a.bin"), "r/a.bin")], {"r/a.bin": ("r", ("s",), "r", True)},
                {"r": entry}, "")
            self.assertEqual(data_directory_revisions({"r": entry})["r"]["sha"], self.COMMIT)
        self.assertEqual(listed[0]["url"], f"https://github.com/o/r/archive/{self.COMMIT}.zip")
        self.assertNotIn("rolling", listed[0])

    def test_every_forge_source_takes_a_commit(self):
        """archive/refs/heads/<commit> is no address: a forge source must be
        written so the commit the refresh reads can replace its branch."""
        registry = load_data_dir_registry(REPO_ROOT / "platforms", required=True)
        for key, entry in registry.items():
            if not datadirs.revisioned(entry):
                continue
            with self.subTest(key):
                self.assertNotIn("refs/heads/", entry["source_url"])
                if entry.get("source_type", "tarball") == "tarball":
                    self.assertIn("{version}", entry["source_path"])


@tests.ONLINE
class TheRemoteCommitComesFromTheForgeClient(unittest.TestCase):
    """get_remote_sha read a GitLab subgroup as its first two segments,
    asked the branches endpoint (no tag, no encoded name), sent the token to
    any URL containing "github", and skipped the refresh on one 502."""

    def _resolve(self, url: str, version: str, answers: list) -> tuple[str | None, list]:
        from core import upstream
        from core import forgehttp

        seen: list = []

        def urlopen(request, timeout=0):
            seen.append(request)
            answer = answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return _Response(json.dumps(answer).encode())

        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp, \
                mock.patch.object(upstream, "CACHE_DIR", tmp), \
                mock.patch.object(forgehttp, "_sleep", lambda _s: None), \
                mock.patch.dict("os.environ", {"GITHUB_TOKEN": "SECRET"}), \
                mock.patch("urllib.request.urlopen", urlopen):
            return datadirs.get_remote_sha(url, version), seen

    def test_a_gitlab_subgroup_tag_resolves_without_the_token(self):
        sha, seen = self._resolve(
            "https://gitlab.com/grp/github-mirror/proj/-/archive/{version}/proj.tar.gz",
            "release/1.0", [[{"id": "a" * 40}]],
        )
        self.assertEqual(sha, "a" * 40)
        self.assertIn("projects/grp%2Fgithub-mirror%2Fproj/repository/commits", seen[0].full_url)
        self.assertIn("ref_name=release%2F1.0", seen[0].full_url)
        self.assertIsNone(seen[0].get_header("Authorization"))

    def test_a_transient_server_error_is_retried(self):
        import urllib.error

        sha, seen = self._resolve(
            "https://github.com/o/n/archive/{version}.tar.gz", "master",
            [urllib.error.HTTPError("u", 502, "Bad Gateway", None, None), [{"sha": "b" * 40}]],
        )
        self.assertEqual((sha, len(seen)), ("b" * 40, 2))
        self.assertEqual(seen[0].get_header("Authorization"), "Bearer SECRET")

    def test_the_answer_is_not_cached(self):
        from core import upstream

        with mock.patch.object(upstream, "write_cache") as write:
            sha, _seen = self._resolve(
                "https://github.com/o/n/archive/{version}.tar.gz", "master",
                [[{"sha": "c" * 40}]],
            )
        self.assertEqual(sha, "c" * 40)
        write.assert_not_called()

class ArchiveExtraction(unittest.TestCase):
    """The member rules, read on a local archive with no download."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / "extract"
        self.out.mkdir()

    def _zip(self, files: dict[str, bytes], method: int = zipfile.ZIP_STORED) -> Path:
        path = self.root / "archive.zip"
        with zipfile.ZipFile(path, "w", method) as zf:
            for name, data in files.items():
                zf.writestr(name, data)
        return path

    def test_members_follow_the_core_ziptools_rule(self):
        """A name with ".." inside a segment was dropped in silence, and a
        backslash member became a file named with the backslash."""
        archive = self._zip({"Docs/Read..me.txt": b"r", "sub\\a.bin": b"a"})
        self.assertEqual(extract_zip_tree(archive, self.out, []), 2)
        self.assertEqual((self.out / "Docs" / "Read..me.txt").read_bytes(), b"r")
        self.assertEqual((self.out / "sub" / "a.bin").read_bytes(), b"a")

    def test_a_traversing_member_refuses_the_archive(self):
        archive = self._zip({"a.bin": b"a", "..\\escape.bin": b"x"})
        with self.assertRaises(ValueError):
            extract_zip_tree(archive, self.out, [])

    def test_two_members_on_one_path_refuse_the_archive(self):
        """`a/x` and `a\\x` are one file once the separator is read: the
        second overwrote the first in silence."""
        archive = self._zip({"a/x": b"1", "a\\x": b"2"})
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            extract_zip_tree(archive, self.out, [])

    def test_stripping_onto_one_path_refuses_the_archive(self):
        archive = self._zip({"r1/a.bin": b"1", "r2/a.bin": b"2"})
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            extract_zip_tree(archive, self.out, [], strip_components=1)

    def test_a_member_larger_than_declared_refuses_the_archive(self):
        """A header that announces 10 bytes for a member that expands to
        more was copied to the end with no bound, and left a partial file."""
        archive = self._zip({"bomb.bin": b"x" * 100})
        data = bytearray(archive.read_bytes())
        local = data.index(b"PK\x03\x04")
        central = data.index(b"PK\x01\x02")
        data[local + 22:local + 26] = (10).to_bytes(4, "little")
        data[central + 24:central + 28] = (10).to_bytes(4, "little")
        archive.write_bytes(bytes(data))
        with self.assertRaises((ValueError, zipfile.BadZipFile)):
            extract_zip_tree(archive, self.out, [])
        self.assertEqual(list(self.out.iterdir()), [])

    def test_strip_and_exclude(self):
        archive = self._zip({
            "root/a.bin": b"a", "root/skip/b.bin": b"b", "root/": b"", "top.bin": b"t",
        })
        self.assertEqual(extract_zip_tree(archive, self.out, ["skip"], strip_components=1), 1)
        self.assertEqual(sorted(p.name for p in self.out.rglob("*")), ["a.bin"])

    def test_tar_subtree_relative_to_its_path(self):
        archive = self.root / "archive.tar.gz"
        payload = self.root / "f"
        payload.write_bytes(b"x")
        with tarfile.open(archive, "w:gz") as tf:
            for name in ("repo/Data/Sys/a.bin", "repo/Data/Sys/skip/b.bin", "repo/Other/c.bin"):
                tf.add(payload, arcname=name)
            link = tarfile.TarInfo("repo/Data/Sys/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tf.addfile(link)
        count, skipped = extract_tar_subtree(archive, self.out, "repo/Data/Sys", ["skip"])
        self.assertEqual((count, skipped), (1, ["repo/Data/Sys/link"]))
        self.assertEqual((self.out / "a.bin").read_bytes(), b"x")


if __name__ == "__main__":
    unittest.main()
