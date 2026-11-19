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
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import refresh_data_dirs as rdd
from packs import datadirs
from model.registry import load_versions
from packs.datatrees import data_directory_members

REPO_ROOT = Path(__file__).resolve().parents[1]


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buffer.getvalue()


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class RefreshConcurrency(unittest.TestCase):
    def setUp(self):
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
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
            datadirs.shutil, "move", side_effect=AssertionError("copy across filesystems")
        ):
            count = datadirs._download_and_extract_zip("https://x/pak.zip", str(self.cache))
        self.assertEqual(count, 1)
        self.assertEqual((self.cache / "a.bin").read_bytes(), b"new")
        leftovers = [p.name for p in self.cache.parent.iterdir() if p.name != "pak"]
        self.assertEqual(leftovers, [])

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
                datadirs.refresh_entry("pak", entry, force=True, versions_path=self.versions)
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
            self.assertTrue(datadirs.refresh_entry("pak", entry, versions_path=self.versions))
            self.assertEqual(load_versions(self.versions)["pak"]["archive_size"],
                             len(payload))
            datadirs._record_version("pak", {"sha": "e1"}, self.versions)
            (self.cache / "a.bin").write_bytes(b"kept")
            self.assertFalse(datadirs.refresh_entry("pak", entry, versions_path=self.versions))
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
                datadirs.refresh_entry("pak", entry, versions_path=self.versions)
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
        with mock.patch.object(datadirs.json, "dump", side_effect=OSError("disk full")), self.assertRaises(OSError):
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


        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            cache = Path(tmp) / "data" / "sdlpal"
            cache.mkdir(parents=True)
            (cache / "a.mkf").write_bytes(b"a")
            (cache / "b.mkf").write_bytes(b"b")
            systems = {"s": {"data_directories": [{"ref": "sdlpal", "destination": "sdlpal"}]}}
            registry = {"sdlpal": {"local_cache": str(cache)}}
            walk = data_directory_members(systems, registry, "p", "", False, set(), set(), set())
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

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            cache = Path(tmp) / "data" / "scummvm"
            cache.mkdir(parents=True)
            (cache / "a.dat").write_bytes(b"a")
            held: list[bool] = []

            def member(_zf, _src, _dest):
                with open(cache.with_name(".scummvm.lock"), "a") as handle:
                    try:
                        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        held.append(True)
                    else:
                        fcntl.flock(handle, fcntl.LOCK_UN)
                        held.append(False)

            with mock.patch("packs.datatrees.add_pack_member", member):
                pack_data_tree(None, str(cache), "scummvm", set(), set(), set())
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
            versions = Path(tmp) / "versions.json"
            versions.write_text(json.dumps({"k": {"etag": '"2725165595"', "archive_size": 1}}))
            entry = {"source_type": "zip", "source_url": "https://x.invalid/a.zip",
                     "local_cache": tmp}
            with mock.patch.object(datadirs, "_get_remote_etag", return_value='"2685251384"'), \
                    self.assertLogs(datadirs.log, "INFO") as logs:
                self.assertTrue(datadirs.refresh_entry("k", entry, dry_run=True,
                                                  versions_path=str(versions)))
        self.assertIn("cached: 2725165595, remote: 2685251384", logs.output[0])

    def test_a_run_ends_on_its_counts(self):
        self.assertEqual(
            rdd.summarize({"a": True, "b": False, "c": False}, dry_run=True),
            "3 entries: 1 would refresh, 2 up to date",
        )
        self.assertEqual(
            rdd.summarize({"a": True, "b": None}, dry_run=False),
            "2 entries: 1 refreshed, 0 up to date, 1 failed",
        )


class TheManifestCarriesTheArchiveSize(unittest.TestCase):
    """The size refresh_data_dirs recorded reaches the install list, which
    the installer announces as the tree's download."""

    def test_recorded_size_is_written_and_an_unrecorded_one_left_out(self):
        from packs.datatrees import manifest_data_directories

        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
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
    at; one with none is marked rolling, and the installer follows it."""

    COMMIT = "c" * 40

    def _listed(self, registry: dict, versions: dict) -> dict[str, dict]:
        from packs.datatrees import manifest_data_directories

        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
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
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
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
                self.assertTrue(datadirs.refresh_entry("r", entry, force=True,
                                                       versions_path=versions))
            self.assertEqual(fetched, [f"https://github.com/o/r/archive/{self.COMMIT}.zip"])
            self.assertEqual(load_versions(versions)["r"],
                             {"sha": self.COMMIT, "version": "master"})

    def test_every_forge_source_takes_a_commit(self):
        """archive/refs/heads/<commit> is no address: a forge source must be
        written so the commit the refresh reads can replace its branch."""
        registry = datadirs.load_registry(str(REPO_ROOT / "platforms" / "_data_dirs.yml"))
        for key, entry in registry.items():
            if not datadirs.revisioned(entry):
                continue
            with self.subTest(key):
                self.assertNotIn("refs/heads/", entry["source_url"])
                if entry.get("source_type", "tarball") == "tarball":
                    self.assertIn("{version}", entry["source_path"])


if __name__ == "__main__":
    unittest.main()
