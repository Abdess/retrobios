"""Data directory refreshes that other sessions can run at the same time.

Two refreshes of one key shared a fixed `<key>.previous` name and a
non-atomic existence test, so the second tree landed inside the first as
`extract/`. Staging in /tmp turned the swap into a 228 MB copy, and the
version file was truncated in place, where a concurrent reader died on an
empty JSON document.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import refresh_data_dirs as rdd  # noqa: E402
from generate_pack import _data_directory_members  # noqa: E402


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
            rdd.urllib.request, "urlopen", lambda *a, **k: _Response(payload)
        ), mock.patch.object(
            rdd.shutil, "move", side_effect=AssertionError("copy across filesystems")
        ):
            count = rdd._download_and_extract_zip("https://x/pak.zip", str(self.cache))
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
        with mock.patch.object(rdd.urllib.request, "urlopen", fake_urlopen), \
                mock.patch.object(rdd, "_get_remote_etag", return_value="e1"):
            self.assertTrue(
                rdd.refresh_entry("pak", entry, force=True, versions_path=self.versions)
            )
        self.assertEqual(seen, [True])

    def test_version_file_is_never_left_truncated(self):
        Path(self.versions).parent.mkdir(parents=True)
        Path(self.versions).write_text(json.dumps({"keep": {"sha": "1"}}))
        with mock.patch.object(rdd.json, "dump", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                rdd._save_versions({"keep": {"sha": "2"}}, self.versions)
        self.assertEqual(json.loads(Path(self.versions).read_text()), {"keep": {"sha": "1"}})

    def test_concurrent_writers_keep_each_other(self):
        keys = [f"k{i}" for i in range(16)]
        threads = [
            threading.Thread(
                target=rdd._record_version, args=(k, {"sha": k}, self.versions)
            )
            for k in keys
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(rdd._load_versions(self.versions)), sorted(keys))


class PackWalkHoldsTheCache(unittest.TestCase):
    def test_a_refresh_waits_for_the_walk(self):
        import fcntl  # noqa: PLC0415


        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            cache = Path(tmp) / "data" / "sdlpal"
            cache.mkdir(parents=True)
            (cache / "a.mkf").write_bytes(b"a")
            (cache / "b.mkf").write_bytes(b"b")
            systems = {"s": {"data_directories": [{"ref": "sdlpal", "destination": "sdlpal"}]}}
            registry = {"sdlpal": {"local_cache": str(cache)}}
            walk = _data_directory_members(systems, registry, "p", "", False, set(), set(), set())
            next(walk)
            with open(cache.with_name(".sdlpal.lock"), "a") as handle, self.assertRaises(
                BlockingIOError
            ):
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            list(walk)
            with open(cache.with_name(".sdlpal.lock"), "a") as handle:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(handle, fcntl.LOCK_UN)

if __name__ == "__main__":
    unittest.main()
