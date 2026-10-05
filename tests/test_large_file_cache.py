#!/usr/bin/env python3
"""Large-file cache downloads.

Two runs fetching the same asset used to stream into one shared scratch
path, interleaving their writes into a full-size file with mixed content
that then replaced the cache entry.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402
import largefiles

PAYLOAD_A = b"A" * (256 * 1024)
PAYLOAD_B = b"B" * (256 * 1024)


class _SlowResponse(io.BytesIO):
    """Serve a payload in chunks, yielding between them."""

    def __init__(self, data: bytes, barrier: threading.Barrier | None = None):
        super().__init__(data)
        self._barrier = barrier
        self._first = True

    def read(self, size: int = -1) -> bytes:
        chunk = super().read(min(size, 4096) if size and size > 0 else 4096)
        if self._first and self._barrier is not None:
            self._first = False
            self._barrier.wait(timeout=10)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class LargeFileCacheTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self._urlopen = largefiles.urllib.request.urlopen

    def tearDown(self):
        largefiles.urllib.request.urlopen = self._urlopen

    def test_concurrent_fetches_do_not_mix(self):
        barrier = threading.Barrier(2, timeout=10)
        payloads = [PAYLOAD_A, PAYLOAD_B]
        index = iter(range(2))
        lock = threading.Lock()

        def fake_urlopen(req, timeout=None):
            with lock:
                i = next(index)
            return _SlowResponse(payloads[i], barrier)

        largefiles.urllib.request.urlopen = fake_urlopen
        results: list[str | None] = [None, None]

        def worker(slot: int):
            results[slot] = common.fetch_large_file("asset.bin", dest_dir=self.dir)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        cached = Path(self.dir) / "asset.bin"
        self.assertTrue(cached.exists())
        digest = hashlib.sha1(cached.read_bytes()).hexdigest()
        accepted = {hashlib.sha1(p).hexdigest() for p in payloads}
        # Whichever run lands last wins, but never a blend of the two
        self.assertIn(digest, accepted)

    def test_no_scratch_file_survives_a_successful_fetch(self):
        largefiles.urllib.request.urlopen = lambda req, timeout=None: _SlowResponse(
            PAYLOAD_A
        )
        common.fetch_large_file("asset.bin", dest_dir=self.dir)
        leftovers = [f for f in os.listdir(self.dir) if f.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_no_scratch_file_survives_a_failed_fetch(self):
        def fail(req, timeout=None):
            raise urllib.error.URLError("offline")

        largefiles.urllib.request.urlopen = fail
        self.assertIsNone(common.fetch_large_file("asset.bin", dest_dir=self.dir))
        self.assertEqual(os.listdir(self.dir), [])

    def test_hash_mismatch_leaves_no_scratch_file(self):
        largefiles.urllib.request.urlopen = lambda req, timeout=None: _SlowResponse(
            PAYLOAD_A
        )
        result = common.fetch_large_file(
            "asset.bin", dest_dir=self.dir, expected_sha1="00" * 20
        )
        self.assertIsNone(result)
        self.assertEqual(os.listdir(self.dir), [])

    def test_cached_file_is_returned_without_download(self):
        cached = Path(self.dir) / "asset.bin"
        cached.write_bytes(PAYLOAD_A)

        def fail(req, timeout=None):
            raise AssertionError("must not download when the cache is valid")

        largefiles.urllib.request.urlopen = fail
        self.assertEqual(
            common.fetch_large_file("asset.bin", dest_dir=self.dir), str(cached)
        )

    def test_offline_cache_miss_never_opens_the_network(self):
        def fail(req, timeout=None):
            raise AssertionError("offline mode must not open the network")

        largefiles.urllib.request.urlopen = fail
        self.assertIsNone(
            common.fetch_large_file(
                "asset.bin", dest_dir=self.dir, offline=True
            )
        )
        self.assertEqual(os.listdir(self.dir), [])

    def test_offline_mode_still_uses_a_verified_cache_hit(self):
        cached = Path(self.dir) / "asset.bin"
        cached.write_bytes(PAYLOAD_A)

        def fail(req, timeout=None):
            raise AssertionError("offline cache hit must not open the network")

        largefiles.urllib.request.urlopen = fail
        self.assertEqual(
            common.fetch_large_file(
                "asset.bin",
                dest_dir=self.dir,
                expected_sha1=hashlib.sha1(PAYLOAD_A).hexdigest(),
                offline=True,
            ),
            str(cached),
        )


class HashCacheKeepsEveryDigest(unittest.TestCase):
    """A cache hit must serve the same five digests a fresh hash produces.

    The cache-hit path rebuilt the hash dict from a hand-written list that
    omitted adler32, then wrote the entry back without it, so one run without
    --force stripped the digest from all 7,850 entries for good.
    """

    def setUp(self):
        import generate_db

        self.generate_db = generate_db
        self._tmp = tempfile.TemporaryDirectory()
        self.bios = Path(self._tmp.name) / "bios"
        (self.bios / "Sony" / "PS").mkdir(parents=True)
        (self.bios / "Sony" / "PS" / "boot.bin").write_bytes(b"CACHED PAYLOAD")

    def tearDown(self):
        self._tmp.cleanup()

    def test_cache_hit_serves_the_full_digest_set(self):
        files, _, cache = self.generate_db.scan_bios_dir(self.bios, {}, force=False)
        entry = next(iter(files.values()))
        self.assertTrue(set(self.generate_db.CACHED_HASHES).issubset(entry))

        # Second pass, this time served entirely from the cache.
        again, _, cache2 = self.generate_db.scan_bios_dir(self.bios, cache, force=False)
        entry2 = next(iter(again.values()))
        self.assertTrue(
            set(self.generate_db.CACHED_HASHES).issubset(entry2),
            f"cache hit lost {set(self.generate_db.CACHED_HASHES) - set(entry2)}",
        )
        self.assertEqual(
            {k: entry[k] for k in self.generate_db.CACHED_HASHES},
            {k: entry2[k] for k in self.generate_db.CACHED_HASHES},
        )
        self.assertTrue(
            set(self.generate_db.CACHED_HASHES).issubset(next(iter(cache2.values())))
        )

    def test_a_warm_cache_serialises_exactly_like_a_fresh_hash(self):
        """Key order must not depend on whether the cache was warm.

        Rebuilding the dict by iterating a set made the order follow set
        hashing, so a run with a warm cache rewrote all 7,850 entries with
        their digests in a different order and no content change.
        """
        fresh, _, cache = self.generate_db.scan_bios_dir(self.bios, {}, force=True)
        warm, _, _ = self.generate_db.scan_bios_dir(self.bios, cache, force=False)
        self.assertEqual(
            [list(entry) for entry in fresh.values()],
            [list(entry) for entry in warm.values()],
        )
        self.assertEqual(
            json.dumps(fresh, indent=2), json.dumps(warm, indent=2)
        )

    def test_a_partial_cache_entry_is_rehashed_instead_of_trusted(self):
        _, _, cache = self.generate_db.scan_bios_dir(self.bios, {}, force=False)
        key = next(iter(cache))
        cache[key].pop("adler32")
        files, _, healed = self.generate_db.scan_bios_dir(self.bios, cache, force=False)
        entry = next(iter(files.values()))
        self.assertTrue(set(self.generate_db.CACHED_HASHES).issubset(entry))
        self.assertTrue(set(self.generate_db.CACHED_HASHES).issubset(healed[key]))


class PreservedLargeFileEntries(unittest.TestCase):
    """A preserved entry must never claim a path another entry already owns.

    A large file replaced on disk by a newer firmware revision left its old
    entry in the database forever, pointing at a path that now serves other
    bytes.
    """

    def setUp(self):
        import generate_db

        self.generate_db = generate_db
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self._cwd = os.getcwd()
        os.chdir(self.tmp)
        (self.tmp / ".gitignore").write_text("bios/Sony/PS3/FW.PUP\n")
        self._real_fetch = common.fetch_large_file
        generate_db.__dict__.pop("fetch_large_file", None)

    def tearDown(self):
        os.chdir(self._cwd)
        common.fetch_large_file = self._real_fetch
        self._tmp.cleanup()

    def _write_db(self, entries: dict) -> str:
        path = str(self.tmp / "database.json")
        Path(path).write_text(json.dumps({"files": entries}))
        return path

    def test_stale_entry_for_a_rescanned_path_is_dropped(self):
        common.fetch_large_file = lambda *a, **k: None
        db_path = self._write_db(
            {
                "a" * 40: {"name": "FW.PUP", "path": "bios/Sony/PS3/FW.PUP"},
                "b" * 40: {"name": "FW.PUP", "path": "bios/Sony/PS3/FW.PUP"},
            }
        )
        # The scan found the current revision at that path.
        files = {"a" * 40: {"name": "FW.PUP", "path": "bios/Sony/PS3/FW.PUP"}}
        count = self.generate_db._preserve_large_file_entries(files, db_path)
        self.assertEqual(count, 0)
        self.assertEqual(list(files), ["a" * 40])

    def test_absent_large_file_is_still_preserved(self):
        common.fetch_large_file = lambda *a, **k: None
        db_path = self._write_db(
            {"b" * 40: {"name": "FW.PUP", "path": "bios/Sony/PS3/FW.PUP"}}
        )
        files: dict = {}
        count = self.generate_db._preserve_large_file_entries(files, db_path)
        self.assertEqual(count, 1)
        self.assertIn("b" * 40, files)

    def test_verified_cache_hit_repoints_the_entry(self):
        common.fetch_large_file = lambda *a, **k: "/cache/large/FW.PUP"
        db_path = self._write_db(
            {"b" * 40: {"name": "FW.PUP", "path": "bios/Sony/PS3/FW.PUP"}}
        )
        files = {"a" * 40: {"name": "FW.PUP", "path": "bios/Sony/PS3/FW.PUP"}}
        count = self.generate_db._preserve_large_file_entries(files, db_path)
        self.assertEqual(count, 1)
        self.assertEqual(files["b" * 40]["path"], "/cache/large/FW.PUP")


class ReleaseAssetNames(unittest.TestCase):
    """One registered path, one asset name, the same for every consumer.

    Every consumer named an asset by the file's basename, so two collection
    files sharing one (`etmain/pak0.pk3` and `demomain/pak0.pk3`) could not
    both be published: the second upload replaced the first and every
    fetch received whichever was there.
    """

    ET = "bios/Id Software/Wolfenstein Enemy Territory/etmain/pak0.pk3"
    RTCW = "bios/Id Software/Return to Castle Wolfenstein/demomain/pak0.pk3"
    PUP = "bios/Sony/PS3/PS3UPDAT.PUP"
    REGISTERED = [ET, RTCW, PUP]

    def test_a_shared_basename_gets_two_distinct_names(self):
        names = largefiles.asset_names(self.REGISTERED)
        self.assertNotEqual(names[self.ET], names[self.RTCW])
        self.assertNotIn("pak0.pk3", (names[self.ET], names[self.RTCW]))
        for name in (names[self.ET], names[self.RTCW]):
            self.assertNotIn("/", name)
            self.assertNotIn(" ", name)
            self.assertTrue(name.endswith("pak0.pk3"))

    def test_the_name_depends_on_the_path_not_on_the_set_order(self):
        forward = largefiles.asset_names(self.REGISTERED)
        backward = largefiles.asset_names(list(reversed(self.REGISTERED)))
        self.assertEqual(forward, backward)

    def test_a_basename_used_once_keeps_its_name(self):
        self.assertEqual(
            largefiles.asset_name(self.PUP, self.REGISTERED), "PS3UPDAT.PUP"
        )
        self.assertEqual(
            largefiles.asset_names(["bios/Arcade/MAME/MAME 0.174 Arcade XML.dat"]),
            {"bios/Arcade/MAME/MAME 0.174 Arcade XML.dat": "MAME 0.174 Arcade XML.dat"},
        )

    def test_the_published_register_has_no_two_paths_on_one_name(self):
        registered = largefiles.registered_paths(
            (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        )
        names = largefiles.asset_names(registered)
        self.assertEqual(len(set(names.values())), len(registered))
        basenames = [os.path.basename(p) for p in registered]
        for registered_path, name in names.items():
            if basenames.count(os.path.basename(registered_path)) == 1:
                self.assertEqual(name, os.path.basename(registered_path))

    def test_manifest_checker_and_fetcher_agree_on_a_path(self):
        import check_release_assets
        import generate_pack

        expected = largefiles.asset_names(self.REGISTERED)
        gitignore = "\n".join(["tmp/", *self.REGISTERED]) + "\n"

        with tempfile.TemporaryDirectory() as root:
            Path(root, ".gitignore").write_text(gitignore, encoding="utf-8")
            generate_pack._GITIGNORE_ENTRIES = None
            try:
                manifest = {
                    p: generate_pack._release_asset_name(os.path.join(root, p), root)
                    for p in self.REGISTERED
                }
            finally:
                generate_pack._GITIGNORE_ENTRIES = None
        self.assertEqual(manifest, expected)

        sizes = {self.ET: 228138631, self.RTCW: 122757192, self.PUP: 10}
        published = {expected[p]: size for p, size in sizes.items()}
        self.assertEqual(
            check_release_assets.compare(
                sizes, published, registered=self.REGISTERED
            ),
            [],
        )
        # The old basename-only asset must not satisfy either pak.
        self.assertEqual(
            {f[1] for f in check_release_assets.compare(
                sizes, {"pak0.pk3": 228138631, "PS3UPDAT.PUP": 10},
                registered=self.REGISTERED,
            )},
            {self.ET, self.RTCW},
        )
        db = {"files": {
            "a" * 40: {"path": self.ET, "size": sizes[self.ET]},
            "b" * 40: {"path": self.RTCW, "size": sizes[self.RTCW]},
            "c" * 40: {"path": self.PUP, "size": sizes[self.PUP]},
        }}
        body = check_release_assets.render_notes(
            db, gitignore, published, "", {}, {}, {}
        )
        self.assertIn(f"[{expected[self.ET]}]", body)
        self.assertIn("a" * 40, body)
        self.assertIn("b" * 40, body)
        self.assertNotIn("## Not indexed", body)

        requested: list[str] = []

        def fake_urlopen(req, timeout=None):
            requested.append(req.full_url.rsplit("/", 1)[1])
            raise urllib.error.URLError("offline")

        self._urlopen = largefiles.urllib.request.urlopen
        largefiles.urllib.request.urlopen = fake_urlopen
        try:
            with tempfile.TemporaryDirectory() as cache:
                largefiles.fetch_large_file(
                    self.RTCW, dest_dir=cache, registered=self.REGISTERED
                )
                self.assertEqual(
                    requested,
                    [largefiles.urllib.parse.quote(expected[self.RTCW])],
                )
                requested.clear()
                largefiles.fetch_large_file(
                    "pak0.pk3", dest_dir=cache, registered=self.REGISTERED
                )
                self.assertEqual(
                    sorted(requested),
                    sorted(
                        largefiles.urllib.parse.quote(expected[p])
                        for p in (self.ET, self.RTCW)
                    ),
                )
        finally:
            largefiles.urllib.request.urlopen = self._urlopen

    def test_a_shared_basename_is_fetched_by_the_asset_its_hash_names(self):
        names = largefiles.asset_names(self.REGISTERED)
        with tempfile.TemporaryDirectory() as cache:
            Path(cache, names[self.ET]).write_bytes(PAYLOAD_A)
            Path(cache, names[self.RTCW]).write_bytes(PAYLOAD_B)
            got = largefiles.fetch_large_file(
                "pak0.pk3",
                dest_dir=cache,
                expected_sha1=hashlib.sha1(PAYLOAD_B).hexdigest(),
                offline=True,
                registered=self.REGISTERED,
            )
            self.assertEqual(got, os.path.join(cache, names[self.RTCW]))
            # The cache entry of the other asset is a valid file, not stale.
            self.assertTrue(Path(cache, names[self.ET]).exists())


if __name__ == "__main__":
    unittest.main()
