#!/usr/bin/env python3
"""Large-file cache downloads.

Two runs fetching the same asset used to stream into one shared scratch
path, interleaving their writes into a full-size file with mixed content
that then replaced the cache entry.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402
import largefiles
import check_release_assets  # noqa: E402

PAYLOAD_A = b"A" * (256 * 1024)
PAYLOAD_B = b"B" * (256 * 1024)


# These tests download through a mocked urlopen into their own directory;
# the CI test job sets RETROBIOS_OFFLINE to keep every other test off the
# network, so it is cleared here.
_ONLINE = mock.patch.dict(os.environ, {"RETROBIOS_OFFLINE": ""})

# The names these tests fetch, registered as .gitignore registers an asset:
# a bare name no registered path carries is never asked of the release.
TEST_REGISTERED = [
    "bios/Test/asset.bin",
    "bios/Test/spaced asset.bin",
    "bios/Test/big.bin",
    "bios/Sony/PlayStation 3/PS3UPDAT.PUP",
]


def _test_registry(case: unittest.TestCase) -> None:
    patcher = mock.patch.object(
        largefiles, "load_registered_paths", return_value=TEST_REGISTERED
    )
    patcher.start()
    case.addCleanup(patcher.stop)


def setUpModule():
    _ONLINE.start()


def tearDownModule():
    _ONLINE.stop()


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
        _test_registry(self)
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

    def test_a_spaced_name_served_dotted_reports_nothing(self):
        """GitHub publishes "spaced asset.bin" as "spaced.asset.bin": the
        404 on the spaced name came first and was printed as a failure."""
        asked: list[str] = []

        def urlopen(req, timeout=None):
            asked.append(req.full_url)
            if "spaced%20asset" in req.full_url:
                raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
            return _SlowResponse(PAYLOAD_A)

        largefiles.urllib.request.urlopen = urlopen
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            result = common.fetch_large_file("spaced asset.bin", dest_dir=self.dir)
        self.assertIsNotNone(result)
        self.assertEqual(len(asked), 2)
        self.assertEqual(err.getvalue(), "")

    def test_no_candidate_answering_reports_each(self):
        def fail(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)

        largefiles.urllib.request.urlopen = fail
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            self.assertIsNone(common.fetch_large_file("spaced asset.bin", dest_dir=self.dir))
        self.assertIn("spaced asset.bin", err.getvalue())
        self.assertIn("spaced.asset.bin", err.getvalue())

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
        self.assertTrue(os.path.samefile(
            common.fetch_large_file("asset.bin", dest_dir=self.dir), cached
        ))

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
        self.assertTrue(os.path.samefile(
            common.fetch_large_file(
                "asset.bin",
                dest_dir=self.dir,
                expected_sha1=hashlib.sha1(PAYLOAD_A).hexdigest(),
                offline=True,
            ),
            cached,
        ))

    def _serve(self, payload: bytes, gets: list):
        class _Head(io.BytesIO):
            headers = {"Content-Length": str(len(payload))}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def urlopen(req, timeout=None):
            if req.get_method() == "HEAD":
                return _Head()
            gets.append(req.full_url)
            return _SlowResponse(payload)

        largefiles.urllib.request.urlopen = urlopen

    def test_a_reuploaded_asset_replaces_the_cached_revision(self):
        """--clobber put new bytes under the name: the stale copy answered
        None on every run, without a single request."""
        cached = Path(self.dir) / "asset.bin"
        cached.write_bytes(PAYLOAD_A)
        rebuilt = b"C" * 1000
        gets: list = []
        self._serve(rebuilt, gets)
        result = common.fetch_large_file(
            "asset.bin", dest_dir=self.dir,
            expected_sha1=hashlib.sha1(rebuilt).hexdigest(),
        )
        self.assertTrue(os.path.samefile(result, cached))
        self.assertEqual(cached.read_bytes(), rebuilt)
        self.assertEqual(len(gets), 1)

    def test_an_orphan_link_is_never_returned(self):
        """A revision link whose cache name was removed has one link left.
        Downloaded again with the same bytes, the old link was returned and
        the prune of that same download removed it."""
        self._serve(PAYLOAD_A, [])
        sha1 = hashlib.sha1(PAYLOAD_A).hexdigest()
        first = common.fetch_large_file("asset.bin", dest_dir=self.dir, expected_sha1=sha1)
        self.assertTrue(first and os.path.isfile(first))
        os.unlink(Path(self.dir) / "asset.bin")
        with mock.patch.object(largefiles, "ORPHAN_GRACE", -1):
            second = common.fetch_large_file(
                "asset.bin", dest_dir=self.dir, expected_sha1=sha1
            )
        self.assertTrue(second and os.path.isfile(second))
        self.assertTrue(os.path.samefile(second, Path(self.dir) / "asset.bin"))

    def test_a_cache_hit_relinks_an_orphan(self):
        """The cache name was replaced by a copy with the same bytes: the hit
        handed out the old link, which a prune elsewhere would remove."""
        self._serve(PAYLOAD_A, [])
        sha1 = hashlib.sha1(PAYLOAD_A).hexdigest()
        common.fetch_large_file("asset.bin", dest_dir=self.dir, expected_sha1=sha1)
        cached = Path(self.dir) / "asset.bin"
        os.unlink(cached)
        cached.write_bytes(PAYLOAD_A)
        hit = common.fetch_large_file(
            "asset.bin", dest_dir=self.dir, expected_sha1=sha1, offline=True
        )
        self.assertTrue(os.path.samefile(hit, cached))

    def test_a_revision_the_release_still_serves_is_kept(self):
        cached = Path(self.dir) / "asset.bin"
        cached.write_bytes(PAYLOAD_A)
        gets: list = []
        self._serve(PAYLOAD_A, gets)
        result = common.fetch_large_file(
            "asset.bin", dest_dir=self.dir, expected_sha1="00" * 20
        )
        self.assertIsNone(result)
        self.assertEqual(gets, [])
        self.assertEqual(cached.read_bytes(), PAYLOAD_A)

    def test_a_download_that_does_not_verify_keeps_the_cache(self):
        cached = Path(self.dir) / "asset.bin"
        cached.write_bytes(PAYLOAD_A)
        gets: list = []
        self._serve(b"D" * 10, gets)
        result = common.fetch_large_file(
            "asset.bin", dest_dir=self.dir, expected_sha1="00" * 20
        )
        self.assertIsNone(result)
        self.assertEqual(cached.read_bytes(), PAYLOAD_A)
        self.assertEqual(os.listdir(self.dir), ["asset.bin"])


class TheOfflineSwitchHoldsEverywhere(unittest.TestCase):
    """RETROBIOS_OFFLINE stops a download whatever the caller asked."""

    def setUp(self):
        _test_registry(self)

    def test_no_request_is_made(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ, {"RETROBIOS_OFFLINE": "1"}
        ), mock.patch.object(largefiles.urllib.request, "urlopen") as urlopen:
            self.assertIsNone(
                largefiles.fetch_large_file("asset.bin", dest_dir=tmp, offline=False)
            )
            urlopen.assert_not_called()


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
        common.fetch_large_file = lambda *_a, **_k: None
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
        common.fetch_large_file = lambda *_a, **_k: None
        db_path = self._write_db(
            {"b" * 40: {"name": "FW.PUP", "path": "bios/Sony/PS3/FW.PUP"}}
        )
        files: dict = {}
        count = self.generate_db._preserve_large_file_entries(files, db_path)
        self.assertEqual(count, 1)
        self.assertIn("b" * 40, files)

    def test_a_fetched_asset_returns_to_its_registered_path(self):
        cache = self.tmp / "cache" / "FW.PUP"
        cache.parent.mkdir()
        cache.write_bytes(b"firmware")
        common.fetch_large_file = lambda *_a, **_k: str(cache)
        db_path = self._write_db(
            {"b" * 40: {"name": "FW.PUP", "path": "bios/Sony/PS3/FW.PUP"}}
        )
        files: dict = {}
        count = self.generate_db._preserve_large_file_entries(files, db_path)
        self.assertEqual(count, 1)
        self.assertEqual(files["b" * 40]["path"], "bios/Sony/PS3/FW.PUP")
        self.assertEqual((self.tmp / "bios/Sony/PS3/FW.PUP").read_bytes(), b"firmware")

    def test_an_interrupted_restore_leaves_no_file_behind(self):
        cache = self.tmp / "cache" / "FW.PUP"
        cache.parent.mkdir()
        cache.write_bytes(b"firmware")
        common.fetch_large_file = lambda *_a, **_k: str(cache)
        db_path = self._write_db(
            {"b" * 40: {"name": "FW.PUP", "path": "bios/Sony/PS3/FW.PUP"}}
        )

        def interrupted(_src, dst, *_a, **_k):
            Path(dst).write_bytes(b"firm")
            raise KeyboardInterrupt

        with mock.patch.object(self.generate_db.shutil, "copy2", interrupted), \
                self.assertRaises(KeyboardInterrupt):
            self.generate_db._preserve_large_file_entries({}, db_path)
        directory = self.tmp / "bios/Sony/PS3"
        self.assertEqual(list(directory.iterdir()), [])

    def test_a_file_sharing_only_the_name_is_not_preserved(self):
        common.fetch_large_file = lambda *_a, **_k: "/cache/large/FW.PUP"
        db_path = self._write_db(
            {"c" * 40: {"name": "FW.PUP", "path": "bios/Sony/PSP/FW.PUP"}}
        )
        files: dict = {}
        self.assertEqual(
            self.generate_db._preserve_large_file_entries(files, db_path), 0
        )
        self.assertEqual(files, {})

    def test_a_second_revision_under_a_rescanned_path_is_dropped(self):
        common.fetch_large_file = lambda *_a, **_k: "/cache/large/FW.PUP"
        db_path = self._write_db(
            {"b" * 40: {"name": "FW.PUP", "path": "bios/Sony/PS3/FW.PUP"}}
        )
        files = {"a" * 40: {"name": "FW.PUP", "path": "bios/Sony/PS3/FW.PUP"}}
        self.assertEqual(
            self.generate_db._preserve_large_file_entries(files, db_path), 0
        )
        self.assertEqual(list(files), ["a" * 40])


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
        import generate_pack

        expected = largefiles.asset_names(self.REGISTERED)
        gitignore = "\n".join(["tmp/", *self.REGISTERED]) + "\n"

        with tempfile.TemporaryDirectory() as root:
            Path(root, ".gitignore").write_text(gitignore, encoding="utf-8")
            generate_pack._registered.cache_clear()
            try:
                manifest = {
                    p: generate_pack._release_asset_name(os.path.join(root, p), root)
                    for p in self.REGISTERED
                }
            finally:
                generate_pack._registered.cache_clear()
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
            self.assertTrue(os.path.samefile(got, os.path.join(cache, names[self.RTCW])))
            # The cache entry of the other asset is a valid file, not stale.
            self.assertTrue(Path(cache, names[self.ET]).exists())


class _StalledResponse(io.BytesIO):
    """Serves one chunk, then the stream stalls."""

    def __init__(self):
        super().__init__(PAYLOAD_A)
        self._served = False

    def read(self, size: int = -1) -> bytes:
        if self._served:
            raise TimeoutError("read timed out")
        self._served = True
        return super().read(4096)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class DownloadFailuresAndRevisions(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=REPO_ROOT / "tmp")
        self._urlopen = largefiles.urllib.request.urlopen
        self.addCleanup(setattr, largefiles.urllib.request, "urlopen", self._urlopen)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_a_stalled_stream_leaves_no_scratch(self):
        largefiles.urllib.request.urlopen = lambda *_a, **_k: _StalledResponse()
        result = largefiles.fetch_large_file(
            "big.bin", self.dir, expected_md5=hashlib.md5(PAYLOAD_A).hexdigest(),
            registered=TEST_REGISTERED,
        )
        self.assertIsNone(result)
        self.assertEqual(os.listdir(self.dir), [])

    def test_another_revision_is_kept_not_evicted(self):
        cached = Path(self.dir, "PS3UPDAT.PUP")
        cached.write_bytes(PAYLOAD_A)
        largefiles.urllib.request.urlopen = lambda *_a, **_k: (_ for _ in ()).throw(
            urllib.error.URLError("offline")
        )
        result = largefiles.fetch_large_file(
            "PS3UPDAT.PUP", self.dir, expected_md5=hashlib.md5(PAYLOAD_B).hexdigest(),
            registered=TEST_REGISTERED,
        )
        self.assertIsNone(result)
        self.assertTrue(cached.exists())

    def test_a_variant_asset_is_a_candidate(self):
        registered = [
            "bios/Sony/PlayStation 3/PS3UPDAT.PUP",
            "bios/Sony/PlayStation 3/.variants/PS3UPDAT.PUP.ed8ab192",
        ]
        self.assertEqual(
            largefiles.asset_candidates("PS3UPDAT.PUP", registered),
            ["PS3UPDAT.PUP", "PS3UPDAT.PUP.ed8ab192"],
        )


class AnUnregisteredNameIsNoAsset(unittest.TestCase):
    """aes.zip and five others are in no .gitignore line: each online build
    asked the release for them and printed an HTTP 404 per name."""

    def test_no_candidate_and_no_request(self):
        self.assertEqual(largefiles.asset_candidates("aes.zip", TEST_REGISTERED), [])
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(largefiles.urllib.request, "urlopen") as urlopen:
            self.assertIsNone(largefiles.fetch_large_file(
                "aes.zip", dest_dir=tmp, offline=False, registered=TEST_REGISTERED,
            ))
        urlopen.assert_not_called()


class GameDataHasOneDefinition(unittest.TestCase):
    """The release notes and the composition table sorted game data apart.

    The notes knew two engine trees, the table sixteen: fifteen assets of
    Doom, Quake, Half-Life and Descent were listed as "Other". The Ur-Quan
    Masters tree was in neither.
    """

    def test_the_release_section_follows_the_composition_tier(self):
        for path in (
            "bios/Id Software/Doom 3/demo/demo00.pk4",
            "bios/Valve/Half-Life/valve/pak0.pak",
            "bios/Toys for Bob/The Ur-Quan Masters/uqm-0.8.0-voice.uqm",
        ):
            with self.subTest(path=path):
                self.assertEqual(common.composition_tier(path), "game_data")
                self.assertEqual(
                    check_release_assets._section_for(path), "Game engine data"
                )

    def test_a_tree_of_game_data_alone_is_a_game_data_tree(self):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            self.skipTest("database.json not generated")
        db = json.loads(db_path.read_text(encoding="utf-8"))
        profiles = common.load_emulator_profiles(str(REPO_ROOT / "emulators"))
        names: dict[str, set[str]] = {}
        for profile in profiles.values():
            for entry in profile.get("files") or []:
                category = entry.get("category", "bios")
                for name in [entry.get("name"), *(entry.get("aliases") or [])]:
                    if name:
                        names.setdefault(name, set()).add(category)
        trees: dict[str, set[str]] = {}
        for record in db["files"].values():
            parts = record["path"].split("/")
            if parts[0] == "bios" and parts[2:]:
                trees.setdefault(parts[1], set()).update(
                    names.get(record["name"], {"unreferenced"})
                )
        only_game_data = sorted(
            top for top, categories in trees.items() if categories == {"game_data"}
        )
        self.assertEqual(
            [top for top in only_game_data if top not in common.GAME_DATA_TOPS], []
        )



class ASameSizeReuploadIsSeen(unittest.TestCase):
    """A DSi NAND rebuilt at the same 251658304 bytes and re-uploaded with
    --clobber: judged by size, the stale cache copy was kept for good."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.cached = self.dir / "dsi_nand.bin"
        self.cached.write_bytes(b"OLD NAND")

    def replaced(self, digests: dict, size: int | None) -> bool:
        with mock.patch.object(largefiles, "_served_digests", lambda: digests), \
                mock.patch.object(largefiles, "_served_size", lambda name: size):
            return largefiles._replaced_on_release(
                "dsi_nand.bin", hashlib.sha256(self.cached.read_bytes()).hexdigest(),
                self.cached.stat().st_size, False,
            )

    def test_the_digest_decides(self):
        same = hashlib.sha256(b"OLD NAND").hexdigest()
        other = hashlib.sha256(b"NEW NAND").hexdigest()
        self.assertTrue(self.replaced({"dsi_nand.bin": other}, 8))
        self.assertFalse(self.replaced({"dsi_nand.bin": same}, 8))

    def test_without_a_digest_the_size_decides(self):
        self.assertFalse(self.replaced({}, 8))
        self.assertTrue(self.replaced({}, 9))

    def test_a_copy_promoted_during_the_check_is_the_one_judged(self):
        """Another run promotes the served revision while this one hashes the
        stale copy: the release check reread the path, found the served
        bytes, and the caller was told the cache held no such file."""
        new = b"NEW NAND"
        real = largefiles.compute_hashes

        def promote_while_hashing(path, *args, **kwargs):
            result = real(path, *args, **kwargs)
            if Path(path).read_bytes() != new:
                promoted = self.dir / "promoted.tmp"
                promoted.write_bytes(new)
                os.replace(promoted, self.cached)
            return result

        digests = {"dsi_nand.bin": hashlib.sha256(new).hexdigest()}
        with mock.patch.object(largefiles, "compute_hashes", promote_while_hashing), \
                mock.patch.object(largefiles, "_served_digests", lambda: digests):
            found = largefiles._fetch_asset(
                "dsi_nand.bin", str(self.dir), hashlib.sha1(new).hexdigest(), "",
                offline=False,
            )
        self.assertTrue(os.path.samefile(found, self.cached))

    def test_the_release_check_compares_digests_at_equal_size(self):
        expected = {"bios/Nintendo/DSi/dsi_nand.bin": 8}
        assets = {"dsi_nand.bin": 8}
        ours = {"bios/Nintendo/DSi/dsi_nand.bin": "a" * 64}
        self.assertEqual(
            [f[0] for f in check_release_assets.compare(
                expected, assets, expected_digests=ours,
                asset_digests={"dsi_nand.bin": "b" * 64},
            )],
            ["content"],
        )
        self.assertEqual(
            check_release_assets.compare(
                expected, assets, expected_digests=ours,
                asset_digests={"dsi_nand.bin": "a" * 64},
            ),
            [],
        )
        self.assertEqual(
            check_release_assets.digests_of(
                [{"name": "x", "digest": "sha256:ABC"}, {"name": "y"}]
            ),
            {"x": "abc"},
        )


class AVerifiedPathKeepsItsBytes(unittest.TestCase):
    """fetch_large_file verified a cached copy and returned its name. Another
    run that found the release re-uploaded then replaced that name with the
    new revision, and the first run packed bytes it never verified, under a
    manifest sha1 that describes the old ones."""

    def setUp(self):
        _test_registry(self)
        self.dir = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        (self.dir / "asset.bin").write_bytes(PAYLOAD_A)
        self.served = {"asset.bin": hashlib.sha256(PAYLOAD_B).hexdigest()}

    def _fetch(self, payload: bytes, offline: bool) -> str | None:
        def urlopen(req, timeout=None):
            return _SlowResponse(PAYLOAD_B)

        with mock.patch.object(largefiles, "_served_digests", lambda: self.served), \
                mock.patch.object(largefiles.urllib.request, "urlopen", urlopen):
            return largefiles.fetch_large_file(
                "asset.bin", dest_dir=str(self.dir),
                expected_sha1=hashlib.sha1(payload).hexdigest(), offline=offline,
            )

    def test_a_revision_promoted_after_the_check_is_not_read(self):
        first = self._fetch(PAYLOAD_A, offline=True)
        second = self._fetch(PAYLOAD_B, offline=False)
        self.assertEqual((self.dir / "asset.bin").read_bytes(), PAYLOAD_B)
        self.assertEqual(Path(second).read_bytes(), PAYLOAD_B)
        self.assertEqual(Path(first).read_bytes(), PAYLOAD_A)
        self.assertEqual(Path(first).name, "asset.bin")

    def test_an_orphaned_revision_is_dropped_after_the_grace(self):
        first = self._fetch(PAYLOAD_A, offline=True)
        self._fetch(PAYLOAD_B, offline=False)
        self.assertTrue(Path(first).exists())
        with mock.patch.object(largefiles, "ORPHAN_GRACE", -1):
            largefiles._prune_verified(str(self.dir))
        self.assertFalse(Path(first).exists())
        self.assertEqual((self.dir / "asset.bin").read_bytes(), PAYLOAD_B)
        self.assertEqual(
            [p.name for p in (self.dir / largefiles.VERIFIED_STORE).iterdir()],
            [hashlib.sha1(PAYLOAD_B).hexdigest()],
        )


if __name__ == "__main__":
    unittest.main()
