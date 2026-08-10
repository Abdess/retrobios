#!/usr/bin/env python3
"""Large-file cache downloads.

Two runs fetching the same asset used to stream into one shared scratch
path, interleaving their writes into a full-size file with mixed content
that then replaced the cache entry.
"""

from __future__ import annotations

import hashlib
import io
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
        self._urlopen = common.urllib.request.urlopen

    def tearDown(self):
        common.urllib.request.urlopen = self._urlopen

    def test_concurrent_fetches_do_not_mix(self):
        barrier = threading.Barrier(2, timeout=10)
        payloads = [PAYLOAD_A, PAYLOAD_B]
        index = iter(range(2))
        lock = threading.Lock()

        def fake_urlopen(req, timeout=None):
            with lock:
                i = next(index)
            return _SlowResponse(payloads[i], barrier)

        common.urllib.request.urlopen = fake_urlopen
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
        common.urllib.request.urlopen = lambda req, timeout=None: _SlowResponse(
            PAYLOAD_A
        )
        common.fetch_large_file("asset.bin", dest_dir=self.dir)
        leftovers = [f for f in os.listdir(self.dir) if f.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_no_scratch_file_survives_a_failed_fetch(self):
        def fail(req, timeout=None):
            raise urllib.error.URLError("offline")

        common.urllib.request.urlopen = fail
        self.assertIsNone(common.fetch_large_file("asset.bin", dest_dir=self.dir))
        self.assertEqual(os.listdir(self.dir), [])

    def test_hash_mismatch_leaves_no_scratch_file(self):
        common.urllib.request.urlopen = lambda req, timeout=None: _SlowResponse(
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

        common.urllib.request.urlopen = fail
        self.assertEqual(
            common.fetch_large_file("asset.bin", dest_dir=self.dir), str(cached)
        )

    def test_offline_cache_miss_never_opens_the_network(self):
        def fail(req, timeout=None):
            raise AssertionError("offline mode must not open the network")

        common.urllib.request.urlopen = fail
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

        common.urllib.request.urlopen = fail
        self.assertEqual(
            common.fetch_large_file(
                "asset.bin",
                dest_dir=self.dir,
                expected_sha1=hashlib.sha1(PAYLOAD_A).hexdigest(),
                offline=True,
            ),
            str(cached),
        )


if __name__ == "__main__":
    unittest.main()
