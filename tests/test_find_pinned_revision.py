"""A platform's pinned revision found in its upstream history.

RetroArch pins ScummVM's queen.tbl and FBNeo's hiscore.dat at revisions
today's upstream no longer carries, but the bytes are in the project's history.
"""

from __future__ import annotations

import tests

import hashlib
import unittest
from unittest import mock

from acquire import history
from core import upstream
from core import forgehttp


class ThePinnedRevisionIsInTheHistory(unittest.TestCase):
    def test_the_newest_matching_revision_is_returned(self):
        repo = upstream.parse_repo("https://github.com/scummvm/scummvm")
        blobs = {"c3": b"today", "c2": b"pinned", "c1": b"older"}

        def api(url, *_a, **_k):
            return [{"sha": s} for s in blobs] if "page=1" in url else []

        def fetch(url, *_a, **_k):
            return next(data for sha, data in blobs.items() if f"/{sha}/" in url)

        with mock.patch.object(upstream, "cached_api", api), mock.patch.object(forgehttp, "fetch_body", fetch):
            found = history.find_revision(
                repo, "dists/engine-data/queen.tbl",
                hashlib.md5(b"pinned").hexdigest(), "unused")
            missing = history.find_revision(
                repo, "dists/engine-data/queen.tbl", "0" * 32, "unused")
        self.assertEqual(found, ("c2", b"pinned"))
        self.assertIsNone(missing)


if __name__ == "__main__":
    unittest.main()
