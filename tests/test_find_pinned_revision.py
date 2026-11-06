"""A platform's pinned revision found in its upstream history.

RetroArch pins ScummVM's queen.tbl and FBNeo's hiscore.dat at revisions
today's upstream no longer carries, but the bytes are in the project's history.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import find_pinned_revision  # noqa: E402
import upstream  # noqa: E402


class ThePinnedRevisionIsInTheHistory(unittest.TestCase):
    def test_the_newest_matching_revision_is_returned(self):
        repo = upstream.parse_repo("https://github.com/scummvm/scummvm")
        blobs = {"c3": b"today", "c2": b"pinned", "c1": b"older"}

        def api(url, *_a, **_k):
            return [{"sha": s} for s in blobs] if "page=1" in url else []

        def fetch(url, *_a, **_k):
            return next(data for sha, data in blobs.items() if f"/{sha}/" in url)

        with mock.patch.object(upstream, "_api", api), mock.patch.object(upstream, "_fetch", fetch):
            found = find_pinned_revision.find_revision(
                repo, "dists/engine-data/queen.tbl",
                hashlib.md5(b"pinned").hexdigest(), "unused")
            missing = find_pinned_revision.find_revision(
                repo, "dists/engine-data/queen.tbl", "0" * 32, "unused")
        self.assertEqual(found, ("c2", b"pinned"))
        self.assertIsNone(missing)


if __name__ == "__main__":
    unittest.main()
