"""A component manifest that could not be read is not a missing one.

The RetroDECK scraper printed "skip" on any HTTP or network error and wrote
retrodeck.yml without that component: a 503 on pcsx2's manifest removed the
PS2 BIOS and the pcsx2 standalone core, exit code 0.
"""

from __future__ import annotations

import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from scripts.scraper.retrodeck_scraper import Scraper  # noqa: E402

TREE = {"tree": [{"path": "pcsx2", "type": "tree"}, {"path": "ppsspp", "type": "tree"}]}


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _opener(failure):
    def urlopen(req, timeout=0):
        url = req.full_url
        if "api.github.com" in url:
            return _Response(json.dumps(TREE).encode())
        if "pcsx2" in url and failure is not None:
            raise failure
        return _Response(json.dumps({"ppsspp": {"bios": []}}).encode())
    return urlopen


class ManifestErrors(unittest.TestCase):
    def fetch(self, failure):
        with mock.patch("urllib.request.urlopen", _opener(failure)):
            return Scraper()._fetch_remote_manifests()

    def test_a_server_error_stops_the_scrape(self):
        error = urllib.error.HTTPError("u", 503, "unavailable", {}, None)
        with self.assertRaises(ConnectionError):
            self.fetch(error)

    def test_a_dropped_connection_stops_the_scrape(self):
        with self.assertRaises(ConnectionError):
            self.fetch(urllib.error.URLError("reset"))

    def test_a_404_is_a_component_without_a_manifest(self):
        error = urllib.error.HTTPError("u", 404, "not found", {}, None)
        self.assertEqual([name for name, _ in self.fetch(error)], ["ppsspp"])

    def test_a_truncated_tree_stops_the_scrape(self):
        TREE["truncated"] = True
        self.addCleanup(TREE.pop, "truncated")
        with self.assertRaises(ConnectionError):
            self.fetch(None)


if __name__ == "__main__":
    unittest.main()
