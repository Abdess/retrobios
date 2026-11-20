"""A component manifest that could not be read is not a missing one.

The RetroDECK scraper printed "skip" on any HTTP or network error and wrote
retrodeck.yml without that component: a 503 on pcsx2's manifest removed the
PS2 BIOS and the pcsx2 standalone core, exit code 0.
"""

from __future__ import annotations

import tests

import io
import json
import unittest
import urllib.error
from unittest import mock

from scripts.scraper.retrodeck_scraper import Scraper

TREE = {"tree": [{"path": "pcsx2", "type": "tree"}, {"path": "ppsspp", "type": "tree"}]}


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _opener(failure):
    def urlopen(req, timeout=0):
        url = req.full_url
        if "/commits/" in url:
            return _Response(json.dumps({"sha": "a" * 40}).encode())
        if "api.github.com" in url:
            return _Response(json.dumps(TREE).encode())
        if "pcsx2" in url and failure is not None:
            raise failure
        return _Response(json.dumps({"ppsspp": {"bios": []}}).encode())
    return urlopen


class ManifestErrors(unittest.TestCase):
    def fetch(self, failure):
        # A 503 is retried after a wait: the waits are skipped, not the retries.
        with mock.patch("urllib.request.urlopen", _opener(failure)), \
                mock.patch("time.sleep"):
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

    def test_the_tree_and_files_are_read_at_one_commit(self):
        seen = []
        opener = _opener(None)

        def recording(req, timeout=0):
            seen.append(req.full_url)
            return opener(req, timeout)

        with mock.patch("urllib.request.urlopen", recording):
            Scraper()._fetch_remote_manifests()
        reads = [url for url in seen if "/commits/" not in url]
        self.assertTrue(reads)
        self.assertTrue(all("a" * 40 in url for url in reads), reads)

    def test_a_truncated_tree_stops_the_scrape(self):
        TREE["truncated"] = True
        self.addCleanup(TREE.pop, "truncated")
        with self.assertRaises(RuntimeError):
            self.fetch(None)



class ManifestMd5(unittest.TestCase):
    def test_a_string_or_a_list_gives_the_valid_values(self):
        from scripts.scraper.retrodeck_scraper import _entry_md5

        md5 = "0123456789abcdef0123456789ABCDEF"
        self.assertEqual(_entry_md5(md5), md5.lower())
        self.assertEqual(_entry_md5([md5, "", "not an md5", md5]), md5.lower())
        self.assertEqual(_entry_md5(""), "")
        self.assertEqual(_entry_md5(None), "")

    def test_a_value_of_another_type_is_refused(self):
        from scripts.scraper.retrodeck_scraper import _entry_md5

        with self.assertRaises(ValueError):
            _entry_md5([1])


if __name__ == "__main__":
    unittest.main()
