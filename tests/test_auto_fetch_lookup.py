"""auto_fetch.py looks a file up by its hash: Software Heritage answers by
content, and nothing it serves is kept unless every declared hash holds."""

from __future__ import annotations

import tests

import contextlib
import hashlib
import io
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from acquire import fetch, fetchtext

PAYLOAD = b"keyboard mcu"
SHA1 = hashlib.sha1(PAYLOAD).hexdigest()


class _Answer(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _serving(payloads: dict[str, bytes]):
    """An urlopen that answers the URLs it knows and 404s the others."""
    asked: list[str] = []

    def urlopen(request, timeout=None):
        url = request.full_url
        asked.append(url)
        for prefix, body in payloads.items():
            if url.startswith(prefix):
                return _Answer(body)
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

    return urlopen, asked


class SoftwareHeritageAnswersByContent(unittest.TestCase):
    def test_the_bytes_it_serves_are_kept_when_the_hash_holds(self):
        urlopen, asked = _serving({f"{fetch.SOFTWARE_HERITAGE}/sha1:{SHA1}/raw/": PAYLOAD})
        with mock.patch.object(fetch.upstream.urllib.request, "urlopen", urlopen):
            data = fetch.step3b_software_heritage({"name": "D8039HLC.rom", "sha1": SHA1}, [])
        self.assertEqual(data, PAYLOAD)
        self.assertEqual(asked, [f"{fetch.SOFTWARE_HERITAGE}/sha1:{SHA1}/raw/"])

    def test_other_bytes_under_the_hash_are_refused(self):
        urlopen, _asked = _serving({fetch.SOFTWARE_HERITAGE: b"something else"})
        with mock.patch.object(fetch.upstream.urllib.request, "urlopen", urlopen):
            data = fetch.step3b_software_heritage({"name": "x", "sha1": SHA1}, [])
        self.assertIsNone(data)

    def test_an_absent_file_is_not_counted_as_a_source_that_did_not_answer(self):
        urlopen, _asked = _serving({})
        with mock.patch.object(fetch.upstream.urllib.request, "urlopen", urlopen):
            found = fetch.search({"name": "x", "sha1": SHA1}, fetch.SHA1_SOURCES)
        self.assertEqual(found, fetch.SearchResult(None, None, ()))


class LookupBySha1(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.acquire = self.root / "tmp" / "acquire"

    def test_a_found_file_goes_to_tmp_acquire_never_to_bios(self):
        urlopen, _asked = _serving({f"{fetch.SOFTWARE_HERITAGE}/sha1:{SHA1}/raw/": PAYLOAD})
        with mock.patch.object(fetch.upstream.urllib.request, "urlopen", urlopen):
            [record] = fetch.lookup_sha1s([SHA1.upper()], {"files": {}},
                                          acquire_dir=self.acquire)
        self.assertEqual((record.outcome, record.source), ("found", "software_heritage"))
        self.assertEqual((self.acquire / SHA1).read_bytes(), PAYLOAD)
        self.assertFalse((self.root / "bios").exists())
        self.assertIn("found in Software Heritage", fetchtext.lookup_line(record))

    def test_the_default_folder_is_under_the_repository(self):
        from core.paths import REPO_ROOT

        self.assertEqual(fetch.ACQUIRE_DIR, REPO_ROOT / "tmp" / "acquire")

    def test_a_held_file_is_named_and_not_fetched(self):
        urlopen, asked = _serving({})
        db = {"files": {SHA1: {"path": "bios/Commodore/Amiga/x.rom"}}}
        with mock.patch.object(fetch.upstream.urllib.request, "urlopen", urlopen), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = fetchtext.report_lookups([SHA1], db, acquire_dir=self.acquire)
        self.assertEqual((code, asked), (0, []))
        self.assertIn("already held at bios/Commodore/Amiga/x.rom", out.getvalue())

    def test_nothing_found_and_a_malformed_hash_end_with_one(self):
        urlopen, _asked = _serving({})
        with mock.patch.object(fetch.upstream.urllib.request, "urlopen", urlopen), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            code = fetchtext.report_lookups([SHA1, "not-a-hash"], {"files": {}},
                                            acquire_dir=self.acquire)
        self.assertEqual(code, 1)
        self.assertEqual(out.getvalue(), f"  {SHA1}: not found\n")
        self.assertEqual(err.getvalue(), "  not-a-hash: not a sha1\n")


class PlatformSearchLines(unittest.TestCase):
    """The search returns records, the text module alone prints them."""

    def test_a_file_kept_out_of_bios_says_why_before_where_it_went(self):
        from acquire.placement import Placement

        record = fetch.FetchRecord(
            {"name": "neogeo.zip", "system": "snk-neogeo"}, "found", source="archive_org",
            placed=Placement("tmp/acquire/ab", kept_out=True, folders=("bios/A/", "bios/B/")))
        self.assertEqual(fetchtext.fetch_lines(record), [
            "    No single bios/ folder for snk-neogeo (bios/A/, bios/B/): kept out of bios/",
            "    [4] Found on archive.org, saved to: tmp/acquire/ab",
        ])

    def test_an_unanswered_source_makes_the_search_incomplete(self):
        record = fetch.FetchRecord({"name": "x", "system": "s"}, "incomplete",
                                   unanswered=("u: offline", "v: offline"))
        self.assertEqual(fetch.fetch_summary([record])["stats"]["errors"], 1)
        self.assertEqual(fetchtext.fetch_lines(record), [
            "    [5] Search incomplete, 2 source(s) did not answer (first: u: offline)"])


class AStalledOrLimitedSourceIsNoAnswer(unittest.TestCase):
    """A timeout during the read is a TimeoutError, not a URLError: it
    escaped every handler and ended the search for every remaining file.
    A 429 from Software Heritage was recorded unanswered at once."""

    def setUp(self):
        from core import upstream

        patcher = mock.patch.object(upstream, "_sleep", lambda _s: None)
        patcher.start()
        self.addCleanup(patcher.stop)
        upstream._exhausted_hosts.clear()
        self.addCleanup(upstream._exhausted_hosts.clear)

    def test_a_stalled_read_is_recorded_and_the_search_goes_on(self):
        class _Stalled(_Answer):
            def read(self, *_args):
                raise TimeoutError("timed out")

        def urlopen(request, timeout=None):
            return _Stalled()

        unanswered: list[str] = []
        with mock.patch.object(fetch.upstream.urllib.request, "urlopen", urlopen):
            self.assertIsNone(fetch.step3_search_public_repos(
                {"name": "x.bin", "sha1": SHA1}, unanswered))
        self.assertEqual(len(unanswered), len(fetch.PUBLIC_REPOS))

    def test_a_rate_limit_is_waited_out(self):
        answers = [urllib.error.HTTPError("u", 429, "Too Many Requests", {}, None), PAYLOAD]

        def urlopen(request, timeout=None):
            answer = answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return _Answer(answer)

        with mock.patch.object(fetch.upstream.urllib.request, "urlopen", urlopen):
            found = fetch.search({"name": "x", "sha1": SHA1}, fetch.SHA1_SOURCES)
        self.assertEqual(found, fetch.SearchResult(PAYLOAD, "software_heritage", ()))

    def test_the_destination_is_tried_when_the_name_is_too_large(self):
        asked: list[str] = []

        def urlopen(request, timeout=None):
            asked.append(request.full_url)
            if request.full_url.endswith("/sub/x.bin"):
                return _Answer(PAYLOAD)
            return _Answer(b"0" * 64)

        with mock.patch.object(fetch, "MAX_DOWNLOAD", 32), \
                mock.patch.object(fetch.upstream.urllib.request, "urlopen", urlopen):
            data = fetch.step3_search_public_repos(
                {"name": "x.bin", "destination": "sub/x.bin", "sha1": SHA1}, [])
        self.assertEqual(data, PAYLOAD)
        self.assertEqual(len(asked), 2)


class ArchiveOrgAnswersByHash(unittest.TestCase):
    """The platform search asked archive.org for the first item and then
    downloaded the platform's name from it: an item storing the dump under
    another path was a 404, and the file went to the issue asking the public
    for it while --sha1 found it."""

    def _archive(self):
        import json

        return _serving({
            "https://archive.org/advancedsearch.php": json.dumps(
                {"response": {"docs": [{"identifier": "psx-bios"}]}}).encode(),
            "https://archive.org/metadata/psx-bios/files": json.dumps(
                {"result": [{"name": "readme.txt", "sha1": "0" * 40},
                            {"name": "bios/SCPH1001.BIN", "sha1": SHA1}]}).encode(),
            "https://archive.org/download/psx-bios/bios/SCPH1001.BIN": PAYLOAD,
        })

    def test_the_member_is_found_by_its_sha1_whatever_its_name(self):
        urlopen, asked = self._archive()
        with mock.patch.object(fetch.upstream.urllib.request, "urlopen", urlopen):
            data = fetch.step4_search_archive_org(
                {"name": "scph1001.bin", "sha1": SHA1.upper()}, [])
        self.assertEqual(data, PAYLOAD)
        self.assertNotIn("https://archive.org/download/psx-bios/scph1001.bin", asked)

    def test_the_platform_search_and_the_sha1_search_agree(self):
        urlopen, _asked = self._archive()
        with mock.patch.object(fetch.upstream.urllib.request, "urlopen", urlopen):
            by_platform = fetch.step4_search_archive_org(
                {"name": "scph1001.bin", "sha1": SHA1}, [])
            by_sha1 = fetch.archive_org_by_sha1(SHA1, [])
        self.assertEqual((by_platform, by_sha1), (PAYLOAD, PAYLOAD))

    def test_a_declared_md5_still_has_to_hold(self):
        urlopen, _asked = self._archive()
        with mock.patch.object(fetch.upstream.urllib.request, "urlopen", urlopen):
            data = fetch.step4_search_archive_org(
                {"name": "scph1001.bin", "sha1": SHA1, "md5": "f" * 32}, [])
        self.assertIsNone(data)


class OptionalDatabase(unittest.TestCase):
    """auto_fetch --sha1 read a mistyped --db as an empty collection and asked
    Software Heritage for a file already held."""

    def setUp(self):
        self.cwd = os.getcwd()
        self.root = Path(tempfile.mkdtemp())
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.cwd)

    def test_the_default_may_be_absent(self):
        from core.paths import DB_FILE
        from model.database import load_optional_database

        self.assertIsNone(load_optional_database(DB_FILE))

    def test_a_named_database_must_exist(self):
        from model.database import DatabaseUnreadable, load_optional_database

        (self.root / "database.json").write_text('{"files": {}}')
        with self.assertRaisesRegex(DatabaseUnreadable, "Close match: database.json"):
            load_optional_database("databse.json")


if __name__ == "__main__":
    unittest.main()
