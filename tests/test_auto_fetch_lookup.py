"""auto_fetch.py looks a file up by its hash: Software Heritage answers by
content, and nothing it serves is kept unless every declared hash holds."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import hashlib
import io
import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import auto_fetch  # noqa: E402

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
        urlopen, asked = _serving({f"{auto_fetch.SOFTWARE_HERITAGE}/sha1:{SHA1}/raw/": PAYLOAD})
        with mock.patch.object(auto_fetch.urllib.request, "urlopen", urlopen):
            data = auto_fetch.step3b_software_heritage({"name": "D8039HLC.rom", "sha1": SHA1})
        self.assertEqual(data, PAYLOAD)
        self.assertEqual(asked, [f"{auto_fetch.SOFTWARE_HERITAGE}/sha1:{SHA1}/raw/"])

    def test_other_bytes_under_the_hash_are_refused(self):
        urlopen, _asked = _serving({auto_fetch.SOFTWARE_HERITAGE: b"something else"})
        with mock.patch.object(auto_fetch.urllib.request, "urlopen", urlopen):
            data = auto_fetch.step3b_software_heritage({"name": "x", "sha1": SHA1})
        self.assertIsNone(data)

    def test_an_absent_file_is_not_counted_as_a_source_that_did_not_answer(self):
        urlopen, _asked = _serving({})
        auto_fetch._UNANSWERED.clear()
        with mock.patch.object(auto_fetch.urllib.request, "urlopen", urlopen):
            self.assertIsNone(auto_fetch.step3b_software_heritage({"name": "x", "sha1": SHA1}))
        self.assertEqual(auto_fetch._UNANSWERED, [])


class LookupBySha1(unittest.TestCase):
    def setUp(self):
        self.cwd = os.getcwd()
        self.root = Path(tempfile.mkdtemp())
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.cwd)

    def test_a_found_file_goes_to_tmp_acquire_never_to_bios(self):
        urlopen, _asked = _serving({f"{auto_fetch.SOFTWARE_HERITAGE}/sha1:{SHA1}/raw/": PAYLOAD})
        with mock.patch.object(auto_fetch.urllib.request, "urlopen", urlopen), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = auto_fetch.lookup_sha1s([SHA1.upper()], {"files": {}})
        self.assertEqual(code, 0)
        self.assertEqual((self.root / "tmp" / "acquire" / SHA1).read_bytes(), PAYLOAD)
        self.assertFalse((self.root / "bios").exists())
        self.assertIn("found in Software Heritage", out.getvalue())

    def test_a_held_file_is_named_and_not_fetched(self):
        urlopen, asked = _serving({})
        db = {"files": {SHA1: {"path": "bios/Commodore/Amiga/x.rom"}}}
        with mock.patch.object(auto_fetch.urllib.request, "urlopen", urlopen), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = auto_fetch.lookup_sha1s([SHA1], db)
        self.assertEqual((code, asked), (0, []))
        self.assertIn("already held at bios/Commodore/Amiga/x.rom", out.getvalue())

    def test_nothing_found_and_a_malformed_hash_end_with_one(self):
        urlopen, _asked = _serving({})
        with mock.patch.object(auto_fetch.urllib.request, "urlopen", urlopen), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            code = auto_fetch.lookup_sha1s([SHA1, "not-a-hash"], {"files": {}})
        self.assertEqual(code, 1)
        self.assertIn(f"{SHA1}: not found", out.getvalue())
        self.assertIn("not-a-hash: not a sha1", err.getvalue())


if __name__ == "__main__":
    unittest.main()
