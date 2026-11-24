"""install.py fetches lists and files over an unreliable network and says what failed in plain words."""
from __future__ import annotations

import tests
from tests import scratch_dir

import contextlib
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import time
import unittest
from types import SimpleNamespace
import unittest.mock
import urllib.error
from pathlib import Path

from tests.netguard import module_guard
from tests.installsupport import REPO_ROOT, install, reported, _FakeResponse


# No connection off the loopback and no card of the host reaches a test:
# the module fails at its end otherwise.
setUpModule, tearDownModule = module_guard("test_install_downloads")


class TestLocalCheckHashing(unittest.TestCase):
    """A file is read once, not once per declared digest."""

    def test_both_digests_come_from_one_read(self):
        tmp = scratch_dir(self)
        payload = b"BIOS PAYLOAD"
        (tmp / "boot.bin").write_bytes(payload)
        entry = {
            "dest": "boot.bin",
            "size": len(payload),
            "sha1": hashlib.sha1(payload).hexdigest(),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        calls = []
        real_digest = install._digest_file

        def recording(path, algorithms):
            calls.append(tuple(sorted(algorithms)))
            return real_digest(path, algorithms)

        install._digest_file = recording
        try:
            to_download, up_to_date, mismatched = install.check_local([entry], tmp)
        finally:
            install._digest_file = real_digest
        self.assertEqual((len(to_download), len(up_to_date), len(mismatched)), (0, 1, 0))
        self.assertEqual(calls, [("sha1", "sha256")], "file must be read once")

    def test_a_wrong_digest_still_lands_in_mismatched(self):
        tmp = scratch_dir(self)
        (tmp / "boot.bin").write_bytes(b"BIOS PAYLOAD")
        entry = {
            "dest": "boot.bin",
            "size": 12,
            "sha1": "0" * 40,
            "sha256": hashlib.sha256(b"BIOS PAYLOAD").hexdigest(),
        }
        _, up_to_date, mismatched = install.check_local([entry], tmp)
        self.assertEqual((len(up_to_date), len(mismatched)), (0, 1))


class FileListsAreRetried(unittest.TestCase):
    """The file list was fetched once with a 30 s timeout: one timeout on
    flaky Wi-Fi ended the run, while each file got three attempts."""

    def _fetch(self, outcomes):
        calls = []

        def urlopen(url, timeout=None):
            calls.append(url)
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return contextlib.nullcontext(io.BytesIO(outcome))

        with unittest.mock.patch.object(install.urllib.request, "urlopen", urlopen), \
                unittest.mock.patch.object(install.time, "sleep"), \
                unittest.mock.patch.object(install, "_read_limited_json",
                                           lambda resp, limit, label: json.loads(resp.read())):
            try:
                return install._fetch_json("https://x/list.json", 1000, "list"), calls
            except OSError as exc:
                return exc, calls

    def test_a_timeout_then_an_answer_succeeds(self):
        import urllib.error

        result, calls = self._fetch([urllib.error.URLError("timed out"), b'{"a": 1}'])
        self.assertEqual(result, {"a": 1})
        self.assertEqual(len(calls), 2)

    def test_a_404_is_not_retried(self):
        import urllib.error

        missing = urllib.error.HTTPError("https://x", 404, "Not Found", None, None)
        result, calls = self._fetch([missing])
        self.assertIs(result, missing)
        self.assertEqual(len(calls), 1)

    def test_a_sign_in_page_is_named(self):
        """A Wi-Fi sign-in page read as "invalid file list: Expecting value:
        line 1 column 1 (char 0)", with no cause and no next step."""
        page = io.BytesIO(b"<html>Sign in to Hotel WiFi</html>")
        page.headers = {}
        err = io.StringIO()
        with unittest.mock.patch.object(
                install.urllib.request, "urlopen",
                lambda url, timeout=None: contextlib.nullcontext(page)), \
                contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            reported(install.fetch_manifest, "retroarch")
        said = err.getvalue()
        self.assertIn("a Wi-Fi sign-in page or a cut download looks like this", said)
        self.assertIn("run the same command again", said)
        self.assertNotIn("Expecting value", said)

    def test_three_failures_end_with_advice(self):
        import urllib.error

        failures = [urllib.error.URLError("timed out")] * install.MAX_RETRIES
        err = io.StringIO()
        with unittest.mock.patch.object(install.urllib.request, "urlopen",
                                        side_effect=failures), \
                unittest.mock.patch.object(install.time, "sleep"), \
                contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
            reported(install.fetch_manifest, "retroarch")
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("HTTPS_PROXY", err.getvalue())
        self.assertIn(f"after {install.MAX_RETRIES} attempts", err.getvalue())


class ASilentServerIsBounded(unittest.TestCase):
    """A server that takes the connection and never answers held line mode
    93 s: three waits of 30 s for a first byte that never came."""

    def test_two_short_waits_then_the_reason(self):
        import socket
        import threading

        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        self.addCleanup(listener.close)
        held = []

        def accept():
            while True:
                try:
                    conn, _addr = listener.accept()
                except OSError:
                    return
                held.append(conn)

        threading.Thread(target=accept, daemon=True).start()
        self.addCleanup(lambda: [conn.close() for conn in held])
        port = listener.getsockname()[1]
        err = io.StringIO()
        start = time.monotonic()
        with unittest.mock.patch.object(install, "LIST_TIMEOUT", 0.5), \
                unittest.mock.patch.object(install, "_retry_delay", return_value=0), \
                unittest.mock.patch.dict(os.environ,
                                         {"RETROBIOS_BASE_URL": f"http://127.0.0.1:{port}"}), \
                contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            reported(install.fetch_manifest, "retroarch")
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 5)
        self.assertEqual(len(held), install.STALLED_ATTEMPTS)
        self.assertIn(f"after {install.STALLED_ATTEMPTS} attempts", err.getvalue())
        # The retry line counts the tries this failure gets: "(2/3)" promised
        # a third that never came.
        self.assertIn(f"(2/{install.STALLED_ATTEMPTS})", err.getvalue())
        self.assertNotIn(f"/{install.MAX_RETRIES})", err.getvalue())
        # A download keeps its own, longer wait between chunks.
        self.assertGreater(install.LIST_TIMEOUT, 1)


class TargetListFailureIsNotAnAnswer(unittest.TestCase):
    """A timeout is not 'no targets': it sent users to the full pack."""

    def test_unreachable_list_is_none(self):
        import urllib.error

        def boom(*args, **kwargs):
            raise urllib.error.URLError("timed out")

        with unittest.mock.patch.object(install.urllib.request, "urlopen", boom), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertIsNone(install.fetch_targets("retroarch"))

    def test_absent_list_is_empty(self):
        import urllib.error

        def missing(url, *args, **kwargs):
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

        with unittest.mock.patch.object(install.urllib.request, "urlopen", missing):
            self.assertEqual(install.fetch_targets("retroarch"), {})


class ACutFileListIsRetried(unittest.TestCase):
    """Wi-Fi dropped mid install/batocera.json: the short body parsed as an
    invalid file list, no retry, no network advice."""

    class _Response(io.BytesIO):
        def __init__(self, body: bytes, length: int):
            super().__init__(body)
            self.headers = {"Content-Length": str(length)}

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def test_the_second_attempt_succeeds(self):
        full = json.dumps({"a": 1}).encode()
        answers = iter([self._Response(full[:4], len(full)), self._Response(full, len(full))])
        with unittest.mock.patch.object(install.urllib.request, "urlopen",
                                        lambda *a, **k: next(answers)), \
                unittest.mock.patch.object(install.time, "sleep"):
            self.assertEqual(install._fetch_json("https://x/y.json", 1000, "manifest"), {"a": 1})

    def test_a_retry_is_announced(self):
        import contextlib

        full = json.dumps({"a": 1}).encode()
        answers = iter([self._Response(full[:4], len(full)), self._Response(full, len(full))])
        err = io.StringIO()
        with unittest.mock.patch.object(install.urllib.request, "urlopen",
                                        lambda *a, **k: next(answers)), \
                unittest.mock.patch.object(install.time, "sleep"), \
                contextlib.redirect_stderr(err):
            install._fetch_json("https://x/y.json", 1000, "file list")
        self.assertIn("trying again (2/3)", err.getvalue())

    def test_a_short_body_is_a_connection_error(self):
        with self.assertRaises(ConnectionError):
            install._read_limited_json(self._Response(b'{"a"', 10), 1000, "manifest")


class AChunkedCutIsADownloadFailure(unittest.TestCase):
    """Behind a proxy that re-encodes as chunked, a cut raised
    http.client.IncompleteRead, which no handler caught: the run ended on a
    traceback with no summary."""

    def test_the_file_fails_and_the_run_goes_on(self):
        import http.client

        class Cut:
            headers = {}
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self, *_args):
                raise http.client.IncompleteRead(b"abc", 10)

        entry = {"dest": "a.bin", "repo_path": "bios/a.bin", "size": 10,
                 "sha1": "0" * 40, "sha256": "0" * 64}
        with unittest.mock.patch.object(install.urllib.request, "urlopen",
                                        lambda *a, **k: Cut()), \
                unittest.mock.patch.object(install, "_retry_delay", return_value=0):
            dest, ok, reason = install._download_one(entry, scratch_dir(self))
        self.assertFalse(ok)
        self.assertEqual(reason, "the connection was cut")
        self.assertIsInstance(reason, install.NetworkReason)


class TheProgressLineFitsTheTerminal(unittest.TestCase):
    """At 80 columns the 94-100 column line wrapped, and every redraw left
    a ghost line behind."""

    def test_each_width(self):
        import os as _os

        for columns in (40, 60, 80, 120):
            with self.subTest(columns=columns):
                out = io.StringIO()
                term = install.Terminal(out)
                term.live = True
                progress = install.Progress(5865, 2_300_000_000, term)
                progress.bytes = 1_000_000_000
                progress.files = 5000
                with unittest.mock.patch.object(
                    install.shutil, "get_terminal_size",
                    return_value=_os.terminal_size((columns, 24)),
                ):
                    progress._draw()
                line = out.getvalue().split("\033[K")[-1]
                self.assertLess(len(line), columns)
                self.assertIn("%", line)


class AResumedCopyIsNotSpeed(unittest.TestCase):
    """The live line divided every byte by the run's time, the 3 GB a
    resumed partial copy already held included: 2.5 GB/s and 0:00 left on a
    1 MB/s link."""

    def test_speed_counts_only_what_this_run_fetched(self):
        import os as _os

        out = io.StringIO()
        term = install.Terminal(out)
        term.live = True
        progress = install.Progress(1, 4_000_000_000, term)
        # Ten seconds exactly: read from the clock, a slow runner added a few
        # milliseconds and moved the last digit of the speed.
        progress.elapsed = lambda: 10.0
        progress.bytes = 3_000_000_000 + 10_000_000
        progress.resumed = 3_000_000_000
        with unittest.mock.patch.object(
            install.shutil, "get_terminal_size",
            return_value=_os.terminal_size((120, 24)),
        ):
            progress._draw()
        line = out.getvalue()
        self.assertIn(f"{install.format_size(1_000_000)}/s", line)
        self.assertNotIn("0:00 left", line)


class APartialIsClosedBeforeItIsDeleted(unittest.TestCase):
    """Windows refuses to delete an open file: a resumed partial copy whose
    hash no longer matched was unlinked with its handle still open, and the
    PermissionError ended the run."""

    def test_the_source_closes_first(self):
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        branch = source[source.index("        except _Corrupt:"):]
        branch = branch[:branch.index("delay = 0.0")]
        self.assertLess(branch.index("partial.close()"), branch.index("tmp_path.unlink()"))


class AMissingFileListNamesTheRef(unittest.TestCase):
    """A 404 on the manifest said three attempts were made and to check the
    connection and proxy, but it was asked once, and the cause is the ref."""

    def _run(self, ref: str) -> str:
        error = install.urllib.error.HTTPError("u", 404, "Not Found", None, None)
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_REF": ref,
                                                   "RETROBIOS_BASE_URL": ""}), \
                unittest.mock.patch.object(install, "_fetch_json", side_effect=error), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit):
            reported(install.fetch_manifest, "retroarch")
        return err.getvalue()

    def test_a_pinned_tag_is_named(self):
        text = self._run("v2020.01.01")
        self.assertIn("RETROBIOS_REF=v2020.01.01", text)
        self.assertNotIn("attempts", text)
        self.assertNotIn("proxy", text)

    def test_the_default_ref_is_not_blamed_on_the_network(self):
        text = self._run(install.DEFAULT_RELEASE_REF)
        self.assertIn("No file list for retroarch", text)
        self.assertNotIn("proxy", text)


def _sharing_violation() -> PermissionError:
    exc = PermissionError(13, "The process cannot access the file")
    exc.winerror = 32
    return exc


class ACompletePartialIsHandedOffOnWindows(unittest.TestCase):
    """Windows renames no open file, so the run that verified a large copy
    released its lock before the rename. A second run claimed the copy in
    that moment, found it complete and truncated it, and the first run's
    rename failed with a sharing violation reported as "folder not
    writable"."""

    PAYLOAD = bytes(range(256)) * 200
    ENTRY = {
        "dest": "big.bin", "repo_path": "bios/big.bin", "size": len(PAYLOAD),
        "sha256": hashlib.sha256(PAYLOAD).hexdigest(),
    }

    def _run(self, tmp: Path, seen: list[int]):
        part = tmp / ".big.bin.part"

        def urlopen(request, timeout=None):
            seen.append(part.stat().st_size if part.exists() else -1)
            return _FakeResponse(self.PAYLOAD)

        with unittest.mock.patch.object(install, "RESUME_FROM_SIZE", 1024), \
                unittest.mock.patch.object(install, "_NO_RENAME_WHILE_OPEN", True), \
                unittest.mock.patch.object(install.urllib.request, "urlopen", urlopen):
            return install._download_one(dict(self.ENTRY), tmp)

    def test_the_other_runs_copy_is_left_whole(self):
        tmp = scratch_dir(self)
        (tmp / ".big.bin.part").write_bytes(self.PAYLOAD)
        seen: list[int] = []
        self.assertEqual(self._run(tmp, seen), ("big.bin", True, ""))
        # The download ran while the complete copy was still whole.
        self.assertEqual(seen, [len(self.PAYLOAD)])
        self.assertEqual((tmp / "big.bin").read_bytes(), self.PAYLOAD)
        # Nothing held it afterwards: it was a leftover, now removed.
        self.assertFalse((tmp / ".big.bin.part").exists())

    def test_the_rename_waits_for_the_other_run_to_let_go(self):
        tmp = scratch_dir(self)
        source = tmp / "copy"
        source.write_bytes(b"x")
        real_replace = os.replace
        calls = []

        def replace(src, dst):
            calls.append(src)
            if len(calls) < 3:
                raise _sharing_violation()
            return real_replace(src, dst)

        with unittest.mock.patch.object(install.os, "replace", replace), \
                unittest.mock.patch.object(install.time, "sleep"):
            install._replace_released(source, tmp / "dest", {})
        self.assertEqual(len(calls), 3)
        self.assertEqual((tmp / "dest").read_bytes(), b"x")

    def test_a_copy_the_other_run_placed_counts_once_verified(self):
        tmp = scratch_dir(self)
        dest = tmp / "dest"
        dest.write_bytes(self.PAYLOAD)
        expected = {"sha256": self.ENTRY["sha256"]}
        install._replace_released(tmp / "gone", dest, expected)
        dest.write_bytes(b"other bytes")
        with self.assertRaises(FileNotFoundError):
            install._replace_released(tmp / "gone", dest, expected)

    def test_a_sharing_violation_is_no_refused_folder(self):
        self.assertFalse(install._write_refused(_sharing_violation()))
        self.assertTrue(install._write_refused(PermissionError(13, "denied")))


class ANetworkFailureNamesTheNetwork(unittest.TestCase):
    """Every transfer cut by the connection ended on "Location that was being
    written to" and "once that is resolved", naming the folder and nothing
    about the connection or the proxy."""

    def _fail(self, error: BaseException) -> str:
        def urlopen(*_args, **_kwargs):
            raise error

        entry = {"dest": "a.bin", "repo_path": "bios/a.bin", "size": 10,
                 "sha256": "0" * 64}
        with unittest.mock.patch.object(install.urllib.request, "urlopen", urlopen), \
                unittest.mock.patch.object(install, "_retry_delay", return_value=0):
            _dest, ok, reason = install._download_one(entry, scratch_dir(self))
        self.assertFalse(ok)
        return reason

    def test_cuts_and_refusals_are_network_failures(self):
        import http.client
        import socket

        for error in (
            urllib.error.URLError(socket.gaierror(-2, "Name or service not known")),
            http.client.IncompleteRead(b"abc", 10),
            ConnectionResetError(104, "Connection reset by peer"),
            socket.timeout("timed out"),
            urllib.error.HTTPError("u", 503, "Service Unavailable", None, None),
        ):
            with self.subTest(error=error):
                self.assertIsInstance(self._fail(error), install.NetworkReason)

    def test_a_full_disk_and_a_missing_file_are_not(self):
        import errno

        for error in (OSError(errno.ENOSPC, "No space left on device"),
                      urllib.error.HTTPError("u", 404, "Not Found", None, None)):
            with self.subTest(error=error):
                self.assertNotIsInstance(self._fail(error), install.NetworkReason)

    def test_a_bios_file_follows_the_shared_retry_rule(self):
        """A 404 on a BIOS file was asked three times, the file list once."""
        cases = ((urllib.error.HTTPError("u", 404, "Not Found", None, None), 1),
                 (urllib.error.HTTPError("u", 503, "Service Unavailable", None, None),
                  install.MAX_RETRIES))
        for error, expected in cases:
            calls: list = []

            def urlopen(*_args, _error=error, _calls=calls, **_kwargs):
                _calls.append(1)
                raise _error

            entry = {"dest": "a.bin", "repo_path": "bios/a.bin", "size": 10,
                     "sha256": "0" * 64}
            with self.subTest(code=error.code), \
                    unittest.mock.patch.object(install.urllib.request, "urlopen", urlopen), \
                    unittest.mock.patch.object(install, "_retry_delay", return_value=0):
                _dest, ok, _reason = install._download_one(entry, scratch_dir(self))
                self.assertFalse(ok)
                self.assertEqual(len(calls), expected)

    def test_the_summary_points_at_the_connection(self):
        failures = [("a.bin", install.NetworkReason("timed out")),
                    ("b.bin", install.NetworkReason("Connection reset by peer"))]
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as raised:
            install._report_outcome([Path("/bios")], 0, 0, 2, 0, False,
                                    details=install.OutcomeDetails(failures=failures))
        self.assertEqual(raised.exception.code, 2)
        text = out.getvalue()
        self.assertIn("HTTPS_PROXY", text)
        self.assertIn("BIOS folder: /bios", text)
        self.assertNotIn("being written to", text)


class AnHttpErrorNamesItsAddress(unittest.TestCase):
    """A file the server answered 404 for ended on "HTTP 404" alone: no
    address, no cause, and a mirror chosen with RETROBIOS_BASE_URL went
    unnamed, as it did behind a NETWORK failure of that mirror."""

    def _said(self, failures: list, base_url: str = "") -> str:
        out = io.StringIO()
        env = {"RETROBIOS_BASE_URL": base_url} if base_url else {}
        with unittest.mock.patch.dict(os.environ, env), contextlib.redirect_stdout(out), \
                self.assertRaises(SystemExit) as raised:
            install._report_outcome([Path("/bios")], 0, 0, len(failures), 0, False,
                                    details=install.OutcomeDetails(failures=failures))
        self.assertEqual(raised.exception.code, 2)
        return " ".join(out.getvalue().split())

    def _reason(self, kind: type, words: str, url: str) -> str:
        reason = kind(words)
        reason.url = url
        return reason

    def test_the_address_and_the_cause_are_said(self):
        url = "https://raw.githubusercontent.com/Abdess/retrobios/main/bios/a.bin"
        failures = [("a.bin", self._reason(install.HttpReason, "HTTP 404", url)),
                    ("b.bin", self._reason(install.HttpReason, "HTTP 404", url + "x"))]
        with unittest.mock.patch.dict(os.environ):
            os.environ.pop("RETROBIOS_BASE_URL", None)
            text = self._said(failures)
        self.assertIn(f"The server answered HTTP 404 for {url} (and 1 other file).", text)
        self.assertIn("running again changes nothing", text)
        self.assertIn("BIOS folder: /bios", text)
        self.assertNotIn("RETROBIOS_BASE_URL", text)

    def test_a_mirror_named_in_the_environment_is_said(self):
        mirror = "http://127.0.0.1:18766"
        for kind, words in ((install.HttpReason, "HTTP 404"),
                            (install.NetworkReason, "the connection timed out")):
            with self.subTest(kind=kind.__name__):
                text = self._said([("a.bin", self._reason(kind, words, f"{mirror}/a.bin"))],
                                  base_url=mirror)
                self.assertIn("RETROBIOS_BASE_URL is set in this environment", text)

    def test_the_download_records_the_address(self):
        error = urllib.error.HTTPError("https://x/bios/a.bin", 404, "Not Found", None, None)
        reason = ANetworkFailureNamesTheNetwork._fail(self, error)
        self.assertIsInstance(reason, install.HttpReason)
        self.assertTrue(reason.url.endswith("/bios/a.bin"), reason.url)


class NetworkFailuresInPlainWords(unittest.TestCase):
    """Offline, the run printed "[Errno -2] Name or service not known". A
    beginner needs "no internet connection", and the raw text only under
    --verbose."""

    def _words(self, reason: BaseException, **kwargs) -> tuple[str, str]:
        return install.network_words(urllib.error.URLError(reason), **kwargs)

    def test_the_common_failures(self):
        import ssl

        cases = (
            (socket.gaierror(-2, "Name or service not known"), "no internet connection"),
            (socket.timeout("timed out"), "timed out"),
            (ConnectionRefusedError(111, "Connection refused"), "refused the connection"),
            (OSError(101, "Network is unreachable"), "no internet connection"),
            (ssl.SSLCertVerificationError(1, "certificate verify failed"),
             "certificate was rejected"),
        )
        with unittest.mock.patch.object(install, "_ca_bundle_found", return_value=True):
            for reason, words in cases:
                with self.subTest(reason=reason):
                    code, text = self._words(reason)
                    self.assertEqual(code, "network")
                    self.assertIn(words, text)
                    self.assertNotIn("Errno", text)

    def test_verbose_keeps_the_raw_text(self):
        _code, text = self._words(socket.gaierror(-2, "Name or service not known"),
                                  verbose=True)
        self.assertIn("Name or service not known", text)

    def test_a_clock_in_the_past_is_named(self):
        """A handheld with no clock battery boots in 1980, and every
        certificate then reads as not yet valid."""
        import datetime
        import ssl

        error = ssl.SSLCertVerificationError(1, "certificate is not yet valid")
        with unittest.mock.patch.object(install, "_ca_bundle_found", return_value=True):
            code, text = self._words(error, today=datetime.date(1980, 1, 1))
            self.assertEqual(code, "clock")
            self.assertIn("The clock reads 1980-01-01", text)
            self.assertIn("set the date", text)
            code, _text = self._words(error, today=install.CLOCK_FLOOR)
            self.assertEqual(code, "network")

    def test_no_certificate_list_names_ssl_cert_file(self):
        import ssl

        error = ssl.SSLCertVerificationError(1, "unable to get local issuer certificate")
        with unittest.mock.patch.object(install, "_ca_bundle_found", return_value=False):
            code, text = self._words(error)
        self.assertEqual(code, "no_ca")
        self.assertIn("SSL_CERT_FILE", text)

    def test_a_certificate_list_is_looked_for_where_openssl_and_systems_keep_it(self):
        root = scratch_dir(self)
        bundle = root / "cert.pem"
        paths = SimpleNamespace(cafile=str(root / "none.pem"), capath=str(root / "none"),
                                openssl_cafile=str(root / "no.pem"),
                                openssl_capath=str(root / "no"))
        with unittest.mock.patch("ssl.get_default_verify_paths", return_value=paths), \
                unittest.mock.patch.object(install, "CA_BUNDLES", ()), \
                unittest.mock.patch.dict(os.environ, {"SSL_CERT_FILE": "", "SSL_CERT_DIR": ""}):
            self.assertFalse(install._ca_bundle_found())
            with unittest.mock.patch.object(install, "CA_BUNDLES", (str(bundle),)):
                self.assertFalse(install._ca_bundle_found())
                bundle.write_text("x")
                self.assertTrue(install._ca_bundle_found())

    def test_a_file_list_out_of_reach_by_name_says_so(self):
        env = {**os.environ, "RETROBIOS_BASE_URL": "https://retrobios-nohost.invalid",
               "HOME": str(scratch_dir(self))}
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retroarch",
             "--dest", str(scratch_dir(self)), "--check"],
            env=env, capture_output=True, text=True, timeout=120, check=False,
            stdin=subprocess.DEVNULL,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no internet connection", proc.stderr)
        self.assertNotIn("Errno", proc.stderr)


if __name__ == "__main__":
    unittest.main()
