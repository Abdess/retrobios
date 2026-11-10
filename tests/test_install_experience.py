"""What the one-liner shows and how it recovers.

A live progress line with speed and time left, a plan before a large
download, a dry run, a quiet mode, a version, a pause between retries that
honours Retry-After, and large files that resume where they stopped.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import errno
import hashlib
import http.server
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import install  # noqa: E402
from test_install_selection import FakeRepository  # noqa: E402

PAYLOAD = bytes(range(256)) * 400  # 102400 bytes


class _RangeHandler(http.server.BaseHTTPRequestHandler):
    """Serves PAYLOAD with Range support and fails first when asked to."""

    ranges: list[str] = []
    fail_first: list[int] = []

    def log_message(self, *args) -> None:  # noqa: D102
        pass

    def do_GET(self) -> None:  # noqa: N802, D102
        if self.fail_first:
            code = self.fail_first.pop(0)
            self.send_response(code)
            self.send_header("Retry-After", "0")
            self.end_headers()
            return
        header = self.headers.get("Range")
        self.ranges.append(header or "")
        start = 0
        if header and header.startswith("bytes="):
            start = int(header[6:].split("-")[0])
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{len(PAYLOAD) - 1}/{len(PAYLOAD)}")
        else:
            self.send_response(200)
        body = PAYLOAD[start:]
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Server:
    def __enter__(self):
        _RangeHandler.ranges = []
        _RangeHandler.fail_first = []
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _RangeHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        port = self.httpd.server_address[1]
        self.patch = mock.patch.object(install, "RAW_FILE_URL", f"http://127.0.0.1:{port}/{{path}}")
        self.patch.start()
        return self

    def __exit__(self, *exc):
        self.patch.stop()
        self.httpd.shutdown()
        self.httpd.server_close()


ENTRY = {
    "dest": "big.bin", "repo_path": "bios/big.bin", "size": len(PAYLOAD),
    "sha256": hashlib.sha256(PAYLOAD).hexdigest(),
}


class LargeFilesResume(unittest.TestCase):
    def test_a_partial_copy_is_completed_with_a_range_request(self):
        with _Server(), tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(install, "RESUME_FROM_SIZE", 1024):
            part = Path(tmp) / ".big.bin.part"
            part.write_bytes(PAYLOAD[:40000])
            dest, ok, reason = install._download_one(dict(ENTRY), Path(tmp))
            self.assertEqual((dest, ok, reason), ("big.bin", True, ""))
            self.assertEqual((Path(tmp) / "big.bin").read_bytes(), PAYLOAD)
            self.assertEqual(_RangeHandler.ranges, ["bytes=40000-"])
            self.assertFalse(part.exists())

    def test_a_small_file_starts_over(self):
        with _Server(), tempfile.TemporaryDirectory() as tmp:
            dest, ok, _ = install._download_one(dict(ENTRY), Path(tmp))
            self.assertTrue(ok)
            self.assertEqual(_RangeHandler.ranges, [""])

    @unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
    def test_a_link_at_the_partial_name_is_never_written_through(self):
        with _Server(), tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(install, "RESUME_FROM_SIZE", 1024):
            victim = Path(tmp) / "victim.txt"
            victim.write_bytes(b"keep me")
            part = Path(tmp) / "bios" / ".big.bin.part"
            part.parent.mkdir()
            part.symlink_to(victim)
            dest, ok, _ = install._download_one(dict(ENTRY), Path(tmp) / "bios")
            self.assertTrue(ok)
            self.assertEqual(victim.read_bytes(), b"keep me")
            final = Path(tmp) / "bios" / "big.bin"
            self.assertFalse(final.is_symlink())
            self.assertEqual(final.read_bytes(), PAYLOAD)
            self.assertEqual(_RangeHandler.ranges, [""])


class TwoRunsOneFolder(unittest.TestCase):
    """Two installs into one BIOS folder appended to the same partial copy:
    each hashed the other's bytes and one renamed a file still growing."""

    @unittest.skipIf(os.name == "nt", "flock semantics")
    def test_a_partial_held_by_another_run_is_left_alone(self):
        with _Server(), tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(install, "RESUME_FROM_SIZE", 1024):
            part = Path(tmp) / ".big.bin.part"
            part.write_bytes(PAYLOAD[:40000])
            other = install._claim_partial(part)
            self.assertIsNotNone(other)
            try:
                dest, ok, reason = install._download_one(dict(ENTRY), Path(tmp))
                self.assertEqual((ok, reason), (True, ""))
                self.assertEqual((Path(tmp) / "big.bin").read_bytes(), PAYLOAD)
                self.assertEqual(part.read_bytes(), PAYLOAD[:40000])
                self.assertEqual(_RangeHandler.ranges, [""])
                self.assertIsNone(install._claim_partial(part))
            finally:
                other.close()
            self.assertIsNotNone(install._claim_partial(part))


class APartialRenamedBeforeTheLock(unittest.TestCase):
    """Open and lock are two steps. The run holding the partial could finish
    in between, rename it into place and release it: the second run then
    locked the installed BIOS, took it for a finished partial and truncated it."""

    @unittest.skipIf(os.name == "nt", "flock semantics")
    def test_the_installed_file_is_not_claimed(self):
        import fcntl

        with tempfile.TemporaryDirectory() as tmp:
            part = Path(tmp) / ".big.bin.part"
            final = Path(tmp) / "big.bin"
            part.write_bytes(PAYLOAD)
            real_flock = fcntl.flock

            def finish_first(fd, op):
                os.replace(part, final)
                return real_flock(fd, op)

            with mock.patch.object(fcntl, "flock", finish_first):
                claimed = install._claim_partial(part)
            self.assertIsNone(claimed)
            self.assertEqual(final.read_bytes(), PAYLOAD)


class InstalledFileModes(unittest.TestCase):
    """A file came out 0600, the mode of the temporary it was written to: run
    with sudo for a root-owned BIOS folder, the emulator's own user could not
    read it, and RetroDECK's pico8 and vox launchers were never executable."""

    def _mode(self, entry: dict) -> int:
        with _Server(), tempfile.TemporaryDirectory() as tmp:
            dest, ok, _ = install._download_one(dict(entry), Path(tmp))
            self.assertTrue(ok)
            return (Path(tmp) / dest).stat().st_mode & 0o777

    def test_the_umask_decides_as_for_any_new_file(self):
        umask = os.umask(0o022)
        try:
            self.assertEqual(self._mode(ENTRY), 0o644)
            self.assertEqual(self._mode({**ENTRY, "executable": True}), 0o755)
        finally:
            os.umask(umask)


class ProgramsAreMarked(unittest.TestCase):
    """The manifest says which files are programs, read from their header:
    the git mode cannot, hundreds of MAME archives carrying an execute bit."""

    def test_header_decides(self):
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import generate_pack

        with tempfile.TemporaryDirectory() as tmp:
            for data, expected in ((b"\x7fELF\x02", True), (b"#!/bin/sh\n", True),
                                   (b"PK\x03\x04", False), (b"", False)):
                path = Path(tmp) / "f"
                path.write_bytes(data)
                with self.subTest(head=data):
                    self.assertEqual(generate_pack._is_program(str(path)), expected)

    def test_retrodeck_launchers_are_executable(self):
        manifest = json.loads((REPO_ROOT / "install" / "retrodeck.json").read_text())
        launchers = [f for f in manifest["files"]
                     if f["dest"].endswith(("pico-8/pico8", "voxatron/vox"))]
        if not launchers:
            self.skipTest("no launcher in the RetroDECK manifest")
        for entry in launchers:
            with self.subTest(dest=entry["dest"]):
                self.assertIs(entry.get("executable"), True)


class ManifestHashesMatchTheScan(unittest.TestCase):
    """A manifest entry's sha1 is checked against the database scan of the
    same path: under load this host hashed a 252 MB DSi NAND to a sha1 no
    file holds, the same wrong value in two runs."""

    def test_a_contradicted_hash_is_refused(self):
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import generate_pack

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nand.bin"
            path.write_bytes(b"real")
            real = hashlib.sha1(b"real").hexdigest()
            good = {"files": {real: {"path": str(path)}}}
            self.assertEqual(generate_pack._stable_hashes(str(path), good)["sha1"], real)
            bad = {"files": {"0" * 40: {"path": str(path)}}}
            with self.assertRaises(RuntimeError):
                generate_pack._stable_hashes(str(path), bad)
            self.assertEqual(generate_pack._stable_hashes(str(path), {"files": {}})["sha1"], real)

    def test_a_wrong_first_reading_is_read_again_from_disk(self):
        """The retries went through the hash cache and got the first, wrong
        value back: one read of the file, then a refusal a second read would
        have avoided."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import generate_pack
        import hashing

        real_compute = hashing._compute_hashes
        reads: list[str] = []

        def flaky(filepath, algos):
            reads.append(str(filepath))
            result = real_compute(filepath, algos)
            if len(reads) == 1:
                result = {**result, "sha1": "0" * 40}
            return result

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nand.bin"
            path.write_bytes(b"flaky")
            real = hashlib.sha1(b"flaky").hexdigest()
            db = {"files": {real: {"path": str(path)}}}
            with mock.patch.object(hashing, "_compute_hashes", flaky):
                self.assertEqual(generate_pack._stable_hashes(str(path), db)["sha1"], real)
        self.assertEqual(len(reads), 2)

    def test_the_cache_is_keyed_by_what_was_checked(self):
        """Keyed by id(db), a database freed and replaced at the same address
        got hashes verified against the first one back, unchecked."""
        source = (REPO_ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8")
        body = source[source.index("def _stable_hashes("):]
        body = body[: body.index("\ndef ")]
        key_line = next(line for line in body.splitlines() if line.strip().startswith("key ="))
        self.assertNotIn("id(", key_line)
        self.assertIn("expected", key_line)


class RetriesWait(unittest.TestCase):
    def test_a_server_error_is_retried_after_the_delay_it_asks(self):
        with _Server(), tempfile.TemporaryDirectory() as tmp:
            _RangeHandler.fail_first = [503]
            dest, ok, _ = install._download_one(dict(ENTRY), Path(tmp))
            self.assertTrue(ok)

    def test_the_delay_doubles_and_follows_retry_after(self):
        self.assertEqual([install._retry_delay(n, None) for n in (1, 2, 3, 4, 5)],
                         [1.0, 2.0, 4.0, 8.0, 8.0])
        self.assertEqual(install._retry_delay(1, "5"), 5.0)
        self.assertEqual(install._retry_delay(1, "999"), 60.0)

    def test_a_refusal_names_the_rate_limit(self):
        with _Server(), tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(install, "MAX_RETRIES", 1):
            _RangeHandler.fail_first = [403]
            _dest, ok, reason = install._download_one(dict(ENTRY), Path(tmp))
            self.assertFalse(ok)
            self.assertIn("rate limit", reason)


class ProgressOutput(unittest.TestCase):
    def _term(self, quiet=False):
        stream = io.StringIO()
        term = install.Terminal(stream, quiet=quiet)
        return stream, term

    def test_a_log_gets_one_line_per_file_and_failures_say_why(self):
        # A file that went well is a line of --verbose, a failure of every run.
        install.OUTPUT.verbose = False
        stream, term = self._term()
        progress = install.Progress(2, 10, term)
        progress.done("a.bin", True)
        progress.done("b.bin", False, "HTTP 404")
        self.assertEqual(stream.getvalue(), "  FAILED b.bin (HTTP 404)\n")
        self.addCleanup(setattr, install.OUTPUT, "verbose", False)
        install.OUTPUT.verbose = True
        stream, term = self._term()
        progress = install.Progress(2, 10, term)
        progress.done("a.bin", True)
        progress.done("b.bin", False, "HTTP 404")
        out = stream.getvalue()
        self.assertIn("[1/2] a.bin ok", out)
        self.assertIn("FAILED b.bin (HTTP 404)", out)
        self.assertNotIn("\033", out)

    def test_quiet_leaves_failures_to_the_summary(self):
        stream, term = self._term(quiet=True)
        progress = install.Progress(2, 10, term)
        progress.done("a.bin", True)
        progress.done("b.bin", False, "HTTP 404")
        self.assertEqual(stream.getvalue(), "")

    def test_durations_read_like_a_clock(self):
        self.assertEqual([install.format_duration(s) for s in (0, 42, 185, 3729)],
                         ["0:00", "0:42", "3:05", "1:02:09"])

    def test_the_summary_names_each_failure(self):
        self.addCleanup(setattr, install.OUTPUT, "verbose", False)
        install.OUTPUT.verbose = True
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit):
            install._report_outcome(
                [Path("/b")], 1, 0, 1, 0, False,
                failures=[("x.bin", "HTTP 404")], transferred=2048, seconds=2.0,
            )
        out = buf.getvalue()
        self.assertIn("failed: x.bin (HTTP 404)", out)
        self.assertIn("2.0 KB downloaded in 0:02", out)

    def test_files_not_set_aside_get_a_remedy_not_a_retry(self):
        # A real Android run: 25 files whose backup folder was refused, told
        # to run again, which refuses them the same way.
        reason = f"{install.NOT_KEPT} (/sdcard/RetroArch/retrobios-backup belongs to another user)"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit) as end:
            install._report_outcome(
                [Path("/b")], 3, 0, 2, 0, False,
                failures=[("a.zip", reason), ("b.zip", reason)],
            )
        out = buf.getvalue()
        self.assertEqual(end.exception.code, 1)
        self.assertIn("The files in place were left as they were", out)
        self.assertNotIn("retry only those", out)


class CommandLine(unittest.TestCase):
    def test_a_dry_run_writes_nothing(self):
        with FakeRepository() as repo:
            proc = repo.run("--dry-run")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("Would download", proc.stdout)
            self.assertIn("Nothing was written", proc.stdout)
            self.assertEqual(repo.installed(), [])

    def test_quiet_prints_the_summary_only(self):
        with FakeRepository() as repo:
            proc = repo.run("--quiet")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn("Checking existing files", proc.stdout)
            self.assertIn("Done.", proc.stdout)
            self.assertTrue(repo.installed())

    def test_version_names_the_file_the_bootstraps_pin(self):
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--version"],
            capture_output=True, text=True, timeout=60, check=True,
        )
        digest = hashlib.sha256((REPO_ROOT / "install.py").read_bytes()).hexdigest()
        self.assertIn(digest[:12], proc.stdout)



class ReviewCases(unittest.TestCase):
    """Saying no to the large-download question ended on Done, --quiet hid
    fatal messages and swallowed --check, and a resumed copy inflated the speed."""

    def test_declining_is_not_done(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            install._report_outcome([Path("/b")], 0, 3, 0, 0, False, declined=12)
        out = buf.getvalue()
        self.assertNotIn("Done.", out)
        self.assertIn("12 files not downloaded", out)
        self.assertIn("3 files already in place", out)

    def test_quiet_refuses_modes_it_would_silence(self):
        for mode in ("--check", "--dry-run", "--list-platforms", "--list-systems"):
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "install.py"), "--quiet", mode],
                capture_output=True, text=True, timeout=60, check=False,
            )
            with self.subTest(mode=mode):
                self.assertEqual(proc.returncode, 2)
                self.assertIn("--quiet applies to an install", proc.stderr)

    def test_quiet_shows_what_a_failed_run_printed(self):
        with tempfile.TemporaryDirectory() as home:
            env = dict(os.environ, HOME=home, USERPROFILE=home, RETROBIOS_OS="linux",
                       XDG_CONFIG_HOME=home)
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "install.py"), "--quiet"],
                capture_output=True, text=True, timeout=60, check=False,
                env=env, stdin=subprocess.DEVNULL,
            )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("No supported platform detected", proc.stderr)

    def test_a_resumed_copy_is_not_counted_as_fetched(self):
        progress = install.Progress(1, 100, install.Terminal(io.StringIO()))
        progress.add(60, resumed=True)
        progress.add(40)
        self.assertEqual(progress.transferred(), 40)

class _HeldHandler(http.server.BaseHTTPRequestHandler):
    """Serves the manifest and first.bin at once, every other file once released."""

    files: dict[str, bytes] = {}
    manifest = b""
    release = threading.Event()

    def log_message(self, *args) -> None:  # noqa: D102
        pass

    def do_GET(self) -> None:  # noqa: N802, D102
        if self.path.endswith(".json"):
            body = self.manifest
        else:
            name = self.path.rsplit("/", 1)[-1]
            if name != "first.bin":
                self.release.wait(30)
            body = self.files[name]
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class AStoppedRunCountsWhatLanded(unittest.TestCase):
    """Stopped at 8 of 118 files, the summary said "118 files installed":
    every queued file was counted, written or not, and a user who read it
    did not run the command again."""

    @unittest.skipIf(os.name == "nt", "SIGINT is sent the POSIX way")
    def test_only_the_written_file_is_counted(self):
        import signal  # noqa: PLC0415
        import time  # noqa: PLC0415

        files = {name: name.encode() * 64 for name in ("first.bin", "second.bin", "third.bin")}
        manifest = {"manifest_version": 2, "platform": "retroarch", "files": [
            {"dest": name, "size": len(data), "sha1": hashlib.sha1(data).hexdigest(),
             "repo_path": f"bios/{name}", "cores": None}
            for name, data in files.items()
        ]}
        _HeldHandler.files, _HeldHandler.manifest = files, json.dumps(manifest).encode()
        _HeldHandler.release = threading.Event()
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _HeldHandler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        self.addCleanup(_HeldHandler.release.set)
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            dest = Path(tmp) / "bios"
            env = dict(os.environ,
                       RETROBIOS_BASE_URL=f"http://127.0.0.1:{httpd.server_address[1]}")
            log = Path(tmp) / "out.txt"
            # The held files are released once the run says it is stopping,
            # not after a fixed pause: under load the stop landed after the
            # release, all three files arrived, and nothing was stopped.
            with open(log, "w", encoding="utf-8") as out_file:
                proc = subprocess.Popen(
                    [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retroarch",
                     "--dest", str(dest), "--no-input"],
                    env=env, stdin=subprocess.DEVNULL, stdout=out_file,
                    stderr=subprocess.STDOUT, text=True,
                )
                deadline = time.monotonic() + 30
                while not (dest / "first.bin").exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                time.sleep(0.2)
                proc.send_signal(signal.SIGINT)
                while ("Stopping." not in log.read_text(encoding="utf-8")
                       and time.monotonic() < deadline):
                    time.sleep(0.05)
                _HeldHandler.release.set()
                proc.wait(timeout=60)
            out = err = log.read_text(encoding="utf-8")
            written = sorted(p.name for p in dest.iterdir() if not p.name.startswith("."))
        self.assertEqual(proc.returncode, 130, out + err)
        self.assertEqual(written, ["first.bin"])
        self.assertIn("Stopped. 1 file installed.", out)


class ARefusedFolderReportsEachFile(unittest.TestCase):
    """A read-only folder ended the run on its first refusal, and --events
    wrote one `downloaded` line for seven failed files, while the events
    table promises one per finished file."""

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                     "a read-only folder is refused by POSIX permissions")
    def test_one_event_per_file_with_the_reason(self):
        with FakeRepository() as repo:
            repo.dest.mkdir()
            os.chmod(repo.dest, 0o555)
            try:
                proc = repo.run("--events")
            finally:
                os.chmod(repo.dest, 0o755)
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        downloaded = [e for e in events if e["event"] == "downloaded"]
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(len(downloaded), len(FakeRepository.PAYLOADS))
        self.assertEqual({e["reason"] for e in downloaded}, {install.NOT_WRITABLE})
        self.assertEqual(sorted(e["files_done"] for e in downloaded),
                         list(range(1, len(downloaded) + 1)))


class AFolderThisUserCannotEnter(unittest.TestCase):
    """A subfolder of the BIOS folder without search permission (made 0700
    by an emulator that ran as root, or denied by a Windows ACL) raised
    PermissionError from Path.exists() before any file was handled, in
    --check and in an install alike."""

    def _locked(self, repo: FakeRepository) -> Path:
        (repo.dest / "pcsx").mkdir(parents=True)
        (repo.dest / "pcsx" / "extra.bin").write_bytes(b"old")
        os.chmod(repo.dest / "pcsx", 0o000)
        return repo.dest / "pcsx"

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                     "a folder without search permission is POSIX")
    def test_check_names_the_file_and_reads_the_others(self):
        with FakeRepository() as repo:
            locked = self._locked(repo)
            try:
                proc = repo.run("--check", "--verbose")
            finally:
                os.chmod(locked, 0o755)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertIn("wrong copy: pcsx/extra.bin", proc.stdout)
        self.assertIn("could not be read (Permission denied)", proc.stdout)
        self.assertIn("missing: scph5501.bin", proc.stdout)

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                     "a folder without search permission is POSIX")
    def test_install_fails_that_file_alone(self):
        with FakeRepository() as repo:
            locked = self._locked(repo)
            try:
                proc = repo.run("--events")
            finally:
                os.chmod(locked, 0o755)
            installed = repo.installed()
        self.assertNotIn("Traceback", proc.stderr)
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        failed = {e["dest"]: e["reason"] for e in events
                  if e["event"] == "downloaded" and not e["ok"]}
        self.assertEqual(list(failed), ["pcsx/extra.bin"], proc.stderr)
        self.assertIn("this user may not have access", failed["pcsx/extra.bin"])
        self.assertIn("scph5501.bin", installed)
        self.assertIn("mgba/extra.bin", installed)

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                     "a folder without search permission is POSIX")
    def test_declared_state_reads_it_as_wrong(self):
        with FakeRepository() as repo:
            locked = self._locked(repo)
            entry = {"dest": "pcsx/extra.bin", "sha1": "0" * 40, "size": 3}
            try:
                state = install._declared_state(entry, entry, repo.dest)
            finally:
                os.chmod(locked, 0o755)
        self.assertEqual(state, "wrong_hash")

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                     "a folder without search permission is POSIX")
    def test_a_bios_folder_under_it_is_refused_in_words(self):
        """--dest /root/.config/retroarch/system without sudo: _missing_dest
        ended --check and the install on a PermissionError traceback."""
        with FakeRepository() as repo:
            lock = repo.root / "lock"
            lock.mkdir()
            repo.dest = lock / "system"
            os.chmod(lock, 0o000)
            try:
                runs = {"check": repo.run("--check"), "install": repo.run(),
                        "events": repo.run("--events")}
            finally:
                os.chmod(lock, 0o755)
            self.assertFalse(repo.dest.exists())
        for name, proc in runs.items():
            with self.subTest(run=name):
                self.assertNotIn("Traceback", proc.stderr)
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn(f"this user cannot open {lock} (Permission denied)",
                              proc.stderr)
                self.assertIn("choose another folder", proc.stderr)
        events = [json.loads(line) for line in runs["events"].stdout.splitlines()]
        errors = [e for e in events if e["event"] == "error"]
        self.assertEqual([(e["stage"], e["reason"]) for e in errors],
                         [("dest", "unreadable")])
        self.assertIn(str(lock), errors[0]["message"])


class ADetectedFolderUnderAClosedOne(unittest.TestCase):
    """retroarch.cfg naming a system_directory under a folder this user
    cannot open, with no --dest: the case probe raised PermissionError and
    the run, and the interface before its first screen, ended on a
    traceback. The refusal --dest gets is the one detection gets."""

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                     "a folder without search permission is POSIX")
    def test_it_is_refused_in_words(self):
        with FakeRepository() as repo:
            home = repo.root / "home"
            lock = repo.root / "lock"
            (home / ".config" / "retroarch").mkdir(parents=True)
            lock.mkdir()
            (home / ".config" / "retroarch" / "retroarch.cfg").write_text(
                f'system_directory = "{lock / "system"}"\n')
            env = {**repo.env(), "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
                   "RETROBIOS_OS": "linux"}
            command = [sys.executable, str(REPO_ROOT / "install.py"), "--platform",
                       "retroarch", "--no-input"]
            os.chmod(lock, 0o000)
            try:
                runs = {name: subprocess.run(command + extra, env=env, capture_output=True,
                                             text=True, timeout=60, stdin=subprocess.DEVNULL)
                        for name, extra in (("check", ["--check"]), ("install", []))}
                kinds = install.tell_apart([("retroarch", lock / "system", "RetroArch"),
                                            ("retroarch", repo.dest, "RetroArch")])
            finally:
                os.chmod(lock, 0o755)
        for name, proc in runs.items():
            with self.subTest(run=name):
                self.assertNotIn("Traceback", proc.stderr)
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn(f"this user cannot open {lock} (Permission denied)",
                              proc.stderr)
        self.assertEqual(len(kinds), 2)


class AHomeThisUserCannotOpen(unittest.TestCase):
    """HOME kept across `su` without `-`: detection stat'ed files under it
    and ended the run on a PermissionError traceback before any line."""

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                     "a folder without search permission is POSIX")
    def test_detection_says_so_and_the_run_goes_on(self):
        with FakeRepository() as repo:
            home = repo.root / "home"
            home.mkdir()
            env = {**repo.env(), "HOME": str(home), "RETROBIOS_OS": "linux"}
            runs = {}
            os.chmod(home, 0o000)
            try:
                for name, extra in (("named", ["--platform", "retroarch", "--dest",
                                               str(repo.dest)]),
                                    ("detected", [])):
                    runs[name] = subprocess.run(
                        [sys.executable, str(REPO_ROOT / "install.py"), "--check",
                         "--no-input", "--verbose", *extra],
                        env=env, capture_output=True, text=True, timeout=60,
                        stdin=subprocess.DEVNULL)
            finally:
                os.chmod(home, 0o755)
        for name, proc in runs.items():
            with self.subTest(run=name):
                self.assertNotIn("Traceback", proc.stderr)
        # A named folder needs no detection and is checked.
        self.assertIn("0 in place, 5 missing", runs["named"].stdout)
        self.assertIn(f"Could not look for setups: this user cannot open {home}",
                      runs["detected"].stderr)

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                     "a folder without search permission is POSIX")
    def test_an_assumed_folder_is_not_called_detected(self):
        """The refusal ended "than the one detected here" for the built-in
        default taken because RetroArch was not detected."""
        with FakeRepository() as repo:
            home = repo.root / "home"
            home.mkdir()
            env = {**repo.env(), "HOME": str(home), "RETROBIOS_OS": "linux"}
            os.chmod(home, 0o000)
            try:
                proc = subprocess.run(
                    [sys.executable, str(REPO_ROOT / "install.py"), "--check",
                     "--no-input", "--platform", "retroarch"],
                    env=env, capture_output=True, text=True, timeout=60,
                    stdin=subprocess.DEVNULL)
            finally:
                os.chmod(home, 0o755)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        said = " ".join(proc.stderr.split())
        self.assertNotIn("the one detected here", said)
        # HOME closed, the default is not assumed at all: --dest is asked for.
        self.assertIn("Platform 'retroarch' not found where this user can look", said)
        self.assertNotIn("using default path", proc.stdout + proc.stderr)


class ASettingsFileThisUserCannotRead(unittest.TestCase):
    """A sudo EmuDeck run left settings.sh to root: its parser swallowed the
    refusal and the run said "No supported platform detected" without a
    word on the file, where the same refusal on retroarch.cfg is said."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        install._DETECTION_REFUSED.clear()
        self.addCleanup(install._DETECTION_REFUSED.clear)
        install._SETUP_SEARCH.active = True
        self.addCleanup(setattr, install._SETUP_SEARCH, "active", False)

    def test_each_settings_parser_says_the_refusal(self):
        for parse, name in ((install._parse_bash_var, "settings.sh"),
                            (install._parse_ps1_var, "settings.ps1")):
            with self.subTest(file=name):
                install._DETECTION_REFUSED.clear()
                path = self.root / name
                path.write_text('emulationPath="/x"\n', encoding="utf-8")
                refusal = PermissionError(errno.EACCES, "Permission denied", str(path))
                with mock.patch.object(Path, "read_text", side_effect=refusal), \
                        mock.patch.object(Path, "read_bytes", side_effect=refusal), \
                        contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertIsNone(parse(path, "emulationPath"))
                self.assertEqual(install._DETECTION_REFUSED, [(path, "Permission denied")])
                self.assertIn(f"cannot open {path}", err.getvalue())


class AConfigThatFailsToRead(unittest.TestCase):
    """retroarch.cfg on a failing card raised EIO, and a link that loops
    ELOOP: both counted as absent without a word, as only a permission
    refusal was said. Absence itself stays silent."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        install._DETECTION_REFUSED.clear()
        self.addCleanup(install._DETECTION_REFUSED.clear)
        install._SETUP_SEARCH.active = True
        self.addCleanup(setattr, install._SETUP_SEARCH, "active", False)

    def test_a_read_error_is_said_with_its_own_words(self):
        cfg = self.root / "retroarch.cfg"
        cfg.write_text('system_directory = "/x"\n', encoding="utf-8")
        failure = OSError(errno.EIO, "Input/output error", str(cfg))
        with mock.patch.object(Path, "read_text", side_effect=failure), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertIsNone(install._retroarch_cfg_dir(cfg, "system_directory",
                                                         self.root, "system"))
        self.assertEqual(install._DETECTION_REFUSED, [(cfg, "Input/output error")])
        said = " ".join(err.getvalue().split())
        self.assertIn(f"{cfg} could not be read (Input/output error)", said)
        self.assertNotIn("Run as its owner", said)

    @unittest.skipIf(os.name == "nt", "a symbolic link needs privileges on Windows")
    def test_a_link_that_loops_is_said_and_absence_is_not(self):
        loop = self.root / "retroarch.cfg"
        loop.symlink_to(loop.name)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(install._exists(loop))
            self.assertFalse(install._exists(self.root / "absent.cfg"))
            self.assertFalse(install._exists(self.root / "absent" / "x.cfg"))
        self.assertEqual([folder for folder, _why in install._DETECTION_REFUSED], [loop])


class TheFrontendsOwnFolderClosed(unittest.TestCase):
    """The Flatpak RetroArch's folder at 000: its retroarch.cfg names
    ~/Games/bios, and the run took ~/.config/retroarch/system, a folder it
    does not read, and offered 6.6 GB there. A folder detection could not
    look in leaves no default to assume."""

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                     "a folder without search permission is POSIX")
    def test_no_default_is_assumed(self):
        with FakeRepository() as repo:
            home = repo.root / "home"
            flatpak = home / ".var" / "app" / "org.libretro.RetroArch"
            cfg = flatpak / "config" / "retroarch" / "retroarch.cfg"
            cfg.parent.mkdir(parents=True)
            cfg.write_text(f'system_directory = "{home / "Games" / "bios"}"\n')
            env = {**repo.env(), "HOME": str(home), "RETROBIOS_OS": "linux"}
            os.chmod(flatpak, 0o000)
            try:
                proc = subprocess.run(
                    [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retroarch",
                     "--dry-run", "--no-input"],
                    env=env, capture_output=True, text=True, timeout=60,
                    stdin=subprocess.DEVNULL)
            finally:
                os.chmod(flatpak, 0o755)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertNotIn("using default path", proc.stdout + proc.stderr)
        self.assertIn(f"this user cannot open {flatpak}", proc.stderr)
        self.assertIn("--dest", proc.stderr)


class ARefusalTheProbeDoesNotRaise(unittest.TestCase):
    """Python 3.14's Path.exists() answers False on a folder this user
    cannot enter instead of raising: every closed-folder line went silent
    and the run took the default again."""

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                     "a folder without search permission is POSIX")
    def test_a_quiet_false_is_still_told_from_absence(self):
        base = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, base, True)
        closed = base / "closed"
        closed.mkdir()
        os.chmod(closed, 0o000)
        self.addCleanup(os.chmod, closed, 0o755)
        target = closed / "retroarch.cfg"
        install._DETECTION_REFUSED.clear()
        self.addCleanup(install._DETECTION_REFUSED.clear)
        quiet = mock.patch.object(install.Path, "exists", lambda self: False)
        # What _detection_guarded sets while it looks for setups.
        outer = getattr(install._SETUP_SEARCH, "active", False)
        install._SETUP_SEARCH.active = True
        self.addCleanup(setattr, install._SETUP_SEARCH, "active", outer)
        with quiet, contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(install._exists(target))
            self.assertFalse(install._exists(base / "absent"))
            self.assertEqual(install.closed_folder(target), (closed, "Permission denied"))
        self.assertEqual([folder for folder, _why in install._DETECTION_REFUSED], [closed])


class APartlyClosedHome(unittest.TestCase):
    """~/.config/EmuDeck at 000 (a sudo run leaves it owned by root) made
    detection return nothing: the readable retroarch.cfg beside it was
    never read, and the run fell back to ~/.config/retroarch/system, a
    folder that RetroArch does not read."""

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                     "a folder without search permission is POSIX")
    def test_retroarch_is_found_past_the_closed_folder(self):
        with FakeRepository() as repo:
            home = repo.root / "home"
            closed = home / ".config" / "EmuDeck"
            closed.mkdir(parents=True)
            cfg = home / ".config" / "retroarch" / "retroarch.cfg"
            cfg.parent.mkdir()
            system = repo.root / "elsewhere" / "system"
            system.mkdir(parents=True)
            cfg.write_text(f'system_directory = "{system}"\n')
            env = {**repo.env(), "HOME": str(home), "RETROBIOS_OS": "linux"}
            runs = {}
            os.chmod(closed, 0o000)
            try:
                for name, extra in (("detected", []),
                                    ("named", ["--platform", "retroarch"]),
                                    ("events", ["--events"])):
                    runs[name] = subprocess.run(
                        [sys.executable, str(REPO_ROOT / "install.py"), "--check",
                         "--no-input", "--verbose", *extra],
                        env=env, capture_output=True, text=True, timeout=60,
                        stdin=subprocess.DEVNULL)
            finally:
                os.chmod(closed, 0o755)
        refusal = (f"Could not look for setups: this user cannot open {closed} "
                   "(Permission denied)")
        for name, proc in runs.items():
            with self.subTest(run=name):
                self.assertNotIn("Traceback", proc.stderr)
                self.assertEqual(" ".join(proc.stderr.split()).count(refusal), 1,
                                 proc.stderr)
                self.assertNotIn(str(home / ".config" / "retroarch" / "system"),
                                 proc.stdout + proc.stderr)
        self.assertIn(f"Found RetroArch at {system}", runs["detected"].stdout)
        self.assertIn("0 in place, 5 missing", runs["named"].stdout)
        self.assertNotIn("not detected", runs["named"].stdout)
        events = [json.loads(line) for line in runs["events"].stdout.splitlines()]
        kinds = [event["event"] for event in events]
        self.assertLess(kinds.index("unsearched"), kinds.index("detect"))
        unsearched = events[kinds.index("unsearched")]
        self.assertEqual((unsearched["folder"], unsearched["reason"]),
                         (str(closed), "Permission denied"))
        detect = events[kinds.index("detect")]
        self.assertEqual([entry["bios_dir"] for entry in detect["platforms"]], [str(system)])


class RetroDeckBiosFolderNamedAsDest(unittest.TestCase):
    """`--platform retrodeck --dest ~/retrodeck/bios`, as --help asks for a
    BIOS folder, put every file under bios/bios, which RetroDECK never reads."""

    def test_the_files_go_below_the_retrodeck_folder(self):
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        (root / "bios").mkdir()
        choice = install.card_choice("retrodeck", "retrodeck", root / "bios")
        self.assertEqual(choice.folder, root)
        self.assertIn("RetroDECK's BIOS folder", choice.note)
        self.assertFalse(choice.refused)

    def test_the_retrodeck_folder_itself_is_kept(self):
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        (root / "bios").mkdir()
        choice = install.card_choice("retrodeck", "retrodeck", root)
        self.assertEqual((choice.folder, choice.note), (root, ""))


class AnUnreadableRetroArchConfigIsSaid(unittest.TestCase):
    """A retroarch.cfg a `sudo retroarch` left at 0600 for root was read as
    no config at all: RetroArch was not found and nothing said why."""

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                     "a file without read permission is POSIX")
    def test_the_closed_config_is_named(self):
        with FakeRepository() as repo:
            home = repo.root / "home"
            cfg = home / ".config" / "retroarch" / "retroarch.cfg"
            cfg.parent.mkdir(parents=True)
            cfg.write_text('system_directory = "/media/card/bios"\n')
            env = {**repo.env(), "HOME": str(home), "RETROBIOS_OS": "linux"}
            os.chmod(cfg, 0o000)
            try:
                proc = subprocess.run(
                    [sys.executable, str(REPO_ROOT / "install.py"), "--check",
                     "--no-input", "--events"],
                    env=env, capture_output=True, text=True, timeout=60,
                    stdin=subprocess.DEVNULL)
            finally:
                os.chmod(cfg, 0o644)
        self.assertNotIn("Traceback", proc.stderr)
        refusal = (f"Could not look for setups: this user cannot open {cfg} "
                   "(Permission denied)")
        self.assertEqual(" ".join(proc.stderr.split()).count(refusal), 1, proc.stderr)
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        unsearched = [event for event in events if event["event"] == "unsearched"]
        self.assertEqual([(event["folder"], event["reason"]) for event in unsearched],
                         [(str(cfg), "Permission denied")])


class OutputToAFileAsksNothing(unittest.TestCase):
    """`install.py > log.txt` at a terminal: the menu went into the file
    and the run waited on an answer to a prompt nobody could see."""

    @unittest.skipIf(os.name == "nt", "a pseudo-terminal for stdin")
    def test_the_run_goes_on_as_with_no_input(self):
        import pty

        master, slave = pty.openpty()
        try:
            with FakeRepository() as repo:
                proc = subprocess.run(
                    repo.command(), env=repo.env(), stdin=slave, capture_output=True,
                    text=True, timeout=60, check=False)
                installed = repo.installed()
        finally:
            os.close(master)
            os.close(slave)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("nothing is asked", proc.stderr)
        self.assertNotIn("Enter) install everything", proc.stdout)
        self.assertEqual(len(installed), len(FakeRepository.PAYLOADS))

    @unittest.skipIf(os.name == "nt", "a pseudo-terminal for stdin")
    def test_a_pipe_is_named_a_pipe(self):
        """`install.py | tee log.txt` was told its output went to a file."""
        import pty

        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        with FakeRepository() as repo:
            piped = subprocess.run(
                [*repo.command(), "--dry-run"], env=repo.env(), stdin=slave,
                capture_output=True, text=True, timeout=60, check=False)
            log = repo.root / "log.txt"
            with open(log, "w", encoding="utf-8") as handle:
                filed = subprocess.run(
                    [*repo.command(), "--dry-run"], env=repo.env(), stdin=slave,
                    stdout=handle, stderr=subprocess.PIPE, text=True, timeout=60,
                    check=False)
        self.assertIn("Output goes to a pipe, so nothing is asked", piped.stderr)
        self.assertIn("run it without the pipe to answer", piped.stderr)
        self.assertIn("Output goes to a file, so nothing is asked", filed.stderr)
        self.assertIn("run it without the redirection to answer", filed.stderr)
        for proc in (piped, filed):
            self.assertIn("Add --no-input to say so", proc.stderr)

    def test_the_kind_of_output(self):
        self.assertEqual(install._output_kind(io.StringIO()), "")
        read, write = os.pipe()
        with open(read, "rb") as reader, open(write, "w") as writer:
            self.assertEqual(install._output_kind(writer), "pipe")
            del reader
        with tempfile.TemporaryFile("w", dir=REPO_ROOT / "tmp") as handle:
            self.assertEqual(install._output_kind(handle), "file")


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


class ColourFollowsNoColorOrg(unittest.TestCase):
    """no-color.org: only a NO_COLOR that is set and not empty turns colour
    off. An empty one, as `NO_COLOR= cmd` leaves, turned it off too."""

    def _colour(self, **env: str) -> bool:
        clean = {k: v for k, v in os.environ.items()
                 if k not in ("NO_COLOR", "FORCE_COLOR", "CLICOLOR_FORCE", "TERM")}
        # A terminal that is named: an unset TERM is a dumb one.
        with mock.patch.dict(os.environ, {**clean, "TERM": "xterm", **env}, clear=True), \
                mock.patch.object(install, "_enable_ansi", return_value=True):
            return install.Terminal(_Tty()).colour

    def test_an_empty_no_color_leaves_colour_on(self):
        self.assertTrue(self._colour())
        self.assertTrue(self._colour(NO_COLOR=""))
        self.assertFalse(self._colour(NO_COLOR="1"))

    def test_force_color_paints_a_pipe(self):
        with mock.patch.object(install, "_enable_ansi", return_value=True):
            for env, expected in (({}, False), ({"FORCE_COLOR": "1"}, True),
                                  ({"CLICOLOR_FORCE": "1"}, True),
                                  ({"FORCE_COLOR": "0"}, False),
                                  ({"FORCE_COLOR": "1", "NO_COLOR": "1"}, False)):
                clean = {k: v for k, v in os.environ.items()
                         if k not in ("NO_COLOR", "FORCE_COLOR", "CLICOLOR_FORCE")}
                with self.subTest(env=env), \
                        mock.patch.dict(os.environ, {**clean, **env}, clear=True):
                    term = install.Terminal(io.StringIO())
                    self.assertEqual(term.colour, expected)
                    self.assertFalse(term.live)


class TheEndOfARunPaintsItsStatusWords(unittest.TestCase):
    """Line mode ends on the words the full screen paints, in the same
    roles, and on the same text without colour."""

    def _end(self, colour: bool, *counts: int, **given) -> str:
        term = install.Terminal(io.StringIO())
        term.colour = colour
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.suppress(SystemExit):
            install._report_outcome([Path("bios")], *counts, term=term, **given)
        return out.getvalue()

    def test_the_same_words_with_and_without_colour(self):
        for counts, given, painted in (
                ((3, 1, 1, 0, False), {"failures": [("a.bin", "HTTP 404")]},
                 (("failure", "Finished with errors"), ("success", "3 files installed"),
                  ("failure", "1 file failed"), ("failure", "failed:"))),
                ((2, 1, 0, 0, False), {},
                 (("success", "Done"), ("success", "2 files installed"),
                  ("success", "1 file already in place"))),
                ((1, 0, 0, 0, False), {"offline": 2},
                 (("warning", "Finished with files missing"), ("warning", "2 not fetched")))):
            with self.subTest(counts=counts):
                plain, coloured = self._end(False, *counts, **given), \
                    self._end(True, *counts, **given)
                self.assertNotIn("\x1b", plain)
                self.assertEqual(install.unpainted(coloured), plain)
                for role, word in painted:
                    self.assertIn(install._sgr(role) + word, coloured)


class SmallWordings(unittest.TestCase):
    def test_check_asks_which_to_check(self):
        """--check with several platforms asked "Install for:", and
        installs nothing."""
        out = io.StringIO()
        with mock.patch("builtins.input", lambda _prompt="": "1"), \
                contextlib.redirect_stdout(out):
            install._prompt_platform_choice(
                [("emudeck", Path("/e")), ("retroarch", Path("/r"))], "Check:")
        self.assertIn("Check:", out.getvalue())
        self.assertNotIn("Install for:", out.getvalue())

    def test_nothing_detected_is_said(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as home:
            env = dict(os.environ, HOME=home, USERPROFILE=home, XDG_CONFIG_HOME=home,
                       RETROBIOS_OS="linux")
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "install.py"), "--list-platforms"],
                env=env, capture_output=True, text=True, timeout=60, check=False,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Detected on this system: none", proc.stdout)


class WindowsMandatoryLock(unittest.TestCase):
    """Issue 82: on Windows the partial copy's lock is mandatory, so hashing
    it by reopening its path failed with a sharing violation, and every file
    of 16 MB or more was reported as "folder not writable"."""

    def test_the_locked_partial_is_hashed_through_its_handle(self):
        real_open = open

        def locked_open(path, *args, **kwargs):
            if str(path).endswith(".part"):
                raise PermissionError(33, "The process cannot access the file")
            return real_open(path, *args, **kwargs)

        with _Server(), tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(install, "RESUME_FROM_SIZE", 1024), \
                mock.patch("builtins.open", locked_open):
            dest, ok, reason = install._download_one(dict(ENTRY), Path(tmp))
        self.assertEqual((dest, ok, reason), ("big.bin", True, ""))

    def test_a_read_only_file_in_place_is_named_as_such(self):
        with _Server(), tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(install.os, "replace",
                                  side_effect=PermissionError(5, "Access is denied")), \
                mock.patch.object(install, "_read_only_file", return_value=True):
            _dest, ok, reason = install._download_one(dict(ENTRY), Path(tmp))
        self.assertFalse(ok)
        self.assertEqual(reason, install.READ_ONLY)

    def test_a_read_only_file_in_place_is_made_writable_on_windows(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "big.bin"
            dest.write_bytes(b"old")
            os.chmod(dest, 0o444)
            with mock.patch.object(install.os, "name", "nt"):
                install._clear_read_only(dest)
            self.assertTrue(os.access(dest, os.W_OK))

    def test_elsewhere_the_attribute_is_left_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "big.bin"
            dest.write_bytes(b"old")
            os.chmod(dest, 0o444)
            with mock.patch.object(install.os, "name", "posix"):
                install._clear_read_only(dest)
            self.assertFalse(os.access(dest, os.W_OK))
            os.chmod(dest, 0o644)

    def test_a_refused_folder_keeps_its_own_reason(self):
        with _Server(), tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(install.os, "replace",
                                  side_effect=PermissionError(13, "Permission denied")), \
                mock.patch.object(install, "_read_only_file", return_value=False):
            _dest, ok, reason = install._download_one(dict(ENTRY), Path(tmp))
        self.assertEqual((ok, reason), (False, install.NOT_WRITABLE))


@unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                 "a folder without search permission is POSIX")
class AClosedFolderBehindALink(unittest.TestCase):
    """~/Emulation linked into a card at 000: the line named the link's
    parent, telling the user they cannot open their own HOME. A link
    that loops was named by its open parent."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.base, True)
        self.home = self.base / "home"
        self.home.mkdir()
        self.card = self.base / "card"
        (self.card / "Emulation" / "bios").mkdir(parents=True)

    def closed(self, path: Path):
        os.chmod(self.card, 0o000)
        try:
            return install.closed_folder(path)
        finally:
            os.chmod(self.card, 0o755)

    def test_a_link_into_the_closed_folder_names_that_folder(self):
        (self.home / "Emulation").symlink_to(self.card / "Emulation")
        self.assertEqual(self.closed(self.home / "Emulation" / "bios"),
                         (self.card, "Permission denied"))

    def test_a_link_to_the_closed_folder_itself_names_it(self):
        (self.home / "Emulation").symlink_to(self.card)
        self.assertEqual(self.closed(self.home / "Emulation" / "Emulation" / "bios"),
                         (self.card, "Permission denied"))

    def test_a_loop_names_the_link(self):
        loop = self.base / "loop"
        loop.symlink_to("loop")
        folder, why = install.closed_folder(loop / "system")
        self.assertEqual(folder, loop)
        self.assertEqual(why, os.strerror(errno.ELOOP))


@unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                 "a folder without search permission is POSIX")
class TheQuietConfigReadSaysNothing(unittest.TestCase):
    """With --dest the run searches for no setup, and the configs read for
    the save directory wrote an unsearched event after detect, for a line
    the human output never showed."""

    def test_no_event_and_no_line(self):
        base = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, base, True)
        closed = base / "home" / ".config" / "EmuDeck"
        closed.mkdir(parents=True)
        os.chmod(closed, 0o000)
        self.addCleanup(os.chmod, closed, 0o755)
        emitted = []
        install._DETECTION_REFUSED.clear()
        self.addCleanup(install._DETECTION_REFUSED.clear)
        with mock.patch.dict(os.environ, {"HOME": str(base / "home"),
                                          "XDG_CONFIG_HOME": str(base / "home" / ".config")}), \
                mock.patch.object(install, "_CONFIGS_READ", []), \
                mock.patch.object(install, "_RETROARCH_CONFIGS", {}), \
                mock.patch.object(install.EVENTS, "emit",
                                  lambda kind, **fields: emitted.append(kind)), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            install._retroarch_config_for(base / "bios")
        self.assertNotIn("unsearched", emitted)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(install._DETECTION_REFUSED, [])


@unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                 "a folder without search permission is POSIX")
class NotFoundWithAClosedFolder(unittest.TestCase):
    """The not-found line spoke of a default set aside for RetroBat on
    Linux, which has none, as soon as any folder was closed, and the exit
    wrote no error event."""

    def run_named(self, platform: str, closed_home: bool) -> tuple:
        with FakeRepository() as repo:
            home = repo.root / "home"
            closed = home / ".config" / "EmuDeck"
            closed.mkdir(parents=True)
            env = {**repo.env(), "HOME": str(home), "RETROBIOS_OS": "linux"}
            if closed_home:
                os.chmod(closed, 0o000)
            try:
                proc = subprocess.run(
                    [sys.executable, str(REPO_ROOT / "install.py"), "--platform", platform,
                     "--dry-run", "--no-input", "--events"],
                    env=env, capture_output=True, text=True, timeout=60,
                    stdin=subprocess.DEVNULL)
            finally:
                os.chmod(closed, 0o755)
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        return proc, events

    def test_a_platform_with_no_folder_here_says_so(self):
        for closed_home in (False, True):
            with self.subTest(closed=closed_home):
                proc, events = self.run_named("retrobat", closed_home)
                self.assertEqual(proc.returncode, 1, proc.stderr)
                said = " ".join(proc.stderr.split())
                self.assertIn("no folder on this system is one it reads", said)
                self.assertNotIn("its default folder may not be", said)
                [error] = [e for e in events if e["event"] == "error"]
                self.assertEqual((error["stage"], error["reason"], error["platform"]),
                                 ("detect", "not_found", "retrobat"))

    def test_a_default_set_aside_says_so(self):
        proc, events = self.run_named("retroarch", True)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("its default folder may not be the one it reads",
                      " ".join(proc.stderr.split()))
        self.assertEqual([e["reason"] for e in events if e["event"] == "error"],
                         ["not_found"])

    def test_a_card_system_and_a_portable_one_write_the_event(self):
        for platform in ("minui", "bizhawk"):
            with self.subTest(platform=platform):
                proc, events = self.run_named(platform, False)
                self.assertEqual(proc.returncode, 1, proc.stderr)
                self.assertEqual([(e["stage"], e["reason"]) for e in events
                                  if e["event"] == "error"], [("detect", "not_found")])

    def test_the_manual_prompt_says_why_there_is_no_default(self):
        home = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, home, True)
        asked = []
        install._DETECTION_REFUSED[:] = [(home / ".config" / "EmuDeck", "Permission denied")]
        self.addCleanup(install._DETECTION_REFUSED.clear)
        # The drives of the machine running the tests are not read, and the
        # question is not printed into the test output.
        with mock.patch.dict(os.environ, {"HOME": str(home)}), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_choose_platform", return_value="retroarch"), \
                mock.patch.object(install, "_ask",
                                  lambda prompt: asked.append(prompt) or str(home / "b")), \
                contextlib.redirect_stdout(io.StringIO()):
            install._prompt_manual_platform("linux")
        self.assertEqual(len(asked), 1)
        self.assertNotIn("no default on this system", asked[0])
        self.assertIn("could not be opened", asked[0])


@unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                 "a folder without search permission is POSIX")
class ADetectedClosedFolderSaysWhereItCameFrom(unittest.TestCase):
    """The refusal said "the one detected here" for a folder retroarch.cfg
    names, and with two setups found the line saying nothing was installed
    came above the error it continues."""

    def run_detected(self, emudeck: bool) -> subprocess.CompletedProcess:
        with FakeRepository() as repo:
            home = repo.root / "home"
            lock = repo.root / "lock"
            cfg = home / ".config" / "retroarch" / "retroarch.cfg"
            cfg.parent.mkdir(parents=True)
            (lock / "system").mkdir(parents=True)
            cfg.write_text(f'system_directory = "{lock / "system"}"\n')
            if emudeck:
                (home / "Emulation" / "bios").mkdir(parents=True)
            env = {**repo.env(), "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
                   "RETROBIOS_OS": "linux"}
            os.chmod(lock, 0o000)
            try:
                proc = subprocess.run(
                    [sys.executable, str(REPO_ROOT / "install.py"), "--check", "--no-input"],
                    env=env, capture_output=True, text=True, timeout=60,
                    stdin=subprocess.DEVNULL)
            finally:
                os.chmod(lock, 0o755)
        self.cfg = cfg
        return proc

    def test_the_config_is_named(self):
        proc = self.run_detected(False)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        said = " ".join(proc.stderr.split())
        self.assertIn(f"than the one {self.cfg} names (name another with --dest)", said)

    def test_two_setups_stop_before_either_folder_is_read(self):
        """A run without questions installs for one
        setup, so two found stop on what to name before either folder is
        read, the closed one included."""
        proc = self.run_detected(True)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        said = " ".join(proc.stderr.split())
        self.assertIn("2 setups were found here, and a run without questions installs for "
                      "one", said)
        self.assertIn("--platform emudeck --dest", said)
        self.assertNotIn("Downloading", proc.stdout)

    def test_an_assumed_default_reads_plainly(self):
        self.assertIn("used by default, since {display_name(name)} was not found",
                      _source_of(install._install))


class OfflineWithNothingFound(unittest.TestCase):
    """An --offline run on a machine with nothing installed ended on "No
    file list for emudeck", a platform nobody asked about: the standalone
    folders are named by file lists that run cannot fetch."""

    def test_the_hint_is_given_and_no_other_platform_named(self):
        with FakeRepository() as repo:
            home = repo.root / "home"
            home.mkdir()
            env = {**repo.env(), "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
                   "RETROBIOS_OS": "linux"}
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "install.py"), "--offline", "--check",
                 "--no-input"],
                env=env, capture_output=True, text=True, timeout=60,
                stdin=subprocess.DEVNULL)
        said = proc.stdout + proc.stderr
        self.assertEqual(proc.returncode, 1, said)
        self.assertNotIn("emudeck", said.lower())
        self.assertIn("Name the setup with --platform and its folder with --dest", said)


class TheDryRunWords(unittest.TestCase):
    """The FAQ's dry run asked "Enter) install everything" before a run
    that installs nothing, then counted 88 systems where the full screen
    lists 66: a shared file made a group of its own."""

    def test_the_question_says_nothing_is_written(self):
        out = io.StringIO()
        files = [{"dest": "a.bin", "size": 1, "systems": ["x"]}]
        with mock.patch.object(install, "_ask", return_value=""), \
                contextlib.redirect_stdout(out):
            install._prompt_custom_selection("retroarch", files, [], None, "RetroArch",
                                             dry_run=True)
        self.assertNotIn("install everything", out.getvalue())
        self.assertIn("nothing is written", out.getvalue())

    def test_the_largest_systems_are_counted_as_systems(self):
        files = [{"dest": f"{n}.bin", "size": n + 1, "systems": [f"s{n}"]}
                 for n in range(12)]
        files.append({"dest": "shared.bin", "size": 1, "systems": ["s0", "s1"]})
        out = io.StringIO()
        with mock.patch.object(install.shutil, "get_terminal_size",
                               return_value=os.terminal_size((80, 10))), \
                contextlib.redirect_stdout(out):
            install._print_plan(files, Path("dest"), install.Terminal(io.StringIO()))
        self.assertIn("12 systems in 13 groups, the largest first", out.getvalue())


def _source_of(function) -> str:
    import inspect

    return " ".join(inspect.getsource(function).split())


if __name__ == "__main__":
    unittest.main()
