"""A run's outcome: free space, destinations, exit codes, the messages and hints it leaves."""
from __future__ import annotations

import tests
from tests import loopback
from tests import scratch_dir

import contextlib
import hashlib
import errno
import io
import json
import os
import shlex
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
import unittest.mock
from pathlib import Path

from tests.netguard import module_guard
from tests.installsupport import REPO_ROOT, install, reported, _install_run


# No connection off the loopback and no card of the host reaches a test:
# the module fails at its end otherwise.
setUpModule, tearDownModule = module_guard("test_install_runs")


class TestRunOutcome(unittest.TestCase):
    """A run says what happened and leaves with a status that matches."""

    def _report(self, **kw):
        defaults = dict(
            paths=[Path("/userdata/bios")],
            downloaded=0,
            up_to_date=0,
            errors=0,
            omitted=0,
            interrupted=False,
        )
        details = {key: kw.pop(key) for key in list(kw) if key not in defaults}
        defaults.update(kw)
        buf = io.StringIO()
        code = 0
        with contextlib.redirect_stdout(buf):
            try:
                install._report_outcome(**defaults, details=install.OutcomeDetails(**details))
            except SystemExit as exc:
                code = exc.code
        return buf.getvalue(), code

    def test_success_names_the_location_and_the_way_to_check(self):
        install.OUTPUT.verbose = install.OUTPUT.where_said = False
        out, code = self._report(downloaded=12, up_to_date=3)
        self.assertEqual(code, 0)
        self.assertIn("12 files installed", out)
        self.assertIn("/userdata/bios", out)
        self.assertIn("Next: ", out)
        self.assertNotIn("--check", out)
        self.addCleanup(setattr, install.OUTPUT, "verbose", False)
        install.OUTPUT.verbose = True
        self.assertIn("--check", self._report(downloaded=12, up_to_date=3)[0])

    def test_total_failure_does_not_say_done_and_exits_two(self):
        out, code = self._report(errors=7)
        self.assertEqual(code, 2)
        self.assertNotIn("Done.", out)
        self.assertIn("Nothing was installed", out)

    def test_partial_failure_exits_one(self):
        out, code = self._report(downloaded=5, errors=2)
        self.assertEqual(code, 1)
        self.assertIn("5 files installed", out)
        self.assertIn("2 files failed", out)

    def test_interruption_is_resumable_and_exits_130(self):
        out, code = self._report(downloaded=431, interrupted=True)
        self.assertEqual(code, 130)
        self.assertIn("carry on", out)
        self.assertIn("Nothing is lost", out)

    def test_one_file_reads_as_one_file(self):
        out, _ = self._report(downloaded=1)
        self.assertIn("1 file installed", out)
        self.assertNotIn("1 files", out)

    def test_every_destination_is_named(self):
        out, _ = self._report(
            paths=[Path("/a/bios"), Path("/b/bios")], downloaded=2
        )
        self.assertIn("/a/bios", out)
        self.assertIn("/b/bios", out)


class TestFreeSpaceGuard(unittest.TestCase):
    """The run refuses before writing when the volume cannot hold it."""

    def setUp(self):
        self.root = scratch_dir(self)
        self.real = install.shutil.disk_usage

    def tearDown(self):
        install.shutil.disk_usage = self.real
        shutil.rmtree(self.root, ignore_errors=True)

    def _run(self, free: int, needed: int, path: Path | None = None):
        install.shutil.disk_usage = lambda _p: SimpleNamespace(free=free)
        buf = io.StringIO()
        code = 0
        with contextlib.redirect_stderr(buf):
            try:
                reported(install._check_free_space, path or self.root, needed)
            except SystemExit as exc:
                code = exc.code
        return buf.getvalue(), code

    def test_enough_space_says_nothing(self):
        out, code = self._run(free=10_000, needed=1_000)
        self.assertEqual((out, code), ("", 0))

    def test_short_of_space_names_both_numbers_and_stops(self):
        """Nothing was installed: code 2, as the exit table says, not the 1
        of a partial install."""
        out, code = self._run(free=1_000, needed=5_000)
        self.assertEqual(code, 2)
        self.assertIn("Needed", out)
        self.assertIn("Free", out)
        self.assertIn("--dest", out)

    def test_short_of_space_is_an_event_with_both_numbers(self):
        """A --events reader got only end code 2, like any other stop."""
        install.shutil.disk_usage = lambda _p: SimpleNamespace(free=1_000)
        events = io.StringIO()
        with unittest.mock.patch.object(install.EVENTS, "stream", events), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            reported(install._check_free_space, self.root, 5_000, "batocera")
        said = [json.loads(line) for line in events.getvalue().splitlines()]
        self.assertEqual(said[0], {"event": "no_space", "platform": "batocera",
                                   "folder": str(self.root), "bytes_needed": 5_000,
                                   "bytes_free": 1_000})
        self.assertEqual((said[1]["event"], said[1]["stage"], said[1]["reason"]),
                         ("error", "space", "drive_full"))

    def test_probe_climbs_to_an_existing_ancestor(self):
        missing = self.root / "not" / "created" / "yet"
        out, code = self._run(free=1, needed=2, path=missing)
        self.assertEqual(code, 2)

    def test_the_space_check_comes_before_the_folder(self):
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        check = source.index("_check_free_space(bios_path, written")
        self.assertLess(check, source.index("bios_path.mkdir(parents=True, exist_ok=True)"))


class ThePlansCountWhatTheRunRefusesOn(unittest.TestCase):
    """The line plan counted the absent files alone: a file in place with
    the wrong bytes, to be replaced, gave no warning at 100 B free, and the
    run stopped for space right after Enter."""

    def setUp(self):
        self.root = scratch_dir(self)
        self.addCleanup(shutil.rmtree, self.root, True)
        # The plan's reads are kept for the check after it.
        install.head_reads_done()
        self.addCleanup(install.head_reads_done)
        wrong = b"w" * 1000
        (self.root / "a.bin").write_bytes(wrong)
        right = b"r" * 1000
        self.files = [{"dest": "a.bin", "size": 1000,
                       "sha1": hashlib.sha1(right).hexdigest()}]

    def short(self, free: int, trees: list[dict] | None = None) -> tuple[int, int] | None:
        with unittest.mock.patch.object(install.shutil, "disk_usage",
                                        lambda _p: SimpleNamespace(free=free)):
            return install._space_short(self.root, self.files, trees or [])

    def test_a_file_to_replace_is_counted(self):
        self.assertEqual(self.short(100), (1000, 100))
        self.assertEqual(self.short(100), (install.bytes_written(self.files, []), 100))

    def test_a_file_in_place_is_not(self):
        (self.root / "a.bin").write_bytes(b"r" * 1000)
        self.assertIsNone(self.short(100))

    def test_the_data_trees_count(self):
        (self.root / "a.bin").write_bytes(b"r" * 1000)
        tree = {"ref": "t", "dest": "tree", "systems": [], "files": {
            "x.bin": {"sha1": hashlib.sha1(b"x").hexdigest(), "size": 500}}}
        with unittest.mock.patch.object(install, "_offline_only", return_value=False):
            # The tree's file, and its source beside it until it is read:
            # a list that records no archive size gives the files' sizes.
            self.assertEqual(self.short(100, [tree]), (1000, 100))

    def test_what_fits_whole_reads_nothing(self):
        with unittest.mock.patch.object(install, "read_in_place") as read:
            self.assertIsNone(self.short(10_000))
        read.assert_not_called()

    def test_a_check_says_the_space_it_needs(self):
        self.assertIn("space", install.EVENT_KEYS)
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        self.assertIn('EVENTS.emit("space", platform=plat, bytes=tally.space_bytes)', source)


class TheDataTreesCountInTheFreeSpace(unittest.TestCase):
    """The space check held only the BIOS files: 18.8 KB passed on a card
    with 20 MB free, then 55.4 MB of archives came and 81.8 MB were written,
    against the page's promise to refuse before writing anything."""

    def _run(self, *frees_after_bios: int) -> list[tuple[int, str, list]]:
        """One run per free size, in one folder: the second finds the BIOS
        files the first installed."""
        from types import SimpleNamespace

        from tests.installsupport import FakeRepository

        member = os.urandom(4096)
        results = []
        # The run is a Linux one whatever the host: under WSL main() reads
        # the Windows side and keeps that in the module, where the Windows
        # detection tests run after it found D:\ turned into /mnt/d.
        with FakeRepository() as repo, unittest.mock.patch.dict(os.environ, RETROBIOS_OS="linux"), \
                unittest.mock.patch.dict(install._WSL):
            listed = json.loads((repo.root / "install" / "retroarch.json").read_text())
            listed["data_directories"] = [{
                "ref": "tree", "dest": "tree", "type": "zip", "archive_size": 50_000_000,
                "url": "https://example.invalid/tree.zip", "systems": ["nintendo-gba"],
                "files": {"Sys/a.bin": {"sha1": hashlib.sha1(member).hexdigest(),
                                        "size": len(member)}}}]
            (repo.root / "install" / "retroarch.json").write_text(json.dumps(listed))
            bios = sum(len(payload) for payload, *_ in FakeRepository.PAYLOADS.values())
            base = repo.env()["RETROBIOS_BASE_URL"]
            for after in frees_after_bios:
                out = io.StringIO()
                fetched: list = []
                free = bios + after
                with unittest.mock.patch.object(
                        sys, "argv", ["install.py", "--platform", "retroarch", "--dest",
                                      str(repo.dest), "--no-input"]), \
                        unittest.mock.patch.dict(os.environ, {"RETROBIOS_BASE_URL": base}), \
                        unittest.mock.patch.object(install.shutil, "disk_usage",
                                                   lambda _p, free=free: SimpleNamespace(free=free)), \
                        unittest.mock.patch.object(
                            install, "install_data_directory",
                            lambda entry, *a, fetched=fetched, **k: fetched.append(entry["ref"]) or {
                                "present": 0, "installed": 1, "updated": 0, "changed": 0, "absent": 0,
                                "error": "", "not_kept": []}), \
                        contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                    try:
                        install.main()
                        code = 0
                    except SystemExit as exc:
                        code = exc.code
                results.append((code, out.getvalue(), repo.installed() + fetched))
        return results

    def test_a_card_short_for_the_trees_is_refused_before_any_write(self):
        ((code, said, written),) = self._run(20_000_000)
        self.assertEqual(code, 2, said)
        self.assertIn("Not enough space", said)
        self.assertEqual(written, [])

    def test_room_for_the_trees_goes_on(self):
        ((code, said, written),) = self._run(60_000_000)
        self.assertEqual(code, 0, said)
        self.assertIn("tree", written)

    def test_the_trees_alone_are_checked_too(self):
        """Every BIOS file in place: the trees were written unchecked."""
        _first, (code, said, written) = self._run(60_000_000, -1)
        self.assertEqual(code, 2, said)
        self.assertIn("Not enough space", said)
        self.assertNotIn("tree", written)

    def test_the_bytes_counted(self):
        state = (Path("x"), {"a": {"size": 10}, "b": {"size": 5}}, 0)
        entry = {"archive_size": 1000}
        with unittest.mock.patch.object(install.LOCAL, "pack", None), \
                unittest.mock.patch.object(install, "_offline_only", return_value=False):
            self.assertEqual(install.data_space_bytes([(entry, state), (entry, state)]), 1030)
        with unittest.mock.patch.object(install.LOCAL, "pack", object()):
            self.assertEqual(install.data_space_bytes([(entry, state)]), 15)


class AMissingDestIsSaid(unittest.TestCase):
    """--dest ~/.config/retroarh/system (a typo) was created with every
    missing parent and reported done, and --check on it said only
    "0/7 present"."""

    def _call(self, dest: Path, ask: bool, answer: str = "") -> tuple[str, object]:
        out = io.StringIO()
        code = None
        with contextlib.redirect_stdout(out), \
                unittest.mock.patch("builtins.input", return_value=answer):
            try:
                install._missing_dest(dest, ask)
            except SystemExit as exc:
                code = exc.code
        return out.getvalue(), code

    def test_an_existing_folder_says_nothing(self):
        root = scratch_dir(self)
        self.assertEqual(self._call(root, True), ("", None))

    def test_a_deep_missing_path_is_asked_and_no_is_the_default(self):
        root = scratch_dir(self)
        dest = root / "retroarh" / "system"
        out, code = self._call(dest, True, "")
        self.assertEqual(code, 2)
        self.assertIn(f"The nearest folder that does: {root}", out)
        self.assertFalse((root / "retroarh").exists())
        self.assertEqual(self._call(dest, True, "y")[1], None)

    def test_only_y_or_yes_creates_the_folders(self):
        # A default-no question read "yeah" as yes, as no other one does.
        root = scratch_dir(self)
        self.assertEqual(self._call(root / "a" / "b", True, "yeah")[1], 2)
        self.assertFalse((root / "a").exists())

    def test_one_missing_level_or_no_terminal_is_said_not_asked(self):
        root = scratch_dir(self)
        # A "no" that was asked would stop the run with 2. Said with
        # --verbose: the folder is made, and the run names it.
        install.OUTPUT.verbose = False
        self.assertEqual(self._call(root / "bios", True, "n"), ("", None))
        self.addCleanup(setattr, install.OUTPUT, "verbose", False)
        install.OUTPUT.verbose = True
        out, code = self._call(root / "bios", True, "n")
        self.assertIsNone(code)
        self.assertIn("does not exist", out)
        out, code = self._call(root / "a" / "b", False, "n")
        self.assertIsNone(code)
        self.assertIn("does not exist", out)


class ADestThatIsAFileIsNamed(unittest.TestCase):
    """--dest naming a file, or a path under one, failed at mkdir with
    EEXIST or ENOTDIR, and the run said this user cannot write there and
    offered a sudo command that fails the same way."""

    def _run(self, dest: Path) -> subprocess.CompletedProcess:
        env = dict(os.environ, RETROBIOS_OS="linux")
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retroarch",
             "--dest", str(dest), "--manifest", str(REPO_ROOT / "install" / "retroarch.json"),
             "--system", "nintendo-gba", "--yes", "--events", "--offline"],
            env=env, capture_output=True, text=True, timeout=120, check=False,
            stdin=subprocess.DEVNULL)

    def test_the_file_is_named_and_sudo_is_not_offered(self):
        root = scratch_dir(self)
        (root / "scph5501.bin").write_bytes(b"x")
        for dest, words in (
            (root / "scph5501.bin", f"{root / 'scph5501.bin'} is a file, not a folder"),
            (root / "scph5501.bin" / "sub",
             f"cannot be a folder: {root / 'scph5501.bin'} is a file"),
        ):
            with self.subTest(dest=dest):
                proc = self._run(dest)
                self.assertEqual(proc.returncode, 1, proc.stderr)
                self.assertIn(words, proc.stderr)
                self.assertNotIn("sudo", proc.stderr)
                errors = [json.loads(line) for line in proc.stdout.splitlines()
                          if line.startswith("{") and '"error"' in line]
                self.assertEqual([(e["stage"], e["reason"]) for e in errors],
                                 [("dest", "not_a_folder")])
                self.assertEqual((root / "scph5501.bin").read_bytes(), b"x")


class AFolderThatRefusesWritesIsNamed(unittest.TestCase):
    """A read-only BIOS folder ended the run on a traceback (a subfolder to
    create), or on three retries per file and "once that is resolved", and a
    platform named but not detected was told to use sudo, which on another
    machine creates /userdata/bios on the wrong disk."""

    ENTRY = {"dest": "mame2015/neogeo.zip", "repo_path": "bios/x", "size": 4}

    def test_a_subfolder_that_cannot_be_made_is_a_failure_not_a_crash(self):
        with unittest.mock.patch.object(Path, "mkdir", side_effect=PermissionError(13, "denied")):
            result = install._download_one(self.ENTRY, Path("/userdata/bios"))
        self.assertEqual(result, ("mame2015/neogeo.zip", False, install.NOT_WRITABLE))

    def test_a_refused_write_is_not_retried(self):
        class _Body(io.BytesIO):
            status, headers = 200, {"Content-Length": "4"}

        with tempfile.TemporaryDirectory() as tmp, \
                unittest.mock.patch.object(install.urllib.request, "urlopen",
                                  return_value=_Body(b"data")) as opened, \
                unittest.mock.patch.object(install.tempfile, "NamedTemporaryFile",
                                  side_effect=PermissionError(13, "denied")):
            result = install._download_one(self.ENTRY, Path(tmp))
        self.assertEqual(result[1:], (False, install.NOT_WRITABLE))
        self.assertEqual(opened.call_count, 1)

    def _summary_for(self, assumed):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit):
            install._report_outcome(paths=[Path("/userdata/bios")], downloaded=0, up_to_date=0,
                                    errors=1, omitted=0, interrupted=False,
                                    details=install.OutcomeDetails(failures=[("neogeo.zip", install.NOT_WRITABLE)],
                                                                   assumed=assumed))
        return buf.getvalue()

    def test_the_summary_says_sudo_on_the_console_and_dest_elsewhere(self):
        here = self._summary_for(set())
        self.assertIn("sudo", here)
        guessed = self._summary_for({Path("/userdata/bios")})
        self.assertIn("--dest", guessed)
        self.assertNotIn("sudo", guessed)


class TestStopFlag(unittest.TestCase):
    """Ctrl+C ends the run instead of letting the queue drain."""

    def tearDown(self):
        install._stop.clear()

    def test_worker_returns_immediately_once_stopped(self):
        install._stop.set()
        dest, ok, reason = install._download_one({"dest": "x.bin"}, Path("/nowhere"))
        self.assertEqual((dest, ok, reason), ("x.bin", False, "stopped"))

    def test_download_files_reports_no_interruption_normally(self):
        failed, interrupted = install.download_files([], Path("/nowhere"))
        self.assertEqual((failed, interrupted), ([], False))


@unittest.skipIf(os.name == "nt" or os.geteuid() == 0, "needs a folder this user cannot write")
class AnUnwritableFolderIsCodeTwo(unittest.TestCase):
    """A BIOS folder that could not be created ended with 1, while the same
    folder existing read-only ended with the documented 2."""

    def test_both_shapes_exit_two(self):
        base = loopback.serve(self, REPO_ROOT)
        home = Path(tempfile.mkdtemp())
        locked = home / "locked"
        locked.mkdir()
        locked.chmod(0o555)
        self.addCleanup(shutil.rmtree, home, True)
        self.addCleanup(locked.chmod, 0o755)
        env = {
            **os.environ,
            "HOME": str(home),
            "RETROBIOS_OS": "linux",
            "RETROBIOS_BASE_URL": base,
        }
        for dest in (locked / "sub", locked):
            with self.subTest(dest=dest.name):
                proc = subprocess.run(
                    [sys.executable, "install.py", "--platform", "retroarch",
                     "--dest", str(dest), "--system", "atari-lynx", "--no-input"],
                    cwd=str(REPO_ROOT), env=env, capture_output=True, text=True,
                    timeout=300, check=False,
                )
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)


class SudoAdviceNamesTheFolder(unittest.TestCase):
    """"Run the same command with sudo" re-ran detection under root's HOME,
    found nothing, installed under /root and reported success."""

    def test_the_advice_carries_platform_and_folder(self):
        advice = install._write_advice(Path("/media/card/Emulation/bios"), False, "emudeck")
        self.assertIn("--platform emudeck", advice)
        self.assertIn("--dest /media/card/Emulation/bios", advice)

    def test_the_closing_report_passes_the_platform(self):
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        self.assertIn("platform_of={path: plat for plat, path in platforms}", source)

    @unittest.skipUnless(hasattr(os, "statvfs"), "statvfs reads mount flags")
    def test_a_read_only_mount_is_not_sent_to_sudo(self):
        """A card Linux mounted read-only after a dirty unplug was answered
        with 'run it again with sudo', which fails the same way."""
        real = os.statvfs(".")
        flags = SimpleNamespace(f_flag=real.f_flag | os.ST_RDONLY)
        for plat in ("retroarch", ""):
            with self.subTest(platform=plat), \
                    unittest.mock.patch.object(install.os, "statvfs", return_value=flags):
                advice = install._write_advice(Path("/media/card/bios"), False, plat)
            self.assertIn("mounted read-only", advice)
            self.assertNotIn("Run it again with sudo", advice)
            self.assertNotIn("sudo python3", advice)
        writable = SimpleNamespace(f_flag=real.f_flag & ~os.ST_RDONLY)
        with unittest.mock.patch.object(install.os, "statvfs", return_value=writable):
            self.assertIn("sudo", install._write_advice(Path("/media/card/bios"), False, "retroarch"))


class ACheckNamesWhatTheCollectionLacks(unittest.TestCase):
    """--check counted the required files the manifest leaves out and named
    none, then said all files were up to date: on Recalbox, c3.555 stayed
    unnamed for a user asking why Caesar III would not start."""

    def test_recalbox_caesar3(self):
        import shutil
        import subprocess

        manifest = json.loads((REPO_ROOT / "install" / "recalbox.json").read_text())
        lacking = sorted(
            e["dest"] for e in manifest.get("omitted_files", [])
            if e.get("required") and e.get("system") == "caesar3"
        )
        if not lacking:
            self.skipTest("the Recalbox manifest omits no required caesar3 file")
        base = loopback.serve(self, REPO_ROOT)
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, True)
        env = {
            **os.environ, "HOME": str(home), "RETROBIOS_OS": "linux",
            "RETROBIOS_BASE_URL": base,
        }
        proc = subprocess.run(
            [sys.executable, "-I", "install.py", "--platform", "recalbox",
             "--no-input", "--dest", str(home / "bios"), "--check", "--verbose"],
            cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=300,
            check=False,
        )
        self.assertNotIn("Traceback", proc.stderr)
        for dest in lacking:
            self.assertIn(dest, proc.stdout)
        self.assertNotIn("unsafe", proc.stdout)


class AFullDriveIsSaidAsOne(unittest.TestCase):
    """A card filling up during a tree rebuild read `fbneo-cheats: could not
    read https://...: [Errno 28] No space left on device`, putting the cause
    on the source, and the run ended on `Run the same command again`."""

    def test_the_tree_reports_the_drive(self):
        work = scratch_dir(self)
        entry = {"ref": "fbneo-cheats", "dest": "fbneo/cheats", "type": "zip",
                 "url": "https://example.invalid/c.zip", "systems": ["arcade"],
                 "files": {"1941r1.ini": {"sha1": "1" * 40, "size": 4}}}

        class Full(io.RawIOBase):
            def readable(self):
                return True

            def readinto(self, buffer):
                return 0

        def members(_archive, _entry):
            yield "1941r1.ini", 4, lambda: io.BufferedReader(Full())

        def full(*_args, **_kwargs):
            raise OSError(errno.ENOSPC, "No space left on device")

        with unittest.mock.patch.object(
                install, "_fetch_archive",
                lambda url, d, progress=None, keep=None: Path(d) / "a"), \
                unittest.mock.patch.object(install, "_archive_members", members), \
                unittest.mock.patch.object(install, "_install_data_member", full):
            counts = install.install_data_directory(entry, work)
        self.assertEqual(counts["error"], install.DRIVE_FULL)

    def test_the_end_names_space_not_a_retry(self):
        bios = scratch_dir(self)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as ended:
            install._report_outcome([bios], 7, 0, 1, 0, False,
                                    details=install.OutcomeDetails(failures=[("fbneo-cheats", install.DRIVE_FULL)]))
        text = out.getvalue()
        self.assertEqual(ended.exception.code, 1)
        self.assertIn("is full: free up space, or install to another drive with --dest", text)
        self.assertNotIn("retry only those", text)

    def test_a_bios_file_on_a_full_drive_is_not_retried(self):
        bios = scratch_dir(self)
        attempts: list = []

        def urlopen(*_args, **_kwargs):
            attempts.append(1)
            raise OSError(errno.ENOSPC, "No space left on device")

        entry = {"dest": "a.bin", "repo_path": "bios/a.bin", "size": 4,
                 "sha1": "1" * 40, "sha256": "2" * 64}
        with unittest.mock.patch.object(install.urllib.request, "urlopen", urlopen), \
                unittest.mock.patch.object(install, "_network_allowed", lambda url: None), \
                unittest.mock.patch.object(install, "_retry_delay", lambda *a: 0):
            result = install._download_one(entry, bios)
        self.assertEqual(result[1:], (False, install.DRIVE_FULL))
        self.assertEqual(len(attempts), 1)


class ACheckThatFindsFilesMissingIsNoFailure(unittest.TestCase):
    """--check ended on 1 for files missing as for a list refused or a
    --from folder that does not exist: a scheduled check could not tell a
    BIOS folder to complete from a tool that never ran."""

    def test_missing_is_3_and_a_failure_stays_1(self):
        from tests.installsupport import FakeRepository

        with FakeRepository() as repo:
            missing = repo.run("--no-input", "--check")
            nowhere = repo.run("--no-input", "--check", "--from", str(repo.root / "nope"))
            repo.run("--no-input")
            complete = repo.run("--no-input", "--check")
        self.assertEqual(missing.returncode, 3, missing.stdout + missing.stderr)
        self.assertEqual(nowhere.returncode, 1, nowhere.stdout + nowhere.stderr)
        self.assertEqual(complete.returncode, 0, complete.stdout + complete.stderr)


class TheInstallerSaysWhatItFound(unittest.TestCase):
    """--check gave a count and no name, a read-only folder printed a line
    per file, a piped log put errors before their step, and Ctrl+C while
    the file list was fetched ended on a socket traceback."""

    def setUp(self):
        import shutil

        base = loopback.serve(self, REPO_ROOT)
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home, True)
        self.env = {
            **os.environ, "HOME": str(self.home), "RETROBIOS_OS": "linux",
            "RETROBIOS_BASE_URL": base,
        }

    def _run(self, *extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "install.py", "--platform", "retroarch", "--no-input", *extra],
            cwd=REPO_ROOT, env=self.env, capture_output=True, text=True, timeout=300,
            check=False,
        )

    def test_check_names_the_files(self):
        dest = self.home / "system"
        self.assertEqual(self._run("--dest", str(dest), "--system", "atari-lynx", "--yes").returncode, 0)
        (dest / "lynxboot.img").write_bytes(b"corrupt")
        proc = self._run("--dest", str(dest), "--system", "atari-lynx", "--check")
        self.assertEqual(proc.returncode, 3)
        # A wrong copy is named in every mode: it is what the user acts on.
        self.assertIn("1 file to download.", proc.stdout)
        self.assertIn("wrong copy: lynxboot.img", proc.stdout)
        self.assertIn("without --check", proc.stdout)

    def test_a_read_only_folder_is_said_once(self):
        if os.geteuid() == 0:
            self.skipTest("root writes anywhere")
        dest = self.home / "system"
        dest.mkdir()
        dest.chmod(0o500)
        self.addCleanup(dest.chmod, 0o700)
        proc = self._run("--dest", str(dest), "--system", "atari-lynx", "--yes")
        output = proc.stdout + proc.stderr
        self.assertNotEqual(proc.returncode, 0)
        self.assertLessEqual(output.count("FAILED"), 1, output)
        self.assertIn("failed: 2 files (folder not writable)", output)

    def test_a_piped_log_keeps_its_order(self):
        proc = subprocess.run(
            [sys.executable, "install.py", "--platform", "retroarch", "--no-input",
             "--verbose", "--target", "no-such-target", "--dest", str(self.home / "s")],
            cwd=REPO_ROOT, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=300, check=False,
        )
        banner = proc.stdout.find("RetroBIOS")
        error = proc.stdout.lower().find("unknown target")
        self.assertGreaterEqual(banner, 0, proc.stdout)
        self.assertGreater(error, banner, proc.stdout)

    def test_ctrl_c_before_the_downloads_is_a_stop(self):
        import signal
        import socket

        silent = socket.socket()
        silent.bind(("127.0.0.1", 0))
        silent.listen(1)
        self.addCleanup(silent.close)
        env = {**self.env, "RETROBIOS_BASE_URL": f"http://127.0.0.1:{silent.getsockname()[1]}"}
        proc = subprocess.Popen(
            [sys.executable, "install.py", "--platform", "retroarch", "--no-input",
             "--dest", str(self.home / "s")],
            cwd=REPO_ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        import time

        time.sleep(3)
        proc.send_signal(signal.SIGINT)
        out, err = proc.communicate(timeout=60)
        self.assertEqual(proc.returncode, 130, out + err)
        self.assertIn("Stopped", out)
        self.assertNotIn("Traceback", err)


class HintsGiveTheUsersOwnCommandBack(unittest.TestCase):
    """A one-liner user was told to run python3 install.py, a file they do
    not have, and the write advice dropped --system, turning a retry of 2
    files into 8069, with sudo on Windows."""

    def setUp(self):
        patcher = unittest.mock.patch.object(install, "_INVOCATION", install.Invocation())
        patcher.start()
        self.addCleanup(patcher.stop)

    def _record(self, *argv: str) -> None:
        args = SimpleNamespace(
            system=None, core=None, emulator=None, region=None, target=None,
            cores_dir=None, every_board=False, installed_cores=False,
            standalone_copies=False, check=False, dry_run=False, no_game_data=False,
            declared_only=False,
        )
        flags = list(argv)
        while flags:
            flag = flags.pop(0)
            attr = flag[2:].replace("-", "_")
            if attr in ("system", "core", "emulator", "region"):
                setattr(args, attr, [*(getattr(args, attr) or []), flags.pop(0)])
            else:
                setattr(args, attr, True)
        install._INVOCATION.record(args)

    def test_the_shell_one_liner_is_rebuilt(self):
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": "sh"}):
            hint = "\n".join(install._manual_usage_hint("linux"))
        self.assertIn("/i | sh -s -- --platform retroarch", hint)
        self.assertNotIn("python3 install.py", hint)
        self.assertIn(install.INSTALLER_PAGE, hint)

    def test_a_clone_keeps_python(self):
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": ""}):
            hint = "\n".join(install._manual_usage_hint("linux"))
        self.assertIn("python3 install.py --platform retroarch", hint)

    def test_a_listing_hint_keeps_the_listing(self):
        """--list-systems with nothing detected was answered with a full
        install command: the listing flag gone, a --dest added."""
        home = scratch_dir(self)
        env = {**os.environ, "HOME": str(home), "RETROBIOS_OS": "linux",
               "RETROBIOS_BOOTSTRAP": ""}
        for flag in ("--list-systems", "--list-cores", "--list-emulators", "--list-targets"):
            with self.subTest(flag=flag):
                proc = _install_run(env, flag, "--no-input")
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn(f"python3 install.py --platform retroarch {flag}", proc.stdout)
                self.assertNotIn("--dest", proc.stdout)

    def test_the_write_advice_keeps_the_narrowing(self):
        self._record("--system", "atari-lynx", "--region", "us")
        install._INVOCATION.os_type = "linux"
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": "sh"}):
            advice = install._write_advice(Path("/media/ro"), False, "retroarch")
        self.assertIn("| sudo sh -s -- --platform retroarch --dest /media/ro "
                      "--system atari-lynx --region us", advice)

    def test_the_platforms_own_list_is_kept_in_the_hint(self):
        self._record("--declared-only", "--system", "atari-lynx")
        install._INVOCATION.os_type = "linux"
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": ""}):
            command = install._INVOCATION.command("retroarch", None)
        self.assertIn("--system atari-lynx --declared-only", command)

    def test_windows_has_no_sudo(self):
        self._record("--system", "atari-lynx")
        install._INVOCATION.os_type = "windows"
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": "ps1"}):
            advice = install._write_advice(Path("C:/Program Files/RetroArch/system"),
                                           False, "retroarch")
        self.assertNotIn("sudo", advice)
        self.assertIn("administrator", advice)
        self.assertIn("/i.ps1", advice)
        self.assertIn("--system atari-lynx", advice)

    def test_a_full_drive_keeps_the_platform(self):
        install._INVOCATION.os_type = "linux"
        err = io.StringIO()
        with unittest.mock.patch.object(install.shutil, "disk_usage",
                                        return_value=SimpleNamespace(free=1)), \
                contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            reported(install._check_free_space, scratch_dir(self), 10, "batocera")
        self.assertIn("--platform batocera --dest <folder on another drive>", err.getvalue())

    def test_the_one_liner_tells_the_installer_how_it_was_started(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe = root / "probe.py"
            probe.write_text("import os\nprint('bootstrap:', os.environ.get('RETROBIOS_BOOTSTRAP'))\n")
            fake_bin = root / "bin"
            fake_bin.mkdir()
            (fake_bin / "curl").write_text(
                "#!/bin/sh\noutput=\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = --output ]; then output=$2; shift 2; else shift; fi\n"
                "done\n"
                f"cp -- {shlex.quote(str(probe))} \"$output\"\n")
            (fake_bin / "curl").chmod(0o755)
            env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                   "TMPDIR": str(root),
                   "RETROBIOS_INSTALL_URL": "https://example.invalid/install.py",
                   "RETROBIOS_INSTALL_SHA256": hashlib.sha256(probe.read_bytes()).hexdigest()}
            proc = subprocess.run(["sh", "-s"], cwd=root, env=env, capture_output=True,
                                  input=(REPO_ROOT / "install.sh").read_text(),
                                  text=True, timeout=30, check=False)
        self.assertIn("bootstrap: sh", proc.stdout, proc.stderr)

    def test_the_help_has_examples_and_the_page(self):
        env = {**os.environ, "RETROBIOS_BOOTSTRAP": "sh"}
        proc = _install_run(env, "--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("examples:", proc.stdout)
        self.assertIn("/i | sh -s -- --platform batocera --dest", proc.stdout)
        self.assertIn(install.INSTALLER_PAGE, proc.stdout)


class APlanGroupFitsItsLine(unittest.TestCase):
    """Batocera's group of systems sharing MAME's device ROMs was one plan
    line of 732 characters: counted as one row, it wrapped to ten and the
    total scrolled out of sight."""

    def _plan(self, files: list[dict], size: tuple[int, int], verbose: bool = False) -> str:
        out = io.StringIO()
        with unittest.mock.patch.object(install.shutil, "get_terminal_size",
                                        return_value=os.terminal_size(size)), \
                contextlib.redirect_stdout(out):
            install._print_plan(files, Path("dest"), install.Terminal(io.StringIO()),
                                verbose=verbose)
        return out.getvalue()

    def test_a_wide_group_is_named_by_its_first_two(self):
        shared = [f"system-number-{n:02d}" for n in range(40)]
        text = self._plan([{"dest": "dev.rom", "size": 1, "systems": shared}], (80, 40))
        self.assertIn("system-number-00, system-number-01 and 38 more systems", text)
        self.assertLess(max(map(len, text.splitlines())), 80)
        self.assertIn("system-number-39", self._plan(
            [{"dest": "dev.rom", "size": 1, "systems": shared}], (80, 40), verbose=True))

    def test_wrapped_rows_count_against_the_screen(self):
        # Six lines that each wrap to three rows on a 20-column terminal of
        # 20 rows: 18 rows of listing, past what the screen leaves it.
        files = [{"dest": f"{'x' * 50}{n}.bin", "size": 1, "systems": [f"s{n}"]}
                 for n in range(3)]
        text = self._plan(files, (20, 20))
        self.assertIn("the largest first", text)


class ReadersAreThePlatformsCores(unittest.TestCase):
    """--check said bbcb.zip is "read by clk, mame, mame0258, mame0278" on
    Batocera: system_cores reaches every profile, Recalbox's builds too."""

    def test_an_off_platform_core_is_not_named(self):
        manifest = {
            "system_cores": {"bbc": ["clk", "mame", "mame0258"]},
            "files": [{"dest": "bbcb.zip", "systems": ["bbc"], "cores": None},
                      {"dest": "other.rom", "systems": ["x"], "cores": ["clk", "mame"]}],
        }
        self.assertEqual(install.readers(manifest["files"][0], manifest), ["clk", "mame"])

    def test_on_the_real_lists(self):
        for plat, dest, absent in (("batocera", "bbcb.zip", "mame0258"),
                                   ("retroarch", "prboom.wad", "bizhawk")):
            manifest = json.loads((REPO_ROOT / "install" / f"{plat}.json").read_text())
            [entry] = [e for e in manifest["files"] + manifest["omitted_files"]
                       if e["dest"] == dest]
            with self.subTest(platform=plat):
                self.assertNotIn(absent, install.readers(entry, manifest))


class WhatTheCollectionLacksSaysForWhom(unittest.TestCase):
    """Required files the installer cannot supply were listed by bare name:
    DARK.GOB, Data.rsdk, ... and 69 more, with no system and no emulator."""

    def test_grouped_by_system_with_its_emulators(self):
        entries = [
            {"dest": "DARK.GOB", "system": "dark-forces", "cores": ["theforceengine"]},
            {"dest": "SOUNDS.GOB", "system": "dark-forces", "cores": ["theforceengine"]},
            {"dest": "Data.rsdk", "system": "sonic-mania", "cores": ["sonicmania"]},
        ]
        lines = install._needed_lines(entries, "Needed to start an emulator")
        self.assertIn("    dark-forces (theforceengine): DARK.GOB, SOUNDS.GOB", lines)
        self.assertIn("    sonic-mania (sonicmania): Data.rsdk", lines)
        self.assertIn("(3 files)", lines[0])
        # The page of each emulator under its group: the index alone left a
        # search over several hundred pages.
        self.assertEqual(lines[lines.index("    dark-forces (theforceengine): DARK.GOB, "
                                           "SOUNDS.GOB") + 1],
                         f"      {install.SITE_URL}emulators/theforceengine/")
        self.assertIn(f"      {install.SITE_URL}emulators/sonicmania/", lines)
        self.assertNotIn(f"{install.SITE_URL}emulators/\n", "\n".join(lines) + "\n")

    def test_a_group_with_no_emulator_keeps_the_index(self):
        lines = install._needed_lines([{"dest": "x.bin", "system": "x"}], "Needed")
        self.assertIn(f"{install.SITE_URL}emulators/", lines[-1])


class AnErrorIsOneShortSentence(unittest.TestCase):
    """A message on stderr says what to do in a few words: one of 35 words
    asked a beginner to read a paragraph to find the option to give."""

    BUDGET = 25

    def test_every_stderr_message_is_short(self):
        import ast

        tree = ast.parse((REPO_ROOT / "install.py").read_text(encoding="utf-8"))
        long = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", getattr(node.func, "attr", ""))
            to_err = any(k.arg == "file" and "stderr" in ast.unparse(k.value)
                         for k in node.keywords)
            if not (to_err or name == "error"):
                continue
            text = " ".join(ast.unparse(a) for a in node.args)
            if ".command(" in text:
                continue
            prose = re.sub(r"\{[^}]*\}", "X", text)
            words = len(re.findall(r"[A-Za-z']+", prose))
            if words > self.BUDGET:
                long.append((node.lineno, words))
        self.assertEqual(long, [])


class TheNextStepFitsWhereTheInstallerRuns(unittest.TestCase):
    """Run on a KNULLI device, the last line said "Next: start KNULLI and
    play.": the system it runs on is already started."""

    def test_on_the_device_detection_found(self):
        folder = Path("/userdata/bios")
        with unittest.mock.patch.dict(install._DETECTED_OS, {("knulli", folder): "KNULLI"},
                                      clear=True), \
                unittest.mock.patch.object(install, "_mounted_cards", return_value=[]):
            self.assertEqual(install.next_step_words({folder: "knulli"}, [folder]),
                             "Next: start a game.")

    def test_on_a_computer(self):
        folder = Path("/home/me/.config/retroarch/system")
        with unittest.mock.patch.dict(install._DETECTED_OS, clear=True), \
                unittest.mock.patch.object(install, "_mounted_cards", return_value=[]):
            self.assertEqual(install.next_step_words({folder: "retroarch"}, [folder]),
                             "Next: start RetroArch and play.")

    def test_a_card_mounted_on_a_computer(self):
        card = Path("/media/me/KNULLI")
        with unittest.mock.patch.dict(install._DETECTED_OS, clear=True), \
                unittest.mock.patch.object(install, "on_its_card", return_value=True):
            self.assertEqual(install.next_step_words({card / "bios": "knulli"}, [card / "bios"]),
                             install.NEXT_ON_CARD)


class EachRunSaysErrorsFromItsOwnOptions(unittest.TestCase):
    """--verbose set the raw-cause flag and nothing cleared it: a later run
    in the same process ended its clock message with the raw SSL text."""

    def test_a_run_without_verbose_clears_it(self):
        self.addCleanup(install._RAW_ERRORS.clear)
        install.say_raw_errors(True)
        self.assertTrue(install._RAW_ERRORS.is_set())
        install.say_raw_errors(False)
        self.assertFalse(install._RAW_ERRORS.is_set())


if __name__ == "__main__":
    unittest.main()
