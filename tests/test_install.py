"""Tests for install.py platform detection and config parsing."""
from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import functools
import hashlib
import http.server
import importlib.util
import errno
import io
import json
import os
import stat
import select
import shlex
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
import unittest.mock
import urllib.error
import zipfile
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("install", REPO_ROOT / "install.py")
install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(install)

sys.path.insert(0, str(REPO_ROOT / "tests"))
from netguard import module_guard  # noqa: E402

# What a stale pin's failure says: the fix is one command.
PIN_ADVICE = "install.py changed: python scripts/pin_installer.py rewrites both pins"

# No connection off the loopback and no card of the host reaches a test:
# the module fails at its end otherwise.
setUpModule, tearDownModule = module_guard("test_install")


def _tempdir(test: unittest.TestCase) -> str:
    """A scratch directory under the repository's tmp/, removed after the test.

    The system temp directory is a RAM disk here, and directories left by
    every run piled up on it.
    """
    scratch = REPO_ROOT / "tmp"
    scratch.mkdir(exist_ok=True)
    path = tempfile.mkdtemp(dir=str(scratch))
    test.addCleanup(shutil.rmtree, path, True)
    return path


class TestShellUnquote(unittest.TestCase):
    def test_plain_value(self):
        self.assertEqual(install._shell_unquote("/userdata/bios"), "/userdata/bios")

    def test_double_quoted(self):
        self.assertEqual(install._shell_unquote('"/home/deck/Emulation"'), "/home/deck/Emulation")

    def test_single_quoted(self):
        self.assertEqual(install._shell_unquote("'/home/deck/Emulation'"), "/home/deck/Emulation")

    def test_concatenated_quoted_unquoted(self):
        # EmuDeck SD card layout (issue: quote left in the middle of the path)
        self.assertEqual(
            install._shell_unquote('"/run/media/deck/EmuSD"/Emulation'),
            "/run/media/deck/EmuSD/Emulation",
        )

    def test_concatenated_preserves_spaces_in_quotes(self):
        self.assertEqual(
            install._shell_unquote('"/run/media/deck/My Card"/Emulation'),
            "/run/media/deck/My Card/Emulation",
        )

    def test_home_variable_expansion(self):
        old = os.environ.get("HOME")
        os.environ["HOME"] = "/home/deck"
        try:
            self.assertEqual(
                install._shell_unquote('"$HOME"/Emulation'),
                "/home/deck/Emulation",
            )
            self.assertEqual(
                install._shell_unquote('"${HOME}/Emulation"'),
                "/home/deck/Emulation",
            )
        finally:
            if old is not None:
                os.environ["HOME"] = old

    def test_single_quotes_do_not_expand(self):
        self.assertEqual(install._shell_unquote("'$HOME/x'"), "$HOME/x")

    def test_trailing_comment(self):
        self.assertEqual(install._shell_unquote("/data/bios # main dir"), "/data/bios")

    def test_unquoted_stops_at_whitespace(self):
        self.assertEqual(install._shell_unquote("/data/bios extra"), "/data/bios")

    def test_tilde_expansion(self):
        old = os.environ.get("HOME")
        os.environ["HOME"] = "/home/deck"
        try:
            self.assertEqual(install._shell_unquote("~/Emulation"), "/home/deck/Emulation")
        finally:
            if old is not None:
                os.environ["HOME"] = old


class TestParseBashVar(unittest.TestCase):
    def _write(self, content: str) -> Path:
        fd, path = tempfile.mkstemp(suffix=".sh")
        os.close(fd)
        Path(path).write_text(content, encoding="utf-8")
        self.addCleanup(os.unlink, path)
        return Path(path)

    def test_emudeck_sd_card_concatenation(self):
        path = self._write(
            'emulationPath="/run/media/deck/EmuSD"/Emulation\n'
            'biosPath="/run/media/deck/EmuSD"/Emulation/bios\n'
        )
        self.assertEqual(
            install._parse_bash_var(path, "emulationPath"),
            "/run/media/deck/EmuSD/Emulation",
        )
        self.assertEqual(
            install._parse_bash_var(path, "biosPath"),
            "/run/media/deck/EmuSD/Emulation/bios",
        )

    def test_emudeck_home_variable(self):
        old = os.environ.get("HOME")
        os.environ["HOME"] = "/home/deck"
        try:
            path = self._write('emulationPath="$HOME"/Emulation\n')
            self.assertEqual(
                install._parse_bash_var(path, "emulationPath"),
                "/home/deck/Emulation",
            )
        finally:
            if old is not None:
                os.environ["HOME"] = old

    def test_missing_key(self):
        path = self._write("other=1\n")
        self.assertIsNone(install._parse_bash_var(path, "emulationPath"))

    def test_missing_file(self):
        self.assertIsNone(
            install._parse_bash_var(Path("/nonexistent/settings.sh"), "emulationPath")
        )


class TestParseJsonPath(unittest.TestCase):
    def _write(self, data) -> Path:
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        Path(path).write_text(
            data if isinstance(data, str) else json.dumps(data), encoding="utf-8"
        )
        self.addCleanup(os.unlink, path)
        return Path(path)

    def test_retrodeck_rd_home_path(self):
        path = self._write(
            {"version": "1.0", "paths": {"rd_home_path": "/home/deck/retrodeck"}}
        )
        self.assertEqual(
            install._parse_json_path(path, "paths", "rd_home_path"),
            "/home/deck/retrodeck",
        )

    def test_missing_key_returns_none(self):
        path = self._write({"paths": {}})
        self.assertIsNone(install._parse_json_path(path, "paths", "rd_home_path"))

    def test_invalid_json_returns_none(self):
        path = self._write("{not json")
        self.assertIsNone(install._parse_json_path(path, "paths", "rd_home_path"))

    def test_empty_value_returns_none(self):
        path = self._write({"paths": {"rd_home_path": ""}})
        self.assertIsNone(install._parse_json_path(path, "paths", "rd_home_path"))

    def test_missing_file(self):
        self.assertIsNone(
            install._parse_json_path(Path("/nonexistent/rd.json"), "paths", "rd_home_path")
        )


class TestDefaultDests(unittest.TestCase):
    def test_retrodeck_defaults_to_rdhome(self):
        self.assertEqual(
            install.DEFAULT_DESTS["retrodeck"], Path.home() / "retrodeck"
        )

    def test_known_fixed_paths(self):
        self.assertEqual(install.DEFAULT_DESTS["batocera"], Path("/userdata/bios"))
        self.assertEqual(
            install.DEFAULT_DESTS["recalbox"], Path("/recalbox/share/bios")
        )

    def test_mister_defaults_to_games_on_the_sd_card(self):
        self.assertEqual(
            install.DEFAULT_DESTS["misterfpga"], Path("/media/fat/games")
        )


class TestDefaultsFollowTheRegistry(unittest.TestCase):
    """A platform named but not detected fell back to ~/bios on every OS for
    RetroArch, RetroBat, BizHawk and RomM, a folder none of them reads."""

    ENV = {"USERPROFILE": "/u", "APPDATA": "/u/AppData/Roaming"}

    def _expand(self, raw: str) -> Path:
        text = raw.replace("$HOME", str(Path.home()))
        for name, value in self.ENV.items():
            text = text.replace(f"%{name}%", value)
        return Path(text.replace("\\", "/"))

    def test_the_default_is_a_folder_detection_looks_for(self):
        import yaml

        registry = yaml.safe_load(
            (Path(__file__).resolve().parent.parent / "platforms" / "_registry.yml")
            .read_text(encoding="utf-8")
        )["platforms"]
        checked = 0
        with unittest.mock.patch.dict(os.environ, self.ENV):
            for name, entry in registry.items():
                by_os: dict[str, set[Path]] = {}
                for rule in (entry.get("install") or {}).get("detect", []):
                    if rule.get("bios_path"):
                        by_os.setdefault(rule["os"], set()).add(self._expand(rule["bios_path"]))
                    elif rule.get("method") == "path_exists":
                        by_os.setdefault(rule["os"], set()).add(self._expand(rule["path"]))
                    elif rule.get("parse_key") == "system_directory":
                        config = self._expand(rule["config"])
                        by_os.setdefault(rule["os"], set()).add(config.parent / "system")
                if name in install.PORTABLE_ONLY:
                    # No folder of its own to fall back on: the run stops
                    # and asks for --dest (test_a_portable_platform_is_not_guessed).
                    continue
                for os_type, candidates in by_os.items():
                    with self.subTest(platform=name, os=os_type):
                        self.assertIn(install._default_dest(os_type, name), candidates)
                        checked += 1
                # The installer's own default comes first in the registry and
                # is the one the pack guide and the installer name.
                first = next(
                    (self._expand(rule["path"]) for rule in (entry.get("install") or {}).get("detect", [])
                     if rule.get("os") == "windows" and rule.get("method") == "path_exists"),
                    None,
                )
                if name == "retrobat":
                    self.assertEqual(install._default_dest("windows", name), first)
        self.assertGreater(checked, 10)


class TestEmbeddedDetection(unittest.TestCase):
    """MiSTer is identified by the main binary at the SD card root."""

    def _detect_with(self, existing: set[str], os_id: str = ""):
        real_exists = install.Path.exists
        real_parse = install._parse_os_release

        def fake_exists(self):
            return str(self) in existing

        install.Path.exists = fake_exists
        install._parse_os_release = lambda: {"ID": os_id} if os_id else {}
        try:
            return install._detect_embedded()
        finally:
            install.Path.exists = real_exists
            install._parse_os_release = real_parse

    def test_mister_detected_from_main_binary(self):
        # A path rule of the registry, read by _detect_by_path.
        real_exists = install.Path.exists
        install.Path.exists = lambda self: str(self) == "/media/fat/MiSTer"
        try:
            found: list = []
            install._detect_by_path("linux", found)
        finally:
            install.Path.exists = real_exists
        self.assertEqual(found, [("misterfpga", Path("/media/fat/games"))])

    def test_rocknix_wins_over_path_probes(self):
        self.assertEqual(
            self._detect_with({"/media/fat/MiSTer"}, os_id="rocknix"),
            [("rocknix", Path("/storage/roms/bios"))],
        )

    def test_no_embedded_os_detected(self):
        self.assertEqual(self._detect_with(set()), [])


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
        defaults.update(kw)
        buf = io.StringIO()
        code = 0
        with contextlib.redirect_stdout(buf):
            try:
                install._report_outcome(**defaults)
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
        self.root = Path(_tempdir(self))
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
                install._check_free_space(path or self.root, needed)
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

    def test_probe_climbs_to_an_existing_ancestor(self):
        missing = self.root / "not" / "created" / "yet"
        out, code = self._run(free=1, needed=2, path=missing)
        self.assertEqual(code, 2)

    def test_the_space_check_comes_before_the_folder(self):
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        check = source.index("_check_free_space(bios_path, dl_size")
        self.assertLess(check, source.index("bios_path.mkdir(parents=True, exist_ok=True)"))


class TheDataTreesCountInTheFreeSpace(unittest.TestCase):
    """The space check held only the BIOS files: 18.8 KB passed on a card
    with 20 MB free, then 55.4 MB of archives came and 81.8 MB were written,
    against the page's promise to refuse before writing anything."""

    def _run(self, *frees_after_bios: int) -> list[tuple[int, str, list]]:
        """One run per free size, in one folder: the second finds the BIOS
        files the first installed."""
        from types import SimpleNamespace

        from test_install_selection import FakeRepository  # noqa: PLC0415

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
                        unittest.mock.patch.object(install, "MANIFEST_URL",
                                                   base + "/install/{platform}.json"), \
                        unittest.mock.patch.object(install, "RAW_FILE_URL", base + "/{path}"), \
                        unittest.mock.patch.object(install.shutil, "disk_usage",
                                                   lambda _p, free=free: SimpleNamespace(free=free)), \
                        unittest.mock.patch.object(
                            install, "install_data_directory",
                            lambda entry, *a, fetched=fetched, **k: fetched.append(entry["ref"]) or {
                                "present": 0, "installed": 1, "changed": 0, "absent": 0,
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
        root = Path(_tempdir(self))
        self.assertEqual(self._call(root, True), ("", None))

    def test_a_deep_missing_path_is_asked_and_no_is_the_default(self):
        root = Path(_tempdir(self))
        dest = root / "retroarh" / "system"
        out, code = self._call(dest, True, "")
        self.assertEqual(code, 2)
        self.assertIn(f"The nearest folder that does: {root}", out)
        self.assertFalse((root / "retroarh").exists())
        self.assertEqual(self._call(dest, True, "y")[1], None)

    def test_one_missing_level_or_no_terminal_is_said_not_asked(self):
        root = Path(_tempdir(self))
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
        root = Path(_tempdir(self))
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


class SaveFilesAListHoldsNoneOfAreNotPromised(unittest.TestCase):
    """RetroPie, ROCKNIX, AmberELEC, EmuELEC and RomM keep their save
    directory in no fixed place: their lists leave those files out with no
    hash or address. The run said "Name it with --save-dir", and said it
    again with --save-dir given, which installs none of them."""

    def test_the_reason_is_said_and_no_option_is_offered(self):
        manifest = json.loads((REPO_ROOT / "install" / "retropie.json").read_text())
        self.assertIsNone(manifest.get("save_directory"))
        root = Path(_tempdir(self))
        env = dict(os.environ, RETROBIOS_OS="linux")
        for extra in ([], ["--save-dir", str(root / "saves")]):
            with self.subTest(extra=extra):
                proc = _install_run(
                    env, "--platform", "retropie", "--dest", str(root / "bios"),
                    "--manifest", "install/retropie.json", "--offline", "--no-input",
                    "--yes", "--emulator", "azahar", *extra)
                out = proc.stdout + proc.stderr
                self.assertIn("read from RetroPie's save directory left out: RetroPie "
                              "keeps it in no fixed place, and its file list holds none "
                              "of them.", out)
                self.assertNotIn("Name it with --save-dir", out)


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
            install._report_outcome(
                paths=[Path("/userdata/bios")], downloaded=0, up_to_date=0, errors=1,
                omitted=0, interrupted=False,
                failures=[("neogeo.zip", install.NOT_WRITABLE)], assumed=assumed,
            )
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


class TestAndroidDetection(unittest.TestCase):
    """Android reports itself as Linux, and RetroArch is the frontend there."""

    def setUp(self):
        self.saved = {
            key: os.environ.get(key)
            for key in ("ANDROID_ROOT", "ANDROID_DATA", "EXTERNAL_STORAGE", "RETROBIOS_OS")
        }
        for key in self.saved:
            os.environ.pop(key, None)

    def tearDown(self):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_runtime_variables_name_android(self):
        os.environ["ANDROID_ROOT"] = "/system"
        os.environ["ANDROID_DATA"] = "/data"
        self.assertTrue(install._is_android())

    def test_plain_linux_is_not_android(self):
        self.assertFalse(
            install._is_android() and not Path("/system/build.prop").exists()
        )

    def test_forced_os_accepts_android(self):
        os.environ["RETROBIOS_OS"] = "android"
        self.assertEqual(install.detect_os(), "android")

    def test_default_directory_found_without_a_config(self):
        storage = Path(_tempdir(self))
        (storage / "RetroArch" / "system").mkdir(parents=True)
        os.environ["EXTERNAL_STORAGE"] = str(storage)
        self.assertEqual(
            install._detect_android(),
            [("retroarch", storage / "RetroArch" / "system")],
        )
        shutil.rmtree(storage)

    def test_config_default_resolves_against_the_retroarch_root(self):
        storage = Path(_tempdir(self))
        files = storage / "Android" / "data" / "com.retroarch.aarch64" / "files"
        files.mkdir(parents=True)
        (files / "retroarch.cfg").write_text(
            'system_directory = "default"\n'
            'bundle_assets_extract_version_current = "1745000000"\n')
        os.environ["EXTERNAL_STORAGE"] = str(storage)
        self.assertEqual(
            install._detect_android(),
            [("retroarch", storage / "RetroArch" / "system")],
        )
        shutil.rmtree(storage)

    def test_custom_system_directory_wins(self):
        storage = Path(_tempdir(self))
        files = storage / "Android" / "data" / "com.retroarch" / "files"
        files.mkdir(parents=True)
        custom = storage / "Emulation" / "bios"
        (files / "retroarch.cfg").write_text(f'system_directory = "{custom}"\n')
        os.environ["EXTERNAL_STORAGE"] = str(storage)
        self.assertEqual(install._detect_android(), [("retroarch", custom)])
        shutil.rmtree(storage)

    def test_nothing_found_on_a_bare_device(self):
        storage = Path(_tempdir(self))
        os.environ["EXTERNAL_STORAGE"] = str(storage)
        self.assertEqual(install._detect_android(), [])
        shutil.rmtree(storage)

    def test_detect_platforms_routes_android(self):
        storage = Path(_tempdir(self))
        (storage / "RetroArch" / "system").mkdir(parents=True)
        os.environ["EXTERNAL_STORAGE"] = str(storage)
        self.assertEqual(
            install.detect_platforms("android"),
            [("retroarch", storage / "RetroArch" / "system")],
        )
        shutil.rmtree(storage)

    def test_manual_hint_names_the_android_path(self):
        hint = "\n".join(install._manual_usage_hint("android"))
        self.assertIn("/storage/emulated/0/RetroArch/system", hint)

    def test_named_platform_falls_back_to_shared_storage(self):
        storage = Path(_tempdir(self))
        os.environ["EXTERNAL_STORAGE"] = str(storage)
        self.assertEqual(
            install._default_dest("android", "retroarch"),
            storage / "RetroArch" / "system",
        )
        self.assertEqual(
            install._default_dest("linux", "batocera"), Path("/userdata/bios")
        )
        shutil.rmtree(storage)

    def test_packages_match_the_published_flavors(self):
        self.assertEqual(
            install.ANDROID_RETROARCH_PACKAGES,
            ("com.retroarch.aarch64", "com.retroarch", "com.retroarch.ra32"),
        )


class TestLaunchboxDetection(unittest.TestCase):
    """LaunchBox references its emulators in Data/Emulators.xml."""

    def _make_launchbox(self, app_path: str, title: str = "Retroarch"):
        root = Path(_tempdir(self))
        data = root / "LaunchBox" / "Data"
        data.mkdir(parents=True)
        xml = data / "Emulators.xml"
        xml.write_text(
            "<?xml version=\"1.0\" standalone=\"yes\"?>\n"
            "<LaunchBox>\n"
            "  <Emulator>\n"
            "    <ID>x</ID>\n"
            f"    <Title>{title}</Title>\n"
            f"    <ApplicationPath>{app_path}</ApplicationPath>\n"
            "  </Emulator>\n"
            "</LaunchBox>\n"
        )
        return root, xml

    def test_relative_application_path(self):
        root, xml = self._make_launchbox("Emulators\\RetroArch\\retroarch.exe")
        ra_dir = root / "LaunchBox" / "Emulators" / "RetroArch"
        ra_dir.mkdir(parents=True)
        self.assertEqual(
            install._launchbox_retroarch_system_dir(xml), ra_dir / "system"
        )

    def test_absolute_application_path(self):
        emu_dir = Path(_tempdir(self)) / "RetroArch"
        emu_dir.mkdir(parents=True)
        root, xml = self._make_launchbox(str(emu_dir / "retroarch.exe"))
        self.assertEqual(
            install._launchbox_retroarch_system_dir(xml), emu_dir / "system"
        )

    def test_no_retroarch_entry(self):
        root, xml = self._make_launchbox("Emulators\\PCSX2\\pcsx2.exe", "PCSX2")
        self.assertIsNone(install._launchbox_retroarch_system_dir(xml))

    def test_missing_emulator_directory(self):
        root, xml = self._make_launchbox("Emulators\\RetroArch\\retroarch.exe")
        self.assertIsNone(install._launchbox_retroarch_system_dir(xml))

    def test_stale_entry_before_installed_one(self):
        root = Path(_tempdir(self))
        data = root / "LaunchBox" / "Data"
        data.mkdir(parents=True)
        ra_dir = root / "LaunchBox" / "Emulators" / "RetroArch"
        ra_dir.mkdir(parents=True)
        xml = data / "Emulators.xml"
        xml.write_text(
            "<?xml version=\"1.0\" standalone=\"yes\"?>\n"
            "<LaunchBox>\n"
            "  <Emulator>\n"
            "    <Title>RetroArch (old)</Title>\n"
            "    <ApplicationPath>Emulators\\RetroArch-old\\retroarch.exe</ApplicationPath>\n"
            "  </Emulator>\n"
            "  <Emulator>\n"
            "    <Title>RetroArch</Title>\n"
            "    <ApplicationPath>Emulators\\RetroArch\\retroarch.exe</ApplicationPath>\n"
            "  </Emulator>\n"
            "</LaunchBox>\n"
        )
        self.assertEqual(
            install._launchbox_retroarch_system_dir(xml), ra_dir / "system"
        )

    def test_missing_or_malformed_xml(self):
        self.assertIsNone(
            install._launchbox_retroarch_system_dir(Path("/nonexistent/Emulators.xml"))
        )
        root = Path(_tempdir(self))
        bad = root / "Emulators.xml"
        bad.write_text("not xml at all <<<")
        self.assertIsNone(install._launchbox_retroarch_system_dir(bad))


class TestRetroarchPathExpansion(unittest.TestCase):
    """RetroArch abbreviates paths with '~' and ':' in its config."""

    def _cfg(self, value: str) -> Path:
        app_dir = Path(_tempdir(self))
        (app_dir / "retroarch.cfg").write_text(f'system_directory = "{value}"\n')
        return app_dir

    def test_application_dir_prefix(self):
        app_dir = self._cfg(":\\system")
        self.assertEqual(
            install._parse_retroarch_system_dir(app_dir / "retroarch.cfg"),
            app_dir / "system",
        )

    def test_application_dir_prefix_forward_slash(self):
        app_dir = self._cfg(":/system")
        self.assertEqual(
            install._parse_retroarch_system_dir(app_dir / "retroarch.cfg"),
            app_dir / "system",
        )

    def test_home_prefix(self):
        app_dir = self._cfg("~/bios")
        self.assertEqual(
            install._parse_retroarch_system_dir(app_dir / "retroarch.cfg"),
            Path.home() / "bios",
        )

    def test_application_dir_overrides_config_dir(self):
        app_dir = self._cfg(":\\system")
        elsewhere = Path(_tempdir(self))
        self.assertEqual(
            install._parse_retroarch_system_dir(
                app_dir / "retroarch.cfg", elsewhere
            ),
            elsewhere / "system",
        )

    def test_absolute_path_untouched(self):
        target = Path(_tempdir(self)) / "bios"
        app_dir = self._cfg(str(target))
        self.assertEqual(
            install._parse_retroarch_system_dir(app_dir / "retroarch.cfg"), target
        )


class TestLaunchboxRoot(unittest.TestCase):
    """LaunchBox installs where the user chooses and keeps no registry key."""

    def _make_root(self, root: Path) -> Path:
        (root / "Data").mkdir(parents=True)
        (root / "Data" / "Emulators.xml").write_text(
            "<?xml version=\"1.0\" standalone=\"yes\"?>\n<LaunchBox></LaunchBox>\n"
        )
        return root

    def test_shortcut_target_is_read(self):
        # Byte layout of the shortcut a real install writes
        lnk = Path(_tempdir(self)) / "LaunchBox.lnk"
        lnk.write_bytes(
            b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00"
            b"\x00\x00\x00\x46" + b"\x00" * 8
            + b"C:\\Games\\LaunchBox\\Core\\LaunchBox.exe\x00"
            b"\x1c\x00\x00\x00LaunchBox\x00"
        )
        self.assertEqual(
            install._lnk_target(lnk, "LaunchBox.exe"),
            Path("C:/Games/LaunchBox/Core/LaunchBox.exe"),
        )

    def test_shortcut_without_target_is_ignored(self):
        lnk = Path(_tempdir(self)) / "LaunchBox.lnk"
        lnk.write_bytes(b"L\x00\x00\x00 no target here ")
        self.assertIsNone(install._lnk_target(lnk, "LaunchBox.exe"))

    def test_shortcut_pointing_elsewhere_falls_back(self):
        # A stale shortcut must not win over a real installation
        userprofile = Path(_tempdir(self))
        root = self._make_root(userprofile / "LaunchBox")
        appdata = Path(_tempdir(self))
        lnk_dir = (
            appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "LaunchBox"
        )
        lnk_dir.mkdir(parents=True)
        (lnk_dir / "LaunchBox.lnk").write_bytes(
            b"L\x00\x00\x00D:\\Gone\\LaunchBox\\Core\\LaunchBox.exe\x00"
        )
        env = {"APPDATA": str(appdata), "USERPROFILE": str(userprofile)}
        with unittest.mock.patch.dict(os.environ, env):
            self.assertEqual(install.launchbox_root("windows"), root)

    def test_falls_back_to_userprofile(self):
        userprofile = Path(_tempdir(self))
        root = self._make_root(userprofile / "LaunchBox")
        env = {"APPDATA": str(Path(_tempdir(self))), "USERPROFILE": str(userprofile)}
        with unittest.mock.patch.dict(os.environ, env):
            self.assertEqual(install.launchbox_root("windows"), root)

    def test_absent_on_linux(self):
        self.assertIsNone(install.launchbox_root("linux"))

    def test_nothing_installed(self):
        env = {
            "APPDATA": str(Path(_tempdir(self))),
            "USERPROFILE": str(Path(_tempdir(self))),
        }
        with unittest.mock.patch.dict(os.environ, env):
            self.assertIsNone(install.launchbox_root("windows"))


class TestLaunchboxBiosDirs(unittest.TestCase):
    """LaunchBox computes where each emulator it manages keeps its BIOS."""

    def _make(self, entries: list[tuple[str, str]]) -> Path:
        root = Path(_tempdir(self)) / "LaunchBox"
        (root / "Data").mkdir(parents=True)
        body = "".join(
            "  <Emulator>\n"
            f"    <Title>{title}</Title>\n"
            f"    <ApplicationPath>{app}</ApplicationPath>\n"
            "  </Emulator>\n"
            for title, app in entries
        )
        (root / "Data" / "Emulators.xml").write_text(
            "<?xml version=\"1.0\" standalone=\"yes\"?>\n"
            f"<LaunchBox>\n{body}</LaunchBox>\n"
        )
        for _, app in entries:
            (root / Path(app.replace("\\", "/")).parent).mkdir(parents=True, exist_ok=True)
        return root

    def test_pcsx2_portable_default_bios(self):
        root = self._make([("PCSX2", "Emulators\\PCSX2\\pcsx2.exe")])
        emu = root / "Emulators" / "PCSX2"
        (emu / "portable.ini").write_text("")
        (emu / "inis").mkdir()
        (emu / "inis" / "PCSX2.ini").write_text("[Folders]\nBios = bios\n")
        self.assertEqual(install.launchbox_bios_dirs(root)["pcsx2"], emu / "bios")

    def test_pcsx2_portable_absolute_bios(self):
        root = self._make([("PCSX2", "Emulators\\PCSX2\\pcsx2.exe")])
        emu = root / "Emulators" / "PCSX2"
        elsewhere = Path(_tempdir(self)) / "ps2bios"
        (emu / "portable.ini").write_text("")
        (emu / "inis").mkdir()
        (emu / "inis" / "PCSX2.ini").write_text(f"Bios = {elsewhere}\n")
        self.assertEqual(install.launchbox_bios_dirs(root)["pcsx2"], elsewhere)

    def test_pcsx2_portable_txt_also_triggers_portable_mode(self):
        root = self._make([("PCSX2", "Emulators\\PCSX2\\pcsx2.exe")])
        emu = root / "Emulators" / "PCSX2"
        (emu / "portable.txt").write_text("")
        self.assertEqual(install.launchbox_bios_dirs(root)["pcsx2"], emu / "bios")

    def test_pcsx2_portable_txt_names_a_data_root(self):
        root = self._make([("PCSX2", "Emulators\\PCSX2\\pcsx2.exe")])
        emu = root / "Emulators" / "PCSX2"
        (emu / "portable.txt").write_text("mydata\n")
        self.assertEqual(
            install.launchbox_bios_dirs(root)["pcsx2"], emu / "mydata" / "bios"
        )

    def test_pcsx2_without_config_uses_documents(self):
        root = self._make([("PCSX2", "Emulators\\PCSX2\\pcsx2.exe")])
        userprofile = Path(_tempdir(self))
        with unittest.mock.patch.dict(os.environ, {"USERPROFILE": str(userprofile)}):
            self.assertEqual(
                install.launchbox_bios_dirs(root)["pcsx2"],
                userprofile / "Documents" / "PCSX2" / "bios",
            )

    def test_xemu_defaults_to_bios_folder(self):
        root = self._make([("Xemu", "Emulators\\Xemu\\xemu.exe")])
        emu = root / "Emulators" / "Xemu"
        with unittest.mock.patch.dict(os.environ, {"APPDATA": str(Path(_tempdir(self)))}):
            self.assertEqual(install.launchbox_bios_dirs(root)["xemu"], emu / "bios")

    def test_xemu_honours_configured_bootrom(self):
        root = self._make([("Xemu", "Emulators\\Xemu\\xemu.exe")])
        emu = root / "Emulators" / "Xemu"
        configured = Path(_tempdir(self)) / "xbox"
        configured.mkdir()
        (configured / "mcpx_1.0.bin").write_text("x")
        (emu / "xemu.toml").write_text(
            "[sys.files]\n"
            f"bootrom_path = '{configured / 'mcpx_1.0.bin'}'\n"
        )
        self.assertEqual(install.launchbox_bios_dirs(root)["xemu"], configured)

    def test_dolphin_portable_user_folder(self):
        root = self._make([("Dolphin", "Emulators\\Dolphin\\Dolphin.exe")])
        emu = root / "Emulators" / "Dolphin"
        (emu / "portable.txt").write_text("")
        self.assertEqual(install.launchbox_bios_dirs(root)["dolphin"], emu / "User")

    def test_dolphin_without_portable_marker_is_absent(self):
        root = self._make([("Dolphin", "Emulators\\Dolphin\\Dolphin.exe")])
        (root / "Emulators" / "Dolphin" / "User").mkdir()
        self.assertNotIn("dolphin", install.launchbox_bios_dirs(root))

    def test_unknown_emulators_are_ignored(self):
        root = self._make([("Cemu", "Emulators\\Cemu\\Cemu.exe")])
        self.assertEqual(install.launchbox_bios_dirs(root), {})

    def test_doctype_is_rejected(self):
        root = Path(_tempdir(self)) / "LaunchBox"
        (root / "Data").mkdir(parents=True)
        (root / "Data" / "Emulators.xml").write_text(
            "<!DOCTYPE LaunchBox [<!ENTITY a 'x'>]>\n<LaunchBox></LaunchBox>\n"
        )
        self.assertEqual(install.launchbox_emulators(root / "Data" / "Emulators.xml"), {})


class TestStandaloneCopiesExtraDirs(unittest.TestCase):
    """Setups that keep emulators outside the default locations."""

    def _manifest(self) -> dict:
        return {
            "standalone_copies": [
                {
                    "pattern": "ps2-*.bin",
                    "emulator": "pcsx2",
                    "targets": {"windows": []},
                },
                {
                    "file": "GC/USA/IPL.bin",
                    "emulator": "dolphin",
                    "targets": {"windows": []},
                },
            ]
        }

    def test_pattern_entry_copies_into_extra_dir(self):
        bios = Path(_tempdir(self))
        (bios / "ps2-0230a.bin").write_text("rom")
        extra = Path(_tempdir(self)) / "bios"
        extra.mkdir()
        copied, _, _ = install.do_standalone_copies(
            self._manifest(), bios, "windows", {"pcsx2": extra}
        )
        self.assertEqual(copied, 1)
        self.assertTrue((extra / "ps2-0230a.bin").exists())

    def test_file_entry_keeps_its_subdirectory(self):
        bios = Path(_tempdir(self))
        (bios / "GC" / "USA").mkdir(parents=True)
        (bios / "GC" / "USA" / "IPL.bin").write_text("ipl")
        user = Path(_tempdir(self)) / "User"
        (user / "GC" / "USA").mkdir(parents=True)
        copied, _, _ = install.do_standalone_copies(
            self._manifest(), bios, "windows", {"dolphin": user}
        )
        self.assertEqual(copied, 1)
        self.assertTrue((user / "GC" / "USA" / "IPL.bin").exists())

    def test_no_extra_dirs_is_unchanged(self):
        bios = Path(_tempdir(self))
        (bios / "ps2-0230a.bin").write_text("rom")
        self.assertEqual(
            install.do_standalone_copies(self._manifest(), bios, "windows"), (0, 0, 0)
        )


@unittest.skipIf(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                 "a closed folder needs POSIX permissions and a non-root user")
class StandaloneFolderClosedToThisUser(unittest.TestCase):
    """Termux on Android 11 and later cannot look into another app's
    Android/data folder: is_dir() on Dolphin's GC/USA raised PermissionError
    after the install, and the run stopped with code 1."""

    def setUp(self) -> None:
        self.bios = Path(_tempdir(self))
        (self.bios / "IPL.bin").write_text("ipl")
        self.app = Path(_tempdir(self)) / "org.dolphinemu.dolphinemu"
        (self.app / "files" / "GC" / "USA").mkdir(parents=True)
        self.app.chmod(0)
        self.addCleanup(self.app.chmod, 0o755)
        self.target = self.app / "files" / "GC" / "USA"
        self.manifest = {"files": [{"dest": "IPL.bin"}], "standalone_copies": [
            {"file": "IPL.bin", "targets": {"android": [str(self.target)]}},
            {"note": "Dolphin reads GC/", "detect": {"android": [str(self.target)]}},
        ]}

    def test_listing_the_folders_here_skips_it(self):
        self.assertEqual(install.standalone_folders_here(self.manifest, "android"), [])

    def test_planning_skips_it(self):
        self.assertEqual(install.standalone_plan([self.manifest], "android"), [])

    def test_copying_names_it_and_goes_on(self):
        """Skipped, not failed: Android answers the same refusal for an app
        that is not installed, and a run without Dolphin is no failure."""
        failures: list[tuple[str, str]] = []
        with contextlib.redirect_stdout(io.StringIO()) as out:
            result = install.do_standalone_copies(
                self.manifest, self.bios, "android", failures=failures)
        self.assertEqual(result, (0, 1, 0))
        self.assertEqual(failures, [])
        self.assertIn(f"{self.target}: could not be read", out.getvalue())


class StandaloneCopiesReadWhereThePackPutTheFile(unittest.TestCase):
    """The registry names Citra/sysdata/aes_keys.txt for every platform,
    but EmuDeck's manifest installs it at the root. The installer looked under
    the registry's path, found nothing and copied nothing to Azahar."""

    def _copy(self, entry: dict) -> tuple[Path, tuple[int, int, int]]:
        bios = Path(_tempdir(self))
        (bios / "aes_keys.txt").write_text("keys")
        sysdata = Path(_tempdir(self)) / "sysdata"
        sysdata.mkdir()
        manifest = {"standalone_copies": [
            {**entry, "emulator": "azahar", "targets": {"linux": [str(sysdata)]}},
        ]}
        return sysdata, install.do_standalone_copies(manifest, bios, "linux")

    def test_the_source_the_manifest_names_is_copied(self):
        sysdata, (copied, _, _) = self._copy(
            {"file": "Citra/sysdata/aes_keys.txt", "source": "aes_keys.txt"}
        )
        self.assertEqual(copied, 1)
        self.assertEqual((sysdata / "aes_keys.txt").read_text(), "keys")

    def test_without_a_source_the_file_path_is_read(self):
        _, (copied, _, _) = self._copy({"file": "Citra/sysdata/aes_keys.txt"})
        self.assertEqual(copied, 0)

    def test_an_unsafe_source_is_refused_at_load(self):
        manifest = json.loads(
            (Path(__file__).resolve().parents[1] / "install" / "emudeck.json").read_text()
        )
        manifest["standalone_copies"] = [
            {"file": "aes_keys.txt", "source": "../../etc/passwd",
             "targets": {"linux": ["/tmp"]}},
        ]
        with self.assertRaisesRegex(ValueError, r"standalone_copies\[0\]\.source"):
            install._validate_manifest(manifest, "emudeck")


class OuterRootsAreUntrusted(unittest.TestCase):
    """roms_directory and emulators_directory come from a downloaded list: each
    path in them meets the rules a BIOS destination meets, and each folder
    they resolve to stays where the platform's layout puts it."""

    ROMS = {"bios_folder": "bios", "from_bios": ".."}
    EMULATORS = {
        "bios_folder": "bios", "searched": ["frontend/{key}", "emulators/{key}"],
        "default": "emulators/{key}", "config": "frontend/launcher.cfg",
    }
    UNSAFE = ("..\\x", "C:", "C:/x", "..//x", "../", "../x\x01", "x" * 1025)

    def test_unsafe_from_bios_is_refused(self):
        for value in (*self.UNSAFE, "../../../x", "../x/..", "x", "./x", "/x", "..x", None):
            with self.subTest(from_bios=value), self.assertRaises(ValueError):
                install._check_relative_directories({"roms_directory": {**self.ROMS, "from_bios": value}})

    def test_the_relations_the_rom_folders_files_use_are_accepted(self):
        bios = Path("/card/system/bios")
        expected = {
            ".": bios, "..": Path("/card/system"), "../roms": Path("/card/system/roms"),
            "../Roms": Path("/card/system/Roms"), "../../Roms": Path("/card/Roms"),
            "../../ROMS": Path("/card/ROMS"),
        }
        for value, root in expected.items():
            with self.subTest(from_bios=value):
                install._check_relative_directories({"roms_directory": {**self.ROMS, "from_bios": value}})
                self.assertEqual(install._relative_root(bios, value), root)
        self.assertEqual(install.MAX_ROMS_UPS, 2)

    def test_a_list_without_a_roms_root_leaves_the_files_out(self):
        files = [{"dest": "pico-8/pico8_64", "root": "roms", "cores": ["x"]}]
        kept, left = install.place_relative_entries(files, Path("/card/roms/bios"), {}, "x", say=False)
        self.assertEqual((kept, [o["reason"] for o in left]), ([], ["no_roms_directory"]))

    def test_unsafe_emulator_folders_are_refused(self):
        for field in ("searched", "default", "config"):
            for value in self.UNSAFE + ("../{key}", "/abs/{key}"):
                layout = dict(self.EMULATORS)
                if field == "searched":
                    layout["searched"] = [value if "{key}" in value else value + "/{key}"]
                    layout["default"] = layout["searched"][0]
                elif field == "default":
                    layout["default"] = value
                else:
                    layout["config"] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    install._check_emulators_directory({"emulators_directory": layout})

    def test_a_drive_or_colon_segment_is_refused_on_either_host(self):
        from pathlib import PureWindowsPath

        bios = PureWindowsPath("C:/RetroBat/bios")
        for host in ("posix", "nt"):
            with unittest.mock.patch.object(install.os, "name", host):
                for value in ("../C:x", "..\\x", "../x:", "../Roms:x"):
                    with self.subTest(host=host, from_bios=value), self.assertRaises(ValueError):
                        install._check_relative_directories(
                            {"roms_directory": {**self.ROMS, "from_bios": value}})
                for value in ("C:x/{key}", "x:/{key}", "emu:x/{key}"):
                    layout = {**self.EMULATORS, "searched": [value], "default": value}
                    with self.subTest(host=host, searched=value), self.assertRaises(ValueError):
                        install._check_emulators_directory({"emulators_directory": layout})
                for dest in ("bios/C:x.bin", "bios/x:", "a:b/c.bin"):
                    with self.subTest(host=host, dest=dest), self.assertRaises(ValueError):
                        install._safe_relative_path(dest, "dest")
                with self.subTest(host=host), self.assertRaises(ValueError):
                    install._safe_relative_path("pico8/x:y", "dest", colons=False)
        # Each of these leaves the folder on Windows once joined.
        self.assertEqual(PureWindowsPath(bios, "..", "D:x"), PureWindowsPath("D:x"))
        self.assertEqual(PureWindowsPath("C:x").drive, "C:")
        # RetroDECK's ares names are kept where the host is not Windows.
        with unittest.mock.patch.object(install.os, "name", "posix"):
            install._safe_relative_path("bios/snes:st018.data.rom", "dest")
        with unittest.mock.patch.object(install.os, "name", "nt"), self.assertRaises(ValueError):
            install._safe_relative_path("bios/snes:st018.data.rom", "dest")

    def test_an_emulator_folder_stays_below_the_platform_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / "bios").mkdir()
            (home / "frontend").mkdir()
            (home / "frontend" / "launcher.cfg").write_text("")
            manifest = {"emulators_directory": self.EMULATORS}
            for dest in ("../x/prog", "C:/prog", "prog\\..\\..\\x/a"):
                with self.subTest(dest=dest), self.assertRaises(ValueError):
                    install.place_emulator_entries(
                        [{"dest": dest, "root": "emulators"}], home / "bios", manifest, "x",
                        say=False)
            kept, left = install.place_emulator_entries(
                [{"dest": "prog/prog.exe", "root": "emulators"}], home / "bios", manifest, "x",
                say=False)
            self.assertEqual((len(kept), left), (1, []))
            folder, rest = install._entry_place(home / "bios", kept[0])
            self.assertEqual((folder, rest), (home / "emulators" / "prog", "prog.exe"))


class DetectionFollowsTheRegistry(unittest.TestCase):
    """The registry declared RetroPie at ~/RetroPie/BIOS and BizHawk at
    ~/.config/BizHawk/Firmware, every manifest published it, and the
    installer never read it: such a home detected nothing."""

    def test_the_table_is_the_registry(self):
        import yaml  # noqa: PLC0415

        registry = yaml.safe_load(
            (Path(__file__).resolve().parents[1] / "platforms" / "_registry.yml").read_text()
        )
        rules = {
            (rule["os"], name, rule["path"], rule.get("bios_path"))
            for name, entry in registry["platforms"].items()
            for rule in (entry.get("install") or {}).get("detect", [])
            if rule["method"] == "path_exists"
        }
        self.assertEqual(set(install._PATH_RULES), rules)

    def test_the_embedded_table_is_the_registry(self):
        """Only the path rules were compared: Knulli, muOS, ArkOS and the
        Recalbox version file were detected by the installer and absent
        from every manifest's `detect`, and ROCKNIX was declared another
        way. A changed bios_path in the registry reached no installer."""
        import yaml  # noqa: PLC0415

        registry = yaml.safe_load(
            (Path(__file__).resolve().parents[1] / "platforms" / "_registry.yml").read_text()
        )
        rules = []
        for name, entry in registry["platforms"].items():
            for rule in (entry.get("install") or {}).get("detect", []):
                if rule["method"] == "os_release":
                    values = tuple(rule["match"])
                elif rule["method"] == "file_exists":
                    files = rule["file"]
                    values = tuple(files if isinstance(files, list) else [files])
                elif rule["method"] == "file_matches":
                    values = (rule["file"], rule["pattern"])
                else:
                    continue
                rules.append(install._OsRule(
                    "" if rule.get("installs") is False else name, rule["name"],
                    rule["method"], values, rule.get("bios_path"),
                    tuple(rule.get("config", ())), rule.get("home", ""),
                    rule.get("derives_from", ""),
                ))
        self.assertEqual(sorted(install._EMBEDDED_RULES, key=repr), sorted(rules, key=repr))

    def test_every_config_file_read_is_published(self):
        """The registry published five RetroArch config files and the fixed
        RetroDECK folder, but the installer also read Snap, the older macOS file,
        C:\\RetroArch, Program Files, ES-DE, Steam and RetroDECK's own
        config. A manifest reader saw a subset of what the installer does."""
        import yaml  # noqa: PLC0415

        registry = yaml.safe_load(
            (Path(__file__).resolve().parents[1] / "platforms" / "_registry.yml").read_text()
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = {
                "HOME": str(root / "home"), "APPDATA": str(root / "appdata"),
                "ProgramFiles": str(root / "pf"), "ProgramFiles(x86)": str(root / "pf86"),
                # Not the host's: a WSL session can hold them.
                "USERPROFILE": "", "LOCALAPPDATA": "", "ProgramData": "",
                "SCOOP": "", "SCOOP_GLOBAL": "",
            }

            def expand(text: str) -> str:
                text = text.replace("$HOME", env["HOME"])
                for var in ("ProgramFiles(x86)", "ProgramFiles", "APPDATA"):
                    text = text.replace(f"%{var}%", env[var])
                return str(Path(text.replace("\\", "/")))

            published = {
                (rule["os"], expand(rule["config"]))
                for entry in registry["platforms"].values()
                for rule in (entry.get("install") or {}).get("detect", [])
                if rule["method"] == "config_file"
            }
            read: set[tuple[str, str]] = set()

            def record(os_type: str):
                def probe(path, *_args, **_kwargs):
                    read.add((os_type, str(Path(str(path).replace("\\", "/")))))
                    return None
                return probe

            with unittest.mock.patch.dict(os.environ, env), \
                    unittest.mock.patch.object(install, "_detect_embedded", lambda: []), \
                    unittest.mock.patch.object(install, "_detect_android", lambda: []):
                for os_type in ("linux", "darwin", "windows"):
                    with unittest.mock.patch.object(
                        install, "_parse_retroarch_system_dir", record(os_type)
                    ):
                        install.detect_platforms(os_type)
                with unittest.mock.patch.object(Path, "is_file", lambda _self: True):
                    for folder in install._windows_retroarch_dirs():
                        read.add(("windows", str(folder / "retroarch.cfg")))
            retrodeck = root / "home/.var/app/net.retrodeck.retrodeck/config/retrodeck"
            read |= {("linux", str(retrodeck / "retrodeck.json")),
                     ("linux", str(retrodeck / "retrodeck.cfg"))}
            # The default Steam library is the Program Files one, already read.
            self.assertEqual(sorted(read - published), [])

    def test_the_first_embedded_match_wins(self):
        with unittest.mock.patch.object(install, "_parse_os_release", return_value={}), \
                unittest.mock.patch.object(
                    Path, "exists",
                    lambda p: str(p) in ("/usr/share/knulli/knulli.version",
                                       "/usr/share/batocera/batocera.version"),
                ):
            self.assertEqual(install._detect_embedded(), [("knulli", Path("/userdata/bios"))])
        # What ROCKNIX writes since 2025: OS_NAME and HW_DEVICE, no ID.
        with unittest.mock.patch.object(install, "_parse_os_release",
                                        return_value={"OS_NAME": "ROCKNIX", "HW_DEVICE": "RK3566"}):
            self.assertEqual(
                install._detect_embedded(), [("rocknix", Path("/storage/roms/bios"))]
            )

    def _home(self) -> Path:
        home = Path(_tempdir(self))
        patcher = unittest.mock.patch.dict(os.environ, {"HOME": str(home), "USERPROFILE": str(home)})
        patcher.start()
        self.addCleanup(patcher.stop)
        return home

    def test_a_home_layout_is_detected(self):
        home = self._home()
        (home / "RetroPie" / "BIOS").mkdir(parents=True)
        found: list = []
        install._detect_by_path("linux", found)
        self.assertIn(("retropie", home / "RetroPie" / "BIOS"), found)

    def test_bizhawk_is_found_by_its_executable(self):
        """~/.config/BizHawk/Firmware is a folder no build reads: the
        archive extracted to ~/Games/BizHawk-2.11.1 reads the Firmware folder
        beside EmuHawkMono.sh."""
        home = self._home()
        extracted = home / "Games" / "BizHawk-2.11.1"
        extracted.mkdir(parents=True)
        (extracted / "EmuHawkMono.sh").write_text("#!/bin/sh\n")
        found: list = []
        install._detect_by_executable("linux", found)
        self.assertEqual(found, [("bizhawk", extracted / "Firmware")])
        self.assertNotIn("bizhawk", install._os_default_dests("linux"))
        self.assertNotIn("bizhawk", install._os_default_dests("windows"))

    def test_a_portable_platform_is_not_guessed(self):
        """--platform bizhawk with no install found wrote 924 files into
        ~/.config/BizHawk/Firmware, then detected that folder next time."""
        home = self._home()
        with unittest.mock.patch.object(sys, "argv", ["install.py", "--platform", "bizhawk"]), \
                unittest.mock.patch.object(install, "detect_os", return_value="linux"), \
                unittest.mock.patch.object(install, "detect_platforms", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit) as stop:
            install.main()
        self.assertEqual(stop.exception.code, 1)
        self.assertIn("--dest", err.getvalue())
        self.assertFalse((home / ".config" / "BizHawk").exists())

    def test_the_executable_table_is_the_registry(self):
        import yaml  # noqa: PLC0415

        registry = yaml.safe_load(
            (Path(__file__).resolve().parents[1] / "platforms" / "_registry.yml").read_text()
        )
        rules = {
            (rule["os"], name, tuple(rule["file"]), rule["bios_subdir"])
            for name, entry in registry["platforms"].items()
            for rule in (entry.get("install") or {}).get("detect", [])
            if rule["method"] == "executable"
        }
        self.assertEqual(set(install._EXE_RULES), rules)

    def test_a_windows_profile_path_is_detected(self):
        home = self._home()
        (home / "BizHawk" / "Firmware").mkdir(parents=True)
        found: list = []
        install._detect_by_path("windows", found)
        self.assertEqual(found, [("bizhawk", home / "BizHawk" / "Firmware")])

    def test_a_platform_already_found_is_not_added_again(self):
        home = self._home()
        (home / "Emulation" / "bios").mkdir(parents=True)
        found = [("emudeck", home / "elsewhere" / "bios")]
        install._detect_by_path("linux", found)
        self.assertEqual(found, [("emudeck", home / "elsewhere" / "bios")])

    def test_emudeck_on_macos_is_found_by_its_settings(self):
        """EmuDeck's macOS build reads ~/.config/EmuDeck/settings.sh as the
        Linux one does (functions/all.sh:3-4,24, vars.sh:2): a Mac with
        EmuDeck detected nothing and was offered RetroArch's folder."""
        home = self._home()
        settings = home / ".config" / "EmuDeck" / "settings.sh"
        settings.parent.mkdir(parents=True)
        settings.write_text(f"emulationPath={home / 'Games' / 'Emulation'}\n")
        self.assertIn(("emudeck", home / "Games" / "Emulation" / "bios"),
                      install.detect_platforms("darwin"))
        settings.unlink()
        (home / "Emulation" / "bios").mkdir(parents=True)
        self.assertIn(("emudeck", home / "Emulation" / "bios"),
                      install.detect_platforms("darwin"))


class RetroArchIsFoundWhereWindowsInstallsPutIt(unittest.TestCase):
    """Program Files\\RetroArch-Win64, a Steam library on another drive and
    an installed ES-DE's Emulators folder all held a RetroArch the one-liner
    reported as "no supported platform detected"."""

    def _env(self, program_files: Path) -> None:
        patcher = unittest.mock.patch.dict(
            os.environ, {"ProgramFiles": str(program_files), "ProgramFiles(x86)": ""}
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def _exe(folder: Path) -> Path:
        folder.mkdir(parents=True)
        (folder / "retroarch.exe").write_bytes(b"MZ")
        return folder

    def test_program_files_win64(self):
        program_files = Path(_tempdir(self))
        self._env(program_files)
        found = self._exe(program_files / "RetroArch-Win64")
        self.assertIn(found, install._windows_retroarch_dirs())

    def test_a_scoop_install(self):
        # `scoop install retroarch` puts it under ~/scoop/apps/retroarch/current,
        # which none of the searched folders covered.
        program_files = Path(_tempdir(self))
        self._env(program_files)
        home = Path(_tempdir(self))
        found = self._exe(home / "scoop" / "apps" / "retroarch" / "current")
        with unittest.mock.patch.dict(os.environ, {"USERPROFILE": str(home)}):
            os.environ.pop("SCOOP", None)
            self.assertIn(found, install._windows_retroarch_dirs())

    def test_a_steam_library_on_another_drive(self):
        program_files = Path(_tempdir(self))
        library = Path(_tempdir(self))
        steamapps = program_files / "Steam" / "steamapps"
        steamapps.mkdir(parents=True)
        (steamapps / "libraryfolders.vdf").write_text(
            '"libraryfolders"\n{\n\t"1"\n\t{\n\t\t"path"\t\t"' + str(library) + '"\n\t}\n}\n'
        )
        self._env(program_files)
        found = self._exe(library / "steamapps" / "common" / "RetroArch")
        self.assertIn(found, install._windows_retroarch_dirs())

    def test_an_installed_es_de(self):
        program_files = Path(_tempdir(self))
        self._env(program_files)
        found = self._exe(program_files / "ES-DE" / "Emulators" / "RetroArch-Win64")
        self.assertIn(found, install._windows_retroarch_dirs())


class InstallerStaysOnPython38AndTheStdlib(unittest.TestCase):
    """install.py runs where the bootstraps let it run: Python 3.8, stdlib only.

    The suite runs on 3.12 with pyyaml installed, so a removeprefix() or an
    import of yaml kept every test green and died at the user's first run,
    after the bootstrap had told them 3.8 was enough.
    """

    SOURCE = (REPO_ROOT / "install.py").read_text(encoding="utf-8")

    def test_the_grammar_is_python_38(self):
        import ast  # noqa: PLC0415

        ast.parse(self.SOURCE, filename="install.py", feature_version=(3, 8))

    def test_every_import_is_standard_library(self):
        import ast  # noqa: PLC0415
        import sys  # noqa: PLC0415

        tree = ast.parse(self.SOURCE)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported.add(node.module.split(".")[0])
        self.assertEqual(sorted(imported - set(sys.stdlib_module_names)), [])

    def test_no_api_newer_than_38(self):
        newer = (".removeprefix(", ".removesuffix(", "zoneinfo", "graphlib",
                 "functools.cache(", ".bit_count(", "math.lcm(", "math.nextafter(",
                 "tomllib", ".is_relative_to(", ".with_stem(", ".hardlink_to(",
                 "itertools.pairwise(", "str.removeprefix", "types.NoneType")
        used = [api for api in newer if api in self.SOURCE]
        self.assertEqual(used, [])

    def test_a_python_38_interpreter_compiles_and_imports_it(self):
        """ast.parse(feature_version=(3, 8)) on 3.12 accepts parenthesized
        context managers and PEP 701 f-strings: only a 3.8 interpreter says."""
        import shutil  # noqa: PLC0415
        import subprocess  # noqa: PLC0415

        python38 = shutil.which("python3.8")
        if python38 is None:
            self.skipTest("no python3.8 on PATH, the static checks below still run")
        code = (
            "import importlib.util; "
            "spec = importlib.util.spec_from_file_location('install', 'install.py'); "
            "spec.loader.exec_module(importlib.util.module_from_spec(spec))"
        )
        proc = subprocess.run(
            [python38, "-I", "-c", code], cwd=REPO_ROOT,
            capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_a_python_38_interpreter_runs_it_end_to_end(self):
        """An import proves the grammar, not the calls a function makes.

        dict | dict, zip(strict=True) or functools.cache import cleanly on
        3.8 and raise the first time their path runs: listing, narrowing by
        system, region and target, installing and checking all run here, on
        the repository's own manifests served over loopback. CI installs the
        interpreter, so there it may not skip.
        """
        import shutil  # noqa: PLC0415
        import subprocess  # noqa: PLC0415

        python38 = shutil.which("python3.8")
        if python38 is None:
            if os.environ.get("CI"):
                self.fail("CI must provide python3.8 for the installer's floor")
            self.skipTest("no python3.8 on PATH, the static checks below still run")
        handler = functools.partial(
            http.server.SimpleHTTPRequestHandler, directory=str(REPO_ROOT)
        )
        handler.log_message = lambda *args: None
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        home = Path(tempfile.mkdtemp(dir=str(REPO_ROOT / "tmp")))
        self.addCleanup(shutil.rmtree, home, True)
        env = {
            **os.environ,
            "HOME": str(home),
            "RETROBIOS_OS": "linux",
            "RETROBIOS_BASE_URL": f"http://127.0.0.1:{httpd.server_address[1]}",
        }
        dest = home / "system"
        base = [python38, "-I", "install.py", "--platform", "retroarch", "--no-input"]
        for extra in (
            ["--list-systems"],
            ["--list-cores"],
            ["--list-targets"],
            ["--dest", str(dest), "--system", "atari-lynx", "--region", "us",
             "--target", "switch", "--yes"],
            ["--dest", str(dest), "--system", "atari-lynx", "--check"],
        ):
            with self.subTest(args=extra):
                proc = subprocess.run(
                    base + extra, cwd=REPO_ROOT, env=env,
                    capture_output=True, text=True, timeout=300, check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertNotIn("Traceback", proc.stderr)
        self.assertTrue((dest / "lynxboot.img").is_file())
        # A check is scripted as `--check && launch`: missing files fail it.
        proc = subprocess.run(
            base + ["--dest", str(home / "empty"), "--system", "atari-lynx", "--check"],
            cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=300,
            check=False,
        )
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertIn("to download.", proc.stdout)

    def test_no_syntax_a_312_parser_lets_through(self):
        """Parenthesized context managers (3.9) and f-strings reusing their
        own quote or a backslash inside a replacement field (3.12)."""
        import io  # noqa: PLC0415
        import tokenize  # noqa: PLC0415

        found = []
        tokens = list(tokenize.generate_tokens(io.StringIO(self.SOURCE).readline))
        for i, tok in enumerate(tokens):
            if tok.type == tokenize.NAME and tok.string == "with" and i + 1 < len(tokens):
                if tokens[i + 1].string != "(":
                    continue
                depth = 0
                for inner in tokens[i + 1:]:
                    if inner.string in "([{" and inner.type == tokenize.OP:
                        depth += 1
                    elif inner.string in ")]}" and inner.type == tokenize.OP:
                        depth -= 1
                        if depth == 0:
                            break
                    elif depth == 1 and inner.type == tokenize.NAME and inner.string == "as":
                        found.append(f"line {tok.start[0]}: parenthesized with")
                        break
        fstring_start = getattr(tokenize, "FSTRING_START", None)
        if fstring_start is not None:
            stack = []
            for tok in tokens:
                if tok.type == fstring_start:
                    if stack:
                        found.append(f"line {tok.start[0]}: f-string inside an f-string")
                    stack.append(tok.string[-1])
                elif tok.type == tokenize.FSTRING_END:
                    stack.pop()
                elif stack and tok.type == tokenize.STRING and stack[-1] in tok.string:
                    found.append(f"line {tok.start[0]}: f-string reuses its quote")
                elif stack and tok.type == tokenize.FSTRING_MIDDLE:
                    continue
                elif stack and tok.type == tokenize.ERRORTOKEN and tok.string == "\\":
                    found.append(f"line {tok.start[0]}: backslash in an f-string field")
        self.assertEqual(found, [])

    def test_no_runtime_generic_builtin(self):
        """dict[str, Path] outside an annotation runs on 3.9 and later only."""
        import ast  # noqa: PLC0415

        tree = ast.parse(self.SOURCE)
        annotations = set()
        for node in ast.walk(tree):
            for field in ("annotation", "returns"):
                sub = getattr(node, field, None)
                if sub is not None:
                    annotations.update(id(n) for n in ast.walk(sub))
        generic = {"dict", "list", "tuple", "set", "frozenset", "type"}
        used = sorted(
            f"line {node.lineno}: {node.value.id}[...]"
            for node in ast.walk(tree)
            if isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id in generic
            and id(node) not in annotations
        )
        self.assertEqual(used, [])


    def test_no_local_is_assigned_and_never_read(self):
        """ruff --select F in py38 mode is the installer's lint gate, and an
        unread `appdata` in _os_default_dests made it exit 1. The suite has
        no ruff, so the rule is read from the syntax tree."""
        import ast  # noqa: PLC0415

        tree = ast.parse((Path(__file__).resolve().parents[1] / "install.py").read_text())
        unread = []
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            stored, loaded = {}, set()
            for node in ast.walk(func):
                if isinstance(node, ast.Name):
                    if isinstance(node.ctx, ast.Store):
                        stored.setdefault(node.id, node.lineno)
                    else:
                        loaded.add(node.id)
            nested = {
                n.id for inner in ast.walk(func) if inner is not func
                and isinstance(inner, (ast.FunctionDef, ast.Lambda))
                for n in ast.walk(inner) if isinstance(n, ast.Name)
            }
            unread += [
                f"{func.name}:{line} {name}" for name, line in stored.items()
                if name not in loaded | nested and not name.startswith("_")
                and not any(
                    isinstance(g, (ast.Global, ast.Nonlocal)) and name in g.names
                    for g in ast.walk(func)
                )
            ]
        self.assertEqual(unread, [])
        # Nor a module rebound: a loop variable named `platform` shadowed the
        # platform module in _detect_by_path (F402).
        modules = {
            alias.asname or alias.name.split(".")[0]
            for node in tree.body if isinstance(node, ast.Import)
            for alias in node.names
        }
        rebound = sorted(
            f"{node.id}:{node.lineno}" for node in ast.walk(tree)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
            and node.id in modules
        )
        self.assertEqual(rebound, [])

class ARefusedCopyIsAnError(unittest.TestCase):
    """A PermissionError on a standalone copy was counted as "dir not found"
    and the run ended on Done with exit code 0."""

    def test_a_refused_copy_is_counted_failed_not_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            bios = Path(tmp, "bios")
            bios.mkdir()
            (bios / "prod.keys").write_bytes(b"k")
            target = Path(tmp, "keys")
            target.mkdir()
            manifest = {"standalone_copies": [
                {"file": "prod.keys", "targets": {"linux": [str(target)]}}
            ]}
            with unittest.mock.patch("shutil.copy2", side_effect=PermissionError(13, "denied")):
                result = install.do_standalone_copies(manifest, bios, "linux")
        self.assertEqual(result, (0, 0, 1))


class TargetFlagIsAppliedOrRefused(unittest.TestCase):
    """A filter the installer cannot apply must stop it, not be ignored.

    An unknown target used to print a warning and then install every file:
    4 GB where the user asked for a subset. And the aliases the pack builder
    accepts -- switch, ps2, psp -- were absent from the published target
    manifests, so the documented word was the one that failed.
    """

    def test_the_published_manifests_carry_the_builder_aliases(self):
        path = REPO_ROOT / "install" / "targets" / "retroarch.json"
        if not path.is_file():
            self.skipTest("no target manifest generated yet")
        targets = json.loads(path.read_text())
        self.assertIn("nintendo-switch", targets)
        for alias in ("switch", "nx"):
            with self.subTest(alias=alias):
                self.assertIn(alias, targets, f"builder accepts --target {alias}")
                self.assertEqual(targets[alias], targets["nintendo-switch"])

    def test_every_alias_resolves_to_its_canonical_core_list(self):
        import sys as _sys

        _sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from common import load_target_config

        for name in ("install/targets/retroarch.json",):
            path = REPO_ROOT / name
            if not path.is_file():
                self.skipTest(f"{name} not generated yet")
            targets = json.loads(path.read_text())
            for alias in ("switch", "ps2", "psp"):
                # An alias the builder accepts and the manifest lacks is a
                # documented word that fails on the installer's side.
                self.assertIn(alias, targets, f"builder accepts --target {alias}")
                with self.subTest(alias=alias):
                    resolved = load_target_config(
                        "retroarch", alias, str(REPO_ROOT / "platforms")
                    )
                    self.assertEqual(
                        sorted(targets[alias] or []),
                        sorted(resolved),
                        f"{alias} disagrees with what the builder resolves",
                    )

    def test_every_published_target_is_the_list_the_builder_resolves(self):
        """add_cores and remove_cores reach the installer, not only the builder.

        The published lists were the scraped ones, untouched by the
        overrides: Batocera x86_64 lacked citron and xenia, which the pack
        for that target ships, and carried the Amiga machine variants and
        the launchers the builder drops.

        Both ways: a target the builder knows and the installer lacks answers
        "unknown target" on one side only, and a published null left behind
        once the builder filters a target makes the installer serve every core.
        """
        import sys as _sys

        _sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from common import list_available_targets, load_target_config

        platforms = str(REPO_ROOT / "platforms")
        sources = sorted(
            path.stem for path in (REPO_ROOT / "platforms" / "targets").glob("*.yml")
            if not path.name.startswith("_")
        )
        manifests = {
            path.stem: path for path in (REPO_ROOT / "install" / "targets").glob("*.json")
        }
        if not manifests:
            self.skipTest("no target manifest generated yet")
        self.assertEqual(sorted(manifests), sources)
        for platform in sources:
            targets = json.loads(manifests[platform].read_text())
            known = {
                name
                for target in list_available_targets(platform, platforms)
                for name in (target["name"], *target["aliases"])
            }
            with self.subTest(platform=platform):
                self.assertEqual(sorted(targets), sorted(known))
            for target, cores in targets.items():
                # A target that names its card images carries them beside.
                cores = cores["cores"] if isinstance(cores, dict) else cores
                with self.subTest(platform=platform, target=target):
                    resolved = load_target_config(platform, target, platforms)
                    self.assertEqual(cores, None if resolved is None else sorted(resolved))


class TestBaseUrlScheme(unittest.TestCase):
    """The bootstraps insist on HTTPS, so the installer must not be laxer."""

    def test_https_is_accepted(self):
        self.assertEqual(
            install._checked_base_url("https://example.test/repo"),
            "https://example.test/repo",
        )

    def test_plain_http_is_refused(self):
        with self.assertRaises(SystemExit):
            install._checked_base_url("http://example.test/repo")

    def test_local_file_scheme_is_refused(self):
        with self.assertRaises(SystemExit):
            install._checked_base_url("file:///etc")

    def test_loopback_http_is_allowed_for_end_to_end_runs(self):
        for url in (
            "http://127.0.0.1:8080/repo",
            "http://localhost:8080/repo",
            "http://[::1]:8080/repo",
        ):
            self.assertEqual(install._checked_base_url(url), url)


class TestLocalCheckHashing(unittest.TestCase):
    """A file is read once, not once per declared digest."""

    def test_both_digests_come_from_one_read(self):
        tmp = Path(_tempdir(self))
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
        tmp = Path(_tempdir(self))
        (tmp / "boot.bin").write_bytes(b"BIOS PAYLOAD")
        entry = {
            "dest": "boot.bin",
            "size": 12,
            "sha1": "0" * 40,
            "sha256": hashlib.sha256(b"BIOS PAYLOAD").hexdigest(),
        }
        _, up_to_date, mismatched = install.check_local([entry], tmp)
        self.assertEqual((len(up_to_date), len(mismatched)), (0, 1))


class TestStandaloneCopyTargetsAreUntrusted(unittest.TestCase):
    """The manifest names these directories, so it does not get to escape them."""

    def _manifest(self, target: str) -> dict:
        return {
            "standalone_copies": [
                {"file": "boot.bin", "targets": {"linux": [target]}}
            ]
        }

    def test_traversal_in_a_target_is_refused_by_validation(self):
        manifest = {
            "manifest_version": 2,
            "platform": "retroarch",
            "files": [],
            "standalone_copies": [
                {"file": "boot.bin", "targets": {"linux": ["~/emu/../../../etc"]}}
            ],
        }
        with self.assertRaises(ValueError):
            install._validate_manifest(manifest, "retroarch")

    def test_nul_in_a_target_is_refused_by_validation(self):
        manifest = {
            "manifest_version": 2,
            "platform": "retroarch",
            "files": [],
            "standalone_copies": [
                {"file": "boot.bin", "targets": {"linux": ["/tmp/a\x00b"]}}
            ],
        }
        with self.assertRaises(ValueError):
            install._validate_manifest(manifest, "retroarch")

    def test_entries_the_copy_step_cannot_read_are_refused(self):
        """Each passed validation and crashed do_standalone_copies after the
        download: a list for detect, no file nor pattern, a list for emulator."""
        for entry in (
            {"note": "hi", "detect": ["/x"]},
            {"emulator": "pcsx2", "targets": {"linux": ["/tmp"]}},
            {"file": "bios/x.bin", "emulator": ["a"], "targets": {"linux": ["/tmp"]}},
        ):
            manifest = {"manifest_version": 2, "platform": "retroarch", "files": [],
                        "standalone_copies": [entry]}
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                install._validate_manifest(manifest, "retroarch")

    def test_plain_absolute_target_still_works(self):
        manifest = {
            "manifest_version": 2,
            "platform": "retroarch",
            "files": [],
            "standalone_copies": [
                {"file": "boot.bin", "targets": {"linux": ["~/.config/emu/bios"]}}
            ],
        }
        self.assertIsInstance(install._validate_manifest(manifest, "retroarch"), dict)

    def test_symlinked_destination_is_not_written_through(self):
        """A link at the name was skipped in silence and counted as "dir
        not found" while the folder existed: the emulator kept whatever the
        link pointed at. The link now gives way to the file."""
        bios = Path(_tempdir(self))
        (bios / "boot.bin").write_text("rom")
        target = Path(_tempdir(self))
        outside = Path(_tempdir(self)) / "secret"
        outside.write_text("untouched")
        (target / "boot.bin").symlink_to(outside)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            copied, skipped, failed = install.do_standalone_copies(
                self._manifest(str(target)), bios, "linux"
            )
        self.assertEqual((copied, skipped, failed), (1, 0, 0))
        self.assertEqual(outside.read_text(), "untouched")
        self.assertFalse((target / "boot.bin").is_symlink())
        self.assertEqual((target / "boot.bin").read_text(), "rom")
        self.assertIn("link replaced", out.getvalue())
        self.assertEqual(sorted(p.name for p in target.iterdir()), ["boot.bin"])


@unittest.skipUnless(shutil.which("pwsh"), "pwsh not available")
class TestDestinationFollowsUserLinks(unittest.TestCase):
    """EmuDeck links bios/shadps4/sys_modules into shadPS4's own directory.

    The manifest still cannot climb out of the BIOS root, but a link the
    user's frontend placed under it is where the emulator reads the file.
    """

    def test_symlinked_directory_under_root_is_followed(self):
        bios = Path(_tempdir(self))
        elsewhere = Path(_tempdir(self)) / "sys_modules"
        elsewhere.mkdir()
        (bios / "shadps4").mkdir()
        (bios / "shadps4" / "sys_modules").symlink_to(elsewhere)

        dest = install._destination_path(bios, "shadps4/sys_modules/libSceLibcInternal.sprx")

        self.assertEqual(dest, bios.resolve() / "shadps4" / "sys_modules" / "libSceLibcInternal.sprx")
        self.assertEqual(dest.resolve().parent, elsewhere.resolve())

    def test_check_local_survives_a_linked_directory(self):
        bios = Path(_tempdir(self))
        elsewhere = Path(_tempdir(self)) / "sys_modules"
        elsewhere.mkdir()
        (bios / "shadps4").mkdir()
        (bios / "shadps4" / "sys_modules").symlink_to(elsewhere)
        entry = {"dest": "shadps4/sys_modules/x.sprx", "size": 1, "sha1": "0" * 40}

        to_download, up_to_date, mismatched = install.check_local([entry], bios)

        self.assertEqual([e["dest"] for e in to_download], ["shadps4/sys_modules/x.sprx"])
        self.assertEqual((up_to_date, mismatched), ([], []))

    def test_climbing_is_still_refused(self):
        bios = Path(_tempdir(self))
        with self.assertRaises(ValueError):
            install._destination_path(bios, "../outside.bin")
        with self.assertRaises(ValueError):
            install._destination_path(bios, "/etc/passwd")


class TestDetectedPlatformPrompt(unittest.TestCase):
    """With two platforms detected the menu had no quit entry, and q or any
    wrong answer brought back a bare prompt."""

    PLATFORMS = [("emudeck", Path("/e")), ("retroarch", Path("/r"))]

    def _answer(self, *answers: str):
        replies = iter(answers)
        out = io.StringIO()
        with unittest.mock.patch("builtins.input", lambda _prompt="": next(replies)), \
                contextlib.redirect_stdout(out):
            try:
                result = install._prompt_platform_choice(self.PLATFORMS)
            except SystemExit as exc:
                result = exc
        return result, out.getvalue()

    def test_q_quits_and_the_menu_says_so(self):
        result, out = self._answer("q")
        self.assertIsInstance(result, SystemExit)
        self.assertEqual(result.code, install.QUIT_CODE)
        self.assertIn("q) quit", out)

    def test_a_wrong_answer_names_the_choices(self):
        result, out = self._answer("x", "2")
        self.assertEqual(result, [self.PLATFORMS[1]])
        self.assertIn("Type a number from 1 to 2, or q to quit.", out)

    def test_enter_takes_the_first_and_there_is_no_all(self):
        """The screen focuses the first and has no All."""
        result, out = self._answer("")
        self.assertEqual(result, [self.PLATFORMS[0]])
        self.assertNotIn("All", out)


class TestManualPlatformPrompt(unittest.TestCase):
    """With nothing detected, an interactive run asks instead of exiting.

    Every test runs on no drive and a home of its own: two read the host's
    drives and home, and failed with a card in the reader."""

    def setUp(self):
        home = Path(_tempdir(self))
        for patcher in (unittest.mock.patch.object(install, "_mounted_cards", return_value=[]),
                        unittest.mock.patch.object(install, "_mount_points",
                                                   return_value=frozenset()),
                        unittest.mock.patch.object(install.Path, "home", return_value=home),
                        unittest.mock.patch.dict(os.environ, {"HOME": str(home)}),
                        unittest.mock.patch("sys.stdout", io.StringIO())):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_the_host_is_not_read(self):
        self.assertEqual(install._mounted_cards(), [])
        self.assertEqual(install._default_dest("linux", "retroarch"),
                         Path.home() / ".config" / "retroarch" / "system")

    def test_number_picks_the_platform_and_default_directory(self):
        answers = iter(["1", ""])
        with unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)):
            chosen = install._prompt_manual_platform("linux")
        self.assertEqual(
            chosen, [("retroarch", Path.home() / ".config" / "retroarch" / "system")]
        )

    def test_enter_takes_retroarch_as_the_dest_menu_does(self):
        """The --dest menu offered `[Enter for RetroArch]` and this one, the
        same list, had no default."""
        answers = iter(["", ""])
        out = io.StringIO()
        with unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                contextlib.redirect_stdout(out):
            chosen = install._prompt_manual_platform("linux")
        self.assertEqual(chosen[0][0], "retroarch")

    def test_name_and_explicit_directory(self):
        answers = iter(["batocera", "~/my bios"])
        with unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)):
            chosen = install._prompt_manual_platform("linux")
        self.assertEqual(chosen, [("batocera", Path("~/my bios").expanduser())])

    def test_default_directory_comes_from_the_table(self):
        answers = iter(["retropie", ""])
        with unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                unittest.mock.patch.object(install, "_mounted_cards", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()):
            chosen = install._prompt_manual_platform("linux")
        self.assertEqual(chosen, [("retropie", install.DEFAULT_DESTS["retropie"])])

    def test_lakka_on_a_computer_asks_for_its_card(self):
        """/storage/system, a folder only the Lakka machine has, was taken
        on a computer: Lakka keeps its BIOS on its card's STORAGE part."""
        card = Path(_tempdir(self))
        (card / ".config" / "retroarch").mkdir(parents=True)
        (card / ".config" / "retroarch" / "retroarch.cfg").write_text(
            'system_directory = "/tmp/system"\n')
        answers = iter(["lakka"])
        out = io.StringIO()
        with unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                unittest.mock.patch.object(install, "_mounted_cards", return_value=[card]), \
                contextlib.redirect_stdout(out):
            chosen = install._prompt_manual_platform("linux")
        self.assertEqual(chosen, [("lakka", card / "system")])
        self.assertIn("Lakka card found", out.getvalue())

    def test_batocera_on_a_computer_gets_no_default(self):
        """/userdata/bios, a folder only the Batocera
        machine has, was offered on a computer, and Enter took it."""
        answers = iter(["batocera", "", "~/share/bios"])
        out = io.StringIO()
        with unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                unittest.mock.patch.object(install, "_mounted_cards", return_value=[]), \
                contextlib.redirect_stdout(out):
            chosen = install._prompt_manual_platform("linux")
        self.assertEqual(chosen, [("batocera", Path("~/share/bios").expanduser())])
        self.assertIn("SHARE drive", out.getvalue())
        self.assertNotIn("/userdata/bios", out.getvalue())

    def test_quit_stops_like_ctrl_c(self):
        """`install.sh && retroarch` went on to start RetroArch with no BIOS
        after a q, which left with 0 where Ctrl+C leaves with 130."""
        with unittest.mock.patch("builtins.input", lambda _prompt="": "q"):
            with self.assertRaises(SystemExit) as raised:
                install._prompt_manual_platform("linux")
        self.assertEqual(raised.exception.code, install.QUIT_CODE)

    def test_quotes_around_a_typed_folder_are_dropped(self):
        """Explorer's "Copy as path" quotes the folder: the files went into a
        folder named `"` under the current directory, and the run said Done."""
        root = Path(_tempdir(self))
        for typed in (f'"{root}/My Card/bios"', f"'{root}/My Card/bios'",
                      f'  "{root}/My Card/bios"  '):
            answers = iter(["1", typed])
            with self.subTest(typed=typed), \
                    unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                    contextlib.redirect_stdout(io.StringIO()):
                chosen = install._prompt_manual_platform("linux")
            self.assertEqual(chosen, [("retroarch", root / "My Card" / "bios")])

    def test_home_and_variables_are_expanded_on_every_system(self):
        for os_type in ("linux", "windows", "darwin"):
            answers = iter(["1", '"~/$RB_TEST_DIR/bios"'])
            with self.subTest(os_type=os_type), \
                    unittest.mock.patch.dict(os.environ, {"RB_TEST_DIR": "cards"}), \
                    unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                    contextlib.redirect_stdout(io.StringIO()):
                chosen = install._prompt_manual_platform(os_type)
            self.assertEqual(chosen[0][1], Path.home() / "cards" / "bios")

    def test_a_default_folder_not_there_is_not_found(self):
        """With nothing installed, Enter printed "Found RetroArch at" a
        folder that did not exist."""
        root = Path(_tempdir(self))
        answers = iter(["1", ""])
        out = io.StringIO()
        with unittest.mock.patch.object(install, "_default_dest",
                                        return_value=root / "retroarch" / "system"), \
                unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                contextlib.redirect_stdout(out):
            install._prompt_manual_platform("linux")
        self.assertIn("default BIOS folder", out.getvalue())
        self.assertIn("will be created", out.getvalue())
        self.assertNotIn("Found", out.getvalue())

    def test_a_wrong_answer_says_what_to_type(self):
        answers = iter(["99", "1", ""])
        out = io.StringIO()
        with unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                contextlib.redirect_stdout(out):
            install._prompt_manual_platform("linux")
        self.assertIn("or q to quit", out.getvalue())

    def test_windows_hint_shows_the_one_liner_with_arguments(self):
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": "ps1"}):
            hint = "\n".join(install._manual_usage_hint("windows"))
        self.assertIn("--platform retroarch --dest", hint)
        self.assertIn("/i.ps1", hint)


class TestSteamRetroarchDetection(unittest.TestCase):
    """The Steam build is a portable install under the default library."""

    def test_steam_library_is_found_on_windows(self):
        program_files = Path(_tempdir(self))
        ra_dir = program_files / "Steam" / "steamapps" / "common" / "RetroArch"
        ra_dir.mkdir(parents=True)
        (ra_dir / "retroarch.cfg").write_text('system_directory = ":\\system"\n')
        env = {"ProgramFiles(x86)": str(program_files)}
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            found = install.detect_platforms("windows")
        self.assertIn(("retroarch", ra_dir / "system"), found)


class TestLaunchboxDetectionPowershell(unittest.TestCase):
    """install.ps1 must resolve LaunchBox's portable RetroArch on its own."""

    def _run(self, entries: str, seed=None, manifest: dict | None = None):
        userprofile = Path(_tempdir(self))
        ra_dir = userprofile / "LaunchBox" / "Emulators" / "RetroArch"
        ra_dir.mkdir(parents=True)
        data = userprofile / "LaunchBox" / "Data"
        data.mkdir(parents=True)
        (data / "Emulators.xml").write_text(
            "<?xml version=\"1.0\" standalone=\"yes\"?>\n"
            "<LaunchBox>\n"
            f"{entries}"
            "</LaunchBox>\n"
        )
        if seed is not None:
            seed(userprofile)
        serve_root = Path(_tempdir(self))
        (serve_root / "install").mkdir()
        payload = dict(manifest if manifest is not None else {"files": []})
        payload.setdefault("manifest_version", 2)
        payload.setdefault("platform", "retroarch")
        payload.setdefault("files", [])
        (serve_root / "install" / "retroarch.json").write_text(json.dumps(payload))
        handler = functools.partial(
            http.server.SimpleHTTPRequestHandler, directory=str(serve_root)
        )
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            env = dict(os.environ)
            env.update(
                USERPROFILE=str(userprofile),
                APPDATA=str(_tempdir(self)),
                RETROBIOS_BASE_URL=f"http://127.0.0.1:{httpd.server_address[1]}",
                # A LaunchBox layout is a Windows layout: the runner is Linux.
                RETROBIOS_OS="wsl",
            )
            proc = subprocess.run(
                [
                    "pwsh", "-NoProfile", "-File",
                    str(REPO_ROOT / "install.ps1"), "--standalone-copies", "--verbose",
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
        finally:
            httpd.shutdown()
            httpd.server_close()
        return proc, ra_dir

    def _assert_resolved(self, proc, ra_dir):
        self.assertIn("Found LaunchBox", proc.stdout)
        self.assertIn("Found RetroArch at", proc.stdout)
        self.assertIn(str(ra_dir), proc.stdout)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Done.", proc.stdout)

    def test_detects_launchbox_retroarch(self):
        proc, ra_dir = self._run(
            "  <Emulator>\n"
            "    <Title>Retroarch</Title>\n"
            "    <ApplicationPath>Emulators\\RetroArch\\retroarch.exe</ApplicationPath>\n"
            "  </Emulator>\n"
        )
        self._assert_resolved(proc, ra_dir)

    def test_stale_entry_before_installed_one(self):
        proc, ra_dir = self._run(
            "  <Emulator>\n"
            "    <Title>RetroArch (old)</Title>\n"
            "    <ApplicationPath>Emulators\\RetroArch-old\\retroarch.exe</ApplicationPath>\n"
            "  </Emulator>\n"
            "  <Emulator>\n"
            "    <Title>RetroArch</Title>\n"
            "    <ApplicationPath>Emulators\\RetroArch\\retroarch.exe</ApplicationPath>\n"
            "  </Emulator>\n"
        )
        self._assert_resolved(proc, ra_dir)

    def test_system_directory_from_config(self):
        def seed(root: Path) -> None:
            ra = root / "LaunchBox" / "Emulators" / "RetroArch"
            (ra / "bios").mkdir(parents=True)
            (ra / "retroarch.cfg").write_text('system_directory = ":\\bios"\n')

        proc, ra_dir = self._run(
            "  <Emulator>\n"
            "    <Title>RetroArch</Title>\n"
            "    <ApplicationPath>Emulators\\RetroArch\\retroarch.exe</ApplicationPath>\n"
            "  </Emulator>\n",
            seed=seed,
        )
        self.assertIn("Found LaunchBox", proc.stdout)
        self.assertIn("Found RetroArch at", proc.stdout)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(str(ra_dir / "bios"), proc.stdout)

    def test_standalone_copy_reaches_launchbox_emulator(self):
        def seed(root: Path) -> None:
            system = root / "LaunchBox" / "Emulators" / "RetroArch" / "system"
            system.mkdir(parents=True)
            (system / "ps2-0230a.bin").write_text("rom")
            pcsx2 = root / "LaunchBox" / "Emulators" / "PCSX2"
            (pcsx2 / "bios").mkdir(parents=True)
            (pcsx2 / "portable.ini").write_text("")
            (pcsx2 / "inis").mkdir()
            (pcsx2 / "inis" / "PCSX2.ini").write_text("[Folders]\nBios = bios\n")

        manifest = {
            "files": [],
            "standalone_copies": [
                {
                    "pattern": "ps2-*.bin",
                    "emulator": "pcsx2",
                    "targets": {"windows": []},
                }
            ],
        }
        proc, ra_dir = self._run(
            "  <Emulator>\n"
            "    <Title>RetroArch</Title>\n"
            "    <ApplicationPath>Emulators\\RetroArch\\retroarch.exe</ApplicationPath>\n"
            "  </Emulator>\n"
            "  <Emulator>\n"
            "    <Title>PCSX2</Title>\n"
            "    <ApplicationPath>Emulators\\PCSX2\\pcsx2.exe</ApplicationPath>\n"
            "  </Emulator>\n",
            seed=seed,
            manifest=manifest,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        landed = ra_dir.parent / "PCSX2" / "bios" / "ps2-0230a.bin"
        self.assertTrue(landed.exists(), proc.stdout)


class TestForcedOs(unittest.TestCase):
    """RETROBIOS_OS overrides detection with a known name only."""

    def test_known_name_wins(self):
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_OS": "Windows"}):
            self.assertEqual(install.detect_os(), "windows")

    def test_unknown_name_is_ignored(self):
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_OS": "amiga"}):
            self.assertIn(install.detect_os(), ("linux", "wsl", "windows", "darwin"))


class TestDetectFrontends(unittest.TestCase):
    """Frontends have no BIOS directory of their own but hint at the setup."""

    def test_esde_from_home_directory(self):
        home = Path(_tempdir(self))
        (home / "ES-DE").mkdir()
        old = os.environ.pop("ESDE_APPDATA_DIR", None)
        try:
            self.assertIn("esde", install.detect_frontends("linux", home=home))
        finally:
            if old is not None:
                os.environ["ESDE_APPDATA_DIR"] = old

    def test_esde_from_env_dir(self):
        home = Path(_tempdir(self))
        appdata = Path(_tempdir(self))
        os.environ["ESDE_APPDATA_DIR"] = str(appdata)
        try:
            self.assertIn("esde", install.detect_frontends("linux", home=home))
        finally:
            del os.environ["ESDE_APPDATA_DIR"]

    def test_nothing_detected(self):
        home = Path(_tempdir(self))
        old = os.environ.pop("ESDE_APPDATA_DIR", None)
        try:
            self.assertEqual(install.detect_frontends("linux", home=home), [])
        finally:
            if old is not None:
                os.environ["ESDE_APPDATA_DIR"] = old


class TestNormalizePlatform(unittest.TestCase):
    """Manifest URLs are case sensitive: user input must be normalized."""

    def test_lowercases_input(self):
        self.assertEqual(install.normalize_platform("Batocera"), "batocera")

    def test_strips_whitespace(self):
        self.assertEqual(install.normalize_platform(" retroarch "), "retroarch")

    def test_unknown_platform_exits(self):
        with self.assertRaises(SystemExit):
            install.normalize_platform("launchbox")

    def test_all_available_platforms_accepted(self):
        for plat in install.AVAILABLE_PLATFORMS:
            self.assertEqual(install.normalize_platform(plat), plat)


class TestAvailablePlatforms(unittest.TestCase):
    """The platform list must match the generated manifests."""

    def test_matches_install_manifests(self):
        manifests = {p.stem for p in (REPO_ROOT / "install").glob("*.json")}
        self.assertEqual(set(install.AVAILABLE_PLATFORMS), manifests)

    def test_every_registered_platform_is_installable(self):
        """The installer serves every registered platform from its manifest."""
        import sys as _sys

        _sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from common import list_registered_platforms

        registered = set(
            list_registered_platforms(
                str(REPO_ROOT / "platforms")
            )
        )
        missing = registered - set(install.AVAILABLE_PLATFORMS)
        self.assertEqual(missing, set(), f"no install manifest for {sorted(missing)}")

    def test_powershell_wrapper_pins_installer_hash(self):
        content = (REPO_ROOT / "install.ps1").read_text()
        match = re.search(r'\$defaultInstallSha256 = "([0-9a-f]{64})"', content)
        self.assertIsNotNone(match, "install.ps1 must embed the installer SHA256")
        expected = hashlib.sha256((REPO_ROOT / "install.py").read_bytes()).hexdigest()
        self.assertEqual(match.group(1), expected, PIN_ADVICE)

    def test_powershell_wrapper_rejects_non_https_bootstrap(self):
        content = (REPO_ROOT / "install.ps1").read_text()
        self.assertIn('$uri.Scheme -ne "https"', content)

    def test_shell_wrapper_pins_installer_hash(self):
        content = (REPO_ROOT / "install.sh").read_text()
        match = re.search(r'DEFAULT_INSTALL_SHA256="([0-9a-f]{64})"', content)
        self.assertIsNotNone(match, "install.sh must embed the installer SHA256")
        expected = hashlib.sha256((REPO_ROOT / "install.py").read_bytes()).hexdigest()
        self.assertEqual(match.group(1), expected, PIN_ADVICE)

    def test_pin_script_writes_both_pins(self):
        """Every edit to install.py meant a sha256sum pasted by hand into two
        files with two syntaxes, and the failing test named no command."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import pin_installer  # noqa: PLC0415

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp" / "tests") as directory:
            root = Path(directory)
            for name in ("install.py", "install.sh", "install.ps1"):
                shutil.copy2(REPO_ROOT / name, root / name)
            (root / "install.py").write_text("# changed\n", encoding="utf-8")
            sh_mode = (root / "install.sh").stat().st_mode
            self.assertEqual(pin_installer.stale_pins(root), ["install.sh", "install.ps1"])
            self.assertEqual(pin_installer.write_pins(root), ["install.sh", "install.ps1"])
            self.assertEqual(pin_installer.stale_pins(root), [])
            digest = hashlib.sha256(b"# changed\n").hexdigest()
            for name in ("install.sh", "install.ps1"):
                before = (REPO_ROOT / name).read_text(encoding="utf-8").splitlines()
                after = (root / name).read_text(encoding="utf-8").splitlines()
                changed = [b for a, b in zip(before, after) if a != b]
                self.assertEqual(len(changed), 1, name)
                self.assertIn(digest, changed[0])
            self.assertEqual((root / "install.sh").stat().st_mode, sh_mode)

    def test_shell_one_liner_downloads_verifies_and_forwards_arguments(self):
        scratch = REPO_ROOT / "tmp" / "tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            # A piped script must not trust a same-named file in the caller's
            # working directory. Only a real local install.sh may use its peer.
            (root / "install.py").write_text(
                "raise SystemExit('untrusted cwd installer ran')\n",
                encoding="utf-8",
            )
            fake_bin = root / "bin"
            fake_bin.mkdir()
            marker = root / "curl-called"
            fake_curl = fake_bin / "curl"
            fake_curl.write_text(
                "#!/bin/sh\n"
                "output=\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = --output ]; then output=$2; shift 2; else shift; fi\n"
                "done\n"
                "cp -- \"$FAKE_INSTALLER_SOURCE\" \"$output\"\n"
                ": > \"$FAKE_CURL_MARKER\"\n",
                encoding="utf-8",
            )
            fake_curl.chmod(0o755)

            env = os.environ.copy()
            env.update(
                PATH=f"{fake_bin}{os.pathsep}{env['PATH']}",
                TMPDIR=str(root),
                RETROBIOS_INSTALL_URL="https://example.invalid/install.py",
                RETROBIOS_INSTALL_SHA256=hashlib.sha256(
                    (REPO_ROOT / "install.py").read_bytes()
                ).hexdigest(),
                FAKE_INSTALLER_SOURCE=str(REPO_ROOT / "install.py"),
                FAKE_CURL_MARKER=str(marker),
            )
            proc = subprocess.run(
                ["sh", "-s", "--", "--list-platforms"],
                cwd=root,
                env=env,
                input=(REPO_ROOT / "install.sh").read_text(encoding="utf-8"),
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertTrue(marker.is_file(), "piped bootstrap did not download install.py")
            self.assertIn("retroarch", proc.stdout)

    def test_busybox_wget_downloads_the_installer(self):
        """BusyBox wget, the only one in the RomM image, refuses
        --https-only: with no curl the one-liner always failed and blamed
        the network."""
        scratch = REPO_ROOT / "tmp" / "tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            for tool in ("mktemp", "wc", "tr", "sha256sum", "awk", "rm", "rmdir",
                         "grep", "tail", "cp", "dirname", "cat", "python3"):
                found = shutil.which(tool)
                if found:
                    (fake_bin / tool).symlink_to(found)
            (fake_bin / "wget").write_text(
                "#!/bin/sh\n"
                "output=\n"
                "for arg in \"$@\"; do\n"
                "  case \"$arg\" in\n"
                "    --help) echo 'Usage: wget [-cqS] [-O FILE] [-T SEC] URL' >&2; exit 1 ;;\n"
                "    --https-only) echo \"wget: unrecognized option '$arg'\" >&2; exit 1 ;;\n"
                "    --output-document=*) output=${arg#--output-document=} ;;\n"
                "  esac\n"
                "done\n"
                "cp -- \"$FAKE_INSTALLER_SOURCE\" \"$output\"\n",
                encoding="utf-8",
            )
            (fake_bin / "wget").chmod(0o755)
            env = {
                "PATH": str(fake_bin), "HOME": str(root), "TMPDIR": str(root),
                "RETROBIOS_INSTALL_URL": "https://example.invalid/install.py",
                "FAKE_INSTALLER_SOURCE": str(REPO_ROOT / "install.py"),
            }
            proc = subprocess.run(
                ["/bin/sh", "-s", "--", "--list-platforms"], cwd=root, env=env,
                input=(REPO_ROOT / "install.sh").read_text(encoding="utf-8"),
                capture_output=True, text=True, timeout=60, check=False,
            )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("retroarch", proc.stdout)

    @unittest.skipIf(os.name == "nt", "the sh bootstrap is POSIX")
    def test_ctrl_c_during_the_download_ends_with_130(self):
        """Ctrl+C while install.py downloaded: the trap cleaned up and the
        script went on to blame the network, with code 1."""
        scratch = REPO_ROOT / "tmp" / "tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            started = root / "started"
            (fake_bin / "curl").write_text(
                f"#!/bin/sh\n: > '{started}'\nexec sleep 60\n", encoding="utf-8")
            (fake_bin / "curl").chmod(0o755)
            env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                   "TMPDIR": str(root),
                   "RETROBIOS_INSTALL_URL": "https://example.invalid/install.py"}
            for shell in ("sh", "bash"):
                if not shutil.which(shell):
                    continue
                with self.subTest(shell=shell):
                    started.unlink(missing_ok=True)
                    proc = subprocess.Popen(
                        [shell, "-s", "--", "--check"], cwd=root, env=env,
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True, start_new_session=True)
                    proc.stdin.write((REPO_ROOT / "install.sh").read_text(encoding="utf-8"))
                    proc.stdin.close()
                    proc.stdin = None
                    try:
                        deadline = time.monotonic() + 30
                        while not started.exists() and time.monotonic() < deadline:
                            time.sleep(0.05)
                        self.assertTrue(started.exists(), "the download never started")
                        os.killpg(proc.pid, signal.SIGINT)
                        _out, err = proc.communicate(timeout=30)
                    finally:
                        if proc.poll() is None:
                            os.killpg(proc.pid, signal.SIGKILL)
                            proc.communicate()
                    self.assertEqual(proc.returncode, 130, err)
                    self.assertNotIn("could not be downloaded", err)
                    self.assertEqual(sorted(p.name for p in root.iterdir()),
                                     ["bin", "started"])

    @unittest.skipIf(os.name == "nt", "the sh bootstrap is POSIX")
    def test_a_versioned_python_is_found_beside_an_old_python3(self):
        """Buster keeps python3 at 3.7: the user installs python3.8 as the
        advice says, and the bootstrap, trying python3 and python alone,
        gave the same advice again."""
        root = Path(_tempdir(self))
        shutil.copy(REPO_ROOT / "install.sh", root / "install.sh")
        (root / "install.py").write_text("import sys\nprint('ran', sys.version_info >= (3, 8))\n")
        fake_bin = root / "bin"
        fake_bin.mkdir()
        old = ("#!/bin/sh\ncase \"$*\" in *SystemExit*) exit 1 ;; esac\n"
               "echo 3.7.3\n")
        for name in ("python3", "python"):
            (fake_bin / name).write_text(old)
            (fake_bin / name).chmod(0o755)
        tools = root / "tools"
        tools.mkdir()
        for tool in ("sh", "grep", "sort", "basename", "dirname", "uname", "sed", "tr"):
            found = shutil.which(tool)
            if found:
                (tools / tool).symlink_to(found)
        (fake_bin / "python3.11").symlink_to(sys.executable)
        proc = subprocess.run(
            [shutil.which("sh"), str(root / "install.sh")],
            env={"PATH": f"{fake_bin}{os.pathsep}{tools}", "HOME": str(root)},
            capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("ran True", proc.stdout)

    def test_a_failed_download_says_so_in_one_message(self):
        """Offline, the one-liner printed curl's progress table and
        "curl: (6) ...", then exited 6, a code the table does not list."""
        scratch = REPO_ROOT / "tmp" / "tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            (fake_bin / "curl").write_text(
                "#!/bin/sh\necho 'curl: (6) Could not resolve host: x' >&2\nexit 6\n",
                encoding="utf-8",
            )
            (fake_bin / "curl").chmod(0o755)
            env = os.environ.copy()
            env.update(
                PATH=f"{fake_bin}{os.pathsep}{env['PATH']}",
                TMPDIR=str(root),
                RETROBIOS_INSTALL_URL="https://example.invalid/install.py",
            )
            proc = subprocess.run(
                ["sh", "-s"], cwd=root, env=env,
                input=(REPO_ROOT / "install.sh").read_text(encoding="utf-8"),
                capture_output=True, text=True, timeout=30, check=False,
            )
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("could not be downloaded", proc.stderr)
        self.assertIn("Nothing was run and nothing was written", proc.stderr)
        self.assertEqual(proc.stderr.count("curl: (6)"), 1)

    def test_powershell_turns_a_failure_into_one_line(self):
        source = (REPO_ROOT / "install.ps1").read_text(encoding="utf-8")
        self.assertIn('[Console]::Error.WriteLine("Error: "', source)
        self.assertIn("winget install Python", source)

    @unittest.skipUnless(shutil.which("script"), "script(1) provides the terminal")
    def test_piped_one_liner_hands_the_terminal_to_the_installer(self):
        """curl | sh gives the installer the script as stdin, so isatty()
        was false and every question it asks was skipped on Linux and Mac."""
        scratch = REPO_ROOT / "tmp" / "tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            probe = root / "probe.py"
            probe.write_text(
                "import sys\nprint('installer stdin is a terminal:', sys.stdin.isatty())\n",
                encoding="utf-8",
            )
            fake_bin = root / "bin"
            fake_bin.mkdir()
            (fake_bin / "curl").write_text(
                "#!/bin/sh\n"
                "output=\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = --output ]; then output=$2; shift 2; else shift; fi\n"
                "done\n"
                f"cp -- {shlex.quote(str(probe))} \"$output\"\n",
                encoding="utf-8",
            )
            (fake_bin / "curl").chmod(0o755)
            env = os.environ.copy()
            env.update(
                PATH=f"{fake_bin}{os.pathsep}{env['PATH']}",
                TMPDIR=str(root),
                RETROBIOS_INSTALL_URL="https://example.invalid/install.py",
                RETROBIOS_INSTALL_SHA256=hashlib.sha256(probe.read_bytes()).hexdigest(),
            )
            piped = f"sh -s < {shlex.quote(str(REPO_ROOT / 'install.sh'))}"
            proc = subprocess.run(
                ["script", "-qec", piped, "/dev/null"],
                cwd=root, env=env, capture_output=True, text=True, timeout=30,
                check=False,
            )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("installer stdin is a terminal: True", proc.stdout)


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
            install.fetch_manifest("retroarch")
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
                contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit) as caught:
                install.fetch_manifest("retroarch")
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
                unittest.mock.patch.object(install, "MANIFEST_URL",
                                           f"http://127.0.0.1:{port}/{{platform}}.json"), \
                contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit):
                install.fetch_manifest("retroarch")
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


class RetroArchWhereItReallyLives(unittest.TestCase):
    """Windows: retroarch.cfg sits beside retroarch.exe and system defaults
    to <exe folder>\\system. Only %APPDATA% was read, and the fallback was a
    folder RetroArch never reads. macOS: the config is under
    Application Support/RetroArch/config, the system folder in Documents."""

    def _exe_dir(self) -> tuple[Path, dict]:
        program_files = Path(_tempdir(self))
        exe_dir = program_files / "RetroArch"
        exe_dir.mkdir()
        (exe_dir / "retroarch.exe").write_bytes(b"MZ")
        return exe_dir, {"ProgramFiles": str(program_files)}

    def test_windows_install_folder_without_a_config(self):
        exe_dir, env = self._exe_dir()
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            found = install.detect_platforms("windows")
        self.assertIn(("retroarch", exe_dir / "system"), found)

    def test_windows_appdata_config_at_default_names_the_exe_folder(self):
        exe_dir, env = self._exe_dir()
        appdata = Path(_tempdir(self))
        (appdata / "RetroArch").mkdir()
        (appdata / "RetroArch" / "retroarch.cfg").write_text('system_directory = "default"\n')
        env["APPDATA"] = str(appdata)
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            found = install.detect_platforms("windows")
        self.assertIn(("retroarch", exe_dir / "system"), found)

    def test_windows_config_beside_the_exe_wins(self):
        exe_dir, env = self._exe_dir()
        (exe_dir / "retroarch.cfg").write_text('system_directory = "D:\\bios"\n')
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            found = install.detect_platforms("windows")
        self.assertIn(("retroarch", Path("D:\\bios")), found)

    def test_macos_config_folder_and_documents_default(self):
        home = Path(_tempdir(self))
        support = home / "Library" / "Application Support" / "RetroArch"
        (support / "config").mkdir(parents=True)
        (support / "config" / "retroarch.cfg").write_text('system_directory = "default"\n')
        with unittest.mock.patch.object(install.Path, "home", return_value=home):
            found = install.detect_platforms("darwin")
            self.assertIn(("retroarch", home / "Documents" / "RetroArch" / "system"), found)
            (support / "portable.txt").write_text("")
            found = install.detect_platforms("darwin")
            self.assertIn(("retroarch", support / "system"), found)


class LinuxRetroArchFollowsXdgConfigHome(unittest.TestCase):
    """RetroArch on Linux keeps its config under $XDG_CONFIG_HOME/retroarch
    when the variable is set, then falls back to ~/.retroarch.cfg
    (file_path_special.c fill_pathname_application_data, configuration.c
    open_default_config_file). Only ~/.config/retroarch was read: a home
    with its own XDG layout detected nothing."""

    def _env(self) -> tuple[Path, Path]:
        home = Path(_tempdir(self))
        xdg = Path(_tempdir(self))
        patcher = unittest.mock.patch.dict(os.environ, {"HOME": str(home)}, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        return home, xdg

    def test_the_config_under_xdg_config_home_is_read(self):
        home, xdg = self._env()
        (xdg / "retroarch").mkdir()
        (xdg / "retroarch" / "retroarch.cfg").write_text('system_directory = "/srv/bios"\n')
        # A config under ~/.config is not the one this RetroArch opens.
        (home / ".config" / "retroarch").mkdir(parents=True)
        (home / ".config" / "retroarch" / "retroarch.cfg").write_text(
            'system_directory = "/elsewhere"\n')
        os.environ["XDG_CONFIG_HOME"] = str(xdg)
        found = install.detect_platforms("linux")
        self.assertIn(("retroarch", Path("/srv/bios")), found)
        self.assertNotIn(("retroarch", Path("/elsewhere")), found)
        self.assertEqual(install._os_default_dests("linux")["retroarch"],
                         xdg / "retroarch" / "system")

    def test_home_retroarch_cfg_is_the_fallback(self):
        home, xdg = self._env()
        os.environ["XDG_CONFIG_HOME"] = str(xdg)
        (home / ".retroarch.cfg").write_text('system_directory = "default"\n')
        found = install.detect_platforms("linux")
        self.assertIn(("retroarch", xdg / "retroarch" / "system"), found)

    def test_without_the_variable_the_folder_is_under_dot_config(self):
        home, _ = self._env()
        (home / ".config" / "retroarch").mkdir(parents=True)
        (home / ".config" / "retroarch" / "retroarch.cfg").write_text(
            'system_directory = "default"\n')
        found = install.detect_platforms("linux")
        self.assertIn(("retroarch", home / ".config" / "retroarch" / "system"), found)


class NoPythonNamesThisSystemsCommand(unittest.TestCase):
    """Without Python the bootstrap said `sudo apt install python3` on every
    system: Termux has no sudo and installs with `pkg install python`, and
    macOS has no apt."""

    def _run(self, extra_env: dict, uname: str = "Linux") -> subprocess.CompletedProcess:
        root = Path(_tempdir(self))
        fake_bin = root / "bin"
        fake_bin.mkdir()
        for tool in ("sed", "tr", "dirname", "cat"):
            found = shutil.which(tool)
            if found:
                (fake_bin / tool).symlink_to(found)
        (fake_bin / "uname").write_text(f"#!/bin/sh\necho {uname}\n", encoding="utf-8")
        (fake_bin / "uname").chmod(0o755)
        # No terminal: the Termux offer is a question asked on /dev/tty.
        return subprocess.run(
            ["/bin/sh", str(REPO_ROOT / "install.sh")], cwd=root,
            env={"PATH": str(fake_bin), "HOME": str(root), **extra_env},
            capture_output=True, text=True, timeout=30, check=False,
            start_new_session=True,
        )

    def test_termux_is_told_pkg(self):
        proc = self._run({"TERMUX_VERSION": "0.118",
                          "PREFIX": "/data/data/com.termux/files/usr"})
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Install it with: pkg install python", proc.stderr)
        self.assertNotIn("sudo", proc.stderr)

    def test_macos_is_told_xcode_select(self):
        proc = self._run({}, uname="Darwin")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Install it with: xcode-select --install", proc.stderr)
        self.assertNotIn("apt", proc.stderr)


class ABootstrapPythonCanDoHttps(unittest.TestCase):
    """find_python checked the version only: a python3 built without ssl
    was chosen over a full python, and every download then failed."""

    def _bin(self) -> tuple[Path, Path]:
        root = Path(_tempdir(self))
        fake_bin = root / "bin"
        fake_bin.mkdir()
        for tool in ("sed", "tr", "dirname", "cat", "awk", "uname"):
            found = shutil.which(tool)
            if found:
                (fake_bin / tool).symlink_to(found)
        shadow = root / "no-ssl"
        shadow.mkdir()
        (shadow / "ssl.py").write_text('raise ImportError("built without ssl")\n')
        (fake_bin / "python3").write_text(
            f'#!/bin/sh\nPYTHONPATH="{shadow}" exec {shlex.quote(sys.executable)} "$@"\n')
        (fake_bin / "python3").chmod(0o755)
        (root / "install.py").write_text("import ssl; print('installer ran')\n")
        shutil.copy(REPO_ROOT / "install.sh", root / "install.sh")
        return root, fake_bin

    def _run(self, root: Path, fake_bin: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["/bin/sh", str(root / "install.sh")], cwd=root,
            env={"PATH": str(fake_bin), "HOME": str(root)},
            capture_output=True, text=True, timeout=30, check=False,
            stdin=subprocess.DEVNULL, start_new_session=True,
        )

    def test_a_full_python_is_preferred(self):
        root, fake_bin = self._bin()
        (fake_bin / "python").symlink_to(sys.executable)
        proc = self._run(root, fake_bin)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("installer ran", proc.stdout)

    def test_an_old_python_is_named_with_its_version(self):
        """Debian Buster's python3 3.7 got "Install it with: sudo apt install
        python3", which apt answers with "already the newest version"."""
        root, fake_bin = self._bin()
        (fake_bin / "python3").write_text(
            '#!/bin/sh\ncase "$2" in *print*) echo 3.7.3 ;; esac\nexit 1\n')
        proc = self._run(root, fake_bin)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Python 3.8 or newer is required, and python3 here is 3.7.3.",
                      proc.stderr)
        self.assertNotIn("Install it with: sudo apt", proc.stderr)

    def test_the_missing_module_is_named(self):
        root, fake_bin = self._bin()
        proc = self._run(root, fake_bin)
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn("installer ran", proc.stdout)
        self.assertIn("python3 is built without a module the installer needs", proc.stderr)


@unittest.skipUnless(shutil.which("pwsh") and shutil.which("script"), "needs PowerShell and a terminal")
class WindowsWithoutPythonIsOfferedWinget(unittest.TestCase):
    """A Windows machine without Python was told to install it, open a new
    window and run the command again, while winget, present on Windows 10
    and 11, could do it from the bootstrap."""

    def _folder(self) -> tuple[Path, Path]:
        folder = Path(_tempdir(self))
        shutil.copy(REPO_ROOT / "install.ps1", folder / "install.ps1")
        (folder / "install.py").write_text("print('installer ran')\n")
        fake_bin = folder / "bin"
        fake_bin.mkdir()
        python = shutil.which("python3") or sys.executable
        (fake_bin / "winget").write_text(
            f"#!/bin/sh\necho \"winget $*\"\n{shutil.which('ln')} -s {shlex.quote(python)} "
            f"{shlex.quote(str(fake_bin / 'python3'))}\n"
        )
        (fake_bin / "winget").chmod(0o755)
        return folder, fake_bin

    def _run(self, folder: Path, fake_bin: Path, answer: str) -> subprocess.CompletedProcess:
        pwsh = shutil.which("pwsh")
        command = (f"{shlex.quote(pwsh)} -NoProfile -File "
                   f"{shlex.quote(str(folder / 'install.ps1'))}")
        return subprocess.run(
            [shutil.which("script"), "-qec", command, "/dev/null"], input=answer,
            env={**os.environ, "PATH": f"{fake_bin}{os.pathsep}/usr/bin/nonexistent"},
            capture_output=True, text=True, timeout=120, check=False,
        )

    def test_yes_installs_and_carries_on(self):
        folder, fake_bin = self._folder()
        proc = self._run(folder, fake_bin, "y\n")
        self.assertIn("Install Python 3.12 now with winget?", proc.stdout)
        self.assertIn("winget install --id Python.Python.3.12", proc.stdout)
        self.assertIn("installer ran", proc.stdout)
        self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_no_names_the_command(self):
        folder, fake_bin = self._folder()
        proc = self._run(folder, fake_bin, "n\n")
        self.assertNotIn("installer ran", proc.stdout)
        self.assertIn("winget install Python.Python.3.12", proc.stdout)
        self.assertFalse((fake_bin / "python3").exists())


@unittest.skipUnless(shutil.which("script"), "needs a terminal")
class TermuxStorageIsSetUpByTheBootstrap(unittest.TestCase):
    """The installer told an Android user to run termux-setup-storage and
    start the whole run over: the bootstrap runs it and waits for ~/storage."""

    def _run(self, storage_exists: bool) -> tuple[subprocess.CompletedProcess, Path]:
        root = Path(_tempdir(self))
        shutil.copy(REPO_ROOT / "install.sh", root / "install.sh")
        (root / "install.py").write_text("print('installer ran')\n")
        home = root / "home"
        home.mkdir()
        if storage_exists:
            (home / "storage").mkdir()
        fake_bin = root / "bin"
        fake_bin.mkdir()
        for tool in ("sed", "tr", "dirname", "cat", "awk", "uname", "sleep", "mkdir"):
            found = shutil.which(tool)
            if found:
                (fake_bin / tool).symlink_to(found)
        (fake_bin / "python3").symlink_to(sys.executable)
        # The app creates ~/storage once Android's dialog is answered.
        (fake_bin / "termux-setup-storage").write_text(
            f'#!/bin/sh\necho ran >> "{root}/setup.log"\nmkdir "$HOME/storage"\n')
        (fake_bin / "termux-setup-storage").chmod(0o755)
        command = (f"PATH={shlex.quote(str(fake_bin))} HOME={shlex.quote(str(home))} "
                   f"TERMUX_VERSION=0.118 /bin/sh {shlex.quote(str(root / 'install.sh'))}")
        proc = subprocess.run(
            [shutil.which("script"), "-qec", command, "/dev/null"],
            capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
        return proc, root

    def test_it_runs_once_then_the_installer(self):
        proc, root = self._run(storage_exists=False)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertEqual((root / "setup.log").read_text(), "ran\n")
        self.assertIn("allow it", proc.stdout)
        self.assertIn("installer ran", proc.stdout)

    def test_a_set_up_storage_is_left_alone(self):
        proc, root = self._run(storage_exists=True)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertFalse((root / "setup.log").exists())
        self.assertIn("installer ran", proc.stdout)


@unittest.skipUnless(shutil.which("pwsh"), "needs PowerShell")
class APyLauncherWithoutARuntimeIsPassed(unittest.TestCase):
    """findPython returned the py launcher as soon as it existed: one left
    with no usable runtime hid a Python 3.12 on PATH, and the bootstrap
    offered a second install or gave up."""

    def test_python_on_path_runs_the_installer(self):
        folder = Path(_tempdir(self))
        shutil.copy(REPO_ROOT / "install.ps1", folder / "install.ps1")
        (folder / "install.py").write_text("print('installer ran')\n")
        fake_bin = folder / "bin"
        fake_bin.mkdir()
        (fake_bin / "py").write_text("#!/bin/sh\necho 'No installed Python found!' >&2\nexit 1\n")
        (fake_bin / "py").chmod(0o755)
        (fake_bin / "python3").symlink_to(sys.executable)
        proc = subprocess.run(
            [shutil.which("pwsh"), "-NoProfile", "-File", str(folder / "install.ps1")],
            env={**os.environ, "PATH": f"{fake_bin}{os.pathsep}/usr/bin/nonexistent"},
            capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("installer ran", proc.stdout)


@unittest.skipUnless(shutil.which("pwsh"), "needs PowerShell")
class APowerShellDownloadThatNeverAnswersEnds(unittest.TestCase):
    """Invoke-WebRequest had no timeout: behind a server that takes the
    connection and never answers, the window waited forever with no line."""

    def test_a_silent_server_ends_on_the_network_advice(self):
        folder = Path(_tempdir(self))
        shutil.copy(REPO_ROOT / "install.ps1", folder / "install.ps1")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            port = listener.getsockname()[1]
            started = time.monotonic()
            proc = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(folder / "install.ps1"), "--check"],
                env={**os.environ,
                     "RETROBIOS_INSTALL_URL": f"https://127.0.0.1:{port}/install.py"},
                capture_output=True, text=True, timeout=150, stdin=subprocess.DEVNULL)
        self.assertLess(time.monotonic() - started, 120)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("could not be downloaded", " ".join((proc.stdout + proc.stderr).split()))


class ThePowerShellWrapperPassesTheStatusOn(unittest.TestCase):
    """Every non-zero exit became a red "installer failed" exception and
    code 1: a --check that found work read as a crash, 2 and 130 were lost."""

    @unittest.skipUnless(shutil.which("pwsh"), "needs PowerShell")
    def test_the_installer_code_comes_back_unchanged(self):
        folder = Path(_tempdir(self))
        shutil.copy(REPO_ROOT / "install.ps1", folder / "install.ps1")
        for code in (0, 1, 2, 130):
            with self.subTest(code=code):
                (folder / "install.py").write_text(f"import sys\nsys.exit({code})\n")
                proc = subprocess.run(
                    ["pwsh", "-NoProfile", "-File", str(folder / "install.ps1")],
                    capture_output=True, text=True, timeout=120,
                )
                self.assertEqual(proc.returncode, code, proc.stderr)
                self.assertNotIn("installer failed", proc.stdout + proc.stderr)


class ThePowerShellWrapperPassesEveryArgument(unittest.TestCase):
    """A [Parameter()] attribute made install.ps1 an advanced script, whose
    common parameters took `-v` (read as `-Verbose`), `-vb`, `-d` and `-ea`:
    the documented `-v` never reached install.py."""

    @unittest.skipUnless(shutil.which("pwsh"), "needs PowerShell")
    def test_short_flags_reach_the_installer(self):
        folder = Path(_tempdir(self))
        shutil.copy(REPO_ROOT / "install.ps1", folder / "install.ps1")
        (folder / "install.py").write_text(
            "import json, sys\nprint(json.dumps(sys.argv[1:]))\n"
        )
        for args in (["-v", "--check"], ["-vb"], ["-Verbose"], ["-d", "-ea", "x"],
                     ["--platform", "a b"], []):
            with self.subTest(args=args):
                proc = subprocess.run(
                    ["pwsh", "-NoProfile", "-File", str(folder / "install.ps1"), *args],
                    capture_output=True, text=True, timeout=120,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(json.loads(proc.stdout), args)


@unittest.skipIf(os.name == "nt" or os.geteuid() == 0, "needs a folder this user cannot write")
class AnUnwritableFolderIsCodeTwo(unittest.TestCase):
    """A BIOS folder that could not be created ended with 1, while the same
    folder existing read-only ended with the documented 2."""

    def test_both_shapes_exit_two(self):
        handler = functools.partial(
            http.server.SimpleHTTPRequestHandler, directory=str(REPO_ROOT)
        )
        handler.log_message = lambda *args: None
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        home = Path(tempfile.mkdtemp(dir=str(REPO_ROOT / "tmp")))
        locked = home / "locked"
        locked.mkdir()
        locked.chmod(0o555)
        self.addCleanup(shutil.rmtree, home, True)
        self.addCleanup(locked.chmod, 0o755)
        env = {
            **os.environ,
            "HOME": str(home),
            "RETROBIOS_OS": "linux",
            "RETROBIOS_BASE_URL": f"http://127.0.0.1:{httpd.server_address[1]}",
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



class CaseVariants(unittest.TestCase):
    """The RetroArch list is folded for Windows and macOS: a Linux user got
    BIOS.col and np2kai/2608_BD.WAV only, while Mesen-CE opens bios.col and
    np2kai np2kai/2608_bd.wav. The manifest carries those as case_variants,
    installed where the directory keeps case."""

    def _manifest(self, variants):
        entry = {
            "dest": "BIOS.col", "sha1": "a" * 40, "sha256": "b" * 64,
            "size": 8192, "repo_path": "bios/Coleco/BIOS.col", "cores": None,
        }
        return {
            "manifest_version": 2, "platform": "retroarch", "files": [entry],
            "total_files": 1, "total_size": 8192, "case_variants": variants,
        }

    def test_a_kept_case_directory_is_detected(self):
        directory = Path(_tempdir(self)) / "not" / "yet"
        self.assertTrue(install.keeps_case(directory))
        self.assertEqual(list(Path(directory.parents[1]).iterdir()), [])

    def test_variants_cross_the_trust_boundary(self):
        variant = {
            "dest": "bios.col", "sha1": "a" * 40, "sha256": "b" * 64,
            "size": 8192, "repo_path": "bios/Coleco/BIOS.col", "cores": ["mesence"],
        }
        install._validate_manifest(self._manifest([variant]), "retroarch")
        for bad in ({**variant, "dest": "../x"}, {**variant, "dest": "BIOS.col"}):
            with self.subTest(dest=bad["dest"]), self.assertRaises(ValueError):
                install._validate_manifest(self._manifest([bad]), "retroarch")

    def test_main_adds_them_only_where_case_is_kept(self):
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        compact = " ".join(source.split())
        self.assertIn(
            'variants = manifest.get("case_variants", []) '
            "case_kept = keeps_case(bios_path) if variants and case_kept:", compact,
        )

    def test_the_published_retroarch_list_carries_them(self):
        manifest = json.loads((REPO_ROOT / "install" / "retroarch.json").read_text())
        variants = {e["dest"] for e in manifest.get("case_variants", [])}
        self.assertIn("bios.col", variants)
        lakka = json.loads((REPO_ROOT / "install" / "lakka.json").read_text())
        folded = {e["dest"] for e in manifest["files"]}
        # A case-keeping RetroArch install is the Lakka list, less what
        # Lakka's own core packages install (installed_on: lakka).
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from common import load_emulator_profiles

        installed = {
            entry.get("path") or entry.get("name")
            for profile in load_emulator_profiles(str(REPO_ROOT / "emulators")).values()
            for entry in profile.get("files") or []
            if isinstance(entry, dict) and "lakka" in (entry.get("installed_on") or [])
        }
        lakka_dests = {e["dest"] for e in lakka["files"]}
        self.assertEqual(lakka_dests - (folded | variants), set())
        self.assertEqual((folded | variants) - lakka_dests - installed, set(),
                         "a case-keeping RetroArch install equals the Lakka list")



class AnUnreadableRetroDeckConfigIsSaid(unittest.TestCase):
    """retrodeck.json present but unreadable: the installer wrote to
    ~/retrodeck without a word, where a home moved to an SD card is not."""

    def test_the_fallback_is_announced(self):
        import contextlib

        home = Path(_tempdir(self))
        conf = home / ".var" / "app" / "net.retrodeck.retrodeck" / "config" / "retrodeck"
        conf.mkdir(parents=True)
        (conf / "retrodeck.json").write_text("{truncated")
        err = io.StringIO()
        with unittest.mock.patch.object(install.Path, "home", return_value=home), \
                unittest.mock.patch.object(install, "_detect_embedded", return_value=[]), \
                contextlib.redirect_stderr(err):
            found = install.detect_platforms("linux")
        self.assertIn(("retrodeck", home / "retrodeck"), found)
        self.assertIn("could not read paths.rd_home_path", err.getvalue())



class RetroDeckFoldersMovedOneByOne(unittest.TestCase):
    """RetroDECK moves its bios folder on its own and records the new place
    in retrodeck.json paths.bios_path, but only rd_home_path was read: the
    files went to <home>/bios, a folder RetroDECK no longer reads."""

    def _detect(self, paths: dict) -> tuple[Path, list]:
        home = Path(_tempdir(self))
        conf = home / ".var/app/net.retrodeck.retrodeck/config/retrodeck"
        conf.mkdir(parents=True)
        (conf / "retrodeck.json").write_text(json.dumps({"paths": paths}))
        with unittest.mock.patch.object(install.Path, "home", return_value=home), \
                unittest.mock.patch.object(install, "_detect_embedded", return_value=[]), \
                unittest.mock.patch.dict(install._MOVED_FOLDERS, clear=True), \
                contextlib.redirect_stderr(io.StringIO()):
            found = install.detect_platforms("linux")
            dests = {name: install._destination_path(home / "retrodeck", f"{name}/a.bin")
                     for name in ("bios", "roms", "saves")}
            label = install.found_label("retrodeck", home / "retrodeck")
        return home, [found, dests, label]

    def test_a_moved_bios_folder_is_followed(self):
        home = Path(_tempdir(self))
        sd = home / "sd"
        root, (found, dests, label) = self._detect({
            "rd_home_path": "", "bios_path": str(sd / "bios"), "roms_path": str(sd / "roms"),
        })
        rd_home = root / "retrodeck"
        self.assertIn(("retrodeck", rd_home), found)
        self.assertEqual(dests["bios"], (sd / "bios").resolve() / "a.bin")
        self.assertEqual(dests["roms"], (sd / "roms").resolve() / "a.bin")
        self.assertEqual(dests["saves"], rd_home.resolve() / "saves" / "a.bin")
        self.assertIn(f"bios/ at {sd / 'bios'}", label)

    def test_folders_in_place_change_nothing(self):
        home = Path(_tempdir(self))
        rd_home = home / "rd"
        _root, (found, dests, label) = self._detect({
            "rd_home_path": str(rd_home), "bios_path": str(rd_home / "bios"),
        })
        self.assertIn(("retrodeck", rd_home), found)
        self.assertNotIn("bios/ at", label)


class AndroidCitationsNameTheRelease(unittest.TestCase):
    """The Android detection cited platform_unix.c lines of a RetroArch
    revision nobody named, which no longer held the code they described."""

    def test_the_lines_are_those_of_v1_22_2(self):
        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        for text in (install._detect_android.__doc__, page):
            self.assertIn("v1.22.2", text)
            self.assertIn("platform_unix.c:1670-1697", text.replace("\n    ", ""))
            self.assertNotIn("1327-1395", text)
            self.assertNotIn("2836-2851", text)


class AndroidRetroArchFolderFollowsItsBuild(unittest.TestCase):
    """The Google Play build of RetroArch builds its defaults under
    Android/data/<package>/files/RetroArch, the retroarch.com build under
    the shared storage root (RetroArch v1.22.2, MainMenuActivity.java:
    182-183), and both publish com.retroarch and com.retroarch.aarch64.
    Detection sent every build to <shared storage>/RetroArch/system."""

    PLAY_CODE = 1597175870
    SITE_CODE = 1745000000

    def _run(self, make):
        root = Path(_tempdir(self))
        app_data, storage = root / "data", root / "storage"
        app_data.mkdir()
        storage.mkdir()
        make(app_data, storage)
        try:
            with unittest.mock.patch.object(install, "ANDROID_APP_DATA", app_data), \
                    unittest.mock.patch.dict(os.environ, {"EXTERNAL_STORAGE": str(storage)}):
                return storage, install._detect_android(), install.android_unreachable_folders()
        finally:
            for folder in root.rglob("*"):
                if folder.is_dir():
                    folder.chmod(0o755)

    @staticmethod
    def _install(app_data, storage, package, cfg=None, visible=True):
        (app_data / package).mkdir()
        if visible:
            files = storage / "Android" / "data" / package / "files"
            files.mkdir(parents=True)
            if cfg is not None:
                (files / "retroarch.cfg").write_text(cfg)

    @staticmethod
    def _cfg(code, system="default"):
        return (f'system_directory = "{system}"\n'
                f'bundle_assets_extract_version_current = "{code}"\n')

    def test_google_play_build_reads_its_own_files(self):
        storage, found, lines = self._run(lambda data, storage: self._install(
            data, storage, "com.retroarch", self._cfg(self.PLAY_CODE)))
        folder = storage / "Android/data/com.retroarch/files/RetroArch/system"
        self.assertEqual(found, [("retroarch", folder)])
        self.assertEqual(lines, [])

    def test_retroarch_com_build_reads_shared_storage(self):
        storage, found, lines = self._run(lambda data, storage: self._install(
            data, storage, "com.retroarch.aarch64", self._cfg(self.SITE_CODE)))
        self.assertEqual(found, [("retroarch", storage / "RetroArch/system")])
        self.assertEqual(lines, [])

    def test_ra32_has_no_google_play_build(self):
        storage, found, _lines = self._run(lambda data, storage: self._install(
            data, storage, "com.retroarch.ra32", 'system_directory = "default"\n'))
        self.assertEqual(found, [("retroarch", storage / "RetroArch/system")])

    def test_play_plus_folder_seen_without_a_config(self):
        def make(data, storage):
            self._install(data, storage, "com.retroarch.aarch64")
            (storage / "Android/data/com.retroarch.aarch64/files/RetroArch").mkdir()
        storage, found, _lines = self._run(make)
        self.assertEqual(found, [(
            "retroarch",
            storage / "Android/data/com.retroarch.aarch64/files/RetroArch/system")])

    def test_play_folder_out_of_reach_is_named(self):
        if os.geteuid() == 0:
            self.skipTest("root writes any folder")

        def make(data, storage):
            self._install(data, storage, "com.retroarch", self._cfg(self.PLAY_CODE))
            (storage / "Android/data/com.retroarch/files").chmod(0o555)
        storage, found, lines = self._run(make)
        self.assertEqual(found, [])
        self.assertEqual(len(lines), 1)
        self.assertIn("RetroArch (Google Play build, com.retroarch) is installed", lines[0])
        self.assertIn(str(storage / "Android/data/com.retroarch/files/RetroArch/system"),
                      lines[0])

    def test_hidden_private_data_and_shared_folder_mean_retroarch_com(self):
        def make(data, storage):
            self._install(data, storage, "com.retroarch", visible=False)
            (storage / "RetroArch").mkdir()
        storage, found, lines = self._run(make)
        self.assertEqual(found, [("retroarch", storage / "RetroArch/system")])
        self.assertEqual(lines, [])

    def test_undecided_build_names_both_folders(self):
        storage, found, lines = self._run(lambda data, storage: self._install(
            data, storage, "com.retroarch.aarch64", visible=False))
        self.assertEqual(found, [])
        self.assertEqual(len(lines), 1)
        self.assertIn(
            str(storage / "Android/data/com.retroarch.aarch64/files/RetroArch/system"),
            lines[0])
        self.assertIn(str(storage / "RetroArch/system"), lines[0])

    def test_named_folder_needs_no_build(self):
        storage, found, _lines = self._run(lambda data, storage: self._install(
            data, storage, "com.retroarch", f'system_directory = "{storage}/bios"\n'))
        self.assertEqual(found, [("retroarch", storage / "bios")])

    def test_each_installed_build_is_found(self):
        def make(data, storage):
            self._install(data, storage, "com.retroarch", self._cfg(self.PLAY_CODE))
            self._install(data, storage, "com.retroarch.ra32", self._cfg(self.SITE_CODE))
        storage, found, _lines = self._run(make)
        self.assertEqual(found, [
            ("retroarch", storage / "Android/data/com.retroarch/files/RetroArch/system"),
            ("retroarch", storage / "RetroArch/system"),
        ])

    def test_detection_prints_the_retroarch_line(self):
        err = io.StringIO()
        root = Path(_tempdir(self))
        (root / "data" / "com.retroarch").mkdir(parents=True)
        with unittest.mock.patch.object(install, "ANDROID_APP_DATA", root / "data"), \
                unittest.mock.patch.dict(os.environ, {"EXTERNAL_STORAGE": str(root / "s")}), \
                contextlib.redirect_stderr(err):
            install.detect_platforms("android")
        self.assertIn("RetroArch (com.retroarch) is installed", err.getvalue())


class AndroidEmulatorsOutOfReachAreSaid(unittest.TestCase):
    """DraStic keeps its BIOS in its private data and Flycast in
    Android/data, which Termux cannot write on Android 11 and later: both
    were skipped without a word."""

    def _lines(self, make) -> list[str]:
        root = Path(_tempdir(self))
        app_data, storage = root / "data", root / "storage"
        app_data.mkdir()
        make(app_data, storage)
        with unittest.mock.patch.object(install, "ANDROID_APP_DATA", app_data), \
                unittest.mock.patch.dict(os.environ, {"EXTERNAL_STORAGE": str(storage)}):
            return install.android_unreachable_folders()

    def test_nothing_installed_says_nothing(self):
        self.assertEqual(self._lines(lambda data, storage: None), [])

    def test_an_installed_drastic_is_named(self):
        lines = self._lines(lambda data, storage: (data / "com.dsemu.drastic").mkdir())
        self.assertEqual(len(lines), 1)
        self.assertIn("DraStic is installed", lines[0])
        self.assertIn("nds_bios_arm7.bin", lines[0])

    def test_flycast_out_of_reach_is_named(self):
        lines = self._lines(lambda data, storage: (data / "com.flycast.emulator").mkdir())
        self.assertEqual(len(lines), 1)
        self.assertIn("Flycast is installed", lines[0])
        self.assertIn("dc_boot.bin", lines[0])

    def test_a_writable_flycast_folder_is_a_copy_target(self):
        def make(data, storage):
            (data / "com.flycast.emulator").mkdir()
            (storage / "Android/data/com.flycast.emulator/files/data").mkdir(parents=True)
        self.assertEqual(self._lines(make), [])
        import yaml  # noqa: PLC0415

        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        copies = {entry.get("file"): entry for entry in registry["_standalone_copies"]}
        self.assertEqual(copies["dc/dc_boot.bin"]["targets"]["android"],
                         ["$EXTERNAL_STORAGE/Android/data/com.flycast.emulator/files/data"])

    def test_detection_prints_them(self):
        err = io.StringIO()
        with unittest.mock.patch.object(install, "_detect_android", return_value=[]), \
                unittest.mock.patch.object(install, "android_unreachable_folders",
                                           return_value=["DraStic is installed, but"]), \
                contextlib.redirect_stderr(err):
            install.detect_platforms("android")
        self.assertIn("DraStic is installed", err.getvalue())


class ACardPreparedOnAComputerGetsItsBoard(unittest.TestCase):
    """A Batocera RPi4 card prepared on a PC took every board's files (8.9 GB
    where bcm2711 reads 5.8): the board was read only on the device, and
    only without --dest, which the full-screen interface always gives."""

    def setUp(self):
        self.root = Path(_tempdir(self))
        self.boot = self.root / "BATOCERA"
        (self.boot / "boot").mkdir(parents=True)
        (self.boot / "boot" / "batocera.board").write_text("bcm2711\n")
        self.share = self.root / "SHARE"
        (self.share / "system").mkdir(parents=True)
        (self.share / "system" / "batocera.conf").write_text("system.hostname=BATOCERA\n")
        lists = self.root / "lists"
        (lists / "targets").mkdir(parents=True)
        one, two = b"pi core file", b"pc core file"
        self.list = lists / "batocera.json"
        self.list.write_text(json.dumps({
            "manifest_version": 2, "platform": "batocera", "base_destination": "bios",
            "files": [
                {"dest": "pi.bin", "sha1": hashlib.sha1(one).hexdigest(), "size": len(one),
                 "repo_path": "bios/pi.bin", "cores": ["picore"], "systems": ["pi"]},
                {"dest": "pc.bin", "sha1": hashlib.sha1(two).hexdigest(), "size": len(two),
                 "repo_path": "bios/pc.bin", "cores": ["pccore"], "systems": ["pc"]},
            ],
            "system_cores": {"pi": ["picore"], "pc": ["pccore"]},
        }))
        (lists / "targets" / "batocera.json").write_text(
            json.dumps({"bcm2711": ["picore"], "x86_64": ["pccore"]}))

    def run_main(self, *extra: str) -> tuple[str, list[dict]]:
        # A child process: main() changes the run's globals (the file list,
        # the event stream), which leaked into the next tests.
        code = ("import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
                "import install; card = Path(sys.argv[2]); "
                "install._mounted_cards = lambda: [card]; "
                "sys.argv = ['install.py', *sys.argv[3:]]; install.main()")
        env = {**os.environ, "RETROBIOS_OS": "linux", "HOME": str(self.root)}
        proc = subprocess.run(
            [sys.executable, "-c", code, str(REPO_ROOT), str(self.boot),
             "--platform", "batocera", "--dest", str(self.share), "--manifest",
             str(self.list), "--offline", "--check", "--events", *extra],
            env=env, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
        events = [json.loads(line) for line in proc.stdout.splitlines()
                  if line.startswith("{")]
        return proc.stdout + proc.stderr, events

    def test_the_boot_partition_names_the_board(self):
        with unittest.mock.patch.object(install, "_mounted_cards", return_value=[self.boot]):
            self.assertEqual(install.card_board("batocera"), "bcm2711")
            self.assertIsNone(install.card_board("retroarch"))

    def test_the_run_keeps_that_boards_files(self):
        _out, events = self.run_main()
        [board] = [event for event in events if event["event"] == "board"]
        self.assertEqual((board["board"], board["applied"]), ("bcm2711", True))
        self.assertIn("found on the card", board["message"])
        files = {event["dest"] for event in events if event["event"] == "file"}
        self.assertEqual(files, {"pi.bin"})

    def test_a_card_naming_its_image_gets_the_board_of_that_image(self):
        """A Batocera RG35XX Plus card names anbernic-rg35xx-plus, a zen3 one
        x86-64-v3: neither is a target name, and the card took every
        board's files (9.0 GB where h700 reads 6.1)."""
        (self.boot / "boot" / "batocera.board").write_text("anbernic-rg35xx-plus\n")
        (self.list.parent / "targets" / "batocera.json").write_text(json.dumps({
            "h700": {"cores": ["picore"], "images": ["anbernic-rg28xx",
                                                    "anbernic-rg35xx-plus"]},
            "x86_64": ["pccore"]}))
        out, events = self.run_main()
        [board] = [event for event in events if event["event"] == "board"]
        self.assertEqual((board["board"], board["applied"]), ("h700", True))
        self.assertIn("Board h700 (anbernic-rg35xx-plus) found on the card", out)
        files = {event["dest"] for event in events if event["event"] == "file"}
        self.assertEqual(files, {"pi.bin"})

    def test_an_image_two_boards_build_names_neither(self):
        targets = install._validate_targets({
            "zen3": {"cores": ["a"], "images": ["x86-64-v3"]},
            "rk3326": {"cores": ["b"], "images": ["r36s"]},
            "rk3566": {"cores": ["c"], "images": ["r36s"]}})
        self.assertEqual(install.board_target("x86-64-v3", targets), "zen3")
        self.assertEqual(install.board_target("zen3", targets), "zen3")
        self.assertIsNone(install.board_target("r36s", targets))

    def test_a_knulli_card_names_its_image_too(self):
        (self.boot / "boot" / "knulli.board").write_text("rg35xx-plus\n")
        with unittest.mock.patch.object(install, "_mounted_cards", return_value=[self.boot]):
            self.assertEqual(install.card_board("knulli"), "rg35xx-plus")
        published = json.loads((REPO_ROOT / "install" / "targets" / "knulli.json").read_text())
        self.assertEqual(install.board_target(
            "rg35xx-plus", install._validate_targets(published)), "h700")
        batocera = install._validate_targets(json.loads(
            (REPO_ROOT / "install" / "targets" / "batocera.json").read_text()))
        for image, board in (("anbernic-rg35xx-plus", "h700"), ("x86-64-v3", "zen3"),
                             ("odroidn2", "s922x"), ("bcm2711", "bcm2711")):
            self.assertEqual(install.board_target(image, batocera), board)

    def test_every_board_keeps_them_all(self):
        _out, events = self.run_main("--every-board")
        self.assertFalse([event for event in events if event["event"] == "board"])
        files = {event["dest"] for event in events if event["event"] == "file"}
        self.assertEqual(files, {"pi.bin", "pc.bin"})

    def test_the_plan_says_it(self):
        state = install.TuiState()
        state.run = "check"
        install._take_event(state, {"event": "board", "platform": "batocera",
                                  "board": "bcm2711", "applied": True,
                                  "message": "Board bcm2711 found on the card (x)"})
        self.assertEqual(state.board, "Board bcm2711 found on the card (x)")


class APlatformWithoutTargetsSaysSoOffline(unittest.TestCase):
    """Offline, --target on AmberELEC asked for install/targets/amberelec.json,
    which existed nowhere: online the same run said it had no targets.
    MiSTer FPGA has none still."""

    def test_the_list_matches_the_published_targets(self):
        published = {path.stem for path in (REPO_ROOT / "install" / "targets").glob("*.json")}
        self.assertEqual(install.TARGET_PLATFORMS, published)

    def test_offline_says_there_are_no_targets(self):
        dest = Path(_tempdir(self))
        for extra in ([], ["--manifest", str(REPO_ROOT / "install" / "misterfpga.json")]):
            with self.subTest(manifest=bool(extra)):
                proc = subprocess.run(
                    [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "misterfpga",
                     "--dest", str(dest), "--target", "de10-nano", "--offline", "--no-input",
                     "--dry-run", *extra],
                    capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertIn("MiSTer FPGA has no hardware targets", proc.stderr)
                self.assertNotIn("targets/misterfpga.json", proc.stderr)


class TheBoardTheSystemNamesIsTheTarget(unittest.TestCase):
    """Batocera, Recalbox and ROCKNIX each write the board they were built
    for, but the installer read none of them, so a Batocera RPi4 installed
    every board's files (8.6 GiB where bcm2711 needs 5.5)."""

    def test_each_source_is_read(self):
        root = Path(_tempdir(self))
        arch = root / "batocera.arch"
        arch.write_text("bcm2711")
        with unittest.mock.patch.dict(install._BOARD_SOURCES, {"batocera": ("file", str(arch))}):
            self.assertEqual(install.detect_board("batocera"), "bcm2711")
        with unittest.mock.patch.object(install, "_parse_os_release",
                                        return_value={"HW_DEVICE": "RK3326"}):
            self.assertEqual(install.detect_board("rocknix"), "rk3326")
        self.assertIsNone(install.detect_board("retroarch"))

    def test_retropie_names_its_pi_as_get_platform_does(self):
        """A RetroPie Pi 4 installed every target's files, 8.4 GiB where
        rpi4 needs 4.0: nothing read the Pi model."""
        root = Path(_tempdir(self))
        (root / "proc" / "device-tree").mkdir(parents=True)
        cpuinfo = root / "proc" / "cpuinfo"
        tree = root / "proc" / "device-tree" / "compatible"
        cases = (
            ("Hardware\t: BCM2835\nRevision\t: c03114\n", None, "rpi4"),
            ("Revision\t: d04170\n", b"raspberrypi,5-model-b\0brcm,bcm2712\0", "rpi5"),
            ("Hardware\t: BCM2835\nRevision\t: a02082\n", None, "rpi3"),
            ("Hardware\t: BCM2835\nRevision\t: 000e\n", None, "rpi1"),
            ("Hardware\t: ODROIDC\n", None, None),
        )
        with unittest.mock.patch.object(install, "_SYSTEM_ROOT", root):
            # Not installed here: a computer preparing a Pi's card.
            cpuinfo.write_text(cases[0][0])
            self.assertIsNone(install.detect_board("retropie"))
            (root / "opt" / "retropie").mkdir(parents=True)
            for text, compatible, board in cases:
                with self.subTest(board=board, text=text):
                    cpuinfo.write_text(text)
                    if compatible is None:
                        tree.unlink(missing_ok=True)
                    else:
                        tree.write_bytes(compatible)
                    self.assertEqual(install.detect_board("retropie"), board)
            tree.unlink(missing_ok=True)
            cpuinfo.write_text("processor\t: 0\n")
            with unittest.mock.patch.object(install.platform, "machine",
                                            return_value="x86_64"):
                self.assertEqual(install.detect_board("retropie"), "x86_64")
        targets = json.loads((REPO_ROOT / "install" / "targets" / "retropie.json")
                             .read_text(encoding="utf-8"))
        self.assertLessEqual({*install._RPI_MODELS.values(), "x86_64"}, set(targets))

    def test_amberelec_names_its_device(self):
        # An RG351P image carries no melonDS or bsnes, and the full list was
        # installed: AmberELEC had no target list to read the device against.
        with unittest.mock.patch.object(
            install, "_parse_os_release", return_value={"COREELEC_DEVICE": "RG351P"}
        ):
            self.assertEqual(install.detect_board("amberelec"), "rg351p")
        targets = json.loads((REPO_ROOT / "install" / "targets" / "amberelec.json")
                             .read_text(encoding="utf-8"))
        self.assertIn("rg351p", targets)

    def test_emuelec_names_its_device(self):
        # An OdroidGoAdvance image carries no DuckStation, Dolphin or MAME
        # core, and the full list was installed: EmuELEC had no target list.
        with unittest.mock.patch.object(
            install, "_parse_os_release", return_value={"COREELEC_DEVICE": "OdroidGoAdvance"}
        ):
            self.assertEqual(install.detect_board("emuelec"), "odroidgoadvance")
        targets = json.loads((REPO_ROOT / "install" / "targets" / "emuelec.json")
                             .read_text(encoding="utf-8"))
        self.assertIn("odroidgoadvance", targets)
        self.assertNotIn("Duckstation", targets["odroidgoadvance"])

    def test_lakka_names_its_device_or_its_project(self):
        # An RPi4 Lakka installed 5.7 GB of every board's files: its board
        # was in os-release and never read.
        for release, board in (
            ({"LIBREELEC_PROJECT": "RPi", "LIBREELEC_DEVICE": "RPi4"}, "rpi4"),
            ({"LIBREELEC_PROJECT": "Generic"}, "generic"),
        ):
            with self.subTest(board=board), unittest.mock.patch.object(
                install, "_parse_os_release", return_value=release
            ):
                self.assertEqual(install.detect_board("lakka"), board)

    def test_every_board_and_target_are_refused_together(self):
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--every-board",
             "--target", "bcm2711", "--platform", "batocera", "--dry-run"],
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--every-board", result.stderr)

    def test_the_sources_name_our_target_lists(self):
        import yaml  # noqa: PLC0415

        for platform in install._BOARD_SOURCES:
            with self.subTest(platform=platform):
                targets = yaml.safe_load(
                    (REPO_ROOT / "platforms" / "targets" / f"{platform}.yml").read_text()
                )["targets"]
                self.assertTrue(targets)



class CaseTwinsOnAFoldingVolume(unittest.TestCase):
    """Batocera and Recalbox list np2kai/bios.rom and np2kai/BIOS.ROM, other
    bytes each. Installed to a share opened from Windows or an exFAT card,
    the second overwrote the first and --check never converged."""

    def test_one_file_per_name_is_kept(self):
        files = [{"dest": "np2kai/bios.rom"}, {"dest": "np2kai/BIOS.ROM"}, {"dest": "x.bin"}]
        kept, folded = install.fold_case_twins(files)
        self.assertEqual([f["dest"] for f in kept], ["np2kai/bios.rom", "x.bin"])
        self.assertEqual(folded, ["np2kai/BIOS.ROM"])

    def test_main_folds_only_where_case_is_not_kept(self):
        source = " ".join((REPO_ROOT / "install.py").read_text(encoding="utf-8").split())
        self.assertIn("if not case_kept: files, folded = fold_case_twins(files)", source)



class StandaloneCopiesReachFlatpakInstalls(unittest.TestCase):
    """Copies went only to native and AppImage directories: Dolphin, PPSSPP
    and Azahar from Flathub received nothing. Azahar's native Linux
    directory was wrong too: XDG_DATA_HOME/azahar-emu (common_paths.h
    EMU_DATA_DIR), not azahar."""

    def test_flatpak_and_native_directories(self):
        import yaml  # noqa: PLC0415

        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        linux = {
            target
            for entry in registry["_standalone_copies"]
            for target in (entry.get("targets") or {}).get("linux", [])
        }
        for expected in (
            "$HOME/.var/app/org.DolphinEmu.dolphin-emu/data/dolphin-emu/GC/USA",
            "$HOME/.var/app/org.ppsspp.PPSSPP/config/ppsspp/PSP/SYSTEM",
            "$HOME/.var/app/org.azahar_emu.Azahar/data/azahar-emu/sysdata",
            "$HOME/.local/share/azahar-emu/sysdata",
        ):
            with self.subTest(target=expected):
                self.assertIn(expected, linux)
        self.assertNotIn("$HOME/.local/share/azahar/sysdata", linux)



class TheInstallerPageNamesEveryEvidence(unittest.TestCase):
    """The page said BizHawk, RetroBat, RomM and RetroPie had no detection
    and fell back to ~/bios, while install.py found each by its directory."""

    def test_every_rule_is_on_the_page(self):
        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        page = page.replace("\\\\", "\\")
        expected = [path for rule in install._EMBEDDED_RULES
                    if rule.method == "file_exists" for path in rule.values]
        expected += [rule.name for rule in install._EMBEDDED_RULES]
        expected += [path.replace("$HOME", "~").rstrip("/")
                     for _os, _p, path, _b in install._PATH_RULES]
        missing = [path for path in expected if path not in page]
        self.assertEqual(missing, [])
        self.assertNotIn("have no detection", page)



class BizHawkIsFoundWhereItReads(unittest.TestCase):
    """BizHawk reads <data dir>/Firmware: $BIZHAWK_DATA_HOME on Unix (the
    Nix package sets $XDG_DATA_HOME/emuhawk-monort-<version>), else the
    EmuHawk folder. Only two conventional folders were looked at, and a
    forced --platform bizhawk wrote where EmuHawk never reads."""

    def test_the_data_home_variable(self):
        home = Path(_tempdir(self))
        with unittest.mock.patch.dict(os.environ, {"BIZHAWK_DATA_HOME": str(home)}):
            self.assertEqual(install._bizhawk_unix_firmware(), home / "Firmware")

    def test_the_nix_data_home(self):
        xdg = Path(_tempdir(self))
        (xdg / "emuhawk-monort-2.11.1").mkdir()
        env = {"XDG_DATA_HOME": str(xdg), "BIZHAWK_DATA_HOME": ""}
        with unittest.mock.patch.dict(os.environ, env):
            self.assertEqual(
                install._bizhawk_unix_firmware(), xdg / "emuhawk-monort-2.11.1" / "Firmware"
            )

    def test_launchbox_names_emuhawk(self):
        source = " ".join((REPO_ROOT / "install.py").read_text(encoding="utf-8").split())
        self.assertIn('.get("emuhawk.exe")', source)



class RetroArchUwpIsFound(unittest.TestCase):
    """The UWP/MSIX RetroArch keeps retroarch.cfg and system/ in its
    package's LocalState, but no rule looked under %LOCALAPPDATA%\\Packages."""

    def _state(self) -> Path:
        local = Path(_tempdir(self))
        state = local / "Packages" / f"{install.RETROARCH_UWP_ID}_abc123" / "LocalState"
        state.mkdir(parents=True)
        patcher = unittest.mock.patch.dict(os.environ, {"LOCALAPPDATA": str(local)})
        patcher.start()
        self.addCleanup(patcher.stop)
        return state

    def test_the_default_is_local_state_system(self):
        state = self._state()
        self.assertEqual(install._retroarch_uwp_system_dir(), state / "system")

    def test_a_tilde_is_local_state(self):
        state = self._state()
        (state / "retroarch.cfg").write_text('system_directory = "~\\bios"\n')
        self.assertEqual(install._retroarch_uwp_system_dir(), state / "bios")

    def test_nothing_installed(self):
        with unittest.mock.patch.dict(os.environ, {"LOCALAPPDATA": _tempdir(self)}):
            self.assertIsNone(install._retroarch_uwp_system_dir())



class QuitMeansNoAtTheLastQuestion(unittest.TestCase):
    """Every menu taught q as quit, yet at "Download 3.2 GB ...? [Y/n]" a q
    started the download."""

    def test_quit_words_refuse(self):
        for answer, expected in (("q", False), ("quit", False), ("exit", False),
                                 ("n", False), ("No", False), ("", True), ("y", True)):
            with self.subTest(answer=answer), \
                    unittest.mock.patch.object(install, "_ask", return_value=answer):
                self.assertIs(install._confirm("? "), expected)



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



class DataDirectoriesAreInstalled(unittest.TestCase):
    """The README said the installer does what the pack does, but for RetroArch
    it left out 2,640 data files (Dolphin's Sys, PPSSPP's assets) and
    --check still said "All files up to date"."""

    def _zip(self, root: Path) -> Path:
        import zipfile

        archive = root / "Dolphin.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("Dolphin/Sys/GC/font.bin", b"font")
            zf.writestr("Dolphin/Sys/GC/dsp.bin", b"new bytes upstream")
            zf.writestr("Dolphin/Themes/x.png", b"theme")
        return archive

    def _entry(self) -> dict:
        return {
            "ref": "dolphin-sys", "dest": "dolphin-emu", "url": "https://example.invalid/D.zip",
            "type": "zip", "strip_components": 1, "exclude": ["Themes"],
            "systems": ["nintendo-gamecube"],
            "files": {
                "Sys/GC/font.bin": {"sha1": hashlib.sha1(b"font").hexdigest(), "size": 4},
                "Sys/GC/dsp.bin": {"sha1": hashlib.sha1(b"old").hexdigest(), "size": 3},
                "Sys/GC/gone.bin": {"sha1": "0" * 40, "size": 1},
            },
        }

    def test_required_only_leaves_out_an_optional_tree(self):
        """A GBA and a SNES game with --for-games --required-only took
        FBNeo's cheats and samples, 3,472 files no game opened."""
        cheats = {**self._entry(), "ref": "fbneo-cheats", "systems": ["snes"], "optional": True}
        sys_tree = {**self._entry(), "systems": ["snes"]}
        manifest = {"data_directories": [cheats, sys_tree]}
        files = [{"dest": "a.rom", "systems": ["snes"]}]
        self.assertEqual(install.select_data_directories(manifest, files, True), [cheats, sys_tree])
        self.assertEqual(install.select_data_directories(manifest, files, True, True), [sys_tree])
        self.assertEqual(install.select_data_directories(manifest, files, False, True), [sys_tree])
        install._check_data_directory(cheats, "data_directories[0]")
        with self.assertRaises(ValueError):
            install._check_data_directory({**cheats, "optional": False}, "data_directories[0]")

    def test_the_archive_is_drawn_and_counted(self):
        """82 MB of archives came with no progress line, and the run ended
        on "310.5 KB downloaded", the BIOS files alone."""
        work = Path(_tempdir(self))
        body = self._zip(work).read_bytes()
        attempts: list[int] = []

        class Response(io.BytesIO):
            headers = {"Content-Length": str(len(body))}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def urlopen(_url, timeout=None):
            attempts.append(1)
            if len(attempts) == 1:
                class Cut(Response):
                    def read(self, size=-1):
                        if self.tell():
                            raise ConnectionResetError("cut")
                        return super().read(5)
                return Cut(body)
            return Response(body)

        progress = install.Progress(1, 0, install.Terminal(io.StringIO()), events=False)
        with unittest.mock.patch.object(install.urllib.request, "urlopen", urlopen), \
                unittest.mock.patch.object(install, "_network_allowed", lambda url: None), \
                unittest.mock.patch.object(install, "_retry_delay", lambda *a: 0), \
                unittest.mock.patch.object(install.EVENTS, "emit") as emit:
            path = install._fetch_archive("https://example.invalid/D.zip", work, progress)
        self.assertEqual(path.read_bytes(), body)
        self.assertEqual(len(attempts), 2)
        # The cut attempt's five bytes are taken back.
        self.assertEqual((progress.transferred(), progress.expected_bytes),
                         (len(body), len(body)))
        emit.assert_not_called()

    def test_a_cut_archive_resumes_where_it_stopped(self):
        """A data archive cut at 90% was deleted and fetched again from
        zero, on the retry and on the next run, while the run said that
        nothing was lost."""
        work = Path(_tempdir(self))
        body = self._zip(work).read_bytes()
        keep = work / ".dolphin-sys.archive.part"
        requests: list[dict] = []

        class Response(io.BytesIO):
            def __init__(self, data, status, headers):
                super().__init__(data)
                self.status, self.headers = status, headers

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def urlopen(request, timeout=None):
            sent = dict(request.header_items())
            requests.append(sent)
            if "Range" in sent:
                start = int(sent["Range"][len("bytes="):-1])
                if sent.get("If-range") != '"v1"':
                    return Response(body, 200, {"ETag": '"v2"'})
                return Response(body[start:], 206, {
                    "Content-Range": f"bytes {start}-{len(body) - 1}/{len(body)}",
                    "Content-Length": str(len(body) - start), "ETag": '"v1"'})
            cut = len(body) * 9 // 10

            class Cut(Response):
                def read(self, size=-1):
                    if self.tell() >= cut:
                        raise ConnectionResetError("cut")
                    return super().read(min(size, cut - self.tell()))
            return Cut(body, 200, {"Content-Length": str(len(body)), "ETag": '"v1"'})

        with unittest.mock.patch.object(install.urllib.request, "urlopen", urlopen), \
                unittest.mock.patch.object(install, "_network_allowed", lambda url: None), \
                unittest.mock.patch.object(install, "_retry_delay", lambda *a: 0):
            # The next run, after a stop: what the cut attempt wrote is kept.
            with unittest.mock.patch.object(install, "MAX_RETRIES", 1), \
                    self.assertRaises(ConnectionResetError):
                install._fetch_archive("https://example.invalid/D.zip", work, None, keep)
            self.assertEqual(keep.stat().st_size, len(body) * 9 // 10)
            path = install._fetch_archive("https://example.invalid/D.zip", work, None, keep)
        self.assertEqual(path.read_bytes(), body)
        self.assertEqual(requests[-1]["Range"], f"bytes={len(body) * 9 // 10}-")
        self.assertEqual(requests[-1]["If-range"], '"v1"')

    def test_a_changed_archive_is_fetched_whole(self):
        work = Path(_tempdir(self))
        body = self._zip(work).read_bytes()
        keep = work / ".dolphin-sys.archive.part"
        keep.write_bytes(b"older revision")
        keep.with_name(keep.name + ".source").write_text(
            'https://example.invalid/D.zip\n"v0"\n')

        class Whole(io.BytesIO):
            status, headers = 200, {"ETag": '"v1"'}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with unittest.mock.patch.object(install.urllib.request, "urlopen",
                                        lambda request, timeout=None: Whole(body)), \
                unittest.mock.patch.object(install, "_network_allowed", lambda url: None):
            path = install._fetch_archive("https://example.invalid/D.zip", work, None, keep)
        self.assertEqual(path.read_bytes(), body)

    def test_a_tree_read_whole_leaves_no_archive(self):
        work = Path(_tempdir(self))
        archive = self._zip(work)
        bios = work / "system"
        bios.mkdir()

        def fetch(url, directory, progress=None, keep=None):
            shutil.copy(archive, keep)
            keep.with_name(keep.name + ".source").write_text(f"{url}\n\"v1\"\n")
            return keep

        with unittest.mock.patch.object(install, "_fetch_archive", fetch):
            install.install_data_directory(self._entry(), bios)
        self.assertEqual([p.name for p in (bios / "dolphin-emu").iterdir()], ["Sys"])

    def test_a_second_run_leaves_the_kept_archive_alone(self):
        """Two runs into one BIOS folder shared .dolphin-sys.archive.part: the
        one that finished first deleted the archive the other was still
        writing, and the other truncated the one being read."""
        work = Path(_tempdir(self))
        archive = self._zip(work)
        bios = work / "system"
        root = bios / "dolphin-emu"
        root.mkdir(parents=True)
        other = root / ".dolphin-sys.archive.part"
        other.write_bytes(b"another run is writing this")
        kept: list = []

        def fetch(url, directory, progress=None, keep=None):
            kept.append(keep)
            copy = Path(directory) / "private.zip"
            shutil.copy(archive, copy)
            return copy

        held = install._claim_partial(root / ".dolphin-sys.archive.lock")
        self.addCleanup(held.close)
        with unittest.mock.patch.object(install, "_fetch_archive", fetch):
            counts = install.install_data_directory(self._entry(), bios)
        self.assertEqual(kept, [None])
        self.assertEqual(counts["installed"], 1)
        self.assertEqual(other.read_bytes(), b"another run is writing this")
        self.assertTrue((root / ".dolphin-sys.archive.lock").exists())

    def test_a_lone_run_keeps_its_archive_beside_the_tree(self):
        work = Path(_tempdir(self))
        archive = self._zip(work)
        bios = work / "system"
        kept: list = []

        def fetch(url, directory, progress=None, keep=None):
            kept.append(keep)
            shutil.copy(archive, keep)
            return keep

        with unittest.mock.patch.object(install, "_fetch_archive", fetch):
            install.install_data_directory(self._entry(), bios)
        self.assertEqual(kept, [bios / "dolphin-emu" / ".dolphin-sys.archive.part"])
        self.assertEqual(sorted(p.name for p in (bios / "dolphin-emu").iterdir()), ["Sys"])

    def test_the_run_ends_on_the_archive_bytes_too(self):
        from test_install_selection import FakeRepository  # noqa: PLC0415

        member = os.urandom(300_000)
        with FakeRepository() as repo:
            with zipfile.ZipFile(repo.root / "tree.zip", "w") as zf:
                zf.writestr("Sys/big.bin", member)
            archive = (repo.root / "tree.zip").stat().st_size
            listed = json.loads((repo.root / "install" / "retroarch.json").read_text())
            listed["data_directories"] = [{
                "ref": "tree", "dest": "tree", "type": "zip",
                "url": f"http://127.0.0.1:{repo.httpd.server_address[1]}/tree.zip",
                "systems": ["nintendo-gba"],
                "files": {"Sys/big.bin": {"sha1": hashlib.sha1(member).hexdigest(),
                                          "size": len(member)}}}]
            (repo.root / "install" / "retroarch.json").write_text(json.dumps(listed))
            proc = repo.run("--no-input", "--verbose")
            bios = sum(len(payload) for payload, *_ in FakeRepository.PAYLOADS.values())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(f"{install.format_size(bios + archive)} downloaded in", proc.stdout)

    def test_the_plan_announces_the_archive_not_the_tree(self):
        """yaps2's tarball is 21.2 MB for a 6.5 MB tree, Cemu's 21.4 MB for
        9.9 KB: the plan announced the tree, and the run downloaded far more."""
        from test_install_selection import FakeRepository  # noqa: PLC0415

        member = b"profile"
        archive_size = 21_360_579
        with FakeRepository() as repo:
            listed = json.loads((repo.root / "install" / "retroarch.json").read_text())
            listed["data_directories"] = [{
                "ref": "cemu-gameprofiles", "dest": "cemu", "type": "tarball",
                "url": "https://example.invalid/Cemu.tar.gz", "source_path": "Cemu-1/bin",
                "systems": ["nintendo-gba"], "archive_size": archive_size,
                "files": {"gameProfiles/a.ini": {"sha1": hashlib.sha1(member).hexdigest(),
                                                 "size": len(member)}}}]
            (repo.root / "install" / "retroarch.json").write_text(json.dumps(listed))
            proc = repo.run("--no-input", "--dry-run")
            bios = sum(len(payload) for payload, *_ in FakeRepository.PAYLOADS.values())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(f"({install.format_size(bios + archive_size)})", proc.stdout)
        self.assertIn(f"(a {install.format_size(archive_size)} archive)", proc.stdout)

    def test_a_pack_or_an_old_list_counts_the_files_themselves(self):
        needed = {"a": {"size": 7}}
        entry = {"archive_size": 21_360_579}
        self.assertEqual(install.data_fetch_bytes(entry, needed), 21_360_579)
        self.assertEqual(install.data_fetch_bytes({}, needed), 7)
        self.assertEqual(install.data_fetch_bytes(entry, {}), 0)
        with unittest.mock.patch.object(install.LOCAL, "pack", object()):
            self.assertEqual(install.data_fetch_bytes(entry, needed), 7)

    def test_verified_members_land_the_rest_are_said(self):
        work = Path(_tempdir(self))
        archive = self._zip(work)
        bios = work / "system"
        bios.mkdir()

        def fetch(url, directory, progress=None, keep=None):
            copy = Path(directory) / "a.zip"
            shutil.copy(archive, copy)
            return copy

        with unittest.mock.patch.object(install, "_fetch_archive", fetch):
            counts = install.install_data_directory(self._entry(), bios)
            again = install.install_data_directory(self._entry(), bios)
        self.assertEqual((counts["installed"], counts["changed"], counts["absent"]), (1, 1, 1))
        self.assertEqual((bios / "dolphin-emu" / "Sys" / "GC" / "font.bin").read_bytes(), b"font")
        self.assertFalse((bios / "dolphin-emu" / "Sys" / "GC" / "dsp.bin").exists())
        self.assertFalse((bios / "dolphin-emu" / "Themes").exists())
        self.assertEqual(again["present"], 1)
        self.assertEqual(sorted(p.name for p in (bios / "dolphin-emu").iterdir()), ["Sys"])

    def test_a_member_that_inflates_is_cut_at_its_size(self):
        # A member whose header claims the recorded size and whose stream
        # never ends: reading stops one byte past it.
        class Endless(io.RawIOBase):
            served = 0

            def readable(self):
                return True

            def readinto(self, buffer):
                Endless.served += len(buffer)
                buffer[:] = b"x" * len(buffer)
                return len(buffer)

        work = Path(_tempdir(self))
        entry = self._entry()
        entry["files"] = {"Sys/GC/font.bin": {"sha1": "1" * 40, "size": 4}}

        def members(_archive, _entry):
            yield "Sys/GC/font.bin", 4, lambda: io.BufferedReader(Endless())

        with unittest.mock.patch.object(
                install, "_fetch_archive",
                lambda url, d, progress=None, keep=None: Path(d) / "a"), \
                unittest.mock.patch.object(install, "_archive_members", members):
            counts = install.install_data_directory(entry, work)
        self.assertEqual(counts["changed"], 1)
        self.assertLess(Endless.served, 64 * 1024)

    def test_a_damaged_member_is_a_reason_and_leaves_no_part(self):
        """zlib.error and EOFError from a damaged member ended the run on a
        traceback, and a failed write left its .part beside the tree."""
        import zlib

        work = Path(_tempdir(self))
        entry = self._entry()
        entry["files"] = {"Sys/GC/font.bin": {"sha1": "1" * 40, "size": 4}}
        for error in (zlib.error("invalid stored block lengths"), EOFError(),
                      OSError(28, "No space left on device")):
            with self.subTest(error=type(error).__name__):
                class Broken(io.RawIOBase):
                    def readable(self):
                        return True

                    def readinto(self, buffer, error=error):
                        raise error

                def members(_archive, _entry):
                    yield "Sys/GC/font.bin", 4, lambda: io.BufferedReader(Broken())

                with unittest.mock.patch.object(
                        install, "_fetch_archive",
                        lambda url, d, progress=None, keep=None: Path(d) / "a"), \
                        unittest.mock.patch.object(install, "_archive_members", members):
                    counts = install.install_data_directory(entry, work)
                self.assertTrue(counts["error"])
                self.assertEqual(counts["installed"], 0)
                self.assertEqual([p.name for p in work.rglob("*.part")], [])

    def test_offline_keeps_its_reason(self):
        work = Path(_tempdir(self))
        with unittest.mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            counts = install.install_data_directory(self._entry(), work)
        self.assertIsInstance(counts["error"], install.OfflineReason)

    def test_a_tarball_maps_through_source_path(self):
        import io as _io
        import tarfile

        work = Path(_tempdir(self))
        archive = work / "src.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            data = b"index"
            info = tarfile.TarInfo("pcsx2-v1/bin/resources/GameIndex.yaml")
            info.size = len(data)
            tf.addfile(info, _io.BytesIO(data))
        entry = {"type": "tarball", "source_path": "pcsx2-v1/bin/resources"}
        names = [rel for rel, _size, _open in install._archive_members(archive, entry)]
        self.assertEqual(names, ["GameIndex.yaml"])

    def test_the_trust_boundary(self):
        entry = self._entry()
        install._check_data_directory(entry, "d")
        for bad in ({"url": "http://example.com/x.zip"}, {"dest": "../up"},
                    {"files": {"../x": {"sha1": "0" * 40, "size": 1}}},
                    {"type": "rar"}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                install._check_data_directory({**entry, **bad}, "d")

    def test_the_published_retroarch_list_carries_them(self):
        manifest = json.loads((REPO_ROOT / "install" / "retroarch.json").read_text())
        dirs = manifest.get("data_directories") or []
        files = sum(len(d["files"]) for d in dirs)
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import generate_pack

        written = generate_pack.PACK_DOCUMENTS + generate_pack.pack_markers(
            "retroarch", None, str(REPO_ROOT / "platforms"))
        self.assertEqual(written, ("README.txt", "manifest.json", ".nomedia"))
        self.assertEqual(
            manifest["pack_files"] - manifest["total_files"] - files, len(written),
            "the pack's two documents and its .nomedia are the only files the "
            "installer lacks",
        )



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
            dest, ok, reason = install._download_one(entry, Path(_tempdir(self)))
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



class ACheckNamesWhatTheCollectionLacks(unittest.TestCase):
    """--check counted the required files the manifest leaves out and named
    none, then said all files were up to date: on Recalbox, c3.555 stayed
    unnamed for a user asking why Caesar III would not start."""

    def test_recalbox_caesar3(self):
        import shutil  # noqa: PLC0415
        import subprocess  # noqa: PLC0415

        manifest = json.loads((REPO_ROOT / "install" / "recalbox.json").read_text())
        lacking = sorted(
            e["dest"] for e in manifest.get("omitted_files", [])
            if e.get("required") and e.get("system") == "caesar3"
        )
        if not lacking:
            self.skipTest("the Recalbox manifest omits no required caesar3 file")
        handler = functools.partial(
            http.server.SimpleHTTPRequestHandler, directory=str(REPO_ROOT)
        )
        handler.log_message = lambda *args: None
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        home = Path(tempfile.mkdtemp(dir=str(REPO_ROOT / "tmp")))
        self.addCleanup(shutil.rmtree, home, True)
        env = {
            **os.environ, "HOME": str(home), "RETROBIOS_OS": "linux",
            "RETROBIOS_BASE_URL": f"http://127.0.0.1:{httpd.server_address[1]}",
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



class ARefusedStandaloneCopyIsNamed(unittest.TestCase):
    """A standalone copy refused by a read-only emulator folder counted as
    an error with no failures entry: the summary named no file, pointed at
    the BIOS folder and gave no advice."""

    def test_the_file_and_its_folder_reach_the_summary(self):
        import contextlib  # noqa: PLC0415

        if os.name == "nt" or os.geteuid() == 0:
            self.skipTest("a read-only folder needs POSIX modes and a non-root user")
        bios = Path(_tempdir(self))
        (bios / "scph5501.bin").write_bytes(b"x")
        target = Path(_tempdir(self)) / "pcsx2-bios"
        target.mkdir()
        target.chmod(0o500)
        self.addCleanup(target.chmod, 0o700)
        manifest = {"standalone_copies": [
            {"file": "scph5501.bin", "emulator": "pcsx2",
             "targets": {"linux": [str(target)]}},
        ]}
        failures: list = []
        with contextlib.redirect_stdout(io.StringIO()):
            _copied, _skipped, failed = install.do_standalone_copies(
                manifest, bios, "linux", None, failures)
        self.assertEqual(failed, 1)
        self.assertEqual(failures, [(str(target / "scph5501.bin"), install.NOT_WRITABLE)])

        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            install._report_outcome([bios], 0, 1, failed, 0, False, failures=failures)
        text = out.getvalue()
        self.assertIn(str(target / "scph5501.bin"), text)
        self.assertIn(str(target), text.split("BIOS folder")[-1])
        self.assertIn("cannot write there", text)



class AFullDriveIsSaidAsOne(unittest.TestCase):
    """A card filling up during a tree rebuild read `fbneo-cheats: could not
    read https://...: [Errno 28] No space left on device`, putting the cause
    on the source, and the run ended on `Run the same command again`."""

    def test_the_tree_reports_the_drive(self):
        work = Path(_tempdir(self))
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
        bios = Path(_tempdir(self))
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as ended:
            install._report_outcome([bios], 7, 0, 1, 0, False,
                                    failures=[("fbneo-cheats", install.DRIVE_FULL)])
        text = out.getvalue()
        self.assertEqual(ended.exception.code, 1)
        self.assertIn("is full: free up space, or install to another drive with --dest", text)
        self.assertNotIn("retry only those", text)

    def test_a_bios_file_on_a_full_drive_is_not_retried(self):
        bios = Path(_tempdir(self))
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
        from test_install_selection import FakeRepository  # noqa: PLC0415

        with FakeRepository() as repo:
            missing = repo.run("--no-input", "--check")
            nowhere = repo.run("--no-input", "--check", "--from", str(repo.root / "nope"))
            repo.run("--no-input")
            complete = repo.run("--no-input", "--check")
        self.assertEqual(missing.returncode, 3, missing.stdout + missing.stderr)
        self.assertEqual(nowhere.returncode, 1, nowhere.stdout + nowhere.stderr)
        self.assertEqual(complete.returncode, 0, complete.stdout + complete.stderr)


class OneEmulatorsFilesInOneCommand(unittest.TestCase):
    """An emulator page offers one command for that emulator's files.
    --core kept the platform's whole list, and narrowing to cores kept the
    platform files of every system no core is mapped to."""

    MANIFEST = {
        "system_cores": {"ibm-pc": ["pcem"], "nintendo-nes": ["fceumm"]},
        "core_names": {"pcem": ["pcem"], "fceumm": ["fceumm"]},
        "files": [],
    }

    def test_only_its_files_and_its_systems(self):
        import contextlib  # noqa: PLC0415

        files = [
            {"dest": "pcem/ibmpc.bin", "cores": ["pcem"], "systems": ["ibm-pc"]},
            {"dest": "disksys.rom", "cores": None, "systems": ["nintendo-nes"]},
            {"dest": "ep128emu/exos.rom", "cores": None, "systems": ["enterprise"]},
            {"dest": "ibm.rom", "cores": None, "systems": ["ibm-pc"]},
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            kept, _omitted = install._narrow_to_emulators(
                ["PCem"], self.MANIFEST, "retroarch", files, [])
        self.assertEqual(sorted(e["dest"] for e in kept), ["ibm.rom", "pcem/ibmpc.bin"])

    def test_an_unknown_name_is_refused(self):
        import contextlib  # noqa: PLC0415

        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            install._narrow_to_emulators(["nope"], self.MANIFEST, "retroarch", [], [])



class ThePagesQuoteTheBootstrapsOwnWords(unittest.TestCase):
    """The installer page and the FAQ quoted "install.py SHA-256 mismatch",
    a message the bootstraps no longer print."""

    def test_the_quoted_message_is_printed(self):
        quoted = "does not match its expected"
        for wrapper in ("install.sh", "install.ps1"):
            self.assertIn(quoted, (REPO_ROOT / wrapper).read_text(encoding="utf-8"))
        for page in ("wiki/installer.md", "wiki/faq.md"):
            text = (REPO_ROOT / page).read_text(encoding="utf-8")
            self.assertNotIn("SHA-256 mismatch`", text)
            self.assertIn(quoted, " ".join(text.split()))



class APartialIsClosedBeforeItIsDeleted(unittest.TestCase):
    """Windows refuses to delete an open file: a resumed partial copy whose
    hash no longer matched was unlinked with its handle still open, and the
    PermissionError ended the run."""

    def test_the_source_closes_first(self):
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        branch = source[source.index("        except _Corrupt:"):]
        branch = branch[:branch.index("delay = 0.0")]
        self.assertLess(branch.index("partial.close()"), branch.index("tmp_path.unlink()"))


class WindowsSeenFromWsl(unittest.TestCase):
    """Under WSL, C:\\RetroBat\\bios was a relative path, %APPDATA% and
    %USERPROFILE% were unset, and --platform retrobat wrote 7 753 files into
    ~/bios inside the distribution, where RetroBat reads nothing."""

    def setUp(self):
        self.root = Path(_tempdir(self))
        patcher = unittest.mock.patch.dict(install._WSL, {"active": True, "root": str(self.root)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_drive_path_is_its_mount(self):
        self.assertEqual(install._host_path("C:\\RetroBat\\bios"), self.root / "c" / "RetroBat" / "bios")
        self.assertEqual(install._rule_path("C:\\RetroBat\\bios"), self.root / "c" / "RetroBat" / "bios")
        self.assertEqual(install._default_dest("wsl", "retrobat"), self.root / "c" / "RetroBat" / "bios")
        self.assertEqual(install._host_path("relative/path"), Path("relative/path"))

    def test_retrobat_on_the_windows_side_is_detected(self):
        (self.root / "c" / "RetroBat" / "bios").mkdir(parents=True)
        found: list = []
        install._detect_by_path("wsl", found)
        self.assertIn(("retrobat", self.root / "c" / "RetroBat" / "bios"), found)

    def test_retroarch_beside_its_exe_on_the_windows_side_is_detected(self):
        """The installer page said both sides are searched under WSL, and
        RetroArch's install folders were looked in on Windows only: a
        C:\\RetroArch-Win64 was never found from WSL."""
        exe_dir = self.root / "c" / "RetroArch-Win64"
        exe_dir.mkdir(parents=True)
        (exe_dir / "retroarch.exe").write_bytes(b"MZ")
        home = Path(_tempdir(self))
        cleared = {name: "" for name in (*install._WINDOWS_VARIABLES, "SCOOP", "SCOOP_GLOBAL",
                                         "ProgramData")}
        with unittest.mock.patch.dict(os.environ, {**cleared, "HOME": str(home)}), \
                unittest.mock.patch.object(Path, "home", return_value=home):
            found = install.detect_platforms("wsl")
        self.assertIn(("retroarch", exe_dir / "system"), found)

    def test_the_windows_variables_are_read_through_cmd(self):
        answers = {"USERPROFILE": "C:\\Users\\me", "APPDATA": "C:\\Users\\me\\AppData\\Roaming"}

        def cmd(argv, **kwargs):
            # cmd.exe must not read the terminal: it swallowed the answer
            # typed at the first prompt.
            self.assertIs(kwargs.get("stdin"), subprocess.DEVNULL)
            name = argv[-1].split("%")[1]
            return subprocess.CompletedProcess(argv, 0, answers.get(name, f"%{name}%") + "\r\n", "")

        cleared = {name: "" for name in install._WINDOWS_VARIABLES}
        with unittest.mock.patch.dict(os.environ, cleared), \
                unittest.mock.patch.object(install.subprocess, "run", cmd):
            install._enter_wsl()
            self.assertEqual(os.environ["USERPROFILE"], str(self.root / "c" / "Users" / "me"))
            self.assertEqual(os.environ["APPDATA"],
                             str(self.root / "c" / "Users" / "me" / "AppData" / "Roaming"))
            self.assertEqual(os.environ["ProgramFiles"], "")


    def test_a_steam_client_outside_program_files_is_found(self):
        """A Steam client in D:\\Steam hid every library: only Program Files
        was searched, and Steam's RetroArch was not detected."""
        empty = self.root / "c" / "Program Files (x86)"
        empty.mkdir(parents=True)
        common = self.root / "d" / "steam" / "steamapps" / "common" / "RetroArch"
        common.mkdir(parents=True)
        (common / "retroarch.exe").write_bytes(b"MZ")
        (common / "retroarch.cfg").write_text('system_directory = "default"\n')
        home = Path(_tempdir(self))
        cleared = {name: "" for name in (*install._WINDOWS_VARIABLES, "SCOOP", "SCOOP_GLOBAL",
                                         "ProgramData")}
        asked: list = []

        def registry(key, value):
            asked.append((key, value))
            return "d:/steam" if (key, value) == ("HKCU\\Software\\Valve\\Steam",
                                                  "SteamPath") else None

        with unittest.mock.patch.dict(os.environ, {**cleared, "HOME": str(home),
                                                   "ProgramFiles(x86)": str(empty)}), \
                unittest.mock.patch.object(Path, "home", return_value=home), \
                unittest.mock.patch.object(install, "_read_registry", registry):
            self.assertEqual(install._steam_libraries(), [self.root / "d" / "steam"])
            found = install.detect_platforms("wsl")
        self.assertIn(("retroarch", common / "system"), found)

    def test_windows_not_answering_is_said_not_taken_for_nothing(self):
        """cmd.exe timing out on the first variable ended the import without
        a word, and detection said no setup was installed."""
        calls: list = []

        def slow(argv, **kwargs):
            calls.append(argv)
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 10))

        cleared = {name: "" for name in install._WINDOWS_VARIABLES}
        home = Path(_tempdir(self))
        err = io.StringIO()
        with unittest.mock.patch.dict(os.environ, {**cleared, "HOME": str(home)}), \
                unittest.mock.patch.object(install.subprocess, "run", slow), \
                unittest.mock.patch.object(Path, "home", return_value=home), \
                unittest.mock.patch.object(install, "_DETECTION_REFUSED", []), \
                unittest.mock.patch.object(install.EVENTS, "emit") as emit, \
                contextlib.redirect_stderr(err):
            install._enter_wsl()
            self.assertEqual(len(calls), 1)
            install.detect_platforms("wsl")
            install.detect_platforms("wsl")
        said = err.getvalue()
        self.assertEqual(said.count("on the Windows side"), 1, said)
        self.assertIn("cmd.exe did not answer in 10 s", said)
        kinds = [c.args[0] for c in emit.call_args_list]
        self.assertEqual(kinds.count("unsearched"), 1)
        self.assertEqual(emit.call_args_list[kinds.index("unsearched")].kwargs["folder"],
                         str(self.root))


class StandaloneCopiesUnderTheirOwnName(unittest.TestCase):
    """melonDS reads dsisd.bin and xemu eeprom.bin, names the platforms
    give dsi_sd_card.bin and xbox_eeprom.bin: a copy says the name the
    emulator reads."""

    def test_the_copy_takes_the_emulator_name(self):
        bios = Path(_tempdir(self))
        (bios / "xbox_eeprom.bin").write_bytes(b"eeprom")
        folder = Path(_tempdir(self))
        manifest = {"standalone_copies": [
            {"file": "xbox_eeprom.bin", "as": "eeprom.bin", "targets": {"linux": [str(folder)]}}]}
        install._validate_manifest({**self._published(), **manifest}, "emudeck")
        self.assertEqual(install.do_standalone_copies(manifest, bios, "linux"), (1, 0, 0))
        self.assertEqual((folder / "eeprom.bin").read_bytes(), b"eeprom")
        self.assertFalse((folder / "xbox_eeprom.bin").exists())
        plan = install.standalone_plan(
            [{"files": [{"dest": "xbox_eeprom.bin", "sha1": "0" * 40, "size": 6}],
              **manifest}], "linux")
        self.assertEqual([entry["dest"] for entry in plan[0][1]], ["eeprom.bin"])

    def _published(self) -> dict:
        return json.loads((REPO_ROOT / "install" / "emudeck.json").read_text())

    def test_a_name_that_climbs_is_refused(self):
        for name in ("../eeprom.bin", "a/eeprom.bin", "", 3):
            with self.subTest(name=name), \
                    self.assertRaisesRegex(ValueError, "standalone copy name|\\.as"):
                install._validate_manifest({**self._published(), "standalone_copies": [
                    {"file": "x.bin", "as": name, "targets": {}}]}, "emudeck")

    def test_cemu_alone_is_found_from_the_published_list(self):
        home = Path(_tempdir(self))
        (home / ".local" / "share" / "Cemu").mkdir(parents=True)
        manifest = json.loads((REPO_ROOT / "install" / "retroarch.json").read_text())
        with unittest.mock.patch.dict(os.environ, {"HOME": str(home)}):
            plan = dict(install.standalone_plan([manifest], "linux"))
        names = {entry["dest"] for entry in plan[home / ".local" / "share" / "Cemu"]}
        self.assertLessEqual({"keys.txt", "otp.bin", "seeprom.bin"}, names)


class TheBoardSystemsAreNamedFromTheCode(unittest.TestCase):
    """--help and the wiki named six systems whose board is read, while the
    code read eight: an AmberELEC user concluded --target was needed."""

    def test_help_and_wiki_name_every_one(self):
        names = [install.display_name(name) for name in install._BOARD_SOURCES]
        help_text = " ".join(install.build_parser().format_help().split())
        wiki = " ".join((REPO_ROOT / "wiki" / "installer.md").read_text().split())
        paragraph = wiki[:wiki.index("RetroPie reads the Pi model") + len("RetroPie")][-400:]
        for name in names:
            with self.subTest(name=name):
                self.assertIn(name, help_text[help_text.index("--target"):])
                self.assertIn(name, paragraph)


class TheInstallerFitsTheOneLiners(unittest.TestCase):
    """install.sh and install.ps1 refuse an installer over their cap, 8 MiB:
    the SHA-256 pin refuses any changed byte, and the cap only stops a page
    served in its place. install.py grew from 596 KB to 1.1 MB in twelve
    days: past REVIEW_BYTES its growth is looked at before it goes on."""

    # The size past which install.py's growth is reviewed, well below the cap.
    REVIEW_BYTES = 3 * 1024 ** 2

    def _caps(self) -> dict[str, int]:
        import re

        shell = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")
        ps1 = (REPO_ROOT / "install.ps1").read_text(encoding="utf-8")
        units = {"": 1, "KB": 1024, "MB": 1024 ** 2}
        number, unit = re.search(r"\$maximumInstallerBytes = (\d+)(KB|MB)?", ps1).groups()
        return {"install.sh": int(re.search(r"^MAX_INSTALLER_BYTES=(\d+)$", shell, re.M)[1]),
                "install.ps1": int(number) * units[unit or ""]}

    def test_both_one_liners_accept_the_same_size(self):
        self.assertEqual(set(self._caps().values()), {8 * 1024 ** 2})

    def test_install_py_stays_below_the_review_size(self):
        size = (REPO_ROOT / "install.py").stat().st_size
        self.assertLess(self.REVIEW_BYTES, min(self._caps().values()))
        self.assertLess(
            size, self.REVIEW_BYTES,
            f"install.py is {size} bytes, past the {self.REVIEW_BYTES} that call for a "
            "look at its growth: shrink it, or raise REVIEW_BYTES once reviewed")

    def test_the_refusal_names_a_cause_and_a_way_out(self):
        for script in ("install.sh", "install.ps1"):
            text = " ".join((REPO_ROOT / script).read_text(encoding="utf-8").split())
            with self.subTest(script=script):
                self.assertIn("this script accepts", text)
                self.assertIn("open any web page to sign in", text)


class RetroArchAppImageIsPortable(unittest.TestCase):
    """The buildbot's Linux RetroArch is an AppImage beside a .home folder
    the AppImage runtime makes its HOME: the run found nothing and offered
    ~/.config/retroarch/system, a folder this RetroArch never reads."""

    def _detect(self, home: Path, env: dict | None = None) -> list:
        cleared = {"HOME": str(home), "XDG_CONFIG_HOME": ""}
        with unittest.mock.patch.dict(os.environ, {**cleared, **(env or {})}), \
                unittest.mock.patch.object(Path, "home", return_value=home):
            os.environ.pop("XDG_CONFIG_HOME")
            return install.detect_platforms("linux")

    def _unpack(self, home: Path) -> Path:
        folder = home / "Downloads" / "RetroArch-Linux-x86_64"
        base = folder / "RetroArch-Linux-x86_64.AppImage.home" / ".config" / "retroarch"
        (base / "system").mkdir(parents=True)
        (folder / "RetroArch-Linux-x86_64.AppImage").write_bytes(b"\x7fELF")
        return base

    def test_the_unpacked_archive_is_found(self):
        home = Path(_tempdir(self))
        base = self._unpack(home)
        self.assertIn(("retroarch", base / "system"), self._detect(home))

    def test_its_config_is_read_with_its_own_home(self):
        home = Path(_tempdir(self))
        base = self._unpack(home)
        (base / "retroarch.cfg").write_text('system_directory = "~/bios"\n')
        portable = base.parent.parent
        self.assertIn(("retroarch", portable / "bios"), self._detect(home))

    def test_a_config_folder_beside_it_wins(self):
        home = Path(_tempdir(self))
        base = self._unpack(home)
        config = base.parent.parent.with_name("RetroArch-Linux-x86_64.AppImage.config")
        (config / "retroarch").mkdir(parents=True)
        found = self._detect(home)
        self.assertIn(("retroarch", config / "retroarch" / "system"), found)
        self.assertNotIn(("retroarch", base / "system"), found)

    def test_a_folder_without_its_appimage_is_left(self):
        home = Path(_tempdir(self))
        base = self._unpack(home)
        (base.parent.parent.with_name("RetroArch-Linux-x86_64.AppImage")).unlink()
        self.assertNotIn(("retroarch", base / "system"), self._detect(home))


class SteamRetroArchOnMacIsPortable(unittest.TestCase):
    """platform_darwin.m makes the Steam build portable (HAVE_STEAM) with no
    portable.txt: a default system_directory is Application Support's, and
    the installer took ~/Documents/RetroArch/system."""

    def test_the_steam_bundle_moves_the_base(self):
        home = Path(_tempdir(self))
        support = home / "Library" / "Application Support"
        with unittest.mock.patch.dict(os.environ, {"HOME": str(home)}), \
                unittest.mock.patch.object(Path, "home", return_value=home):
            self.assertEqual(install._macos_retroarch_base(), home / "Documents" / "RetroArch")
            (support / "Steam/steamapps/common/RetroArch/RetroArch.app").mkdir(parents=True)
            self.assertEqual(install._macos_retroarch_base(), support / "RetroArch")


class AMissingFileListNamesTheRef(unittest.TestCase):
    """A 404 on the manifest said three attempts were made and to check the
    connection and proxy, but it was asked once, and the cause is the ref."""

    def _run(self, ref: str) -> str:
        error = install.urllib.error.HTTPError("u", 404, "Not Found", None, None)
        with unittest.mock.patch.object(install, "RELEASE_REF", ref), \
                unittest.mock.patch.object(install, "_fetch_json", side_effect=error), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit):
            install.fetch_manifest("retroarch")
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


class TheInstallerSaysWhatItFound(unittest.TestCase):
    """--check gave a count and no name, a read-only folder printed a line
    per file, a piped log put errors before their step, and Ctrl+C while
    the file list was fetched ended on a socket traceback."""

    def setUp(self):
        import functools  # noqa: PLC0415
        import http.server  # noqa: PLC0415
        import shutil  # noqa: PLC0415

        handler = functools.partial(
            http.server.SimpleHTTPRequestHandler, directory=str(REPO_ROOT)
        )
        handler.log_message = lambda *args: None
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        self.home = Path(tempfile.mkdtemp(dir=str(REPO_ROOT / "tmp")))
        self.addCleanup(shutil.rmtree, self.home, True)
        self.env = {
            **os.environ, "HOME": str(self.home), "RETROBIOS_OS": "linux",
            "RETROBIOS_BASE_URL": f"http://127.0.0.1:{httpd.server_address[1]}",
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
        import signal  # noqa: PLC0415
        import socket  # noqa: PLC0415

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
        import time  # noqa: PLC0415

        time.sleep(3)
        proc.send_signal(signal.SIGINT)
        out, err = proc.communicate(timeout=60)
        self.assertEqual(proc.returncode, 130, out + err)
        self.assertIn("Stopped", out)
        self.assertNotIn("Traceback", err)


class NoFallbackOutsideWhatAPlatformReads(unittest.TestCase):
    """A forced platform not found here fell back to ~/bios for RetroBat on
    Linux and for BizHawk from the menu, and on Windows to /userdata/bios,
    which resolves to the root of the current drive. Each run reported done."""

    def test_the_fallback_is_none_where_nothing_is_read(self):
        self.assertIsNone(install._default_dest("linux", "retrobat"))
        self.assertIsNone(install._default_dest("linux", "bizhawk"))
        self.assertIsNone(install._default_dest("windows", "batocera"))
        self.assertIsNone(install._default_dest("windows", "retropie"))
        self.assertEqual(install._default_dest("linux", "batocera"), Path("/userdata/bios"))
        # emudeck-we functions/all.ps1:12-14, not the profile folder.
        self.assertEqual(
            install._default_dest("windows", "emudeck"), install._host_path("C:/Emulation/bios")
        )

    def test_a_forced_platform_without_a_folder_is_refused(self):
        with unittest.mock.patch.object(install, "detect_platforms", return_value=[]), \
                unittest.mock.patch.object(install, "detect_os", return_value="linux"), \
                unittest.mock.patch("sys.argv", ["install.py", "--platform", "retrobat",
                                                 "--no-input"]), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit) as caught:
            install.main()
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("--dest", err.getvalue())


class EveryStandaloneCopyNamesItsMacFolder(unittest.TestCase):
    """--standalone-copies copied Azahar's keys and Flycast's boot ROM on
    Linux and Windows and silently skipped them on macOS, where both
    emulators read a fixed Application Support folder."""

    def test_each_copy_has_a_darwin_target(self):
        import yaml

        registry = yaml.safe_load(
            (Path(__file__).resolve().parents[1] / "platforms" / "_registry.yml").read_text()
        )
        missing = [
            entry.get("file") or entry.get("pattern")
            for entry in registry["_standalone_copies"]
            if entry.get("targets") and "darwin" not in entry["targets"]
        ]
        self.assertEqual(missing, [])



class _LoopbackRun:
    """install.py against the repository's own manifests over loopback."""

    def serve(self, test: unittest.TestCase) -> dict:
        handler = functools.partial(
            http.server.SimpleHTTPRequestHandler, directory=str(REPO_ROOT)
        )
        handler.log_message = lambda *args: None
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        test.addCleanup(httpd.server_close)
        test.addCleanup(httpd.shutdown)
        self.home = Path(_tempdir(test))
        return {
            **os.environ, "HOME": str(self.home), "RETROBIOS_OS": "linux",
            "RETROBIOS_BASE_URL": f"http://127.0.0.1:{httpd.server_address[1]}",
        }


def _install_run(env: dict, *argv: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "install.py", *argv], cwd=REPO_ROOT, env=env,
        capture_output=True, text=True, timeout=300, check=False, **kwargs,
    )


class AListingAppliesItsOptionsOrRefusesThem(unittest.TestCase):
    """--list-systems --list-cores printed the systems alone, and
    --list-platforms, --list-targets and --list-emulators printed the same
    list with --system, --region or --core as without, code 0."""

    def test_two_listings_or_an_option_a_listing_ignores_are_refused(self):
        env = dict(os.environ, RETROBIOS_OS="linux")
        given = ["--platform", "retroarch", "--offline", "--no-input",
                 "--manifest", "install/retroarch.json"]
        for argv, words in (
            ([*given, "--list-systems", "--list-cores"],
             "--list-systems and --list-cores each print a list"),
            ([*given, "--list-cores", "--list-emulators"],
             "--list-cores and --list-emulators each print a list"),
            (["--list-platforms", "--list-systems", "--platform", "retroarch"],
             "--list-platforms and --list-systems each print a list"),
            (["--list-platforms", "--region", "us"],
             "--list-platforms prints the whole list, which --region does not narrow"),
            (["--list-platforms", "--platform", "retroarch"],
             "--list-platforms prints the whole list, which --platform does not narrow"),
            ([*given, "--list-targets", "--system", "sony-playstation"],
             "--list-targets prints the whole list, which --system does not narrow"),
            ([*given, "--list-targets", "--target", "switch"],
             "--list-targets prints the whole list, which --target does not narrow"),
            ([*given, "--list-emulators", "--system", "sony-playstation"],
             "--list-emulators prints the whole list, which --system does not narrow"),
            ([*given, "--list-emulators", "--core", "beetle_psx"],
             "--list-emulators prints the whole list, which --core does not narrow"),
        ):
            with self.subTest(argv=argv):
                proc = _install_run(env, *argv)
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertIn(words, proc.stderr)

    def test_the_options_a_listing_reads_still_apply(self):
        env = dict(os.environ, RETROBIOS_OS="linux")
        given = ["--platform", "retroarch", "--offline", "--no-input",
                 "--manifest", "install/retroarch.json"]
        whole = _install_run(env, *given, "--list-cores")
        narrowed = _install_run(env, *given, "--list-cores", "--system", "nintendo-gba")
        self.assertEqual((whole.returncode, narrowed.returncode), (0, 0), narrowed.stderr)
        self.assertLess(len(narrowed.stdout), len(whole.stdout))


class AMissingPackNamesTheOptionAndThePacksBeside(unittest.TestCase):
    """A typo in --from-pack said "Error: X does not exist": not the option,
    not the pack sitting next to the name typed."""

    def test_the_pack_beside_is_named(self):
        folder = Path(_tempdir(self))
        (folder / "RetroArch_BIOS_Pack.zip").write_bytes(b"")
        with self.assertRaises(ValueError) as raised:
            install.PackSource._resolve([folder / "RetroArch_BIOS_Pak.zip"])
        said = str(raised.exception)
        self.assertIn("--from-pack names a pack ZIP", said)
        self.assertIn(f"The packs in {folder}: RetroArch_BIOS_Pack.zip.", said)


class RomMIsToldToScan(unittest.TestCase, _LoopbackRun):
    """RomM serves the firmware its library scan records, and the run ended
    on "installed" with no word of the scan the player waits on."""

    def test_the_end_of_an_install_names_the_scan(self):
        env = self.serve(self)
        dest = self.home / "library" / "bios"
        dest.mkdir(parents=True)
        proc = _install_run(env, "--platform", "romm", "--dest", str(dest),
                            "--system", "atari-lynx", "--no-input")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(install.ROMM_SCAN_WORDS, " ".join(proc.stdout.split()))


class AnUnknownNameIsAnEvent(unittest.TestCase):
    """--events carried start then end with code 1 for an unknown platform,
    target or system: the reason was on stderr only, which readers ignore."""

    def _events(self, *argv: str) -> tuple[int, list[dict]]:
        env = {key: value for key, value in os.environ.items()
               if key != "RETROBIOS_BASE_URL"}
        env[install.OFFLINE_VARIABLE] = "1"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as dest:
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "install.py"), "--dest", dest,
                 "--check", "--events", "--no-input", *argv],
                env=env, capture_output=True, text=True, timeout=120,
                stdin=subprocess.DEVNULL)
        return proc.returncode, [json.loads(line) for line in proc.stdout.splitlines()]

    def test_each_refusal_says_why(self):
        manifest = str(REPO_ROOT / "install" / "retroarch.json")
        for argv, words in (
                (["--platform", "nope"], "Unknown platform 'nope'"),
                (["--platform", "retroarch", "--manifest", manifest, "--system", "nope"],
                 "unknown system: nope"),
                (["--platform", "retroarch", "--manifest", manifest, "--core", "nope"],
                 "unknown core: nope"),
                (["--platform", "retroarch", "--manifest", manifest, "--emulator", "nope"],
                 "unknown emulator: nope")):
            with self.subTest(argv=argv):
                code, events = self._events(*argv)
                self.assertEqual(code, 2)
                errors = [event for event in events if event["event"] == "error"]
                self.assertEqual(len(errors), 1, events)
                self.assertEqual((errors[0]["stage"], errors[0]["reason"]),
                                 ("option", "unknown"))
                self.assertIn(words, errors[0]["message"])
                self.assertFalse(errors[0]["message"].startswith("Error"))
                self.assertEqual(events[-1]["event"], "end")


class ATypoGetsTheClosestName(unittest.TestCase):
    """--platform batocra, --system playstation or --core swanstaton were
    answered with every name the platform has, up to 400 on one line, and
    MiSTer FPGA as the site writes it was refused."""

    def test_the_names_the_site_writes_are_platforms(self):
        self.assertEqual(install.normalize_platform("MiSTer FPGA"), "misterfpga")
        self.assertEqual(install.normalize_platform("RetroArch "), "retroarch")
        self.assertEqual(install.normalize_platform("RetroDECK"), "retrodeck")

    def test_a_system_name_stands_for_the_list_it_gets(self):
        """--list-platforms printed `muOS: retroarch`, and --platform muos
        answered "Unknown platform"."""
        for typed, plat in (("muos", "retroarch"), ("muOS", "retroarch"),
                            ("ArkOS", "retroarch"), ("PAN4ELEC", "amberelec"),
                            ("JELOS", "retroarch")):
            out = io.StringIO()
            with self.subTest(typed=typed), contextlib.redirect_stdout(out):
                self.assertEqual(install.normalize_platform(typed), plat)
            self.assertIn(f"--platform {plat}", out.getvalue())

    def test_a_system_that_gets_no_list_is_still_refused(self):
        """TrimUI, which --list-platforms prints, was answered "Unknown
        platform" with no way forward."""
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            install.normalize_platform("TrimUI")
        self.assertNotIn("Unknown platform", err.getvalue())
        self.assertIn("--platform retroarch --dest FOLDER", err.getvalue())

    def test_a_frontend_without_a_bios_folder_says_what_to_do(self):
        """ES-DE, LaunchBox and Android have no BIOS folder: each emulator
        reads its own, and --platform es-de was "Unknown platform"."""
        for typed, said in (("es-de", "ES-DE"), ("esde", "ES-DE"),
                            ("launchbox", "LaunchBox"), ("android", "Android")):
            err = io.StringIO()
            with self.subTest(typed=typed), contextlib.redirect_stderr(err), \
                    self.assertRaises(SystemExit) as raised:
                install.normalize_platform(typed)
            self.assertEqual(raised.exception.code, 2)
            self.assertIn(f"{said} has no BIOS folder of its own: run again without "
                          "--platform", err.getvalue())

    def test_a_system_name_is_suggested(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            install.normalize_platform("spruce")
        self.assertIn("Close matches: spruceOS.", err.getvalue())
        # The distinct names --list-platforms prints: Batocera is both a
        # platform and a system it recognises.
        names = [*install.AVAILABLE_PLATFORMS,
                 *(line.split(":")[0] for line in install._system_lines()),
                 *install._NO_BIOS_FOLDER]
        listed = len({install._name_key(name) for name in names})
        self.assertIn(f"lists all {listed}.", err.getvalue())

    def test_a_platform_typo_is_answered_with_one_name(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as raised:
            install.normalize_platform("batocra")
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("Close matches: batocera.", err.getvalue())
        self.assertNotIn("recalbox", err.getvalue())

    def test_a_system_is_found_inside_its_full_id(self):
        known = ["3do", "nintendo-gba", "sega-saturn", "sony-playstation", "sony-playstation-2"]
        with self.assertRaises(ValueError) as raised:
            install.resolve_choices(["playstation"], known, "system")
        text = str(raised.exception)
        self.assertIn("unknown system: playstation", text)
        self.assertIn("sony-playstation", text)
        self.assertIn("--list-systems", text)
        self.assertNotIn("3do", text)

    def test_a_core_typo_points_at_the_listing(self):
        known = [f"core{i}" for i in range(200)] + ["swanstation"]
        with self.assertRaises(ValueError) as raised:
            install.resolve_choices(["swanstaton"], known, "core")
        text = str(raised.exception)
        self.assertIn("Close matches: swanstation.", text)
        self.assertIn("--list-cores lists all 201", text)
        self.assertNotIn("core17", text)

    def test_a_name_spelled_as_the_site_writes_it(self):
        known = ["sony-playstation", "sony-playstation-2"]
        self.assertEqual(
            install.resolve_choices(["Sony PlayStation"], known, "system"),
            ["sony-playstation"],
        )

    def test_a_target_typo(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            install._unknown_target("swich", "retroarch", {"switch": {}, "desktop": {}})
        self.assertIn("Close matches: switch.", err.getvalue())
        self.assertIn("--list-targets", err.getvalue())


class PlatformsAreNamedAsTheyNameThemselves(unittest.TestCase):
    """str.capitalize() printed Retroarch, Retrodeck and Misterfpga on the
    first screen a user sees."""

    def test_the_table_is_the_manifests(self):
        for plat in install.AVAILABLE_PLATFORMS:
            manifest = json.loads((REPO_ROOT / "install" / f"{plat}.json").read_text())
            with self.subTest(plat=plat):
                self.assertEqual(install.PLATFORM_NAMES[plat], manifest["display_name"])

    def test_the_menus_use_them(self):
        out = io.StringIO()
        with unittest.mock.patch("builtins.input", lambda _prompt="": "1"), \
                contextlib.redirect_stdout(out):
            install._prompt_platform_choice(
                [("misterfpga", Path("/m")), ("retrodeck", Path("/r"))])
        self.assertIn("MiSTer FPGA: /m", out.getvalue())
        self.assertIn("RetroDECK: /r", out.getvalue())
        self.assertEqual(install.display_name("romm", {"display_name": "RomM"}), "RomM")
        self.assertEqual(install.display_name("romm", {"display_name": "\x1b[2J"}), "RomM")


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
        home = Path(_tempdir(self))
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
            install._check_free_space(Path(_tempdir(self)), 10, "batocera")
        self.assertIn("--platform batocera --dest <folder on another drive>", err.getvalue())

    def test_the_one_liner_tells_the_installer_how_it_was_started(self):
        scratch = REPO_ROOT / "tmp" / "tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
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


class AnOverrideIsNamedWhenItIsTheCause(unittest.TestCase):
    """A RETROBIOS_INSTALL_SHA256 of the user's own read as a cut download,
    and a dead RETROBIOS_BASE_URL as a network fault naming no host."""

    def test_an_unreachable_base_url_is_named(self):
        error = install.urllib.error.URLError("timed out")
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_BASE_URL": "https://mirror.invalid"}), \
                unittest.mock.patch.object(install, "_fetch_json", side_effect=error), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit):
            install.fetch_manifest("retroarch")
        text = err.getvalue()
        self.assertIn("Address: " + install.MANIFEST_URL.format(platform="retroarch"), text)
        self.assertIn("RETROBIOS_BASE_URL is set", text)

    def test_a_pinned_fingerprint_is_named(self):
        scratch = REPO_ROOT / "tmp" / "tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            (fake_bin / "curl").write_text(
                "#!/bin/sh\noutput=\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = --output ]; then output=$2; shift 2; else shift; fi\n"
                "done\n"
                "echo 'print(1)' > \"$output\"\n")
            (fake_bin / "curl").chmod(0o755)
            env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                   "TMPDIR": str(root), "RETROBIOS_INSTALL_SHA256": "0" * 64}
            proc = subprocess.run(["sh", "-s"], cwd=root, env=env, capture_output=True,
                                  input=(REPO_ROOT / "install.sh").read_text(),
                                  text=True, timeout=30, check=False)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("RETROBIOS_INSTALL_SHA256 is set", proc.stderr)
        self.assertNotIn("cut short", proc.stderr)
        ps1 = (REPO_ROOT / "install.ps1").read_text()
        self.assertIn('"RETROBIOS_INSTALL_URL", "RETROBIOS_INSTALL_SHA256"', ps1)


@unittest.skipUnless(shutil.which("pwsh"), "needs PowerShell")
class ThePowerShellOneLinerLeavesTheSessionAlone(unittest.TestCase):
    """irm | iex left $ErrorActionPreference = Stop and the script's
    variables in the user's session: their next error stopped everything."""

    def test_nothing_is_left_behind(self):
        script = (
            "Get-Content install.ps1 -Raw | Invoke-Expression; "
            "\"EAP=$ErrorActionPreference temporary=[$temporary] installer=[$installer] "
            "bootstrap=[$env:RETROBIOS_BOOTSTRAP]\""
        )
        # Refused before any request, so the run needs no network.
        env = {**os.environ, "RETROBIOS_INSTALL_URL": "http://127.0.0.1/install.py"}
        env.pop("RETROBIOS_BOOTSTRAP", None)
        proc = subprocess.run(["pwsh", "-NoProfile", "-Command", script], cwd=REPO_ROOT,
                              env=env, capture_output=True, text=True, timeout=120)
        self.assertIn("must use HTTPS", proc.stderr)
        self.assertIn("EAP=Continue temporary=[] installer=[] bootstrap=[]", proc.stdout)


class AQuestionLeftWithCtrlDOrCtrlCIsAStop(unittest.TestCase):
    """Ctrl+C or Ctrl+D at a question left with 0, so `install.sh && retroarch`
    carried on with no BIOS, while the page documents 130."""

    def test_eof_raises_the_stop(self):
        def closed(_prompt=""):
            raise EOFError

        with unittest.mock.patch("builtins.input", closed), \
                contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(KeyboardInterrupt):
            install._ask("> ")

    @unittest.skipIf(os.name == "nt", "needs a pseudo-terminal")
    def test_ctrl_d_at_the_platform_question_exits_130(self):
        import pty  # noqa: PLC0415
        import time  # noqa: PLC0415

        home = Path(_tempdir(self))
        master, slave = pty.openpty()
        # Its output on the terminal too: piped, nothing is asked, and the
        # test skipped on every machine.
        proc = subprocess.Popen(
            [sys.executable, "install.py", "--plain"], cwd=REPO_ROOT, stdin=slave,
            stdout=slave, stderr=slave,
            # No request leaves the machine: the standalone emulators' lists
            # come from the network.
            env={**os.environ, "HOME": str(home), "RETROBIOS_OS": "linux",
                 "RETROBIOS_INSTALL_OFFLINE": "1"},
        )
        os.close(slave)
        self.addCleanup(os.close, master)
        out = ""
        deadline = time.monotonic() + 60
        while "Which setup?" not in out and proc.poll() is None \
                and time.monotonic() < deadline:
            if select.select([master], [], [], 0.2)[0]:
                out += os.read(master, 65536).decode("utf-8", "replace")
        os.write(master, b"\x04")
        proc.wait(timeout=60)
        while select.select([master], [], [], 0.2)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            out += chunk.decode("utf-8", "replace")
        if "Which setup?" not in out:
            self.skipTest("a platform was detected on this machine")
        self.assertEqual(proc.returncode, 130, out)
        self.assertIn("Stopped", out)


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


class RunsAgainstTheRealLists(unittest.TestCase, _LoopbackRun):
    """Behaviour read end to end over loopback."""

    def setUp(self):
        self.env = self.serve(self)

    def test_a_wrong_hash_is_listed_first(self):
        dest = self.home / "system"
        dest.mkdir()
        (dest / "scph5501.bin").write_bytes(b"junk")
        proc = _install_run(self.env, "--platform", "retroarch", "--dest", str(dest),
                            "--check", "--no-input", "--verbose")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        listing = proc.stdout.split("to download.\n", 1)[1].splitlines()
        self.assertEqual(listing[0].strip(), "wrong copy: scph5501.bin")

    def test_a_dry_run_counts_the_data_trees_and_ends_on_its_last_line(self):
        proc = _install_run(self.env, "--platform", "retroarch", "--dest",
                            str(self.home / "s"), "--dry-run", "--no-input")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        self.assertIn("Nothing was written", lines[-1])
        at = next(index for index, line in enumerate(lines) if line.startswith("Would download"))
        # One total on the header, the data files among the kinds under it.
        self.assertNotIn("data files", lines[at])
        self.assertIn("data files", lines[at + 1])

    def test_dest_alone_says_whose_list_it_is(self):
        proc = _install_run(self.env, "--dest", str(self.home / "card"), "--dry-run",
                            "--no-input", "--system", "atari-lynx")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("File list: RetroArch", proc.stdout)
        self.assertIn("--platform", proc.stdout)

    def test_check_says_in_place_only_when_the_data_files_are_too(self):
        """The PSP BIOS in place and PPSSPP's assets absent: --check said
        "Everything is in place." then "169 to fetch", and exited 1."""
        dest = self.home / "psp"
        (dest / "PPSSPP").mkdir(parents=True)
        for repo_path in ("bios/Sony/PlayStation Portable/ppge_atlas.zim",
                          "bios/Other/ppsspp/PPSSPP/ppge_atlas.meta"):
            shutil.copy(REPO_ROOT / repo_path, dest / "PPSSPP")
        proc = _install_run(self.env, "--platform", "retroarch", "--dest", str(dest),
                            "--system", "sony-psp", "--check", "--no-input", "--verbose")
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertNotIn("Every file on the list is in place", proc.stdout)
        found = re.search(r"(\d+) in place, (\d+) missing", proc.stdout)
        self.assertIsNotNone(found, proc.stdout)
        self.assertIn(f"\n  {found.group(2)} data files to fetch\n", proc.stdout)

    def test_check_gives_one_total_offline(self):
        """Offline on an empty folder: "10805 missing", then "8164 files not in
        place" and "8164 files need the internet", the data files left out."""
        dest = self.home / "empty"
        dest.mkdir()
        proc = _install_run({**self.env, "RETROBIOS_INSTALL_OFFLINE": "1"}, "--platform",
                            "retroarch", "--dest", str(dest), "--check", "--no-input",
                            "--verbose",
                            "--manifest", str(REPO_ROOT / "install" / "retroarch.json"))
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        missing = re.search(r"0 in place, (\d+) missing", proc.stdout).group(1)
        self.assertIn(f"\n  {missing} files not in place.\n", proc.stdout)
        self.assertIn(f"  {missing} files need the internet", proc.stdout)

    def test_a_cores_folder_can_be_named(self):
        cores = self.home / "cores"
        cores.mkdir()
        (cores / "handy_libretro.so").write_bytes(b"")
        proc = _install_run(self.env, "--platform", "retroarch", "--dest",
                            str(self.home / "s"), "--cores-dir", str(cores),
                            "--dry-run", "--no-input", "--verbose")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("to the installed cores", proc.stdout)

    def test_a_cores_folder_that_cannot_be_listed_says_why(self):
        """A typo (core/ for cores/) or a closed folder read as an empty
        one: the run said "none in" and asked for the --cores-dir given."""
        missing = self.home / "core"
        a_file = self.home / "cores.txt"
        a_file.write_text("")
        for folder, why in ((missing, "does not exist"), (a_file, "is not a folder")):
            with self.subTest(why=why):
                proc = _install_run(self.env, "--platform", "retroarch", "--dest",
                                    str(self.home / "s"), "--cores-dir", str(folder),
                                    "--dry-run", "--no-input")
                self.assertEqual(proc.returncode, 1)
                self.assertIn(f"--cores-dir {folder} {why}", proc.stderr)
                self.assertNotIn("none in", proc.stderr)

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                     "a folder without read permission is POSIX")
    def test_a_closed_cores_folder_says_so(self):
        cores = self.home / "closed"
        cores.mkdir()
        (cores / "handy_libretro.so").write_bytes(b"")
        os.chmod(cores, 0o000)
        try:
            proc = _install_run(self.env, "--platform", "retroarch", "--dest",
                                str(self.home / "s"), "--cores-dir", str(cores),
                                "--dry-run", "--no-input")
        finally:
            os.chmod(cores, 0o755)
        self.assertEqual(proc.returncode, 1)
        self.assertIn(f"--cores-dir {cores} cannot be opened by this user", proc.stderr)

    def test_no_core_found_says_how_to_go_on(self):
        proc = _install_run(self.env, "--platform", "retroarch", "--dest",
                            str(self.home / "s"), "--installed-cores", "--dry-run",
                            "--no-input")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("--cores-dir <cores folder>", proc.stderr)
        self.assertIn("without --installed-cores", proc.stderr)


class DestAloneFollowsWhatIsFoundHere(unittest.TestCase):
    """--dest without --platform always meant RetroArch's list, even on a
    machine where Batocera was found, and nothing said so."""

    def _pick(self, found, interactive=False, answer=""):
        out = io.StringIO()
        with unittest.mock.patch.object(install, "detect_platforms", return_value=found), \
                unittest.mock.patch("builtins.input", lambda _prompt="": answer), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                plat, folder = install._platform_for_dest("linux", Path("/media/card"),
                                                          interactive)
                self.assertEqual(folder, Path("/media/card"))
                return plat, out.getvalue()
            except SystemExit as exc:
                return exc, out.getvalue()

    def test_a_card_system_chosen_checks_the_folder(self):
        """The menu offered no card system, and one
        chosen now reads --dest as --platform does."""
        root = Path(_tempdir(self))
        answers = iter(["Onion", "retroarch"])
        out = io.StringIO()
        with unittest.mock.patch.object(install, "detect_platforms", return_value=[]), \
                unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                contextlib.redirect_stdout(out):
            plat, folder = install._platform_for_dest("linux", root, True)
        self.assertEqual((plat, folder), ("retroarch", root))
        self.assertIn(f"{root} is not an Onion SD card", out.getvalue())
        self.assertIn("Onion, SD card (Miyoo Mini, Miyoo Mini Plus)", out.getvalue())

    def test_nothing_found_is_retroarch_said_aloud(self):
        plat, out = self._pick([])
        self.assertEqual(plat, "retroarch")
        self.assertIn("File list: RetroArch (nothing was detected here)", out)

    def test_the_one_platform_found_is_used(self):
        plat, out = self._pick([("batocera", Path("/userdata/bios"))])
        self.assertEqual(plat, "batocera")
        self.assertIn("File list: Batocera", out)

    def test_several_found_without_a_terminal_is_refused(self):
        result, out = self._pick([("emudeck", Path("/e")), ("retroarch", Path("/r"))])
        self.assertIsInstance(result, SystemExit)
        self.assertEqual(result.code, 1)
        self.assertIn("--platform", out)

    def test_a_terminal_asks_and_enter_keeps_the_one_found(self):
        plat, out = self._pick([("batocera", Path("/userdata/bios"))], interactive=True)
        self.assertEqual(plat, "batocera")
        self.assertIn("Which platform's files go to /media/card?", out)


class _FakeResponse:
    """What urlopen returns, serving one payload from its start."""

    def __init__(self, payload: bytes) -> None:
        self.status = 200
        self.headers = {"Content-Length": str(len(payload))}
        self._body = io.BytesIO(payload)

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)


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
        tmp = Path(_tempdir(self))
        (tmp / ".big.bin.part").write_bytes(self.PAYLOAD)
        seen: list[int] = []
        self.assertEqual(self._run(tmp, seen), ("big.bin", True, ""))
        # The download ran while the complete copy was still whole.
        self.assertEqual(seen, [len(self.PAYLOAD)])
        self.assertEqual((tmp / "big.bin").read_bytes(), self.PAYLOAD)
        # Nothing held it afterwards: it was a leftover, now removed.
        self.assertFalse((tmp / ".big.bin.part").exists())

    def test_the_rename_waits_for_the_other_run_to_let_go(self):
        tmp = Path(_tempdir(self))
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
        tmp = Path(_tempdir(self))
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


class StandaloneFoldersAreNamedWhenThereAreAny(unittest.TestCase, _LoopbackRun):
    """'Standalone copies skipped' closed every install, on a machine with
    no standalone emulator as on one whose DuckStation lacked its BIOS."""

    def setUp(self):
        self.env = self.serve(self)

    def _run(self) -> str:
        proc = _install_run(self.env, "--platform", "retroarch", "--dest",
                            str(self.home / "system"), "--system", "atari-lynx",
                            "--no-input", "--verbose")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc.stdout

    def test_nothing_is_said_without_an_emulator_folder(self):
        out = self._run()
        self.assertNotIn("skipped", out)
        self.assertNotIn("--standalone-copies", out)

    def test_a_found_folder_is_named(self):
        duckstation = self.home / ".local" / "share" / "duckstation" / "bios"
        duckstation.mkdir(parents=True)
        out = self._run()
        self.assertIn("Standalone emulator folders found here:", out)
        self.assertIn(str(duckstation), out)
        self.assertIn("--standalone-copies", out)


class StandaloneEmulatorsWithoutAPlatformAreServed(unittest.TestCase, _LoopbackRun):
    """ES-DE with DuckStation and PCSX2 and no RetroArch: the run said 'No
    supported platform detected' and offered RetroArch's folder, which no
    emulator on the machine reads."""

    def setUp(self):
        self.env = self.serve(self)
        (self.home / "ES-DE").mkdir()
        self.duckstation = self.home / ".local" / "share" / "duckstation" / "bios"
        self.duckstation.mkdir(parents=True)

    def test_the_emulator_folder_is_filled(self):
        proc = _install_run(self.env, "--no-input", "--dry-run")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Found standalone emulator folders:", proc.stdout)
        self.assertIn(f"to {self.duckstation}:", proc.stdout)
        self.assertNotIn("--platform retroarch --dest", proc.stdout)
        proc = _install_run(self.env, "--no-input")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        names = sorted(path.name for path in self.duckstation.iterdir())
        self.assertIn("scph5501.bin", names)
        # Every image the DuckStation profile places in its bios folder,
        # its PS2 and OpenBIOS images included, and nothing else.
        import yaml  # noqa: PLC0415

        profile = yaml.safe_load((REPO_ROOT / "emulators" / "duckstation.yml").read_text())
        named = {PurePosixPath(entry["standalone_path"]).name
                 for entry in profile["files"] if entry.get("standalone_path")}
        self.assertEqual([name for name in names
                          if name not in named and not name.startswith("scph")], [])
        proc = _install_run(self.env, "--no-input", "--check")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Every file on the list is in place.", proc.stdout)

    def test_no_emulator_folder_keeps_the_hint(self):
        self.duckstation.rmdir()
        proc = _install_run(self.env, "--no-input")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("--platform retroarch --dest", proc.stdout)


class TheEmulatorNamesHaveTheirOwnListing(unittest.TestCase, _LoopbackRun):
    """--emulator nope said "--list-cores lists all 441" and --list-cores
    printed 189: the buildbot names --emulator accepts were listed nowhere."""

    def setUp(self):
        self.env = self.serve(self)

    def test_the_hint_counts_what_the_listing_prints(self):
        proc = _install_run(self.env, "--platform", "retroarch", "--no-input",
                            "--emulator", "nope")
        self.assertEqual(proc.returncode, 2, proc.stdout)
        found = re.search(r"--list-emulators lists all (\d+)\.", proc.stderr)
        self.assertIsNotNone(found, proc.stderr)
        listing = _install_run(self.env, "--platform", "retroarch", "--no-input",
                               "--list-emulators")
        self.assertEqual(listing.returncode, 0, listing.stderr)
        names = [re.split(r"\s{2,}", line.strip())[0]
                 for line in listing.stdout.splitlines() if line.startswith("  ")]
        manifest = json.loads((REPO_ROOT / "install" / "retroarch.json").read_text())
        accepted = install.emulator_names(
            manifest, manifest["files"], manifest.get("omitted_files", []))
        self.assertEqual(int(found.group(1)), len(accepted))
        self.assertTrue(set(accepted) <= set(names), set(accepted) - set(names))
        self.assertIn("mednafen_psx", accepted)
        self.assertRegex(listing.stdout, r"mednafen_psx\s+same as beetle_psx")

    def test_every_listed_name_is_accepted(self):
        manifest = {"core_names": {"beetle_psx": ["mednafen_psx"]}}
        files = [{"dest": "a", "cores": ["pcsx_rearmed"]}]
        names = install.emulator_names(manifest, files, [])
        self.assertEqual(names, {"beetle_psx": "beetle_psx", "mednafen_psx": "beetle_psx",
                                 "pcsx_rearmed": "pcsx_rearmed"})
        self.assertEqual(install.resolve_choices(["MEDNAFEN_PSX"], sorted(names), "emulator"),
                         ["mednafen_psx"])


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
            _dest, ok, reason = install._download_one(entry, Path(_tempdir(self)))
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

    def test_the_summary_points_at_the_connection(self):
        failures = [("a.bin", install.NetworkReason("timed out")),
                    ("b.bin", install.NetworkReason("Connection reset by peer"))]
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as raised:
            install._report_outcome([Path("/bios")], 0, 0, 2, 0, False, failures=failures)
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
                                    failures=failures)
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


class RetroBatIsFoundWhereItSaysItIs(unittest.TestCase):
    """RetroBat on D:\\RetroBat was not detected, and --platform retrobat
    wrote 7.6 GB into C:\\RetroBat\\bios, a folder it does not read.
    RetroBat.exe writes its folder to the registry on every start."""

    def test_the_table_is_the_registry(self):
        import yaml  # noqa: PLC0415

        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        rules = {
            (rule["os"], name, rule["key"], rule["value"], rule["bios_subdir"])
            for name, entry in registry["platforms"].items()
            for rule in (entry.get("install") or {}).get("detect", [])
            if rule["method"] == "registry"
        }
        self.assertEqual(set(install._REGISTRY_RULES), rules)

    def test_the_registry_folder_wins_over_the_default(self):
        folder = Path(_tempdir(self))
        with unittest.mock.patch.object(install, "_read_registry",
                                        return_value=str(folder) + "\\"):
            found: list = []
            install._detect_by_registry("windows", found)
        self.assertEqual(found, [("retrobat", folder / "bios")])

    def test_a_folder_since_removed_is_passed_over(self):
        gone = Path(_tempdir(self)) / "moved"
        with unittest.mock.patch.object(install, "_read_registry", return_value=str(gone)):
            found: list = []
            install._detect_by_registry("windows", found)
        self.assertEqual(found, [])

    def test_wsl_reads_it_through_reg_exe(self):
        output = ("\nHKEY_CURRENT_USER\\SOFTWARE\\RetroBat\n"
                  "    LatestKnownInstallPath    REG_SZ    D:\\Games\\RetroBat\\\n\n")
        with unittest.mock.patch.dict(install._WSL, {"active": True, "root": "/mnt"}), \
                unittest.mock.patch.object(install.os, "name", "posix"), \
                unittest.mock.patch.object(
                    install.subprocess, "run",
                    return_value=SimpleNamespace(stdout=output, returncode=0)) as run:
            value = install._read_registry("HKCU\\SOFTWARE\\RetroBat", "LatestKnownInstallPath")
            self.assertEqual(value, "D:\\Games\\RetroBat\\")
            self.assertEqual(install._host_path(value.rstrip("\\")),
                             Path("/mnt/d/Games/RetroBat"))
        self.assertEqual(run.call_args[0][0][:2], ["reg.exe", "query"])


class EmuDeckWindowsIsFoundAsItsScriptsFindIt(unittest.TestCase):
    """EmuDeck's Windows scripts read %APPDATA%\\EmuDeck\\settings.ps1, else
    %USERPROFILE%\\EmuDeck\\settings.ps1, and take C:\\Emulation when neither
    names a folder (functions/all.ps1:4-14). Only the first was read, and a
    forced --platform emudeck wrote into %USERPROFILE%\\Emulation\\bios."""

    def _env(self) -> tuple[Path, Path]:
        root = Path(_tempdir(self))
        appdata, profile = root / "appdata", root / "profile"
        patcher = unittest.mock.patch.dict(
            os.environ, {"APPDATA": str(appdata), "USERPROFILE": str(profile)})
        patcher.start()
        self.addCleanup(patcher.stop)
        return appdata, profile

    @staticmethod
    def _settings(folder: Path, text: str, encoding: str = "utf-8-sig") -> None:
        (folder / "EmuDeck").mkdir(parents=True, exist_ok=True)
        (folder / "EmuDeck" / "settings.ps1").write_bytes(text.encode(encoding))

    def test_the_profile_settings_are_read_when_appdata_has_none(self):
        _appdata, profile = self._env()
        self._settings(profile, '\n$emulationPath="/games/Emulation"\n')
        self.assertEqual(install._emudeck_windows_bios(), Path("/games/Emulation/bios"))

    def test_appdata_comes_first(self):
        appdata, profile = self._env()
        self._settings(profile, '$emulationPath="/b/Emulation"\n')
        self._settings(appdata, '$emulationPath="/a/Emulation"\n', "utf-16")
        self.assertEqual(install._emudeck_windows_bios(), Path("/a/Emulation/bios"))

    def test_settings_naming_no_folder_mean_c_emulation(self):
        appdata, _profile = self._env()
        self._settings(appdata, '$device="Windows"\n')
        self.assertEqual(install._emudeck_windows_bios(),
                         install._host_path("C:\\Emulation") / "bios")

    def test_a_network_install_is_its_share(self):
        appdata, _profile = self._env()
        self._settings(appdata, '$networkInstallation="true"\n'
                       '$VolName="/nas/games"\n'
                       '$emulationPath=$testdrive.ToString() + ":\\Emulation"\n')
        self.assertEqual(install._emudeck_windows_bios(),
                         Path("/nas/games\\Emulation") / "bios")

    def test_no_settings_detects_nothing(self):
        self._env()
        self.assertIsNone(install._emudeck_windows_bios())

    def test_a_forced_platform_falls_back_to_c_emulation(self):
        self.assertEqual(install._default_dest("windows", "emudeck"),
                         install._host_path("C:/Emulation/bios"))


def _device(test: unittest.TestCase, files: dict[str, str],
            release: str = "", home: str = "/root") -> Path:
    """A fake root holding these files, read by the embedded rules."""
    root = Path(_tempdir(test))
    if release:
        files = {**files, "/etc/os-release": release}
    for name, text in files.items():
        path = root / name.lstrip("/")
        if name.endswith("/"):
            path.mkdir(parents=True, exist_ok=True)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    for patcher in (
        unittest.mock.patch.object(install, "_SYSTEM_ROOT", root),
        unittest.mock.patch.dict(os.environ, {"HOME": home}),
        unittest.mock.patch.dict(install._RETROARCH_CONFIGS, clear=True),
        unittest.mock.patch.dict(install._DETECTED_OS, clear=True),
    ):
        patcher.start()
        test.addCleanup(patcher.stop)
    return root


class MuOsIsReadFromItsRetroArchConfig(unittest.TestCase):
    """muOS wrote to /mnt/mmc/MUOS/bios while RetroArch reads
    /run/muos/storage/bios, bound to the second card when it holds MUOS/bios,
    and --installed-cores found no core in /opt/muos/share/core."""

    USER = "/opt/muos/share/info/config/retroarch.cfg"
    DEFAULT = "/opt/muos/share/emulator/retroarch/retroarch.default.cfg"

    def _muos(self, files: dict[str, str]) -> Path:
        root = _device(self, {"/opt/muos/": "", **files})
        found = install._detect_embedded()
        self.assertEqual(len(found), 1)
        self.assertEqual(install.detected_os(*found[0]), "muOS")
        return root

    def test_the_users_config_decides(self):
        root = self._muos({
            self.USER: 'libretro_directory = "/opt/muos/share/core"\n'
                       'system_directory = "/mnt/sdcard/MUOS/bios"\n',
            self.DEFAULT: 'system_directory = "/run/muos/storage/bios"\n',
        })
        self.assertEqual(install._detect_embedded(),
                         [("retroarch", root / "mnt/sdcard/MUOS/bios")])
        self.assertIn(Path("/opt/muos/share/core"),
                      install.core_dirs("retroarch", root / "mnt/sdcard/MUOS/bios"))

    def test_before_the_first_launch_the_default_does(self):
        root = self._muos({self.DEFAULT: 'system_directory = "/run/muos/storage/bios"\n'})
        self.assertEqual(install._detect_embedded(),
                         [("retroarch", root / "run/muos/storage/bios")])

    def test_without_a_config_the_bound_folder_is_used(self):
        root = self._muos({})
        self.assertEqual(install._detect_embedded(),
                         [("retroarch", root / "run/muos/storage/bios")])


class HandheldSystemsByTheirOwnFiles(unittest.TestCase):
    """AmberELEC, EmuELEC, JELOS, ArkOS on a second card and a dozen other
    handheld systems were not detected, or got /roms/bios whatever their
    RetroArch read: each is found by what its own build writes, and its
    folder is the system_directory of its RetroArch config."""

    ELEC_CFG = "/storage/.config/retroarch/retroarch.cfg"
    ARK_CFG = "/home/ark/.config/retroarch/retroarch.cfg"
    TITLE = "/usr/share/plymouth/themes/text.plymouth"

    def _found(self, files: dict, release: str = "", home: str = "/root"):
        root = _device(self, files, release, home)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            found = install._detect_embedded()
        names = [install.detected_os(plat, path) for plat, path in found]
        return root, found, names, err.getvalue()

    def _one(self, files: dict, release: str = "", home: str = "/root"):
        root, found, names, _err = self._found(files, release, home)
        self.assertEqual(len(found), 1, found)
        return root, found[0], names[0]

    def _elec(self, release: str, name: str, extra: dict | None = None,
              plat: str = "retroarch", folder: str = "storage/roms/bios"):
        cfg = {self.ELEC_CFG: 'system_directory = "~/roms/bios"\n'}
        root, (found_plat, path), found_name = self._one({**cfg, **(extra or {})}, release)
        self.assertEqual((found_plat, path, found_name),
                         (plat, root / folder, name))

    # AmberELEC and EmuELEC publish their own lists, written against
    # /storage/roms (bios/, ports/ and neogeo/ side by side).
    def test_amberelec(self):
        self._elec('NAME="AmberELEC"\nID="coreelec"\n', "AmberELEC",
                   plat="amberelec", folder="storage/roms")

    def test_chaos_names_itself_amberelec(self):
        # tech4bot/AmberELEC writes the same os-release as AmberELEC.
        self._elec('NAME="AmberELEC"\nID="coreelec"\nCOREELEC_DEVICE="RG552"\n', "AmberELEC",
                   plat="amberelec", folder="storage/roms")

    def test_pan4elec_over_amberelec(self):
        self._elec('NAME="AmberELEC"\n', "PAN4ELEC",
                   {"/usr/bin/batocera-info": 'echo "OPERATING SYSTEM: PAN4ELEC"\n'},
                   plat="amberelec", folder="storage/roms")

    def test_emuelec(self):
        self._elec('NAME="EmuELEC"\nID="emuelec"\n', "EmuELEC",
                   plat="emuelec", folder="storage/roms")

    def test_jelos(self):
        self._elec('OS_NAME="JELOS"\nHW_DEVICE="RK3566"\n', "JELOS")

    def test_kolos_over_jelos(self):
        self._elec('OS_NAME="JELOS"\n', "KOLOS",
                   {"/usr/lib/systemd/system/jelos-ready.service":
                    "Description=KOLOS system ready script\n"})

    def test_unofficialos(self):
        self._elec('OS_NAME="UnofficialOS"\n', "UnofficialOS")

    def test_archr(self):
        self._elec('NAME="ArchR"\nID="archr"\nOS_NAME="ArchR"\n', "ArchR")

    def test_an_elec_config_moved_elsewhere_is_followed(self):
        root, (_plat, path), _name = self._one(
            {self.ELEC_CFG: 'system_directory = "/storage/roms2/bios"\n'}, 'OS_NAME="JELOS"\n')
        self.assertEqual(path, root / "storage/roms2/bios")

    def test_arkos_first_and_second_card(self):
        base = {"/home/ark/": "", "/opt/system/": "",
                self.TITLE: "[ubuntu-text]\ntitle=ArkOS 2.0 (02012025)-3\n"}
        for folder in ("/roms/bios", "/roms2/bios"):
            with self.subTest(folder=folder):
                root, found, name = self._one(
                    {**base, self.ARK_CFG: f'system_directory = "{folder}"\n'})
                self.assertEqual((found, name),
                                 (("retroarch", root / folder.lstrip("/")), "ArkOS"))

    def test_arkos_32_bit_config_when_the_64_bit_one_is_missing(self):
        root, found, _name = self._one({
            "/home/ark/": "", "/opt/system/": "",
            "/home/ark/.config/retroarch32/retroarch.cfg": 'system_directory = "/roms2/bios"\n',
        })
        self.assertEqual(found, ("retroarch", root / "roms2/bios"))

    def test_darkos_first_and_second_card(self):
        base = {"/home/ark/": "", "/opt/system/": "",
                self.TITLE: "title=dArkOS (05102026)\n"}
        for folder in ("/roms/bios", "/roms2/bios"):
            with self.subTest(folder=folder):
                root, found, name = self._one(
                    {**base, self.ARK_CFG: f'system_directory = "{folder}"\n'})
                self.assertEqual((found, name),
                                 (("retroarch", root / folder.lstrip("/")), "dArkOS"))

    def test_darkos_without_a_config(self):
        root, found, name = self._one({"/home/ark/": "", "/opt/system/": "",
                                       self.TITLE: "title=dArkOS (05102026)\n"})
        self.assertEqual((found, name), (("retroarch", root / "roms/bios"), "dArkOS"))

    def test_retrooz(self):
        cfg = "/home/odroid/.config/retroarch32/retroarch.cfg"
        root, found, name = self._one({
            "/opt/.retrooz/version": "0.60\n", self.TITLE: "[ubuntu-text]\ntitle=RetroOZ\n",
            cfg: 'system_directory = "/roms/bios"\n',
        })
        self.assertEqual((found, name), (("retroarch", root / "roms/bios"), "RetroOZ"))
        root, found, name = self._one({"/etc/retrooz_version": "1\n"})
        self.assertEqual((found, name), (("retroarch", root / "roms/bios"), "RetroOZ"))

    def test_thera_is_not_detected(self):
        _root, found, _names, _err = self._found({self.TITLE: "title= *TheRA RC 1*\n"})
        self.assertEqual(found, [])

    def test_spruceos_on_a_trimui(self):
        root, found, name = self._one({
            "/usr/trimui/": "", "/mnt/SDCARD/spruce/": "",
            "/mnt/SDCARD/Saves/ra-configs/retroarch-Brick.cfg":
                'system_directory = "/mnt/SDCARD/BIOS"\n',
        })
        self.assertEqual((found, name), (("retroarch", root / "mnt/SDCARD/BIOS"), "spruceOS"))

    def test_crossmix_os(self):
        root, found, name = self._one({
            "/usr/trimui/": "", "/mnt/SDCARD/System/usr/trimui/crossmix-version.txt": "1.3\n",
            "/mnt/SDCARD/RetroArch/retroarch.cfg": 'system_directory = "/mnt/SDCARD/BIOS"\n',
        })
        self.assertEqual((found, name), (("retroarch", root / "mnt/SDCARD/BIOS"), "CrossMix-OS"))

    def _miyoo_mini(self, marker: str, name: str):
        root, found, found_name = self._one({
            marker: "x\n",
            "/mnt/SDCARD/RetroArch/.retroarch/retroarch.cfg":
                'system_directory = "/mnt/SDCARD/BIOS"\n',
        })
        self.assertEqual((found, found_name), (("retroarch", root / "mnt/SDCARD/BIOS"), name))

    def test_onion(self):
        self._miyoo_mini("/mnt/SDCARD/.tmp_update/onionVersion/version.txt", "Onion")

    def test_allium(self):
        self._miyoo_mini("/mnt/SDCARD/.allium/version.txt", "Allium")

    def test_koriki(self):
        self._miyoo_mini("/mnt/SDCARD/Koriki/version.txt", "Koriki")

    def test_miyoocfw_default_and_config(self):
        base = {"/etc/main": "export HOME=/mnt\n", "/usr/bin/miyooctl": ""}
        root, found, name = self._one(base)
        self.assertEqual((found, name),
                         (("retroarch", root / "mnt/.retroarch/system"), "MiyooCFW"))
        root, found, _name = self._one(
            {**base, "/mnt/.retroarch/retroarch.cfg": 'system_directory = "~/bios"\n'})
        self.assertEqual(found, ("retroarch", root / "mnt/bios"))

    def test_plumos(self):
        root, found, name = self._one({"/mnt/plumos-user/": ""}, 'NAME="plumOS"\nID=plumos\n')
        self.assertEqual((found, name), (("retroarch", root / "mnt/plumos-user/bios"), "plumOS"))
        _root, found, _names, err = self._found({}, 'NAME="plumOS"\nID=plumos\n')
        self.assertEqual(found, [])
        self.assertIn("plumOS found here", err)

    def test_trimui_stock_and_minui_are_named_not_installed_to(self):
        _root, found, _names, err = self._found({"/usr/trimui/": ""})
        self.assertEqual(found, [])
        self.assertIn("TrimUI found here", err)
        _root, found, _names, err = self._found(
            {"/usr/trimui/": "", "/mnt/SDCARD/.system/res/": ""})
        self.assertEqual(found, [])
        self.assertIn("MinUI found here", err)
        self.assertIn("--platform minui", err)
        self.assertIn("--dest", err)
        self.assertNotIn("TrimUI", err)

    def test_a_minui_card_on_its_device_gets_its_file_list(self):
        """--list-platforms said the MinUI layout was not written yet, while
        --from-pack and --dest wrote it: on the device the card root is the
        folder, and the card's version.txt names which of the three it is."""
        for release, plat, shown in (("MinUI-20251127-0", "minui", "MinUI"),
                                     ("NextUI-20250601-1", "nextui", "NextUI"),
                                     ("MyMinUI-20260809b-0", "myminui", "MyMinUI")):
            with self.subTest(release=release):
                root, found, name = self._one({
                    "/usr/trimui/": "", "/mnt/SDCARD/.system/res/": "",
                    "/mnt/SDCARD/.system/version.txt": release + "\n"})
                self.assertEqual((found, name), ((plat, root / "mnt/SDCARD"), shown))

    def test_the_listing_says_what_the_minui_family_gets(self):
        line = next(line for line in install._system_lines() if line.startswith("MinUI:"))
        self.assertNotIn("does not write", line)
        self.assertIn("minui, nextui or myminui", line)

    def test_two_unrelated_systems_are_refused(self):
        _root, found, names, _err = self._found(
            {"/mnt/SDCARD/Koriki/version.txt": "1\n"}, 'OS_NAME="JELOS"\n')
        self.assertEqual(names, ["JELOS", "Koriki"])
        self.assertEqual(install.os_conflict(found), ["JELOS", "Koriki"])
        with unittest.mock.patch.object(sys, "argv", ["install.py", "--no-input"]), \
                unittest.mock.patch.object(install, "detect_os", return_value="linux"), \
                unittest.mock.patch.object(install, "detect_platforms", return_value=found), \
                unittest.mock.patch.object(install, "detect_frontends", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit) as stop:
            install.main()
        self.assertEqual(stop.exception.code, 1)
        self.assertIn("JELOS and Koriki are both detected here", err.getvalue())
        with unittest.mock.patch.object(sys, "argv", ["install.py", "--no-input", "--events"]), \
                unittest.mock.patch.object(install, "detect_os", return_value="linux"), \
                unittest.mock.patch.object(install, "detect_platforms", return_value=found), \
                unittest.mock.patch.object(install, "detect_frontends", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit):
            install.main()
        errors = [event for event in map(json.loads, out.getvalue().splitlines())
                  if event["event"] == "error"]
        self.assertEqual([(e["stage"], e["reason"]) for e in errors], [("detect", "conflict")])

    def test_the_system_is_announced_by_its_own_name(self):
        root, found, _name = self._one({self.ELEC_CFG: ""}, 'OS_NAME="JELOS"\n')
        self.assertEqual(install.found_label(*found),
                         f"JELOS at {root / 'storage/roms/bios'} (RetroArch files)")

    def test_list_platforms_names_every_system(self):
        with unittest.mock.patch.object(sys, "argv", ["install.py", "--list-platforms"]), \
                unittest.mock.patch.object(install, "detect_os", return_value="linux"), \
                unittest.mock.patch.object(install, "detect_platforms", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            install.main()
        for rule in install._EMBEDDED_RULES:
            self.assertIn(f"  {rule.name}: ", out.getvalue())


class BatoceraAndKnulliByWhatTheirBuildsWrite(unittest.TestCase):
    """No Batocera build writes /etc/batocera-version (batocera-system.mk
    writes /usr/share/batocera/batocera.version), and Knulli writes no
    /etc/knulli-release and removes /usr/share/batocera: neither was
    detected, and a Knulli board got every board's files without a word."""

    def _detect(self, release: dict, files: tuple[str, ...]):
        with unittest.mock.patch.object(install, "_parse_os_release", return_value=release), \
                unittest.mock.patch.object(Path, "exists", lambda p: str(p) in files):
            return install._detect_embedded()

    def test_batocera_by_its_version_file(self):
        self.assertEqual(self._detect({}, ("/usr/share/batocera/batocera.version",)),
                         [("batocera", Path("/userdata/bios"))])
        self.assertEqual(self._detect({}, ("/etc/batocera-version",)), [])

    def test_knulli_by_its_os_release_or_version_file(self):
        self.assertEqual(self._detect({"OS_NAME": "knulli"}, ()),
                         [("knulli", Path("/userdata/bios"))])
        self.assertEqual(self._detect({}, ("/usr/share/knulli/knulli.version",)),
                         [("knulli", Path("/userdata/bios"))])

    def test_amberelec_and_emuelec_by_their_os_release(self):
        """Both write os-release from DISTRONAME in scripts/image. AmberELEC
        keeps CoreELEC's ID, so its NAME tells it apart."""
        self.assertEqual(self._detect({"NAME": "AmberELEC", "ID": "coreelec"}, ()),
                         [("amberelec", Path("/storage/roms"))])
        self.assertEqual(self._detect({"NAME": "EmuELEC", "ID": "emuelec"}, ()),
                         [("emuelec", Path("/storage/roms"))])
        self.assertEqual(self._detect({"NAME": "CoreELEC", "ID": "coreelec"}, ()), [])

    def test_a_knulli_board_narrows_to_its_target(self):
        """KNULLI publishes a core list per board since 2026-11-05, and an
        H700 handheld still took every board's files (9.3 GB for 4.5)."""
        arch = Path(_tempdir(self)) / "knulli.arch"
        targets = json.loads((REPO_ROOT / "install" / "targets" / "knulli.json")
                             .read_text(encoding="utf-8"))
        for written, board in (("h700", "h700"), ("rk3568", "rk3566"), ("unknown", None)):
            arch.write_text(written)
            with self.subTest(written=written), unittest.mock.patch.dict(
                    install._BOARD_SOURCES, {"knulli": ("file", str(arch))}):
                self.assertEqual(install.detect_board("knulli"), board)
                if board:
                    self.assertIn(board, targets)

    def test_a_batocera_zen3_board_narrows_to_its_target(self):
        """batocera.arch says x86-64-v3 on a zen3 image, which no target
        list names: the run installed the files of every board."""
        arch = Path(_tempdir(self)) / "batocera.arch"
        arch.write_text("x86-64-v3")
        with unittest.mock.patch.dict(install._BOARD_SOURCES,
                                      {"batocera": ("file", str(arch))}):
            self.assertEqual(install.detect_board("batocera"), "zen3")

    def test_each_board_name_is_a_published_target(self):
        for plat, names in install._BOARD_NAMES.items():
            targets = json.loads((REPO_ROOT / "install" / "targets" / f"{plat}.json")
                                 .read_text(encoding="utf-8"))
            for written, board in names.items():
                with self.subTest(platform=plat, board=board):
                    self.assertIn(board, targets)
                    self.assertNotIn(written, targets)

    def test_the_run_says_why_every_board_is_installed(self):
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        block = source[source.index("board = detect_board(plat_name)"):]
        block = block[:block.index("if target:")]
        self.assertIn("has no", block)


class RomMFirmwareFollowsItsTemplate(unittest.TestCase):
    """RomM 5.4 reads firmware where filesystem.structure.firmware says, and
    a {platform}/roms library is told to declare "{platform}/bios". The
    installer only wrote bios/<platform>/, where such a library lists none."""

    CONFIG = (
        "# RomM\n"
        "exclude:\n"
        "  platforms: []\n"
        "filesystem:\n"
        "  structure:\n"
        "    default: \"{platform}/roms/{game}\"\n"
        "    firmware: \"{platform}/bios\"  # as RomM suggests\n"
        "system:\n"
        "  firmware: elsewhere\n"
    )

    def _romm(self, config: str | None) -> Path:
        base = Path(_tempdir(self))
        library = base / "library"
        (library / "psx" / "roms").mkdir(parents=True)
        if config is not None:
            (base / "config").mkdir()
            (base / "config" / "config.yml").write_text(config)
        return library / "bios"

    def test_templates_parse_as_romm_parses_them(self):
        self.assertEqual(install.parse_romm_firmware("bios/{platform}"), (("bios",), ()))
        self.assertEqual(install.parse_romm_firmware("{platform}/bios"), ((), ("bios",)))
        self.assertEqual(install.parse_romm_firmware("/a/{platform}/b/c/"),
                         (("a",), ("b", "c")))
        for bad in ("", "bios", "{platform}/{game}", "{region}/{platform}",
                    "../{platform}", "{platform}/{platform}"):
            with self.subTest(template=bad), self.assertRaises(ValueError):
                install.parse_romm_firmware(bad)

    def test_the_template_is_read_from_config_yml(self):
        bios = self._romm(self.CONFIG)
        layout = install.romm_firmware_layout(bios, None)
        self.assertEqual(layout, ((), ("bios",)))
        files = [{"dest": "psx/scph5501.bin"}, {"dest": "3do/panafz1.bin"}]
        moved, root = install.romm_relayout(files, bios, *layout)
        self.assertEqual(root, bios.parent)
        self.assertEqual([f["dest"] for f in moved],
                         ["psx/bios/scph5501.bin", "3do/bios/panafz1.bin"])

    def test_the_default_keeps_the_pack_layout(self):
        bios = self._romm("filesystem:\n  structure:\n    firmware: bios/{platform}\n")
        files = [{"dest": "psx/scph5501.bin"}]
        self.assertEqual(install.romm_relayout(files, bios, *install.romm_firmware_layout(
            bios, None)), (files, bios))

    def test_a_platform_first_library_without_a_template_is_refused(self):
        bios = self._romm(None)
        with self.assertRaises(ValueError) as raised:
            install.romm_firmware_layout(bios, None)
        self.assertIn('--romm-firmware "{platform}/bios"', str(raised.exception))
        self.assertEqual(install.romm_firmware_layout(bios, "{platform}/bios"),
                         ((), ("bios",)))

    def test_the_option_is_refused_where_romm_is_not_installed(self):
        err = io.StringIO()
        with unittest.mock.patch.object(install, "detect_os", return_value="linux"), \
                unittest.mock.patch("sys.argv", [
                    "install.py", "--platform", "batocera", "--dest", _tempdir(self),
                    "--romm-firmware", "{platform}/bios", "--no-input"]), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
            install.main()
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("--romm-firmware applies to RomM", err.getvalue())


class RomMFirmwareInstallsUnderItsTemplate(unittest.TestCase, _LoopbackRun):
    """The whole run, over loopback: config.yml beside the library decides."""

    def setUp(self):
        self.env = self.serve(self)

    def test_lynx_lands_in_its_platform_folder(self):
        base = self.home / "romm"
        (base / "library" / "lynx" / "roms").mkdir(parents=True)
        (base / "config").mkdir()
        (base / "config" / "config.yml").write_text(
            "filesystem:\n  structure:\n    default: \"{platform}/roms/{game}\"\n"
            "    firmware: \"{platform}/bios\"\n")
        proc = _install_run(self.env, "--platform", "romm", "--dest",
                            str(base / "library" / "bios"), "--system", "atari-lynx",
                            "--no-input", "--verbose")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue((base / "library" / "lynx" / "bios" / "lynxboot.img").is_file())
        self.assertFalse((base / "library" / "bios").exists())
        self.assertIn("{platform}/bios", proc.stdout)


class _SyntheticTree:
    """A served tree of four BIOS files over loopback, one with no system,
    and a BIOS folder holding one of them, another with other bytes, and
    neither of the last two."""

    FILES = {
        "bios/A/a.bin": b"alpha" * 20,
        "bios/A/b.bin": b"bravo" * 30,
        "bios/B/c.bin": b"charlie" * 10,
        "bios/X/d.bin": b"delta" * 5,
    }

    def serve_tree(self, test: unittest.TestCase) -> dict:
        root = Path(_tempdir(test))
        files = []
        for path, data in self.FILES.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_bytes(data)
            name = Path(path).name
            systems = {"a.bin": ["sys-a"], "b.bin": ["sys-a"], "c.bin": ["sys-b"]}.get(name)
            entry = {"dest": name, "repo_path": path, "size": len(data),
                     "sha1": hashlib.sha1(data).hexdigest(), "cores": None}
            if systems:
                entry["systems"] = systems
            files.append(entry)
        manifest = {
            "manifest_version": 2, "platform": "retroarch", "display_name": "RetroArch",
            "files": files, "system_names": {"sys-a": ["alpha"]},
            "omitted_files": [{"dest": "e.bin", "name": "e.bin", "system": "sys-b",
                               "required": True, "reason": "not_found",
                               "systems": ["sys-b"]}],
        }
        (root / "install").mkdir()
        (root / "install" / "retroarch.json").write_text(json.dumps(manifest))

        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *args) -> None:
                return

        handler = functools.partial(Quiet, directory=str(root))
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        test.addCleanup(httpd.server_close)
        test.addCleanup(httpd.shutdown)
        self.home = Path(_tempdir(test))
        self.bios = self.home / "bios"
        self.bios.mkdir()
        (self.bios / "a.bin").write_bytes(self.FILES["bios/A/a.bin"])
        (self.bios / "b.bin").write_bytes(b"other bytes")
        return {
            **os.environ, "HOME": str(self.home), "RETROBIOS_OS": "linux",
            "RETROBIOS_BASE_URL": f"http://127.0.0.1:{httpd.server_address[1]}",
        }


def _events(proc: subprocess.CompletedProcess) -> list[dict]:
    """The --events stream, every stdout line a JSON object."""
    return [json.loads(line) for line in proc.stdout.splitlines()]


class SystemEventsFollowTheChoice(unittest.TestCase):
    """--system nintendo-gba wrote `system` events for nintendo-ds, gb and
    gbc: SkyEmu's files carry four systems, and each was described by the
    few of its files the choice kept."""

    def test_only_the_chosen_systems_are_described(self):
        files = [{"dest": "gba_bios.bin", "size": 1, "systems": ["nintendo-gba"]},
                 {"dest": "SkyEmu/dmg.bin", "size": 1,
                  "systems": ["nintendo-gb", "nintendo-gba"]}]
        stream = io.StringIO()
        install.EVENTS.open(stream)
        self.addCleanup(setattr, install.EVENTS, "stream", None)
        install._emit_check("retroarch", {}, Path("/b"), files, [], [], 0, 0,
                            chosen=["nintendo-gba"])
        systems = [json.loads(line)["system"] for line in stream.getvalue().splitlines()
                   if json.loads(line)["event"] == "system"]
        self.assertEqual(systems, ["nintendo-gba"])
        stream.seek(0)
        stream.truncate()
        install._emit_check("retroarch", {}, Path("/b"), files, [], [], 0, 0)
        systems = [json.loads(line)["system"] for line in stream.getvalue().splitlines()
                   if json.loads(line)["event"] == "system"]
        self.assertEqual(systems, ["nintendo-gb", "nintendo-gba"])


class EventsDescribeTheRun(unittest.TestCase, _SyntheticTree):
    """--events: the handheld port reads the run as JSON lines on stdout and
    never parses the text, which goes to stderr."""

    def setUp(self):
        self.env = self.serve_tree(self)

    def _run(self, *argv: str) -> tuple[subprocess.CompletedProcess, list[dict]]:
        proc = _install_run(self.env, "--platform", "retroarch", "--dest", str(self.bios),
                            "--events", "--jobs", "1", *argv)
        self.assertNotIn("Traceback", proc.stderr)
        return proc, _events(proc)

    def _head(self, mode: str, installer: str) -> list[dict]:
        return [
            {"event": "start", "schema": install.EVENT_SCHEMA, "installer": installer,
             "mode": mode},
            {"event": "detect", "os": "linux", "os_name": install._os_name(),
             "platforms": [{"platform": "retroarch", "name": "RetroArch",
                            "bios_dir": str(self.bios)}]},
            # The systems Choose systems lists, before the files are read.
            {"event": "choices", "platform": "retroarch",
             "systems": ["sys-a", "sys-b", "other"]},
            # Nothing set aside before the choice.
            {"event": "set_aside", "platform": "retroarch", "dests": []},
            # a.bin and b.bin are in place: the first read and the last.
            {"event": "checking", "files_done": 1, "files_total": 2},
            {"event": "checking", "files_done": 2, "files_total": 2},
            {"event": "file", "platform": "retroarch", "dest": "a.bin",
             "systems": ["sys-a"], "size": 100, "state": "present"},
            {"event": "file", "platform": "retroarch", "dest": "b.bin",
             "systems": ["sys-a"], "size": 150, "state": "wrong_hash"},
            {"event": "file", "platform": "retroarch", "dest": "c.bin",
             "systems": ["sys-b"], "size": 70, "state": "missing"},
            {"event": "file", "platform": "retroarch", "dest": "d.bin",
             "systems": [], "size": 25, "state": "missing"},
            {"event": "system", "platform": "retroarch", "system": "other", "name": "other",
             "files": 1, "present": 0, "missing": 1, "wrong_hash": 0, "bytes_needed": 25},
            {"event": "system", "platform": "retroarch", "system": "sys-a", "name": "alpha",
             "files": 2, "present": 1, "missing": 0, "wrong_hash": 1, "bytes_needed": 150},
            {"event": "system", "platform": "retroarch", "system": "sys-b", "name": "sys-b",
             "files": 1, "present": 0, "missing": 1, "wrong_hash": 0, "bytes_needed": 70},
            {"event": "check", "platform": "retroarch", "name": "RetroArch",
             "bios_dir": str(self.bios), "files": 4, "present": 1, "missing": 2,
             "wrong_hash": 1, "bytes_needed": 245, "data_missing": 0,
             "not_installable": 1},
            # Every file of this list is the platform's own (cores: null).
            {"event": "declared", "platform": "retroarch", "files": 4, "present": 1,
             "missing": 2, "wrong_hash": 1, "bytes_needed": 245,
             "dests": ["a.bin", "b.bin", "c.bin", "d.bin"]},
            # No data tree in this list.
            {"event": "data", "platform": "retroarch", "files": 0, "bytes": 0},
        ]

    SKIPPED = [{"reason": "not_found", "label": "not found", "files": 1, "required": 1}]

    def test_a_check_run(self):
        proc, events = self._run("--check", "--verbose")
        self.assertEqual(proc.returncode, 3)
        installer = events[0]["installer"]
        self.assertEqual(events, self._head("check", installer) + [
            {"event": "summary", "mode": "check", "installed": 0, "up_to_date": 1,
             "pending": 3, "failed": [], "skipped": self.SKIPPED, "left_out": [], "kept": [],
             "interrupted": False},
            {"event": "end", "code": 3},
        ])
        self.assertIn("1 in place, 2 missing, 1 wrong copy", proc.stderr)
        self.assertFalse((self.bios / "c.bin").exists())

    def test_an_install_run(self):
        proc, events = self._run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        installer = events[0]["installer"]
        kept = events[-2]["kept"]
        self.assertEqual(len(kept), 1, kept)
        self.assertEqual(Path(kept[0]["folder"]).parent, self.home / install.BACKUP_DIR)
        progress = [event for event in events if event["event"] == "progress"]
        for event in progress:
            self.assertEqual(list(event), ["event", *install.EVENT_KEYS["progress"]])
        done = [{"event": "downloaded", "dest": dest, "ok": True, "reason": "",
                 "size": size, "files_done": n, "files_total": 3, "bytes_done": total,
                 "bytes_total": 245}
                for n, (dest, size, total) in enumerate(
                    (("c.bin", 70, 70), ("d.bin", 25, 95), ("b.bin", 150, 245)), 1)]
        # The last transfer: every byte came over the network.
        self.assertEqual([e for e in events if e["event"] == "transfer"][-1],
                         {"event": "transfer", "bytes_local": 0, "bytes_network": 245})
        record = next(e for e in events if e["event"] == "record")
        # What the run placed, and its choice, the whole list: written
        # right before the summary.
        self.assertEqual({key: record[key] for key in ("folder", "status", "choice", "files")},
                         {"folder": str(self.bios), "status": "written",
                          "choice": ["--all-files"], "files": 3})
        self.assertEqual(record["path"], str(self.home / install.BACKUP_DIR
                                             / f"{self.bios.name}.install.json"))
        self.assertEqual([e for e in events if e["event"] not in ("progress", "transfer")],
                         self._head("install", installer) + [
            {"event": "download", "platform": "retroarch", "files": 3, "bytes": 245},
            *done,
            record,
            {"event": "summary", "mode": "install", "installed": 3, "up_to_date": 1,
             "pending": 0, "failed": [], "skipped": self.SKIPPED, "left_out": [],
             "kept": [{"folder": kept[0]["folder"], "files": 1, "bytes": 11}],
             "interrupted": False},
            {"event": "end", "code": 0},
        ])
        self.assertEqual((self.bios / "b.bin").read_bytes(), self.FILES["bios/A/b.bin"])
        self.assertIn("Done. 3 files installed", proc.stderr)

    def test_every_event_has_its_schema_keys(self):
        _proc, events = self._run()
        for event in events:
            self.assertEqual(list(event), ["event", *install.EVENT_KEYS[event["event"]]])

    def test_a_file_list_out_of_reach_is_a_network_error(self):
        # A port nothing listens on: the connection is refused at once.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed = probe.getsockname()[1]
        env = {**self.env, "RETROBIOS_BASE_URL": f"http://127.0.0.1:{closed}"}
        proc = _install_run(env, "--platform", "retroarch", "--dest", str(self.bios),
                            "--events", "--check")
        events = _events(proc)
        self.assertEqual([e["event"] for e in events], ["start", "detect", "error", "end"])
        self.assertEqual(events[2]["reason"], "network")
        self.assertEqual(events[2]["stage"], "manifest")
        self.assertEqual(events[3], {"event": "end", "code": 1})

    def test_nothing_detected_is_an_empty_platform_list(self):
        proc = _install_run(self.env, "--events", "--check")
        events = _events(proc)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(events[1]["platforms"], [])
        self.assertEqual(events[-1], {"event": "end", "code": 1})

    def test_the_schema_is_documented(self):
        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        for kind, keys in install.EVENT_KEYS.items():
            row = next((line for line in page.splitlines()
                        if line.startswith(f"| `{kind}` |")), None)
            self.assertIsNotNone(row, kind)
            for key in keys:
                self.assertIn(f"`{key}`", row, f"{kind}.{key}")

    def test_a_run_is_valid_against_the_published_schema(self):
        try:
            from jsonschema import Draft202012Validator  # noqa: PLC0415
        except ImportError:
            self.skipTest("jsonschema is not installed")
        schema = json.loads(EVENT_SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        for argv in (("--check",), ()):
            _proc, events = self._run(*argv)
            for event in events:
                errors = [error.message for error in validator.iter_errors(event)]
                self.assertEqual(errors, [], event)
        self.assertTrue(list(validator.iter_errors({"event": "file", "platform": "x"})))
        self.assertTrue(list(validator.iter_errors(
            {"event": "end", "code": 0, "extra": 1})))


EVENT_SCHEMA_PATH = REPO_ROOT / "schemas" / "install-events.schema.json"


class TheEventSchemaFileIsEventKeys(unittest.TestCase):
    """The table in the wiki was the only description of --events a reader
    outside Python could check a stream against."""

    def _generator(self):
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import generate_event_schema  # noqa: PLC0415

        return generate_event_schema

    def test_the_committed_file_is_the_generated_one(self):
        generator = self._generator()
        self.assertEqual(EVENT_SCHEMA_PATH.read_text(encoding="utf-8"),
                         generator.render(generator.build_schema()),
                         "run python scripts/generate_event_schema.py")

    def test_each_kind_has_exactly_its_keys(self):
        schema = json.loads(EVENT_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["event"]["enum"], list(install.EVENT_KEYS))
        for kind, keys in install.EVENT_KEYS.items():
            shape = schema["$defs"][kind]
            self.assertEqual(shape["required"], ["event", *keys], kind)
            self.assertEqual(list(shape["properties"]), ["event", *keys], kind)
            self.assertIs(shape["additionalProperties"], False, kind)
        start = schema["$defs"]["start"]["properties"]["schema"]
        self.assertEqual(start, {"const": install.EVENT_SCHEMA})

    def test_a_key_without_a_type_stops_the_generator(self):
        generator = self._generator()
        with unittest.mock.patch.dict(install.EVENT_KEYS, {"new": ("untyped_key",)}), \
                unittest.mock.patch.object(generator, "EVENT_KEYS", install.EVENT_KEYS), \
                self.assertRaises(KeyError):
            generator.build_schema()

    def test_the_check_command_fails_on_a_stale_file(self):
        generator = self._generator()
        scratch = Path(_tempdir(self)) / "events.schema.json"
        scratch.write_text("{}\n", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(generator.main(["--check", "--output", str(scratch)]), 1)
            self.assertEqual(generator.main(["--output", str(scratch)]), 0)
            self.assertEqual(generator.main(["--check", "--output", str(scratch)]), 0)


class TheInstallerPageIsWrittenFromTheCode(unittest.TestCase):
    """The options, events, exit codes and keys of wiki/installer.md were
    written by hand beside the code that defines them, and every audit
    found one of them behind it."""

    PAGE = REPO_ROOT / "wiki" / "installer.md"

    def setUp(self):
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import generate_installer_doc  # noqa: PLC0415

        self.generator = generate_installer_doc
        self.scratch = Path(_tempdir(self)) / "installer.md"
        self.scratch.write_text(self.PAGE.read_text(encoding="utf-8"), encoding="utf-8")

    def run_generator(self, *argv: str) -> tuple[int, str]:
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = self.generator.main([*argv, "--page", str(self.scratch)])
        return code, err.getvalue()

    def test_the_committed_page_is_the_generated_one(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(self.generator.main(["--check"]), 0,
                             err.getvalue() + "run python scripts/generate_installer_doc.py")

    def test_a_hand_edit_of_a_fact_fails_the_check(self):
        page = self.scratch.read_text(encoding="utf-8")
        for old, new in (("`--jobs N`", "`--jobs JOBS`"),
                         ("| `end` | `code` |", "| `end` | `code`, `reason` |"),
                         ("| Quit at once | none |", "| Quit at once | q |"),
                         # A code install.py never exits with.
                         ("| `141` |", "| `142` | stopped twice |\n| `141` |")):
            with self.subTest(edit=new):
                self.assertIn(old, page)
                self.scratch.write_text(page.replace(old, new, 1), encoding="utf-8")
                self.assertEqual(self.run_generator("--check")[0], 1)
                self.assertEqual(self.run_generator()[0], 0)
                self.assertEqual(self.scratch.read_text(encoding="utf-8"), page)

    def test_the_prose_is_kept(self):
        page = self.scratch.read_text(encoding="utf-8")
        old = "| Parallel downloads, 1 to 32, default 8 |"
        self.assertIn(old, page)
        edited = page.replace(old, "| Parallel downloads, from 1 to 32 |")
        self.scratch.write_text(edited, encoding="utf-8")
        self.assertEqual(self.run_generator("--check")[0], 0)

    def test_what_the_code_gains_stops_it_until_the_page_says_it(self):
        real = self.generator._install.build_parser

        def gained() -> argparse.ArgumentParser:
            parser = real()
            parser.add_argument("--brand-new", action="store_true", help="new")
            return parser

        page = self.scratch.read_text(encoding="utf-8")
        events = {**self.generator._install.EVENT_KEYS, "brand_new": ("thing",)}
        for name, patch in (
                ("--brand-new", unittest.mock.patch.object(
                    self.generator._install, "build_parser", gained)),
                ("brand_new", unittest.mock.patch.object(
                    self.generator._install, "EVENT_KEYS", events))):
            with self.subTest(gained=name), patch:
                code, said = self.run_generator()
                self.assertEqual(code, 1)
                self.assertIn(name, said)
                self.assertEqual(self.scratch.read_text(encoding="utf-8"), page)
                self.assertEqual(self.run_generator("--check")[0], 1)
        # The row added by hand, its first cell alone: the generator fills it.
        close = "\n\n<!-- /generated: options -->"
        self.scratch.write_text(
            page.replace(close, "\n| `--brand-new` | Something new |" + close, 1),
            encoding="utf-8")
        with unittest.mock.patch.object(self.generator._install, "build_parser", gained):
            self.assertEqual(self.run_generator()[0], 0)
        self.assertIn('| <span id="option-brand-new"></span>`--brand-new` | Something new |',
                      self.scratch.read_text(encoding="utf-8"))

    def test_the_exit_codes_are_the_ones_install_py_exits_with(self):
        self.assertEqual(self.generator.exit_codes(), [0, 1, 2, 3, 4, 130, 141])

    def test_a_missing_marker_stops_it(self):
        page = self.scratch.read_text(encoding="utf-8")
        self.scratch.write_text(page.replace("<!-- generated: route-keys -->\n", ""),
                                encoding="utf-8")
        code, said = self.run_generator("--check")
        self.assertEqual(code, 1)
        self.assertIn("route-keys", said)


class AStrippedPythonIsNamed(unittest.TestCase):
    """A Python built without ssl blamed the network three times, and one
    without zlib or unicodedata stopped on a ModuleNotFoundError traceback."""

    def _run(self, hidden: str, *argv: str) -> subprocess.CompletedProcess:
        code = (f"import runpy, sys; sys.modules[{hidden!r}] = None; "
                "sys.argv = sys.argv[1:]; "
                "runpy.run_path(sys.argv[0], run_name='__main__')")
        env = {key: value for key, value in os.environ.items()
               if key not in ("RETROBIOS_BASE_URL", install.OFFLINE_VARIABLE)}
        return subprocess.run(
            [sys.executable, "-c", code, str(REPO_ROOT / "install.py"), *argv],
            env=env, capture_output=True, text=True, timeout=60,
            stdin=subprocess.DEVNULL)

    def test_a_missing_c_module_is_named(self):
        for hidden in ("zlib", "unicodedata"):
            with self.subTest(module=hidden):
                proc = self._run(hidden, "--help")
                self.assertEqual(proc.returncode, 1)
                self.assertNotIn("Traceback", proc.stderr)
                self.assertIn(f"built without its {hidden} module", proc.stderr)

    def test_no_ssl_is_said_once_not_retried(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as dest:
            proc = self._run("ssl", "--platform", "retroarch", "--dest", dest,
                             "--check", "--no-input")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("built without its ssl module and cannot use HTTPS", proc.stderr)
        self.assertNotIn("trying again", proc.stderr)
        self.assertNotIn("HTTPS_PROXY", proc.stderr)


class NetworkFailuresInPlainWords(unittest.TestCase):
    """Offline, the run printed "[Errno -2] Name or service not known". A
    beginner needs "no internet connection", and the raw text only under
    --verbose."""

    def _words(self, reason: BaseException, **kwargs) -> tuple[str, str]:
        return install.network_words(urllib.error.URLError(reason), **kwargs)

    def test_the_common_failures(self):
        import ssl  # noqa: PLC0415

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
        import datetime  # noqa: PLC0415
        import ssl  # noqa: PLC0415

        error = ssl.SSLCertVerificationError(1, "certificate is not yet valid")
        with unittest.mock.patch.object(install, "_ca_bundle_found", return_value=True):
            code, text = self._words(error, today=datetime.date(1980, 1, 1))
            self.assertEqual(code, "clock")
            self.assertIn("The clock reads 1980-01-01", text)
            self.assertIn("set the date", text)
            code, _text = self._words(error, today=install.CLOCK_FLOOR)
            self.assertEqual(code, "network")

    def test_no_certificate_list_names_ssl_cert_file(self):
        import ssl  # noqa: PLC0415

        error = ssl.SSLCertVerificationError(1, "unable to get local issuer certificate")
        with unittest.mock.patch.object(install, "_ca_bundle_found", return_value=False):
            code, text = self._words(error)
        self.assertEqual(code, "no_ca")
        self.assertIn("SSL_CERT_FILE", text)

    def test_a_certificate_list_is_looked_for_where_openssl_and_systems_keep_it(self):
        root = Path(_tempdir(self))
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
               "HOME": _tempdir(self)}
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retroarch",
             "--dest", _tempdir(self), "--check"],
            env=env, capture_output=True, text=True, timeout=120, check=False,
            stdin=subprocess.DEVNULL,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no internet connection", proc.stderr)
        self.assertNotIn("Errno", proc.stderr)


class AFileYouHadIsKept(unittest.TestCase):
    """A BIOS file whose contents differ was replaced and lost: a personal
    dump or another revision could not be brought back by deleting what the
    installer wrote. It is moved beside the BIOS folder first, never inside,
    where a core that finds its BIOS by content could take it."""

    NEW = b"the collection's copy"
    OLD = b"a dump of my own"

    def setUp(self):
        install.KEPT.reset()
        self.addCleanup(install.KEPT.reset)
        self.home = Path(_tempdir(self))
        self.bios = self.home / "system"
        self.bios.mkdir()

    def _entry(self, dest: str) -> dict:
        return {"dest": dest, "repo_path": f"bios/{dest}", "size": len(self.NEW),
                "sha1": hashlib.sha1(self.NEW).hexdigest(),
                "sha256": hashlib.sha256(self.NEW).hexdigest()}

    def _download(self, dest: str):
        with unittest.mock.patch.object(install.urllib.request, "urlopen",
                                        lambda *a, **k: _FakeResponse(self.NEW)):
            return install._download_one(self._entry(dest), self.bios)

    def _run_folder(self) -> Path:
        runs = list((self.home / install.BACKUP_DIR).iterdir())
        self.assertEqual(len(runs), 1, runs)
        return runs[0]

    def test_a_differing_file_is_kept_with_its_relative_path(self):
        (self.bios / "sub").mkdir()
        (self.bios / "sub" / "x.bin").write_bytes(self.OLD)
        self.assertEqual(self._download("sub/x.bin"), ("sub/x.bin", True, ""))
        self.assertEqual((self.bios / "sub" / "x.bin").read_bytes(), self.NEW)
        run = self._run_folder()
        self.assertEqual((run / "system" / "sub" / "x.bin").read_bytes(), self.OLD)
        self.assertEqual(install.KEPT.summary(),
                         [{"folder": str(run), "files": 1, "bytes": len(self.OLD)}])
        # Nothing new sits inside the BIOS folder, where a scan would read it.
        self.assertEqual(sorted(p.name for p in self.bios.rglob("*")), ["sub", "x.bin"])

    def test_an_identical_file_is_not_copied(self):
        (self.bios / "x.bin").write_bytes(self.NEW)
        self.assertEqual(self._download("x.bin"), ("x.bin", True, ""))
        self.assertFalse((self.home / install.BACKUP_DIR).exists())
        self.assertEqual(install.KEPT.summary(), [])

    def test_a_missing_file_keeps_nothing(self):
        self.assertEqual(self._download("x.bin"), ("x.bin", True, ""))
        self.assertFalse((self.home / install.BACKUP_DIR).exists())

    def test_a_second_replacement_keeps_the_first_file(self):
        # Two lists in one run writing one path: what is kept is the user's.
        (self.bios / "x.bin").write_bytes(self.OLD)
        self._download("x.bin")
        (self.bios / "x.bin").write_bytes(b"what this run wrote first")
        self._download("x.bin")
        self.assertEqual((self._run_folder() / "system" / "x.bin").read_bytes(), self.OLD)

    def test_a_file_that_cannot_be_kept_stays(self):
        (self.bios / "x.bin").write_bytes(self.OLD)

        def refuse(*_args):
            raise PermissionError(13, "Permission denied")

        with unittest.mock.patch.object(install, "_move_aside", refuse):
            _dest, ok, reason = self._download("x.bin")
        self.assertFalse(ok)
        self.assertIn(install.NOT_KEPT, reason)
        self.assertEqual((self.bios / "x.bin").read_bytes(), self.OLD)
        self.assertEqual(sorted(p.name for p in self.bios.iterdir()), ["x.bin"])

    def test_a_symlinked_subfolder_keeps_working(self):
        elsewhere = self.home / "shadPS4" / "sys_modules"
        elsewhere.mkdir(parents=True)
        (elsewhere / "lib.sprx").write_bytes(self.OLD)
        (self.bios / "shadps4").mkdir()
        (self.bios / "shadps4" / "sys_modules").symlink_to(elsewhere)
        self.assertTrue(self._download("shadps4/sys_modules/lib.sprx")[1])
        self.assertEqual((elsewhere / "lib.sprx").read_bytes(), self.NEW)
        self.assertTrue((self.bios / "shadps4" / "sys_modules").is_symlink())
        run = self._run_folder()
        kept = run / "system" / "shadps4" / "sys_modules" / "lib.sprx"
        self.assertEqual(kept.read_bytes(), self.OLD)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(install.restore_kept(run), 0)
        self.assertEqual((elsewhere / "lib.sprx").read_bytes(), self.OLD)
        self.assertTrue((self.bios / "shadps4" / "sys_modules").is_symlink())

    def test_a_link_at_the_name_is_not_kept(self):
        # The replace takes the link's place: the file it points to is untouched.
        target = self.home / "mine.bin"
        target.write_bytes(self.OLD)
        (self.bios / "x.bin").symlink_to(target)
        self.assertTrue(self._download("x.bin")[1])
        self.assertEqual(target.read_bytes(), self.OLD)
        self.assertFalse((self.home / install.BACKUP_DIR).exists())

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root writes anywhere")
    def test_without_room_beside_the_folder_it_goes_inside(self):
        (self.bios / "x.bin").write_bytes(self.OLD)
        self.home.chmod(0o555)
        self.addCleanup(self.home.chmod, 0o755)
        self.assertTrue(self._download("x.bin")[1])
        runs = list((self.bios / install.BACKUP_DIR).iterdir())
        self.assertEqual(len(runs), 1)
        self.assertEqual((runs[0] / "x.bin").read_bytes(), self.OLD)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(install.restore_kept(runs[0]), 0)
        self.assertEqual((self.bios / "x.bin").read_bytes(), self.OLD)

    def test_a_data_tree_file_is_kept(self):
        import zipfile

        tree = self.bios / "dolphin-emu" / "Sys"
        tree.mkdir(parents=True)
        (tree / "a.ini").write_bytes(self.OLD)
        archive = self.home / "src.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("Sys/a.ini", self.NEW)
        entry = {"ref": "d", "dest": "dolphin-emu", "url": "https://example.invalid/d.zip",
                 "type": "zip", "files": {"Sys/a.ini": {
                     "sha1": hashlib.sha1(self.NEW).hexdigest(), "size": len(self.NEW)}}}

        def fetch(url, directory, progress=None, keep=None):
            copy = Path(directory) / "a.zip"
            shutil.copy(archive, copy)
            return copy

        with unittest.mock.patch.object(install, "_fetch_archive", fetch):
            counts = install.install_data_directory(entry, self.bios)
        self.assertEqual(counts["installed"], 1)
        self.assertEqual((tree / "a.ini").read_bytes(), self.NEW)
        kept = self._run_folder() / "system" / "dolphin-emu" / "Sys" / "a.ini"
        self.assertEqual(kept.read_bytes(), self.OLD)

    def test_a_standalone_copy_keeps_the_emulators_file(self):
        (self.bios / "ps2-0230a.bin").write_bytes(self.NEW)
        pcsx2 = self.home / "PCSX2" / "bios"
        pcsx2.mkdir(parents=True)
        (pcsx2 / "ps2-0230a.bin").write_bytes(self.OLD)
        manifest = {"standalone_copies": [
            {"pattern": "ps2-*.bin", "emulator": "pcsx2", "targets": {"linux": [str(pcsx2)]}}]}
        self.assertEqual(install.do_standalone_copies(manifest, self.bios, "linux"), (1, 0, 0))
        self.assertEqual((pcsx2 / "ps2-0230a.bin").read_bytes(), self.NEW)
        runs = list((self.home / "PCSX2" / install.BACKUP_DIR).iterdir())
        self.assertEqual((runs[0] / "bios" / "ps2-0230a.bin").read_bytes(), self.OLD)
        # Copied again, the file is the same: nothing more is kept.
        self.assertEqual(install.do_standalone_copies(manifest, self.bios, "linux"), (1, 0, 0))
        self.assertEqual(install.KEPT.summary()[0]["files"], 1)

    def test_a_kept_file_inside_the_tree_is_no_copy_source(self):
        inside = self.bios / install.BACKUP_DIR / "20261022-153000"
        inside.mkdir(parents=True)
        (inside / "ps2-old.bin").write_bytes(self.OLD)
        pcsx2 = self.home / "PCSX2" / "bios"
        pcsx2.mkdir(parents=True)
        manifest = {"standalone_copies": [
            {"pattern": "ps2-*.bin", "emulator": "pcsx2", "targets": {"linux": [str(pcsx2)]}}]}
        self.assertEqual(install.do_standalone_copies(manifest, self.bios, "linux"), (0, 0, 0))

    def test_restore_refuses_a_folder_that_is_no_backup(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(install.restore_kept(self.bios), 2)
        self.assertIn(install.BACKUP_DIR, err.getvalue())

    def test_a_linked_backup_holder_is_not_written_through(self):
        # Someone with write access to a shared parent folder placed a link
        # where the holder goes: the user's file must not land at its target.
        elsewhere = self.home / "elsewhere"
        elsewhere.mkdir()
        (self.home / install.BACKUP_DIR).symlink_to(elsewhere)
        (self.bios / "x.bin").write_bytes(self.OLD)
        self.assertTrue(self._download("x.bin")[1])
        self.assertEqual(list(elsewhere.iterdir()), [])
        inside = list((self.bios / install.BACKUP_DIR).iterdir())
        self.assertEqual(len(inside), 1)
        self.assertEqual((inside[0] / "x.bin").read_bytes(), self.OLD)

    def test_a_holder_with_every_name_taken_is_not_reused(self):
        # Folders planted under every dated name of this run: none of them
        # may receive the user's file.
        holder = self.home / install.BACKUP_DIR
        stamp = "20260101-000000"
        for n in range(1, 1000):
            (holder / (stamp if n == 1 else f"{stamp}-{n}")).mkdir(parents=True)
        (self.bios / "x.bin").write_bytes(self.OLD)
        with unittest.mock.patch.object(install.time, "strftime", return_value=stamp):
            self.assertTrue(self._download("x.bin")[1])
        self.assertEqual(sum(1 for p in holder.rglob("x.bin")), 0)
        inside = list((self.bios / install.BACKUP_DIR).iterdir())
        self.assertEqual(len(inside), 1)
        self.assertEqual((inside[0] / "x.bin").read_bytes(), self.OLD)

    def test_a_holder_swapped_after_the_check_is_noticed(self):
        holder = self.home / install.BACKUP_DIR
        holder.mkdir()
        checked = install._check_holder(holder)
        self.assertTrue(install._same_folder(holder, checked))
        holder.rename(self.home / "moved")
        (self.home / "elsewhere").mkdir()
        holder.symlink_to(self.home / "elsewhere")
        self.assertFalse(install._same_folder(holder, checked))
        with self.assertRaises(OSError):
            install._check_holder(holder)

    @unittest.skipUnless(hasattr(os, "getuid"), "user ids are POSIX")
    def test_a_holder_another_user_owns_is_refused(self):
        holder = self.home / install.BACKUP_DIR
        holder.mkdir()
        real = os.lstat

        def planted(path, *args, **kwargs):
            info = real(path, *args, **kwargs)
            if Path(path) != holder:
                return info
            fields = list(info)
            fields[stat.ST_UID] = info.st_uid + 2
            return os.stat_result(fields)

        with self.assertRaises(OSError), \
                unittest.mock.patch.object(install.os, "lstat", side_effect=planted):
            install._check_holder(holder)
        install._check_holder(holder)

    @unittest.skipUnless(hasattr(os, "getuid"), "user ids are POSIX")
    def test_a_storage_with_one_owner_for_every_file_takes_the_holder(self):
        # Android's shared storage, seen from Termux on Android 17: a folder
        # the run has just made is shown as another user's, like every other
        # file there. Refusing it left 25 files unreplaced on a real phone.
        holder = self.home / install.BACKUP_DIR
        holder.mkdir()
        with unittest.mock.patch.object(install.os, "getuid", return_value=os.getuid() + 1):
            install._check_holder(holder)
            (self.bios / "x.bin").write_bytes(self.OLD)
            self.assertTrue(self._download("x.bin")[1])
        self.assertEqual((self._run_folder() / "system" / "x.bin").read_bytes(), self.OLD)

    def test_restore_refuses_a_folder_the_installer_did_not_write(self):
        planted = self.home / install.BACKUP_DIR / "20260101-000000"
        (planted / "system").mkdir(parents=True)
        (planted / "system" / "x.bin").write_bytes(b"not the user's")
        (self.bios / "x.bin").write_bytes(self.OLD)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(install.restore_kept(planted), 2)
        self.assertEqual((self.bios / "x.bin").read_bytes(), self.OLD)

    def test_restore_does_not_follow_links_inside_the_backup(self):
        (self.bios / "x.bin").write_bytes(self.OLD)
        self.assertTrue(self._download("x.bin")[1])
        run = self._run_folder()
        outside = self.home / "outside"
        (outside / "deep").mkdir(parents=True)
        (outside / "deep" / "y.bin").write_bytes(b"foreign")
        (run / "system" / "linked").symlink_to(outside)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(install.restore_kept(run), 0)
        self.assertEqual((self.bios / "x.bin").read_bytes(), self.OLD)
        self.assertFalse((self.bios / "linked").exists())


class KeptFilesEndToEnd(unittest.TestCase, _SyntheticTree):
    """The run says what it kept and where, --dry-run what it would keep
    and writes nothing, and --restore puts the original bytes back."""

    def setUp(self):
        self.env = self.serve_tree(self)

    def test_dry_run_says_what_would_be_kept_and_writes_nothing(self):
        proc = _install_run(self.env, "--platform", "retroarch", "--dest", str(self.bios),
                            "--dry-run", "--no-input")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Would keep 1 file already there (11 B)", proc.stdout)
        self.assertIn(str(self.home / install.BACKUP_DIR), proc.stdout)
        self.assertFalse((self.home / install.BACKUP_DIR).exists())
        self.assertEqual((self.bios / "b.bin").read_bytes(), b"other bytes")
        events = _events(_install_run(self.env, "--platform", "retroarch", "--dest",
                                      str(self.bios), "--dry-run", "--events"))
        kept = events[-2]["kept"]
        self.assertEqual([(item["files"], item["bytes"]) for item in kept], [(1, 11)])
        self.assertFalse((self.home / install.BACKUP_DIR).exists())

    def test_install_then_restore(self):
        proc = _install_run(self.env, "--platform", "retroarch", "--dest", str(self.bios),
                            "--no-input", "--jobs", "1", "--verbose")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((self.bios / "b.bin").read_bytes(), self.FILES["bios/A/b.bin"])
        # The install record sits beside the run folders, a file of its own.
        held = list((self.home / install.BACKUP_DIR).iterdir())
        runs = [path for path in held if path.is_dir()]
        self.assertEqual(sorted(path.name for path in held if not path.is_dir()),
                         [f"{self.bios.name}.install.json"])
        self.assertEqual(len(runs), 1)
        self.assertIn("Kept 1 file already there (11 B), which the collection's copies "
                      f"replaced, in {runs[0]}", proc.stdout)
        self.assertIn(f"--restore {runs[0]}", proc.stdout)
        # a.bin held the expected bytes: it is not among the kept files.
        self.assertEqual([p.name for p in (runs[0] / "bios").iterdir()], ["b.bin"])

        refused = _install_run(self.env, "--restore", str(runs[0]), "--platform", "retroarch")
        self.assertEqual(refused.returncode, 2)
        self.assertIn("--restore", refused.stderr)

        looked = _install_run(self.env, "--restore", str(runs[0]), "--dry-run")
        self.assertEqual(looked.returncode, 0, looked.stderr)
        self.assertIn(f"would put back {self.bios / 'b.bin'}", looked.stdout)
        self.assertEqual((self.bios / "b.bin").read_bytes(), self.FILES["bios/A/b.bin"])

        back = _install_run(self.env, "--restore", str(runs[0]))
        self.assertEqual(back.returncode, 0, back.stdout + back.stderr)
        self.assertEqual((self.bios / "b.bin").read_bytes(), b"other bytes")
        self.assertEqual((self.bios / "a.bin").read_bytes(), self.FILES["bios/A/a.bin"])
        self.assertIn("Put back 1 file", back.stdout)
        # The backup stays until the user deletes it.
        self.assertTrue((runs[0] / "bios" / "b.bin").is_file())

        # A second install keeps the restored file in a new folder.
        again = _install_run(self.env, "--platform", "retroarch", "--dest", str(self.bios),
                             "--no-input", "--jobs", "1")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(len([path for path in (self.home / install.BACKUP_DIR).iterdir()
                              if path.is_dir()]), 2)



class TheListVersionIsComparedWithTheSystems(unittest.TestCase):
    """The list says which version of the platform it was built for, and the
    installer reads the version the system runs from the file the system
    writes. A difference is said, never refused."""

    def note(self, plat: str, listed: str, bios: Path = Path("/userdata/bios")):
        return install.version_note(plat, bios, {"platform": plat, "version": listed})

    def test_batocera_reads_the_first_word_of_its_version_file(self):
        _device(self, {"/usr/share/batocera/batocera.version": "41 2025/01/17 10:12\n"})
        listed, installed, text = self.note("batocera", "43.1")
        self.assertEqual((listed, installed), ("43.1", "41"))
        self.assertEqual(
            text, "This list was built for Batocera 43.1, this machine runs 41. "
            "Batocera's own BIOS check reads the list of the version it runs, and "
            "may show some files as not matching it.")
        self.assertIsNone(self.note("batocera", "41"))

    def test_recalbox_reads_only_a_release(self):
        _device(self, {"/recalbox/recalbox.version": "10.0\n"})
        self.assertEqual(self.note("recalbox", "10.1.1")[:2], ("10.1.1", "10.0"))
        self.assertIsNone(self.note("recalbox", "10.0"))
        for built in ("development", "2026/10/01 main (4242)"):
            with self.subTest(built=built):
                _device(self, {"/recalbox/recalbox.version": built})
                self.assertIsNone(self.note("recalbox", "10.1.1"))

    def test_retrobat_reads_the_folder_beside_its_bios_folder(self):
        root = Path(_tempdir(self))
        version = root / "system" / "version.info"
        version.parent.mkdir()
        version.write_text("8.3.1.1-stable-win64")
        # The release tagged 8.3.1 ships 8.3.1.1.
        self.assertIsNone(self.note("retrobat", "8.3.1", root / "bios"))
        version.write_text("8.2.0-stable-win64")
        self.assertEqual(self.note("retrobat", "8.3.1", root / "bios")[:2],
                         ("8.3.1", "8.2.0"))

    def test_lakka_and_emuelec_read_os_release(self):
        _device(self, {}, release='NAME="Lakka"\nID="lakka"\nVERSION_ID="6.0"\n')
        listed, installed, text = self.note("lakka", "v6.1")
        self.assertEqual((listed, installed), ("v6.1", "6.0"))
        self.assertIn("Lakka checks only that a file is there", text)
        _device(self, {}, release='NAME="Lakka"\nID="lakka"\nVERSION_ID="6.1"\n')
        self.assertIsNone(self.note("lakka", "v6.1"))
        _device(self, {}, release='NAME="EmuELEC"\nVERSION_ID="4.7"\n')
        self.assertEqual(self.note("emuelec", "4.8")[:2], ("4.8", "4.7"))
        # The file of another system says nothing about this one.
        self.assertIsNone(self.note("lakka", "v6.1"))

    def test_an_unknown_version_says_nothing(self):
        _device(self, {"/usr/share/batocera/batocera.version": "41 2025/01/17 10:12"})
        self.assertIsNone(self.note("batocera", "1.0"))
        self.assertIsNone(install.version_note("batocera", Path("/userdata/bios"),
                                               {"platform": "batocera"}))
        self.assertIsNone(self.note("retroarch", "v1.22.2"))
        _device(self, {"/usr/share/knulli/knulli.version": "scarab 2026/05/11 10:00"})
        self.assertIsNone(self.note("knulli", "20260511"))
        _device(self, {})
        self.assertIsNone(self.note("batocera", "43.1"))
        _device(self, {"/usr/share/batocera/batocera.version": "\x1b[2J 2025/01/17"})
        self.assertIsNone(self.note("batocera", "43.1"))

    def test_a_pack_alone_gives_the_version_of_its_list(self):
        """A handheld without network installs from the pack: its manifest.json
        records the list's version, which generate_pack takes from the
        install list built with the same choices."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import generate_pack
        data = b"bios"
        install_list = {"version": "43.1", "files": [
            {"dest": "a.bin", "sha1": hashlib.sha1(data).hexdigest(), "size": 4}]}
        pack_list = {"files": [{"path": "a.bin", "sha1": hashlib.sha1(data).hexdigest(),
                                "size": 4}]}
        generate_pack.annotate_pack_systems(pack_list, generate_pack.pack_systems(install_list))
        self.assertEqual(pack_list["list_version"], "43.1")
        pack = Path(_tempdir(self)) / "Batocera_43.1_BIOS_Pack.zip"
        with zipfile.ZipFile(pack, "w") as archive:
            archive.writestr("manifest.json", json.dumps(pack_list))
            archive.writestr("a.bin", data)
        source = install.PackSource([pack])
        self.addCleanup(source.close)
        self.assertEqual(source.manifest("batocera")["version"], "43.1")

    def test_the_result_repeats_it_in_every_ending(self):
        for kw in ({"downloaded": 3}, {"errors": 2}, {"downloaded": 1, "errors": 1}):
            with self.subTest(**kw):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf), contextlib.suppress(SystemExit):
                    install._report_outcome([Path("/userdata/bios")], omitted=0,
                                            interrupted=False, notes=["Built for 43.1."],
                                            **{"downloaded": 0, "up_to_date": 0,
                                               "errors": 0, **kw})
                self.assertIn("Built for 43.1.", buf.getvalue())


class TheListVersionIsSaidBeforeAndAfter(unittest.TestCase):
    """A RetroBat folder holding 8.2.0 and a list built for 8.3.1, through
    the installer as a person and as the screen run it."""

    DATA = b"retrobat bios" * 8

    def setUp(self):
        self.root = Path(_tempdir(self))
        (self.root / "system").mkdir()
        (self.root / "system" / "version.info").write_text("8.2.0-stable-win64")
        self.bios = self.root / "bios"
        self.bios.mkdir()
        (self.bios / "a.bin").write_bytes(self.DATA)
        self.list = self.root / "retrobat.json"
        self.list.write_text(json.dumps({
            "manifest_version": 2, "platform": "retrobat", "version": "8.3.1",
            "files": [{"dest": "a.bin", "sha1": hashlib.sha1(self.DATA).hexdigest(),
                       "size": len(self.DATA), "repo_path": "bios/a.bin"}],
        }))

    def run_installer(self, *options: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retrobat",
             "--dest", str(self.bios), "--manifest", str(self.list), "--offline",
             "--yes", *options],
            capture_output=True, text=True, timeout=120, check=False,
            stdin=subprocess.DEVNULL,
        )

    SAID = ("This list was built for RetroBat 8.3.1, this machine runs 8.2.0. "
            "RetroBat's own BIOS check reads the list of the version it runs, and "
            "may show some files as not matching it.")

    def test_line_mode_says_it_before_the_install_and_with_the_result(self):
        proc = self.run_installer("--verbose")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout.count(self.SAID), 2, proc.stdout)
        self.assertLess(proc.stdout.index(self.SAID), proc.stdout.index("Checking existing"))
        self.assertGreater(proc.stdout.rindex(self.SAID), proc.stdout.index("Done."))

    def test_the_screen_reads_an_event(self):
        proc = self.run_installer("--check", "--events")
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        said = [event for event in events if event["event"] == "version"]
        self.assertEqual(said, [{"event": "version", "platform": "retrobat",
                                 "list_version": "8.3.1", "installed_version": "8.2.0",
                                 "message": self.SAID}])
        kinds = [event["event"] for event in events]
        self.assertLess(kinds.index("version"), kinds.index("check"))

    def test_the_same_version_says_nothing(self):
        (self.root / "system" / "version.info").write_text("8.3.1.1-stable-win64")
        proc = self.run_installer()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("This list was built for", proc.stdout)


class APackageHintNamesThePackageCommand(unittest.TestCase):
    """Run from the retrobios package, a hint said `python3 install.py`,
    a file the user does not have."""

    def test_the_environment_names_the_command(self):
        for prefix, command in (
            ("/home/me/.cache/uv/archive-v0/UwL4i3xOlCEYSTnw", "uvx retrobios"),
            ("C:\\Users\\me\\AppData\\Local\\uv\\cache\\archive-v0\\x1", "uvx retrobios"),
            ("/home/me/.cache/pipx/539b8243c11ee7c", "pipx run retrobios"),
            ("/home/me/.local/pipx/.cache/539b8243c11ee7c", "pipx run retrobios"),
            ("/home/me/.local/share/pipx/venvs/retrobios", "retrobios"),
            ("/home/me/.local/share/uv/tools/retrobios", "retrobios"),
            ("/home/me/venv", "retrobios"),
        ):
            with self.subTest(prefix=prefix):
                self.assertEqual(install.package_command(prefix), command)

    def test_the_launcher_is_the_package_command(self):
        hint = install.Invocation()
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": "pypi"}), \
                unittest.mock.patch.object(install.sys, "prefix", "/home/me/.cache/uv/archive-v0/a"):
            self.assertEqual(hint.launcher(), "uvx retrobios")
            self.assertEqual(hint.launcher(elevated=True), "sudo uvx retrobios")
            self.assertTrue(hint.command("retroarch", "DIR").startswith(
                "uvx retrobios --platform retroarch --dest DIR"))


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
