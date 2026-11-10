"""The installer's full-screen interface.

The interface is a model, a pure update on keys and events, and pure views:
most of it is tested here without a terminal. The end-to-end cases run the
real install.py --tui on a pseudo-terminal read back with pyte, against a
loopback copy of the repository, and skip when pyte is not installed (CI
installs it).
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import argparse
import contextlib
import errno
import fcntl
import functools
import hashlib
import http.server
import io
import json
import os
import queue
import re
import select
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import types
import unittest
import warnings
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import install  # noqa: E402
from test_install_app import make_card  # noqa: E402
from test_install_selection import FakeRepository, _QuietHandler  # noqa: E402
from netguard import module_guard  # noqa: E402

# No connection off the loopback and no card of the host reaches a test, in
# this process or one it starts: 261 connections to
# GitHub left this module in a run, and two tests failed with an AmberELEC
# card in the reader. The module fails at its end when one is tried.
setUpModule, tearDownModule = module_guard("test_install_tui")

try:
    import pyte
except ImportError:
    pyte = None

try:
    import pty
except ImportError:
    pty = None

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except ImportError:
    given = None

GOLDEN = REPO_ROOT / "tests" / "fixtures" / "tui"
SIZES = ((40, 12), (40, 15), (80, 24), (120, 40))
# RETROBIOS_PAD's values, and "keys" for a desktop that sets none.
ROUTES = ("keys", "gptokeyb", "gptokeyb_muxterm", "evmapy", "muxterm", "miyoo")
UP, DOWN, RIGHT, LEFT = "\x1b[A", "\x1b[B", "\x1b[C", "\x1b[D"
Key = install.TuiKey


def keys(*names: str) -> list:
    return [Key("char", name[5:]) if name.startswith("char:") else Key(name) for name in names]


# The screens as --verbose draws them, every Details line where it belongs:
# the findings marked with it read lines the default leaves to Details.
in_full = mock.patch.object(install, "tui_verbose", lambda _state: True)


def _args(**given) -> argparse.Namespace:
    """The namespace main() parses, every option at its default."""
    values = dict(
        platform=None, dest=None, target=None, every_board=False, check=False,
        list_platforms=False, list_targets=False, jobs=8, verbose=False,
        standalone_copies=False, emulator=None, installed_cores=False, save_dir=None,
        cores_dir=None, system=None, core=None, region=None, no_game_data=False,
        list_systems=False, list_cores=False, romm_firmware=None, list_emulators=False,
        no_input=False, dry_run=False, yes=False, quiet=False, events=False,
        restore=None, from_pack=None, manifest=None, tui=False, plain=False, add_app=False,
    )
    values["from"] = None
    values.update(given)
    return argparse.Namespace(**values)


class KeyDecoding(unittest.TestCase):
    def feed(self, *chunks: str, flush: bool = True) -> list:
        decoder = install.KeyDecoder()
        found = []
        for chunk in chunks:
            found += decoder.feed(chunk)
        if flush:
            found += decoder.flush()
        return found

    def test_every_key_of_the_table(self):
        table = {
            "\x1b[A": "up", "\x1b[B": "down", "\x1b[C": "right", "\x1b[D": "left",
            "\x1bOA": "up", "\x1bOB": "down", "\x1bOC": "right", "\x1bOD": "left",
            "\x1b[5~": "pgup", "\x1b[6~": "pgdn", "\x1b[H": "home", "\x1b[F": "end",
            "\x1b[1~": "home", "\x1b[4~": "end", "\x1b[7~": "home", "\x1b[8~": "end",
            "\x1bOH": "home", "\x1bOF": "end", "\x1bOP": "f1", "\x1b[11~": "f1",
            "\x1b[1;2A": "shift-up", "\x1b[1;2B": "shift-down", "\x1b[3~": "delete",
            "\r": "enter", "\n": "enter", "\x1bOM": "enter", "\x7f": "backspace",
            "\x08": "backspace", "\t": "tab", "\x03": "ctrl-c", "\x04": "ctrl-d",
            "\x1b": "esc",
        }
        for sequence, name in table.items():
            with self.subTest(sequence=sequence):
                self.assertEqual(self.feed(sequence), [Key(name)])

    def test_text_keys(self):
        self.assertEqual(self.feed("q /?jké"), keys("char:q", "char: ", "char:/", "char:?",
                                                    "char:j", "char:k", "char:é"))

    def test_two_arrows_in_one_read_are_two_moves(self):
        self.assertEqual(self.feed("\x1b[B\x1b[B"), keys("down", "down"))

    def test_a_sequence_split_across_reads_is_one_key(self):
        for cut in range(1, 4):
            with self.subTest(cut=cut):
                sequence = "\x1b[5~"
                self.assertEqual(self.feed(sequence[:cut], sequence[cut:]), keys("pgup"))

    def test_esc_waits_for_the_rest_then_stands_alone(self):
        decoder = install.KeyDecoder()
        self.assertEqual(decoder.feed("\x1b"), [])
        self.assertTrue(decoder.waiting)
        self.assertEqual(decoder.flush(), keys("esc"))
        self.assertFalse(decoder.waiting)

    def test_esc_then_a_letter(self):
        self.assertEqual(self.feed("\x1bq"), keys("esc", "char:q"))
        self.assertEqual(self.feed("\x1b\x1b[A"), keys("esc", "up"))

    def test_unknown_sequences_are_dropped_not_typed(self):
        for sequence in ("\x1b[25~", "\x1b[1;5A", "\x1b[M !!", "\x1b[<0;10;5M", "\x1b[?1;2c",
                         "\x1bOZ"):
            with self.subTest(sequence=sequence):
                # A mouse report is a report (MouseReports), never typed.
                self.assertEqual([key for key in self.feed(sequence + "x")
                                  if key.name != "mouse"], keys("char:x"))

    def test_an_incomplete_sequence_is_dropped_at_the_timeout(self):
        self.assertEqual(self.feed("\x1b[1"), [])

    def test_a_paste_is_one_piece_without_its_newlines(self):
        self.assertEqual(self.feed("\x1b[200~/media/sd\ncard\r\n\x1b[201~"),
                         [Key("paste", "/media/sdcard")])
        self.assertEqual(self.feed("\x1b[200~/a/b\x1b[2", "01~\r"),
                         [Key("paste", "/a/b"), Key("enter")])

    def test_controls_nobody_bound_are_ignored(self):
        self.assertEqual(self.feed("\x00\x1cx"), keys("char:x"))
        # Ctrl-Z is a key once ISIG is off: the run stops on it, as on SIGTSTP.
        self.assertEqual(self.feed("\x1a"), [Key("ctrl-z")])

    def test_windows_scan_codes(self):
        for prefix in ("\x00", "\xe0"):
            for code, name in (("H", "up"), ("P", "down"), ("K", "left"), ("M", "right"),
                               ("I", "pgup"), ("Q", "pgdn"), ("G", "home"), ("O", "end"),
                               (";", "f1")):
                with self.subTest(prefix=prefix, code=code):
                    pending = iter([code])
                    self.assertEqual(install.decode_windows_key(prefix, pending.__next__),
                                     Key(name))
        unread = iter(())
        for char, name in (("\r", "enter"), ("\x1b", "esc"), ("\x08", "backspace"),
                           ("\x03", "ctrl-c"), ("\t", "tab")):
            self.assertEqual(install.decode_windows_key(char, unread.__next__), Key(name))
        self.assertEqual(install.decode_windows_key("a", unread.__next__), Key("char", "a"))
        self.assertIsNone(install.decode_windows_key("\xe0", iter(["\x86"]).__next__))

    @unittest.skipUnless(given, "the decoder fuzz needs hypothesis")
    def test_any_input_decodes_the_same_however_it_is_split(self):
        alphabet = st.sampled_from(["\x1b", "[", "O", "A", "B", "5", "~", "1", ";", "2",
                                    "200~", "201~", "\r", "x", "M", "\x03", "<", " "])

        @settings(max_examples=400, deadline=None)
        @given(st.lists(alphabet, max_size=30), st.data())
        def check(parts, data):
            text = "".join(parts)
            whole = self.feed(text)
            cuts = sorted(data.draw(st.lists(st.integers(0, len(text)), max_size=5)))
            chunks = [text[a:b] for a, b in zip([0, *cuts], [*cuts, len(text)])]
            self.assertEqual(self.feed(*chunks), whole)
            for key in whole:
                if key.name == "char":
                    self.assertNotEqual(key.text, "\x1b")

        check()


class TextWidth(unittest.TestCase):
    def test_wide_and_combining_characters(self):
        self.assertEqual(install.cell_width("PlayStation"), 11)
        self.assertEqual(install.cell_width("ファミコン"), 10)
        self.assertEqual(install.cell_width("e\u0301"), 1)

    def test_fit_never_cuts_a_character(self):
        self.assertEqual(install.fit("ファミコン", 5), "ファ")
        self.assertEqual(install.cell_width(install.fit("aファ", 2)), 1)

    def test_middle_keeps_both_ends(self):
        path = "/run/media/user/SDCARD/Bios/PS"
        cut = install.middle(path, 20)
        self.assertEqual(install.cell_width(cut), 20)
        self.assertTrue(cut.startswith("/run/med"))
        self.assertTrue(cut.endswith("Bios/PS"))
        self.assertIn("...", cut)
        self.assertEqual(install.middle("short", 20), "short")


class StartConditions(unittest.TestCase):
    class _Tty(io.StringIO):
        def __init__(self, fd: int) -> None:
            super().__init__()
            self.fd = fd

        def isatty(self) -> bool:
            return True

        def fileno(self) -> int:
            return self.fd

    def setUp(self):
        self.master, self.slave = os.openpty()
        self.addCleanup(os.close, self.master)
        self.addCleanup(os.close, self.slave)
        self.size(80, 24)
        self.tty = self._Tty(self.slave)

    def size(self, cols: int, rows: int) -> None:
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def blocker(self, env=None, **given) -> str:
        return install.tui_blocker(_args(**given), self.tty, self.tty,
                                   {"TERM": "xterm"} if env is None else env)

    def test_an_install_at_a_terminal_opens_it(self):
        self.assertEqual(self.blocker(), "")
        self.assertEqual(self.blocker(platform="retroarch", system=["x"], region=["us"]), "")

    def test_flags_that_keep_the_line_questions(self):
        for flag in ("check", "dry_run", "list_platforms", "list_targets", "list_systems",
                     "list_cores", "list_emulators", "events", "quiet", "no_input", "yes"):
            with self.subTest(flag=flag):
                self.assertIn("runs without questions", self.blocker(**{flag: True}))
        self.assertIn("--restore", self.blocker(restore=Path("x")))

    def test_dumb_or_missing_term(self):
        self.assertIn("TERM", self.blocker(env={"TERM": "dumb"}))
        self.assertIn("TERM", self.blocker(env={}))

    def test_not_a_terminal(self):
        args = _args()
        self.assertIn("input", install.tui_blocker(args, io.StringIO(), self.tty,
                                                   {"TERM": "xterm"}))
        self.assertIn("output", install.tui_blocker(args, self.tty, io.StringIO(),
                                                    {"TERM": "xterm"}))

    def test_too_small_and_unsized(self):
        self.size(39, 30)
        self.assertIn("39x30", self.blocker())
        # script(1) fed from a pipe never sizes its terminal.
        self.size(0, 0)
        self.assertIn("0x0", self.blocker())

    def test_a_windows_console_without_escape_sequences(self):
        # Legacy conhost, PowerShell ISE: no virtual terminal, the questions run.
        with mock.patch.dict(sys.modules, {"msvcrt": mock.Mock()}), \
                mock.patch.object(install.os, "name", "nt"), \
                mock.patch.object(install, "_enable_ansi", return_value=False):
            self.assertIn("escape sequences", self.blocker(env={}))
        with mock.patch.dict(sys.modules, {"msvcrt": mock.Mock()}), \
                mock.patch.object(install.os, "name", "nt"), \
                mock.patch.object(install, "_enable_ansi", return_value=True):
            self.assertEqual(self.blocker(env={}), "")

    def test_plain_mode(self):
        self.assertTrue(install.plain_requested(_args(plain=True), {}))
        self.assertTrue(install.plain_requested(_args(), {"RETROBIOS_PLAIN": "1"}))
        self.assertTrue(install.plain_requested(_args(), {"ACCESSIBLE": "1"}))
        self.assertFalse(install.plain_requested(_args(), {"ACCESSIBLE": "0",
                                                           "RETROBIOS_PLAIN": ""}))

    def test_tui_refused_with_a_reason(self):
        for extra, message in ((["--check"], "--check runs without questions"),
                               (["--plain"], "two different interfaces"),
                               ([], "not a terminal")):
            with self.subTest(extra=extra):
                proc = install_run("--tui", *extra)
                self.assertEqual(proc.returncode, 2)
                self.assertIn(message, proc.stderr)
                self.assertNotIn("\x1b", proc.stdout + proc.stderr)


def install_run(*options: str, env: dict | None = None):
    import subprocess

    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "install.py"), *options], capture_output=True,
        text=True, timeout=60, check=False, stdin=subprocess.DEVNULL,
        env={**os.environ, **(env or {})},
    )


# A repository-like state, as the events of a check fill it.
MANIFEST = {
    "manifest_version": 2, "platform": "retroarch", "categorized": True,
    "system_cores": {"sony-playstation": ["pcsx_rearmed"]},
    "files": [
        {"dest": "scph5500.bin", "size": 524288, "systems": ["sony-playstation"],
         "regions": ["japan"], "cores": None},
        {"dest": "scph5501.bin", "size": 524288, "systems": ["sony-playstation"],
         "regions": ["north-america"], "cores": None},
        {"dest": "gba_bios.bin", "size": 16384, "systems": ["nintendo-gba"], "cores": None},
        {"dest": "pcsx/extra.bin", "size": 4, "systems": ["sony-playstation"],
         "cores": ["pcsx_rearmed"]},
        {"dest": "fc/disksys.rom", "size": 8192, "systems": ["nintendo-famicom-disk"],
         "cores": ["mesen"]},
    ],
}
SYSTEMS = [
    {"event": "system", "platform": "retroarch", "system": "nintendo-famicom-disk",
     "name": "ファミコン", "files": 1, "present": 1, "missing": 0, "wrong_hash": 0,
     "bytes_needed": 0},
    {"event": "system", "platform": "retroarch", "system": "nintendo-gba",
     "name": "gba", "files": 1, "present": 0, "missing": 1, "wrong_hash": 0,
     "bytes_needed": 16384},
    {"event": "system", "platform": "retroarch", "system": "sony-playstation",
     "name": "sony-playstation", "files": 3, "present": 0, "missing": 2, "wrong_hash": 1,
     "bytes_needed": 1048580},
]
CHECK = {"event": "check", "platform": "retroarch", "name": "RetroArch",
         "bios_dir": "/home/user/.config/retroarch/system", "files": 5, "present": 1,
         "missing": 3, "wrong_hash": 1, "bytes_needed": 1064964, "data_missing": 0,
         "not_installable": 2}
FILES = [
    {"event": "file", "platform": "retroarch", "dest": "scph5500.bin",
     "systems": ["sony-playstation"], "size": 524288, "state": "missing"},
    {"event": "file", "platform": "retroarch", "dest": "scph5501.bin",
     "systems": ["sony-playstation"], "size": 524288, "state": "wrong_hash"},
    {"event": "file", "platform": "retroarch", "dest": "pcsx/extra.bin",
     "systems": ["sony-playstation"], "size": 4, "state": "missing"},
    {"event": "file", "platform": "retroarch", "dest": "gba_bios.bin",
     "systems": ["nintendo-gba"], "size": 16384, "state": "missing"},
]
HOME = Path("/home/user")
SYSTEM_DIR = HOME / ".config" / "retroarch" / "system"


def screen_text(lines) -> str:
    """The screen as one line of words, a path broken after a separator
    joined again: a folder under the checkout is as long as the checkout's
    own path, and a deep clone wrapped it across two lines."""
    return re.sub(r"(?<=[/\\]) ", "", " ".join(" ".join(lines).split()))


def fresh_state() -> install.TuiState:
    state = install.TuiState(os_type="linux", home=HOME)
    state.setups = [("retroarch", SYSTEM_DIR, "RetroArch"),
                    ("batocera", Path("/userdata/bios"), "KNULLI (Batocera files)")]
    return state


GAMES = {"event": "games", "platform": "retroarch", "folder": "/media/user/SDCARD/Roms",
         "games": 412, "recognised": 398,
         "found": [{"system": "sony-playstation", "folder": "PS", "games": 400,
                      "recognised": 390, "regions": []},
                     {"system": "nintendo-gba", "folder": "GBA", "games": 12,
                      "recognised": 8, "regions": ["europe"]}],
         "fallback": [{"system": "nintendo-gba", "folder": "GBA", "name": "GBA/demo.gba",
                       "reason": "not_recognised"},
                      {"system": "nintendo-gba", "folder": "GBA", "name": "GBA/hack.gba",
                       "reason": "not_recognised"}],
         "not_games": 3, "required_only": False}


def games_state() -> install.TuiState:
    """The plan of a card whose games the check read (--for-games)."""
    state = fresh_state()
    state.stack = ["setup"]
    with mock.patch.object(install.Path, "exists", return_value=True):
        install.tui_update(state, Key("enter"))
    install.tui_receive(state, ("games_here", "retroarch", SYSTEM_DIR, 2))
    effects = install.tui_receive(state, ("manifest", "retroarch", MANIFEST))
    assert effects == [("run", "check")], effects
    for event in [GAMES, *FILES, *SYSTEMS, CHECK]:
        install.tui_receive(state, ("event", state.run_id, event))
    with mock.patch.object(install, "_tui_folder_facts", return_value={
            "free": 50 * 1024 ** 3, "writable": True, "cores": ["pcsx_rearmed"]}):
        install.tui_receive(state, ("ended", state.run_id, 1, []))
    return state


def checked_state(facts: dict | None = None) -> install.TuiState:
    """The plan screen of a RetroArch folder with files missing."""
    state = fresh_state()
    state.stack = ["setup"]
    with mock.patch.object(install.Path, "exists", return_value=True):
        effects = install.tui_update(state, Key("enter"))
    assert effects == [("fetch", "retroarch")], effects
    effects = install.tui_receive(state, ("manifest", "retroarch", MANIFEST))
    assert effects == [("run", "check")], effects
    for event in [*FILES, *SYSTEMS, CHECK]:
        install.tui_receive(state, ("event", state.run_id, event))
    with mock.patch.object(install, "_tui_folder_facts", return_value=facts or {
            "free": 50 * 1024 ** 3, "writable": True, "cores": ["pcsx_rearmed"]}):
        install.tui_receive(state, ("ended", state.run_id, 1, []))
    return state


class HoldingPack:
    """A pack given to the run that holds every file asked of it."""

    name = "RetroArch_BIOS_Pack.zip"

    @staticmethod
    def find(entry: dict) -> tuple:
        return (None, entry)


def press(state: install.TuiState, *pressed) -> list:
    effects = []
    for key in pressed:
        effects += install.tui_update(state, Key("char", key) if isinstance(key, str)
                                      and len(key) == 1 else Key(key))
    return effects


class Flow(unittest.TestCase):
    """update() on keys and events: what each choice starts and passes on."""

    def test_three_presses_install_everything(self):
        state = checked_state()
        self.assertEqual(state.screen, "plan")
        self.assertEqual(press(state, "enter"), [("run", "install")])
        self.assertEqual(state.screen, "installing")
        argv = install.tui_argv(state, "install", "py", "install.py")
        self.assertEqual(argv, ["py", "install.py", "--platform=retroarch",
                                f"--dest={SYSTEM_DIR}", "--events", "--yes"])
        for event in ({"event": "download", "platform": "retroarch", "files": 4,
                       "bytes": 1064964},
                      {"event": "downloaded", "dest": "gba_bios.bin", "ok": True, "reason": "",
                       "size": 16384, "files_done": 1, "files_total": 4,
                       "bytes_done": 16384, "bytes_total": 1064964},
                      {"event": "summary", "mode": "install", "installed": 4, "up_to_date": 1,
                       "pending": 0, "failed": [], "skipped": [], "left_out": [],
                       "kept": [], "interrupted": False}):
            install.tui_receive(state, ("event", state.run_id, event))
        install.tui_receive(state, ("ended", state.run_id, 0, []))
        self.assertEqual(state.screen, "result")
        press(state, "enter")
        self.assertEqual(state.exit_code, 0)

    def test_every_run_reads_the_folders_given_with_from(self):
        """--tui --from OLD: the check and the install both copy from OLD,
        each folder named once."""
        args = _args(**{"from": [Path("old-card"), Path("backup.zip")],
                        "from_pack": [Path("pack.zip")]})
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            started, _effects = install.tui_start(args, "linux")
        state = checked_state()
        state.passthrough = started.passthrough
        state.from_folders = started.from_folders
        for run in ("check", "install"):
            argv = install.tui_argv(state, run, "py", "i.py")
            for folder in ("old-card", "backup.zip"):
                self.assertEqual(argv.count(f"--from={Path(folder).absolute()}"), 1, argv)
            self.assertIn(f"--from-pack={Path('pack.zip').absolute()}", argv)

    def test_the_check_runs_with_the_command_line_choices(self):
        state = fresh_state()
        state.passthrough = [("--target", "switch")]
        state.cli_systems = ["psx"]
        state.regions = ["north-america"]
        state.platform, state.dest = "retroarch", SYSTEM_DIR
        state.manifest, state.manifest_for = MANIFEST, "retroarch"
        self.assertEqual(install._start_check(state), [("run", "check")])
        self.assertEqual(install.tui_argv(state, "check", "py", "i.py")[4:], [
            "--target=switch", "--system=psx", "--region=north-america",
            "--check", "--events"])

    def test_one_system_goes_through_the_dry_run(self):
        state = checked_state()
        press(state, "down", "enter")
        self.assertEqual(state.screen, "systems")
        self.assertEqual(state.ticked, {"nintendo-gba", "sony-playstation"})
        self.assertEqual(install.tui_rows(state)[state.focus["systems"]].action, "system")
        press(state, "n")
        self.assertEqual(state.ticked, set())
        focus = next(i for i, row in enumerate(install.tui_rows(state))
                     if row.value == "nintendo-gba")
        state.focus["systems"] = focus
        # A ticks the system in focus, B goes back to the plan, and Install
        # there counts the choice first.
        self.assertEqual(press(state, "enter", "esc"), [])
        self.assertEqual(state.ticked, {"nintendo-gba"})
        self.assertEqual(state.screen, "plan")
        self.assertEqual(press(state, "enter"), [("run", "confirm")])
        self.assertEqual(state.screen, "confirm")
        self.assertIn("--system=nintendo-gba", install.tui_argv(state, "confirm", "py", "i.py"))
        self.assertIn("--dry-run", install.tui_argv(state, "confirm", "py", "i.py"))
        dry = {**CHECK, "files": 1, "present": 0, "missing": 1, "wrong_hash": 0,
               "bytes_needed": 16384}
        install.tui_receive(state, ("event", state.run_id, dry))
        install.tui_receive(state, ("ended", state.run_id, 0, []))
        self.assertEqual(state.screen, "confirm")
        self.assertEqual(press(state, "enter"), [("run", "install")])
        argv = install.tui_argv(state, "install", "py", "i.py")
        self.assertEqual(argv[4:], ["--system=nintendo-gba", "--events", "--yes"])

    def test_a_choice_that_changes_nothing_skips_the_confirmation(self):
        state = checked_state()
        state.jobs = 4
        self.assertEqual(press(state, "enter"), [("run", "confirm")])
        install.tui_receive(state, ("event", state.run_id, dict(CHECK)))
        effects = install.tui_receive(state, ("ended", state.run_id, 0, []))
        self.assertEqual(effects, [("run", "install")])
        self.assertEqual(state.screen, "installing")

    def test_options_set_the_flags_they_name(self):
        state = checked_state()
        press(state, "o")
        self.assertEqual(state.screen, "options")
        rows = install.tui_rows(state)
        self.assertEqual([row.right for row in rows], [
            "--region", "--no-game-data", "--installed-cores", "--core", "--jobs", "--dest",
            "--from", "--dry-run", ""])
        press(state, "enter")
        self.assertEqual(state.screen, "regions")
        # Ticked in the order of preference, then moved up.
        regions = [row.value for row in install.tui_rows(state) if row.action == "region"]
        self.assertEqual(regions, ["japan", "north-america"])
        press(state, "enter", "down", "enter")
        self.assertEqual(state.regions, ["japan", "north-america"])
        press(state, "left")
        self.assertEqual(state.regions, ["north-america", "japan"])
        # The rank moves, the row stays where it is, under the focus.
        self.assertEqual(state.focus["regions"], 1)
        self.assertEqual([row.label for row in install.tui_rows(state)],
                         ["[2] Japan", "[1] North America", "None", "Done"])
        press(state, "shift-down")
        self.assertEqual(state.regions, ["japan", "north-america"])
        press(state, "esc", "down", "enter", "down", "right", "down", "down", "right", "right")
        self.assertTrue(state.no_game_data)
        self.assertTrue(state.installed_only)
        self.assertEqual(state.jobs, 10)
        argv = install.tui_argv(state, "install", "py", "i.py")
        self.assertEqual(argv[4:], ["--region=japan,north-america", "--no-game-data",
                                    "--installed-cores", "--jobs=10", "--events", "--yes"])
        self.assertIn("--region japan,north-america --no-game-data", install.tui_command(state))

    def test_cores_checklist(self):
        state = checked_state()
        press(state, "o")
        state.focus["options"] = 3
        press(state, "enter")
        self.assertEqual(state.screen, "cores")
        self.assertEqual([row.value for row in install.tui_rows(state)
                          if row.action == "core"], ["mesen", "pcsx_rearmed"])
        self.assertEqual(install.tui_rows(state)[state.focus["cores"]].value, "mesen")
        # Every core ticked while none narrows the run: one untick keeps
        # the others, ticked back it is every core again.
        press(state, " ")
        self.assertEqual(state.cores, ["pcsx_rearmed"])
        press(state, "right")
        self.assertEqual(state.cores, [])
        press(state, "/", "p", "c")
        self.assertEqual([row.value for row in install.tui_rows(state)
                          if row.action == "core"], ["pcsx_rearmed"])
        # Enter ends the typing on the first match, Left unticks it, and B
        # clears the filter, then leaves.
        press(state, "enter", "left", "esc", "esc")
        self.assertEqual(state.screen, "options")
        self.assertEqual(install.tui_flags(state), [("--core", "mesen")])

    def test_preview_is_a_dry_run(self):
        state = checked_state()
        press(state, "o")
        state.focus["options"] = 7
        self.assertEqual(press(state, "enter"), [("run", "preview")])
        self.assertEqual(install.tui_argv(state, "preview", "py", "i.py")[-2:],
                         ["--dry-run", "--events"])
        for event in [*FILES, CHECK]:
            install.tui_receive(state, ("event", state.run_id, event))
        install.tui_receive(state, ("ended", state.run_id, 0, []))
        text = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn("4 files to download, 1.0 MB. Nothing is written.", text)
        self.assertIn("wrong copy", text)
        press(state, "esc")
        self.assertEqual(state.screen, "options")

    def test_back_and_quit(self):
        state = fresh_state()
        press(state, "esc")
        self.assertEqual(state.screen, "quit")
        press(state, "esc")
        self.assertEqual(state.screen, "setup")
        press(state, "esc", "enter")
        self.assertEqual(state.exit_code, install.QUIT_CODE)
        state = checked_state()
        self.assertEqual(press(state, "q"), [])
        self.assertEqual(state.exit_code, install.QUIT_CODE)

    def test_ctrl_c_stops_an_install_once_then_kills(self):
        state = checked_state()
        press(state, "enter")
        self.assertEqual(press(state, "ctrl-c"), [("stop",)])
        self.assertTrue(state.stopping)
        self.assertEqual(press(state, "ctrl-c"), [("kill",)])
        summary = {"event": "summary", "mode": "install", "installed": 1, "up_to_date": 1,
                   "pending": 3, "failed": [], "skipped": [], "left_out": [], "kept": [],
                   "interrupted": True}
        install.tui_receive(state, ("event", state.run_id,
                                    {"event": "download", "platform": "retroarch",
                                     "files": 4, "bytes": 1064964}))
        install.tui_receive(state, ("event", state.run_id, summary))
        install.tui_receive(state, ("ended", state.run_id, 130, []))
        title, lines = install.tui_outcome(state)
        self.assertEqual(title, "Stopped")
        self.assertEqual(lines[0], "Stopped: 1 of 4 installed, run again to finish.")
        press(state, "enter")
        self.assertEqual(state.exit_code, 130)

    def test_back_from_the_check_stops_it(self):
        state = fresh_state()
        with mock.patch.object(install.Path, "exists", return_value=True):
            press(state, "enter")
        install.tui_receive(state, ("manifest", "retroarch", MANIFEST))
        self.assertTrue(state.running)
        self.assertEqual(press(state, "esc"), [("kill",)])
        self.assertEqual(state.screen, "setup")
        install.tui_receive(state, ("ended", state.run_id - 1, 1, []))
        self.assertEqual(state.screen, "setup")

    def test_ctrl_c_elsewhere_ends_at_once(self):
        state = fresh_state()
        self.assertEqual(press(state, "ctrl-c"), [])
        self.assertEqual(state.exit_code, 130)
        state = checked_state()
        state.running = True
        self.assertEqual(press(state, "ctrl-d"), [("kill",)])

    def test_the_folder_path(self):
        state = fresh_state()
        press(state, "down", "down", "enter")
        self.assertEqual(state.screen, "platforms")
        self.assertEqual(install.tui_rows(state)[state.focus["platforms"]].value, "retroarch")
        press(state, "/", "b", "a", "t", "o")
        self.assertEqual([row.value for row in install.tui_rows(state)][1:], ["batocera"])
        # the one match is chosen with the first Enter.
        press(state, "enter")
        self.assertEqual(state.screen, "folder")
        self.assertEqual(state.platform, "batocera")
        state.focus["folder"] = 2
        press(state, "enter")
        self.assertEqual(state.screen, "path")
        state.path_text = ""
        press(state, "paste")
        install.tui_update(state, Key("paste", '"~/my bios"'))
        with mock.patch.object(install.Path, "exists", return_value=False), \
                mock.patch.object(install, "_nearest_folder", return_value=HOME):
            press(state, "enter")
        self.assertEqual(state.screen, "create")
        self.assertEqual(state.dest, Path(os.path.expanduser("~/my bios")))
        press(state, "down", "enter")
        self.assertEqual(state.screen, "folder")

    def test_typed_paths(self):
        with mock.patch.dict(os.environ, {"CARD": "/media/sd"}):
            self.assertEqual(install.typed_path(' "$CARD/Bios" '), Path("/media/sd/Bios"))
        self.assertEqual(install.typed_path("'C:\\RetroBat\\bios'"), Path("C:\\RetroBat\\bios"))
        self.assertIsNone(install.typed_path('""'))

    def test_the_browser_lists_folders_and_goes_up(self):
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        for name in ("system", ".config", "Bios"):
            (root / name).mkdir()
        (root / "file.bin").write_bytes(b"")
        state = fresh_state()
        state.platform = "retroarch"
        state.stack = ["folder"]
        state.folder_default = root / "system"
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            press(state, "down", "enter")
            self.assertEqual(state.screen, "browse")
            self.assertEqual(state.browse_dir, root / "system")
            self.assertEqual([row.label for row in install.tui_rows(state)],
                             ["Use this folder", ".."])
            press(state, "down", "enter")
            self.assertEqual(state.browse_dir, root)
            labels = [row.label for row in install.tui_rows(state)]
            self.assertEqual(labels, ["Use this folder", "..", "Bios/", "system/", ".config/"])
            self.assertEqual(install.tui_rows(state)[state.focus["browse"]].label, "system/")
            effects = press(state, "home", "enter")
        self.assertEqual(effects, [("fetch", "retroarch")])
        self.assertEqual(state.dest, root)

    def test_a_holds_no_bios_folder_root_never_takes_a(self):
        """With no usual folder the browser opens at HOME, on Use this
        folder: A five times installed the BIOS files into ~. At HOME or a
        drive's root, A goes into the first folder instead."""
        home = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, home, True)
        (home / "Games").mkdir()
        state = install.TuiState(os_type="linux", home=home)
        state.platform = "retroarch"
        state.stack = ["folder"]
        state.folder_default = None
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            install._browse_to(state, home)
            self.assertEqual(state.browse_rows[state.focus["browse"]].label, "Games/")
            install._browse_to(state, home / "Games")
            self.assertEqual(state.browse_rows[state.focus["browse"]].label,
                             "Use this folder")
            install._browse_to(state, Path(home.anchor))
            self.assertNotEqual(state.browse_rows[state.focus["browse"]].action, "use")

    def test_cards_are_listed_first(self):
        card = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, card, True)
        (card / ".system").mkdir()
        (card / ".system" / "version.txt").write_text("NextUI-20250101\n")
        with mock.patch.object(install, "_mounted_cards", return_value=[card]):
            rows, error = install._browse_rows(REPO_ROOT / "tests")
        self.assertEqual(error, "")
        self.assertEqual(rows[2].label, f"{card} (NextUI card)")

    def test_a_mounted_card_is_a_setup_of_its_own(self):
        card = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, card, True)
        (card / ".system").mkdir()
        (card / ".system" / "version.txt").write_text("MinUI-20250101\n")
        with mock.patch.object(install, "_mounted_cards", return_value=[card]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, effects = install.tui_start(_args(), "linux")
        self.assertEqual((state.screen, effects), ("setup", []))
        label = f"MinUI SD card ({card.name})"
        self.assertEqual(state.setups, [("minui", card, label)])
        self.assertEqual([row.label for row in install.tui_rows(state)],
                         [label, "Another setup or folder"])

    def test_an_error_offers_another_try(self):
        state = fresh_state()
        with mock.patch.object(install.Path, "exists", return_value=True):
            press(state, "enter")
        install.tui_receive(state, ("manifest_failed", "retroarch", "No connection",
                                    ["  Could not fetch the file list for retroarch", ""], 1))
        self.assertIn("RetroBIOS: No connection", install.tui_view(state, 80, 24)[0])
        self.assertEqual(state.screen, "error")
        self.assertEqual([row.action for row in install.tui_rows(state)],
                         ["retry", "elsewhere", "quit"])
        self.assertEqual(press(state, "enter"), [("fetch", "retroarch")])
        install.tui_receive(state, ("manifest_failed", "retroarch", "No connection", ["no"], 1))
        press(state, "down", "down", "enter")
        self.assertEqual(state.exit_code, 1)

    def test_a_check_that_writes_no_check_event_is_an_error(self):
        state = fresh_state()
        state.platform, state.dest = "retroarch", SYSTEM_DIR
        state.manifest, state.manifest_for = MANIFEST, "retroarch"
        install._start_check(state)
        install.tui_receive(state, ("ended", state.run_id, 1,
                                    ["Error: /x is inside a NextUI card."]))
        self.assertEqual(state.screen, "error")
        self.assertEqual(state.error, ["Error: /x is inside a NextUI card."])

    def test_events_of_an_abandoned_run_are_ignored(self):
        state = checked_state()
        press(state, "o")
        state.focus["options"] = 7
        press(state, "enter")
        old = state.run_id
        self.assertEqual(press(state, "esc"), [("kill",)])
        install.tui_receive(state, ("event", old, dict(CHECK)))
        install.tui_receive(state, ("ended", old, 0, []))
        self.assertIsNone(state.dry)
        self.assertEqual(state.screen, "options")

    def test_help_and_a_small_window(self):
        state = fresh_state()
        press(state, "?")
        self.assertTrue(state.help)
        self.assertIn("Any key closes", install.tui_view(state, 80, 24)[-1])
        press(state, "down")
        self.assertFalse(state.help)
        self.assertEqual(state.focus.get("setup", 0), 0)
        state.cols, state.rows = 30, 10
        press(state, "enter")
        self.assertEqual(state.screen, "setup")
        lines = install.tui_view(state, 30, 10)
        self.assertEqual([line.strip() for line in lines if line.strip()],
                         ["Make the window larger:", "40x12 or more, now 30x10"])
        self.assertEqual(len(install.tui_view(state, 39, 1)), 1)
        self.assertEqual(install.tui_view(state, 30, 0), [])


class PlanWarnings(unittest.TestCase):
    def test_a_folder_that_cannot_take_the_files_says_so_first(self):
        state = checked_state({"free": 1024, "writable": False, "cores": []})
        text = " ".join(install.tui_view(state, 120, 40))
        self.assertIn("Not enough free space: 1.0 MB needed.", text)
        self.assertIn("This folder cannot be written to: choose another one.", text)
        # sudo changes the home folder: the advice names this one.
        self.assertIn("Or run it as root, this folder named: sudo python3 install.py "
                      f"--platform retroarch --dest {SYSTEM_DIR}",
                      " ".join(text.replace(" \\", "").split()))
        rows = install.tui_rows(state)
        self.assertEqual([row.action for row in rows[:2]], ["folder", "install"])
        self.assertEqual(state.focus.get("plan", 0), 0)
        self.assertEqual(press(state, "enter"), [])
        self.assertEqual(state.screen, "folder")
        self.assertNotIn("--installed-cores", [row.right for row in install._option_rows(state)])


class Widgets(unittest.TestCase):
    def systems_state(self, count: int) -> install.TuiState:
        state = checked_state()
        state.systems = [{"event": "system", "system": f"system-{n:03d}", "name": f"s{n}",
                          "files": 1, "present": 0, "missing": 1, "wrong_hash": 0,
                          "bytes_needed": 10} for n in range(count)]
        state.ticked = {row["system"] for row in state.systems}
        state.stack.append("systems")
        return state

    def test_a_long_list_scrolls_and_says_where(self):
        state = self.systems_state(112)
        press(state, "end")
        lines = install.tui_view(state, 40, 15)
        self.assertIn("> Done", "\n".join(lines))
        self.assertIn("[x] system-111", "\n".join(lines))
        # The Filter, All, None and Done rows are not counted among the systems.
        self.assertTrue(any(re.fullmatch(r" \d+-112 of 112", line) for line in lines), lines)
        press(state, "pgup")
        self.assertLess(state.focus["systems"], 114)
        press(state, "home")
        self.assertEqual(state.focus["systems"], 0)

    def test_up_wraps_only_in_short_menus(self):
        state = fresh_state()
        press(state, "up")
        self.assertEqual(state.focus["setup"], 2)
        state = fresh_state()
        state.stack = ["setup", "platforms"]
        press(state, "up")
        self.assertEqual(state.focus["platforms"], 0)
        # A list of ticks wraps at any length: None and Done, at its end,
        # are a few presses up from its first item.
        state = self.systems_state(20)
        state.focus["systems"] = 0
        press(state, "up")
        self.assertEqual(install.tui_rows(state)[state.focus["systems"]].action, "done")

    def test_filter_ignores_case_and_accents(self):
        state = self.systems_state(3)
        state.systems.append({"system": "sega-genesis", "name": "Mégadrive", "files": 1,
                              "present": 0, "missing": 1, "wrong_hash": 0,
                              "bytes_needed": 3})
        press(state, "/", "M", "E", "G")
        self.assertEqual([row.value for row in install.tui_rows(state)
                          if row.action == "system"], ["sega-genesis"])
        press(state, "esc")
        self.assertEqual(state.filters["systems"], "")
        self.assertEqual(state.screen, "systems")
        press(state, "/", "z", "z", "enter")
        self.assertIn("No system matches 'zz'.", "\n".join(install.tui_view(state, 80, 24)))
        # Esc clears a kept filter first, and goes back only then.
        press(state, "esc")
        self.assertEqual((state.screen, state.filters["systems"]), ("systems", ""))
        press(state, "esc")
        self.assertEqual(state.screen, "plan")

    def test_all_and_none(self):
        state = self.systems_state(5)
        press(state, "n")
        self.assertEqual(state.ticked, set())
        press(state, "a")
        self.assertEqual(len(state.ticked), 5)
        state.focus["systems"] = next(i for i, row in enumerate(install.tui_rows(state))
                                      if row.action == "none")
        # X on None does nothing: only A, an explicit choice, unticks all.
        press(state, " ")
        self.assertEqual(len(state.ticked), 5)
        press(state, "enter")
        self.assertEqual(state.ticked, set())

    def test_running_total_counts_each_file_once(self):
        state = checked_state()
        state.stack.append("systems")
        state.files.append({"event": "file", "dest": "shared.bin", "size": 1024 * 1024,
                            "systems": ["nintendo-gba", "sony-playstation"],
                            "state": "missing"})
        footer = install.tui_view(state, 80, 24)[-2]
        self.assertEqual(footer.strip(), "2 of 3 systems: 5 files, 2.0 MB")
        state.ticked = {"nintendo-gba"}
        footer = install.tui_view(state, 80, 24)[-2]
        self.assertEqual(footer.strip(), "1 of 3 systems: 2 files, 1.0 MB")


def golden_states() -> dict:
    """One state per screen, filled as a run fills it."""
    states = {}
    states["setup"] = fresh_state()
    states["setup"].notes = ["ES-DE found: its BIOS files go to each emulator, not to "
                             "ES-DE itself."]
    platforms = fresh_state()
    platforms.stack = ["setup", "platforms"]
    platforms.focus["platforms"] = 1
    states["platforms"] = platforms
    folder = fresh_state()
    folder.platform, folder.stack = "retroarch", ["platforms", "folder"]
    folder.folder_default = SYSTEM_DIR
    states["folder"] = folder
    card = fresh_state()
    card.platform, card.stack = "nextui", ["platforms", "folder"]
    states["folder-card"] = card
    browse = fresh_state()
    browse.platform, browse.stack = "retroarch", ["folder", "browse"]
    browse.browse_dir = HOME / ".config" / "retroarch"
    browse.browse_rows = [
        install.TuiRow("use", "Use this folder"), install.TuiRow("up", "..", value=HOME),
        install.TuiRow("dir", "/media/user/SDCARD (NextUI card)",
                       value=Path("/media/user/SDCARD")),
        install.TuiRow("dir", "cores/", value=HOME / "cores"),
        install.TuiRow("dir", "system/", value=SYSTEM_DIR)]
    states["browse"] = browse
    path = fresh_state()
    path.platform, path.stack, path.path_text = "retroarch", ["folder", "path"], "~/bios"
    states["path"] = path
    create = fresh_state()
    create.platform, create.dest, create.stack = "retroarch", HOME / "bios" / "new", ["create"]
    create.facts = {"nearest": HOME}
    states["create"] = create
    checking = fresh_state()
    checking.platform, checking.dest, checking.stack = "retroarch", SYSTEM_DIR, ["checking"]
    checking.manifest, checking.started, checking.now = MANIFEST, 10.0, 14.2
    states["checking"] = checking
    states["plan"] = checked_state()
    done = checked_state()
    done.check = {**CHECK, "present": 5, "missing": 0, "wrong_hash": 0, "bytes_needed": 0,
                  "not_installable": 0}
    states["plan-in-place"] = done
    systems = checked_state()
    systems.stack.append("systems")
    systems.focus["systems"] = 3
    states["systems"] = systems
    options = checked_state()
    options.stack.append("options")
    options.regions = ["north-america", "japan"]
    states["options"] = options
    regions = checked_state()
    regions.stack += ["options", "regions"]
    regions.regions = ["north-america"]
    states["regions"] = regions
    cores = checked_state()
    cores.stack += ["options", "cores"]
    cores.cores = ["pcsx_rearmed"]
    states["cores"] = cores
    preview = checked_state()
    preview.stack += ["options", "preview"]
    preview.dry, preview.dry_files = dict(CHECK), list(FILES)
    states["preview"] = preview
    command = checked_state()
    command.stack += ["options", "command"]
    command.ticked = {"nintendo-gba"}
    states["command"] = command
    confirm = checked_state()
    confirm.stack.append("confirm")
    confirm.ticked = {"nintendo-gba"}
    confirm.dry = {**CHECK, "files": 1, "present": 0, "missing": 1, "wrong_hash": 0,
                   "bytes_needed": 16384, "not_installable": 0}
    states["confirm"] = confirm
    installing = checked_state()
    installing.stack.append("installing")
    installing.run, installing.running = "install", True
    installing.download = {"event": "download", "files": 4, "bytes": 1064964}
    installing.samples, installing.now = [(100.0, 12672), (104.0, 540672)], 104.0
    installing.network = 540672
    installing.progress = {"files_done": 2, "files_total": 4, "bytes_done": 540672,
                           "bytes_total": 1064964}
    installing.finished = [("gba_bios.bin", True, ""), ("scph5500.bin", False, "HTTP 404")]
    states["installing"] = installing
    states["result"] = golden_states_result()
    error = fresh_state()
    error.stack, error.run = ["setup", "error"], "check"
    error.error = ["  Could not fetch the file list for retroarch after 3 attempts: "
                   "[Errno -2] Name or service not known",
                   "  Address: https://raw.githubusercontent.com/Abdess/retrobios/main/"
                   "install/retroarch.json"]
    states["error"] = error
    quitting = fresh_state()
    quitting.stack = ["setup", "quit"]
    states["quit"] = quitting
    helped = checked_state()
    helped.help = True
    states["help"] = helped
    states["plan-games"] = games_state()
    listed = games_state()
    listed.stack.append("games")
    states["games"] = listed
    # What the plan and the result leave out by default, one press away.
    details = checked_state()
    details.stack.append("details")
    states["plan-details"] = details
    told = golden_states_result()
    told.stack.append("details")
    states["result-details"] = told
    return states


def golden_states_result() -> install.TuiState:
    """The result golden_states draws, a file failed and one kept."""
    result = checked_state()
    result.stack.append("result")
    result.code = 1
    result.log = "/tmp/retrobios-x/install.log"
    result.download = {"event": "download", "files": 4, "bytes": 1064964}
    result.summary = {
        "event": "summary", "mode": "install", "installed": 3, "up_to_date": 1, "pending": 1,
        "failed": [{"dest": "scph5500.bin", "reason": "HTTP 404"}],
        "skipped": [{"reason": "not_found", "label": "not found", "files": 2, "required": 1}],
        "left_out": [], "kept": [{"folder": str(HOME / ".config/retroarch/retrobios-backup/"
                                               "2026-10-23_1200"), "files": 1, "bytes": 4}],
        "interrupted": False}
    return result


def result_states() -> dict:
    """The result of a run that installed everything, of one with a file
    failed, of one --offline left files out of, and of one stopped."""
    def ended(code: int, **summary) -> install.TuiState:
        state = checked_state()
        state.stack.append("result")
        state.code = code
        state.download = {"event": "download", "files": 4, "bytes": 1064964}
        state.summary = {"event": "summary", "mode": "install", "installed": 4,
                         "up_to_date": 1, "pending": 0, "failed": [], "skipped": [],
                         "left_out": [], "kept": [], "interrupted": False, **summary}
        return state

    return {
        "done": ended(0),
        "partial": golden_states()["result"],
        "offline": ended(1, installed=1, pending=3, failed=[
            {"dest": name, "reason": install.OFFLINE_WORDS}
            for name in ("scph5500.bin", "scph5501.bin", "pcsx/extra.bin")]),
        "stopped": ended(130, installed=2, interrupted=True),
    }


class Views(unittest.TestCase):
    """Every screen as text, at the sizes a handheld and a desktop show."""

    def setUp(self):
        # The card screen lists the cards mounted here: none, on every machine.
        patcher = mock.patch.object(install, "_mounted_cards", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_goldens(self):
        update = os.environ.get("RETROBIOS_UPDATE_GOLDENS") == "1"
        GOLDEN.mkdir(parents=True, exist_ok=True)
        for name, state in golden_states().items():
            for cols, rows in SIZES:
                with self.subTest(screen=name, size=f"{cols}x{rows}"):
                    state.cols, state.rows = cols, rows
                    lines = install.tui_view(state, cols, rows)
                    self.assertEqual(len(lines), rows)
                    for line in lines:
                        # A path or a command kept whole folds in the terminal.
                        if line.style != "long":
                            self.assertLessEqual(install.cell_width(line), cols, line)
                        self.assertTrue(all(ord(c) < 128 or c in "ファミコン" for c in line),
                                        line)
                    self.assertLess(install.cell_width(lines[-1]), cols)
                    text = "\n".join(line.rstrip() for line in lines) + "\n"
                    path = GOLDEN / f"{name}-{cols}x{rows}.txt"
                    if update:
                        path.write_text(text, encoding="utf-8")
                    self.assertEqual(text, path.read_text(encoding="utf-8"))

    def test_goldens_per_route(self):
        """Each input route at the handheld sizes and 80x24, kept only where a
        screen reads differently from the both-names form."""
        update = os.environ.get("RETROBIOS_UPDATE_GOLDENS") == "1"
        for route in ROUTES:
            sections = []
            for name, state in golden_states().items():
                state.pad = route
                for cols, rows in SIZES[:3]:
                    with self.subTest(route=route, screen=name, size=f"{cols}x{rows}"):
                        state.cols, state.rows = cols, rows
                        lines = install.tui_view(state, cols, rows)
                        for line in lines:
                            if line.style != "long":
                                self.assertLessEqual(install.cell_width(line), cols, line)
                        self.assertLess(install.cell_width(lines[-1]), cols)
                    text = "\n".join(line.rstrip() for line in lines) + "\n"
                    both = (GOLDEN / f"{name}-{cols}x{rows}.txt").read_text(encoding="utf-8")
                    if text != both:
                        sections.append(f"=== {name} {cols}x{rows}\n{text}")
            path = GOLDEN / f"route-{route}.txt"
            if update:
                path.write_text("".join(sections), encoding="utf-8")
            with self.subTest(route=route):
                self.assertEqual("".join(sections), path.read_text(encoding="utf-8"))

    def test_colour_goldens(self):
        """Every screen as the terminal gets it with colour, the escape
        codes kept (ESC written ^[), one file per size."""
        update = os.environ.get("RETROBIOS_UPDATE_GOLDENS") == "1"
        for cols, rows in SIZES:
            sections = []
            for name, state in golden_states().items():
                state.cols, state.rows = cols, rows
                painted = [install.tui_paint(str(line), line.style, True)
                           for line in install.tui_view(state, cols, rows)]
                sections.append(f"=== {name}\n" + "\n".join(painted).replace("\x1b", "^[")
                                + "\n")
            path = GOLDEN / f"colour-{cols}x{rows}.txt"
            if update:
                path.write_text("".join(sections), encoding="utf-8")
            with self.subTest(size=f"{cols}x{rows}"):
                self.assertEqual("".join(sections), path.read_text(encoding="utf-8"))

    def test_colour_adds_codes_and_never_text(self):
        """With colour off a line is drawn as before, its style alone, and
        with colour on, stripped of its codes, it is the same text: the
        golden screen, character for character."""
        for cols, rows in SIZES:
            colour = (GOLDEN / f"colour-{cols}x{rows}.txt").read_text(encoding="utf-8")
            screens = dict(re.findall(r"=== (\S+)\n(.*?)(?=\n=== |\n\Z)", colour, re.S))
            for name, state in golden_states().items():
                with self.subTest(screen=name, size=f"{cols}x{rows}"):
                    state.cols, state.rows = cols, rows
                    lines = install.tui_view(state, cols, rows)
                    for line in lines:
                        # The bar's key names faint, its actions not:
                        # the rest as before.
                        self.assertEqual(install.tui_paint(str(line), line.style, False),
                                         install.painted(line, install._bar_spans(
                                             line, "strong")) if line.style == "hint"
                                         else install._STYLES.get(line.style, "") + line)
                    stripped = [install.unpainted(painted.replace("^[", "\x1b")).rstrip()
                                for painted in screens[name].split("\n")]
                    golden = (GOLDEN / f"{name}-{cols}x{rows}.txt").read_text(encoding="utf-8")
                    self.assertEqual("\n".join(stripped) + "\n", golden)

    def test_each_role_paints_a_status_word_on_the_result_screens(self):
        """Done, a part done, files left offline, a stop: between them the
        result screens use every role, each on a word that says it."""
        # The failed files are listed on the result's Details.
        told = result_states()["partial"]
        told.stack.append("details")
        drawn = "\n".join(install.tui_paint(str(line), line.style, True)
                          for state in [*result_states().values(), told]
                          for line in install.tui_view(state, 80, 24))
        for role, word in (("accent", "RetroBIOS"), ("strong+success", "4 files installed"),
                           ("strong+success", "Done"), ("failure", "1 failed"),
                           ("failure", "failed:"), ("strong+warning", "3 not fetched"),
                           ("strong+warning", "Stopped"),
                           ("strong", "/home/user/.config/retroarch/system")):
            with self.subTest(role=role, word=word):
                self.assertIn(install._sgr(role) + word, drawn)
        # "2 of 4 installed" is no count of files installed.
        self.assertNotIn(install._sgr("strong+success") + "4 installed", drawn)

    def test_the_status_words_take_their_role_and_a_zero_none(self):
        spans = install.status_spans("1 in place, 0 missing, 3 missing, 1 wrong copy, 2 failed")
        self.assertEqual([("1 in place", "success"), ("3 missing", "warning"),
                          ("1 wrong copy", "warning"), ("2 failed", "failure")],
                         [("1 in place, 0 missing, 3 missing, 1 wrong copy, 2 failed"[a:b], r)
                          for a, b, r in spans])
        self.assertEqual(install.status_spans("0 wrong copies, 0 missing"), [])
        self.assertEqual(install.status_spans("python3 install.py --platform retroarch"), [])

    def test_the_bar_paints_a_key_only(self):
        """The first entry's key in the accent, never a word: "Writing to the
        card..." and "Any key closes this help" name no key."""
        for text in (" Writing to the card...", " Any key closes this help"):
            self.assertEqual(install.tui_paint(text, "hint", True), text)
        painted = install.tui_paint(" A/Enter Exit  B/Esc Back", "hint", True)
        # The actions plain, the other keys faint.
        self.assertEqual(painted, " " + install._sgr("accent") + "A/Enter\x1b[0m Exit  "
                         + install._sgr("muted") + "B/Esc\x1b[0m Back")

    def test_the_hint_bar_names_the_primary_action_first(self):
        for name, state in golden_states().items():
            with self.subTest(screen=name):
                hint = install.tui_view(state, 40, 15)[-1].strip()
                # Checking has no A: Back comes first, Quit never in the
                # cell the screen before had Continue in.
                self.assertTrue(hint.startswith(("A/Enter", "A ", "Enter", "Ctrl-C", "Any key",
                                                 "B/Esc Stop", "B Stop")
                                                + (("B ",) if name == "checking" else ())),
                                hint)

    def test_focus_is_marked_without_colour(self):
        lines = install.tui_view(fresh_state(), 80, 24)
        focused = [line for line in lines if getattr(line, "style", "") == "focus"]
        self.assertEqual(len(focused), 1)
        self.assertTrue(focused[0].lstrip().startswith("> RetroArch"))


def _bar_keys(line: str) -> set:
    """The key each entry of a hint bar names: its first word."""
    return {part.split(" ", 1)[0] for part in line.strip().split("  ") if part}


# The keys each route has, as the bar may name them. "Any" opens "Any key
# closes this help", <> and ^v are the narrow forms of Left/Right, Up/Down.
ROUTE_KEYS = {
    "keys": {"Enter", "Esc", "Space", "o", "?", "/", "Ctrl-C", "Ctrl-U", "PgUp/PgDn"},
    "gptokeyb": {"A", "B", "X", "Y", "Select+Start", "L1/R1"},
    "gptokeyb_muxterm": {"A", "B", "X", "Y", "Select+Start", "D-pad"},
    "evmapy": {"A", "B", "X", "Y", "L1/R1"},
    "muxterm": {"Start", "B", "Y", "Menu", "Select", "D-pad"},
    "miyoo": {"A", "Start", "R2", "L2", "L1/R1"},
}
EVERY_ROUTE_HAS = {"Left/Right", "Up/Down", "<>", "^v", "Any"}


class PadRoutes(unittest.TestCase):
    """The bar names the buttons the launcher maps, and a desktop's keys."""

    def test_the_route_from_the_environment(self):
        route = install.tui_pad_route
        for value in install.TUI_PAD_ROUTES:
            self.assertEqual(route("linux", {"RETROBIOS_PAD": value, "DISPLAY": ":0"}), value)
        self.assertEqual(route("linux", {"RETROBIOS_PAD": " MiYoo "}), "miyoo")
        self.assertEqual(route("linux", {"RETROBIOS_PAD": "dualshock"}), "both")
        for os_type in ("windows", "darwin", "wsl"):
            self.assertEqual(route(os_type, {}), "keys", os_type)
        for env in ({"DISPLAY": ":0", "TERM": "xterm-256color"}, {"WAYLAND_DISPLAY": "w-0"},
                    {"SSH_CONNECTION": "10.0.0.2 5 10.0.0.3 22"}, {"SSH_TTY": "/dev/pts/1"}):
            self.assertEqual(route("linux", env), "keys", env)
        # SteamOS game mode and anything Steam starts: Steam Input may be
        # all there is. A console with nothing named, or Android: unknown.
        for os_type, env in (("linux", {"SteamGamepadUI": "1", "DISPLAY": ":0"}),
                             ("linux", {"GAMESCOPE_WAYLAND_DISPLAY": "gamescope-0",
                                        "WAYLAND_DISPLAY": "w-0"}),
                             ("windows", {"SteamGameId": "123"}),
                             ("linux", {"SteamDeck": "1", "DISPLAY": ":0"}),
                             ("linux", {"TERM": "linux", "SSH_TTY": "/dev/pts/0"}),
                             ("linux", {"TERM": "linux"}), ("linux", {}),
                             ("android", {"DISPLAY": ":0"})):
            self.assertEqual(route(os_type, env), "both", env)

    def test_the_launchers_values_are_the_routes(self):
        tui = (REPO_ROOT / "ports" / "shared" / "tui.txt").read_text(encoding="utf-8")
        named = set(re.findall(r'RB_PAD="(\w+)"', tui))
        for launcher in REPO_ROOT.glob("ports/*/*.sh"):
            named |= set(re.findall(r'RB_PAD="(\w+)"', launcher.read_text(encoding="utf-8")))
        self.assertLessEqual(named, set(install.TUI_PAD_ROUTES))
        self.assertEqual(set(ROUTES) - {"keys"}, set(install.TUI_PAD_ROUTES))

    def test_the_plan_bar_of_each_route(self):
        expected = {
            "both": "A/Enter Install  B/Esc Back  Y/o Options  ? Help",
            "keys": "Enter Install  Esc Back  o Options  ? Help",
            "gptokeyb": "A Install  B Back  Y Options",
            "evmapy": "A Install  B Back  Y Options",
            "muxterm": "Start Install  B Back",
            "miyoo": "A Install  R2 Back  L2 Options",
        }
        for route, bar in expected.items():
            with self.subTest(route=route):
                state = checked_state()
                state.pad = route
                self.assertEqual(install.tui_view(state, 80, 24)[-1].strip(), bar)

    def test_no_bar_names_a_key_its_route_lacks(self):
        for route, have in ROUTE_KEYS.items():
            for name, state in golden_states().items():
                state.pad = route
                for cols, rows in SIZES:
                    with self.subTest(route=route, screen=name, size=f"{cols}x{rows}"):
                        state.cols, state.rows = cols, rows
                        bar = install.tui_view(state, cols, rows)[-1]
                        self.assertLessEqual(_bar_keys(bar) - EVERY_ROUTE_HAS, have, bar)

    def test_the_install_says_what_stops_it_there(self):
        expected = {
            "both": "B, Ctrl-C or Select+Start stops.", "keys": "Esc or Ctrl-C stops.",
            "gptokeyb": "B or Select+Start stops.", "evmapy": "B stops.",
            "muxterm": "B stops.", "miyoo": "R2 stops.",
        }
        for route, words in expected.items():
            with self.subTest(route=route):
                state = golden_states()["installing"]
                state.pad = route
                text = "\n".join(install.tui_view(state, 80, 24))
                self.assertIn(f"{words} What is done stays done.", text)
                state.stopping = True
                again = {"both": "B or Ctrl-C", "keys": "Esc or Ctrl-C", "miyoo": "R2"}
                self.assertIn(f"Press {again.get(route, 'B')} again to stop now.",
                              " ".join(" ".join(install.tui_view(state, 80, 24)).split()))

    def test_the_help_lists_the_buttons_and_the_keys(self):
        def help_text(route: str, screen: str = "plan") -> str:
            state = golden_states()[screen]
            state.pad, state.help = route, True
            return "\n".join(line.rstrip() for line in install.tui_view(state, 80, 24))

        gptk = help_text("gptokeyb")
        for words in ("D-pad, Up/Down", "A, Start, Enter", "B, Select, Esc", "Y, Tab, o",
                      "Select, then Start", "Quit at once", "q, Ctrl-C"):
            self.assertIn(words, gptk)
        self.assertNotIn("Select+Start", help_text("evmapy"))
        keys = help_text("keys")
        for words in ("Enter", "Esc, Backspace", "o, Tab"):
            self.assertIn(words, keys)
        for button in ("A/Enter", "B/Esc", "L1", "Start", "Y,"):
            self.assertNotIn(button, keys)
        muxterm = help_text("muxterm")
        for words in ("Start, Enter", "B, Esc, Backspace", "Keyboard on or off",
                      "Close the terminal"):
            self.assertIn(words, muxterm)
        self.assertNotIn("Select+Start", muxterm)
        # gptokeyb2 owns the pad inside muxterm, which keeps PgUp and PgDn
        # for its scrollback: the gptokeyb buttons, Left and Right to page.
        in_muxterm = help_text("gptokeyb_muxterm", "preview")
        for words in ("A, Start, Enter", "Select, then Start"):
            self.assertIn(words, in_muxterm)
        self.assertNotIn("L1/R1", in_muxterm)
        self.assertIn("L1/R1", help_text("gptokeyb", "preview"))
        # muxterm keeps PgUp and PgDn for its scrollback, and L1 and R1
        # send nothing: the D-pad's Left and Right page there instead.
        for screen in ("systems", "result", "plan"):
            with self.subTest(screen=screen):
                text = help_text("muxterm", screen)
                for words in ("L1", "R1", "PgUp", "PgDn"):
                    self.assertNotIn(words, text)
        self.assertIn("D-pad Left/Right   Page", help_text("muxterm", "result"))
        miyoo = help_text("miyoo", "systems")
        for words in ("Start, Enter", "A, Space, Right/Left", "R2, Esc, Backspace",
                      "L2, Tab, o", "Sends no key here"):
            self.assertIn(words, miyoo)
        # The both-names form is the one it was.
        self.assertEqual(help_text("both"), (GOLDEN / "help-80x24.txt").read_text().rstrip("\n"))

    def test_a_miyoo_a_chooses_and_ticks(self):
        """A is Space on a Miyoo: it chooses where Enter does, ticks where X
        would, and L1 and R1 (E and T) page."""
        state = checked_state()
        state.pad = "miyoo"
        self.assertEqual(press(state, " "), [("run", "install")])
        state = checked_state()
        state.pad = "miyoo"
        state.stack.append("systems")
        rows = install.tui_rows(state)
        first = next(i for i, row in enumerate(rows) if row.action == "system")
        state.focus["systems"] = first
        before = set(state.ticked)
        press(state, " ")
        self.assertNotEqual(state.ticked, before)
        state.focus["systems"] = next(i for i, row in enumerate(rows) if row.action == "all")
        press(state, " ")
        self.assertEqual(state.ticked, {row["system"] for row in state.systems})
        state.focus["systems"] = first
        press(state, "t")
        self.assertGreater(state.focus["systems"], first)
        press(state, "e")
        self.assertEqual(state.focus["systems"], 0)
        # In a text field the letters are letters.
        state.editing = "systems"
        press(state, "t")
        self.assertEqual(state.filters["systems"], "t")

    def test_space_stays_x_on_the_other_routes(self):
        for route in ("both", "keys", "gptokeyb", "evmapy", "muxterm"):
            with self.subTest(route=route):
                state = checked_state()
                state.pad = route
                self.assertEqual(press(state, " "), [("run", "confirm")])


class Rendering(unittest.TestCase):
    def test_only_changed_lines_are_written(self):
        out = io.StringIO()
        terminal = install._TuiTerminal.__new__(install._TuiTerminal)
        terminal.stdout, terminal.encoding, terminal.frame = out, "ascii", []
        state = fresh_state()
        terminal.draw(install.tui_view(state, 40, 12), 40)
        first = out.getvalue()
        self.assertTrue(first.startswith("\x1b[H\x1b[2J"))
        press(state, "down")
        out.seek(0)
        out.truncate()
        terminal.draw(install.tui_view(state, 40, 12), 40)
        changed = out.getvalue()
        self.assertEqual(changed.count("\x1b[7m"), 1)
        before = install.tui_view(fresh_state(), 40, 12)
        after = install.tui_view(state, 40, 12)
        moved = [f"\x1b[{i + 1};1H" for i, (a, b) in enumerate(zip(before, after)) if a != b]
        self.assertEqual(changed.count(";1H"), len(moved))
        for move in moved:
            self.assertIn(move, changed)

    def test_text_the_terminal_cannot_encode_is_replaced(self):
        out = io.StringIO()
        terminal = install._TuiTerminal.__new__(install._TuiTerminal)
        terminal.stdout, terminal.encoding, terminal.frame = out, "ascii", []
        terminal.write("ファ")
        self.assertEqual(out.getvalue(), "??")


class TheSectionStandsApart(unittest.TestCase):
    def test_no_name_of_the_installer_is_defined_again(self):
        """_run and _system_label were defined twice: the later one won, and
        the installer's listing called the interface's."""
        import ast

        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        start = source[:source.index("# Full-screen interface\n#")].count("\n") + 1
        seen: dict = {}
        for node in ast.parse(source).body:
            names = [node.name] if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else [
                target.id for target in getattr(node, "targets", [])
                if isinstance(target, ast.Name)]
            for name in names:
                seen.setdefault(name, []).append(node.lineno)
        twice = {name: lines for name, lines in seen.items()
                 if len(lines) > 1 and max(lines) >= start}
        self.assertEqual(twice, {})


class ControlCharacters(unittest.TestCase):
    """Names from the file list, the folders on disk and the installer's own
    words reach the screen: an escape sequence among them would drive the
    terminal (clear it, or set the clipboard with OSC 52)."""

    HOSTILE = "a\x1b[2Jb\x1b]52;c;x\x07c\rd\ne\x7ff\x9bg\x85h"

    def test_the_cleaning(self):
        self.assertEqual(install.screen_text(self.HOSTILE), "a?[2Jb?]52;c;x?c?d?e?f?g?h")
        self.assertEqual(install.screen_text("ファミコン é"), "ファミコン é")

    def assertClean(self, lines) -> None:
        for line in lines:
            self.assertIsNone(re.search(r"[\x00-\x1f\x7f-\x9f]", line), repr(line))

    def test_a_file_name_in_the_preview(self):
        state = checked_state()
        state.stack += ["options", "preview"]
        state.dry = dict(CHECK)
        state.dry_files = [{**FILES[0], "dest": "\x1b[2Jevil.bin"}]
        lines = install.tui_view(state, 80, 24)
        self.assertClean(lines)
        self.assertIn("?[2Jevil.bin", "\n".join(lines))

    def test_a_folder_name_in_the_browser(self):
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        (root / "x\x1b]52;c;x\x07").mkdir()
        state = fresh_state()
        state.platform, state.stack = "retroarch", ["folder", "browse"]
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            install._browse_to(state, root)
        lines = install.tui_view(state, 80, 24)
        self.assertClean(lines)
        self.assertIn("x?]52;c;x?/", "\n".join(lines))

    def test_the_child_tail_on_the_error_screen(self):
        state = fresh_state()
        state.stack, state.run = ["setup", "error"], "check"
        state.error = ["\x1b[31mError\x1b[0m: \x07bad\r"]
        self.assertClean(install.tui_view(state, 40, 15))

    def test_the_renderer_guards_whatever_reaches_it(self):
        out = io.StringIO()
        terminal = install._TuiTerminal.__new__(install._TuiTerminal)
        terminal.stdout, terminal.encoding = out, "utf-8"
        terminal.frame = [("", "")] * 3
        terminal.draw(["x", "\x1b]52;c;x\x07", "z"], 40)
        self.assertNotIn("\x1b]", out.getvalue())
        self.assertNotIn("\x07", out.getvalue())

    def test_the_farewell_is_clean(self):
        state = checked_state()
        state.dest = Path("/media/\x1b[2J")
        state.stack.append("result")
        state.code = 0
        state.summary = {"installed": 1, "failed": [{"dest": "\x1b]0;t\x07x", "reason": "\x1b"}]}
        self.assertClean(install.tui_farewell(state))


class SmallFixes(unittest.TestCase):
    def test_a_system_name_is_said_once_with_a_pack(self):
        """"Onion gets the RetroArch file list" was
        printed by the pack check, then again where the platform is read."""
        pack = mock.Mock(files=[Path("RetroArch_BIOS_Pack.zip")])
        pack.name = "RetroArch_BIOS_Pack.zip"
        pack.platforms.return_value = ["retroarch"]
        args = argparse.Namespace(manifest=None, from_pack=Path("p.zip"), platform="onion",
                                  **{"from": None})
        with mock.patch.object(install, "PackSource", return_value=pack), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            install._open_local_sources(args)
        self.assertNotIn("Onion gets", out.getvalue())
        install.LOCAL.reset()

    def test_a_command_line_region_the_list_lacks(self):
        state = checked_state()
        state.cli_regions = ["europe"]
        state.regions = list(state.cli_regions)
        state.stack += ["options", "regions"]
        self.assertEqual([row.value for row in install.tui_rows(state)
                          if row.action == "region"], ["europe", "japan", "north-america"])
        press(state, "enter")
        self.assertEqual(state.regions, [])
        self.assertIn("europe", [row.value for row in install.tui_rows(state)])
        press(state, "enter")
        self.assertEqual(state.regions, ["europe"])

    def test_stay_after_esc_on_a_direct_check_checks_again(self):
        state = fresh_state()
        state.stack = []
        state.manifest, state.manifest_for = MANIFEST, "retroarch"
        install._choose(state, "retroarch", Path(REPO_ROOT))
        self.assertEqual(state.screen, "checking")
        self.assertEqual(press(state, "esc"), [("kill",)])
        self.assertEqual(state.screen, "quit")
        self.assertEqual(press(state, "down", "enter"), [("run", "check")])
        self.assertEqual((state.stack, state.running), (["checking"], True))
        press(state, "esc")
        self.assertEqual(press(state, "esc"), [("run", "check")])

    def test_speed_ignores_a_resumed_partial(self):
        state = checked_state()
        press(state, "enter")
        mega = 1024 * 1024
        state.now = 9.0
        install.tui_receive(state, ("event", state.run_id, {
            "event": "download", "platform": "retroarch", "files": 2, "bytes": 1000 * mega}))
        # The first event carries the 500 MB already on disk.
        for when, done in ((10.0, 500 * mega), (11.0, 501 * mega), (12.0, 502 * mega)):
            state.now = when
            install.tui_receive(state, ("event", state.run_id, {
                "event": "progress", "files_done": 0, "files_total": 2,
                "bytes_done": done, "bytes_total": 1000 * mega}))
            # The partial copy resumed is counted local by the engine.
            install.tui_receive(state, ("event", state.run_id, {
                "event": "transfer", "bytes_local": 500 * mega,
                "bytes_network": done - 500 * mega}))
        text = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn("1.0 MB/s, 8:18 left", text)

    def test_numbers_from_before_the_options_say_so(self):
        state = checked_state()
        state.stack.append("systems")
        self.assertNotIn("before the options", "\n".join(install.tui_view(state, 80, 24)))
        state.regions = ["japan"]
        footer = "\n".join(install.tui_view(state, 80, 24)[-3:])
        self.assertIn("before the options", footer)

    def test_a_cores_folder_implies_the_installed_cores(self):
        state = checked_state()
        state.passthrough = [("--cores-dir", "/opt/cores")]
        state.installed_only = True
        state.stack.append("options")
        row = next(r for r in install.tui_rows(state) if r.action == "installed")
        self.assertEqual(row.label, "Installed cores only: yes, implied by --cores-dir")
        state.focus["options"] = install.tui_rows(state).index(row)
        press(state, "enter", "left")
        self.assertTrue(state.installed_only)
        self.assertNotIn("--installed-cores", [f for f, _v in install.tui_flags(state)])

    @in_full
    def test_the_end_of_a_wrapped_pager_is_reachable(self):
        state = checked_state()
        state.stack.append("result")
        state.code, state.summary = 0, {"installed": 3}
        state.dest = Path("/media/" + "long-folder-name/" * 8)
        state.cols, state.rows = 40, 12
        press(state, "end")
        lines = install.tui_view(state, 40, 12)
        self.assertIn("python3 install.py", "\n".join(lines))
        top = state.focus["result"]
        press(state, "up")
        self.assertEqual(state.focus["result"], top - 1)

    def test_end_then_up_in_a_pager(self):
        state = checked_state()
        state.stack += ["options", "preview"]
        state.dry, state.dry_files = dict(CHECK), list(FILES) * 10
        state.cols, state.rows = 40, 15
        press(state, "end")
        last = install.tui_view(state, 40, 15)
        press(state, "up")
        self.assertNotEqual(install.tui_view(state, 40, 15), last)

    def test_a_paste_slower_than_the_escape_wait_stays_one_piece(self):
        decoder = install.KeyDecoder()
        self.assertEqual(decoder.feed("\x1b[200~/media/"), [])
        self.assertEqual(decoder.flush(), [])
        self.assertTrue(decoder.waiting)
        self.assertEqual(decoder.feed("sd\x1b[201~"), [Key("paste", "/media/sd")])

    def test_values_cannot_be_read_as_options(self):
        state = checked_state()
        state.dest = Path("-rf")
        state.cores = ["-x"]
        argv = install.tui_argv(state, "install", "py", "i.py")
        self.assertIn("--dest=-rf", argv)
        self.assertIn("--core=-x", argv)
        self.assertIn("--platform=retroarch", argv)

    def test_the_second_ctrl_c_is_announced_and_the_result_stays_honest(self):
        state = checked_state()
        press(state, "enter")
        install.tui_receive(state, ("event", state.run_id, {
            "event": "download", "platform": "retroarch", "files": 4, "bytes": 100}))
        install.tui_receive(state, ("event", state.run_id, {
            "event": "downloaded", "dest": "a.bin", "ok": True, "reason": "", "size": 1,
            "files_done": 1, "files_total": 4, "bytes_done": 1, "bytes_total": 100}))
        press(state, "ctrl-c")
        self.assertIn("Press B or Ctrl-C again to stop now.",
                      " ".join(install.tui_view(state, 120, 40)))
        self.assertEqual(press(state, "ctrl-c"), [("kill",)])
        install.tui_receive(state, ("ended", state.run_id, -9, []))
        title, lines = install.tui_outcome(state)
        self.assertEqual((title, state.code), ("Stopped", 130))
        self.assertEqual(lines[0], "Stopped: 1 of 4 installed, run again to finish.")

    def test_systems_show_the_platform_names(self):
        state = checked_state()
        state.systems.append({"event": "system", "system": "sega-saturn",
                              "name": "Sega - Saturn", "files": 1, "present": 0,
                              "missing": 1, "wrong_hash": 0, "bytes_needed": 5})
        state.ticked.add("sega-saturn")
        state.stack.append("systems")
        wide = "\n".join(install.tui_view(state, 120, 40))
        self.assertIn("[x] Sega - Saturn", wide)
        self.assertIn("sega-saturn", wide)
        narrow = "\n".join(install.tui_view(state, 40, 15))
        self.assertIn("[x] Sega - Saturn", narrow)
        self.assertNotIn("sega-saturn", narrow)
        press(state, "/", "s", "a", "t", "u")
        self.assertEqual([row.value for row in install.tui_rows(state)
                          if row.action == "system"], ["sega-saturn"])


class CleanupSurvivesABrokenTerminal(unittest.TestCase):
    """A write that fails (EIO when the window closed, EPIPE) on the way out
    left the terminal raw and the handlers installed."""

    class Tty(io.StringIO):
        broken = False

        def __init__(self, fd: int) -> None:
            super().__init__()
            self.fd = fd

        def isatty(self) -> bool:
            return True

        def fileno(self) -> int:
            return self.fd

        def write(self, text: str) -> int:
            if CleanupSurvivesABrokenTerminal.Tty.broken:
                raise OSError(5, "Input/output error")
            return super().write(text)

    def test_termios_and_handlers_come_back(self):
        import signal

        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        before = termios.tcgetattr(slave)
        handlers = {n: signal.getsignal(n) for n in (signal.SIGINT, signal.SIGTERM,
                                                     signal.SIGHUP)}
        # Keys come in on the terminal itself, the screen goes out on a
        # descriptor of its own, as fd 0 and fd 1 are.
        tty, screen_fd = self.Tty(slave), os.dup(slave)
        self.addCleanup(os.close, screen_fd)
        out = self.Tty(screen_fd)
        real_draw = install._TuiTerminal.draw

        def breaking_draw(terminal, lines, cols):
            terminal.frame = []
            real_draw(terminal, lines, cols)
            CleanupSurvivesABrokenTerminal.Tty.broken = True

        self.addCleanup(setattr, CleanupSurvivesABrokenTerminal.Tty, "broken", False)
        work = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, work, True)
        with mock.patch.object(install._TuiTerminal, "draw", breaking_draw), \
                mock.patch.object(install.tempfile, "mkdtemp", return_value=str(work)), \
                mock.patch.object(install, "tui_start", return_value=(fresh_state(), [])), \
                mock.patch.object(install, "_open_local_sources"), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(sys, "stdin", tty), mock.patch.object(sys, "stdout", out), \
                mock.patch.object(sys, "stderr", out):
            code = install.run_tui(_args())
            self.assertIs(sys.stdout, out)
        # A window that answers EIO is a closed window: its signal's code,
        # not a crash.
        self.assertEqual(code, 129)
        # The farewell found no terminal: what still flushes at exit goes to
        # the null device, and the exit code stays the one returned.
        self.assertEqual(os.fstat(screen_fd).st_rdev, os.stat(os.devnull).st_rdev)
        # No crash log is kept, and nothing else of the run.
        self.assertFalse(work.exists())
        self.assertEqual(termios.tcgetattr(slave), before)
        for number, handler in handlers.items():
            self.assertEqual(signal.getsignal(number), handler)


class TicksBarAndPaths(unittest.TestCase):
    """Ticks, the key bar, the network clock and typed paths."""

    def systems(self) -> install.TuiState:
        state = checked_state()
        press(state, "down", "enter")
        self.assertEqual(state.screen, "systems")
        return state

    def focused(self, state: install.TuiState) -> install.TuiRow:
        rows = install.tui_rows(state)
        return rows[state.focus[state.screen]]

    def test_install_says_the_size_the_headline_says(self):
        """One system ticked: the headline said About 3479 files, 82.2 MB
        and the row Install 6.6 GB, the whole list's size."""
        big = 6 * 1024 ** 3
        state = checked_state()
        state.files[0] = {**state.files[0], "size": big}
        state.check = {**state.check, "bytes_needed": state.check["bytes_needed"] + big}
        self.assertEqual(install.tui_rows(state)[0].label, "Install 6.0 GB")
        for system, label, head in (("nintendo-gba", "Install", "About 1 file, 16.0 KB"),
                                    ("sony-playstation", "Install 6.0 GB",
                                     "About 3 files, 6.0 GB")):
            with self.subTest(system=system):
                state.ticked = {system}
                self.assertTrue(install._tui_estimating(state))
                self.assertEqual(install.tui_rows(state)[0].label, label)
                self.assertIn(head, "\n".join(install.tui_view(state, 80, 24)))

    def test_the_filter_never_changes_the_ticks(self):
        state = self.systems()
        press(state, "n")
        state.focus["systems"] = next(i for i, row in enumerate(install.tui_rows(state))
                                      if row.value == "nintendo-gba")
        press(state, "right")
        self.assertEqual(state.ticked, {"nintendo-gba"})
        press(state, "/", "p", "l", "a", "y")
        self.assertEqual(self.focused(state).action, "filter")
        press(state, "enter")
        # Enter lands on the first match, never on All or None.
        self.assertEqual(self.focused(state).value, "sony-playstation")
        press(state, " ")
        self.assertEqual(state.ticked, {"nintendo-gba", "sony-playstation"})
        press(state, " ")
        press(state, "esc")
        # The filter is cleared, the row in focus stays in focus, and A there
        # continues instead of ticking everything.
        self.assertEqual(state.filters["systems"], "")
        self.assertEqual(self.focused(state).value, "sony-playstation")
        self.assertEqual(state.ticked, {"nintendo-gba"})
        self.assertIn("A/Enter Tick", install.tui_view(state, 80, 24)[-1])
        state.focus["systems"] = 0
        press(state, " ")
        self.assertEqual(state.editing, "")
        self.assertEqual(state.ticked, {"nintendo-gba"})

    def test_the_bar_names_what_a_does_on_the_focused_row(self):
        state = checked_state()
        self.assertTrue(install.tui_view(state, 80, 24)[-1].strip().startswith("A/Enter Install"))
        press(state, "down")
        self.assertTrue(install.tui_view(state, 80, 24)[-1].strip().startswith("A/Enter Open"))
        state = self.systems()
        state.focus["systems"] = next(i for i, row in enumerate(install.tui_rows(state))
                                      if row.action == "all")
        self.assertIn("A/Enter Tick all", install.tui_view(state, 80, 24)[-1])

    def test_esc_and_q_stop_an_install(self):
        for key in ("esc", "backspace", "q"):
            with self.subTest(key=key):
                state = checked_state()
                press(state, "enter")
                self.assertEqual(press(state, key), [("stop",)])
                self.assertTrue(state.stopping)
                self.assertEqual(press(state, key), [("kill",)])

    def test_options_read_the_plan_again(self):
        state = self.systems()
        press(state, "n")
        state.focus["systems"] = 1
        press(state, "right")
        ticked = set(state.ticked)
        press(state, "esc", "o")
        self.assertEqual(state.screen, "options")
        state.focus["options"] = 1
        press(state, "enter")
        self.assertTrue(state.no_game_data)
        effects = press(state, "esc")
        self.assertEqual(effects, [("run", "check")])
        self.assertIn("--no-game-data", [f for f, _v in state.checked_flags])
        self.assertNotIn("--system", [f for f, _v in state.checked_flags])
        for event in [*FILES, *SYSTEMS, {**CHECK, "missing": 2, "bytes_needed": 600}]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={}):
            install.tui_receive(state, ("ended", state.run_id, 1, []))
        self.assertEqual(state.screen, "plan")
        self.assertEqual(state.ticked, ticked)
        for cols, rows in ((80, 24), (40, 15)):
            text = "\n".join(install.tui_view(state, cols, rows))
            # the headline counts the ticked systems.
            self.assertIn("About 1 file, 16.0 KB, for 1 of 3 systems", " ".join(text.split()))
            self.assertNotIn("3 files to download", text)

    def test_no_network_is_said_at_once(self):
        import socket

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        inbox = __import__("queue").Queue()
        started = time.monotonic()
        with mock.patch.object(install, "MANIFEST_URL",
                               f"http://127.0.0.1:{port}/install/{{platform}}.json"):
            install._tui_fetch("retroarch", inbox, io.StringIO())
        self.assertLess(time.monotonic() - started, 5)
        kind, plat, title, lines, code = inbox.get_nowait()
        self.assertEqual((kind, title, code), ("manifest_failed", "No connection", 1))
        self.assertIn("could not be downloaded: the server refused the connection", lines[0])
        # The pack is the one option named: the way of a handheld with no
        # Wi-Fi.
        self.assertIn("Or copy a pack to the card and run the installer with --from-pack",
                      " ".join(lines))
        self.assertNotIn("--", " ".join(lines).replace("--from-pack", ""))
        state = fresh_state()
        with mock.patch.object(install.Path, "exists", return_value=True):
            press(state, "enter")
        install.tui_receive(state, (kind, plat, title, lines, code))
        self.assertEqual([row.action for row in install.tui_rows(state)],
                         ["retry", "elsewhere", "quit"])

    def test_the_clock_says_so(self):
        import ssl

        inbox = __import__("queue").Queue()
        error = urllib_error(ssl.SSLCertVerificationError("certificate is not yet valid"))
        words = install.network_words(error, today=install.datetime.date(1980, 1, 1))
        with mock.patch.object(install, "_fetch_json", side_effect=error), \
                mock.patch.object(install, "network_words", return_value=words):
            install._tui_fetch("retroarch", inbox, io.StringIO())
        _kind, _plat, title, lines, _code = inbox.get_nowait()
        self.assertEqual(title, "The clock is wrong")
        self.assertIn("The clock reads 1980-01-01", lines[0])

    def test_one_line_per_cause(self):
        state = checked_state()
        state.stack.append("result")
        state.code = 2
        state.summary = {"installed": 0, "up_to_date": 0, "failed": [
            {"dest": f"f{n}.bin", "reason": "folder not writable"} for n in range(50)]}
        _title, lines = install.tui_outcome(state)
        self.assertEqual([line for line in lines if "failed" in line],
                         ["Nothing was installed: 50 files failed.",
                          "  50 files failed, all for one reason: folder not writable."])

    def test_folder_inside_a_card_offers_its_root(self):
        card = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, card, True)
        (card / ".system").mkdir()
        (card / ".system" / "version.txt").write_text("MinUI-20250101\n")
        (card / "Bios").mkdir()
        state = fresh_state()
        state.stack = ["folder"]
        self.assertEqual(install._choose(state, "minui", card / "Bios"), [])
        self.assertEqual(state.screen, "cardroot")
        text = screen_text(install.tui_view(state, 120, 40))
        self.assertIn(f"under the card's root: {card}", text)
        self.assertEqual(press(state, "enter"), [("fetch", "minui")])
        self.assertEqual(state.dest, card)

    def test_the_banner_is_not_an_error_line(self):
        state = fresh_state()
        state.platform, state.dest = "retroarch", SYSTEM_DIR
        state.manifest, state.manifest_for = MANIFEST, "retroarch"
        install._start_check(state)
        install.tui_receive(state, ("ended", state.run_id, 1,
                                    ["RetroBIOS 532f0b8d96e0", "Error: refused."]))
        self.assertEqual(state.error, ["Error: refused."])
        self.assertNotIn("retry", [row.action for row in install.tui_rows(state)])

    def test_typed_path_replaces_the_one_offered(self):
        state = fresh_state()
        state.platform, state.stack = "retroarch", ["folder"]
        state.folder_default = SYSTEM_DIR
        state.focus["folder"] = 2
        press(state, "enter")
        self.assertEqual((state.screen, state.path_selected), ("path", True))
        install.tui_update(state, Key("paste", '"/media/sd card/bios"'))
        self.assertEqual(state.path_text, '"/media/sd card/bios"')
        install.tui_update(state, Key("ctrl-u"))
        self.assertEqual(state.path_text, "")
        install.tui_update(state, Key("paste", '/media/x"'))
        self.assertEqual(install.typed_path(state.path_text), Path("/media/x"))

    def test_path_from_the_root_is_not_created_on_a(self):
        state = fresh_state()
        state.stack = ["folder"]
        install._choose(state, "retroarch", Path("/no/such/deep/folder"))
        self.assertEqual(state.screen, "create")
        self.assertEqual(self.focused(state).action, "other")
        self.assertIn("Every folder of this path would be made",
                      " ".join(install.tui_view(state, 120, 40)))
        near = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, near, True)
        install._choose(state, "retroarch", near / "bios")
        self.assertEqual(self.focused(state).action, "create")

    def test_two_setups_of_one_name(self):
        flatpak = HOME / ".var/app/org.libretro.RetroArch/config/retroarch/system"
        setups = install.tell_apart([("retroarch", flatpak, "RetroArch"),
                                     ("retroarch", SYSTEM_DIR, "RetroArch"),
                                     ("emudeck", HOME / "Emulation/bios", "EmuDeck")])
        self.assertEqual([label for _p, _f, label in setups],
                         ["RetroArch (Flatpak)", "RetroArch (installed)", "EmuDeck"])
        # Two that no package names keep the end of their folder.
        twice = install.tell_apart([("retroarch", SYSTEM_DIR, "RetroArch"),
                                    ("retroarch", HOME / "ra2/system", "RetroArch")])
        self.assertEqual([label for _p, _f, label in twice],
                         ["RetroArch (retroarch/system)", "RetroArch (ra2/system)"])
        state = fresh_state()
        state.setups = setups
        self.assertIn("RetroArch (Flatpak)", "\n".join(install.tui_view(state, 40, 15)))
        # A Flatpak whose config names a system folder outside its sandbox.
        elsewhere = HOME / "bios"
        config = HOME / ".var/app/org.libretro.RetroArch/config/retroarch/retroarch.cfg"
        with mock.patch.dict(install._RETROARCH_CONFIGS, {elsewhere: (config, config.parent)}):
            setups = install.tell_apart([("retroarch", elsewhere, "RetroArch"),
                                         ("retroarch", SYSTEM_DIR, "RetroArch")])
        self.assertEqual(setups[0][2], "RetroArch (Flatpak)")

    def test_the_check_counts_while_it_reads(self):
        state = fresh_state()
        state.platform, state.dest = "retroarch", SYSTEM_DIR
        state.manifest, state.manifest_for = MANIFEST, "retroarch"
        install._start_check(state)
        install.tui_receive(state, ("event", state.run_id,
                                    {"event": "checking", "files_done": 120, "files_total": 400}))
        self.assertIn("Reading the files already in the folder: 120 of 400",
                      "\n".join(install.tui_view(state, 80, 24)))

    def test_narrow_bar_keeps_the_keys_to_finish(self):
        state = self.systems()
        self.assertEqual(install.tui_view(state, 40, 15)[-1].strip(),
                         "A Tick  B Done  ? Help")

    def test_device_name_finds_its_setup(self):
        state = fresh_state()
        state.stack = ["platforms"]
        press(state, "/", "m", "u", "o", "s")
        self.assertEqual([row.value for row in install.tui_rows(state)][1:],
                         [("retroarch", "muOS")])

    def test_long_preview_wraps_only_what_is_in_view(self):
        state = checked_state()
        state.stack += ["options", "preview"]
        state.dry = dict(CHECK)
        state.dry_files = [{**FILES[0], "dest": f"file{n:05d}.bin"} for n in range(8000)]
        state.cols, state.rows = 40, 15
        real = install._text_lines
        calls = []

        def counted(items, width, whole=False):
            calls.append(len(items))
            return real(items, width, whole)

        with mock.patch.object(install, "_text_lines", counted):
            press(state, "end")
            lines = install.tui_view(state, 40, 15)
        self.assertLess(sum(calls), 40)
        self.assertIn("file07999.bin", "\n".join(lines))

    def test_titles_and_regions(self):
        state = checked_state()
        state.manifest = {**MANIFEST, "system_titles": {"nintendo-gba": "Game Boy Advance"}}
        state.stack.append("systems")
        text = "\n".join(install.tui_view(state, 40, 15))
        self.assertIn("[x] Game Boy Advance", text)
        self.assertEqual(install.region_title("asia-ntsc"), "Asia (NTSC)")
        self.assertEqual(install.region_title("north-america"), "North America")

    def test_jobs_stop_at_the_ends_and_q_keeps_the_error_code(self):
        state = checked_state()
        state.jobs = 1
        install._option(state, "jobs", -1)
        self.assertEqual(state.jobs, 1)
        state.jobs = 32
        install._option(state, "jobs", 1)
        self.assertEqual(state.jobs, 32)
        state = fresh_state()
        state.stack, state.error_code = ["setup", "error"], 2
        press(state, "q")
        self.assertEqual(state.exit_code, 2)

    def test_ascii_keeps_the_columns(self):
        self.assertEqual(install.ascii_text("Édition ファミ"), "Edition ??????")

    def test_refused_tui_says_why_without_the_usage(self):
        proc = install_run("--tui")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr.strip().splitlines(),
                         ["install.py: error: --tui cannot open the full-screen interface "
                          "here: the input is not a terminal"])


def urllib_error(reason: BaseException):
    import urllib.error

    return urllib.error.URLError(reason)


class WorkFolders(unittest.TestCase):
    """Every run's folder of logs goes, but the one a failure names."""

    class Terminal:
        state_to = None

        def __init__(self, *_streams) -> None:
            self.frame = []

        def enter(self) -> None:
            pass

        def leave(self) -> None:
            pass

        def size(self) -> tuple:
            return 80, 24

        def draw(self, lines, cols) -> None:
            pass

        def set_mouse(self, on: bool) -> None:
            pass

        def keys(self, timeout):
            WorkFolders.Terminal.state_to(self)
            return [Key("enter")]

    def run_to(self, code: int) -> tuple:
        work = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, work, True)
        state = checked_state()
        state.stack.append("result")
        state.code = code
        state.log = str(work / "install.log")
        state.summary = {"installed": 1, "failed": [] if code == 0 else [
            {"dest": "a.bin", "reason": "HTTP 404"}]}
        WorkFolders.Terminal.state_to = lambda _t: None
        out = io.StringIO()
        with mock.patch.object(install, "_TuiTerminal", self.Terminal), \
                mock.patch.object(install, "tui_start", return_value=(state, [])), \
                mock.patch.object(install, "_open_local_sources"), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.tempfile, "mkdtemp", return_value=str(work)), \
                mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", out):
            self.assertEqual(install.run_tui(_args()), code)
        return work, out.getvalue()

    def test_a_success_leaves_nothing(self):
        work, out = self.run_to(0)
        self.assertFalse(work.exists())
        self.assertNotIn("Details:", out)

    def test_a_failure_keeps_the_log_it_names(self):
        work, out = self.run_to(1)
        self.assertTrue(work.exists())
        self.assertIn(f"Log: {work / 'install.log'}", out)

    def test_a_stop_leaves_nothing(self):
        work, out = self.run_to(130)
        self.assertFalse(work.exists())

    def test_a_full_temp_disk_or_a_failing_pruner_still_opens(self):
        real_write = Path.write_text

        def full(path, *args, **kwargs):
            if path.name == install.TUI_OWNER:
                raise OSError(errno.ENOSPC, "No space left on device")
            return real_write(path, *args, **kwargs)

        with mock.patch.object(Path, "write_text", full):
            work, out = self.run_to(0)
        self.assertFalse(work.exists())
        with mock.patch.object(install, "_prune_work_folders",
                               side_effect=OSError(errno.EACCES, "denied")):
            work, out = self.run_to(0)
        self.assertFalse(work.exists())
        err = io.StringIO()
        with mock.patch.object(install.tempfile, "mkdtemp",
                               side_effect=OSError(errno.ENOSPC, "No space left")), \
                mock.patch.object(install, "tui_start", return_value=(fresh_state(), [])), \
                mock.patch.object(install, "_open_local_sources"), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(sys, "stderr", err):
            self.assertEqual(install.run_tui(_args()), 1)
        self.assertIn("no work folder could be made", err.getvalue())

    def test_a_stop_while_it_starts_ends_on_the_farewell(self):
        """Start+Select during the detection: the signal is the interface's,
        never the default action that ended Python without a word."""
        import signal

        for number in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=number):
                heard = []

                def recorder(signum, _frame, heard=heard):
                    heard.append(signum)

                previous = signal.signal(number, recorder)
                self.addCleanup(signal.signal, number, previous)
                interrupt = signal.getsignal(signal.SIGINT)

                def starting(*_args, **_kwargs):
                    os.kill(os.getpid(), number)
                    return fresh_state(), [("fetch", "retroarch")]

                entered = []
                WorkFolders.Terminal.state_to = lambda _t: None
                out = io.StringIO()
                work = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
                self.addCleanup(shutil.rmtree, work, True)
                with mock.patch.object(install, "_TuiTerminal", self.Terminal), \
                        mock.patch.object(install.tempfile, "mkdtemp", return_value=str(work)), \
                        mock.patch.object(self.Terminal, "enter",
                                          lambda _t: entered.append(True)), \
                        mock.patch.object(install, "tui_start", side_effect=starting), \
                        mock.patch.object(install, "_open_local_sources"), \
                        mock.patch.object(install, "_tui_fetch") as fetch, \
                        mock.patch.object(install, "detect_os", return_value="linux"), \
                        mock.patch.object(sys, "stdout", out), \
                        mock.patch.object(sys, "stderr", out):
                    code = install.run_tui(_args())
                self.assertEqual(code, 128 + number)
                self.assertEqual(heard, [])
                self.assertEqual(entered, [])
                fetch.assert_not_called()
                self.assertEqual(out.getvalue(), "RetroBIOS: stopped. Nothing was installed.\n")
                self.assertIs(signal.getsignal(number), recorder)
                self.assertIs(signal.getsignal(signal.SIGINT), interrupt)


def found(dest: str, folder: str, reason: str = "") -> dict:
    return {"event": "found", "platform": "retroarch", "dest": dest, "folder": folder,
            "path": f"{folder}/{dest}", "member": "", "reason": reason}


class CopyFromAnOldCard(unittest.TestCase):
    """--from in the interface: a row on the plan, the browser, the counts."""

    def recheck(self, state: install.TuiState, events: list) -> None:
        for event in [*FILES, *SYSTEMS, *events, CHECK]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={
                "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
            install.tui_receive(state, ("ended", state.run_id, 1, []))

    def test_the_plan_offers_it_and_the_browser_adds_the_folder(self):
        old = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, old, True)
        (old / "bios").mkdir()
        (old / "backup.zip").write_bytes(b"PK")
        state = checked_state()
        row = next(i for i, r in enumerate(install.tui_rows(state)) if r.action == "fromcard")
        self.assertEqual(install.tui_rows(state)[row].label,
                         "Copy the BIOS files from an old card or a folder")
        state.focus["plan"] = row
        state.home = old
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            press(state, "enter")
            self.assertEqual((state.screen, state.browse_for), ("browse", "from"))
            labels = [r.label for r in install.tui_rows(state)]
            self.assertEqual(labels, ["Use this folder", "..", "bios/", "backup.zip"])
            self.assertIn("Choose the old card", "\n".join(install.tui_view(state, 80, 24)))
            effects = press(state, "enter")
        self.assertEqual(effects, [("run", "check")])
        self.assertEqual(state.from_folders, [old])
        self.assertIn(f"--from={old}", install.tui_argv(state, "check", "py", "i.py"))
        self.recheck(state, [found("scph5500.bin", str(old)), found("gba_bios.bin", str(old))])
        self.assertEqual(state.screen, "plan")
        text = "".join("".join(install.tui_view(state, 120, 40)).split())
        # The folder by its name: the whole path pushed the BIOS folder off.
        self.assertIn("".join(f"2 found in {old.name}, 2 to download (512.0 KB)".split()), text)
        # A second folder from the options: --from twice.
        press(state, "o")
        state.focus["options"] = next(i for i, r in enumerate(install.tui_rows(state))
                                      if r.action == "from")
        self.assertEqual(install.tui_rows(state)[state.focus["options"]].right, "--from")
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            press(state, "enter")
            # It opens beside the first folder: the second card sits next to it.
            self.assertEqual(state.browse_dir, old.parent)
            install._browse_to(state, old)
            state.focus["browse"] = 3
            self.assertEqual(press(state, "enter"), [("run", "check")])
        self.assertEqual(state.from_folders, [old, old / "backup.zip"])
        self.assertEqual([flag for flag in install.tui_argv(state, "check", "py", "i.py")
                          if flag.startswith("--from=")],
                         [f"--from={old}", f"--from={old / 'backup.zip'}"])

    def test_left_takes_the_last_folder_back(self):
        state = checked_state()
        state.from_folders = [Path("/media/old")]
        state.checked_flags = install.tui_flags(state)
        state.stack.append("options")
        state.focus["options"] = next(i for i, r in enumerate(install.tui_rows(state))
                                      if r.action == "from")
        # Said, and the screen stays: Back to the plan counts again.
        self.assertEqual(press(state, "left"), [])
        self.assertEqual((state.screen, state.from_folders), ("options", []))
        self.assertIn("No longer copying from old.", "\n".join(install.tui_view(state, 80, 24)))
        self.assertEqual(press(state, "esc"), [("run", "check")])

    def test_the_command_line_folders_are_kept(self):
        with mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "_mounted_cards", return_value=[]):
            args = _args(platform="retroarch", dest=SYSTEM_DIR)
            setattr(args, "from", [Path("/media/old")])
            state, _effects = install.tui_start(args, "linux")
        self.assertEqual(state.from_folders, [Path("/media/old")])
        self.assertIn(("--from", "/media/old"), install.tui_flags(state))

    @in_full
    def test_files_in_the_wrong_place_are_said_and_listed(self):
        state = checked_state()
        state.platform, state.dest = "retroarch", SYSTEM_DIR
        install._start_check(state)
        self.recheck(state, [found("scph5500.bin", str(SYSTEM_DIR),
                                   "nested folder: bios/scph5500.bin")])
        text = " ".join(line.strip() for line in install.tui_view(state, 120, 40))
        # a fix copies, and the screen says the user's
        # copy stays.
        self.assertIn("1 file is in the wrong place, it will be copied where the emulators "
                      "read it, the copy left as it is.", text)
        row = next(i for i, r in enumerate(install.tui_rows(state)) if r.action == "misplaced")
        state.focus["plan"] = row
        press(state, "enter")
        self.assertEqual(state.screen, "misplaced")
        self.assertIn("scph5500.bin: nested folder: bios/scph5500.bin",
                      "\n".join(install.tui_view(state, 80, 24)))
        press(state, "esc")
        self.assertEqual(state.screen, "plan")

    def test_the_result_says_the_misplaced_copies_stay(self):
        state = checked_state()
        state.stack.append("result")
        state.code = 0
        state.summary = {"event": "summary", "mode": "install", "installed": 2,
                         "up_to_date": 0, "pending": 0, "failed": [], "skipped": [],
                         "left_out": [], "kept": [], "interrupted": False}
        state.local_dests = {"scph5500.bin": (str(SYSTEM_DIR), "nested folder: bios/a")}
        state.finished = [("scph5500.bin", True, ""), ("gba_bios.bin", True, "")]
        text = " ".join(" ".join(install.tui_outcome(state)[1]).split())
        self.assertIn("1 file copied from the wrong place in the BIOS folder, 1 downloaded. "
                      "The copies in the wrong place were left as they are.", text)

    def test_a_local_copy_is_no_download_speed(self):
        state = checked_state()
        press(state, "enter")
        mega = 1024 * 1024
        events = [(9.0, {"event": "found", **found("big.bin", "/media/old")}),
                  (9.0, {"event": "download", "platform": "retroarch", "files": 2,
                         "bytes": 300 * mega}),
                  (10.0, {"event": "downloaded", "dest": "big.bin", "ok": True, "reason": "",
                          "size": 200 * mega, "files_done": 1, "files_total": 2,
                          "bytes_done": 200 * mega, "bytes_total": 300 * mega}),
                  # The engine says which bytes came from this machine.
                  (10.0, {"event": "transfer", "bytes_local": 200 * mega,
                          "bytes_network": 0}),
                  (11.0, {"event": "progress", "files_done": 1, "files_total": 2,
                          "bytes_done": 201 * mega, "bytes_total": 300 * mega}),
                  (11.0, {"event": "transfer", "bytes_local": 200 * mega,
                          "bytes_network": mega}),
                  (12.0, {"event": "progress", "files_done": 1, "files_total": 2,
                          "bytes_done": 202 * mega, "bytes_total": 300 * mega}),
                  (12.0, {"event": "transfer", "bytes_local": 200 * mega,
                          "bytes_network": 2 * mega})]
        for when, event in events:
            state.now = when
            install.tui_receive(state, ("event", state.run_id, event))
        text = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn("1.0 MB/s, 1:38 left", text)


class CardsSpaceAndConfirm(unittest.TestCase):
    """Each card by its own files, Space on install, and a short card."""

    CARDS = {
        "muOS": ({"MUOS/": ""}, "retroarch", "MUOS/bios"),
        "Onion": ({".tmp_update/onionVersion/version.txt": "4.3.1\n"}, "retroarch", "BIOS"),
        "spruceOS": ({"spruce/": ""}, "retroarch", "BIOS"),
        "KNULLI": ({"system/batocera.conf": "a=1\nsystem.hostname=KNULLI\n"}, "knulli",
                   "bios"),
        "ROCKNIX": ({".config/system/configs/system.cfg": "root.password=rocknix\n"},
                    "rocknix", "roms/bios"),
        # Lakka's STORAGE partition, once RetroArch has written its config.
        "Lakka": ({".config/retroarch/retroarch.cfg":
                   'menu_driver = "xmb"\nsystem_directory = "/tmp/system"\n'},
                  "lakka", "system"),
    }

    def card(self, files: dict) -> Path:
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        for name, text in files.items():
            path = root / name
            if name.endswith("/"):
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
        return root

    # a handheld's card mounted on a computer.

    def test_each_card_by_its_own_files(self):
        for name, (files, plat, folder) in self.CARDS.items():
            with self.subTest(card=name):
                root = self.card(files)
                self.assertEqual(install.card_system(root), (plat, root / folder, name))

    def test_card_nothing_names_is_left_alone(self):
        self.assertIsNone(install.card_system(self.card({"roms/": "", "BIOS/": ""})))
        # Batocera's own share is its SHARE drive, read
        # by a batocera.conf that names no KNULLI.
        share = self.card({"system/batocera.conf": "system.hostname=BATOCERA\n"})
        self.assertEqual(install.card_system(share), ("batocera", share / "bios", "Batocera"))

    def test_the_card_rules_are_the_device_rules(self):
        # The folder and the marker come from the rule the device reads, so
        # they are never written twice.
        rules = {rule.name: rule for rule in install._card_rules()}
        self.assertLessEqual({"muOS", "Onion", "spruceOS", "CrossMix-OS", "Allium", "Koriki",
                              "KNULLI", "ROCKNIX"}, set(rules))
        # Only a marker on the part its BIOS folder is on names the card:
        # plumOS's and the Anbernic firmware's are on another part.
        for setup in install.card_setups():
            for rule in setup.rules:
                with self.subTest(system=setup.name, rule=rule.values):
                    self.assertEqual(rule.bios, setup.below)
        self.assertIn("ArkOS", rules)
        self.assertEqual(install.DEFAULT_DESTS["knulli"], Path("/userdata") / "bios")
        self.assertEqual(install.DEFAULT_DESTS["rocknix"], Path("/storage") / "roms/bios")

    def test_the_first_screen_offers_the_card_folder(self):
        root = self.card(self.CARDS["muOS"][0])
        with mock.patch.object(install, "_mounted_cards", return_value=[root]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, effects = install.tui_start(_args(), "linux")
        label = f"muOS SD card ({root.name})"
        self.assertEqual(state.setups, [("retroarch", root / "MUOS" / "bios", label)])
        text = screen_text(install.tui_view(state, 120, 40))
        self.assertIn(f"> {label}", text)
        self.assertIn(f"BIOS folder: {root / 'MUOS' / 'bios'}", text)
        (root / "MUOS" / "bios").mkdir()
        self.assertEqual(press(state, "enter"), [("fetch", "retroarch")])
        self.assertEqual(state.dest, root / "MUOS" / "bios")

    def test_drive_letter_names_the_card(self):
        self.assertEqual(install._mount_name(PureWindowsPath("E:\\")), "E:\\")
        self.assertEqual(install._mount_name(Path("/media/me/MUOS")), "MUOS")
        # under WSL the card screen listed "d (card or drive)".
        with mock.patch.dict(install._WSL, {"active": True}):
            self.assertEqual(install._mount_name(Path("/mnt/d")), "D:")
            self.assertEqual(install._mount_name(Path("/mnt/wslg")), "wslg")
        self.assertEqual(install._mount_name(Path("/mnt/d")), "d")

    def test_on_the_device_its_card_is_not_offered_twice(self):
        root = self.card(self.CARDS["muOS"][0])
        bound = Path("/run/muos/storage/bios")
        with mock.patch.object(install, "_mounted_cards", return_value=[root]), \
                mock.patch.object(install, "detect_platforms", return_value=[("retroarch",
                                                                              bound)]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.dict(install._DETECTED_OS, {("retroarch", bound): "muOS"}):
            state, _effects = install.tui_start(_args(), "linux")
        self.assertEqual([setup[1] for setup in state.setups], [bound])

    def test_browsing_to_the_card_root_uses_its_folder(self):
        root = self.card(self.CARDS["KNULLI"][0])
        with mock.patch.object(install, "_mounted_cards", return_value=[root]):
            rows, _error = install._browse_rows(REPO_ROOT / "tests")
        self.assertEqual(rows[2].label, f"{root} (KNULLI card)")
        state = fresh_state()
        install._choose(state, "knulli", root)
        self.assertEqual(state.dest, root / "bios")
        # Another platform's list keeps the folder it was given.
        install._choose(state, "batocera", root)
        self.assertEqual(state.dest, root)

    def test_the_command_line_writes_where_muos_reads(self):
        root = self.card(self.CARDS["muOS"][0])
        with FakeRepository() as repo:
            proc = install_run("--platform", "muos", "--dest", str(root), "--yes",
                               env=repo.env())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(f"muOS card: RetroArch files, in {root / 'MUOS' / 'bios'}", proc.stdout)
        self.assertEqual(sorted(path.name for path in root.iterdir()), ["MUOS"])
        self.assertTrue((root / "MUOS" / "bios" / "scph5501.bin").is_file())

    def test_folder_that_is_no_muos_card_is_refused(self):
        root = self.card({"roms/": ""})
        proc = install_run("--platform", "muos", "--dest", str(root), "--yes")
        self.assertEqual(proc.returncode, 1)
        self.assertIn(f"{root} is not a muOS SD card: no muOS files on it. muOS keeps "
                      "MUOS at the root of its card.", proc.stderr)
        # muOS always names its card: <card>/MUOS/bios would be refused the
        # same, the card's top folder is the remedy.
        self.assertIn("Name the top folder of the muOS card with --dest", proc.stderr)
        self.assertNotIn("<card>/", proc.stderr)
        self.assertEqual(list(root.iterdir()), [root / "roms"])
        # Its BIOS folder named outright is its card's, checked as the card
        # is: on a folder with no MUOS it is refused, as typed it was.
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            install.card_dest("muos", "retroarch", root / "MUOS" / "bios")
        card = self.card({"MUOS/bios/": ""})
        self.assertEqual(install.card_dest("muos", "retroarch", card / "MUOS" / "bios"),
                         ("retroarch", card / "MUOS" / "bios"))
        # On the device, the folder muOS binds it to.
        bound = Path("/run/muos/storage/bios")
        self.assertEqual(install.card_dest("muos", "retroarch", bound), ("retroarch", bound))
        # A list named by its own name says which list, not which card.
        self.assertEqual(install.card_dest("retroarch", "retroarch", root),
                         ("retroarch", root))

    def test_the_folder_named_is_compared_by_folders(self):
        """NOTMUOS/bios ended with MUOS/bios as text and was taken for a
        muOS card's folder."""
        root = self.card({"roms/": ""})
        stray = root / "NOTMUOS" / "bios"
        with self.assertRaises(SystemExit), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            install.card_dest("muos", "retroarch", stray)
        self.assertIn("does not exist", err.getvalue())
        card = self.card({"MUOS/bios/": ""})
        self.assertEqual(install.card_dest("muos", "retroarch", card / "muos" / "BIOS"),
                         ("retroarch", card / "muos" / "BIOS"))

    def test_card_two_systems_claim_says_so(self):
        root = self.card({"MUOS/": "", "spruce/": ""})
        self.assertIsNone(install.card_system(root))
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(install.card_dest("retroarch", "retroarch", root),
                             ("retroarch", root))
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("holds the files of muOS and spruceOS", lines[0])
        # The system named among them decides.
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(install.card_dest("muos", "retroarch", root),
                             ("retroarch", root / "MUOS/bios"))
        self.assertIn("muOS card", out.getvalue())

    # Space is X on PortMaster and Y on muxterm.

    def test_space_on_install_opens_the_confirm_screen(self):
        state = checked_state()
        self.assertEqual(install.tui_rows(state)[0].action, "install")
        self.assertEqual(press(state, " "), [("run", "confirm")])
        self.assertEqual(state.screen, "confirm")
        # The same plan comes back: the screen still waits for A.
        install.tui_receive(state, ("event", state.run_id, dict(CHECK)))
        self.assertEqual(install.tui_receive(state, ("ended", state.run_id, 0, [])), [])
        self.assertEqual(state.screen, "confirm")
        self.assertEqual(install.tui_rows(state)[0].action, "install")
        self.assertEqual(press(state, " "), [])
        self.assertEqual(state.screen, "confirm")
        self.assertEqual(press(state, "enter"), [("run", "install")])

    def test_space_never_closes_or_quits(self):
        for action in ("quit", "close"):
            with self.subTest(row=action):
                state = checked_state()
                if action == "close":
                    state.check = {**CHECK, "missing": 0, "wrong_hash": 0, "bytes_needed": 0}
                rows = install.tui_rows(state)
                state.focus["plan"] = next(i for i, r in enumerate(rows) if r.action == action)
                self.assertEqual(press(state, " "), [])
                self.assertIsNone(state.exit_code)
        state = checked_state()
        state.focus["plan"] = next(i for i, r in enumerate(install.tui_rows(state))
                                   if r.action == "options")
        press(state, " ")
        self.assertEqual(state.screen, "options")

    def test_enter_still_installs_in_three_presses(self):
        state = checked_state()
        self.assertEqual(press(state, "enter"), [("run", "install")])
        self.assertEqual(state.screen, "installing")

    # a card too small for the download.

    def test_a_stop_asked_for_says_only_the_outcome(self):
        """Start+Select (SIGTERM) or SIGHUP stops the child before it writes
        a summary: the farewell then listed the log's last lines."""
        state = checked_state()
        state.download = {"files": 50}
        state.finished = [("scph5501.bin", True, "")]
        state.tail = ["    [2/50] scph5501.bin ok",
                      "    Stopping. Files already installed are kept."]
        for code, shown in ((130, False), (1, True)):
            with self.subTest(code=code):
                state.code = code
                _title, lines = install.tui_outcome(state)
                self.assertEqual(any("[2/50]" in line for line in lines), shown, lines)

    def test_a_pack_installs_from_the_pack_not_the_network(self):
        """With --from-pack and no Wi-Fi, the plan said "to download", which
        on a handheld with no network read as a failure on its way."""
        state = checked_state()
        with mock.patch.object(install.LOCAL, "pack", HoldingPack()):
            headline = str(install.tui_view(state, 80, 24)[0])
            plan = "\n".join(str(line) for line in install.tui_view(state, 80, 24))
            state.summary = {"installed": 3, "failed": [], "up_to_date": 0}
            title, lines = install.tui_outcome(state)
        self.assertIn("to install from the pack", plan, headline)
        self.assertNotIn("to download", plan)
        self.assertEqual(lines[0], "3 files installed from the pack.")

    def test_another_folder_comes_first_when_space_is_short(self):
        state = checked_state({"free": 1024, "writable": True, "cores": []})
        self.assertEqual([row.label for row in install.tui_rows(state)[:2]],
                         ["Choose another folder", "Install anyway"])
        self.assertEqual(press(state, "enter"), [])
        self.assertEqual(state.screen, "folder")

    def test_offline_with_nothing_to_copy_offers_no_install_anyway(self):
        """Offline with nothing here to copy, Install is removed: a folder
        short of space then put "Install anyway" back, a run that could
        only fail every file."""
        state = checked_state({"free": 1024, "writable": False, "cores": []})
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            labels = [row.label for row in install.tui_rows(state)]
        self.assertEqual(labels[0], "Choose another folder")
        self.assertNotIn("Install anyway", labels)
        self.assertFalse(any(label.startswith("Install") for label in labels), labels)

    FULL_TAIL = [
        "  Checking existing files...",
        "    0/50 present (0 verified, 0 wrong hash)",
        "  Downloading 50 files (845.7 KB)...",
        "Not enough space on the drive holding /media/me/MUOS/MUOS/bios.",
        "  Needed: 1.2 GB. Free: 300.0 MB.",
        "  Free up 920.0 MB, or install to another drive:",
        "    python3 install.py --platform retroarch --dest '<folder on another drive>'",
    ]

    def test_full_card_is_said_in_words(self):
        root = self.card(self.CARDS["muOS"][0])
        state = checked_state()
        state.dest, state.log = root / "MUOS" / "bios", "/tmp/retrobios-tui-x/install.log"
        state.stack.append("result")
        state.code, state.tail = 2, list(self.FULL_TAIL)
        with mock.patch.object(install, "_mounted_cards", return_value=[root]):
            title, lines = install.tui_outcome(state)
        self.assertEqual(title, "Not enough space")
        self.assertEqual(lines[0], "The card is full: 1.2 GB needed, 300.0 MB free.")
        self.assertIn("Free some space, or run again and choose another folder.", lines)
        text = "\n".join(lines)
        for raw in ("Checking existing files", "Downloading", "stopped with code", "Details:"):
            self.assertNotIn(raw, text)
        self.assertFalse(install.tui_keeps_log(state))

    def test_advice_never_names_the_interface_list(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root writes to a read-only folder")
        folder = self.card({})
        folder.chmod(0o555)
        self.addCleanup(folder.chmod, 0o755)
        with FakeRepository() as repo:
            listed = repo.root / "install" / "retroarch.json"
            proc = install_run("--platform", "retroarch", "--dest", str(folder),
                               f"--manifest={listed}", "--yes",
                               env={**repo.env(), install.TUI_LIST_ENV: "1"})
        self.assertIn("sudo", proc.stdout + proc.stderr)
        self.assertNotIn("--manifest", proc.stdout + proc.stderr)

    # the BIOS folder line on a handheld screen.

    def test_the_plan_keeps_the_folder_at_handheld_sizes(self):
        zipped = "/home/me/a/long/path/to/the/Downloads/PSX BIOS.zip"
        for cols, rows in ((40, 12), (40, 15)):
            with self.subTest(size=f"{cols}x{rows}"):
                state = checked_state()
                state.dest = Path("/home/someone/with/a/long/path/.config/retroarch/system")
                state.found = [found("scph5500.bin", zipped)]
                state.cols, state.rows = cols, rows
                lines = [line.strip() for line in install.tui_view(state, cols, rows)]
                at = next(index for index, line in enumerate(lines)
                          if line.startswith("BIOS folder: "))
                # Whole, broken after a separator: cut in its middle at 40
                # columns, it was spelled one way on the plan and another on
                # the result.
                self.assertEqual(lines[at] + lines[at + 1], "BIOS folder: /home/someone/with/"
                                 "a/long/path/.config/retroarch/system")
                self.assertIn("1 found in PSX BIOS.zip,", " ".join(lines))
                self.assertNotIn("/home/me/a/long", " ".join(lines))

    # where the files came from.

    def test_the_result_says_what_came_from_the_card(self):
        state = checked_state()
        state.stack.append("result")
        state.code, state.download = 0, {"files": 5, "bytes": 10}
        state.local_dests = {"scph5500.bin": ("/media/me/OLD", ""),
                             "scph5501.bin": ("/media/me/OLD", ""),
                             "gba_bios.bin": (str(SYSTEM_DIR), "one folder too deep")}
        state.finished = [("scph5500.bin", True, ""), ("scph5501.bin", True, ""),
                          ("gba_bios.bin", True, ""), ("pcsx/extra.bin", True, ""),
                          ("fc/disksys.rom", False, "HTTP 404")]
        state.summary = {"installed": 4, "up_to_date": 0, "failed": [
            {"dest": "fc/disksys.rom", "reason": "HTTP 404"}]}
        _title, lines = install.tui_outcome(state)
        # One count, the failed file said as failed.
        self.assertEqual(lines[0], "2 files copied from OLD, 1 copied from the wrong place "
                                   "in the BIOS folder, 1 downloaded, 1 failed.")
        # The line mode's own sentence, from the same counts.
        self.assertEqual(lines[0], install.sources_line([("OLD", 2)], 1, 1, 0, failed=1))

    def test_run_that_copied_nothing_adds_no_line(self):
        state = install.TuiState()
        state.summary, state.finished = {"installed": 2, "failed": []}, [("a", True, "")]
        self.assertEqual(install._tui_sources(state, 2, 0), "")

    # the systems list.

    def systems_state(self) -> install.TuiState:
        state = checked_state()
        state.systems = [*state.systems,
                         {"system": "other", "name": "other", "files": 2, "present": 0,
                          "missing": 2, "wrong_hash": 0, "bytes_needed": 300},
                         {"system": "3do", "name": "3do", "files": 3, "present": 0,
                          "missing": 3, "wrong_hash": 0, "bytes_needed": 600}]
        state.files = [*state.files,
                       {"event": "file", "dest": "panafz1.bin", "systems": ["3do"],
                        "size": 100, "state": "missing"},
                       {"event": "file", "dest": "mame/hash/a.xml", "systems": ["3do", "mac"],
                        "size": 200, "state": "missing"},
                       {"event": "file", "dest": "mame/hash/b.xml", "systems": ["3do", "mac"],
                        "size": 300, "state": "missing"}]
        state.ticked |= {"other", "3do"}
        state.stack.append("systems")
        return state

    def test_the_other_row_is_named_and_explained(self):
        state = self.systems_state()
        rows = install.tui_rows(state)
        other = next(i for i, row in enumerate(rows) if row.value == "other")
        self.assertEqual(rows[other].label, "[x] Other systems and game engines")
        state.focus["systems"] = other
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("Other systems and game engines: what cores load for systems this "
                      "setup does not list", text)

    def test_shared_files_are_counted_apart(self):
        state = self.systems_state()
        rows = install.tui_rows(state)
        three = next(i for i, row in enumerate(rows) if row.value == "3do")
        self.assertEqual(rows[three].right, "1 file, 100 B + 2 shared")
        state.focus["systems"] = three
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("+2 shared: counted once", text)
        # The line mode counts the same files apart.
        self.assertIn("and 2 files, 500 B shared with other systems", install._system_sized([
            {"dest": "panafz1.bin", "size": 100, "systems": ["3do"]},
            {"dest": "a.xml", "size": 200, "systems": ["3do", "mac"]},
            {"dest": "b.xml", "size": 300, "systems": ["3do", "mac"]}]))
        narrow = install.tui_view(state, 40, 15)
        self.assertTrue(any("100 B + 2 shared" in line for line in narrow), narrow)

    # a file that cannot be supplied, by name, where it matters.

    def unavailable_state(self) -> install.TuiState:
        state = checked_state()
        state.manifest = {**MANIFEST, "system_titles": {"nintendo-gba": "Game Boy Advance"},
                          "omitted_files": [
                              {"dest": "gba_extra.bin", "system": "nintendo-gba",
                               "required": True, "reason": "not_found"},
                              {"dest": "optional.bin", "system": "nintendo-gba",
                               "required": False, "reason": "not_found"}]}
        state.stack.append("result")
        state.code, state.download = 0, {"files": 1, "bytes": 1}
        state.summary = {"installed": 1, "up_to_date": 0, "failed": []}
        return state

    def test_the_missing_file_is_named_with_its_system(self):
        state = self.unavailable_state()
        _title, lines = install.tui_outcome(state)
        self.assertIn("Not available here, and needed to start its emulator: gba_extra.bin "
                      "(Game Boy Advance). An owned copy goes in the BIOS folder.", lines)
        self.assertNotIn("collection", " ".join(lines))

    def test_it_is_left_out_when_it_does_not_concern_the_run(self):
        state = self.unavailable_state()
        state.ticked = {"sony-playstation"}
        self.assertEqual(install._unavailable_lines(state), [])
        state = self.unavailable_state()
        state.summary = {"installed": 1, "failed": [], "interrupted": True}
        self.assertFalse(any("Not available" in line for line in install.tui_outcome(state)[1]))

    # small fixes the audit listed.

    def fetch_failure(self, error: BaseException, env: dict | None = None) -> tuple:
        inbox = __import__("queue").Queue()
        with mock.patch.object(install, "_fetch_json", side_effect=error), \
                mock.patch.dict(os.environ, env or {}):
            for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
                if name not in (env or {}):
                    os.environ.pop(name, None)
            install._tui_fetch("retroarch", inbox, io.StringIO())
        _kind, _plat, title, lines, _code = inbox.get_nowait()
        return title, lines

    def test_the_clock_names_the_row_to_choose(self):
        import ssl

        error = urllib_error(ssl.SSLCertVerificationError("certificate is not yet valid"))
        words = install.network_words(error, today=install.datetime.date(1980, 1, 1))
        with mock.patch.object(install, "network_words", return_value=words):
            _title, lines = self.fetch_failure(error)
        self.assertTrue(lines[0].endswith("then choose Try again."), lines[0])

    def test_proxy_in_the_way_is_named_not_shown(self):
        error = urllib_error(ConnectionRefusedError(111, "Connection refused"))
        _title, lines = self.fetch_failure(
            error, {"HTTPS_PROXY": "http://me:secret@10.0.0.1:3128"})
        self.assertIn("HTTPS_PROXY is set, so the connection goes through a proxy: check "
                      "that it answers.", lines)
        self.assertNotIn("secret", " ".join(lines))
        _title, lines = self.fetch_failure(error)
        self.assertFalse(any("PROXY" in line for line in lines))

    def test_list_that_is_no_json_is_said_in_words(self):
        try:
            install.json.loads("<html>")
        except install.json.JSONDecodeError as cause:
            error = ValueError(f"invalid file list: {cause}")
            error.__cause__ = cause
        title, lines = self.fetch_failure(error)
        self.assertEqual(title, "The file list is not valid")
        self.assertNotIn("Expecting value", " ".join(lines))
        self.assertIn("a Wi-Fi sign-in page or a cut download looks like this.", lines[0])

    def test_the_preview_counts_its_files_only(self):
        state = checked_state()
        state.stack += ["options", "preview"]
        state.dry = dict(CHECK)
        state.dry_files = [{**FILES[0], "dest": f"f{n}.bin"} for n in range(40)]
        state.rows = 24
        lines = [line.strip() for line in install.tui_view(state, 80, 24)]
        self.assertIn("1-18 of 40", lines)

    def test_game_data_reads_without_a_double_negative(self):
        state = checked_state()
        label = next(row.label for row in install._option_rows(state)
                     if row.action == "game_data")
        self.assertEqual(label, "Game data: kept")
        state.no_game_data = True
        label = next(row.label for row in install._option_rows(state)
                     if row.action == "game_data")
        self.assertEqual(label, "Game data: left out")

    @in_full
    def test_the_plan_says_which_config_named_the_folder(self):
        config = HOME / ".config/retroarch/retroarch.cfg"
        with mock.patch.dict(install._RETROARCH_CONFIGS, {SYSTEM_DIR: (config, config.parent)}):
            text = "\n".join(install.tui_view(checked_state(), 80, 24))
        self.assertIn("Named by ~/.config/retroarch/retroarch.cfg", text)

    # The engine's own events (main, after the second audit).

    def test_the_speed_is_the_network_bytes(self):
        state = checked_state()
        state.stack.append("installing")
        state.run, state.running = "install", True
        install.tui_receive(state, ("event", state.run_id,
                                    {"event": "download", "files": 4, "bytes": 4 << 20}))
        for now, done, network in ((100.0, 1 << 20, 0), (102.0, 3 << 20, 1 << 20)):
            state.now = now
            install.tui_receive(state, ("event", state.run_id, {
                "event": "progress", "files_done": 1, "files_total": 4, "bytes_done": done,
                "bytes_total": 4 << 20}))
            install.tui_receive(state, ("event", state.run_id, {
                "event": "transfer", "bytes_local": done - network, "bytes_network": network}))
        text = "\n".join(install.tui_view(state, 80, 24))
        # 1 MB from the network in 2 s, whatever came from the old card.
        self.assertIn("512.0 KB/s, 0:02 left", text)

    @in_full
    def test_the_plan_says_what_the_scan_left_out(self):
        state = checked_state()
        state.from_folders = [Path("E:\\")]
        install._start_check(state)
        events = [{"event": "scanned", "folder": "E:\\", "files": 200000, "truncated": True,
                   "other_drives": ["E:\\D"]},
                  {"event": "unreadable", "platform": "retroarch", "folder": "E:\\",
                   "path": "E:\\bios\\scph5501.bin", "member": "", "reason": "Permission denied"},
                  {"event": "unreadable", "platform": "retroarch", "folder": "E:\\",
                   "path": "E:\\backup.zip", "member": "gba_bios.bin",
                   "reason": "it is encrypted, a password is needed"}]
        for event in [*FILES, *SYSTEMS, *events, CHECK]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={
                "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
            install.tui_receive(state, ("ended", state.run_id, 1, []))
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertIn("Read the first 200,000 files of E:\\.", text)
        self.assertIn("E:\\D is another drive: add it to copy from it too.", text)
        # The folder by its name: "your old card" was said of any folder.
        self.assertIn("2 files in E:\\ could not be read.", text)
        rows = install.tui_rows(state)
        state.focus["plan"] = next(i for i, row in enumerate(rows) if row.action == "unreadable")
        press(state, "enter")
        self.assertEqual(state.screen, "unreadable")
        self.assertEqual(install._pager_items(state), [
            "E:\\bios\\scph5501.bin: Permission denied",
            "E:\\backup.zip, gba_bios.bin: it is encrypted, a password is needed"])

    def test_the_interface_does_not_index_the_folders_itself(self):
        missing = REPO_ROOT / "tmp" / "no-such-old-card"
        err = io.StringIO()
        with mock.patch.object(install, "FolderIndex", side_effect=AssertionError("indexed")), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install, "tui_start", side_effect=AssertionError("opened")), \
                mock.patch.object(sys, "stderr", err):
            self.assertEqual(install.run_tui(_args(**{"from": [missing]})), 1)
        self.assertIn(f"Error: {missing} does not exist: --from names the folder", err.getvalue())

    # Work folders: only a kill no handler sees leaves one, and the next
    # run takes it away.

    def test_work_folders_left_behind_are_pruned(self):
        import subprocess

        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        gone = subprocess.Popen([sys.executable, "-c", "pass"])
        gone.wait()
        now = time.time()
        week = install.TUI_KEEP_SECONDS

        def folder(name: str, pid: int | None, kept: bool, age: float) -> Path:
            path = root / f"{install.TUI_WORK_PREFIX}{name}"
            path.mkdir()
            if pid is not None:
                (path / install.TUI_OWNER).write_text(str(pid))
            if kept:
                (path / install.TUI_KEPT).write_text("")
            os.utime(path, (now - age, now - age))
            return path

        killed = folder("killed", gone.pid, False, 60)
        running = folder("running", os.getpid(), False, 2 * week)
        failed = folder("failed", gone.pid, True, 60)
        failed_old = folder("failed-old", gone.pid, True, 2 * week)
        unknown = folder("unknown", None, False, 60)
        unknown_old = folder("unknown-old", None, False, 2 * week)
        other = root / "something-else"
        other.mkdir()
        # A stray or hostile owner file is an unknown owner: a number past
        # what a pid holds raised OverflowError, and 0 or -1 name a group.
        hostile = [folder(f"hostile{index}", None, False, 60)
                   for index in range(3)]
        for path, text in zip(hostile, ("9" * 40, "0", "-1")):
            (path / install.TUI_OWNER).write_text(text)
            self.assertIsNone(install._owner_alive(path))
        removed = install._prune_work_folders(root, now)
        self.assertEqual(sorted(removed), sorted([killed, failed_old, unknown_old]))
        for path in hostile:
            shutil.rmtree(path)
        self.assertEqual(sorted(path.name for path in root.iterdir()),
                         sorted(path.name for path in (running, failed, unknown, other)))


class IdleExit(unittest.TestCase):
    def test_the_variable(self):
        for value, seconds in (("30", 30.0), (" 2.5 ", 2.5), ("", None), ("0", None),
                               ("-4", None), ("soon", None), ("inf", None), ("nan", None)):
            with self.subTest(value=value):
                self.assertEqual(install.tui_idle_exit({install.TUI_IDLE_ENV: value}),
                                 seconds)
        self.assertIsNone(install.tui_idle_exit({}))

    def test_the_farewell(self):
        state = fresh_state()
        state.idle_closed, state.exit_code = True, 0
        self.assertEqual(install.tui_farewell(state),
                         ["RetroBIOS: No button pressed, closing."])

    def test_an_error_screen_closes_with_its_code(self):
        """Closed idle on "No internet: offline mode", the launcher read 0
        and showed nothing."""
        state = fresh_state()
        state.stack = ["setup", "checking"]
        install._fail(state, ["Give the file list with --manifest FILE."], 1)
        state.error_title = "No internet: offline mode"
        self.assertEqual(self.idle_close(state), 1)
        self.assertEqual(install.tui_farewell(state), [
            "RetroBIOS: No button pressed, closing.",
            "RetroBIOS: No internet: offline mode",
            "Give the file list with --manifest FILE."])

    def test_a_result_closes_with_the_install_code(self):
        state = fresh_state()
        state.stack = ["setup", "result"]
        state.code = 2
        state.summary = {"event": "summary", "mode": "install", "installed": 1,
                         "up_to_date": 0, "pending": 0,
                         "failed": [{"dest": "a.bin", "reason": "disk full"}],
                         "skipped": [], "left_out": [], "kept": [], "interrupted": False}
        state.dest = SYSTEM_DIR
        self.assertEqual(self.idle_close(state), 2)
        farewell = install.tui_farewell(state)
        self.assertEqual(farewell[:2], ["RetroBIOS: No button pressed, closing.",
                                        "RetroBIOS: Finished with errors"])

    def test_any_other_screen_closes_as_a_quit(self):
        """0 read as "everything asked for is installed" with nothing done."""
        state = fresh_state()
        state.stack = ["setup"]
        self.assertEqual(self.idle_close(state), install.QUIT_CODE)

    def idle_close(self, state: install.TuiState) -> int:
        """run_tui on state, no key ever pressed, closed by the idle timer."""
        class Quiet(Crash.FakeTerminal):
            def keys(self, timeout):
                time.sleep(0.01)
                return []

        out = io.StringIO()
        work = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, work, True)
        with mock.patch.object(install, "_TuiTerminal", Quiet), \
                mock.patch.object(install.tempfile, "mkdtemp", return_value=str(work)), \
                mock.patch.object(install, "tui_start", return_value=(state, [])), \
                mock.patch.object(install, "_open_local_sources"), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.dict(os.environ, {install.TUI_IDLE_ENV: "0.05"}), \
                mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", out):
            code = install.run_tui(_args())
        self.assertTrue(state.idle_closed)
        self.assertIn("No button pressed, closing.", out.getvalue())
        return code


class AReadErrorIsNotAClosedWindow(unittest.TestCase):
    """Any EIO read as the window closing: a failing SD card answers EIO
    too, and that run ended 129, no error.log, no launcher message."""

    def test_eio_counts_only_once_the_terminal_hung_up(self):
        import pty

        master, slave = pty.openpty()
        screen = open(os.dup(slave), "w", encoding="utf-8")  # noqa: SIM115
        terminal = mock.Mock(fd=slave, stdout=screen)
        try:
            card = OSError(errno.EIO, "Input/output error", "/media/card/bios/x.bin")
            self.assertFalse(install._closed_terminal(card, terminal))
            self.assertFalse(install._closed_terminal(
                OSError(errno.ENOENT, "No such file"), terminal))
            os.close(master)
            master = -1
            self.assertTrue(install._closed_terminal(card, terminal))
            self.assertTrue(install._closed_terminal(termios.error(errno.EIO, "gone"),
                                                     terminal))
        finally:
            with contextlib.suppress(OSError):
                screen.close()
            os.close(slave)
            if master >= 0:
                os.close(master)


class SaveDirectoryLeftOut(unittest.TestCase):
    """Files left out of the save directory are said."""

    UNPLACED = {"reason": "no_save_directory", "label": "no save directory", "files": 2,
                "required": 0}

    def _ended(self, manifest: dict) -> tuple:
        state = fresh_state()
        state.stack = ["setup"]
        with mock.patch.object(install.Path, "exists", return_value=True):
            install.tui_update(state, Key("enter"))
        install.tui_receive(state, ("manifest", "retroarch", manifest))
        summary = {"event": "summary", "mode": "check", "installed": 0, "up_to_date": 0,
                   "pending": 5, "failed": [], "skipped": [self.UNPLACED], "left_out": [],
                   "kept": [], "interrupted": False}
        for event in [*FILES, *SYSTEMS, CHECK, summary]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={
                "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
            install.tui_receive(state, ("ended", state.run_id, 1, []))
        return state, summary

    @in_full
    def test_a_list_that_holds_none_of_them_offers_no_folder(self):
        """RetroPie's list leaves its save files out with no hash or address:
        --save-dir installs none of them, and was advised again each run."""
        state, summary = self._ended(MANIFEST)
        # The count on the screen, why on Details.
        lines = ["2 files read from RetroArch's save directory left out.",
                 "RetroArch keeps it in no fixed place, and its file list holds none of them."]
        plan = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertIn(" ".join(lines), plan)
        self.assertNotIn("--save-dir", plan)
        state.stack.append("result")
        state.code = 0
        state.summary = {**summary, "mode": "install", "installed": 5}
        outcome = install.tui_outcome(state)[1]
        self.assertEqual([text for text in outcome if "save" in text or "place" in text],
                         lines)
        self.assertTrue(install._is_detail(outcome[outcome.index(lines[1])]))

    @in_full
    def test_files_left_out_of_the_save_directory_are_said(self):
        state = fresh_state()
        state.stack = ["setup"]
        with mock.patch.object(install.Path, "exists", return_value=True):
            install.tui_update(state, Key("enter"))
        install.tui_receive(state, ("manifest", "retroarch", {
            **MANIFEST, "save_directory": {"folder": "saves", "by_core": True}}))
        summary = {"event": "summary", "mode": "check", "installed": 0, "up_to_date": 0,
                   "pending": 5, "failed": [], "skipped": [self.UNPLACED], "left_out": [],
                   "kept": [], "interrupted": False}
        for event in [*FILES, *SYSTEMS, CHECK, summary]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={
                "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
            install.tui_receive(state, ("ended", state.run_id, 1, []))
        line = "2 files read from RetroArch's save directory left out. "
        plan = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        # The plan names the row that sets it, the result the option a
        # command carries.
        self.assertIn(line + "Choose it in Options, Save folder (--save-dir). Its place is "
                      "not known.", plan)
        state.stack.append("result")
        state.code = 0
        state.summary = {**summary, "mode": "install", "installed": 5}
        self.assertIn(line + "Choose it in Options, Save folder (--save-dir), next time.",
                      install.tui_outcome(state)[1])


class TheSaveFolderHasARow(unittest.TestCase):
    """A card on a PC left the save-directory files out and named
    --save-dir, which Options had no row for: the interface user had to
    leave it and type a command."""

    def state(self) -> install.TuiState:
        state = checked_state()
        state.manifest = {**MANIFEST, "save_directory": {"folder": "saves", "by_core": True}}
        return state

    def test_options_list_it_and_the_browser_sets_it(self):
        state = self.state()
        rows = install._option_rows(state)
        [row] = [row for row in rows if row.action == "savedir"]
        # Named as line mode names it, from the same rules.
        place = install.save_directory_for(state.dest, state.manifest, None)
        self.assertEqual((row.label, row.right),
                         (f"Save folder: {install._short_path(place.directory, HOME)}",
                          "--save-dir"))
        saves = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, saves, True)
        state.stack = ["setup", "plan", "options"]
        install._option(state, "savedir", 0)
        self.assertEqual(state.screen, "browse")
        self.assertIn("save directory", " ".join(" ".join(install.tui_view(state, 120, 40))
                                                 .split()))
        install._browse_to(state, saves)
        effects = install._activate(state, install.TuiRow("use", "Use this folder"))
        self.assertIn(("--save-dir", str(saves)), install.tui_flags(state))
        self.assertTrue(any(effect[0] == "run" for effect in effects), effects)
        self.assertEqual(install._save_folder_words(state), str(saves))

    def test_a_list_without_a_save_directory_has_no_row(self):
        self.assertNotIn("savedir", [row.action for row in install._option_rows(checked_state())])


class ACardSystemNamedOnAComputer(unittest.TestCase):
    """`--platform onion` on a PC wrote RetroArch's files into the PC's own
    ~/.config/retroarch/system, which Onion never reads: the system's list
    is RetroArch's, and so was the folder detection found for it."""

    ONION = {".tmp_update/onionVersion/version.txt": "4.3.1\n"}

    def card(self, files: dict) -> Path:
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text, encoding="utf-8")
        return root

    def test_the_systems_that_run_from_a_card(self):
        self.assertEqual(install.card_bound("onion", "retroarch"), ("Onion", "BIOS"))
        self.assertEqual(install.card_bound("muOS", "retroarch"), ("muOS", "MUOS/bios"))
        self.assertEqual(install.card_bound("spruceos", "retroarch"), ("spruceOS", "BIOS"))
        self.assertEqual(install.card_bound("knulli", "knulli"), ("KNULLI", "bios"))
        self.assertEqual(install.card_bound("nextui", "nextui"), ("NextUI", ""))
        self.assertIsNone(install.card_bound("retroarch", "retroarch"))
        self.assertIsNone(install.card_bound("batocera", "batocera"))

    def test_without_questions_the_run_names_the_card_and_writes_nothing(self):
        home = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, home, True)
        system = home / ".config" / "retroarch" / "system"
        system.mkdir(parents=True)
        (home / ".config" / "retroarch" / "retroarch.cfg").write_text(
            f'system_directory = "{system}"\n', encoding="utf-8")
        with FakeRepository() as repo:
            proc = install_run("--platform", "onion", "--yes",
                               env={**repo.env(), "HOME": str(home), "RETROBIOS_OS": "linux"})
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("Onion keeps its BIOS files on its SD card, not on this machine.",
                      proc.stderr)
        self.assertIn("--platform onion --dest /media/$USER/<card>", proc.stderr)
        self.assertEqual(list(system.iterdir()), [])

    def test_one_mounted_card_of_that_system_is_taken(self):
        onion, other = self.card(self.ONION), self.card({"roms/a": ""})
        with mock.patch.object(install, "_mounted_cards", return_value=[other, onion]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("onion", "retroarch", interactive=False)
        self.assertEqual(dest, onion / "BIOS")
        self.assertIn(f"Onion card found at {onion.name}, BIOS folder {onion / 'BIOS'}",
                      out.getvalue())

    def test_at_a_terminal_the_card_root_is_asked(self):
        onion = self.card(self.ONION)
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_ask", return_value=str(onion)) as ask, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("onion", "retroarch", interactive=True)
        self.assertEqual(dest, onion / "BIOS")
        self.assertIn("Mount the card, then type its top folder.", out.getvalue())
        ask.assert_called_once()
        knulli = self.card({"roms/a": ""})
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_ask", return_value=str(knulli)), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(install.card_install_dest("knulli", "knulli", True),
                             knulli / "bios")

    def ask(self, *answers: str):
        """_ask answering in turn, and the prompts it was asked."""
        given = iter(answers)
        asked: list = []

        def answer(prompt: str) -> str:
            asked.append(prompt)
            return next(given)
        return mock.patch.object(install, "_ask", side_effect=answer), asked

    def test_a_typed_root_that_does_not_exist_is_asked_again(self):
        """A typo four folders deep was created and
        filled, and a menu answer (8) became the card."""
        onion = self.card(self.ONION)
        typo = REPO_ROOT / "tmp" / "no-such" / "media" / "NEXT"
        patcher, asked = self.ask("8", str(typo), str(onion))
        with mock.patch.object(install, "_mounted_cards", return_value=[]), patcher, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("onion", "retroarch", interactive=True)
        self.assertEqual(dest, onion / "BIOS")
        self.assertEqual(len(asked), 3)
        # No card is listed: 8 is no number of the list, and no folder.
        self.assertIn("Type the card's top folder, Enter to look again, or q to quit.",
                      out.getvalue())
        self.assertIn("NEXT does not exist, or is not a folder. Type the top folder of the "
                      "Onion card.", out.getvalue())
        self.assertFalse((REPO_ROOT / "tmp" / "no-such").exists())

    def test_a_typed_root_that_is_no_card_of_that_system_is_asked_again(self):
        """A folder that was no Onion card ended the run."""
        blank, onion = self.card({"roms/a": ""}), self.card(self.ONION)
        patcher, asked = self.ask(str(blank), str(onion))
        with mock.patch.object(install, "_mounted_cards", return_value=[]), patcher, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("onion", "retroarch", interactive=True)
        self.assertEqual((dest, len(asked)), (onion / "BIOS", 2))
        self.assertIn(f"{blank} is not an Onion SD card: no Onion files on it. Onion keeps "
                      ".tmp_update at the root of its card.", out.getvalue())

    def test_a_minui_root_is_a_minui_card(self):
        blank = self.card({"roms/a": ""})
        minui = self.card({".system/version.txt": "NextUI-20250101\n", "Bios/x": ""})
        patcher, asked = self.ask(str(minui / "Bios"), str(blank), str(minui))
        with mock.patch.object(install, "_mounted_cards", return_value=[]), patcher, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("nextui", "nextui", interactive=True)
        self.assertEqual((dest, len(asked)), (minui, 3))
        self.assertIn(f"is inside a NextUI card, whose root is {minui}", out.getvalue())
        self.assertIn("is not a NextUI SD card: no NextUI files on it. NextUI keeps "
                      ".system/version.txt at the root of its card.", out.getvalue())

    def test_the_mounted_drives_are_listed_and_taken_by_number(self):
        """The screen lists the mounted cards, the
        prompt did not: it listed
        every drive, a muOS card beside Onion's question, and the muOS card
        taken by number made the run a muOS install."""
        muos, blank = self.card({"MUOS/bios/x": ""}), self.card({"roms/a": ""})
        first, second = (self.card({"system/batocera.conf": "system.hostname=KNULLI\n"})
                         for _card in range(2))
        patcher, asked = self.ask("4", "2")
        with mock.patch.object(install, "_mounted_cards",
                               return_value=[muos, first, blank, second]), \
                patcher, contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("knulli", "knulli", interactive=True)
        self.assertEqual((dest, len(asked)), (second / "bios", 2))
        self.assertIn(f"1) {first.name} (KNULLI card, {first})", out.getvalue())
        self.assertIn(f"2) {second.name} (KNULLI card, {second})", out.getvalue())
        self.assertNotIn(str(muos), out.getvalue())
        # KNULLI fills its card when it first starts, and
        # a blank drive is listed after its own cards, as on the screen.
        self.assertIn(f"3) {blank.name} (card or drive, {blank})", out.getvalue())
        self.assertIn("Type a number from 1 to 3, a folder, Enter to look again, or q to "
                      "quit.", out.getvalue())

    def test_creating_several_folders_on_the_card_is_asked(self):
        """N to the question ended the whole run where it
        meant "not that card"."""
        root = self.card({"roms/a.txt": ""})
        rocknix = root / "R"
        rocknix.mkdir()
        card = self.card({"roms/a": ""})
        make_card(card, "ROCKNIX")
        patcher, asked = self.ask(str(rocknix), "n", str(card))
        with mock.patch.object(install, "_mounted_cards", return_value=[]), patcher, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("rocknix", "rocknix", interactive=True)
        self.assertEqual(dest, card / "roms" / "bios")
        self.assertIn("[y/N]", asked[1])
        self.assertEqual(asked[2], "Card root, Enter to look again, q to quit: ")
        self.assertIn("Not created.", out.getvalue())
        self.assertFalse((rocknix / "roms").exists())

    def test_the_menu_asks_a_card_system_for_its_card(self):
        """ROCKNIX picked from the menu on a PC was
        offered /storage/roms/bios."""
        card = self.card({"roms/a": ""})
        make_card(card, "ROCKNIX")
        patcher, asked = self.ask(str(card))
        with mock.patch.object(install, "_choose_platform", return_value="rocknix"), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), patcher, \
                contextlib.redirect_stdout(io.StringIO()):
            chosen = install._prompt_manual_platform("linux")
        self.assertEqual(chosen, [("rocknix", card / "roms" / "bios")])
        self.assertEqual(asked, ["Card root, Enter to look again, q to quit: "])

    def test_a_card_of_another_system_is_not_offered(self):
        """A on the first mount wrote Onion's BIOS/ on a
        muOS card, which reads MUOS/bios."""
        muos, blank = self.card({"MUOS/bios/x": ""}), self.card({"roms/a": ""})
        found = [("retroarch", SYSTEM_DIR)]
        with mock.patch.object(install, "_mounted_cards", return_value=[muos, blank]), \
                mock.patch.object(install, "detect_platforms", return_value=found), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, effects = install.tui_start(_args(platform="onion"), "linux")
            self.assertEqual((state.screen, effects), ("folder", []))
            rows = install.tui_rows(state)
            text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertEqual([row.action for row in rows], ["browse", "type", "rescan"])
        self.assertEqual(state.focus["folder"], 0)
        self.assertIn("Where is the SD card?", text)
        self.assertIn("No Onion card is mounted. Insert it, then choose Look again.", text)

    def test_only_the_cards_of_that_system_are_listed(self):
        first, second = self.card(self.ONION), self.card(self.ONION)
        muos = self.card({"MUOS/bios/x": ""})
        state = fresh_state()
        state.stack = ["setup", "platforms"]
        state.filters["platforms"] = "onion"
        state.focus["platforms"] = 1
        with mock.patch.object(install, "_mounted_cards", return_value=[muos, first, second]):
            press(state, "enter")
            self.assertEqual(state.screen, "folder")
            rows = install.tui_rows(state)
            install.tui_update(state, Key("enter"))
        self.assertEqual([(row.action, row.value) for row in rows][:2],
                         [("card", first), ("card", second)])
        self.assertNotIn("rescan", [row.action for row in rows])
        self.assertEqual(state.dest, first / "BIOS")
        # Titled as the card found by itself.
        self.assertEqual(install.detected_os("retroarch", first / "BIOS"), "Onion")

    def test_look_again_finds_the_card_inserted(self):
        onion = self.card(self.ONION)
        mounts: list = []
        with mock.patch.object(install, "_mounted_cards", side_effect=lambda: list(mounts)), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, _effects = install.tui_start(_args(platform="onion"), "linux")
            press(state, "down", "down", "enter")
            self.assertEqual(state.status, "Still no Onion card is mounted.")
            mounts.append(onion)
            press(state, "enter")
            rows = install.tui_rows(state)
        self.assertEqual(rows[state.focus["folder"]].action, "card")
        self.assertEqual(state.status, "")

    def test_a_folder_that_is_no_card_of_that_system_is_refused(self):
        blank = self.card({"roms/a": ""})
        muos = self.card({"MUOS/bios/x": ""})
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, _effects = install.tui_start(_args(platform="onion"), "linux")
            press(state, "enter")
            self.assertEqual(state.screen, "browse")
            install._browse_to(state, blank)
            effects = press(state, "enter")
            self.assertEqual((effects, state.screen), ([], "browse"))
            self.assertIn("Not an Onion SD card: no Onion files on it.", state.status)
            self.assertIn(f"{blank} is not an Onion SD card", state.status_more)
            self.assertIsNone(state.dest)
            # a muOS card made the run a muOS install
            # without a word.
            install._browse_to(state, muos)
            press(state, "enter")
            # it is a card's top folder, of another card.
            self.assertEqual(state.status, "That is a muOS card. Insert the Onion card, or "
                             "go back and choose muOS.")
        self.assertIsNone(state.dest)

    def test_a_typed_card_root_is_checked_on_the_path_screen(self):
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, _effects = install.tui_start(_args(platform="rocknix"), "linux")
            press(state, "down", "enter")
            self.assertEqual(state.screen, "path")
            state.path_text = str(REPO_ROOT / "tmp" / "no-such-card")
            effects = press(state, "enter")
        self.assertEqual((effects, state.screen), ([], "path"))
        self.assertEqual("That folder does not exist. Choose the card's top folder.",
                         state.status)

    def test_a_dest_that_is_no_card_of_that_system_is_refused(self):
        blank = self.card({"roms/a": ""})
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, effects = install.tui_start(_args(platform="onion", dest=str(blank)),
                                               "linux")
        self.assertEqual((effects, state.screen), ([], "folder"))
        self.assertIn("Not an Onion SD card", state.status)

    def test_change_folder_names_the_folder_it_reuses(self):
        """Use this folder on the card screen named
        nothing."""
        onion = self.card(self.ONION)
        state = checked_state()
        state.platform, state.card_bound = "retroarch", ("Onion", "BIOS")
        state.dest = onion / "BIOS"
        press(state, "o")
        rows = install.tui_rows(state)
        state.focus["options"] = [row.action for row in rows].index("folder")
        press(state, "enter")
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertEqual(state.screen, "folder")
        self.assertIn("Where is the SD card?", text)
        self.assertIn("The BIOS folder chosen for Onion:", text)
        self.assertEqual(state.folder_default, onion / "BIOS")

    def test_the_interface_takes_the_one_onion_card_mounted(self):
        onion = self.card(self.ONION)
        (onion / "BIOS").mkdir()
        found = [("retroarch", SYSTEM_DIR)]
        with mock.patch.object(install, "_mounted_cards", return_value=[onion]), \
                mock.patch.object(install, "detect_platforms", return_value=found), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, effects = install.tui_start(_args(platform="onion"), "linux")
        self.assertEqual(effects, [("fetch", "retroarch")])
        self.assertEqual(state.dest, onion / "BIOS")

    def test_on_the_device_its_own_folder_is_used(self):
        device = Path("/mnt/SDCARD/BIOS")
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms",
                                  return_value=[("retroarch", device)]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.dict(install._DETECTED_OS, {("retroarch", device): "Onion"}), \
                mock.patch.object(install.Path, "exists", return_value=True):
            state, effects = install.tui_start(_args(platform="onion"), "linux")
        self.assertEqual(effects, [("fetch", "retroarch")])
        self.assertEqual(state.dest, device)


class TheSetupFilterKnowsDevices(unittest.TestCase):
    """The filter found nothing for steam deck, r36s,
    trimui or retroid, and miyoo found RetroArch with muOS, JELOS... beside it."""

    TYPED = {
        "steam deck": {"retroarch", "batocera", "emudeck", "retrodeck"},
        # MinUI and MyMinUI list their devices, and on
        # a computer an Android device is no RetroArch of this machine's.
        "r36s": {"retroarch", "rocknix", "myminui"},
        "rg35xx": {"retroarch", "rocknix", "knulli", "minui", "myminui"},
        "trimui": {"retroarch", "knulli", "minui", "nextui"},
        "retroid": {"rocknix", "knulli"},
        "miyoo": {"retroarch", "knulli", "minui", "myminui"},
        "anbernic": {"retroarch", "rocknix", "amberelec", "knulli", "minui", "myminui"},
        "odin": {"rocknix"},
        "ayn": {"retroarch", "rocknix"},
        "rp5": {"rocknix", "knulli"},
        "rog ally": {"retroarch", "emudeck", "retrobat", "bizhawk"},
        "onion": {"retroarch"},
    }

    def rows(self, needle: str) -> list:
        state = fresh_state()
        state.stack = ["platforms"]
        state.filters["platforms"] = needle
        return [row for row in install.tui_rows(state)
                if row.action in ("platform", "cardsystem")]

    def test_each_device_finds_every_setup_it_runs(self):
        for needle, setups in self.TYPED.items():
            with self.subTest(needle=needle):
                self.assertEqual({row.value[0] if row.action == "cardsystem" else row.value
                                  for row in self.rows(needle)}, setups)

    def test_the_right_column_names_what_matched(self):
        rows = self.rows("miyoo")
        # MiyooCFW stayed on the
        # RetroArch row, which opened this computer's folder.
        self.assertNotIn("retroarch", [row.value for row in rows if row.action == "platform"])
        self.assertEqual([row.label for row in rows if row.action == "cardsystem"],
                         ["Allium, SD card", "Koriki, SD card", "MiyooCFW, SD card",
                          "Onion, SD card", "spruceOS, SD card"])
        spruce = {row.label: row for row in rows}["spruceOS, SD card"]
        self.assertEqual(spruce.right, "Miyoo A30, Miyoo Flip, Miyoo Mini, Miyoo Mini Plus, "
                         "Miyoo Mini Flip")
        # Cut at a comma, never inside a name ("Miyoo ...s").
        self.assertIn("Miyoo A30, Miyoo Flip, +3", spruce.narrow)
        line = str(install._row_line(spruce, False, 60))
        self.assertTrue(line.rstrip().endswith(("+1", "+2", "+3", "+4")), line)
        deck = {row.value: row for row in self.rows("steam deck")}
        self.assertEqual(deck["retroarch"].right, "Steam Deck")
        self.assertEqual({row.value: row for row in self.rows("")}["retroarch"].right, "")

    def test_the_handheld_lists_are_the_guides(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("pyyaml is not installed")

        guides = yaml.safe_load((REPO_ROOT / "platforms" / "_guides.yml").read_text())
        for system in guides["handheld_guide"]["systems"]:
            if system.get("devices"):
                with self.subTest(system=system["name"]):
                    self.assertEqual(install._SETUP_DEVICES[system["name"]],
                                     tuple(str(name) for name in system["devices"]))


class ACardSetupIsOneDesign(unittest.TestCase):
    """A setup that runs from
    its SD card, chosen on a computer, always asks for that card."""

    def platforms(self, needle: str = "") -> install.TuiState:
        state = fresh_state()
        state.stack = ["setup", "platforms"]
        state.filters["platforms"] = needle
        state.focus["platforms"] = 1
        return state

    def test_a_handheld_typed_in_the_filter_asks_for_its_card(self):
        for needle in ("onion", "miyoo mini", "rg35xx", "r36s", "arkos", "anbernic"):
            with self.subTest(needle=needle):
                state = self.platforms(needle)
                with mock.patch.object(install, "_mounted_cards", return_value=[]):
                    row = install.tui_rows(state)[1]
                    effects = press(state, "enter")
                    text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
                plat, name = row.value if row.action == "cardsystem" else (row.value,) * 2
                self.assertEqual((effects, state.screen), ([], "folder"))
                self.assertIsNotNone(state.card_bound)
                self.assertEqual(state.card_bound, install.card_bound(name, plat))
                self.assertIn("Where is the SD card?", text)
                self.assertNotIn("default", [r.action for r in install.tui_rows(state)])
                self.assertNotIn(str(SYSTEM_DIR), text)

    def test_retroarch_typed_is_still_this_computer(self):
        state = self.platforms("retroarch")
        press(state, "enter")
        self.assertIsNone(state.card_bound)
        self.assertEqual(state.folder_default, SYSTEM_DIR)

    def test_a_card_backed_out_of_is_forgotten(self):
        state = fresh_state()
        state.stack = ["setup"]
        state.focus["setup"] = 2
        press(state, "enter")
        state.focus["platforms"] = install._platform_focus(state, "rocknix")
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            press(state, "enter")
            self.assertEqual(state.card_bound, ("ROCKNIX", "roms/bios"))
            press(state, "esc", "esc")
            self.assertEqual(state.screen, "setup")
            state.focus["setup"] = 0
            with mock.patch.object(install.Path, "exists", return_value=True):
                press(state, "enter")
        self.assertIsNone(state.card_bound)
        self.assertEqual((state.platform, state.dest), ("retroarch", SYSTEM_DIR))
        install._open_folder_screen(state, state.dest, "chosen")
        title = install.tui_view(state, 80, 24)[0]
        self.assertIn("Which folder?", title)
        self.assertNotIn("card", [row.action for row in install.tui_rows(state)])

    def test_on_the_device_its_own_folder_is_offered(self):
        share = Path("/userdata/bios")
        state = fresh_state()
        state.setups = [("knulli", share, "KNULLI")]
        state.stack = ["setup", "platforms"]
        state.focus["platforms"] = install._platform_focus(state, "knulli")
        with mock.patch.dict(install._DETECTED_OS, {("knulli", share): "KNULLI"}), \
                mock.patch.object(install, "_mounted_cards", return_value=[]):
            press(state, "enter")
            rows = [row.action for row in install.tui_rows(state)]
            text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertEqual(rows, ["default", "browse", "type"])
        self.assertEqual((state.folder_default, state.folder_kind), (share, "found"))
        self.assertIn("Which folder? KNULLI reads its BIOS files from: /userdata/bios", text)
        self.assertNotIn("No KNULLI card is mounted", text)


class OneSystemInFewPresses(unittest.TestCase):
    """One system with a controller took 15 presses on
    the fixture list, about 60 on muxterm, which has no page key."""

    # The buttons each route sends, as the keys the interface reads.
    PADS = {
        "gptokeyb": {"A": "enter", "B": "esc", "X": " ", "Start": "enter", "R1": "pgdn",
                     "L1": "pgup"},
        "muxterm": {"A": "enter", "B": "esc", "X": " ", "Start": "enter", "R1": "right",
                    "L1": "left"},
    }

    def long_list(self, pad: str) -> install.TuiState:
        state = checked_state()
        state.pad = pad
        state.cols, state.rows = 40, 15
        state.systems = [{"event": "system", "platform": "retroarch", "system": f"sys-{n:02d}",
                          "name": f"System {n:02d}", "files": 1, "present": 0, "missing": 1,
                          "wrong_hash": 0, "bytes_needed": 10} for n in range(66)]
        state.ticked = {row["system"] for row in state.systems}
        state.focus["plan"] = next(i for i, row in enumerate(install.tui_rows(state))
                                   if row.action == "install")
        return state

    def press_button(self, state, pad: str, button: str) -> list:
        name = self.PADS[pad].get(button, button)
        return install.tui_update(state, Key("char", name) if len(name) == 1 else Key(name))

    def go_to(self, state, pad: str, target: str, paging: bool) -> int:
        """Presses from the focus to the target system, or to the row of that
        action (none), as a person does."""
        count = 0
        while True:
            rows = install.tui_rows(state)
            focus = state.focus.get("systems", 0)
            index = next(i for i, row in enumerate(rows)
                         if target in (row.value, row.action))
            if index == focus:
                return count
            # A page is the rows drawn.
            page = install._page_step(state)
            if index > focus:
                button = "R1" if paging and index - focus >= page else "down"
            else:
                button = "L1" if paging and focus - index >= page else "up"
            self.press_button(state, pad, button)
            count += 1

    def presses(self, pad: str, fast: bool) -> int:
        """From the plan to the run that installs sys-45 alone, with the
        setup's A before it."""
        state = self.long_list(pad)
        count = 1
        for button in ("down", "A"):
            self.press_button(state, pad, button)
            count += 1
        self.assertEqual(state.screen, "systems")
        # On its first system, None at the list's end.
        self.assertEqual(install.tui_rows(state)[state.focus["systems"]].action, "system")
        paging = pad != "muxterm" or fast
        # Up from the first item wraps to the list's end: Done, then None.
        while install.tui_rows(state)[state.focus["systems"]].action != "none":
            self.press_button(state, pad, "up")
            count += 1
        self.press_button(state, pad, "A")
        count += 1
        count += self.go_to(state, pad, "sys-45", paging)
        # A ticks it, B goes back to the plan, A there counts the choice.
        self.press_button(state, pad, "A")
        self.press_button(state, pad, "B")
        effects = self.press_button(state, pad, "A")
        count += 3
        self.assertEqual(state.ticked, {"sys-45"})
        self.assertEqual(effects, [("run", "confirm")])
        # Install on the confirm screen, then Exit on the result.
        return count + 2

    def test_presses_before_and_after(self):
        # The audit's path, A Down A Up Up A R1 x5 X Start A A. Before the
        # fast path it took 17 presses here, 57 on muxterm (None kept the
        # focus, and muxterm had no page key).
        # A page is the rows drawn, ten here where it
        # was nine: sys-45 is four pages and five Downs away, not five pages.
        # None now at the list's end, three presses up
        # from the first system: the list wraps. fast pages down to sys-45.
        self.assertEqual(self.presses("gptokeyb", fast=True), 21)
        self.assertEqual(self.presses("muxterm", fast=False), 57)
        self.assertEqual(self.presses("muxterm", fast=True), 21)

    def test_a_on_a_system_with_none_ticked_takes_it_alone(self):
        state = self.long_list("keys")
        state.stack.append("systems")
        state.ticked = set()
        state.focus["systems"] = 5
        text = install.tui_view(state, 80, 24)[-1]
        self.assertIn("Enter Tick", text)
        focused = install.tui_rows(state)[5].value
        self.assertEqual(press(state, "enter"), [])
        self.assertEqual(state.ticked, {focused})

    def test_enter_still_continues_with_the_ticks_as_they_are(self):
        state = self.long_list("keys")
        state.stack.append("systems")
        state.focus["systems"] = 5
        # nothing runs from the list. A unticks the system
        # in focus, B goes back to the plan.
        self.assertEqual(press(state, "enter"), [])
        self.assertEqual((state.screen, len(state.ticked)), ("systems", 65))
        press(state, "esc")
        self.assertEqual(state.screen, "plan")

    def test_left_and_right_page_inside_muxterm_only(self):
        for pad in ("muxterm", "gptokeyb_muxterm", "gptokeyb"):
            with self.subTest(pad=pad):
                state = self.long_list(pad)
                state.stack.append("systems")
                state.focus["systems"] = 3
                press(state, "right")
                paged = pad != "gptokeyb"
                self.assertEqual(state.focus["systems"] > 4, paged)
                self.assertEqual(len(state.ticked), 66)
                state.help = True
                help_text = " ".join(install.tui_view(state, 80, 24))
                self.assertEqual("D-pad Left/Right" in help_text, paged)

    def test_a_short_list_opens_on_its_first_system(self):
        state = checked_state()
        state.focus["plan"] = next(i for i, row in enumerate(install.tui_rows(state))
                                   if row.action == "systems")
        press(state, "enter")
        self.assertEqual(install.tui_rows(state)[state.focus["systems"]].action, "system")


class DataFilesHaveASize(unittest.TestCase):
    """"8179 files to download, 6.6 GB, and 2636 data
    files", the data files with no size."""

    @in_full
    def test_the_plan_gives_the_data_files_size(self):
        state = fresh_state()
        state.stack = ["setup"]
        with mock.patch.object(install.Path, "exists", return_value=True):
            install.tui_update(state, Key("enter"))
        install.tui_receive(state, ("manifest", "retroarch", MANIFEST))
        check = {**CHECK, "data_missing": 2636}
        data = {"event": "data", "platform": "retroarch", "files": 2636,
                "bytes": 412 * 1024 ** 2}
        for event in [*FILES, *SYSTEMS, check, data]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={
                "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
            install.tui_receive(state, ("ended", state.run_id, 1, []))
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertIn("and 2636 data files (412.0 MB)", text)


class ThePagerCountsLines(unittest.TestCase):
    """At 40x12 the result read "1-2 of 5" over eight
    lines, counting paragraphs, and its last paragraph was cut."""

    def result_state(self, cols: int, rows: int) -> install.TuiState:
        state = checked_state()
        state.stack.append("result")
        state.code, state.summary = 0, {"installed": 3}
        state.dest = Path("/media/" + "long-folder-name/" * 12)
        state.cols, state.rows = cols, rows
        return state

    def test_the_last_line_is_reachable_at_every_size(self):
        for cols, rows in (*SIZES, (50, 13), (60, 14)):
            with self.subTest(size=f"{cols}x{rows}"):
                state = self.result_state(cols, rows)
                width = min(cols, install.TUI_MAX_WIDTH) - 2
                # The result keeps a path whole (whole=True): its rows after
                # it are left to the terminal's folding ("cont").
                wrapped = install._text_lines(install._pager_items(state), width, True)
                last = [line for line in wrapped if line.style != "cont"][-1]
                press(state, "end")
                screen = install.tui_view(state, cols, rows)
                body = [line.rstrip() for line in screen[2:-1]]
                self.assertIn(" " + str(last).rstrip(), body)
                if len(wrapped) > rows - 3:
                    self.assertTrue(any(re.fullmatch(rf" \d+-{len(wrapped)} of {len(wrapped)}",
                                                     line) for line in body), body)

    @in_full
    def test_the_counter_moves_one_line_per_press(self):
        state = self.result_state(40, 12)
        first = [line for line in install.tui_view(state, 40, 12) if " of " in line][-1]
        self.assertRegex(first, r"^ 1-8 of \d+")
        press(state, "down")
        second = [line for line in install.tui_view(state, 40, 12) if " of " in line][-1]
        self.assertRegex(second, r"^ 2-9 of \d+")


class OfflineInTheInterface(unittest.TestCase):
    """--offline in the full screen: a "No connection" error offering a Try
    again that can never work, and a plan counting downloads the run
    forbids."""

    def setUp(self):
        # The value --offline gives the variable.
        patcher = mock.patch.dict(os.environ,
                                  {install.OFFLINE_VARIABLE: install.OFFLINE_FLAG_VALUE})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_variable_is_named_when_it_made_the_run_offline(self):
        """"(--offline)" and "without --offline" with
        RETROBIOS_INSTALL_OFFLINE=1 and no --offline: nothing to remove."""
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            inbox = queue.Queue()
            install._tui_fetch("retroarch", inbox, io.StringIO())
            text = " ".join(inbox.get_nowait()[3])
            self.assertIn("(RETROBIOS_INSTALL_OFFLINE=1)", text)
            self.assertIn("with RETROBIOS_INSTALL_OFFLINE unset", text)
            self.assertNotIn("--offline", text)
            plan = " ".join(" ".join(install.tui_view(checked_state(), 120, 40)).split())
            self.assertIn("which RETROBIOS_INSTALL_OFFLINE=1 does not use", plan)
            self.assertNotIn("without --offline", plan)

    def test_no_list_names_the_ways_that_work(self):
        inbox = queue.Queue()
        install._tui_fetch("retroarch", inbox, io.StringIO())
        kind, plat, title, lines, code = inbox.get_nowait()
        self.assertEqual((kind, title, code), ("manifest_failed",
                                               "No internet: offline mode", 1))
        text = " ".join(lines)
        for words in ("--manifest", "--from-pack", "without --offline"):
            self.assertIn(words, text)
        state = fresh_state()
        state.stack = ["setup"]
        with mock.patch.object(install.Path, "exists", return_value=True):
            install.tui_update(state, Key("enter"))
        install.tui_receive(state, (kind, plat, title, lines, code))
        self.assertEqual(state.screen, "error")
        self.assertNotIn("retry", [row.action for row in install.tui_rows(state)])
        view = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn("No internet: offline mode", view)
        self.assertNotIn("Try again", view)

    def test_the_plan_offers_no_download(self):
        state = checked_state()
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertNotIn("to download", text)
        self.assertIn("need the internet, which --offline does not use", text)
        self.assertNotIn("install", [row.action for row in install.tui_rows(state)])
        # A file found on this machine can still be copied.
        state.found = [{"event": "found", "platform": "retroarch", "dest": FILES[0]["dest"],
                        "folder": "/media/old", "path": "/media/old/scph5500.bin",
                        "member": "", "reason": ""}]
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertIn("1 found in old,", text)
        self.assertIn("need the internet (--offline)", text)
        self.assertEqual(install.tui_rows(state)[0].action, "install")
        self.assertIn("--offline", install.tui_command(state))


class BackTicksAndSaveFolder(unittest.TestCase):
    """Going back keeps the ticks, and the save folder is said once."""

    def long_list(self) -> install.TuiState:
        state = OneSystemInFewPresses().long_list("keys")
        state.cols, state.rows = 80, 24
        return state

    def test_back_from_none_keeps_the_ticks_it_opened_with(self):
        state = self.long_list()
        everything = set(state.ticked)
        press(state, "down", "enter")
        # The list opens on its first system, None at its end.
        self.assertEqual(install.tui_rows(state)[state.focus["systems"]].action, "system")
        press(state, "n")
        self.assertEqual(state.ticked, set())
        self.assertEqual(install._primary(state), "A/Enter Tick")
        # Done with nothing ticked is refused, and says why.
        press(state, "esc")
        self.assertEqual(state.screen, "systems")
        self.assertIn("No system is ticked", " ".join(install.tui_view(state, 80, 24)))
        press(state, "a", "esc")
        self.assertEqual(state.screen, "plan")
        self.assertEqual(state.ticked, everything)
        text = " ".join(install.tui_view(state, 80, 24))
        self.assertNotIn("No system is ticked", text)

    def test_the_page_says_where_the_list_opens(self):
        """wiki/installer.md said a long list opens on None, where A
        unticked every system as the first press: the focus moved to the
        first system, and the page kept the old words."""
        state = self.long_list()
        self.assertGreater(len(state.systems), install.TUI_LONG_LIST)
        press(state, "down", "enter")
        rows = install.tui_rows(state)
        self.assertEqual(state.focus["systems"],
                         next(i for i, row in enumerate(rows) if row.action == "system"))
        self.assertEqual([row.action for row in rows][-3:], ["all", "none", "done"])
        page = " ".join((REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8").split())
        self.assertNotIn("opens on **None**", page)
        self.assertIn("It opens on its first system, every system ticked", page)
        self.assertIn("**None** (`a` and `n`) sit at the end of the list", page)

    def test_back_after_a_choice_keeps_the_choice(self):
        state = self.long_list()
        press(state, "down", "enter", "enter")
        press(state, " ")
        chosen = set(state.ticked)
        press(state, "esc")
        self.assertEqual((state.screen, state.ticked), ("plan", chosen))

    def test_confirm_offline_with_nothing_on_hand_has_no_install(self):
        state = checked_state()
        state.stack.append("confirm")
        state.dry = dict(CHECK)
        state.dry_files = [dict(event, state="missing") for event in FILES]
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            rows = [row.action for row in install.tui_rows(state)]
            text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
            self.assertEqual(rows, ["back"])
            self.assertIn("Copy them from an old card or a folder", text)
            state.found = [{"event": "found", "platform": "retroarch",
                            "dest": FILES[0]["dest"], "folder": "/media/old",
                            "path": "/media/old/x", "member": "", "reason": ""}]
            self.assertEqual(install.tui_rows(state)[0].action, "install")

    def test_the_checking_clock_starts_at_zero(self):
        state = install.TuiState()
        self.assertLess(abs(state.now - time.monotonic()), 5)

    @in_full
    def test_a_pack_installs_from_the_pack(self):
        state = checked_state()
        state.found = [{"event": "found", "platform": "retroarch", "dest": FILES[0]["dest"],
                        "folder": "/media/old", "path": "/media/old/x", "member": "",
                        "reason": "misplaced"}]
        with mock.patch.object(install.LOCAL, "pack", mock.Mock()):
            text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
            # one count, "4 files to install" above "3 from
            # the pack", where "3 to install from the pack" sat over "4".
            self.assertIn("4 files to install, 1.0 MB", text)
            self.assertIn("3 from the pack, 1 copied from this machine", text)
            self.assertNotIn("downloaded", text)
            self.assertNotIn("of them", text)
            state.finished = [(FILES[0]["dest"], True, ""), (FILES[1]["dest"], True, "")]
            state.local_dests = {FILES[0]["dest"]: ("/media/old", "misplaced")}
            self.assertIn("1 from the pack", install._tui_sources(state, 2, 0))

    def test_the_wrong_place_screen_says_the_copies_stay(self):
        state = checked_state()
        state.stack.append("misplaced")
        self.assertEqual(install._pager_items(state)[0],
                         "They are copied where the emulators read them. The copies found stay "
                         "where they are.")

    def test_the_save_folder_is_a_line_of_its_own(self):
        state = checked_state()
        saves = {"files": 1, "folder": str(HOME / ".config" / "retroarch" / "saves" / "<core>")}
        lines = install._saves_lines(state, saves)
        # In words: "saves/<core>" read as a folder named <core>.
        # The folder at the BIOS folder's indent.
        self.assertEqual(lines, ["1 file read from RetroArch's save directory goes to a "
                                 "folder per core under:", "  ~/.config/retroarch/saves"])

    def test_the_shared_note_is_one_line(self):
        state = self.long_list()
        state.cols, state.rows = 40, 12
        state.files = [{"event": "file", "dest": "mame.zip", "size": 10,
                        "systems": ["sys-00", "sys-01"]}]
        state.stack.append("systems")
        state.focus["systems"] = install._first_item(state)
        lines = install.tui_view(state, 40, 12)
        self.assertIn(" Shared, counted once", lines)

    def test_the_save_folder_remedy_is_the_same_on_both_screens(self):
        summary = {"skipped": [{"reason": "no_save_directory", "files": 1}]}
        state = checked_state()
        state.manifest = {**state.manifest, "save_directory": {"folder": "saves",
                                                               "by_core": True}}
        lines = install._unplaced_lines(summary, state)
        self.assertIn("Options, Save folder (--save-dir)", lines[0])

    def test_a_size_keeps_its_unit(self):
        for width in range(20, 45):
            for line in install._wrap("2 files to install from the pack, 5.1 KB", width):
                self.assertNotEqual(line.strip(), "KB")

    def test_the_miyoo_bar_names_the_tick(self):
        state = self.long_list()
        state.pad = "miyoo"
        press(state, "down", "enter")
        state.ticked = set()
        state.focus["systems"] = install._first_item(state)
        bar = install.tui_view(state, 40, 15)[-1]
        # A is Space on a Miyoo, and ticks as Start does.
        self.assertTrue(bar.strip().startswith("A Tick"))
        # the way out was the entry given up at 40 columns.
        self.assertIn("R2 Done", bar)

    def test_muxterm_help_names_no_home_key(self):
        state = self.long_list()
        state.pad = "muxterm"
        press(state, "down", "enter")
        keys = [key for key, _what in install._help_lines(state)]
        self.assertNotIn("Home/End, g/G", keys)
        state.pad = "keys"
        self.assertIn("Home/End, g/G", [key for key, _what in install._help_lines(state)])


class LineModeOffline(unittest.TestCase):
    """The line mode under --offline asked to
    download, and said nothing of the data files."""

    @unittest.skipUnless(pyte and pty and hasattr(pty, "fork"),
                         "the line mode run needs pyte and a pty")
    def test_nothing_is_offered_that_cannot_come(self):
        with FakeRepository() as repo:
            env = {**repo.env(), "TERM": "xterm", install.OFFLINE_VARIABLE: "1"}
            term = Pty(["--plain", "--manifest", str(repo.root / "install" / "retroarch.json"),
                        "--dest", str(repo.dest), "--offline"], env)
            term.wait("q) quit")
            term.send("\r")
            code = term.close()
            # Read as words: a terminal gets the status words painted.
            out = install.unpainted(term.raw.decode("utf-8", "replace"))
        self.assertIn("--offline: only the files found on this machine are installed, and no "
                      "--from names a folder to copy them from.", out)
        # nothing to copy from, nothing to install.
        self.assertIn("Enter) check the BIOS folder, nothing can be downloaded", out)
        self.assertIn("f) copy from a folder or an old card", out)
        self.assertIn("5 files need the internet, which --offline does not use.", out)
        self.assertNotIn("Downloading", out)
        self.assertNotIn("failed", out.lower())
        # nothing installed ended on
        # exit 0, where the screen's run gives 2.
        self.assertIn("Nothing installed: 5 files need the internet, which --offline does "
                      "not use.", out.replace("\r\n", " ").replace("\n", " "))
        self.assertNotIn("already up to date", out)
        self.assertEqual(code, 2)

    def test_the_data_files_are_counted_before_the_question(self):
        files = [{"dest": "a.bin", "size": 1024}]
        trees = [{"ref": "t", "files": {"x": {"size": 2048}, "y": {"size": 2048}}}]
        with mock.patch.object(install, "_ask", return_value=""), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            install._prompt_custom_selection("retroarch", files, [], data_trees=trees)
        # One total, the kinds under it adding up to it.
        self.assertIn("RetroArch: 3 files, 5.0 KB.\n  1 BIOS file (1.0 KB) and 2 data files "
                      "(4.0 KB).", out.getvalue())

    def test_one_save_file_goes(self):
        files = [{"dest": "keys.txt", "root": "save", "size": 1}]
        place = install.SavePlace(Path("/saves"), False)
        with mock.patch.object(install, "save_directory_for", return_value=place), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            install.place_save_entries(files, Path("/bios"), {}, None, "RetroArch")
        self.assertIn("1 file read from RetroArch's save directory goes to /saves",
                      out.getvalue())


class NarrowSystemNames(unittest.TestCase):
    """At 40 columns the size column took half the line: Game Boy, Game Boy
    Advance and Game Boy Color all read "Nintendo Gam"."""

    def test_the_name_comes_before_the_size(self):
        state = checked_state()
        names = {"nintendo-gb": "Nintendo Game Boy", "nintendo-gba": "Nintendo Game Boy Advance",
                 "nintendo-gbc": "Nintendo Game Boy Color",
                 "videoton-tvc": "Videoton TV Computer"}
        state.manifest = {**state.manifest, "system_titles": names}
        state.systems = [
            {"event": "system", "platform": "retroarch", "system": system, "name": system,
             "files": 30, "present": 0, "missing": 30, "wrong_hash": 0,
             "bytes_needed": 30 * 1024 * 1024}
            for system in names]
        state.files = [{"event": "file", "platform": "retroarch", "dest": f"s{n}.bin",
                        "systems": list(names), "size": 1024, "state": "missing"}
                       for n in range(27)]
        state.ticked = set(names)
        state.stack.append("systems")
        for cols, rows in ((40, 15), (40, 12), (52, 15)):
            with self.subTest(size=f"{cols}x{rows}"):
                text = "\n".join(install.tui_view(state, cols, rows))
                # the size stays as the total counts it,
                # 30.0 MB, and a name too long beside it is cut where the
                # three still read apart.
                lines = [line for line in text.splitlines() if "[x]" in line]
                self.assertEqual(len(lines), 4, text)
                self.assertTrue(all(line.rstrip().endswith(("30.0 MB", "30.0 MB + 27 shared"))
                                    for line in lines), text)
                labels = [line.split("[x] ")[1].split("30.0 MB", 1)[0].strip()
                          for line in lines]
                self.assertEqual(len(set(labels)), 4, text)
                for label, name in zip(labels, names.values()):
                    stem = label[:-3] if label.endswith("...") else label
                    self.assertTrue(name.startswith(stem), (label, name))
                for line in text.splitlines():
                    self.assertLessEqual(install.cell_width(line), cols)
        # Wide, the full form stays.
        self.assertIn("3 files, 30.0 MB + 27 shared",
                      "\n".join(install.tui_view(state, 120, 40)))

    def test_one_spelling_of_shared_and_the_focused_size_below(self):
        """At 40 columns the shared part read "+ 1689 shared", "+ 28 sh.",
        ", shared" and ", all shared" on one screen, and a long name kept
        whole lost its size."""
        state = checked_state()
        names = {"epoch-scv": "Epoch Super Cassette Vision", "sega-dc": "Sega Dreamcast",
                 "snk-ng": "SNK Neo Geo"}
        state.manifest = {**state.manifest, "system_titles": names}
        state.systems = [
            {"event": "system", "platform": "retroarch", "system": system, "name": system,
             "files": count, "present": 0, "missing": count, "wrong_hash": 0,
             "bytes_needed": count * 1024}
            for system, count in (("epoch-scv", 30), ("sega-dc", 1690), ("snk-ng", 3))]
        state.files = [{"event": "file", "platform": "retroarch", "dest": f"s{n}.bin",
                        "systems": ["sega-dc", "snk-ng"], "size": 1024, "state": "missing"}
                       for n in range(3)]
        state.ticked = set(names)
        state.stack.append("systems")
        spellings = set()
        for cols in (40, 46, 52, 80):
            text = "\n".join(install.tui_view(state, cols, 15))
            spellings |= set(re.findall(r"\+ \d+ sh\w*\.?|, (?:all )?shared", text))
        self.assertLessEqual(spellings, {"+ 3 shared", ", all shared"}, spellings)
        state.focus["systems"] = next(
            index for index, row in enumerate(install.tui_rows(state))
            if row.value == "epoch-scv")
        text = " ".join(" ".join(install.tui_view(state, 40, 15)).split())
        self.assertIn("Epoch Super Cassette Vision: 30 files, 30.0 KB", text)


class Crash(unittest.TestCase):
    """An unexpected error ends on one sentence and a log, never a traceback."""

    class FakeTerminal:
        left = False

        def __init__(self, *_streams) -> None:
            self.frame = []

        def enter(self) -> None:
            pass

        def leave(self) -> None:
            Crash.FakeTerminal.left = True

        def size(self) -> tuple:
            return 80, 24

        def draw(self, lines, cols) -> None:
            pass

        def set_mouse(self, on: bool) -> None:
            pass

        def keys(self, timeout):
            raise RuntimeError("a defect")

    def test_the_terminal_is_restored_and_one_line_printed(self):
        args = _args()
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(install, "_TuiTerminal", self.FakeTerminal), \
                mock.patch.object(install, "tui_start", return_value=(fresh_state(), [])), \
                mock.patch.object(install, "_open_local_sources"), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
            code = install.run_tui(args)
        self.assertEqual(code, 1)
        self.assertTrue(self.FakeTerminal.left)
        lines = err.getvalue().splitlines()
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("stopped on an unexpected error", lines[0])
        log = Path(lines[0].rsplit(" ", 1)[-1].rstrip("."))
        self.addCleanup(shutil.rmtree, log.parent, True)
        self.assertIn("RuntimeError: a defect", log.read_text())
        self.assertNotIn("Traceback", err.getvalue() + out.getvalue())


class TheSaveFolderLineFollowsTheChoice(unittest.TestCase):
    """The save-folder line was the check's: with the system owning the
    save file unticked, the result named a folder nothing was written to,
    and kept, the Confirm screen did not name it."""

    SAVES = {"event": "saves", "platform": "retroarch", "files": 1,
             "folder": "/home/user/MySaves/<core>"}
    LINE = ("1 file read from RetroArch's save directory goes to a folder per core under: "
            "~/MySaves")
    # The result spells every folder in full.
    RESULT = ("1 file read from RetroArch's save directory goes to a folder per core under: "
              "/home/user/MySaves")

    def said(self, lines) -> str:
        return " ".join(" ".join(lines).split())

    def run_to_result(self, confirm_saves: bool, install_saves: bool) -> install.TuiState:
        state = checked_state()
        state.saves = dict(self.SAVES)
        state.must_confirm = True
        state.stack.append("confirm")
        install._start_run(state, "confirm")
        dry = {**CHECK, "files": 3, "missing": 3, "wrong_hash": 0}
        for event in [*([self.SAVES] if confirm_saves else []), dry]:
            install.tui_receive(state, ("event", state.run_id, event))
        install.tui_receive(state, ("ended", state.run_id, 1, []))
        self.confirm = self.said(install.tui_view(state, 200, 40))
        install._start_run(state, "install")
        summary = {"event": "summary", "mode": "install", "installed": 3, "up_to_date": 0,
                   "pending": 0, "failed": [], "skipped": [], "left_out": [], "kept": [],
                   "interrupted": False}
        for event in [*([self.SAVES] if install_saves else []), summary]:
            install.tui_receive(state, ("event", state.run_id, event))
        install.tui_receive(state, ("ended", state.run_id, 0, []))
        return state

    def test_unticked_it_is_named_nowhere(self):
        state = self.run_to_result(confirm_saves=False, install_saves=False)
        self.assertNotIn("save directory", self.confirm)
        self.assertEqual(state.screen, "result")
        self.assertNotIn("save directory", self.said(install.tui_outcome(state)[1]))

    @in_full
    def test_kept_the_confirm_screen_and_the_result_name_it(self):
        state = self.run_to_result(confirm_saves=True, install_saves=True)
        self.assertIn(self.LINE, self.confirm)
        self.assertIn(self.RESULT, self.said(install.tui_outcome(state)[1]))


@unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                 "a folder without search permission is POSIX")
class AFolderThisUserCannotOpen(unittest.TestCase):
    """A BIOS folder under a folder this user cannot enter: given with
    --dest the interface ended on a traceback before its first screen, and
    typed on the folder screen it ended on a crash log."""

    def setUp(self):
        base = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, base, True)
        self.lock = base / "lock"
        self.lock.mkdir()
        os.chmod(self.lock, 0o000)
        self.addCleanup(os.chmod, self.lock, 0o755)
        self.dest = self.lock / "system"

    def said(self, state: install.TuiState) -> str:
        return screen_text(install.tui_view(state, 200, 40))

    def test_typed_it_stays_on_the_path_screen(self):
        state = fresh_state()
        state.platform = "retroarch"
        state.stack = ["setup", "folder", "path"]
        state.path_text = str(self.dest)
        self.assertEqual(install.tui_update(state, Key("enter")), [])
        self.assertEqual(state.screen, "path")
        self.assertEqual(state.path_text, str(self.dest))
        self.assertIn(f"This user cannot open {install._short_path(self.lock, state.home)} "
                      "(Permission denied)", self.said(state))

    def test_given_with_dest_opens_the_folder_screen(self):
        args = _args(platform="retroarch", dest=str(self.dest))
        with mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "_mounted_cards", return_value=[]):
            state, effects = install.tui_start(args, "linux")
        self.assertEqual(effects, [])
        self.assertEqual(state.screen, "folder")
        self.assertIn(f"This user cannot open {install._short_path(self.lock, state.home)} "
                      "(Permission denied)", self.said(state))
        self.assertIn("choose another folder", self.said(state))

    def test_chosen_from_the_setups(self):
        state = fresh_state()
        state.setups = [("retroarch", self.dest, "RetroArch")]
        state.stack = ["setup"]
        self.assertEqual(install.tui_update(state, Key("enter")), [])
        self.assertEqual(state.screen, "folder")
        # The folder found is the one RetroArch reads: its built-in default
        # is not, and was offered with Enter on "Use this folder".
        self.assertIsNone(state.folder_default)
        self.assertNotIn("reads its BIOS files from", self.said(state))
        self.assertIn(f"This user cannot open {install._short_path(self.lock, state.home)} "
                      "(Permission denied)", self.said(state))

    def test_a_home_it_cannot_open_is_said_on_the_first_screen(self):
        """HOME kept across su without -: detection raised PermissionError
        before the first screen."""
        home = self.lock.parent / "home"
        home.mkdir()
        os.chmod(home, 0o000)
        self.addCleanup(os.chmod, home, 0o755)
        install._DETECTION_REFUSED.clear()
        self.addCleanup(install._DETECTION_REFUSED.clear)
        with mock.patch.dict(os.environ, {"HOME": str(home)}), \
                mock.patch.object(install, "_mounted_cards", return_value=[]):
            state, _effects = install.tui_start(_args(), "linux")
        self.assertIn("Could not look for setups: this user cannot open", self.said(state))

    def test_the_nearest_folder_stops_above_it(self):
        self.assertEqual(install._nearest_folder(self.dest / "deeper"), self.lock)

    def test_a_closed_folder_under_home_hides_nothing_else(self):
        """~/.config/EmuDeck at 000 made detection return nothing, and the
        folder screen offered ~/.config/retroarch/system, which this
        RetroArch does not read: its retroarch.cfg names another."""
        home = self.lock.parent / "home"
        closed = home / ".config" / "EmuDeck"
        closed.mkdir(parents=True)
        cfg = home / ".config" / "retroarch" / "retroarch.cfg"
        cfg.parent.mkdir()
        system = self.lock.parent / "elsewhere" / "system"
        system.mkdir(parents=True)
        cfg.write_text(f'system_directory = "{system}"\n')
        os.chmod(closed, 0o000)
        self.addCleanup(os.chmod, closed, 0o755)
        install._DETECTION_REFUSED.clear()
        self.addCleanup(install._DETECTION_REFUSED.clear)
        with mock.patch.dict(os.environ, {"HOME": str(home)}), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_RETROARCH_CONFIGS", {}):
            state, _effects = install.tui_start(_args(), "linux")
        self.assertEqual([setup[:2] for setup in state.setups], [("retroarch", system)])
        screen = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertEqual(screen.count("Could not look for setups: this user cannot open "
                                      "~/.config/EmuDeck (Permission denied)"), 1, screen)

    def test_the_refusal_is_drawn_above_a_full_list(self):
        """With a closed HOME the first screen is the 18 setups: the line,
        drawn under them, was dropped at 80x24 and at 40x15."""
        home = self.lock.parent / "home"
        home.mkdir()
        os.chmod(home, 0o000)
        self.addCleanup(os.chmod, home, 0o755)
        install._DETECTION_REFUSED.clear()
        self.addCleanup(install._DETECTION_REFUSED.clear)
        with mock.patch.dict(os.environ, {"HOME": str(home)}), \
                mock.patch.object(install, "_mounted_cards", return_value=[]):
            state, _effects = install.tui_start(_args(), "linux")
        self.assertEqual(state.screen, "platforms")
        for cols, rows in ((80, 24), (40, 15)):
            with self.subTest(size=f"{cols}x{rows}"):
                lines = install.tui_view(state, cols, rows)
                self.assertEqual(len(lines), rows)
                screen = " ".join(" ".join(lines).split())
                self.assertIn("Could not look for setups", screen)
                self.assertIn("name the BIOS folder with --dest.", screen)
                # The list keeps its focused row in view.
                self.assertIn("RetroArch", screen)


class AGoesIntoASubfolder(unittest.TestCase):
    """At HOME or a drive root A went into the first "dir" row: a mounted
    card or drive listed first (/mnt/d, the Windows D: drive, then took
    the BIOS files at its root) or .cache."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.home, True)
        self.card = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.card, True)
        self.state = install.TuiState(os_type="linux", home=self.home)
        self.state.platform = "retroarch"
        self.state.stack = ["folder", "browse"]

    def focused(self) -> install.TuiRow:
        return self.state.browse_rows[self.state.focus["browse"]]

    def test_a_card_and_cache_are_passed_over(self):
        (self.home / ".cache").mkdir()
        (self.home / "Games").mkdir()
        with mock.patch.object(install, "_mounted_cards", return_value=[self.card]):
            install._browse_to(self.state, self.home)
        self.assertEqual(self.state.browse_rows[2].value, self.card)
        self.assertEqual(self.focused().label, "Games/")
        self.assertEqual(self.state.status, "")

    def test_with_no_visible_subfolder_a_folder_below_takes_the_focus(self):
        """The focus stayed on Use this folder under the
        sentence that warns against it, and A, A, A installed BizHawk into
        the home folder."""
        (self.home / ".cache").mkdir()
        (self.home / ".config").mkdir()
        with mock.patch.object(install, "_mounted_cards", return_value=[self.card]):
            install._browse_to(self.state, self.home)
        self.assertEqual(self.focused().label, ".cache/")
        self.assertIn("No setup reads BIOS files in the home folder", self.state.status)
        screen = " ".join(" ".join(install.tui_view(self.state, 80, 24)).split())
        self.assertIn("No setup reads BIOS files in the home folder.", screen)

    def test_on_windows_the_other_drives_are_passed_over(self):
        """The card rows are drive roots there (E:\\): at D:\\ the first
        was E:\\, and at E:\\ it was D:\\."""
        (self.home / "Games").mkdir()
        drives = [Path("D:\\"), Path("E:\\")]
        windows = WindowsOs()
        windows.path = types.SimpleNamespace(
            **{name: getattr(os.path, name) for name in dir(os.path)
               if not name.startswith("_")})
        windows.path.exists = lambda path: str(path) in ("C:\\", "D:\\", "E:\\")
        with mock.patch.object(install, "os", windows), \
                mock.patch.object(install, "_mounted_cards", return_value=drives):
            install._browse_to(self.state, self.home)
            self.assertEqual(self.focused().label, "Games/")
            # The drives list keeps its first drive focused.
            install._browse_to(self.state, None)
            self.assertEqual([row.label for row in self.state.browse_rows],
                             ["C:\\", "D:\\", "E:\\"])
            self.assertEqual(self.state.focus["browse"], 0)


# POSIX modules a Windows Python does not have: importing one raises there.
POSIX_ONLY = ("termios", "tty", "pty", "fcntl", "select", "resource", "pwd", "grp")
# The signal names a Windows Python defines.
WINDOWS_SIGNALS = ("SIGABRT", "SIGBREAK", "SIGFPE", "SIGILL", "SIGINT", "SIGSEGV",
                   "SIGTERM")


class WindowsOs(types.ModuleType):
    """The os module with os.name "nt", everything else delegated."""

    def __init__(self) -> None:
        super().__init__("os")
        self.name = "nt"

    def __getattr__(self, attribute: str) -> object:
        return getattr(os, attribute)


class SimulatedWindows:
    """os.name "nt", the POSIX modules unimportable, the signal module cut
    down to the names Windows has, and msvcrt reading the given keys."""

    def __init__(self, keys: str = "") -> None:
        self.keys = list(keys)
        self.handlers: dict[int, object] = {}
        self.locked: list[int] = []
        self.msvcrt = types.SimpleNamespace(
            kbhit=lambda: bool(self.keys), getwch=lambda: self.keys.pop(0),
            locking=lambda fd, mode, size: self.locked.append(fd), LK_NBLCK=2)
        self.signal = types.ModuleType("signal")
        for number, name in enumerate(WINDOWS_SIGNALS, start=100):
            setattr(self.signal, name, number)
        self.signal.SIG_DFL, self.signal.SIG_IGN = 0, 1
        self.signal.CTRL_C_EVENT, self.signal.CTRL_BREAK_EVENT = 0, 1
        self.signal.signal = self._install
        self.signal.getsignal = lambda number: self.handlers.get(number, 0)
        self.stack = contextlib.ExitStack()

    def _install(self, number: int, handler: object) -> object:
        if number not in {getattr(self.signal, name) for name in WINDOWS_SIGNALS}:
            raise ValueError(f"invalid signal value {number}")
        previous = self.handlers.get(number, 0)
        self.handlers[number] = handler
        return previous

    def __enter__(self) -> SimulatedWindows:
        self.stack.enter_context(mock.patch.dict(
            sys.modules, {**{name: None for name in POSIX_ONLY}, "msvcrt": self.msvcrt}))
        # install.py alone sees "nt": pathlib here keeps making PosixPaths.
        self.stack.enter_context(mock.patch.object(install, "os", WindowsOs()))
        self.stack.enter_context(mock.patch.object(install, "signal", self.signal))
        return self

    def __exit__(self, *exc: object) -> None:
        self.stack.close()


class WindowsHasNoPosixModules(unittest.TestCase):
    """_terminal_gone imported termios unguarded: on Windows a closed console
    raised ModuleNotFoundError inside run_tui's except block, a traceback
    instead of an exit code. Every path the interface takes on Windows runs
    here with the POSIX modules gone."""

    class Console(io.StringIO):
        broken = False

        def fileno(self) -> int:
            return 0

        def isatty(self) -> bool:
            return True

        def write(self, text: str) -> int:
            if self.broken:
                raise OSError(errno.EPIPE, "The pipe is being closed")
            return super().write(text)

    def test_the_simulation_refuses_posix_imports(self):
        with SimulatedWindows():
            for name in POSIX_ONLY:
                with self.subTest(module=name), self.assertRaises(ImportError):
                    __import__(name)
            self.assertFalse(hasattr(install.signal, "SIGTSTP"))

    def test_a_closed_console_is_a_closed_terminal(self):
        console = self.Console()
        with SimulatedWindows():
            terminal = install._TuiTerminal(console, console)
            self.assertTrue(install._closed_terminal(
                OSError(errno.EPIPE, "The pipe is being closed"), terminal))
            self.assertFalse(install._closed_terminal(
                OSError(errno.ENOENT, "No such file"), terminal))

    def test_keys_enter_leave_and_cleanup(self):
        console = self.Console()
        with SimulatedWindows("a\xe0H") as windows:
            terminal = install._TuiTerminal(console, console)
            terminal.enter()
            self.assertEqual([(key.name, key.text) for key in terminal.keys(0.05)],
                             [("char", "a"), ("up", "")])
            handlers = {windows.signal.SIGINT: windows.signal.SIG_DFL}
            self.assertEqual(install._tui_cleanup(terminal, [], handlers, fresh_state()), [])
            self.assertIn(install._SCREEN_OFF, console.getvalue())

    def test_a_child_is_interrupted_through_the_console(self):
        run = install._EngineRun.__new__(install._EngineRun)
        run.proc = mock.Mock(**{"poll.return_value": None})
        with SimulatedWindows(), mock.patch.object(install.os, "kill") as kill:
            run.interrupt(from_key=False)
            kill.assert_not_called()
            run.proc.send_signal.assert_not_called()
            run.interrupt(from_key=True)
            kill.assert_called_once_with(0, install.signal.CTRL_C_EVENT)

    def test_work_folder_owner_and_partial_lock(self):
        work = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, work, True)
        (work / install.TUI_OWNER).write_text(str(os.getpid()), encoding="utf-8")
        with SimulatedWindows() as windows:
            self.assertIsNone(install._owner_alive(work))
            handle = install._claim_partial(work / "x.bin.part")
            self.assertIsNotNone(handle)
            handle.close()
            self.assertEqual(len(windows.locked), 1)

    def test_run_tui_ends_on_the_closed_console_code(self):
        console = self.Console()
        real_draw = install._TuiTerminal.draw

        def breaking_draw(terminal, lines, cols):
            console.broken = True
            real_draw(terminal, lines, cols)

        work = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, work, True)
        with SimulatedWindows() as windows, \
                mock.patch.object(install._TuiTerminal, "draw", breaking_draw), \
                mock.patch.object(install, "_drop_closed_terminal"), \
                mock.patch.object(install.tempfile, "mkdtemp", return_value=str(work)), \
                mock.patch.object(install, "tui_start", return_value=(fresh_state(), [])), \
                mock.patch.object(install, "_open_local_sources"), \
                mock.patch.object(install, "detect_os", return_value="windows"), \
                mock.patch.object(sys, "stdin", console), \
                mock.patch.object(sys, "stdout", console), \
                mock.patch.object(sys, "stderr", console):
            code = install.run_tui(_args())
            # SIGHUP does not exist there: the closed window's code is 129.
            self.assertEqual(code, 129)
            self.assertFalse((work / "error.log").exists())
            self.assertTrue(all(handler == 0 for handler in windows.handlers.values()),
                            windows.handlers)


# --- End to end, on a pseudo-terminal -------------------------------------


class Pty:
    """install.py on a pseudo-terminal, its screen read back through pyte."""

    def __init__(self, args: list[str], env: dict, cols: int = 80, rows: int = 24,
                 program: list[str] | None = None) -> None:
        """program runs instead of this Python on install.py: the wrapper
        a user runs, install.sh."""
        self.screen = pyte.Screen(cols, rows)
        self.stream = pyte.ByteStream(self.screen)
        self.raw = b""
        with warnings.catch_warnings():
            # The child replaces itself at once: the fork-with-threads hazard
            # (a lock held by the loopback server thread) never reaches it.
            warnings.simplefilter("ignore", DeprecationWarning)
            self.pid, self.fd = pty.fork()
        if self.pid == 0:
            argv = program or [sys.executable, str(REPO_ROOT / "install.py")]
            os.execve(argv[0], [*argv, *args], env)
        self.resize(cols, rows)
        self.status: int | None = None

    def resize(self, cols: int, rows: int) -> None:
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.screen.resize(rows, cols)

    def _pump(self, wait: float) -> bool:
        if not select.select([self.fd], [], [], wait)[0]:
            return True
        try:
            chunk = os.read(self.fd, 65536)
        except OSError:
            return False
        if not chunk:
            return False
        self.raw += chunk
        self.stream.feed(chunk)
        return True

    def text(self) -> str:
        return "\n".join(line.rstrip() for line in self.screen.display)

    def settle(self, quiet: float = 0.3, timeout: float = 10.0) -> str:
        """The screen once nothing more arrives for `quiet` seconds.

        text() shows only what was read: a loop that sent a key and looked
        again saw the screen before the key, and on a slow runner pressed
        Enter twelve rows past the folder it was looking for.
        """
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if not select.select([self.fd], [], [], quiet)[0]:
                break
            if not self._pump(0):
                break
        return self.text()

    def wait(self, needle: str, timeout: float = 20.0) -> str:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if needle in self.text():
                return self.text()
            if not self._pump(0.05):
                break
        if needle in self.text():
            return self.text()
        raise AssertionError(f"{needle!r} never shown:\n{self.text()}")

    def send(self, *keys: str) -> None:
        for key in keys:
            os.write(self.fd, key.encode())
            # The interface waits 40 ms to tell Esc from an arrow.
            time.sleep(0.15)

    def close(self, timeout: float = 30.0) -> int:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                while self._pump(0.05) and select.select([self.fd], [], [], 0)[0]:
                    pass
                # The modes the run left the terminal in: the master reads
                # the slave's.
                self.modes = termios.tcgetattr(self.fd)
                os.close(self.fd)
                self.status = os.WEXITSTATUS(status)
                return self.status
            self._pump(0.05)
        os.kill(self.pid, 9)
        raise AssertionError(f"still running:\n{self.text()}")

    def after(self) -> str:
        """What the terminal keeps once the full screen is gone."""
        return self.raw.split(b"\x1b[?1049l")[-1].decode("utf-8", "replace")


class _SlowHandler(_QuietHandler):
    """Serves each file after a pause, so a test can stop a download midway."""

    def do_GET(self) -> None:  # noqa: N802, D102
        if self.path.startswith("/bios/"):
            time.sleep(0.6)
        super().do_GET()


class GameDataRepository(FakeRepository):
    """The fake repository with a categorized list and one slow file per file."""

    def __init__(self, slow: bool = False) -> None:
        super().__init__()
        self.slow = slow

    def __enter__(self) -> GameDataRepository:
        super().__enter__()
        path = self.root / "install" / "retroarch.json"
        manifest = json.loads(path.read_text())
        manifest["categorized"] = True
        payload = b"a game's data"
        (self.root / "bios" / "game.dat").write_bytes(payload)
        manifest["files"].append({
            "dest": "game.dat", "sha1": hashlib.sha1(payload).hexdigest(),
            "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload),
            "repo_path": "bios/game.dat", "cores": None, "systems": ["nintendo-gba"],
            "category": "game_data"})
        path.write_text(json.dumps(manifest))
        if self.slow:
            self.httpd.shutdown()
            self.httpd.server_close()
            handler = functools.partial(_SlowHandler, directory=str(self.root))
            self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
            threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self


class SaveDirectoryRepository(FakeRepository):
    """The fake repository with one file read from RetroArch's save
    directory, as Azahar's keys.txt and 105 others of the real list."""

    KEYS = b"azahar keys"

    def __enter__(self) -> SaveDirectoryRepository:
        super().__enter__()
        path = self.root / "install" / "retroarch.json"
        manifest = json.loads(path.read_text())
        (self.root / "bios" / "keys.txt").write_bytes(self.KEYS)
        manifest["files"].append({
            "dest": "Azahar/Azahar/sysdata/keys.txt", "root": "save",
            "core_folder": "Azahar", "sha1": hashlib.sha1(self.KEYS).hexdigest(),
            "sha256": hashlib.sha256(self.KEYS).hexdigest(), "size": len(self.KEYS),
            "repo_path": "bios/keys.txt", "cores": ["azahar"],
            "systems": ["nintendo-3ds"]})
        manifest["save_directory"] = {"folder": "saves", "by_core": True}
        manifest["base_destination"] = "system"
        path.write_text(json.dumps(manifest))
        return self


def _app_card(test: unittest.TestCase, system: str) -> tuple[Path, Path]:
    """A card of system in the repository's tmp/, its root and BIOS folder."""
    from test_install_app import make_card  # noqa: PLC0415

    (REPO_ROOT / "tmp").mkdir(exist_ok=True)
    root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
    test.addCleanup(shutil.rmtree, root, True)
    return root / "card", make_card(root / "card", system)


def _installed_state(dest: Path, code: int = 0, failed: list | None = None) -> install.TuiState:
    """The result screen of an install into dest."""
    state = fresh_state()
    state.platform, state.dest, state.manifest = "retroarch", dest, MANIFEST
    state.stack, state.run, state.code = ["result"], "install", code
    state.summary = {"event": "summary", "mode": "install", "installed": 5, "up_to_date": 0,
                     "pending": 0, "failed": failed or [], "skipped": [], "left_out": [],
                     "kept": [], "interrupted": False}
    return state


class TheRomMResultNamesTheScan(unittest.TestCase):
    """RomM's player sees firmware its scan recorded: the result said
    "installed" and left the scan unsaid."""

    def test_the_result_and_its_farewell_say_it(self):
        state = _installed_state(SYSTEM_DIR)
        state.platform = "romm"
        _title, lines = install.tui_outcome(state)
        self.assertIn(install.ROMM_SCAN_WORDS, lines)
        self.assertIn(install.ROMM_SCAN_WORDS, install._farewell_lines(state))
        state.platform = "retroarch"
        self.assertNotIn(install.ROMM_SCAN_WORDS, install.tui_outcome(state)[1])


class AppOnTheCard(unittest.TestCase):
    """The RetroBIOS app offered on the result screen and in the options."""

    def setUp(self):
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop(install.OFFLINE_VARIABLE, None)

    def fields(self, card_root: Path, ok: bool = True) -> dict:
        return {"event": "app", "system": "muOS", "folder": str(card_root), "ok": ok,
                "reason": "" if ok else "it could not be downloaded: no connection",
                "dests": ["ARCHIVE/RetroBIOS.muxapp"],
                "written": ["ARCHIVE/RetroBIOS.muxapp"] if ok else [], "kept": []}

    def test_the_result_offers_it_and_exit_stays_the_default(self):
        root, bios = _app_card(self, "muOS")
        state = _installed_state(bios)
        rows = install.tui_rows(state)
        self.assertEqual([row.action for row in rows], ["exit", "addapp"])
        self.assertEqual(rows[1].label, install.APP_OFFER)
        screen = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn(install.APP_OFFER, screen)
        self.assertIn("A/Enter Exit", screen)
        self.assertEqual(press(state, "enter"), [])
        self.assertEqual(state.exit_code, 0)

    def test_choosing_it_puts_it_then_says_what_it_did(self):
        root, bios = _app_card(self, "muOS")
        state = _installed_state(bios)
        effects = press(state, "down", "enter")
        self.assertEqual(effects, [("app", install.card_app(bios))])
        self.assertTrue(state.app_running)
        screen = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn("Putting RetroBIOS on the card...", screen)
        # Nothing ends the screen while the card is written.
        self.assertEqual(press(state, "enter", "esc"), [])
        self.assertIsNone(state.exit_code)
        install.tui_receive(state, ("app", self.fields(root)))
        self.assertEqual(install.tui_rows(state), [])
        screen = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn("RetroBIOS is on the muOS card: 1 file written", screen)
        self.assertIn("Archive Manager", screen)
        self.assertIn("--add-app", install.tui_command(state))
        press(state, "enter")
        self.assertEqual(state.exit_code, 0)

    def test_a_failure_is_said_and_ends_on_1(self):
        root, bios = _app_card(self, "KNULLI")
        state = _installed_state(bios)
        press(state, "down", "enter")
        install.tui_receive(state, ("app", {**self.fields(root, ok=False), "system": "KNULLI"}))
        _title, lines = install.tui_outcome(state)
        self.assertTrue(any("could not be put on the KNULLI card" in line for line in lines))
        press(state, "enter")
        self.assertEqual(state.exit_code, 1)

    def test_space_and_b_never_put_it(self):
        _root, bios = _app_card(self, "muOS")
        state = _installed_state(bios)
        self.assertEqual(press(state, "down", " "), [])
        self.assertFalse(state.app_running)
        press(state, "esc")
        self.assertEqual(state.exit_code, 0)

    def test_no_offer_where_it_cannot_go(self):
        _root, muos = _app_card(self, "muOS")
        _root, onion = _app_card(self, "Onion")
        cases = {
            "failed install": _installed_state(muos, 1, [{"dest": "a", "reason": "x"}]),
            "plain folder": _installed_state(SYSTEM_DIR),
            "no launcher": _installed_state(onion),
        }
        offline = _installed_state(muos)
        for name, state in cases.items():
            with self.subTest(case=name):
                self.assertEqual(install.tui_rows(state), [])
        os.environ[install.OFFLINE_VARIABLE] = "1"
        self.assertEqual(install.tui_rows(offline), [])
        os.environ.pop(install.OFFLINE_VARIABLE)
        _title, lines = install.tui_outcome(cases["no launcher"])
        self.assertIn(install.no_python_words("Onion"), lines)

    def test_put_by_the_install_itself_no_second_offer(self):
        root, bios = _app_card(self, "muOS")
        state = _installed_state(bios)
        install._take_event(state, self.fields(root))
        self.assertEqual(install.tui_rows(state), [])
        self.assertIn("RetroBIOS is on the muOS card", "\n".join(install.tui_outcome(state)[1]))

    def test_the_options_row_sets_the_flag_of_the_install_only(self):
        _root, bios = _app_card(self, "muOS")
        state = _installed_state(bios)
        state.stack = ["plan", "options"]
        rows = install.tui_rows(state)
        row = next(row for row in rows if row.action == "addapp")
        self.assertEqual((row.label, row.right), ("Put RetroBIOS on this card: no", "--add-app"))
        state.focus["options"] = rows.index(row)
        press(state, "enter")
        self.assertTrue(state.add_app)
        self.assertIn("--add-app", install.tui_argv(state, "install", "py", "install.py"))
        for run in ("check", "confirm", "preview"):
            self.assertNotIn("--add-app", install.tui_argv(state, run, "py", "install.py"))
        self.assertIn("--add-app", install.tui_command(state))
        press(state, "left")
        self.assertFalse(state.add_app)
        plain = _installed_state(SYSTEM_DIR)
        plain.stack = ["plan", "options"]
        self.assertFalse(any(row.action == "addapp" for row in install.tui_rows(plain)))

    def test_the_command_line_flag_ticks_the_row(self):
        _root, bios = _app_card(self, "ROCKNIX")
        state, _effects = install.tui_start(_args(add_app=True, platform="rocknix",
                                                  dest=bios), "linux", detect=False)
        self.assertTrue(state.add_app)


@unittest.skipUnless(pyte and pty and hasattr(pty, "fork"),
                     "screen tests need pyte (pip install pyte==0.8.2) and a pty")
class EndToEnd(unittest.TestCase):
    """The real install.py --tui, keys in and screens out."""

    def repo(self, cls=FakeRepository, **options) -> FakeRepository:
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        repo = cls(**options)
        repo.__enter__()
        self.addCleanup(repo.__exit__, None, None, None)
        home = repo.root / "home"
        cfg = home / ".config" / "retroarch"
        cfg.mkdir(parents=True)
        repo.dest.mkdir()
        (cfg / "retroarch.cfg").write_text(f'system_directory = "{repo.dest}"\n')
        self.env = {**repo.env(), "HOME": str(home), "TERM": "xterm",
                    "RETROBIOS_OS": "linux", "XDG_CONFIG_HOME": str(home / ".config")}
        self.env.pop("NO_COLOR", None)
        # Whatever the shell running the tests has, the input is not known:
        # the bar names both the button and the key. Each test names its own.
        for name in ("DISPLAY", "WAYLAND_DISPLAY", "SSH_CONNECTION", "SSH_TTY",
                     install.TUI_PAD_ENV, *install._STEAM_MARKERS):
            self.env.pop(name, None)
        return repo

    def start(self, *args: str, cols: int = 80, rows: int = 24) -> Pty:
        term = Pty(list(args), self.env, cols, rows)
        self.addCleanup(lambda: term.status is None and os.kill(term.pid, 9))
        return term


    def card_repo(self, system: str) -> tuple[Path, Path]:
        from test_install_app import AppRepository, make_card  # noqa: PLC0415

        repo = self.repo(AppRepository)
        root = repo.root / "card"
        return root, make_card(root, system)

    def assertAppOnCard(self, root: Path, system: str) -> None:
        index = json.loads((REPO_ROOT / "install" / "launchers" / "index.json").read_text())
        targets = install.app_targets(index, install.APP_PLACES[system])
        for target in targets:
            data = (root / target["dest"]).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), target["sha256"],
                             target["dest"])

    def test_put_the_app_on_a_muos_card_from_the_result(self):
        root, bios = self.card_repo("muOS")
        term = self.start("--platform", "retroarch", "--dest", str(root))
        term.wait("files to download")
        term.send("\r")
        screen = term.wait(install.APP_OFFER)
        self.assertIn("> Exit", screen)
        term.send(DOWN, "\r")
        screen = term.wait("RetroBIOS is on the muOS card")
        self.assertIn("Archive Manager", screen)
        term.send("\r")
        self.assertEqual(term.close(), 0)
        self.assertAppOnCard(root, "muOS")
        self.assertEqual(len(list(bios.iterdir())), 5)
        self.assertIn("RetroBIOS is on the muOS card", term.after())

    def test_put_the_app_on_a_knulli_card_from_the_options(self):
        root, _bios = self.card_repo("KNULLI")
        term = self.start("--platform", "knulli", "--dest", str(root))
        term.wait("files to download")
        term.send("o")
        term.wait("Each row is an option")
        for _step in range(20):
            if "> Put RetroBIOS on this card: no" in term.settle():
                break
            term.send(DOWN)
        term.send("\r")
        term.wait("> Put RetroBIOS on this card: yes")
        term.send("\x1b")
        term.wait("files to download")
        term.send("\r")
        screen = term.wait("RetroBIOS is on the KNULLI card")
        self.assertIn("start RetroBIOS from Ports", screen)
        self.assertNotIn(install.APP_OFFER, screen)
        # The command, a Details line, is said after Exit once they were opened.
        term.send("d")
        term.wait("RetroBIOS: Details")
        term.send("\x1b")
        term.wait("RetroBIOS is on the KNULLI card")
        term.send("\r")
        self.assertEqual(term.close(), 0)
        self.assertAppOnCard(root, "KNULLI")
        self.assertIn("--add-app", term.after())

    def test_three_presses_install_everything(self):
        repo = self.repo()
        term = self.start()
        screen = term.wait("Where to install?")
        self.assertIn("> RetroArch", screen)
        term.send("\r")
        screen = term.wait("files to download")
        self.assertIn("5 files to download, 30 B", screen)
        self.assertIn("> Install", screen)
        term.send("\r")
        term.wait("5 files installed.")
        term.send("\r")
        self.assertEqual(term.close(), 0)
        self.assertEqual(len(repo.installed()), 5)
        after = term.after()
        self.assertIn("RetroBIOS: Done", after)
        self.assertIn("5 files installed.", after)
        # The command is a Details line: said after Exit once they were opened.
        self.assertIn("Next: start RetroArch and play.", after)
        self.assertNotIn("--platform retroarch --dest", after)
        # The cursor and the main screen come back before the result is printed.
        self.assertIn(b"\x1b[?25h\x1b[?1049l", term.raw)

    def test_the_save_directory_is_the_one_line_mode_finds(self):
        """The interface named the BIOS folder with --dest, so its runs never
        read retroarch.cfg: keys.txt went to a guessed RetroArch/saves, or
        was dropped without a word, where line mode writes it to the
        savefile_directory RetroArch reads."""
        import subprocess

        def written(repo, saves: Path) -> list[str]:
            return sorted([*repo.installed(), *(
                "saves/" + p.relative_to(saves).as_posix()
                for p in saves.rglob("*") if p.is_file())])

        results = []
        for mode in ("line", "interface"):
            with self.subTest(mode=mode):
                repo = self.repo(SaveDirectoryRepository)
                home = Path(self.env["HOME"])
                saves = home / "MySaves"
                saves.mkdir()
                cfg = home / ".config" / "retroarch" / "retroarch.cfg"
                cfg.write_text(f'system_directory = "{repo.dest}"\n'
                               f'savefile_directory = "{saves}"\n')
                if mode == "line":
                    proc = subprocess.run(
                        [sys.executable, str(REPO_ROOT / "install.py"), "--platform",
                         "retroarch", "--yes"], env=self.env, capture_output=True,
                        text=True, timeout=60, check=False, stdin=subprocess.DEVNULL)
                    self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    self.assertIn("6 files installed", proc.stdout)
                else:
                    term = self.start()
                    term.wait("Where to install?")
                    term.send("\r")
                    screen = term.wait("files to download")
                    self.assertIn("6 files to download", screen)
                    # The second folder the run writes to, named on the
                    # plan's Details before anything is written, and on the
                    # result's.
                    term.send("d")
                    screen = term.wait("RetroBIOS: Details")
                    self.assertIn("1 file read from RetroArch's save directory goes to a "
                                  "folder per core under:\n   ~/MySaves", screen)
                    term.send("\x1b")
                    term.wait("files to download")
                    term.send("\r")
                    term.wait("6 files installed.")
                    term.send("d")
                    screen = term.wait("RetroBIOS: Details")
                    # Spelled in full on the result, as its other folders.
                    joined = "".join(line.strip() for line in screen.splitlines())
                    self.assertIn("folder per core under:" + str(saves), joined)
                    term.send("\x1b")
                    term.wait("6 files installed.")
                    term.send("\r")
                    self.assertEqual(term.close(), 0)
                results.append(written(repo, saves))
                self.assertIn("saves/Azahar/Azahar/sysdata/keys.txt", results[-1])
        self.assertEqual(results[0], results[1])

    def test_one_system_from_the_checklist(self):
        repo = self.repo()
        term = self.start("--platform", "retroarch", "--dest", str(repo.dest), cols=40, rows=15)
        term.wait("> Install")
        term.send(DOWN, "\r")
        term.wait("Choose systems")
        # D-pad and A only: the list opens on its first system, A unticks
        # it, B goes back to the plan.
        term.send("\r")
        screen = term.wait("1 of 2 systems")
        self.assertIn("> [ ] nintendo-gba", screen)
        self.assertIn("[x] sony-playstation", screen)
        term.send("\x1b")
        term.wait("About 3 files")
        # Install counts the choice on Confirm first.
        term.send("\r")
        screen = term.wait("files to download")
        self.assertIn("3 files to download", screen)
        term.send("\r")
        term.wait("3 files installed.")
        term.send("d")
        term.wait("RetroBIOS: Details")
        term.send("\x1b")
        term.wait("3 files installed.")
        term.send("\r")
        self.assertEqual(term.close(), 0)
        self.assertEqual(repo.installed(), ["pcsx/extra.bin", "scph5500.bin", "scph5501.bin"])
        self.assertIn("--system sony-playstation", term.after().replace("\n", " "))

    def test_options_region_and_game_data(self):
        repo = self.repo(GameDataRepository)
        term = self.start("--platform", "retroarch", "--dest", str(repo.dest))
        term.wait("6 files to download")
        term.send("o")
        screen = term.wait("Each row is an option")
        self.assertIn("--no-game-data", screen)
        term.send("\r")
        term.wait("Preferred regions")
        term.send(DOWN, "\r", "\x1b")
        screen = term.wait("Preferred regions: North America")
        term.send(DOWN, RIGHT, "\x1b")
        # Back on the plan, the check runs again under the new options.
        screen = term.wait("4 files to download")
        self.assertIn("> Install", screen)
        term.send("\r")
        term.wait("installed.")
        term.send("o")
        screen = term.wait("RetroBIOS: Details")
        self.assertIn("1 game data file left out.", screen)
        term.send("\r")
        term.wait("installed.")
        term.send("\r")
        self.assertEqual(term.close(), 0)
        self.assertEqual(repo.installed(), ["gba_bios.bin", "mgba/extra.bin",
                                            "pcsx/extra.bin", "scph5501.bin"])

    def test_preview_writes_nothing(self):
        repo = self.repo()
        term = self.start("--platform", "retroarch", "--dest", str(repo.dest))
        term.wait("> Install")
        term.send("o", "G", UP, "\r")
        screen = term.wait("Nothing is written.")
        self.assertIn("missing", screen)
        self.assertIn("scph5501.bin", screen)
        term.send("\x1b", "\x1b", "q")
        self.assertEqual(term.close(), install.QUIT_CODE)
        self.assertEqual(repo.installed(), [])
        self.assertIn("Nothing was installed.", term.after())

    def test_ctrl_c_during_the_download(self):
        repo = self.repo(GameDataRepository, slow=True)
        term = self.start("--platform", "retroarch", "--dest", str(repo.dest), "--jobs", "1")
        term.wait("> Install")
        term.send("\r")
        term.wait("1 of 6 files")
        term.send("\x03")
        screen = term.wait("Stopped:")
        term.send("\r")
        self.assertEqual(term.close(), 130)
        # The count said is the count on disk: "6 of 6" after a stop at 1
        # passed a regex and was false.
        on_disk = len(repo.installed())
        self.assertLess(on_disk, 6)
        self.assertIn(f"Stopped: {on_disk} of 6 installed, run again to finish.", screen)
        self.assertIn(f"Stopped: {on_disk} of 6 installed", term.after())

    def test_sigterm_during_the_download_is_a_stop(self):
        """Start+Select on a handheld is gptokeyb's pkill: SIGTERM, SIGKILL 3 s on."""
        import signal

        repo = self.repo(GameDataRepository, slow=True)
        term = self.start("--platform", "retroarch", "--dest", str(repo.dest), "--jobs", "1")
        term.wait("> Install")
        term.send("\r")
        term.wait("1 of 6 files")
        started = time.monotonic()
        os.kill(term.pid, signal.SIGTERM)
        code = term.close()
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(code, 130)
        on_disk = len(repo.installed())
        self.assertGreaterEqual(on_disk, 1)
        after = term.after()
        self.assertIn(f"Stopped: {on_disk} of 6 installed, run again to finish.", after)
        self.assertNotIn("Nothing was installed", after)
        # The plain outcome only: the log's last lines are for a run that died.
        self.assertIsNone(re.search(r"\[\d+/6\]", after), after)
        self.assertNotIn("Stopping.", after)
        time.sleep(1)
        self.assertEqual(len(repo.installed()), on_disk)

    def test_copy_from_an_old_card(self):
        repo = self.repo()
        old = Path(self.env["HOME"]) / "oldcard"
        (old / "bios").mkdir(parents=True)
        for name in ("scph5500.bin", "scph5501.bin", "gba_bios.bin"):
            payload = FakeRepository.PAYLOADS[name][0]
            (old / "bios" / name).write_bytes(payload)
        term = self.start("--platform", "retroarch", "--dest", str(repo.dest))
        term.wait("5 files to download")
        term.send(DOWN, DOWN, "\r")
        term.wait("Choose the old card")
        for _ in range(12):
            if "> oldcard/" in term.settle():
                break
            term.send(DOWN)
        self.assertIn("> oldcard/", term.settle())
        term.send("\r")
        term.wait("> Use this folder")
        term.send("\r")
        screen = term.wait("found in")
        # The folder wraps at a slash: compared without the spaces.
        self.assertIn("3 found in oldcard, 2 to download (8 B)", screen)
        # Checked again, the plan opens on Install.
        term.send("\r")
        screen = term.wait("files installed.")
        # Where each came from, as the line mode says it.
        self.assertIn("5 files installed.", screen)
        self.assertIn("3 files copied from", screen)
        self.assertIn("2 downloaded.", screen)
        term.send("o")
        term.wait("RetroBIOS: Details")
        term.send("\r")
        term.wait("files installed.")
        term.send("\r")
        self.assertEqual(term.close(), 0)
        self.assertEqual(len(repo.installed()), 5)
        self.assertIn(f"--from {old}", term.after().replace("\n", " "))

    def test_ctrl_c_on_the_first_screen(self):
        self.repo()
        term = self.start()
        term.wait("Where to install?")
        term.send("\x03")
        self.assertEqual(term.close(), 130)
        self.assertIn(b"\x1b[?2004l\x1b[0m\x1b[?25h\x1b[?1049l", term.raw)

    def test_a_stop_from_outside_gives_the_terminal_back(self):
        import signal

        self.repo()
        term = self.start()
        term.wait("Where to install?")
        mark = len(term.raw)
        os.kill(term.pid, signal.SIGTSTP)
        end = time.monotonic() + 10
        stopped = False
        while time.monotonic() < end and not stopped:
            term._pump(0.05)
            pid, status = os.waitpid(term.pid, os.WNOHANG | os.WUNTRACED)
            stopped = bool(pid) and os.WIFSTOPPED(status)
        self.assertTrue(stopped)
        self.assertIn(b"\x1b[?25h\x1b[?1049l", term.raw[mark:])
        mark = len(term.raw)
        os.kill(term.pid, signal.SIGCONT)
        term.wait("A/Enter Continue")
        end = time.monotonic() + 5
        while b"\x1b[?1049h" not in term.raw[mark:] and time.monotonic() < end:
            term._pump(0.05)
        self.assertIn(b"\x1b[?1049h", term.raw[mark:])
        term.send("q")
        self.assertEqual(term.close(), install.QUIT_CODE)

    def test_closing_the_window_ends_with_its_signal(self):
        """The terminal gone, the farewell has nowhere to go: the code is
        129 (SIGHUP), not 120 from the flush failing at exit."""
        self.repo()
        for screen_name, keys_first in (("Where to install?", ()),
                                        ("files to download", ("\r",))):
            with self.subTest(screen=screen_name):
                term = self.start()
                term.wait("Where to install?")
                term.send(*keys_first)
                term.wait(screen_name)
                os.close(term.fd)
                end = time.monotonic() + 20
                status = None
                while time.monotonic() < end:
                    pid, status = os.waitpid(term.pid, os.WNOHANG)
                    if pid:
                        break
                    time.sleep(0.05)
                else:
                    os.kill(term.pid, 9)
                    self.fail("still running once its window closed")
                term.status = os.WEXITSTATUS(status)
                self.assertTrue(os.WIFEXITED(status))
                self.assertEqual(term.status, 129)

    def test_closing_the_window_while_it_installs(self):
        """The changing screen fails to draw on the closed window: that is
        the window's signal, not a crash with a log kept."""
        repo = self.repo(GameDataRepository, slow=True)
        scratch = repo.root / "scratch"
        scratch.mkdir()
        self.env["TMPDIR"] = str(scratch)
        term = self.start("--platform", "retroarch", "--dest", str(repo.dest), "--jobs", "1")
        term.wait("> Install")
        term.send("\r")
        term.wait("1 of 6 files")
        os.close(term.fd)
        end = time.monotonic() + 20
        while time.monotonic() < end:
            pid, status = os.waitpid(term.pid, os.WNOHANG)
            if pid:
                break
            time.sleep(0.05)
        else:
            os.kill(term.pid, 9)
            self.fail("still running once its window closed")
        term.status = os.WEXITSTATUS(status)
        self.assertEqual(term.status, 129)
        self.assertEqual(list(scratch.glob("retrobios-tui-*/error.log")), [])

    def test_no_key_on_the_first_screen_closes_it(self):
        """A mapper that never opens the pad left the first screen up for
        good: a handheld then has no way out but the power button."""
        self.repo()
        self.env[install.TUI_IDLE_ENV] = "1"
        term = self.start()
        term.wait("Where to install?")
        self.assertEqual(term.close(), install.QUIT_CODE)
        self.assertIn("No button pressed, closing.", term.after())
        # A key pressed, the screen stays: the person is there.
        term = self.start()
        term.wait("Where to install?")
        term.send(DOWN)
        end = time.monotonic() + 2.5
        while time.monotonic() < end:
            term._pump(0.05)
        self.assertEqual(os.waitpid(term.pid, os.WNOHANG), (0, 0))
        term.send("q")
        self.assertEqual(term.close(), install.QUIT_CODE)

    def test_no_key_on_a_screen_reached_by_itself_closes_it(self):
        """Given --platform, as the offline launcher route is, the check
        runs at once and the plan follows without a key: the close counted
        only on the first screen, and never came."""
        repo = self.repo()
        self.env[install.TUI_IDLE_ENV] = "1"
        term = self.start("--platform", "retroarch", "--dest", str(repo.dest))
        term.wait("> Install")
        self.assertEqual(term.close(), install.QUIT_CODE)
        self.assertIn("No button pressed, closing.", term.after())
        self.assertEqual(repo.installed(), [])

    def test_a_desktop_names_its_keys_and_a_pad_its_buttons(self):
        self.repo()
        for env, bar in (({"DISPLAY": ":0"}, "Enter Continue  Esc Quit  ? Help"),
                         ({"RETROBIOS_PAD": "gptokeyb", "DISPLAY": ":0"},
                          "A Continue  B Quit"),
                         ({"RETROBIOS_PAD": "muxterm"}, "Start Continue  B Quit")):
            with self.subTest(env=env):
                self.env.update(env)
                term = self.start(cols=40, rows=12)
                term.wait("Where to install?")
                screen = term.wait(bar)
                self.assertEqual(screen.splitlines()[-1].strip(), bar)
                term.send("q")
                self.assertEqual(term.close(), install.QUIT_CODE)
                for name in env:
                    self.env.pop(name)

    def test_resize_redraws(self):
        self.repo()
        term = self.start(cols=40, rows=15)
        term.wait("Where to install?")
        term.resize(100, 30)
        term.send(DOWN)
        screen = term.wait("> Another setup or folder")
        self.assertIn("B/Esc Quit", screen.splitlines()[29])
        term.resize(30, 10)
        term.wait("40x12 or more, now 30x10")
        term.resize(40, 12)
        term.wait("Where to install?")
        term.send("q")
        self.assertEqual(term.close(), install.QUIT_CODE)

    def test_plain_mode_keeps_the_line_questions(self):
        self.repo()
        for env in ({"RETROBIOS_PLAIN": "1"}, {"ACCESSIBLE": "1"}):
            with self.subTest(env=env):
                self.env.update(env)
                term = self.start()
                # The setup found is asked as the screen asks it.
                term.wait("Enter for RetroArch")
                term.send("\r")
                term.wait("Enter) install everything")
                term.send("q\r")
                term.close()
                self.assertNotIn(b"\x1b[?1049h", term.raw)
                for name in env:
                    self.env.pop(name)

    def test_dumb_terminal_writes_no_escape(self):
        """TERM unset printed the banner bold and dim, and redrew the
        progress with CSI, where the screen itself read it as dumb."""
        self.repo()
        for value in ("dumb", None):
            with self.subTest(term=value):
                if value is None:
                    self.env.pop("TERM", None)
                else:
                    self.env["TERM"] = value
                term = self.start()
                term.wait("Enter for RetroArch")
                term.send("\r")
                if value is None:
                    # In place since the first run: no menu, nothing asked.
                    term.wait("every one in place: nothing to install")
                else:
                    term.wait("Enter) install everything")
                    term.send("\r")
                term.wait("Done.")
                term.close()
                self.assertNotIn(b"\x1b", term.raw)

    def test_a_terminal_that_cannot_draw_the_screen_gets_the_questions(self):
        """TERM=vt52 moves the cursor with ESC Y: the screen opened and drew
        CSI sequences it printed as text."""
        self.repo()
        self.env["TERMINFO"] = str(_terminfo_folder(self))
        for name in ("rbtest-glass", "rbtest-vt52"):
            with self.subTest(term=name):
                self.env["TERM"] = name
                term = self.start()
                term.wait("Enter for RetroArch")
                term.send("\r")
                term.wait("Enter) install everything")
                term.send("q\r")
                term.close()
                self.assertNotIn(b"\x1b[?1049h", term.raw)
                term = self.start("--tui")
                self.assertEqual(term.close(), 2)
                said = term.raw.decode()
                self.assertIn(f"--tui cannot open the full-screen interface here: TERM={name}",
                              said)
                self.assertNotIn("\x1b", said)

    def test_no_color_draws_no_colour(self):
        """The screen marks the row in focus with > as well as reverse video,
        so NO_COLOR, or a terminal of fewer than 8 colours, takes the colour
        away and leaves the same screen."""
        self.repo()
        screens = {}
        for name, env in (("colour", {}), ("no_color", {"NO_COLOR": "1"}),
                          ("mono", {"TERM": "rbtest-mono",
                                    "TERMINFO": str(_terminfo_folder(self))})):
            with self.subTest(env=name):
                self.env.pop("NO_COLOR", None)
                self.env.update({"TERM": "xterm", **env})
                term = self.start()
                screen = term.wait("Where to install?")
                self.assertIn("> RetroArch", screen)
                screens[name] = screen
                # pyte reads the colours drawn: RetroBIOS in the accent.
                title = term.screen.buffer[0]
                at = screen.splitlines()[0].index("RetroBIOS")
                self.assertEqual(title[at].fg, "magenta" if name == "colour" else "default")
                term.send("q")
                self.assertEqual(term.close(), install.QUIT_CODE)
                colours = set()
                for params in re.findall(rb"\x1b\[([0-9;]*)m", term.raw):
                    colours |= {int(code) for code in params.split(b";") if code} & {
                        *range(30, 50), *range(90, 108)}
                self.assertEqual(bool(colours), name == "colour", colours)
        self.assertEqual(screens["colour"], screens["no_color"])
        self.assertEqual(screens["colour"], screens["mono"])


def _terminfo_entry(name: str, cup: str | None, extended: bool = False,
                    colours: int | None = 8) -> bytes:
    """A compiled term(5) entry holding the strings up to cursor_address,
    only that one set, and the numbers up to max_colors when colours is
    given, columns alone when it is not."""
    def short(value: int) -> bytes:
        return value.to_bytes(2, "little", signed=True)

    width = 4 if extended else 2
    names = name.encode() + b"|test terminal\0"
    table = (cup.encode("latin-1") + b"\0") if cup is not None else b""
    offsets = [-1] * (install._TERMINFO_CUP + 1)
    if cup is not None:
        offsets[install._TERMINFO_CUP] = 0
    numbers = [80] + ([-1] * (install._TERMINFO_COLORS - 1) + [colours]
                      if colours is not None else [])
    body = names + (b"\0" if len(names) % 2 else b"")
    body += b"".join(number.to_bytes(width, "little", signed=True) for number in numbers)
    body += b"".join(short(offset) for offset in offsets) + table
    header = b"".join(short(value) for value in (
        0o1036 if extended else 0o432, len(names), 0, len(numbers), len(offsets),
        len(table)))
    return header + body


def _terminfo_folder(test: unittest.TestCase) -> Path:
    """A $TERMINFO with a glass terminal, a VT52, two ANSI terminals of 8
    colours, one in the extended format, and two ANSI terminals without
    colour: one naming 2, one naming none (vt100)."""
    (REPO_ROOT / "tmp").mkdir(exist_ok=True)
    folder = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
    test.addCleanup(shutil.rmtree, folder, True)
    ansi = "\x1b[%i%p1%d;%p2%dH"
    for name, cup, extended, colours in (
            ("rbtest-glass", None, False, None),
            ("rbtest-vt52", "\x1bY%p1%' '%+%c%p2%' '%+%c", False, None),
            ("rbtest-ansi", ansi, False, 8),
            ("rbtest-ansi2", ansi, True, 256),
            ("rbtest-two", ansi, True, 2),
            ("rbtest-mono", ansi, False, None)):
        (folder / "r").mkdir(exist_ok=True)
        (folder / "r" / name).write_bytes(_terminfo_entry(name, cup, extended, colours))
    return folder


class TerminalsTheScreenCannotDraw(unittest.TestCase):
    """The screen writes CSI sequences: a terminal whose description moves
    the cursor otherwise, or not at all, gets the line questions."""

    def setUp(self):
        self.master, self.slave = os.openpty()
        self.addCleanup(os.close, self.master)
        self.addCleanup(os.close, self.slave)
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        self.tty = StartConditions._Tty(self.slave)
        self.env = {"TERMINFO": str(_terminfo_folder(self))}

    def blocker(self, term: str) -> str:
        return install.tui_blocker(_args(), self.tty, self.tty, {**self.env, "TERM": term})

    def test_the_cursor_address_is_read(self):
        self.assertEqual(install.terminal_cursor_address("rbtest-ansi", self.env),
                         "\x1b[%i%p1%d;%p2%dH")
        self.assertEqual(install.terminal_cursor_address("rbtest-ansi2", self.env),
                         "\x1b[%i%p1%d;%p2%dH")
        self.assertEqual(install.terminal_cursor_address("rbtest-glass", self.env), "")
        self.assertIsNone(install.terminal_cursor_address("rbtest-none", self.env))

    def test_ansi_opens_and_the_others_say_why(self):
        self.assertEqual(self.blocker("rbtest-ansi"), "")
        self.assertEqual(self.blocker("rbtest-ansi2"), "")
        self.assertEqual(self.blocker("rbtest-glass"),
                         "TERM=rbtest-glass cannot move the cursor")
        self.assertIn("escape sequences", self.blocker("rbtest-vt52"))

    def test_no_description_is_no_refusal(self):
        """Android and most handheld images carry no terminfo: the screen
        draws there as before."""
        self.assertEqual(self.blocker("rbtest-none"), "")
        self.assertEqual(self.blocker("../r/rbtest-glass"), "")

    def test_the_folders_are_searched_in_order(self):
        home = Path(self.env["TERMINFO"])
        (home / ".terminfo" / "r").mkdir(parents=True)
        (home / ".terminfo" / "r" / "rbtest-ansi").write_bytes(
            _terminfo_entry("rbtest-ansi", None))
        # $TERMINFO first, then ~/.terminfo, then $TERMINFO_DIRS.
        self.assertTrue(install.terminal_cursor_address(
            "rbtest-ansi", {**self.env, "HOME": str(home)}))
        self.assertEqual(install.terminal_cursor_address(
            "rbtest-ansi", {"HOME": str(home), "TERMINFO_DIRS": self.env["TERMINFO"]}), "")
        # macOS files a terminal under the hex of its first letter.
        (home / "72").mkdir()
        (home / "72" / "rbtest-hex").write_bytes(_terminfo_entry("rbtest-hex", None))
        self.assertEqual(install.terminal_cursor_address(
            "rbtest-hex", {"TERMINFO_DIRS": str(home)}), "")

    def test_the_line_questions_draw_no_escape_there_either(self):
        """The progress line redraws with CSI and paints with SGR: on a VT52
        both print as text, as on TERM=dumb."""
        for term, live in (("rbtest-ansi", True), ("rbtest-vt52", False),
                           ("rbtest-glass", False)):
            with self.subTest(term=term), mock.patch.dict(
                    os.environ, {**self.env, "TERM": term}), \
                    mock.patch.object(install, "_enable_ansi", return_value=True):
                os.environ.pop("NO_COLOR", None)
                shown = install.Terminal(self.tty)
                self.assertEqual((shown.live, shown.colour), (live, live))
                self.assertEqual(shown.ok("ok") == "ok", not live)

    def test_the_colours_are_read(self):
        self.assertEqual(install.terminal_colours("rbtest-ansi", self.env), 8)
        self.assertEqual(install.terminal_colours("rbtest-ansi2", self.env), 256)
        self.assertEqual(install.terminal_colours("rbtest-two", self.env), 2)
        self.assertEqual(install.terminal_colours("rbtest-mono", self.env), 0)
        self.assertIsNone(install.terminal_colours("rbtest-none", self.env))
        for data in (b"", b"\x00" * 12, _terminfo_entry("x", None, colours=8)[:40]):
            with self.subTest(data=data):
                self.assertIsNone(install.terminfo_number(data, install._TERMINFO_COLORS))

    def test_fewer_than_8_colours_draw_the_line_live_and_plain(self):
        """A vt100 moves the cursor the ANSI way and has no colour: the
        progress line still redraws, its words unpainted."""
        for term, colour in (("rbtest-ansi", True), ("rbtest-ansi2", True),
                             ("rbtest-two", False), ("rbtest-mono", False),
                             ("rbtest-none", True)):
            with self.subTest(term=term), mock.patch.dict(
                    os.environ, {**self.env, "TERM": term}), \
                    mock.patch.object(install, "_enable_ansi", return_value=True):
                os.environ.pop("NO_COLOR", None)
                shown = install.Terminal(self.tty)
                self.assertEqual((shown.live, shown.colour), (True, colour))
                self.assertEqual(shown.status("1 failed") != "1 failed", colour)

    def test_the_screen_draws_without_colour_for_each_reason(self):
        """NO_COLOR, TERM dumb or unset, fewer than 8 colours, an output no
        terminal: each turns the colour off, and says which."""
        for env, said in (({"TERM": "rbtest-ansi"}, ""),
                          ({"TERM": "rbtest-none"}, ""),
                          ({"TERM": "rbtest-ansi", "NO_COLOR": "1"}, "NO_COLOR is set"),
                          ({"TERM": "rbtest-ansi", "NO_COLOR": ""}, ""),
                          ({"TERM": "dumb"}, "TERM is dumb or not set"),
                          ({}, "TERM is dumb or not set"),
                          ({"TERM": "rbtest-two"},
                           "TERM=rbtest-two names 2 colours, fewer than 8"),
                          ({"TERM": "rbtest-mono"},
                           "TERM=rbtest-mono names 0 colours, fewer than 8")):
            with self.subTest(env=env):
                self.assertEqual(install.colour_blocker({**self.env, **env}, self.tty), said)
        self.assertEqual(install.colour_blocker({**self.env, "TERM": "rbtest-ansi"},
                                                io.StringIO()),
                         "the output is not a terminal")
        with mock.patch.dict(os.environ, {**self.env, "TERM": "rbtest-mono"}), \
                mock.patch.object(install, "_enable_ansi", return_value=True):
            self.assertFalse(install._TuiTerminal(self.tty, self.tty).colour)
            os.environ["TERM"] = "rbtest-ansi"
            os.environ.pop("NO_COLOR", None)
            self.assertTrue(install._TuiTerminal(self.tty, self.tty).colour)

    def test_an_unset_term_is_a_dumb_one(self):
        with mock.patch.dict(os.environ, {"FORCE_COLOR": ""}), \
                mock.patch.object(install, "_enable_ansi", return_value=True):
            for name in ("TERM", "NO_COLOR"):
                os.environ.pop(name, None)
            shown = install.Terminal(self.tty)
            self.assertEqual((shown.live, shown.colour), (False, False))
            with mock.patch.object(install.os, "name", "nt"):
                self.assertTrue(install.Terminal(self.tty).live)

    def test_a_damaged_description_is_no_description(self):
        for data in (b"", b"\x1a\x01", b"\x00" * 12, _terminfo_entry("x", "\x1b[H")[:-1]):
            with self.subTest(data=data):
                self.assertIsNone(install.terminfo_string(data, install._TERMINFO_CUP))


@unittest.skipUnless(pyte and pty and hasattr(pty, "fork"),
                     "screen tests need pyte (pip install pyte==0.8.2) and a pty")
class TheTerminalComesBack(unittest.TestCase):
    """However the screen ends or pauses, the terminal is handed back as it
    was lent: the cursor shown, the main screen, echo, lines and signals."""

    repo = EndToEnd.repo
    start = EndToEnd.start

    # What a new pseudo-terminal has, which the child started on.
    @staticmethod
    def fresh_modes() -> list:
        master, slave = os.openpty()
        try:
            return termios.tcgetattr(slave)
        finally:
            os.close(master)
            os.close(slave)

    def assertGivenBack(self, term: Pty, since: int = 0) -> None:
        raw = term.raw[since:]
        self.assertGreater(raw.rfind(b"\x1b[?1049l"), raw.rfind(b"\x1b[?1049h"), raw[-200:])
        self.assertGreater(raw.rfind(b"\x1b[?25h"), raw.rfind(b"\x1b[?25l"), raw[-200:])
        # Clicks are given back too: a shell left with them on reads each
        # one as a line of escape bytes.
        for mode in (b"1000", b"1006"):
            self.assertGreater(raw.rfind(b"\x1b[?" + mode + b"l"),
                               raw.rfind(b"\x1b[?" + mode + b"h"), raw[-200:])
        self.assertNotIn(b"\x1b[?1003h", raw)

    def assertModesBack(self, modes: list) -> None:
        fresh = self.fresh_modes()
        for index, flag in ((3, termios.ECHO), (3, termios.ICANON), (3, termios.ISIG),
                            (3, termios.IEXTEN), (0, termios.ICRNL), (0, termios.IXON)):
            self.assertEqual(modes[index] & flag, fresh[index] & flag, (index, flag))
        self.assertEqual(modes, fresh)

    def ended(self, how) -> Pty:
        self.repo()
        term = self.start()
        term.wait("Where to install?")
        # Every way out below starts with the clicks asked for, written
        # right after the frame.
        term.settle()
        self.assertIn(install._MOUSE_ON.encode(), term.raw)
        how(term)
        return term

    def test_ctrl_c(self):
        term = self.ended(lambda term: term.send("\x03"))
        self.assertEqual(term.close(), 130)
        self.assertGivenBack(term)
        self.assertModesBack(term.modes)

    def test_eof_on_stdin(self):
        """Ctrl-D, the terminal's end of input, typed at the screen."""
        term = self.ended(lambda term: term.send("\x04"))
        self.assertEqual(term.close(), 130)
        self.assertGivenBack(term)
        self.assertModesBack(term.modes)

    def test_sigterm(self):
        import signal

        term = self.ended(lambda term: os.kill(term.pid, signal.SIGTERM))
        self.assertEqual(term.close(), 128 + signal.SIGTERM)
        self.assertGivenBack(term)
        self.assertModesBack(term.modes)

    def test_sighup(self):
        """The hangup without the window gone (kill -HUP, an ssh session
        dropped while its pty lingers)."""
        import signal

        term = self.ended(lambda term: os.kill(term.pid, signal.SIGHUP))
        self.assertEqual(term.close(), 128 + signal.SIGHUP)
        self.assertGivenBack(term)
        self.assertModesBack(term.modes)

    def shell(self) -> Pty:
        """An interactive bash on a pseudo-terminal, a shell with job control
        as a person's terminal runs one."""
        self.repo()
        env = {**self.env, "PS1": "PROMPT$ ",
               "PATH": f"{Path(sys.executable).parent}{os.pathsep}{self.env.get('PATH', '')}"}
        term = Pty(["--norc", "--noprofile", "-i"], env, program=["/bin/bash"])
        self.addCleanup(lambda: term.status is None and os.killpg(term.pid, 9))
        term.wait("PROMPT$")
        return term

    def typed(self, term: Pty, line: str) -> None:
        os.write(term.fd, line.encode() + b"\r")

    @unittest.skipUnless(Path("/bin/bash").exists(), "a shell with job control")
    def test_ctrl_z_then_fg(self):
        """ISIG is off on the screen, so Ctrl-Z reached it as a byte and did
        nothing: the shell never got its terminal back. From a shell with
        job control it stops, and fg brings the screen back."""
        term = self.shell()
        self.typed(term, f"{shlex.quote(sys.executable)} {REPO_ROOT / 'install.py'} --tui")
        term.wait("Where to install?")
        mark = len(term.raw)
        term.send("\x1a")
        end = time.monotonic() + 10
        while b"PROMPT$" not in term.raw[mark:] and time.monotonic() < end:
            term._pump(0.05)
        self.assertIn(b"Stopped", term.raw[mark:], term.raw[mark:][-300:])
        self.assertGivenBack(term, mark)
        # fg: the shell's SIGCONT, and the screen is back, raw again.
        mark = len(term.raw)
        self.typed(term, "fg")
        end = time.monotonic() + 5
        while b"\x1b[?1049h" not in term.raw[mark:] and time.monotonic() < end:
            term._pump(0.05)
        self.assertIn(b"\x1b[?1049h", term.raw[mark:])
        term.wait("Where to install?")
        self.assertFalse(termios.tcgetattr(term.fd)[3] & termios.ECHO)
        # The clicks come back with the screen.
        term.settle()
        self.assertIn(install._MOUSE_ON.encode(), term.raw[mark:])
        term.send("q")
        term.wait("PROMPT$")
        self.typed(term, "exit")
        self.assertEqual(term.close(), install.QUIT_CODE)
        self.assertGivenBack(term)

    def test_ctrl_z_with_no_shell_to_resume_it_is_ignored(self):
        """Started straight on a terminal (a terminal
        app's -e, a desktop entry) or under a launcher's sh -c, nothing ever
        resumed the screen a Ctrl-Z stopped. It now goes on, and says why."""
        self.repo()
        for program in (None, ["/bin/sh", "-c", f"{shlex.quote(sys.executable)} "
                                                f"{REPO_ROOT / 'install.py'} \"$@\"", "sh"]):
            with self.subTest(program=program):
                term = Pty(["--tui"], self.env, program=program)
                self.addCleanup(lambda term=term: term.status is None
                                and os.killpg(term.pid, 9))
                term.wait("Where to install?")
                term.send("\x1a")
                screen = term.wait("Ctrl-Z is ignored")
                self.assertIn("no shell started this installer", " ".join(screen.split()))
                pid, status = os.waitpid(term.pid, os.WNOHANG | os.WUNTRACED)
                self.assertEqual(pid, 0, "stopped")
                term.send("q")
                self.assertEqual(term.close(), install.QUIT_CODE)
                self.assertGivenBack(term)

    def test_ctrl_z_needs_a_shell_that_can_resume(self):
        state = install.TuiState(os_type="linux", home=HOME)
        with mock.patch.object(install.os, "getpgrp", return_value=10), \
                mock.patch.object(install.os, "getsid", return_value=10):
            self.assertFalse(install.tui_ctrl_z(state))
        self.assertEqual(state.status, install.CTRL_Z_NO_SHELL)
        state.status = ""
        with mock.patch.object(install.os, "getpgrp", return_value=12), \
                mock.patch.object(install.os, "getsid", return_value=10):
            self.assertTrue(install.tui_ctrl_z(state))
        self.assertEqual(state.status, "")

    @staticmethod
    def proc_state(pid: int) -> str:
        """The state letter Linux gives a process (T is stopped)."""
        text = Path(f"/proc/{pid}/stat").read_text()
        return text[text.rindex(")") + 2]

    @staticmethod
    def children(pid: int) -> list[int]:
        found = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                text = (entry / "stat").read_text()
            except OSError:
                continue
            if int(text[text.rindex(")") + 2:].split()[1]) == pid:
                found.append(int(entry.name))
        return found

    @unittest.skipUnless(Path("/proc/self/stat").exists(), "reads process states in /proc")
    def test_ctrl_z_through_install_sh_stops_the_wrapper_and_the_install(self):
        """Ctrl-Z stopped the installer alone. install.sh,
        which runs it as a child, kept waiting, the shell never got its prompt
        back, and the install run behind the screen kept writing."""
        repo = self.repo(GameDataRepository, slow=True)
        env = {**self.env, "PS1": "PROMPT$ ",
               "PATH": f"{Path(sys.executable).parent}{os.pathsep}{self.env['PATH']}"}
        # Typed at an interactive bash, as a person runs it: install.sh is a
        # job of a shell that can resume it.
        term = Pty(["--norc", "--noprofile", "-i"], env, program=["/bin/bash"])
        self.addCleanup(lambda: term.status is None and os.killpg(term.pid, 9))
        term.wait("PROMPT$")
        self.typed(term, f"sh {REPO_ROOT / 'install.sh'} --jobs 1")
        term.wait("Where to install?")
        term.send("\r")
        term.wait("to download")
        term.send("\r")
        term.wait("Installing")
        time.sleep(0.8)
        wrapper = self.children(term.pid)
        self.assertEqual(len(wrapper), 1, wrapper)
        installer = self.children(wrapper[0])
        self.assertEqual(len(installer), 1, installer)
        runs = self.children(installer[0])
        self.assertTrue(runs, "no install run")
        mark = len(term.raw)
        term.send("\x1a")
        end = time.monotonic() + 10
        while b"PROMPT$" not in term.raw[mark:] and time.monotonic() < end:
            term._pump(0.05)
        # The wrapper is stopped: the shell reports its job stopped.
        self.assertIn(b"Stopped", term.raw[mark:], term.raw[mark:][-300:])
        self.assertEqual(self.proc_state(wrapper[0]), "T")
        self.assertEqual(self.proc_state(installer[0]), "T")
        self.assertEqual([self.proc_state(run) for run in runs], ["T"] * len(runs))
        written = sorted(repo.dest.rglob("*"))
        time.sleep(2)
        self.assertEqual(sorted(repo.dest.rglob("*")), written)
        # fg continues the job's group: the screen comes back and the install
        # carries on to its end.
        mark = len(term.raw)
        self.typed(term, "fg")
        end = time.monotonic() + 5
        while b"\x1b[?1049h" not in term.raw[mark:] and time.monotonic() < end:
            term._pump(0.05)
        self.assertIn(b"\x1b[?1049h", term.raw[mark:])
        term.wait("files installed", timeout=30)
        term.send("\r")
        term.wait("PROMPT$")
        self.typed(term, "exit")
        self.assertEqual(term.close(), 0)


class TheFolderScreenSaysWhatItOffers(unittest.TestCase):
    """The folder screen said "usually reads its BIOS files from" for any
    folder it offered: the folder named with --dest, reached by Change
    folder, and the built-in default while the retroarch.cfg found here
    names another. A closed folder found here opened on "No usual
    RetroArch folder here" under the setup that listed it."""

    def said(self, state: install.TuiState) -> str:
        return " ".join(" ".join(install.tui_view(state, 200, 40)).split())

    def test_change_folder_names_the_chosen_folder(self):
        state = checked_state()
        state.stack = ["setup", "plan"]
        mine = Path("/home/user/typed/mybios")
        state.dest = mine
        install._activate(state, install.TuiRow("folder", "Change folder"))
        self.assertEqual(state.screen, "folder")
        screen = self.said(state)
        self.assertNotIn("usually reads", screen)
        self.assertIn(f"The BIOS folder chosen for RetroArch: {mine}", screen)

    def test_another_setup_offers_the_folder_found_here(self):
        state = fresh_state()
        found = Path("/home/user/Games/bios")
        state.setups = [("retroarch", found, "RetroArch")]
        state.stack = ["setup", "platforms"]
        install._activate(state, install.TuiRow("platform", "RetroArch", value="retroarch"))
        self.assertEqual(state.folder_default, found)
        self.assertIn(f"RetroArch reads its BIOS files from: {found}", self.said(state))

    def test_with_none_found_the_usual_folder_is_offered(self):
        state = fresh_state()
        state.setups = []
        state.stack = ["setup", "platforms"]
        install._activate(state, install.TuiRow("platform", "RetroArch", value="retroarch"))
        self.assertIn("RetroArch usually reads its BIOS files from:", self.said(state))

    def test_a_closed_folder_found_here_asks_for_another(self):
        state = fresh_state()
        state.stack = ["setup"]
        with mock.patch.object(install, "closed_folder",
                               return_value=(Path("/home/user/lock"), "Permission denied")):
            install.tui_update(state, Key("enter"))
        self.assertEqual(state.screen, "folder")
        screen = self.said(state)
        self.assertNotIn("No usual RetroArch folder here", screen)
        self.assertIn("Choose another folder for RetroArch", screen)

    def test_a_refused_folder_puts_browse_under_a(self):
        for facts in ({"free": 10, "writable": True, "cores": []},
                      {"free": 50 * 1024 ** 3, "writable": False, "cores": []}):
            with self.subTest(facts=facts):
                state = checked_state(facts)
                self.assertEqual(install.tui_rows(state)[0].action, "folder")
                install.tui_update(state, Key("enter"))
                self.assertEqual(state.screen, "folder")
                rows = install.tui_rows(state)
                self.assertEqual(rows[state.focus["folder"]].action, "browse")


class ThePlanNumbersAddUp(unittest.TestCase):
    """"47 files to download" sat above "49 missing, 1 wrong copy": the 3
    found on this machine were the difference, left to the reader."""

    @in_full
    def test_the_copied_files_are_the_difference(self):
        state = checked_state()
        state.found = [found("scph5500.bin", str(SYSTEM_DIR), "one folder too deep")]
        screen = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertIn("3 files to download", screen)
        # The backup line under the count it explains, then the split.
        self.assertIn("1 in place, 3 missing, 1 wrong copy The 1 wrong copy is replaced, the "
                      "old one kept in a backup folder. 4 to install: 1 copied from this "
                      "machine, 3 downloaded", screen)


class GameDataIsNoFirmwareAlarm(unittest.TestCase):
    """Every RetroArch plan named jazz2/Source/Anims.j2a (jazz-jackrabbit-2)
    as the file needed to start an emulator: a game's data, under a raw id."""

    def test_game_data_has_its_own_line(self):
        state = checked_state()
        state.systems = []
        state.manifest = {**MANIFEST, "omitted_files": [
            {"dest": "jazz2/Source/Anims.j2a", "system": "jazz-jackrabbit-2",
             "required": True, "category": "game_data"},
            {"dest": "missing.bin", "system": "sony-playstation", "required": True}]}
        lines = install._unavailable_lines(state)
        self.assertEqual(len(lines), 2, lines)
        self.assertIn("needed to start its emulator: missing.bin", lines[0])
        self.assertNotIn("Anims.j2a", lines[0])
        # The folder it goes in, and what game data is (the Android run of
        # 2026-10-27 said neither).
        # The names first, the kind in a word, the definition on its own
        # line of the plan.
        self.assertIn("Not available here: jazz2/Source/Anims.j2a (Jazz Jackrabbit 2), game "
                      "data its game reads. Copy it", lines[1])
        self.assertNotIn("files a game or a game engine reads", lines[1])
        self.assertIn(f"into {SYSTEM_DIR / 'jazz2' / 'Source'}{os.sep}", lines[1])
        self.assertIn("Anims.j2a (Jazz Jackrabbit 2)", lines[1])


class TheHelpNamesKeysThatCome(unittest.TestCase):
    """Every route's help listed "?, F1  This help", which no pad sends, and
    a key as wide as the column touched its text."""

    def test_pad_routes_name_no_help_key(self):
        for pad in ROUTES:
            with self.subTest(route=pad):
                state = checked_state()
                state.pad = pad
                keys = [key for key, _what in install._help_lines(state)]
                self.assertEqual("?, F1" in keys, pad == "keys")

    def test_a_wide_key_keeps_two_spaces(self):
        state = checked_state()
        state.help = True
        with mock.patch.object(install, "_help_lines",
                               return_value=[("A, Start, Enter, Space, x", "Choose"),
                                             ("q", "Quit")]):
            lines = install._view_help(state, 80, 24)[1]
        self.assertTrue(any("A, Start, Enter, Space, x  Choose" in line for line in lines))


class CopyFromStartsInDownloads(unittest.TestCase):
    """A ZIP in Downloads took 18 presses from the first screen: the copy
    browser opened at HOME, under every mounted drive."""

    def test_a_zip_in_downloads_opens_there(self):
        home = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, home, True)
        (home / "Downloads").mkdir()
        state = checked_state()
        state.home = home
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            install._open_from_browser(state)
            self.assertEqual(state.browse_dir, home)
            state.stack.pop()
            (home / "Downloads" / "PSX BIOS.zip").write_bytes(b"")
            install._open_from_browser(state)
        self.assertEqual(state.browse_dir, home / "Downloads")


class NothingFoundIsSaid(unittest.TestCase):
    """With nothing detected the first screen was the list of 18 setups,
    with no line at 40x15 saying nothing was found, which the beginner's
    page names."""

    def test_at_every_size(self):
        with mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "_mounted_cards", return_value=[]):
            state, _effects = install.tui_start(_args(), "linux")
        self.assertEqual(state.screen, "platforms")
        for cols, rows in ((40, 12), (40, 15), (80, 24)):
            with self.subTest(size=f"{cols}x{rows}"):
                screen = " ".join(" ".join(install.tui_view(state, cols, rows)).split())
                self.assertIn("Nothing was found here", screen)
        page = (REPO_ROOT / "wiki" / "first-install.md").read_text(encoding="utf-8")
        self.assertIn("Nothing was found here", page)


class AFocusesNoSystemFolder(unittest.TestCase):
    """At / A went into bin/, and at a drive root holding $RECYCLE.BIN into
    the recycle bin, which Use this folder then took as the BIOS folder."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.home, True)
        self.state = install.TuiState(os_type="linux", home=self.home)
        self.state.platform = "retroarch"
        self.state.stack = ["folder", "browse"]

    def focused(self) -> install.TuiRow:
        return self.state.browse_rows[self.state.focus["browse"]]

    def test_the_recycle_bin_and_restore_points_are_passed_over(self):
        for name in ("$RECYCLE.BIN", "System Volume Information", "Games"):
            (self.home / name).mkdir()
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            install._browse_to(self.state, self.home)
        self.assertEqual(self.focused().label, "Games/")

    def test_explorer_hidden_folders_are_passed_over(self):
        for name in ("Boot", "Games"):
            (self.home / name).mkdir()
        real_stat = os.stat

        def stat(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            hidden = 0x2 | 0x4 if Path(path).name == "Boot" else 0
            return types.SimpleNamespace(st_file_attributes=hidden, st_mode=result.st_mode)

        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install.os, "stat", stat):
            install._browse_to(self.state, self.home)
        self.assertEqual(self.focused().label, "Games/")

    def test_at_the_root_no_system_folder_is_focused(self):
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            install._browse_to(self.state, Path("/"))
        row = self.focused()
        if row.action == "dir":
            self.assertNotIn(row.value.name, install._POSIX_ROOT_SYSTEM)
        names = {r.value.name for r in self.state.browse_rows if r.action == "dir"}
        if "bin" in names and names - install._POSIX_ROOT_SYSTEM - {""}:
            self.assertEqual(row.action, "dir")



def _card_from_rules(root: Path, setup: install.CardSetup) -> Path:
    """A card as setup's system leaves it, written from the rules that
    tell it: a test that names each marker by hand misses the next one."""
    root.mkdir(parents=True, exist_ok=True)
    if setup.plat in install.CARD_PLATFORMS:
        (root / ".system").mkdir(exist_ok=True)
        prefix = next(prefix for name, _marker, prefix in install._CARD_RULES
                      if name == setup.plat)
        (root / install.CARD_MARKER).write_text(f"{prefix}20250101\n", encoding="utf-8")
    for rule in setup.rules[:1]:
        if rule.method == "file_matches":
            path, pattern = rule.values
            text = re.sub(r"\\(.)", r"\1", pattern.strip("^$").replace(r"\s*", ""))
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text + "\n", encoding="utf-8")
            continue
        if rule.method == "games_part":
            # What the system writes beside its bios folder on that part.
            (root / "bios").mkdir(exist_ok=True)
        for value in rule.values:
            (root / value).parent.mkdir(parents=True, exist_ok=True)
            # A marker the BIOS folder sits under is a folder on the card
            # (muOS's MUOS/bios): written as a file, no folder fits below it.
            if (rule.method == "games_part" and "." not in PurePosixPath(value).name
                    or str(setup.below).startswith(f"{value}/")):
                (root / value).mkdir(exist_ok=True)
            else:
                (root / value).write_text("", encoding="utf-8")
    return root


def _card_row(setup: install.CardSetup) -> str:
    """The setup list's row of a card system: MiSTer's board sits on a desk
    and keeps its plain row among the platforms."""
    return setup.name if setup.plat in install._DESK_CARDS else f"{setup.name}, SD card"


def _setup_folder(setup: install.CardSetup, card: Path) -> Path:
    return card / setup.below if setup.below else card


class EveryCardSetupGoesToItsCard(unittest.TestCase):
    """The card setups were fixed one
    by one, and UnofficialOS, ArchR, ArkOS, MiyooCFW and the Anbernic
    firmware stayed on the RetroArch row, which listed them and opened this
    computer's folder. Each system that runs from its SD card, from every
    way in, goes to its card."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.setups = install.card_setups()

    def test_one_list_holds_every_card_system(self):
        names = {setup.name for setup in self.setups}
        self.assertLessEqual({rule.name for rule in install._card_rules()}, names)
        self.assertLessEqual(set(install._systems_reading()["retroarch"]), names)
        self.assertLessEqual({install.display_name(plat) for plat in install.CARD_PLATFORMS},
                             names)
        self.assertLessEqual({"Onion", "spruceOS", "muOS", "JELOS", "ROCKNIX", "KNULLI",
                              "ArkOS", "dArkOS", "UnofficialOS", "ArchR", "MiyooCFW",
                              "Anbernic stock firmware", "Allium", "Koriki", "CrossMix-OS",
                              "MinUI", "NextUI", "MyMinUI"}, names)
        self.assertEqual(len(names), len(self.setups))
        # A system the guide writes is one of them.
        try:
            import yaml
        except ImportError:
            return
        guides = yaml.safe_load((REPO_ROOT / "platforms" / "_guides.yml").read_text())
        for system in guides["handheld_guide"]["systems"]:
            with self.subTest(system=system["name"]):
                self.assertIn(system["name"], names)

    def test_its_folder_is_the_one_the_guide_names(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("pyyaml is not installed")
        guides = yaml.safe_load((REPO_ROOT / "platforms" / "_guides.yml").read_text())
        below = {setup.name: setup.below for setup in self.setups}
        for system in guides["handheld_guide"]["systems"]:
            folder = re.search(r"`([^`]+)`", system.get("folder", ""))
            if folder:
                with self.subTest(system=system["name"]):
                    self.assertTrue(folder.group(1).endswith(below[system["name"]]),
                                    (folder.group(1), below[system["name"]]))

    def platforms(self, needle: str = "") -> install.TuiState:
        state = fresh_state()
        state.stack = ["setup", "platforms"]
        state.filters["platforms"] = needle
        return state

    def test_the_setup_list_has_a_row_for_each_without_the_filter(self):
        state = self.platforms()
        rows = install.tui_rows(state)
        self.assertEqual({row.value: row for row in rows if row.action == "platform"}[
            "retroarch"].right, "")
        for setup in self.setups:
            with self.subTest(system=setup.name):
                state = self.platforms()
                rows = install.tui_rows(state)
                index = next(i for i, row in enumerate(rows)
                             if row.label == _card_row(setup))
                state.focus["platforms"] = index
                with mock.patch.object(install, "_mounted_cards", return_value=[]):
                    effects = press(state, "enter")
                    text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
                self.assertEqual((effects, state.screen), ([], "folder"))
                self.assertEqual(state.card_bound, (setup.name, setup.below))
                self.assertIsNone(state.folder_default)
                self.assertIn("Where is the SD card?", text)
                self.assertNotIn(str(SYSTEM_DIR), text)

    def test_its_name_in_the_filter_finds_its_row(self):
        for setup in self.setups:
            with self.subTest(system=setup.name):
                rows = install.tui_rows(self.platforms(setup.name))
                self.assertIn(_card_row(setup), [row.label for row in rows])

    def test_platform_named_on_a_computer_asks_for_the_card(self):
        for setup in self.setups:
            with self.subTest(system=setup.name):
                plat = install.normalize_platform(setup.name, say=False)
                self.assertEqual(plat, setup.plat)
                self.assertEqual(install.card_bound(setup.name, plat),
                                 (setup.name, setup.below))
                with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                        contextlib.redirect_stderr(io.StringIO()) as err, \
                        self.assertRaises(SystemExit) as stop:
                    install.card_install_dest(setup.name, plat, interactive=False)
                self.assertEqual(stop.exception.code, 1)
                self.assertIn(f"{setup.name} keeps its BIOS files on its SD card",
                              err.getvalue())
                with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                        mock.patch.object(install, "detect_platforms", return_value=[
                            ("retroarch", SYSTEM_DIR)]), \
                        mock.patch.object(install, "detect_frontends", return_value=[]):
                    state, effects = install.tui_start(_args(platform=setup.name), "linux")
                self.assertEqual((effects, state.screen), ([], "folder"))
                self.assertEqual(state.card_bound, (setup.name, setup.below))
                self.assertIsNone(state.folder_default)

    def test_the_line_menu_offers_it_and_asks_for_its_card(self):
        offered = [name for name, _label in install._line_setups()]
        for setup in self.setups:
            with self.subTest(system=setup.name):
                key = setup.plat if setup.name == install.display_name(setup.plat) \
                    else setup.name
                self.assertIn(key, offered)
                card = _card_from_rules(self.root / f"menu{offered.index(key)}", setup)
                with mock.patch.object(install, "_choose_platform", return_value=key), \
                        mock.patch.object(install, "_mounted_cards", return_value=[]), \
                        mock.patch.object(install, "_ask", return_value=str(card)), \
                        contextlib.redirect_stdout(io.StringIO()):
                    chosen = install._prompt_manual_platform("linux", ask=False)
                self.assertEqual(chosen, [(setup.plat, _setup_folder(setup, card))])

    def test_its_card_gives_one_folder_whichever_way_it_is_named(self):
        for index, setup in enumerate(self.setups):
            with self.subTest(system=setup.name):
                card = _card_from_rules(self.root / f"card{index}", setup)
                # a card no file names gets its folder
                # below the root with --dest too, as typed.
                want = _setup_folder(setup, card)
                with contextlib.redirect_stdout(io.StringIO()):
                    by_dest = install.card_dest(setup.name, setup.plat, card)
                self.assertEqual(by_dest, (setup.plat, want))
                with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                        mock.patch.object(install, "detect_platforms", return_value=[]), \
                        mock.patch.object(install, "detect_frontends", return_value=[]):
                    state, _effects = install.tui_start(
                        _args(platform=setup.name, dest=str(card)), "linux")
                    self.assertEqual(state.dest, want)
                    # --dest alone, then the setup's row: the folder of the
                    # same --dest.
                    state, _effects = install.tui_start(_args(dest=str(card)), "linux")
                    if state.screen == "platforms":
                        rows = install.tui_rows(state)
                        label = (f"{setup.name}, SD card")
                        state.focus["platforms"] = [row.label for row in rows].index(label)
                        press(state, "enter")
                    self.assertEqual(state.dest, want)
                # Its card chosen as a card's root: its BIOS folder below it.
                if setup.known():
                    choice = install.card_choice(setup.name, setup.plat, card)
                    self.assertEqual((choice.refused, choice.folder),
                                     ("", _setup_folder(setup, card)))

    def test_another_systems_card_is_refused_for_each(self):
        """KNULLI and ROCKNIX took a
        muOS or an Onion card, and wrote their layout into it."""
        cards = {}
        for name in ("muOS", "Onion", "MinUI"):
            setup = next(item for item in self.setups if item.name == name)
            cards[name] = _card_from_rules(self.root / name, setup)
        for setup in self.setups:
            for name, card in cards.items():
                if name == setup.name or (name == "MinUI"
                                          and setup.plat in install.CARD_PLATFORMS):
                    continue
                with self.subTest(system=setup.name, card=name):
                    choice = install.card_choice(setup.name, setup.plat, card)
                    self.assertIn(f"is {install._a(name)} card, not "
                                  f"{install._a(setup.name)} card", choice.refused)
                    self.assertTrue(install.card_choice(setup.name, setup.plat,
                                                        card).refused)
                    with mock.patch.object(install, "_mounted_cards",
                                           return_value=list(cards.values())):
                        self.assertNotIn(card, install.mounted_cards_of(setup.name,
                                                                        setup.plat))

    def test_a_games_part_named_by_its_bios_folder_is_its_card(self):
        """AmberELEC and EmuELEC write bios/ below their games part, as
        RetroDECK below its folder. Their BIOS folder named got bios/bios
        on a card not started once, and was refused on one started."""
        for setup in self.setups:
            if setup.name not in install._GAMES_PART_CARDS:
                continue
            started = _card_from_rules(self.root / setup.name / "started", setup)
            blank = self.root / setup.name / "blank"
            (blank / "bios").mkdir(parents=True)
            for card in (started, blank):
                with self.subTest(system=setup.name, card=card.name):
                    choice = install.card_choice(setup.name, setup.plat, card / "bios")
                    self.assertEqual((choice.refused, choice.folder), ("", card))
            # A folder named bios holding bios/ is a card's root, as named.
            nested = self.root / setup.name / "bios"
            (nested / "bios").mkdir(parents=True)
            self.assertEqual(install.card_choice(setup.name, setup.plat, nested).folder,
                             nested)

    def test_a_mister_card_gets_its_files_below_games(self):
        """A MiSTer card mounted on a computer got RetroArch's list, and
        with --platform misterfpga its files at the root, where MiSTer
        reads none: it reads games/<core>/ below /media/fat."""
        card = self.root / "MiSTer"
        (card / "games").mkdir(parents=True)
        (card / "_Computer").mkdir()
        for name in ("MiSTer", "menu.rbf", "MiSTer.ini"):
            (card / name).write_text("", encoding="utf-8")
        self.assertEqual(install.card_system(card),
                         ("misterfpga", card / "games", "MiSTer FPGA"))
        for named in (card, card / "games"):
            with self.subTest(named=named.name):
                choice = install.card_choice("misterfpga", "misterfpga", named)
                self.assertEqual((choice.refused, choice.folder), ("", card / "games"))
        # A folder holding a games folder and nothing of MiSTer's is no card.
        other = self.root / "stick"
        (other / "games").mkdir(parents=True)
        self.assertIsNone(install.card_system(other))

    def test_a_blank_drive_is_refused_where_the_card_always_names_its_system(self):
        blank = self.root / "BLANK"
        blank.mkdir()
        for setup in self.setups:
            with self.subTest(system=setup.name):
                choice = install.card_choice(setup.name, setup.plat, blank)
                if setup.known() and not setup.fresh:
                    self.assertIn(f"is not {install._a(setup.name)} SD card", choice.refused)
                else:
                    self.assertEqual((choice.refused, choice.folder),
                                     ("", _setup_folder(setup, blank)))
                    self.assertTrue(choice.note)


class ConfirmRefusalsAndCardRows(unittest.TestCase):
    """Confirm before an install, refusals said in full, and card rows."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)

    def onion(self, name: str = "ONION") -> Path:
        card = self.root / name
        make_card(card, "Onion")
        return card

    def test_continue_never_installs_without_confirm(self):
        """A on a system, the ticks unchanged, installed at once,
        offline too where the plan had no Install."""
        state = checked_state()
        press(state, "down", "enter")
        self.assertEqual(state.screen, "systems")
        # A ticks there, and Done goes back to the plan: nothing runs from
        # the list.
        self.assertEqual(install._primary(state), "A/Enter Tick")
        self.assertEqual(press(state, "enter"), [])
        self.assertEqual(state.screen, "systems")
        self.assertEqual(press(state, "enter"), [])
        self.assertEqual(press(state, "esc"), [])
        self.assertEqual(state.screen, "plan")

    def test_offline_with_nothing_on_hand_runs_nothing_from_the_list(self):
        state = checked_state()
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            state.focus["plan"] = [row.action for row in install.tui_rows(state)].index(
                "systems")
            press(state, "enter")
            # A ticks: the list runs nothing. The way to
            # Confirm is Space on the plan's Install.
            self.assertEqual(press(state, "enter", "esc"), [])
            state.focus["plan"] = 0
            state.must_confirm = True
            install._push(state, "confirm")
            install._start_run(state, "confirm")
            install.tui_receive(state, ("event", state.run_id, dict(CHECK)))
            for event in FILES:
                install.tui_receive(state, ("event", state.run_id, dict(event)))
            install.tui_receive(state, ("ended", state.run_id, 0, []))
            self.assertEqual([row.action for row in install.tui_rows(state)], ["back"])
            view = install.tui_view(state, 40, 12)
            text = " ".join(" ".join(view).split())
        self.assertEqual(state.screen, "confirm")
        # Back alone, no word of an Install.
        self.assertNotIn("before Install", text)
        self.assertNotIn("backup folder", text)
        self.assertIn("Copy them from an old card", text)
        # The short names at 40 columns, as every screen of that width.
        self.assertEqual(view[-1].strip(), "A Back  ? Help")

    def test_a_refusal_shows_at_40x12_on_type_a_path(self):
        """Enter seemed to do nothing, the refusal drawn below the
        last line."""
        blank = self.root / "USBSTICK"
        blank.mkdir()
        state = fresh_state()
        state.stack = ["setup", "folder", "path"]
        state.platform, state.card_bound = "retroarch", ("Onion", "BIOS")
        state.path_text = str(blank)
        press(state, "enter")
        self.assertEqual(state.screen, "path")
        text = " ".join(" ".join(install.tui_view(state, 40, 12)).split())
        self.assertIn("Not an Onion SD card: no Onion files on it.", text)
        self.assertNotIn("Ctrl-U clears", text)
        # no hidden folder named in the short form, the detail after.
        self.assertNotIn(".tmp_update", state.status)
        self.assertIn(".tmp_update", state.status_more)
        # the prompt asks for the card.
        self.assertIn("The top folder of the Onion SD card:", text)

    def test_the_help_says_the_refusal_in_full(self):
        state = fresh_state()
        state.stack = ["setup", "folder"]
        state.platform, state.card_bound = "retroarch", ("Onion", "BIOS")
        blank = self.root / "STICK"
        blank.mkdir()
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            install._choose_card(state, blank)
            press(state, "?")
            text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("STICK is not an Onion SD card: no Onion files on it. Onion keeps "
                      ".tmp_update at the root of its card.", text)

    def test_wsl_drive_letters_are_taken_as_typed(self):
        """The screen says D:, and D: typed was refused."""
        with mock.patch.dict(install._WSL, {"active": True}):
            for typed in ("D:", "D:\\", "d:\\", "\"D:\\\""):
                with self.subTest(typed=typed):
                    self.assertEqual(install._typed_folder(typed), Path("/mnt/d"))
                    self.assertEqual(install.typed_path(typed), Path("/mnt/d"))
            self.assertEqual(install._typed_folder("E:\\bios"), Path("/mnt/e/bios"))
            args = _args(dest=Path("D:\\"))
            install._wsl_dest(args)
            self.assertEqual(args.dest, Path("/mnt/d"))
            card = Path("/mnt/d")
            with mock.patch.object(install, "_card_what", return_value="Onion card"):
                self.assertEqual(install.card_line(card), "D: (Onion card)")
        self.assertEqual(install._typed_folder("D:"), Path("D:"))

    def test_a_dest_refused_on_the_setup_list_names_dest(self):
        """"Choose the root of the Onion card", where
        --dest fixes the folder, and the refused system stayed chosen."""
        blank = self.root / "USBSTICK"
        blank.mkdir()
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, _effects = install.tui_start(_args(dest=str(blank)), "linux")
            state.filters["platforms"] = "onion"
            state.focus["platforms"] = 1
            self.assertEqual(install.tui_rows(state)[1].label, "Onion, SD card")
            self.assertEqual(press(state, "enter"), [])
        self.assertEqual(state.screen, "platforms")
        # --dest is fixed: a stick that is no card is named again in the
        # command, another setup would not help.
        self.assertIn("Run it again with the card's top folder.", state.status)
        self.assertNotIn("choose another setup", state.status)
        self.assertEqual((state.platform, state.card_bound), ("", None))

    def test_on_the_device_a_folder_typed_is_taken_as_typed(self):
        """A KNULLI got bios added to what was typed."""
        share = self.root / "userdata" / "share"
        share.mkdir(parents=True)
        state = fresh_state()
        state.stack = ["setup", "platforms"]
        state.platform, state.card_bound = "knulli", ("KNULLI", "bios")
        install._open_folder_screen(state, Path("/userdata/bios"), "found")
        state.stack.append("path")
        state.path_text = str(share)
        text = " ".join(install.tui_view(state, 80, 24))
        self.assertIn("The folder for KNULLI:", text)
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            press(state, "enter")
        self.assertEqual(state.dest, share)

    def test_a_card_in_a_reader_asks_for_its_card_once(self):
        """"Which folder? Onion reads
        its BIOS files from" on a computer, the same card listed twice."""
        first, second = self.onion("D"), self.onion("E")
        with mock.patch.object(install, "_mounted_cards", return_value=[first, second]), \
                mock.patch.object(install, "detect_platforms",
                                  return_value=[("retroarch", SYSTEM_DIR)]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, _effects = install.tui_start(_args(), "linux")
            self.assertEqual(len(state.setups), 3)
            state.focus["setup"] = len(state.setups)
            press(state, "enter")
            state.filters["platforms"] = "onion"
            state.focus["platforms"] = 1
            press(state, "enter")
            rows = install.tui_rows(state)
            title = install.tui_view(state, 80, 24)[0]
        self.assertIn("Where is the SD card?", title)
        self.assertEqual([(row.action, row.value) for row in rows][:2],
                         [("card", first), ("card", second)])
        self.assertNotIn("default", [row.action for row in rows])
        # The RetroArch row stays this computer's, never the card's folder.
        state.stack = ["setup", "platforms"]
        state.filters["platforms"] = ""
        state.focus["platforms"] = install._platform_focus(state, "retroarch")
        with mock.patch.object(install, "_mounted_cards", return_value=[first, second]):
            press(state, "enter")
        self.assertEqual(state.folder_default, SYSTEM_DIR)

    def test_browsing_for_a_card_starts_on_the_drives(self):
        """The browser opened on the home folder, Use this
        folder focused, saying to go back, the cards listed under it."""
        card = self.onion()
        state = fresh_state()
        state.stack = ["setup", "platforms"]
        state.platform, state.card_bound = "retroarch", ("Onion", "BIOS")
        with mock.patch.object(install, "_mounted_cards", return_value=[card]):
            install._open_folder_screen(state, None)
            state.focus["folder"] = [row.action for row in install.tui_rows(state)].index(
                "browse")
            press(state, "enter")
            rows = install.tui_rows(state)
        self.assertEqual(state.screen, "browse")
        self.assertEqual(rows[state.focus["browse"]].value, card)
        self.assertEqual(state.status, "Choose the Onion card below.")

    def test_a_number_outside_the_list_is_said(self):
        """9 was read as a folder."""
        card, other = self.onion(), self.onion("SECOND")
        answers = iter(["9", "0", "2"])
        with mock.patch.object(install, "_mounted_cards", return_value=[card, other]), \
                mock.patch.object(install, "_ask", side_effect=lambda _p: next(answers)), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("onion", "retroarch", True)
        self.assertEqual(dest, other / "BIOS")
        self.assertEqual(out.getvalue().count(
            "Type a number from 1 to 2, a folder, Enter to look again, or q to quit."), 2)

    def test_the_articles_read(self):
        self.assertEqual([install._a(name) for name in ("Onion", "Allium", "ArkOS", "muOS",
                                                        "KNULLI")],
                         ["an Onion", "an Allium", "an ArkOS", "a muOS", "a KNULLI"])

    def test_every_card_row_reads_the_same(self):
        """KNULLI, ROCKNIX and the MinUI family asked for
        their card without saying so."""
        state = fresh_state()
        state.stack = ["setup", "platforms"]
        labels = {row.value: row.label for row in install.tui_rows(state)
                  if row.action == "platform"}
        for plat in ("knulli", "rocknix", "minui", "nextui", "myminui"):
            self.assertEqual(labels[plat], f"{install.display_name(plat)}, SD card")
        self.assertEqual(labels["retroarch"], "RetroArch")
        # On the device itself it is that device's setup, not a card.
        share = Path("/userdata/bios")
        state.setups.append(("knulli", share, "KNULLI"))
        with mock.patch.dict(install._DETECTED_OS, {("knulli", share): "KNULLI"}):
            labels = {row.value: row.label for row in install.tui_rows(state)
                      if row.action == "platform"}
        self.assertEqual(labels["knulli"], "KNULLI")

    @in_full
    def test_offline_plan_counts_agree(self):
        """"3 downloaded" under "3 need the internet";
        the data files read as if on hand."""
        state = checked_state()
        state.found = [{"event": "found", "platform": "retroarch", "dest": FILES[0]["dest"],
                        "folder": "/media/old", "path": "/media/old/x", "member": "",
                        "reason": ""}]
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: install.OFFLINE_FLAG_VALUE}):
            text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
            self.assertNotIn("downloaded", text)
            state.found = []
            state.check = dict(state.check, data_missing=2636, data_bytes=40 * 1024 * 1024)
            text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        # One count of files, the kinds apart under the folder: "4 files and
        # 2636 data files" read as two kinds of one.
        self.assertIn("2640 files need the internet, which --offline does not use", text)
        self.assertIn("2636 data files (40.0 MB).", text)

    def test_the_error_row_and_the_bar_agree(self):
        """"Choose another setup or folder" over
        "A/Enter Back"."""
        state = checked_state()
        state.run = "check"
        install._fail(state, ["went wrong"], 1)
        state.focus["error"] = 0
        self.assertEqual(install.tui_rows(state)[0].label, "Choose another setup or folder")
        self.assertEqual(install._primary(state), "A/Enter Choose")
        press(state, "enter")
        self.assertNotEqual(state.screen, "error")

    def test_a_long_name_keeps_a_size_at_40_columns(self):
        """Nintendo Game Boy Advance lost its size.
        It also kept it rounded, 3 KB beside a total of
        2.7 KB. The size stays whole, the name is cut."""
        row = install.TuiRow("system", "[x] Nintendo Game Boy Advance", "1 file, 16.0 KB",
                             "nintendo-gba", narrow=("16.0 KB",), keep_right=True)
        line = str(install._row_line(row, False, 38)).rstrip()
        self.assertTrue(line.endswith("16.0 KB"), line)
        self.assertRegex(line, r"Nintendo Game Boy A?d?\.\.\.")

    def test_the_shared_note_keeps_its_line(self):
        """The page held 4, 3 and 5 systems as the note
        came and went, and "+19" read as 19 more."""
        state = OneSystemInFewPresses().long_list("keys")
        state.files = [{"event": "file", "dest": "mame.zip", "size": 10,
                        "systems": ["sys-00", "sys-01"]},
                       {"event": "file", "dest": "two.zip", "size": 10,
                        "systems": ["sys-00", "sys-01"]}]
        state.stack.append("systems")
        footers = set()
        for focus in range(1, 10):
            state.focus["systems"] = focus
            lines = install.tui_view(state, 40, 12)
            footers.add(next(i for i, line in enumerate(lines) if "of 66 systems:" in line))
        self.assertEqual(len(footers), 1, footers)
        state.focus["systems"] = 1
        self.assertIn(" +2 shared: counted once", install.tui_view(state, 40, 12))


class OneCardReading(unittest.TestCase):
    """One reading
    of a card's root, said the same on the screen and in line mode."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        patcher = mock.patch.dict(install._DETECTED_OS, {})
        patcher.start()
        self.addCleanup(patcher.stop)

    def blank(self, name: str = "USBSTICK") -> Path:
        stick = self.root / name
        (stick / "photos").mkdir(parents=True)
        return stick

    def start(self, **given) -> install.TuiState:
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, _effects = install.tui_start(_args(**given), "linux")
        return state

    def test_a_blank_card_gets_one_folder_and_one_note_everywhere(self):
        """--dest kept the stick's
        root, typed it got bios below it, and the screen said nothing."""
        stick = self.blank()
        for named, plat, below in (("knulli", "knulli", "bios"),
                                   ("rocknix", "rocknix", "roms/bios"),
                                   ("ArkOS", "retroarch", "bios")):
            with self.subTest(system=named):
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    by_dest = install.card_dest(named, plat, stick)
                self.assertEqual(by_dest, (plat, stick / below))
                note = install.card_choice(named, plat, stick).note
                self.assertTrue(note)
                self.assertIn(note, out.getvalue())
                state = self.start(platform=named, dest=str(stick))
                self.assertEqual(state.dest, stick / below)
                self.assertEqual(state.card_note, note)
                # one rule with line mode, whose question
                # creates one missing level and says it. Two are asked, and
                # the note is kept on Create the folder? and on the plan.
                one = (stick / below).parent.is_dir()
                self.assertEqual(state.screen, "checking" if one else "create")
                if not one:
                    self.assertIn(note.split(":")[0],
                                  screen_text(install.tui_view(state, 120, 40)))
                    install.tui_update(state, Key("enter"))
                self.assertEqual(state.card_note, note)

    def test_the_minui_family_refuses_a_blank_dest(self):
        """Taken with --dest, refused typed."""
        stick = self.blank()
        for plat in ("minui", "nextui", "myminui"):
            with self.subTest(platform=plat):
                choice = install.card_choice(plat, plat, stick)
                self.assertIn("SD card", choice.refused)
                with self.assertRaises(SystemExit), \
                        contextlib.redirect_stderr(io.StringIO()):
                    install.card_dest(plat, plat, stick)

    def test_a_card_mounted_as_its_bios_folder_is_the_card(self):
        """An Onion card mounted as BIOS was refused,
        ROCKNIX's roms/bios was taken for KNULLI, a muOS card's folder
        too."""
        onion = self.root / "BIOS"
        make_card(onion, "Onion")
        choice = install.card_choice("Onion", "retroarch", onion)
        self.assertEqual((choice.refused, choice.folder), ("", onion / "BIOS"))
        knulli = self.root / "k" / "bios"
        make_card(knulli, "KNULLI")
        self.assertEqual(install.card_choice("knulli", "knulli", knulli).folder,
                         knulli / "bios")
        rocknix = self.root / "ROCKNIX"
        make_card(rocknix, "ROCKNIX")
        refused = install.card_choice("knulli", "knulli", rocknix / "roms" / "bios")
        self.assertIn("is a ROCKNIX card, not a KNULLI card", refused.refused)
        muos = self.root / "MUOS"
        make_card(muos, "muOS")
        refused = install.card_choice("knulli", "knulli", muos / "MUOS" / "bios")
        self.assertIn("is a muOS card", refused.refused)

    def test_no_folder_above_a_mounted_drive_is_its_card(self):
        """A card mounted as MUOS beside a stick: /media/me, which holds
        it, is no muOS card for the stick."""
        stick = self.blank()
        (self.root / "MUOS" / "bios").mkdir(parents=True)
        with mock.patch.object(install, "_mounted_cards",
                               return_value=[stick, self.root / "MUOS"]):
            choice = install.card_choice("knulli", "knulli", stick)
            self.assertEqual((choice.refused, choice.folder), ("", stick / "bios"))
            bios = self.root / "mnt" / "bios"
            (bios / "x").mkdir(parents=True)
        with mock.patch.object(install, "_mounted_cards", return_value=[bios]):
            # A drive mounted at a folder named bios is the card itself.
            self.assertEqual(install._card_and_below(
                install.card_setup("knulli", "knulli"), bios), (bios, False))

    def test_a_refused_dest_says_why_in_the_events(self):
        """Code 1 and no reason in the stream."""
        stick = self.blank()
        proc = install_run("--events", "--platform", "onion", "--dest", str(stick),
                           "--manifest", str(REPO_ROOT / "install" / "retroarch.json"),
                           "--dry-run", env={install.OFFLINE_VARIABLE: "1"})
        self.assertEqual(proc.returncode, 1, proc.stderr)
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        error = next(event for event in events if event["event"] == "error")
        self.assertEqual((error["stage"], error["reason"]), ("detect", "not_found"))
        self.assertIn("is not an Onion SD card", error["message"])
        self.assertEqual(events[-1], {"event": "end", "code": 1})
        table = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        self.assertIn("not the card of the system named", table)

    def test_a_card_no_file_names_is_titled_by_its_system(self):
        """An ArkOS card chosen read as RetroArch."""
        stick = self.blank()
        state = self.start(platform="ArkOS", dest=str(stick))
        self.assertEqual(install.detected_os("retroarch", state.dest), "ArkOS")

    def test_a_list_named_for_another_systems_card_says_so(self):
        """--platform batocera on an Onion card."""
        onion = self.root / "ONION"
        make_card(onion, "Onion")
        choice = install.card_choice("batocera", "batocera", onion)
        self.assertEqual((choice.refused, choice.folder), ("", onion))
        self.assertIn("is an Onion card", choice.note)
        self.assertIn("--platform onion", choice.note)
        state = self.start(platform="batocera", dest=str(onion))
        self.assertEqual(state.card_note, choice.note)

    def test_amberelec_and_emuelec_are_asked_for_their_card(self):
        """"Use this folder" on /storage/roms of a PC."""
        for plat, name in (("amberelec", "AmberELEC"), ("emuelec", "EmuELEC")):
            with self.subTest(system=name):
                setup = install.card_setup(plat, plat)
                self.assertEqual((setup.name, setup.below), (name, ""))
                state = self.start(platform=plat)
                self.assertEqual(state.screen, "folder")
                self.assertIsNone(state.folder_default)
                self.assertIn("Where is the SD card?",
                              " ".join(install.tui_view(state, 80, 24)))
                stick = self.blank(f"{name}STICK")
                choice = install.card_choice(plat, plat, stick)
                self.assertEqual(choice.folder, stick)
                # Its card is told by what it writes at every boot: a stick
                # holding none of it is one not started yet, never "cannot
                # tell".
                self.assertIn(f"says it is {install._a(name)} card yet", choice.note)
                self.assertNotIn("cannot tell", choice.note)

    def test_install_py_has_two_blank_lines_around_each_definition(self):
        """E305 after _card_mount, and the same slip
        before _Interrupted, TuiRow and _setup_label (pycodestyle E302,
        E303, E305 at top level)."""
        import ast

        lines = (REPO_ROOT / "install.py").read_text(encoding="utf-8").splitlines()
        body = ast.parse("\n".join(lines)).body

        def blank_before(node: ast.stmt) -> int:
            # The longest run of blank lines between the code above and the
            # statement, its decorators and comments in between, as
            # pycodestyle counts them.
            index = min([node.lineno] + [item.lineno for item in
                                         getattr(node, "decorator_list", [])]) - 2
            runs, run = [], 0
            while index >= 0 and (not lines[index].strip() or lines[index].startswith("#")):
                if lines[index].strip():
                    runs.append(run)
                    run = 0
                else:
                    run += 1
                index -= 1
            return max(runs + [run])

        definitions = (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)
        for before, after in zip(body, body[1:]):
            count = blank_before(after)
            with self.subTest(line=after.lineno):
                if isinstance(after, definitions):
                    self.assertEqual(count, 2)
                elif isinstance(before, definitions):
                    self.assertEqual(count, 2)

    def test_a_refusal_is_said_once_and_another_card_names_its_remedy(self):
        """Said twice, and "Choose the card's top folder"
        for the top folder of another card."""
        stick = self.blank()
        state = self.start(platform="onion")
        state.pad = "keys"
        install._card_status(state, install.card_choice("Onion", "retroarch", stick))
        after = install._status_after(state)
        self.assertEqual(len(after), 1)
        self.assertTrue(after[0].endswith("? says more."))
        state.help = True
        self.assertIn("Onion keeps .tmp_update",
                      " ".join(" ".join(install.tui_view(state, 80, 24)).split()))
        state.help = False
        muos = self.root / "MUOS"
        make_card(muos, "muOS")
        install._card_status(state, install.card_choice("Onion", "retroarch", muos))
        self.assertEqual(state.status, "That is a muOS card. Insert the Onion card, or go "
                         "back and choose muOS.")
        with mock.patch.object(install, "_ask", side_effect=[str(muos), str(stick),
                                                              KeyboardInterrupt]), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(KeyboardInterrupt):
            install.card_install_dest("Onion", "retroarch", True)
        self.assertIn("Insert the Onion card, or choose muOS for that one.", out.getvalue())

    def test_line_mode_names_the_card_picked_and_its_folder(self):
        """No echo of the card picked, "Mount the
        card" under two mounted, /mnt/d where the list says D:."""
        cards = [self.root / "ONION", self.root / "ONION2"]
        for card in cards:
            make_card(card, "Onion")
        with mock.patch.object(install, "_ask", return_value="2"), \
                mock.patch.object(install, "_mounted_cards", return_value=cards), \
                mock.patch.object(install, "_missing_dest", return_value=True), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()):
            dest = install.card_install_dest("Onion", "retroarch", True)
        self.assertEqual(dest, cards[1] / "BIOS")
        text = out.getvalue()
        self.assertIn("Type its number or its top folder:", text)
        self.assertNotIn("Mount the card", text)
        self.assertIn(f"Onion card ONION2, BIOS folder {cards[1] / 'BIOS'}", text)
        self.assertEqual(install.detected_os("retroarch", dest), "Onion")
        with mock.patch.object(install, "_ask", return_value=""), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            install._prompt_custom_selection("retroarch", [], [], name="Onion",
                                             bios_path=dest)
        self.assertIn("Onion: 0 files", out.getvalue())
        self.assertIn(f"BIOS folder: {dest}", out.getvalue())
        proc = install_run("--platform", "onion", "--dest", str(cards[0]), "--dry-run",
                           "--manifest", str(REPO_ROOT / "install" / "retroarch.json"),
                           env={install.OFFLINE_VARIABLE: "1"})
        self.assertNotIn("gets the RetroArch file list", proc.stdout)

    def test_wsl_names_the_folder_by_its_drive_letter(self):
        with mock.patch.dict(install._WSL, {"active": True, "root": "/mnt"}):
            self.assertEqual(install._short_path(Path("/mnt/d/BIOS"), HOME), "D:\\BIOS")
            self.assertEqual(install.shown_path(Path("/mnt/d")), "D:\\")
            args = _args(dest=Path("D:\\"), save_dir=Path("F:\\saves"))
            setattr(args, "from", [Path("E:\\")])
            args.from_pack = [Path("E:\\pack.zip")]
            install._wsl_dest(args)
            self.assertEqual((args.dest, getattr(args, "from"), args.from_pack, args.save_dir),
                             (Path("/mnt/d"), [Path("/mnt/e")], [Path("/mnt/e/pack.zip")],
                              Path("/mnt/f/saves")))
        with mock.patch.dict(install._WSL, {"active": False}):
            self.assertEqual(install._short_path(Path("/mnt/d/BIOS"), HOME), "/mnt/d/BIOS")

    def test_a_multi_word_system_example_can_be_pasted(self):
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit):
            install.card_install_dest("Anbernic stock firmware", "retroarch", False)
        self.assertIn("--platform anbernicstockfirmware --dest", err.getvalue())


class WhatEachScreenOffers(unittest.TestCase):
    """What each screen offers and says."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)

    def setups(self, pad: str = "keys") -> install.TuiState:
        state = install.TuiState(os_type="linux", home=HOME)
        state.pad = pad
        state.stack = ["platforms"]
        state.focus["platforms"] = 1
        return state

    def test_a_handheld_is_found_by_its_device_in_few_presses(self):
        """Onion was row 30 of 34, its row said "RetroArch files"."""
        state = self.setups("gptokeyb")
        rows = install.tui_rows(state)
        labels = [row.label for row in rows]
        self.assertEqual(labels[1], "RetroArch")
        cards = [index for index, row in enumerate(rows) if row.label.endswith(", SD card")]
        # One block, right after RetroArch.
        self.assertEqual(cards, list(range(2, 2 + len(cards))))
        onion = labels.index("Onion, SD card")
        self.assertIn("Miyoo Mini", rows[onion].right)
        # At 40x12 a page is 6 rows: L1/R1 then Down, then A.
        page = 12 - 6
        presses = (onion - 1) // page + (onion - 1) % page + 1
        self.assertLessEqual(presses, 4)
        text = " ".join(install.tui_view(state, 40, 12))
        self.assertIn("handhelds come after RetroArch", " ".join(text.split()))
        state.pad = "keys"
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("type the device's name (/)", text)
        self.assertIn("Filter by setup or device name",
                      [what for _key, what in install._help_lines(state)])
        # Something found here: the list keeps its order.
        found = fresh_state()
        found.stack = ["setup", "platforms"]
        self.assertEqual([row.label for row in install.tui_rows(found)][2], "Batocera")

    def test_line_mode_takes_a_device_name(self):
        """"miyoo" refused at the line menu."""
        with mock.patch.object(install, "_ask", side_effect=["bittboy"]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(install._choose_platform("Which?"), "MiyooCFW")
        self.assertIn("the device's name", out.getvalue())
        choices = install._line_setups()
        onion = [name for name, _label in choices].index("Onion") + 1
        with mock.patch.object(install, "_ask", side_effect=["miyoo mini+", str(onion)]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(install._choose_platform("Which?"), "Onion")
        self.assertIn("setups run on 'miyoo mini+'", out.getvalue())
        self.assertIn(f"{onion}) Onion, SD card (Miyoo Mini, Miyoo Mini Plus)", out.getvalue())

    def test_one_spelling_per_device_and_one_press_for_one_match(self):
        for name, devices in install._SETUP_DEVICES.items():
            with self.subTest(system=name):
                self.assertFalse(any("+" in device for device in devices))
        self.assertFalse(any(device.startswith("Anbernic RG35XX")
                             for device in install._SETUP_DEVICES["spruceOS"]))
        state = self.setups()
        state.filters["platforms"] = "mini+"
        self.assertIn("Onion, SD card", [row.label for row in install.tui_rows(state)])
        state.filters["platforms"] = "koriki"
        state.focus["platforms"] = 0
        self.assertEqual(install._primary(state), "A/Enter Choose")
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            press(state, "enter")
        self.assertEqual(state.screen, "folder")
        self.assertEqual(state.card_bound[0], "Koriki")
        rows = {row.value: row for row in install.tui_rows(self.setups())}
        self.assertNotIn("PAN4ELEC", rows["amberelec"].right)

    def test_help_rows_keep_their_column_at_40(self):
        """"/ Filter (Esc clears)" ran back to the left edge."""
        for pad in ("gptokeyb", "gptokeyb_muxterm", "miyoo", "evmapy"):
            with self.subTest(pad=pad):
                state = self.setups(pad)
                state.filters["platforms"] = "x"
                state.help = True
                lines = [line[1:] for line in install.tui_view(state, 40, 12)[2:-1]
                         if line.strip()]
                column = lines[0].index("Move")
                for line in lines:
                    self.assertTrue(line[:column].strip() == "" or line[column - 2:column]
                                    == "  ", line)

    def test_copy_from_a_folder_with_none_says_so(self):
        """The plan came back the same."""
        state = checked_state()
        old = self.root / "old"
        old.mkdir()
        state.from_folders = [old]
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("old holds none of these files.", text)
        state.found = [found("gba_bios.bin", str(old))]
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertNotIn("holds none", text)
        stick = self.root / "STICK"
        stick.mkdir()
        state.home = self.root
        with mock.patch.object(install, "_mounted_cards", return_value=[stick]), \
                mock.patch.object(install, "_listed", return_value=[]):
            install._open_from_browser(state)
        rows = install.tui_rows(state)
        self.assertEqual(rows[state.focus["browse"]].value, stick)

    @in_full
    def test_offline_plan_names_the_folder_already_copied_from(self):
        state = checked_state()
        state.from_folders = [self.root / "from1"]
        state.found = [found("gba_bios.bin", str(self.root / "from1"))]
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            text = " ".join(" ".join(install.tui_view(state, 100, 40)).split())
        # The rest named by kind as not in it, the remedy after.
        self.assertIn("Not in from1: ", text)
        self.assertIn("Run the installer again with a pack (--from-pack)", text)
        self.assertNotIn("They are not in", text)
        self.assertNotIn("Copy them from an old card", text)

    def test_the_card_browser_focuses_the_card_asked_for(self):
        """The muOS card, listed first, was focused for Onion."""
        muos, onion, second = self.root / "A_MUOS", self.root / "B_ONION", self.root / "C"
        make_card(muos, "muOS")
        make_card(onion, "Onion")
        make_card(second, "Onion")
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, _effects = install.tui_start(_args(platform="onion"), "linux")
        state.home = self.root
        state.focus["folder"] = [row.action for row in install.tui_rows(state)].index(
            "browse")
        with mock.patch.object(install, "_mounted_cards",
                               return_value=[muos, onion, second]):
            press(state, "enter")
            self.assertEqual(install.tui_rows(state)[state.focus["browse"]].value, onion)
            self.assertEqual(state.status, "Choose the Onion card below.")
            for line in install.tui_view(state, 40, 12):
                self.assertNotIn("Go back", line)

    def test_confirm_offers_no_install_while_it_counts(self):
        state = checked_state()
        state.stack.append("confirm")
        state.running, state.dry = True, None
        self.assertEqual(install.tui_view(state, 80, 24)[-1].split(), ["B/Esc", "Back", "?",
                                                                      "Help"])
        self.assertNotIn("Install", [what for _key, what in install._help_lines(state)])

    def test_back_after_choosing_systems_lands_on_install(self):
        state = checked_state()
        state.focus["plan"] = [row.action for row in install.tui_rows(state)].index("systems")
        press(state, "enter")
        self.assertEqual(state.screen, "systems")
        state.focus["systems"] = next(index for index, row in
                                      enumerate(install.tui_rows(state))
                                      if row.action == "system")
        press(state, " ", "esc")
        self.assertEqual(state.screen, "plan")
        rows = install.tui_rows(state)
        self.assertEqual(rows[state.focus["plan"]].action, "install")

    def test_a_lone_card_opens_the_first_screen_with_a_list(self):
        """With --manifest, the card's folder was the first screen."""
        onion = self.root / "ONIONB"
        make_card(onion, "Onion")
        shutil.rmtree(onion / "BIOS")
        args = _args(platform="retroarch", manifest=str(REPO_ROOT / "install" /
                                                        "retroarch.json"))
        args.platform_from_list = True
        with mock.patch.object(install, "_mounted_cards", return_value=[onion]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.dict(install._DETECTED_OS, {}):
            state, effects = install.tui_start(args, "linux")
        self.assertEqual((state.screen, effects), ("setup", []))

    def test_a_file_left_for_its_save_directory_is_said_so(self):
        """The menu counted 23, 22 were checked, and the end blamed
        the collection for the file whose save directory is unknown."""
        menus = []

        def menu(_plat, files, *_rest, **_named):
            menus.append([entry["dest"] for entry in files])
            return None

        with SaveDirectoryRepository() as repo:
            argv = ["install.py", "--platform", "retroarch", "--dest", str(repo.dest),
                    "--manifest", str(repo.root / "install" / "retroarch.json")]
            # The files come from the repository on the loopback: the module
            # read its base before the environment named it.
            served = repo.env()["RETROBIOS_BASE_URL"] + "/{path}"
            with mock.patch.dict(os.environ, repo.env()), \
                    mock.patch.object(install, "RAW_FILE_URL", served), \
                    mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(sys.stdin, "isatty", return_value=True), \
                    mock.patch.object(install, "_is_terminal", return_value=True), \
                    mock.patch.object(install, "detect_os", return_value="linux"), \
                    mock.patch.object(install, "records_selection", return_value=True), \
                    mock.patch.object(install, "_prompt_custom_selection", menu), \
                    mock.patch.object(install, "_ask", return_value="y"), \
                    contextlib.redirect_stdout(io.StringIO()) as out, \
                    contextlib.redirect_stderr(io.StringIO()):
                try:
                    install.main()
                except SystemExit:
                    pass
                finally:
                    install.LOCAL.reset()
        self.assertEqual(len(menus), 1)
        self.assertNotIn("Azahar/Azahar/sysdata/keys.txt", menus[0])
        text = out.getvalue()
        self.assertIn("1 file read from RetroArch's save directory left out: its place is "
                      "not known. Name it with --save-dir next time.", text)
        self.assertNotIn("the collection does not hold", text)

    @in_full
    def test_plural_game_data_and_the_backup_line_at_40x12(self):
        state = checked_state()
        games = [{"dest": f"g{index}.dat", "system": "", "category": install.GAME_DATA}
                 for index in range(2)]
        with mock.patch.object(install, "_unavailable", return_value=(games, 0)):
            self.assertIn("Copy them from", " ".join(install._unavailable_lines(state)))
        with mock.patch.object(install, "_unavailable", return_value=(games[:1], 0)):
            self.assertIn("Copy it from", " ".join(install._unavailable_lines(state)))
        view = " ".join(" ".join(install.tui_view(state, 40, 12)).split())
        self.assertIn("1 wrong copy: backed up, replaced.", view)


def games_part(card: Path) -> Path:
    """An ArkOS EASYROMS (dArkOS game_systems.txt: themes, launchimages
    with loading.jpg) or an AmberELEC GAMES (autostart.sh: gamedata,
    homebrew with gamelist.xml), console folders beside them."""
    marks = (("gamedata/retroarch", "homebrew") if card.name.startswith("GAMES")
             else ("themes/es-theme-nes-box", "launchimages"))
    for folder in ("bios", "nes", "gba", "psx", *marks):
        (card / folder).mkdir(parents=True)
    if card.name.startswith("GAMES"):
        (card / "homebrew" / "gamelist.xml").write_text("<gameList/>\n")
    else:
        (card / "launchimages" / "loading.jpg").write_bytes(b"\xff\xd8")
    return card


class _Decided(Exception):
    """Raised where line mode has chosen its platforms and folders."""


def line_decision(args: argparse.Namespace, answer) -> tuple[list, str]:
    """(platforms, text) line mode reaches at a terminal for args: the run
    stops where its platforms are known, before anything is read or written.
    answer(prompt) answers each question."""
    def stop(_args, platforms):
        raise _Decided(platforms)

    # --verbose's text, which names what detection found.
    args.verbose = True
    install.LOCAL.reset()
    with mock.patch.object(install, "app_refusal", side_effect=stop), \
            mock.patch.object(install, "detect_os", return_value="linux"), \
            mock.patch.object(install.sys.stdin, "isatty", return_value=True), \
            mock.patch.object(install, "_is_terminal", return_value=True), \
            mock.patch.object(install, "_ask", side_effect=answer), \
            mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
            contextlib.redirect_stdout(io.StringIO()) as out, \
            contextlib.redirect_stderr(io.StringIO()):
        try:
            install._install(args, io.StringIO())
        except _Decided as decided:
            return decided.args[0], out.getvalue()
        finally:
            install.LOCAL.reset()
    raise AssertionError("line mode chose nothing:\n" + out.getvalue())


def screen_decision(args: argparse.Namespace) -> tuple[str, Path]:
    """(platform, folder) the full screen reaches for args, A pressed on
    whatever it offers first, as Enter is in line mode."""
    install.LOCAL.reset()
    with mock.patch.object(install, "detect_os", return_value="linux"), \
            mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
            contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        try:
            state, effects = install._tui_startup(args)
            for _press in range(6):
                if any(effect[0] == "fetch" for effect in effects):
                    return state.platform, state.dest
                effects = install.tui_update(state, Key("enter"))
        finally:
            install.LOCAL.reset()
    raise AssertionError(f"the screen chose nothing: {state.stack}")


def screen_keys(args: argparse.Namespace, presses: list,
                until: tuple = ("fetch", "run")) -> install.TuiState:
    """The full screen for args once the keys are pressed, stopped as soon
    as it fetches the list or starts a run (until)."""
    install.LOCAL.reset()
    with mock.patch.object(install, "detect_os", return_value="linux"), \
            mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
            contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        try:
            state, effects = install._tui_startup(args)
            for key in presses:
                if any(effect[0] in until for effect in effects):
                    break
                effects = install.tui_update(state, key if isinstance(key, Key) else Key(key))
            return state
        finally:
            install.LOCAL.reset()


def engine_events(args: argparse.Namespace) -> tuple[list[dict], str]:
    """(events, text) of the line engine run in this process with --events,
    the run the screen starts for its check."""
    stream = io.StringIO()
    install.LOCAL.reset()
    try:
        with mock.patch.object(install.EVENTS, "stream", stream), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()), \
                contextlib.suppress(SystemExit):
            install._install(args, io.StringIO())
    finally:
        install.LOCAL.reset()
    return [json.loads(line) for line in stream.getvalue().splitlines()], out.getvalue()


def screen_plan(args: argparse.Namespace, manifest: dict, events: list[dict],
                facts: dict | None = None) -> tuple[install.TuiState, str]:
    """The plan screen fed the events of a check run, as the screen reads
    its child: (state, text at 120x40)."""
    state, _effects = install.tui_start(args, "linux", detect=False)
    state.manifest, state.manifest_for = manifest, state.platform
    state.stack = ["checking"]
    install._start_run(state, "check")
    for event in events:
        install.tui_receive(state, ("event", state.run_id, event))
    with mock.patch.object(install, "_tui_folder_facts", return_value=facts or {
            "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
        install.tui_receive(state, ("ended", state.run_id, 0, []))
    return state, " ".join(" ".join(install.tui_view(state, 120, 40)).split())


class _CardFixtures:
    """Drives, lists and packs for the classes that test them on the screen and
    in line mode."""

    ABOUT = "system/configs/emulationstation/about.info"

    def drive(self, name: str, files: dict) -> Path:
        root = self.root / "media" / name
        root.mkdir(parents=True)
        for path, text in files.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text, encoding="utf-8")
        return root

    def renamed(self) -> dict:
        """Renamed drives: KNULLI and Batocera each
        renamed in its own menu, with and without the file KNULLI alone
        writes, and Recalbox's share."""
        conf = "system/batocera.conf"
        return {
            "KNULLI renamed": self.drive("K1", {self.ABOUT: "KNULLI\n",
                                                conf: "system.hostname=RG40XXH\n"}),
            "KNULLI as shipped": self.drive("K2", {self.ABOUT: "KNULLI\n",
                                                   conf: "system.hostname=KNULLI\n"}),
            "renamed, no about.info": self.drive("K3", {conf: "system.hostname=RG40XXH\n"}),
            "Batocera as shipped": self.drive("B1", {conf: "system.hostname=BATOCERA\n"}),
            "Batocera, no hostname": self.drive("B2", {conf: "# system.hostname=X\n"}),
            "Recalbox": self.drive("R1", {"system/recalbox.conf": "a=1\n"}),
            "two shares": self.drive("T1", {conf: "system.hostname=BATOCERA\n",
                                            "system/recalbox.conf": ""}),
        }

    def minui(self, plat: str = "minui", systems: bool = False, cores: bool = True,
              regions: bool = True) -> tuple[Path, Path, dict]:
        """A list of plat's shape (the MinUI family records cores and regions,
        no system), the pack built from it and the files' payloads."""
        from test_install_offline import GBA, JP, US  # noqa: PLC0415

        payloads = {"Bios/MGBA/gba_bios.bin": (GBA, "nintendo-gba", "mgba", None),
                    "Bios/PS/scph5501.bin": (US, "sony-playstation", "pcsx_rearmed",
                                             "north-america"),
                    "Bios/PS/scph5500.bin": (JP, "sony-playstation", "pcsx_rearmed", "japan")}
        files = []
        for dest, (data, system, core, region) in payloads.items():
            entry = {"dest": dest, "sha1": hashlib.sha1(data).hexdigest(), "size": len(data),
                     "repo_path": f"bios/{dest}", "cores": [core] if cores else None}
            if systems:
                entry["systems"] = [system]
            if regions and region:
                entry.update(regions=[region], region_groups=["ps"])
            files.append(entry)
        listing = self.root / f"{plat}.json"
        install_list = {"manifest_version": 2, "platform": plat, "files": files}
        listing.write_text(json.dumps(install_list))
        if sys.version_info < (3, 9):
            # generate_pack.py's context managers need Python 3.9.
            return listing, None, {}
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        self.addCleanup(sys.path.remove, str(REPO_ROOT / "scripts"))
        import generate_pack  # noqa: PLC0415

        pack_list = {"files": [{"path": dest, "sha1": entry["sha1"], "size": entry["size"]}
                               for dest, entry in zip(payloads, files)]}
        generate_pack.annotate_pack_systems(pack_list, generate_pack.pack_systems(install_list))
        name = {"minui": "MinUI", "misterfpga": "MiSTer_FPGA"}[plat]
        pack = self.root / f"{name}_v1_BIOS_Pack.zip"
        with zipfile.ZipFile(pack, "w") as archive:
            for dest, (data, *_rest) in payloads.items():
                archive.writestr(dest, data)
            archive.writestr("manifest.json", json.dumps(pack_list))
        return listing, pack, pack_list

    def narrowed(self, plat: str, **given) -> tuple[int, str, list]:
        """(exit code, what was said, the files kept) of a --dry-run narrowed
        as given."""
        dest = self.root / f"dest-{plat}"
        if plat == "misterfpga" and not dest.exists():
            # A MinUI card is another system's card for MiSTer's list.
            dest.mkdir()
            for marker in ("MiSTer", "menu.rbf"):
                (dest / marker).write_text("", encoding="utf-8")
        elif not dest.exists():
            make_card(dest, "MinUI")
        stream = io.StringIO()
        code = 0
        with mock.patch.object(install.EVENTS, "stream", stream), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            try:
                install._install(_args(platform=plat, dest=dest, dry_run=True, events=True,
                                       no_input=True, declared_only=False, **given),
                                 io.StringIO())
            except SystemExit as stop:
                code = stop.code
            finally:
                install.LOCAL.reset()
        kept = [json.loads(line)["dest"] for line in stream.getvalue().splitlines()
                if '"event": "file"' in line]
        return code, out.getvalue() + err.getvalue(), kept



class _LineModeFindings(_CardFixtures):
    """The line-mode cases of the card fixtures, run by
    LineModeAndScreenDecideAlike."""

    def test_a_drive_two_systems_fit_is_taken_as_named_and_said(self):
        """--platform knulli is never refused on a
        drive whose only evidence is a batocera.conf, --platform batocera
        takes its bios folder, and the doubt is said. Recalbox refuses it
        with words for a SHARE drive."""
        drives = self.renamed()
        for name in ("renamed, no about.info", "Batocera as shipped"):
            drive = drives[name]
            with self.subTest(drive=name):
                choice = install.card_choice("knulli", "knulli", drive)
                self.assertEqual((choice.plat, choice.folder, choice.refused),
                                 ("knulli", drive / "bios", ""))
                self.assertIn("Taken as KNULLI's, as named", choice.note)
        drive = drives["renamed, no about.info"]
        choice = install.card_choice("batocera", "batocera", drive)
        self.assertEqual((choice.plat, choice.folder), ("batocera", drive / "bios"))
        self.assertIn("names the host RG40XXH", choice.note)
        refused = install.card_choice("recalbox", "recalbox", drive)
        self.assertIn("could be a KNULLI card or a Batocera SHARE drive", refused.refused)
        words = install._dest_refusal_words(refused, None)
        self.assertIn("Connect the Recalbox SHARE drive", words)
        self.assertNotIn("Insert", words)
        other = install.card_choice("recalbox", "recalbox", drives["Batocera as shipped"])
        words = install._dest_refusal_words(other, None)
        self.assertIn("Connect the Recalbox SHARE drive, or name that drive's own system: "
                      "--platform batocera", words)

    def test_the_first_screen_and_line_mode_say_the_doubt(self):
        """The screen's first row was "Batocera SHARE
        drive (KNULLI2)". A renamed card with about.info is KNULLI's, one
        without is listed by neither and said."""
        drives = self.renamed()
        knulli, doubt = drives["KNULLI renamed"], drives["renamed, no about.info"]
        with mock.patch.object(install, "_mounted_cards", return_value=[knulli, doubt]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            setups, _mounted = install.found_setups("linux")
        self.assertEqual([(plat, path) for plat, path, _label in setups],
                         [("knulli", knulli / "bios")])
        self.assertIn("KNULLI SD card", setups[0][2])
        text = out.getvalue()
        self.assertIn(f"{doubt} could be a KNULLI card or a Batocera SHARE drive", text)
        self.assertIn(f"--platform knulli --dest {doubt} or --platform batocera --dest {doubt}",
                      text)
        with mock.patch.object(install, "_mounted_cards", return_value=[knulli, doubt]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()):
            state, _effects = install.tui_start(_args(), "linux")
        self.assertTrue(any("could be a KNULLI card" in note for note in state.notes))
        self.assertEqual([setup[0] for setup in state.setups], ["knulli"])

    def test_a_list_without_systems_narrows_by_what_it_records(self):
        """Install/minui.json records cores and regions,
        no system, and all three options were refused with a remedy that
        fetched the same list."""
        listing, _pack, _listed = self.minui()
        code, text, kept = self.narrowed("minui", manifest=listing, core=["mgba"])
        self.assertEqual(code, 0, text)
        self.assertEqual(kept, ["Bios/MGBA/gba_bios.bin"])
        code, text, kept = self.narrowed("minui", manifest=listing, region=["us"])
        self.assertEqual(code, 0, text)
        self.assertNotIn("Bios/PS/scph5500.bin", kept)
        code, text, _kept = self.narrowed("minui", manifest=listing,
                                          system=["nintendo-gba"])
        self.assertEqual(code, 1)
        self.assertIn("records no systems, so --system cannot narrow it", text)
        self.assertIn("Run it without --system, or narrow with --core and --region", text)
        self.assertNotIn("one-line installer", text)
        # The remedy followed: what it names works.
        code, text, _kept = self.narrowed("minui", manifest=listing, core=["mgba"],
                                          region=["us"])
        self.assertEqual(code, 0, text)

    @unittest.skipIf(sys.version_info < (3, 9),
                     "generate_pack.py's context managers need Python 3.9")
    def test_a_pack_names_its_list_only_when_that_list_records_it(self):
        """A MinUI pack sent --core to install/minui.json,
        refused the same way, and a MiSTer pack to install/misterfpga.json,
        which records no core. The pack now records what its list narrows
        by, and each remedy changes the outcome."""
        listing, pack, listed = self.minui()
        self.assertEqual(listed["list_records"], ["cores", "regions"])
        # The pack carries its install list since 2026-11: --core narrows it
        # alone, as with the list named beside it.
        code, text, kept = self.narrowed("minui", from_pack=[pack], core=["mgba"])
        self.assertEqual((code, kept), (0, ["Bios/MGBA/gba_bios.bin"]), text)
        code, text, kept = self.narrowed("minui", from_pack=[pack], manifest=listing,
                                         core=["mgba"])
        self.assertEqual((code, kept), (0, ["Bios/MGBA/gba_bios.bin"]), text)
        mister_list, mister, listed = self.minui("misterfpga", systems=True, cores=False,
                                                 regions=False)
        self.assertEqual(listed["list_records"], ["regions", "systems"])
        code, text, _kept = self.narrowed("misterfpga", from_pack=[mister], core=["x"])
        self.assertEqual(code, 1)
        # Its own list, which the pack carries, refuses it as --manifest would.
        self.assertIn("the misterfpga file list records no cores, so --core cannot narrow it",
                      text)
        self.assertNotIn("--manifest", text)
        code, text, kept = self.narrowed("misterfpga", from_pack=[mister],
                                         system=["nintendo-gba"])
        self.assertEqual((code, kept), (0, ["Bios/MGBA/gba_bios.bin"]), text)
        self.assertTrue(mister_list.exists())

    def test_line_mode_offers_what_can_be_chosen(self):
        """"c) choose systems, cores and regions" with a
        pack that records systems only, and "Cores: 1) azahar" asked with
        one answer."""
        mister, _pack, _listed = self.minui("misterfpga", systems=True, cores=False,
                                            regions=False)
        files = json.loads(mister.read_text())["files"]
        self.assertEqual(install.narrowing_words(files, []), "systems")
        listing, _pack, _listed = self.minui()
        minui = json.loads(listing.read_text())["files"]
        self.assertEqual(install.narrowing_words(minui, []), "cores and regions")
        one_core = [{**entry, "systems": ["nintendo-3ds"], "cores": ["azahar"]}
                    for entry in minui[:1]]
        with mock.patch.object(install, "_ask", side_effect=["", ""]) as asked, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            install._choose_narrowing(one_core, [], {}, None)
        self.assertNotIn("Cores:", out.getvalue())
        self.assertEqual(asked.call_count, 0)

    # the remedies of a card.

    def test_a_full_card_is_freed_never_left_for_another_drive(self):
        with mock.patch.object(install.shutil, "disk_usage",
                               return_value=mock.Mock(free=10)), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit):
            install._check_free_space(self.root, 1000, "retroarch", card=True)
        said = err.getvalue()
        self.assertIn("on the card, then run it again", said)
        self.assertNotIn("--platform", said)
        self.assertNotIn("another drive", said)

    def test_line_mode_names_the_way_to_another_folder(self):
        hint = install.Invocation()
        with mock.patch.object(install, "_folder_writable", return_value=False), \
                mock.patch.object(install, "_on_read_only_mount", return_value=False):
            lines = install.folder_warnings("retroarch", self.root, [], hint, True, False)
        self.assertIn("This folder cannot be written to: run it again with another --dest.",
                      lines)
        self.assertNotIn("choose another one", " ".join(lines))
        with mock.patch.object(install, "_folder_writable", return_value=False), \
                mock.patch.object(install, "_on_read_only_mount", return_value=True):
            lines = install.folder_warnings("retroarch", self.root, [], hint, True, True)
        self.assertEqual(lines, [install.read_only_words(self.root)])



class _OutsideTextFindings:
    """A pack's member path, a --manifest dest, the
    names a list records, a card's label and a retroarch.cfg folder reached
    line mode, the events and the disk with their control characters. Each
    source is fed escape sequences, and none comes out raw."""

    OSC = "\x1b]0;PWNED\x07"
    CSI = "\x1b[41m"

    @property
    def dest(self) -> Path:
        dest = self.root / "dest"
        dest.mkdir(exist_ok=True)
        return dest

    def assertClean(self, text: str, where: str) -> None:
        self.assertNotIn("\x1b", text, where)
        self.assertNotIn("\x07", text, where)

    def assertNothingRawOnDisk(self) -> None:
        for path in self.root.rglob("*"):
            self.assertIsNone(install._CONTROLS.search(path.name), path)

    def run_install(self, args: argparse.Namespace, mounts: list = (),
                    env: dict | None = None) -> str:
        events = io.StringIO()
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        with mock.patch.object(install, "_UNNAMEABLE", []), \
                mock.patch.object(install, "_mounted_cards", return_value=list(mounts)), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.EVENTS, "stream", events), \
                mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1", **(env or {})}), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                contextlib.suppress(SystemExit):
            install._install(args, io.StringIO())
        return out.getvalue() + err.getvalue() + events.getvalue()

    def test_a_pack_member_path_is_refused(self):
        from test_install_offline import _pack, GBA  # noqa: PLC0415

        pack = _pack(self.root, "RetroArch_v1_BIOS_Pack.zip", {f"x{self.OSC}.bin": GBA})
        text = self.run_install(_args(platform="retroarch", dest=self.dest,
                                      from_pack=[pack], no_input=True, declared_only=False))
        self.assertClean(text, "pack")
        self.assertIn("is not valid: unsafe", text)
        self.assertEqual(list(self.dest.iterdir()), [])
        self.assertNothingRawOnDisk()

    def test_a_list_dest_and_its_names_are_refused_or_shown(self):
        files = [{"dest": f"x{self.CSI}BAD.bin", "sha1": "0" * 40, "size": 1,
                  "repo_path": "bios/x", "cores": None, "systems": ["a"]}]
        listing = self.root / "list.json"
        listing.write_text(json.dumps({"manifest_version": 2, "platform": "retroarch",
                                       "files": files}))
        text = self.run_install(_args(platform="retroarch", dest=self.dest, manifest=listing,
                                      no_input=True, dry_run=True, verbose=True,
                                      declared_only=False))
        self.assertClean(text, "--manifest dest")
        self.assertIn("unsafe", text)
        named = {"manifest_version": 2, "platform": "retroarch", "files": [
            {**files[0], "dest": "a.bin", "systems": [f"a{self.CSI}"],
             "cores": [f"core{self.OSC}"]}],
            "system_titles": {f"a{self.CSI}": f"Title{self.OSC}"}}
        cleaned = install._validate_manifest(named, "retroarch")
        self.assertClean(json.dumps(cleaned, ensure_ascii=False), "names")
        self.assertNothingRawOnDisk()

    def test_a_card_label_is_shown_and_never_obeyed(self):
        card = self.root / "media" / f"S{self.CSI}RED"
        (card / "system").mkdir(parents=True)
        (card / "system" / "batocera.conf").write_text("system.hostname=BATOCERA\n")
        listing = self.root / "batocera.json"
        listing.write_text(json.dumps({"manifest_version": 2, "platform": "batocera",
                                       "files": []}))
        with mock.patch.object(install, "detect_platforms", return_value=[]):
            text = self.run_install(_args(platform="batocera", manifest=listing,
                                          no_input=True, dry_run=True, events=True,
                                          declared_only=False), [card])
        self.assertIn("S?[41mRED", text)
        self.assertClean(text, "card label")
        self.assertClean(install.card_line(card), "card row")

    def test_a_folder_a_config_names_is_refused(self):
        home = self.root / "home"
        weird = home / f"sys{self.OSC}x"
        weird.mkdir(parents=True)
        cfg = home / ".config" / "retroarch" / "retroarch.cfg"
        cfg.parent.mkdir(parents=True)
        cfg.write_text(f'system_directory = "{weird}"\n')
        listing = self.root / "retroarch.json"
        listing.write_text(json.dumps({"manifest_version": 2, "platform": "retroarch",
                                       "files": []}))
        text = self.run_install(
            _args(manifest=listing, no_input=True, dry_run=True, events=True,
                  declared_only=False),
            env={"HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
                 "RETROBIOS_OS": "linux"})
        self.assertClean(text, "retroarch.cfg")
        self.assertIn("holds a control character", text)
        self.assertNotIn("using default path", text)
        self.assertNotIn(str(home / ".config" / "retroarch" / "system"), text)

    def test_a_path_with_a_control_character_is_no_relative_path(self):
        for value in ("a\x1bb.bin", "a\x07.bin", "a\x9bb.bin", "a\nb.bin"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                install._safe_relative_path(value, "dest")
        self.assertEqual(install.shown_path(Path("/a/b\x1b[2Jc")), "/a/b?[2Jc")



class LineModeAndScreenDecideAlike(_LineModeFindings, _OutsideTextFindings,
                                   unittest.TestCase):
    """Line mode looked at
    this machine alone, took this computer's default folder with a card in
    the reader or nothing found, and the screen put RetroArch under A for a
    KNULLI card named with --dest. The same inputs now give the same
    platform and folder on both, A or Enter taking what each offers first."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        for patcher in (mock.patch.dict(install._DETECTED_OS, {}),
                        mock.patch.dict(os.environ, {"HOME": str(self.root / "home"),
                                                     "XDG_CONFIG_HOME": str(self.root / "cfg"),
                                                     "RETROBIOS_OS": "linux"})):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.list = self.root / "retroarch.json"
        self.list.write_text(json.dumps({"manifest_version": 2, "platform": "retroarch",
                                         "files": []}))
        self.here = self.root / "pc" / "system"
        self.here.mkdir(parents=True)

    def card(self, name: str, system: str) -> Path:
        root = self.root / "media" / name
        make_card(root, system)
        return root

    def both(self, mounts: list, found: list, **given) -> tuple:
        def answer(prompt: str) -> str:
            # The first entry of a numbered list, the default of a folder,
            # the first drive of a folder question that has no default.
            first = prompt.startswith(">") or ("Enter for" not in prompt and " or 1" in prompt)
            return "1" if first else ""

        extra = {"declared_only": False, "offline": False}
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=found), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            platforms, text = line_decision(_args(**extra, **given), answer)
            install._DETECTED_OS.clear()
            screen = screen_decision(_args(**extra, **given))
        return platforms[0], screen, text

    def test_the_same_scenarios_give_the_same_platform_and_folder(self):
        onion = self.card("ONION", "Onion")
        muos = self.card("MUOS", "muOS")
        knulli = self.card("KNULLI", "KNULLI")
        bare = self.card("ONIONB", "Onion")
        shutil.rmtree(bare / "BIOS")
        default = install._default_dest("linux", "retroarch")
        pc = [("retroarch", self.here)]
        share = self.root / "media" / "SHARE"
        (share / "roms").mkdir(parents=True)
        batocera = self.root / "batocera.json"
        batocera.write_text(json.dumps({"manifest_version": 2, "platform": "batocera",
                                        "files": []}))
        blank = self.root / "blank"
        blank.mkdir()
        scenarios = {
            # the drive's root in
            # line mode, another system's card first on the screen.
            "a Batocera list, its SHARE drive": (
                [share], [], {"manifest": batocera}, ("batocera", share / "bios")),
            "a Batocera list, a muOS card and its SHARE drive": (
                [muos, share], [], {"manifest": batocera}, ("batocera", share / "bios")),
            # the setups found asked as the screen
            # asks, Enter on the first.
            "nothing named, RetroArch here": ([], pc, {}, ("retroarch", self.here)),
            "a list, RetroArch here and an Onion card": (
                [onion], pc, {"manifest": self.list}, ("retroarch", self.here)),
            # --dest with a setup found.
            "--dest a blank folder, RetroArch here": (
                [onion], pc, {"dest": blank}, ("retroarch", blank)),
            "a list, an Onion card in the reader": (
                [onion], [], {"manifest": self.list}, ("retroarch", onion / "BIOS")),
            "a list, an Onion card without its BIOS folder": (
                [bare], [], {"manifest": self.list}, ("retroarch", bare / "BIOS")),
            "a list, a KNULLI card in the reader": (
                [knulli], [], {"manifest": self.list}, ("retroarch", default)),
            "a list, nothing here": ([], [], {"manifest": self.list}, ("retroarch", default)),
            "nothing named, two cards": (
                [muos, onion], [], {}, ("retroarch", muos / "MUOS" / "bios")),
            "nothing named, nothing here": ([], [], {}, ("retroarch", default)),
            "--dest a KNULLI card, RetroArch here": (
                [knulli], pc, {"dest": knulli}, ("knulli", knulli / "bios")),
            "--platform onion, its card": (
                [onion, muos], pc, {"platform": "onion"}, ("retroarch", onion / "BIOS")),
        }
        for name, (mounts, found, given, expected) in scenarios.items():
            with self.subTest(scenario=name):
                line, screen, text = self.both(mounts, found, **given)
                self.assertEqual(tuple(line), expected, text)
                self.assertEqual(screen, expected)
                self.assertNotIn("using default path", text)

    def unasked(self, mounts: list, found: list, **given) -> tuple:
        """(platforms or exit code, text, events) of a run without
        questions: --no-input, or --yes, which implies it."""
        def stop(_args, platforms):
            raise _Decided(platforms)

        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        args = _args(declared_only=False, offline=False, no_input=True, **given)
        events = []
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=found), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "app_refusal", side_effect=stop), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.EVENTS, "emit",
                                  side_effect=lambda kind, **keys: events.append((kind, keys))), \
                mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            try:
                install._install(args, io.StringIO())
            except _Decided as decided:
                return [tuple(each) for each in decided.args[0]], out.getvalue(), events
            except SystemExit as exit_:
                return exit_.code, out.getvalue() + err.getvalue(), events
        raise AssertionError(out.getvalue())

    def test_a_run_without_questions_sees_the_cards_the_screen_sees(self):
        """--yes and --no-input looked at this machine
        alone, beside the Onion card the screen and line mode open on: the
        files went to the home folder, or the run said nothing is here."""
        onion = self.card("ONION", "Onion")
        default = install._default_dest("linux", "retroarch")
        for flag in ({"yes": True}, {}):
            for name, (mounts, given) in {
                "an Onion card, a list": ([onion], {"manifest": self.list}),
                "an Onion card, nothing named": ([onion], {}),
            }.items():
                with self.subTest(flag=flag, scenario=name):
                    chosen, text, _events = self.unasked(mounts, [], **flag, **given)
                    self.assertEqual(chosen, [("retroarch", onion / "BIOS")], text)
                    self.assertNotIn(str(default), text)
                    install._DETECTED_OS.clear()
                    with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                            mock.patch.object(install, "_mount_points",
                                              return_value=frozenset()), \
                            mock.patch.object(install, "detect_platforms", return_value=[]), \
                            mock.patch.object(install, "detect_frontends", return_value=[]):
                        screen = screen_decision(_args(declared_only=False, **given))
                    self.assertEqual(chosen, [screen])

    def test_a_run_without_questions_stops_on_two_setups(self):
        """--yes beside two setups
        installed for both, where its help says it stops on what to name.
        It now stops with an error event naming each and its --dest."""
        onion, muos = self.card("ONION", "Onion"), self.card("MUOS", "muOS")
        pc = [("retroarch", self.here)]
        for flag in ({"yes": True}, {}):
            for name, (mounts, found, given) in {
                "two cards": ([onion, muos], [], {}),
                "a card and RetroArch here, a list": ([onion], pc, {"manifest": self.list}),
                "two setups here": ([], [("retroarch", self.here),
                                         ("emudeck", self.root / "Emulation" / "bios")], {}),
            }.items():
                with self.subTest(flag=flag, scenario=name):
                    code, text, events = self.unasked(mounts, found, **flag, **given)
                    self.assertEqual(code, 1, text)
                    errors = [keys for kind, keys in events if kind == "error"]
                    self.assertEqual([(e["stage"], e["reason"]) for e in errors],
                                     [("detect", "conflict")])
                    self.assertIn("a run without questions installs for one", text)
                    self.assertRegex(text, r"--platform \w+ --dest ")

    def share(self, name: str = "SHARE") -> Path:
        share = self.root / "media" / name
        (share / "system").mkdir(parents=True)
        (share / "roms").mkdir()
        (share / "system" / "batocera.conf").write_text("system.hostname=BATOCERA\n")
        return share

    def test_a_drive_is_offered_by_the_folder_its_system_reads(self):
        """RetroArch's folder question
        numbered a Batocera SHARE drive and a KNULLI card, and one press put
        RetroArch's list at their root, beside roms/ and system/. A drive
        nothing names went to its root too. Now another system's drive is
        left out and said, in both modes, and a drive is its bios folder."""
        share, knulli = self.share(), self.card("KNULLI", "KNULLI")
        stick = self.root / "media" / "EASYROMS"
        (stick / "bios").mkdir(parents=True)
        onion = self.card("ONION", "Onion")
        mounts = [share, knulli, stick, onion]
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                mock.patch.object(install, "_ask", side_effect=["q"]), \
                self.assertRaises(SystemExit):
            install.ask_platform_folder("linux", "retroarch")
        text = out.getvalue()
        # One parenthesis a row.
        self.assertIn(f"1) EASYROMS: bios (drive, {stick / 'bios'})", text)
        self.assertIn(f"2) ONION: BIOS (Onion SD card, {onion / 'BIOS'})", text)
        self.assertNotIn("3)", text)
        self.assertIn("Not offered here, each reads its own system's files: SHARE (Batocera "
                      f"SHARE drive: --platform batocera --dest {share}), KNULLI (KNULLI SD "
                      f"card: --platform knulli --dest {knulli}).", text)
        state = install.TuiState(os_type="linux", home=HOME)
        state.platform, state.stack = "retroarch", ["folder"]
        state.folder_default, state.folder_kind = SYSTEM_DIR, "usual"
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            rows = install.tui_rows(state)
            screen = " ".join(install.tui_view(state, 120, 40))
            state.focus["folder"] = next(index for index, row in enumerate(rows)
                                         if row.action == "drive")
            install.tui_update(state, Key("enter"))
        self.assertEqual([row.value for row in rows if row.action == "drive"],
                         [stick / "bios", onion / "BIOS"])
        self.assertIn("Not offered here", screen)
        self.assertEqual(state.dest, stick / "bios")

    def test_a_list_card_setups_read_offers_them_first(self):
        """With a RetroArch pack or list and nothing found,
        the first screen was RetroArch's folder question: ArkOS, muOS and
        JELOS, which read the same list, were out of reach. Both modes now
        open on the setups that read it, RetroArch first."""
        stick = self.root / "media" / "EASYROMS"
        (stick / "bios").mkdir(parents=True)
        args = dict(manifest=self.list, declared_only=False, offline=False)
        text, asked = self.line_run(_args(**args), [], mounts=[stick])
        self.assertIn("Which setup is the RetroArch list for?", text)
        self.assertIn("ArkOS", text)
        self.assertNotIn("Batocera", text)
        self.assertIn("[Enter for RetroArch]", asked[0])
        with mock.patch.object(install, "_mounted_cards", return_value=[stick]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            install._DETECTED_OS.clear()
            state = screen_keys(_args(**args), [])
            with contextlib.redirect_stdout(io.StringIO()):
                install._open_local_sources(_args(**args))
            rows = install.tui_rows(state)
            labels = [row.label for row in rows]
            focused = rows[state.focus["platforms"]]
            install._DETECTED_OS.clear()
            ark = screen_keys(_args(**args), ["end", Key("char", "/"), *[
                Key("char", c) for c in "arkos"], "enter", "enter"])
        self.assertEqual(state.screen, "platforms")
        self.assertEqual(focused.value, "retroarch")
        self.assertTrue(any(label.startswith("ArkOS") for label in labels), labels)
        self.assertFalse(any(label.startswith("Batocera") for label in labels), labels)
        self.assertEqual(ark.screen, "folder")
        self.assertEqual(install._tui_card_bound(ark)[0], "ArkOS")

    # The owner's request of 2026-10-27: BIOS files and game data counted
    # apart, the game data choice on the plan itself and in the menu.

    def game_list(self) -> tuple[Path, list]:
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"]),
                 self.entry("doom/doom1.wad", b"wad" * 10, ["doom"], category="game_data")]
        return self.listing("retroarch", files, categorized=True), files

    def test_line_mode_counts_game_data_apart_and_g_leaves_it_out(self):
        listing, _files = self.game_list()
        args = dict(manifest=listing, dest=self.here, declared_only=False, dry_run=True)
        text, asked = self.line_run(_args(**args), ["g", ""])
        self.assertIn("1 BIOS file (3 B) and 1 game data file (30 B).", text)
        self.assertIn("g) Game data: kept (1 file, 30 B): leave it out", text)
        self.assertIn("Game data: files a game or a game engine reads, of no use to the "
                      "other cores.", text)
        after = text[text.index("Counted again"):]
        self.assertIn("RetroArch: 1 file, 3 B.", after)
        self.assertIn("g) Game data: left out (1 file, 30 B): keep it", after)
        self.assertIn("--no-game-data", after)
        self.assertIn("1 game data file left out (--no-game-data)", after)
        self.assertNotIn("doom1.wad would", after)

    @in_full
    def test_the_plan_counts_game_data_apart_and_one_press_leaves_it_out(self):
        state = checked_state()
        manifest = json.loads(json.dumps(state.manifest))
        for entry in manifest["files"]:
            if entry["dest"] == "pcsx/extra.bin":
                entry["category"] = "game_data"
        state.manifest = manifest
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("3 BIOS files (1.0 MB) and 1 game data file (4 B).", text)
        self.assertIn("Game data: files a game or a game engine reads, of no use to the "
                      "other cores.", text)
        rows = install.tui_rows(state)
        row = next(row for row in rows if row.action == "gamedata")
        self.assertEqual(row.label, "Game data: kept")
        state.focus["plan"] = rows.index(row)
        effects = install.tui_update(state, Key("enter"))
        self.assertTrue(state.no_game_data)
        self.assertEqual(effects, [("run", "check")])
        self.assertIn(("--no-game-data", None), install.tui_flags(state))

    def test_the_result_counts_game_data_apart_in_both_modes(self):
        state = _installed_state(Path("/x/system"))
        state.manifest = {**state.manifest, "files": [
            *state.manifest["files"],
            {"dest": "doom/doom1.wad", "size": 30, "category": "game_data", "cores": None}]}
        state.finished = [("scph5500.bin", True, ""), ("doom/doom1.wad", True, "")]
        state.summary = {**state.summary, "installed": 2}
        _title, lines = install.tui_outcome(state)
        self.assertIn("Installed: 1 BIOS file and 1 game data file.", lines)
        # The data tree files are installed without a file event: the parts
        # still add up to the head's count.
        state.summary = {**state.summary, "installed": 5}
        _title, lines = install.tui_outcome(state)
        self.assertIn("5 files installed.", lines[0])
        self.assertIn("Installed: 1 BIOS file, 1 game data file and 3 data files.", lines)
        listing, _files = self.game_list()
        backup = self.root / "old"
        (backup / "doom").mkdir(parents=True)
        (backup / "gba_bios.bin").write_bytes(b"gba")
        (backup / "doom" / "doom1.wad").write_bytes(b"wad" * 10)
        args = _args(manifest=listing, dest=self.here, offline=True, declared_only=False,
                     no_input=True, verbose=True)
        setattr(args, "from", [backup])
        real = io.StringIO()
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        with mock.patch.object(install, "detect_os", return_value="linux"), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            install._install(args, real)
        # Every file from one folder: one count, as the screen's result.
        self.assertIn(f"Done. 2 files copied from {backup}.", real.getvalue())
        self.assertIn("Installed: 1 BIOS file and 1 game data file.", real.getvalue())

    # 2026-10-27, CI run 40541886959: the run said 8069 files, the menu
    # 8348 and 3259 BIOS files and 5089 game data files, the real dry run
    # 8358. Every count of a run is one tally of one list.

    def counted_list(self) -> Path:
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"]),
                 self.entry("doom/doom1.wad", b"wad" * 10, ["doom"], category="game_data"),
                 self.entry("doom/doom2.wad", b"two" * 20, ["doom"], category="game_data")]
        variant = {**self.entry("DOOM/DOOM1.WAD", b"WAD" * 10, ["doom"]),
                   "category": "game_data"}
        omitted = [{"dest": "doom/doom3.wad", "name": "doom3.wad", "system": "doom",
                    "systems": ["doom"], "required": False, "reason": "not_found",
                    "category": "game_data"}]
        return self.listing("retroarch", files, categorized=True, case_variants=[variant],
                            omitted_files=omitted)

    def test_every_count_of_a_line_run_is_one_list(self):
        args = dict(manifest=self.counted_list(), dest=self.here, declared_only=False,
                    dry_run=True)
        text, _asked = self.line_run(_args(**args), [""])
        # The second spelling a folder keeping case installs is counted
        # everywhere or nowhere: here, everywhere.
        self.assertIn("RetroArch: 4 files, 123 B.\n  1 BIOS file (3 B) and 3 game data files "
                      "(120 B).", text)
        self.assertIn("g) Game data: kept (3 files, 120 B): leave it out", text)
        # Said once, by the menu: the run head repeated it right under it.
        after = text[text.index("q) quit"):text.index("Checking existing files")]
        self.assertNotIn("4 files (123 B)", after)
        self.assertIn("0 in place, 4 missing, 0 wrong copies", text)
        self.assertIn("4 files (123 B)", text[text.index("Checking existing files"):])

    def test_g_counts_the_systems_chosen_and_leaves_out_what_it_said(self):
        args = dict(manifest=self.counted_list(), dest=self.here, declared_only=False,
                    dry_run=True)
        text, _asked = self.line_run(_args(**args), ["c", "2", ""])
        after = text[text.index("Counted again"):]
        self.assertIn("RetroArch: 1 file, 3 B, for 1 of 2 systems.", after)
        # No game data among the systems chosen: nothing for g to leave out.
        self.assertNotIn("g) Game data", after)
        text, _asked = self.line_run(_args(**args), ["c", "1", "g", "", "g", ""])
        after = text[text.index("Counted again"):]
        self.assertIn("g) Game data: kept (3 files, 120 B): leave it out", after)
        # doom holds only game data: Enter is refused, as the screen offers
        # no Install for it, and g puts it back.
        self.assertIn("g) Game data: left out (3 files, 120 B): keep it", after)
        self.assertIn("doom holds only game data: nothing is left to install.", after)
        self.assertNotIn("All files up to date", text)
        self.assertIn("RetroArch: 3 files, 120 B, for 1 of 2 systems.",
                      after[after.rindex("Counted again"):])
        text, _asked = self.line_run(_args(**args), ["g", ""])
        self.assertIn("4 game data files left out (--no-game-data), 1 of them not "
                      "installable", text)

    def test_the_parts_add_up_on_every_committed_list(self):
        for path in sorted((REPO_ROOT / "install").glob("*.json")):
            manifest = json.loads(path.read_text(encoding="utf-8"))
            if not manifest.get("categorized"):
                continue
            with self.subTest(path.name):
                for files in (manifest.get("files", []),
                              manifest.get("files", []) + manifest.get("case_variants", [])):
                    counts = install.tally(files)
                    self.assertEqual(counts.bios + counts.games, counts.files)
                    self.assertEqual(counts.files, len(files))
                    self.assertEqual(counts.bios_size + counts.game_size, counts.size)
                    self.assertEqual(counts.size, sum(e.get("size") or 0 for e in files))
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    install._print_menu_head(
                        manifest["platform"], manifest["files"], [], None, "", [], None,
                        None, None, manifest, False)
                head = re.search(r"(\d+) files?, ", out.getvalue())
                split = re.search(r"(\d+) BIOS files? \(.*?\) and (\d+) game data files?",
                                  out.getvalue())
                if split:
                    self.assertEqual(int(split[1]) + int(split[2]), int(head[1]))

    @in_full
    def test_the_screen_divides_the_count_it_shows(self):
        state = checked_state()
        manifest = json.loads(json.dumps(state.manifest))
        manifest["case_variants"] = [{"dest": "PCSX/EXTRA.BIN", "size": 4,
                                      "category": "game_data", "cores": ["pcsx_rearmed"],
                                      "systems": ["sony-playstation"]}]
        for entry in manifest["files"]:
            if entry["dest"] == "pcsx/extra.bin":
                entry["category"] = "game_data"
        state.manifest = manifest
        state.files = [*state.files, {
            "event": "file", "platform": "retroarch", "dest": "PCSX/EXTRA.BIN",
            "systems": ["sony-playstation"], "size": 4, "state": "missing"}]
        state.checked_dests.add("PCSX/EXTRA.BIN")
        state.check = {**state.check, "missing": state.check["missing"] + 1,
                       "files": state.check["files"] + 1,
                       "bytes_needed": state.check["bytes_needed"] + 4}
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertIn("5 files to download", text)
        self.assertIn("3 BIOS files (1.0 MB) and 2 game data files (8 B).", text)
        row = next(row for row in install.tui_rows(state) if row.action == "gamedata")
        self.assertEqual((row.label, row.right), ("Game data: kept", "2 files, 8 B"))

    # line mode wording.

    def test_one_row_says_type_1(self):
        with mock.patch.object(install, "_ask", side_effect=["2", "q"]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit):
            install._prompt_platform_choice([("retroarch", self.here)], other=lambda: [])
        self.assertIn("Type 1, o for another setup or folder, or q to quit.", out.getvalue())
        self.assertNotIn("1 to 1", out.getvalue())

    def test_a_number_out_of_range_at_copy_from_is_said_as_one(self):
        stick = self.root / "media" / "STICK"
        stick.mkdir(parents=True)
        with mock.patch.object(install, "_mounted_cards", return_value=[stick]), \
                mock.patch.object(install, "_ask", side_effect=["2", ""]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            install._ask_from_folder([], self.here)
        self.assertIn("Type 1, a folder, or Enter.", out.getvalue())
        self.assertNotIn("does not exist", out.getvalue())

    def test_the_copy_line_names_the_folder_it_copies_from(self):
        payload = b"gba"
        files = [self.entry("gba_bios.bin", payload, ["nintendo-gba"])]
        listing = self.listing("retroarch", files)
        old = self.root / "OLD"
        old.mkdir()
        (old / "gba_bios.bin").write_bytes(payload)
        args = _args(manifest=listing, dest=self.here, declared_only=False, offline=True)
        setattr(args, "from", [old])
        text, _asked = self.line_run(args, [""])
        self.assertIn(f"Copying 1 file (3 B) from {old}...", text)
        self.assertNotIn("copied from", text[text.index("\nCopying "):])
        self.assertNotIn("found on this machine (", text)

    def test_the_save_lines_name_the_frontend_both_times(self):
        onion = self.card("ONION", "Onion")
        files = [self.entry("gba_bios.bin", b"g", ["nintendo-gba"]),
                 self.entry("x/keys.txt", b"k", ["nintendo-3ds"], root="save")]
        listing = self.listing("retroarch", files, base_destination="RetroArch",
                               save_directory={"folder": "saves", "by_core": False})
        text, _asked = self.line_run(_args(manifest=listing, declared_only=False,
                                           offline=False), [""], mounts=[onion])
        self.assertIn("Install for:", text)
        self.assertIn("save directory left out", text)
        self.assertNotIn("Onion's save directory", text)
        self.assertIn("RetroArch's save directory", text)

    def test_line_mode_repeats_the_command_after_enter(self):
        payload = b"gba"
        files = [self.entry("gba_bios.bin", payload, ["nintendo-gba"])]
        listing = self.listing("retroarch", files)
        old = self.root / "OLD"
        old.mkdir()
        (old / "gba_bios.bin").write_bytes(payload)
        args = _args(manifest=listing, declared_only=False, offline=True, verbose=True)
        setattr(args, "from", [old])
        real = io.StringIO()
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        invocation = install.Invocation()
        invocation.os_type = "linux"
        invocation.record(args)
        with mock.patch.object(install, "_INVOCATION", invocation), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms",
                                  return_value=[("retroarch", self.here)]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(install, "_is_terminal", return_value=True), \
                mock.patch.object(install, "_ask", return_value=""), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            install._install(args, real)
        said = real.getvalue()
        self.assertIn("Same choice without questions: python3 install.py --platform retroarch "
                      f"--dest {self.here}", said)
        self.assertIn("To check this later, run that command with --check.", said)

    def test_line_mode_says_the_card_it_found_and_names_its_folder(self):
        onion = self.card("ONION", "Onion")
        with mock.patch.object(install, "_mounted_cards", return_value=[onion]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            _platforms, text = line_decision(_args(manifest=self.list, declared_only=False),
                                             lambda prompt: "")
        self.assertIn(f"Found Onion at {onion / 'BIOS'} (RetroArch files)", text)
        self.assertNotIn("No supported platform detected", text)

    def test_a_pack_gets_the_menu_and_its_folder_named(self):
        """No menu and no folder before the copy, the pack's list
        recording no system."""
        from test_install_offline import _pack, PAYLOAD

        downloads = self.root / "downloads"
        downloads.mkdir()
        pack = _pack(downloads, "RetroArch_v1_BIOS_Pack.zip", PAYLOAD)
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        menus = []
        real = install._prompt_custom_selection

        def menu(*given, **named):
            with mock.patch.object(install, "_ask", return_value="q"):
                try:
                    real(*given, **named)
                except SystemExit as stop:
                    menus.append(stop.code)
                    raise

        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(install, "_is_terminal", return_value=True), \
                mock.patch.object(install, "_ask", side_effect=lambda prompt: (
                    "" if prompt.startswith(">") else str(self.here))), \
                mock.patch.object(install, "_prompt_custom_selection", menu), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit):
            install._install(_args(from_pack=[pack], declared_only=False), io.StringIO())
        text = out.getvalue()
        self.assertEqual(menus, [install.QUIT_CODE])
        self.assertIn("RetroArch was not found here.", text)
        self.assertIn(f"BIOS folder: {self.here}", text)
        self.assertIn("Enter) install everything", text)
        self.assertNotIn("c) choose systems", text)
        self.assertNotIn("Copying", text)

    # every line-mode finding, each answered
    # by line mode and the screen from one decision.

    def line_run(self, args: argparse.Namespace, answers: list, mounts: list = (),
                 found: list = ()) -> tuple[str, list]:
        """(text, prompts) of line mode at a terminal for args, the answers
        given in turn: the run stops at the first question left unanswered.
        Its text is --verbose's: these findings read the lines the default
        leaves out."""
        args.verbose = True
        given, asked = iter(answers), []

        def answer(prompt: str) -> str:
            asked.append(prompt)
            try:
                return next(given)
            except StopIteration:
                raise _Decided(prompt) from None

        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        # The options the run was started with, as main() records them.
        invocation = install.Invocation()
        invocation.os_type = "linux"
        invocation.record(args)
        with mock.patch.object(install, "_INVOCATION", invocation), \
                mock.patch.object(install, "_mounted_cards", return_value=list(mounts)), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=list(found)), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(install, "_is_terminal", return_value=True), \
                mock.patch.object(install, "_ask", side_effect=answer), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                contextlib.suppress(_Decided, SystemExit):
            install._install(args, io.StringIO())
        return out.getvalue() + err.getvalue(), asked

    def listing(self, plat: str, files: list, **extra) -> Path:
        path = self.root / f"{plat}-{len(list(self.root.glob('*.json')))}.json"
        path.write_text(json.dumps({"manifest_version": 2, "platform": plat,
                                    "files": files, **extra}))
        return path

    @staticmethod
    def entry(dest: str, payload: bytes, systems: list, **extra) -> dict:
        return {"dest": dest, "sha1": hashlib.sha1(payload).hexdigest(),
                "size": len(payload), "repo_path": f"bios/{dest}", "cores": None,
                "systems": systems, **extra}

    def test_o_then_the_setup_found_offers_the_folder_it_reads(self):
        """O then RetroArch offered
        its built-in folder, and Enter filled it, where the screen keeps the
        folder retroarch.cfg names."""
        pc = [("retroarch", self.here)]
        args = dict(manifest=self.list, declared_only=False, offline=False)
        text, asked = self.line_run(_args(**args), ["o", "", ""], found=pc)
        self.assertIn(f"RetroArch reads its BIOS files from: {self.here}.", text)
        self.assertIn("(Enter for the folder RetroArch reads)", asked[2])
        self.assertNotIn("default BIOS folder", text)
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=pc), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            install._DETECTED_OS.clear()
            given = iter(["o", "", ""])
            line, _text = line_decision(_args(**args), lambda _prompt: next(given))
            install._DETECTED_OS.clear()
            state = screen_keys(_args(**args), ["end", "enter", "enter", "enter"])
        self.assertEqual(tuple(line[0]), ("retroarch", self.here))
        self.assertEqual((state.platform, state.dest), ("retroarch", self.here))

    def test_a_share_drive_typed_is_read_as_its_bios_folder(self):
        """The SHARE drive's root,
        typed for Batocera or Recalbox, was the BIOS folder, beside roms/
        and system/. Another system's drive is refused, in both modes."""
        shares = {}
        for plat, marker in (("batocera", "system/batocera.conf"),
                             ("recalbox", "system/recalbox.conf")):
            share = self.root / "media" / f"SHARE-{plat}"
            (share / "system").mkdir(parents=True)
            (share / "roms").mkdir()
            # Batocera's own hostname: another would fit KNULLI renamed too.
            (share / marker).write_text("system.hostname=BATOCERA\n")
            shares[plat] = share
        for plat, share in shares.items():
            other = shares["recalbox" if plat == "batocera" else "batocera"]
            listing = self.listing(plat, [])
            with self.subTest(platform=plat):
                text, _asked = self.line_run(_args(manifest=listing, declared_only=False),
                                             [str(other), str(share)])
                self.assertIn(f"{other} is a {install.display_name(install.share_drive(other))}"
                              " SHARE drive", text)
                self.assertIn(f"SHARE drive: its BIOS folder is {share / 'bios'}", text)
                with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                        mock.patch.object(install, "detect_platforms", return_value=[]), \
                        mock.patch.object(install, "detect_frontends", return_value=[]):
                    line, _text = line_decision(_args(manifest=listing, declared_only=False),
                                                lambda _prompt, typed=str(share): typed)
                    refused = screen_keys(_args(manifest=listing), [
                        "end", "enter", Key("paste", str(other)), "enter"])
                    state = screen_keys(_args(manifest=listing), [
                        "end", "enter", Key("paste", str(share)), "enter"])
                self.assertEqual(tuple(line[0]), (plat, share / "bios"))
                self.assertEqual((state.platform, state.dest), (plat, share / "bios"))
                self.assertIn("SHARE drive", refused.status)
                self.assertEqual(refused.screen, "path")

    def test_the_setups_found_are_labelled_alike(self):
        """"Onion SD card
        (ONION) (/media/me/ONION/BIOS)", two pairs of brackets, and a MinUI
        card named by its root where its BIOS folder is Bios."""
        onion, minui = self.card("ONION", "Onion"), self.card("MINUI", "MinUI")
        mounts, pc = [onion, minui], [("retroarch", self.here)]
        text, _asked = self.line_run(_args(declared_only=False), [], mounts, pc)
        self.assertNotIn(") (", text)
        self.assertIn(f"Found MinUI at {minui / 'Bios'}", text)
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=pc), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            install._DETECTED_OS.clear()
            setups, _mounted = install.found_setups("linux")
            state = install.TuiState(os_type="linux", home=HOME)
            state.setups = setups
            for index, (plat, path, label) in enumerate(setups):
                state.focus["setup"] = index
                screen = " ".join(install.tui_view(state, 120, 40))
                folder = install.setup_bios_folder(plat, path)
                with self.subTest(setup=label):
                    self.assertIn(f"{index + 1}) {label}: {folder}", text)
                    self.assertIn(f"BIOSfolder:{folder}", screen.replace(" ", ""))

    def test_both_count_the_systems_out_of_the_same_list(self):
        """The plan said 1 of 12 systems where Choose
        systems and line mode listed 11, a system whose only file is read
        from an unknown save directory counted."""
        payload = b"gba"
        files = [self.entry("gba_bios.bin", payload, ["nintendo-gba"]),
                 self.entry("ds.bin", b"ds", ["nintendo-ds"]),
                 self.entry("Azahar/keys.txt", b"keys", ["nintendo-3ds"], root="save")]
        # No retroarch.cfg, and a BIOS folder not named as the list's: the
        # save directory is not known, and keys.txt is left out.
        manifest = {"base_destination": "RetroArch",
                    "save_directory": {"folder": "saves", "by_core": False}}
        listing = self.listing("retroarch", files, **manifest)
        args = dict(manifest=listing, dest=self.here, declared_only=False,
                    system=["nintendo-gba"])
        text, _asked = self.line_run(_args(**args), [])
        self.assertIn("for 1 of 2 systems (--system).", text)
        events, _out = engine_events(_args(**args, check=True, events=True, no_input=True))
        choices = next(event for event in events if event["event"] == "choices")
        self.assertEqual(choices["systems"], ["nintendo-ds", "nintendo-gba"])
        manifest = json.loads(listing.read_text())
        state, screen = screen_plan(_args(**args), manifest, events)
        self.assertIn("For 1 of 2 systems (--system).", screen)
        # Choose systems, opened from that plan, lists the same two.
        self.assertEqual(len(install.tui_systems(state)), 2)

    def test_after_o_the_list_offers_the_setups_its_file_list_serves(self):
        """Batocera was offered for a RetroArch list,
        and refused once its folder had been asked."""
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        install.LOCAL.manifest = self.list
        line = [name for name, _label in install._line_setups([], set(), "linux")]
        state = install.TuiState(os_type="linux", home=HOME)
        state.stack = ["platforms"]
        screen = [install._row_name(row) for row in install.tui_rows(state)
                  if row.action != "filter"]
        self.assertEqual(line, screen)
        self.assertIn("retroarch", line)
        self.assertIn("Onion", line)
        self.assertNotIn("batocera", line)
        self.assertNotIn("knulli", line)

    def test_a_choice_of_systems_is_confirmed_before_anything_is_written(self):
        """C installed as soon as the
        last list was answered, and its command left out --dest and
        --manifest. The menu comes back counted, as the screen's Confirm."""
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"]),
                 self.entry("scph5501.bin", b"psx", ["sony-playstation"])]
        listing = self.listing("retroarch", files)
        args = _args(manifest=listing, dest=self.here, declared_only=False)
        text, asked = self.line_run(args, ["c", "1"])
        self.assertIn("Counted again for these choices. Nothing is written before Enter.", text)
        self.assertIn("RetroArch: 1 file, 3 B, for 1 of 2 systems.", text)
        self.assertIn("Enter) install these", text)
        self.assertEqual(asked[-1], "> ")
        command = next(line for line in text.splitlines()
                       if "Same choice without questions:" in line)
        for option in (f"--dest {self.here}", f"--manifest {listing}",
                       "--system nintendo-gba"):
            self.assertIn(option, command)
        self.assertNotIn("Copying", text)
        self.assertEqual(list(self.here.iterdir()), [])
        # The screen: Choose systems, A ticks, B back to the plan, whose
        # Install counts the choice on Confirm first.
        state = checked_state()
        press(state, "down", "enter")
        self.assertEqual(state.screen, "systems")
        press(state, "enter", "esc")
        effects = press(state, "enter")
        self.assertEqual((state.screen, effects), ("confirm", [("run", "confirm")]))

    def tree(self, ref: str, systems: list, count: int) -> dict:
        return {"ref": ref, "url": "https://example.org/tree.zip", "type": "zip",
                "systems": systems, "dest": ref,
                "files": {f"f{n}.dat": {"sha1": "a" * 40, "size": 10} for n in range(count)}}

    def test_both_count_the_data_files_of_the_systems_kept(self):
        """Line mode counted 2636 data files of other
        systems for every --system tried, where the screen counts none."""
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"]),
                 self.entry("scph5501.bin", b"psx", ["sony-playstation"])]
        trees = [self.tree("gba-tree", ["nintendo-gba"], 2),
                 self.tree("psx-tree", ["sony-playstation"], 5)]
        listing = self.listing("retroarch", files, data_directories=trees)
        args = dict(manifest=listing, dest=self.here, declared_only=False)
        for system, count in (("nintendo-gba", 2), ("sony-playstation", 5)):
            with self.subTest(system=system):
                text, _asked = self.line_run(_args(**args, system=[system]), [])
                self.assertIn(f"and {count} data files (", text)
                events, _out = engine_events(_args(**args, system=[system], check=True,
                                                   events=True, no_input=True))
                data = next(event for event in events if event["event"] == "data")
                self.assertEqual(data["files"], count)
        text, _asked = self.line_run(_args(**args), [])
        self.assertIn("and 7 data files (", text)

    @unittest.skipUnless(hasattr(os, "statvfs"), "statvfs reads mount flags")
    def test_a_read_only_card_gets_one_remedy_and_no_sudo(self):
        """The plan offered sudo for a read-only mount,
        with a command that dropped --from-pack and --manifest, and the
        result offered nothing. One advice, line mode before its menu, the
        plan and the result."""
        listing = self.listing("retroarch", [self.entry("a.bin", b"a", ["x"])])
        args = _args(manifest=listing, dest=self.here, declared_only=False)
        words = install.read_only_words(self.here)
        with mock.patch.object(install, "_on_read_only_mount", return_value=True), \
                mock.patch.object(install, "_folder_writable", return_value=False):
            text, _asked = self.line_run(args, [])
            state = checked_state({"free": 10 ** 9, "writable": False, "cores": []})
            plan = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
            state.summary = {"installed": 0, "up_to_date": 0, "pending": 1, "kept": [],
                             "failed": [{"dest": "a.bin", "reason": install.NOT_WRITABLE}],
                             "skipped": [], "left_out": [], "interrupted": False}
            state.code = 2
            _title, result = install.tui_outcome(state)
        menu = text[:text.index("Enter)")]
        for said in (menu, plan, " ".join(result)):
            self.assertIn(words, said)
            self.assertNotIn("sudo", said)

    def test_the_sudo_command_keeps_every_option_of_the_run(self):
        """The plan's sudo line dropped --from-pack and
        --manifest, and with --offline stopped at the file list."""
        state = checked_state({"free": 10 ** 9, "writable": False, "cores": []})
        state.manifest_path, state.manifest_given = Path("/l/retroarch.json"), True
        state.passthrough = [("--from-pack", "/p/RetroArch_BIOS_Pack.zip")]
        with mock.patch.object(install, "_on_read_only_mount", return_value=False):
            plan = " ".join(str(line) for line in install._plan_lines(state.check, state.dest,
                                                                       state))
        line = plan[plan.index("Or run it as root"):]
        for option in ("--manifest /l/retroarch.json", "--from-pack /p/RetroArch_BIOS_Pack.zip",
                       f"--dest {SYSTEM_DIR}"):
            self.assertIn(option, line)

    def test_the_save_files_are_counted_after_the_choice(self):
        """--system sony-playstation said 106 files went
        to the save directory, none of them PlayStation's."""
        here = self.root / "pc" / "system"
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"]),
                 self.entry("Azahar/keys.txt", b"keys", ["nintendo-3ds"], root="save")]
        listing = self.listing("retroarch", files, base_destination="system",
                               save_directory={"folder": "saves", "by_core": False})
        for system, count in ((["nintendo-gba"], 0), (["nintendo-3ds"], 1), (None, 1)):
            args = dict(manifest=listing, dest=here, declared_only=False, system=system)
            with self.subTest(system=system):
                text, _asked = self.line_run(_args(**args), [])
                events, _out = engine_events(_args(**args, check=True, events=True,
                                                   no_input=True))
                saves = [event for event in events if event["event"] == "saves"]
                if count:
                    self.assertIn("1 file read from RetroArch's save directory goes to", text)
                    self.assertEqual([event["files"] for event in saves], [1])
                else:
                    self.assertNotIn("save directory", text)
                    self.assertEqual(saves, [])

    def test_a_list_that_leaves_out_save_files_says_so_before_the_menu(self):
        """ROCKNIX's 44 files left out were said after
        the install only, as the frontend's, where the plan says them."""
        omitted = [{"dest": f"saves/{n}.key", "name": f"{n}.key", "system": "",
                    "systems": [], "required": False, "reason": "no_save_directory",
                    "cores": None} for n in range(3)]
        listing = self.listing("rocknix", [self.entry("a.bin", b"a", ["x"])],
                               omitted_files=omitted)
        card = self.card("ROCKNIX", "ROCKNIX")
        args = _args(manifest=listing, dest=card, declared_only=False)
        text, _asked = self.line_run(args, [])
        said = "3 files read from ROCKNIX's save directory left out"
        self.assertLess(text.index(said), text.index("Enter)"))
        state = checked_state()
        state.platform = "rocknix"
        summary = {"skipped": [{"reason": "no_save_directory", "files": 3}]}
        self.assertIn(said, " ".join(install._unplaced_lines(summary, state)))
        # And the end of the run names it as the plan does.
        seen = [{**entry, "frontend": "ROCKNIX"} for entry in omitted]
        with contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.suppress(SystemExit):
            install._report_outcome([self.here], 1, 0, 0, 3, False, omitted_entries=seen)
        self.assertIn(said, out.getvalue())

    def test_the_drives_mounted_here_are_offered_in_both(self):
        """The copy question listed no drive and took q
        as a folder, and the screen's Which folder? listed none where line
        mode numbered them."""
        stick, onion = self.root / "media" / "USBSTICK", self.card("ONION", "Onion")
        stick.mkdir(parents=True)
        mounts = [stick]
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                mock.patch.object(install, "_ask", side_effect=["q"]), \
                self.assertRaises(SystemExit) as stop:
            install._ask_from_folder([], onion / "BIOS")
        self.assertEqual(stop.exception.code, install.QUIT_CODE)
        self.assertIn(f"1) {install.card_line(stick)}", out.getvalue())
        with mock.patch.object(install, "_mounted_cards", return_value=[stick, onion]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                mock.patch.object(install, "_ask", side_effect=["2", ""]):
            install._ask_from_folder([], onion / "BIOS")
        # The card installed to is not offered to copy from.
        self.assertNotIn(str(onion), out.getvalue())
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                mock.patch.object(install, "_ask", side_effect=["1"]), \
                mock.patch.object(install, "_missing_dest", return_value=True):
            folder = install.ask_platform_folder("linux", "retroarch")
        # a drive is offered by its bios folder, never its
        # root, which no setup reads.
        self.assertEqual(folder, stick / "bios")
        state = install.TuiState(os_type="linux", home=HOME)
        state.platform, state.stack = "retroarch", ["folder"]
        state.folder_default, state.folder_kind = SYSTEM_DIR, "usual"
        with mock.patch.object(install, "_mounted_cards", return_value=mounts):
            rows = install.tui_rows(state)
        self.assertEqual([row.value for row in rows if row.action == "drive"],
                         [stick / "bios"])

    def test_the_systems_are_listed_by_title_in_the_screen_order(self):
        """Line mode listed ids, nintendo-3ds before
        nintendo-ds, where the screen lists titles."""
        titles = {"nintendo-ds": "Nintendo DS", "nintendo-gba": "Nintendo Game Boy Advance"}
        files = [self.entry("ds.bin", b"ds", ["nintendo-ds"]),
                 self.entry("gba.bin", b"gba", ["nintendo-gba"]),
                 self.entry("3ds.bin", b"3ds", ["nintendo-3ds"])]
        manifest = {"system_titles": titles}
        listing = self.listing("retroarch", files, **manifest)
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False), ["c"])
        listed = text[text.index("Systems:"):]
        places = [listed.index(label) for label in (
            "1) Nintendo DS  nintendo-ds", "2) Nintendo Game Boy Advance  nintendo-gba",
            "3) nintendo-3ds")]
        self.assertEqual(places, sorted(places))
        state = install.TuiState(os_type="linux", home=HOME)
        state.manifest = {"files": files, **manifest}
        state.systems = [{"system": system, "name": system, "missing": 1, "wrong_hash": 0,
                          "bytes_needed": 2} for system in ("nintendo-3ds", "nintendo-ds",
                                                            "nintendo-gba")]
        order = [row["system"] for row in install._sorted_systems(state)]
        self.assertEqual(order, ["nintendo-ds", "nintendo-gba", "nintendo-3ds"])

    def test_the_card_question_looks_again_and_lists_blank_drives(self):
        """Enter at Card root never looked again, a
        blank stick was listed for KNULLI on the screen alone, and the two
        modes differed on creating its bios."""
        onion = self.card("ONION", "Onion")
        seen: list = []
        answers = iter(["", "1"])

        def answer(_prompt: str) -> str:
            value = next(answers)
            if not value:
                # The card goes in while the question waits.
                seen.append(onion)
            return value

        with mock.patch.object(install, "_mounted_cards", side_effect=lambda: list(seen)), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "_ask", side_effect=answer), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("onion", "retroarch", True)
        self.assertEqual(dest, onion / "BIOS")
        self.assertIn(f"1) {install.card_line(onion)}", out.getvalue())
        # KNULLI fills its card when it first starts: a blank drive is
        # listed in both, after Look again on the screen, and its bios is
        # created without a question in both.
        stick = self.root / "media" / "USBSTICK"
        stick.mkdir(parents=True)
        with mock.patch.object(install, "_mounted_cards", return_value=[stick]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "_ask", side_effect=["1"]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("knulli", "knulli", True)
            state = screen_keys(_args(platform="knulli"), [])
            rows = install.tui_rows(state)
            self.assertEqual([row.action for row in rows][:2], ["rescan", "card"])
            self.assertEqual(rows[state.focus["folder"]].action, "rescan")
            press(state, "down", "enter")
        self.assertEqual(dest, stick / "bios")
        self.assertIn(f"1) {install.card_line(stick)}", out.getvalue())
        self.assertEqual((state.dest, state.screen), (stick / "bios", "checking"))

    def test_a_full_or_read_only_folder_is_said_before_enter(self):
        """Line mode showed Enter) install
        everything over a full card and refused after it. On a card setup
        both say to free space on the card."""
        onion = self.card("ONION", "Onion")
        listing = self.listing("retroarch", [self.entry("a.bin", b"a" * 4096, ["x"])])
        usage = mock.Mock(free=1024)
        with mock.patch.object(install.shutil, "disk_usage", return_value=usage), \
                mock.patch.object(install, "dest_drive", return_value=onion):
            install._DETECTED_OS[("retroarch", onion / "BIOS")] = "Onion"
            text, _asked = self.line_run(_args(manifest=listing, dest=onion / "BIOS",
                                               platform="retroarch", declared_only=False),
                                         [], [onion])
            state = checked_state({"free": 1024, "writable": True, "cores": []})
            state.dest = onion / "BIOS"
            install._DETECTED_OS[("retroarch", state.dest)] = "Onion"
            plan = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        menu = text[:text.index("Enter)")]
        self.assertIn("Not enough free space: 4.0 KB needed, 1.0 KB free. Free some space "
                      "on the card first.", menu)
        self.assertIn("Free some space on the card first.", plan)

    def test_a_device_typed_is_named_first(self):
        """"miyoo mini" listed MinUI with RG28XX, RG34XX
        and RG34XX SP, where the screen's row names the Miyoo Mini."""
        install.LOCAL.reset()
        choices = install._line_setups([], set(), "linux")
        found = install._line_matches(choices, "miyoo mini", [], set(), "linux")
        rows = {install._row_name(row): row
                for row in install.setup_list([], set(), "miyoo mini", "linux")}
        self.assertTrue(found)
        for index, label in found:
            name = choices[index][0]
            with self.subTest(setup=name):
                self.assertIn("Miyoo Mini", label.split("(", 1)[1])
                first = rows[name].right.split(", ")[0]
                self.assertTrue(label.split("(", 1)[1].startswith(first), (label, first))

    def test_line_mode_says_setup_where_the_screen_does(self):
        """"Detecting platform..." and "No supported
        platform found here", where the screen says setup and "Nothing was
        found here.\""""
        # The standalone emulators' lists come from the network: none here
        #, and none found.
        with mock.patch.object(install, "_install_standalone_folders", return_value=False):
            text, _asked = self.line_run(_args(declared_only=False), [])
        self.assertIn("Looking for setups here...", text)
        # Said once, the question alone after it.
        self.assertEqual(text.count("Nothing was found here."), 1)
        self.assertIn("\nWhich setup?\n", text)
        self.assertNotIn("Detecting platform", text)
        self.assertNotIn("No supported platform", text)
        state = install.TuiState(os_type="linux", home=HOME)
        state.stack = ["platforms"]
        self.assertIn("Nothing was found here.", " ".join(install.tui_view(state, 80, 24)))

    def test_yes_at_a_terminal_asks_nothing(self):
        """--yes waited at Install for: and at the menu."""
        seen = []
        with mock.patch.object(sys, "argv", ["install.py", "--yes", "--plain"]), \
                mock.patch.object(install, "_run", side_effect=seen.append):
            install.main()
        self.assertTrue(seen[0].no_input)
        self.assertIn("implies --no-input",
                      " ".join(install.build_parser().format_help().split()))
        # Asked nothing, with two setups found where the screen offers both.
        pc = [("retroarch", self.here), ("retroarch", self.root / "other")]
        seen[0].manifest = self.list
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            _text, asked = self.line_run(seen[0], [], found=pc)
        self.assertEqual(asked, [])

    # line mode, and the screen beside it.

    def copy_folder(self) -> tuple[Path, Path]:
        listing, _files = self.game_list()
        old = self.root / "OLD"
        (old / "doom").mkdir(parents=True)
        (old / "gba_bios.bin").write_bytes(b"gba")
        (old / "doom" / "doom1.wad").write_bytes(b"wad" * 10)
        return listing, old

    def test_the_copy_line_says_copying_once(self):
        """"Copying 22 files copied
        from ...", its size read as the folder's."""
        listing, old = self.copy_folder()
        args = _args(manifest=listing, dest=self.here, declared_only=False, no_input=True,
                     offline=True)
        setattr(args, "from", [old])
        text, _asked = self.line_run(args, [])
        self.assertIn(f"Copying 2 files (33 B) from {old}...", text)
        self.assertNotIn("files copied from", text[text.index("\nCopying "):])

    def test_narrowed_is_said_only_when_the_list_shrank(self):
        """Enter for every system said "Narrowed 4 to 4"."""
        args = dict(manifest=self.counted_list(), dest=self.here, declared_only=False,
                    dry_run=True)
        text, _asked = self.line_run(_args(**args), ["c", "", ""])
        self.assertNotRegex(text, r"Narrowed (\d+) to \1 files")
        text, _asked = self.line_run(_args(**args), ["c", "1", ""])
        # The menu counted the choice again before Enter: said once.
        self.assertIn("Counted again for these choices", text)
        self.assertNotIn("Narrowed", text)
        args = _args(manifest=self.counted_list(), dest=self.here, declared_only=False,
                     dry_run=True, no_input=True, system=["doom"])
        text, _asked = self.line_run(args, [])
        self.assertRegex(text, r"Narrowed 4 to \d files")

    def test_the_dry_run_names_systems_by_their_titles(self):
        """--dry-run listed microsoft-msx where the list
        and the screen say Microsoft MSX."""
        files = [self.entry("msx/msx.rom", b"msx", ["microsoft-msx"]),
                 self.entry("gba_bios.bin", b"gba", ["nintendo-gba"])]
        listing = self.listing("retroarch", files, system_titles={
            "microsoft-msx": "Microsoft MSX", "nintendo-gba": "Nintendo Game Boy Advance"})
        args = _args(manifest=listing, dest=self.here, declared_only=False, dry_run=True,
                     no_input=True)
        text, _asked = self.line_run(args, [])
        self.assertIn("  Microsoft MSX  1 file, 3 B", text)
        self.assertNotIn("  microsoft-msx  1 file", text)
        manifest = json.loads(listing.read_text(encoding="utf-8"))
        state = install.TuiState(os_type="linux", home=HOME)
        state.manifest = manifest
        self.assertEqual(install._tui_system_label({"system": "microsoft-msx"},
                                                   install._system_titles(state)),
                         "Microsoft MSX")

    def test_the_largest_systems_tail_counts_groups(self):
        """"... and 78 more systems" under a plan of 65."""
        files = [{"dest": f"{n}.bin", "size": n + 1, "systems": [f"s{n}"]} for n in range(12)]
        files.append({"dest": "shared.bin", "size": 1, "systems": ["s0", "s1"]})
        out = io.StringIO()
        with mock.patch.object(install.shutil, "get_terminal_size",
                               return_value=os.terminal_size((80, 10))), \
                contextlib.redirect_stdout(out):
            install._print_plan(files, Path("dest"), install.Terminal(io.StringIO()))
        self.assertIn("12 systems in 13 groups, the largest first", out.getvalue())
        self.assertIn("... and 3 more groups:", out.getvalue())
        # The same tail under --check, for the files the collection lacks.
        absent = [{"dest": f"{n}.bin", "systems": [f"s{n}", "shared"]} for n in range(10)]
        lines = install._needed_lines(absent, "Absent")
        self.assertIn("    ... and 2 more groups (--check --verbose lists them all)", lines)

    def test_a_command_given_back_keeps_offline_in_both_modes(self):
        """With the variable alone,
        line mode's Same choice ended with --offline and the screen's not."""
        args = dict(manifest=self.counted_list(), dest=self.here, declared_only=False,
                    dry_run=True)
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            text, _asked = self.line_run(_args(**args), ["c", "1", ""])
            line = next(line for line in text.splitlines() if "Same choice" in line)
            self.assertIn(" --offline", line)
            state = checked_state()
            self.assertIn(" --offline", install.tui_command(state))

    def test_q_quits_on_the_quit_code_in_both_modes(self):
        args = dict(manifest=self.counted_list(), dest=self.here, declared_only=False)
        install.LOCAL.reset()
        with mock.patch.object(install, "_ask", return_value="q"), \
                contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(SystemExit) as stop:
            install._prompt_custom_selection("retroarch", [], [])
        self.assertEqual(stop.exception.code, 2)
        self.assertEqual(install.QUIT_CODE, 2)
        state = checked_state()
        install.tui_update(state, Key("char", "q"))
        self.assertEqual(state.exit_code, 2)
        del args

    def test_a_card_in_the_reader_is_offered_not_asked_for(self):
        """Line mode numbered the card and said to mount
        it, the screen said none was mounted."""
        card = self.root / "media" / "KNULLI2"
        (card / "system").mkdir(parents=True)
        (card / "system" / "batocera.conf").write_text("system.hostname=RG40XXH\n")
        with mock.patch.object(install, "_mounted_cards", return_value=[card]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "_ask", side_effect=["q"]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit):
            install.card_install_dest("knulli", "knulli", interactive=True)
        text = out.getvalue()
        self.assertIn("Type 1 if it is the KNULLI card, or type its top folder.", text)
        self.assertNotIn("Mount the card", text)
        self.assertIn(f"1) {card.name} (card or drive, {card})", text)
        state = install.TuiState(os_type="linux", home=HOME)
        state.platform = "knulli"
        state.card_bound = install.card_bound("knulli", "knulli")
        with mock.patch.object(install, "_mounted_cards", return_value=[card]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            install._open_folder_screen(state, None)
            rows = install.tui_rows(state)
            text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertEqual(rows[state.focus["folder"]].value, card)
        self.assertNotIn("is mounted", text)

    def test_a_list_and_nothing_found_stops_a_run_without_questions(self):
        """--yes with a list filled this computer's
        default folder, where the page says a run that needs an answer stops."""
        for flag in ({"yes": True}, {}):
            with self.subTest(flag=flag):
                code, text, events = self.unasked([], [], manifest=self.list, **flag)
                self.assertEqual(code, 1, text)
                self.assertNotIn("using default path", text)
                self.assertIn("Name its folder with --dest", text)
                self.assertEqual([(keys["stage"], keys["reason"]) for kind, keys in events
                                  if kind == "error"], [("detect", "not_found")])
        chosen, text, _events = self.unasked([], [], platform="retroarch", yes=True)
        self.assertEqual(chosen, [("retroarch", install._default_dest("linux", "retroarch"))])

    def test_a_terminal_the_screen_cannot_use_is_named(self):
        """TERM unset or dumb gave line questions without
        a word, where a small window said why."""
        reason = install.line_mode_reason
        self.assertEqual(reason("TERM is dumb or not set", {}),
                         "TERM is not set: questions come line by line.")
        self.assertEqual(reason("TERM is dumb or not set", {"TERM": "dumb"}),
                         "TERM=dumb: questions come line by line.")
        self.assertEqual(reason("TERM=vt52 cannot move the cursor", {}),
                         "TERM=vt52 cannot move the cursor: questions come line by line.")
        self.assertEqual(reason("the terminal is 39x12, smaller than 40x12", {}),
                         "The window is 39x12: questions come line by line (40x12 for the "
                         "full screen).")
        self.assertEqual(reason("the terminal is 0x0, smaller than 40x12", {}), "")
        self.assertEqual(reason("--check runs without questions", {}), "")
        self.assertEqual(reason("the input is not a terminal", {}), "")

    def test_game_data_has_one_wording_and_one_decision(self):
        """Five wordings, "No game data" read as a
        list holding none, and --no-game-data given offered it back on the
        screen alone."""
        listing, _files = self.game_list()
        args = dict(manifest=listing, dest=self.here, declared_only=False, dry_run=True)
        text, _asked = self.line_run(_args(**args), ["g", ""])
        self.assertIn("g) Game data: kept (1 file, 30 B): leave it out", text)
        after = text[text.index("Counted again"):]
        self.assertIn("1 BIOS file (3 B). 1 game data file left out.", after)
        self.assertIn("1 game data file left out (--no-game-data)", after)
        text, _asked = self.line_run(_args(no_game_data=True, **args), [""])
        self.assertNotIn("g) ", text)
        state = checked_state()
        state.manifest = {**state.manifest, "files": [
            *state.manifest["files"], {"dest": "doom/doom1.wad", "size": 30,
                                       "category": "game_data", "systems": ["doom"]}]}
        state.no_game_data = state.cli_no_game_data = True
        self.assertFalse(any(row.action == "gamedata" for row in install.tui_rows(state)))

    def test_three_kinds_are_named_in_both_modes(self):
        """"data files" beside game data files, never
        said what they were."""
        listing, _files = self.game_list()
        manifest = json.loads(listing.read_text(encoding="utf-8"))
        manifest["data_directories"] = [{"ref": "dolphin-sys", "systems": ["nintendo-gba"],
                                         "files": {"a": {"size": 5}, "b": {"size": 5}}}]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            install._print_menu_head("retroarch", manifest["files"], [], None, "",
                                     manifest["data_directories"], None, None, None, manifest,
                                     False)
        self.assertIn("1 BIOS file (3 B), 1 game data file (30 B) and 2 data files (10 B).",
                      out.getvalue())
        self.assertIn("Data files: the files an emulator reads from a data folder of its own",
                      out.getvalue())

    def test_the_wsl_folder_question_offers_both_sides(self):
        """Line mode's half."""
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_ask", side_effect=["q"]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit):
            install.ask_platform_folder("wsl", "retroarch")
        label, folder = install.other_side("wsl", "retroarch")[0]
        self.assertIn(f"1) {label}", out.getvalue())
        self.assertEqual(out.getvalue().count(install.shown_path(folder)), 1)


class PacksWordingAndDocs(unittest.TestCase):
    """What the screen, the packs, the
    wording and the docs answer, line mode's parity being in
    LineModeAndScreenDecideAlike."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)

    @unittest.skipUnless(pyte and pty and hasattr(pty, "fork") and shutil.which("script"),
                         "the line mode run needs a pty")
    def test_the_printed_command_makes_the_same_choice(self):
        """"Same choice without
        questions" left out the folder chosen at a question and the file
        list, and installed elsewhere or was refused. Run as printed, it
        finds every file of the choice in place and nothing else."""
        with FakeRepository() as repo:
            home = repo.root / "home"
            home.mkdir()
            listing = repo.root / "install" / "retroarch.json"
            env = {**repo.env(), "HOME": str(home), "RETROBIOS_OS": "linux", "TERM": "xterm",
                   "XDG_CONFIG_HOME": str(home / ".config")}
            env.pop("RETROBIOS_BOOTSTRAP", None)
            command = " ".join(shlex.quote(part) for part in [
                sys.executable, str(REPO_ROOT / "install.py"), "--plain",
                "--manifest", str(listing)])
            proc = subprocess.run(
                ["script", "-qec", command, "/dev/null"],
                # Enter on RetroArch, first of the setups that read its list
                #, then its folder.
                input=f"\n{repo.dest}\nc\n2\n2\n\n", env=env, capture_output=True,
                text=True, timeout=120, check=False)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            installed = repo.installed()
            self.assertEqual(installed, ["pcsx/extra.bin", "scph5501.bin"])
            printed = re.search(r"Same choice without questions: (.+)", proc.stdout)[1]
            words = shlex.split(printed.strip())
            self.assertEqual(words[:2], ["python3", "install.py"])
            for option in ("--dest", "--manifest", "--system"):
                self.assertIn(option, words)
            again = subprocess.run(
                [sys.executable, str(REPO_ROOT / "install.py"), *words[2:], "--dry-run",
                 "--events"], env=env, capture_output=True, text=True, timeout=120,
                check=False, stdin=subprocess.DEVNULL)
            files = [json.loads(line) for line in again.stdout.splitlines()
                     if '"event": "file"' in line]
            self.assertEqual(sorted(event["dest"] for event in files), installed)
            self.assertTrue(all(event["state"] == "present" for event in files))

    # a pack's own list records its systems.

    @unittest.skipIf(sys.version_info < (3, 9),
                     "generate_pack.py's context managers need Python 3.9")
    def test_a_pack_records_the_systems_of_its_files(self):
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        self.addCleanup(sys.path.remove, str(REPO_ROOT / "scripts"))
        import generate_pack  # noqa: PLC0415

        install_list = {"files": [{"dest": "a.bin", "systems": ["3do"]},
                                  {"dest": "b/c.bin", "systems": []}],
                        "system_titles": {"3do": "3DO Interactive Multiplayer"},
                        "system_names": {"3do": ["3do"]}}
        manifest = {"files": [{"path": "a.bin"}, {"path": "b/c.bin"}, {"path": "README.md"}]}
        generate_pack.annotate_pack_systems(manifest, generate_pack.pack_systems(install_list))
        self.assertEqual([entry.get("systems") for entry in manifest["files"]],
                         [["3do"], [], None])
        self.assertEqual(manifest["system_titles"], {"3do": "3DO Interactive Multiplayer"})
        source = (REPO_ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8")
        self.assertIn("pack_systems_by_name=systems_for", source)
        schema = json.loads((REPO_ROOT / "schemas" / "pack-manifest.schema.json").read_text())
        self.assertIn("systems", schema["properties"]["files"]["items"]["properties"])

    def pack(self, systems: bool) -> Path:
        from test_install_offline import GBA, US  # noqa: PLC0415

        members = {"scph5501.bin": US, "gba_bios.bin": GBA}
        listed = [{"path": path, "sha1": hashlib.sha1(data).hexdigest(),
                   "md5": hashlib.md5(data).hexdigest(), "size": len(data),
                   "status": "verified", "name": path,
                   **({"systems": ["sony-playstation" if "scph" in path else "nintendo-gba"]}
                      if systems else {})} for path, data in members.items()]
        folder = self.root / ("new" if systems else "old")
        folder.mkdir()
        path = folder / "RetroArch_v1_BIOS_Pack.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for member, data in members.items():
                archive.writestr(member, data)
            archive.writestr("manifest.json", json.dumps({
                "files": listed, **({"system_titles": {"nintendo-gba": "Game Boy Advance"}}
                                    if systems else {})}))
        return path

    def test_system_works_with_a_pack_alone(self):
        dest = self.root / "system"
        dest.mkdir()
        new = self.pack(True)
        events, _text = engine_events(_args(from_pack=[new], dest=dest, platform="retroarch",
                                            system=["nintendo-gba"], check=True, events=True,
                                            no_input=True, declared_only=False))
        files = [event["dest"] for event in events if event["event"] == "file"]
        self.assertEqual(files, ["gba_bios.bin"])
        # The screen offers Choose systems with that pack, titled from it.
        install.LOCAL.pack = install.PackSource([new])
        manifest = install.LOCAL.pack.manifest("retroarch")
        self.assertEqual(manifest["system_titles"], {"nintendo-gba": "Game Boy Advance"})
        state = checked_state()
        state.manifest = manifest
        self.assertIn("systems", [row.action for row in install.tui_rows(state)])
        # An older pack names the remedy that works.
        old = self.pack(False)
        install.LOCAL.reset()
        err = io.StringIO()
        install.LOCAL.pack = install.PackSource([old])
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            install._requested_narrowing(_args(system=["nintendo-gba"]), "retroarch",
                                         install.LOCAL.pack.manifest("retroarch")["files"], [])
        self.assertIn("Add --manifest FILE, a copy of install/retroarch.json", err.getvalue())
        self.assertNotIn("older release", err.getvalue())

    def test_a_pack_cannot_write_escapes_through_its_system_names(self):
        """The titles and ids a pack
        records reached print() raw in the systems list."""
        from test_install_offline import GBA, US  # noqa: PLC0415

        members = {"scph5501.bin": US, "gba_bios.bin": GBA}
        listed = [{"path": path, "sha1": hashlib.sha1(data).hexdigest(), "size": len(data),
                   "systems": ["bad\nid" if "scph" in path else "nintendo-gba"]}
                  for path, data in members.items()]
        path = self.root / "RetroArch_v1_BIOS_Pack.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for member, data in members.items():
                archive.writestr(member, data)
            archive.writestr("manifest.json", json.dumps({
                "files": listed,
                "system_titles": {"nintendo-gba": "\x1b]0;x\x07GBA", "bad\nid": "Bad"},
                "system_names": {"nintendo-gba": ["\x1b[2J"]}}))
        pack = install.PackSource([path])
        self.addCleanup(pack.close)
        manifest = pack.manifest("retroarch")
        self.assertEqual(manifest.get("system_titles", {}), {})
        self.assertEqual(manifest.get("system_names", {}), {})
        self.assertNotIn("systems", next(f for f in manifest["files"]
                                         if f["dest"] == "scph5501.bin"))
        # What _pick prints and the command line go through screen_text.
        with contextlib.redirect_stdout(io.StringIO()) as out, \
                mock.patch.object(install, "_ask", side_effect=["1"]):
            install._pick("Systems:", [("x", [])], labels={"x": "\x1b]0;x\x07GBA"})
        self.assertNotIn("\x1b", out.getvalue())
        self.assertIn("?]0;x?GBA", out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()) as out, \
                mock.patch.object(install, "_ask", side_effect=["c", "1", "q"]), \
                contextlib.suppress(SystemExit):
            install._prompt_custom_selection(
                "retroarch", [{"dest": "a", "size": 1, "systems": ["x"], "cores": None}], [],
                command=lambda _choice: "python3 install.py --dest '\x1b[2J'")
        self.assertNotIn("\x1b", out.getvalue())

    def test_the_home_folder_is_said_on_the_plan(self):
        """The plan named ~ and said nothing more."""
        state = checked_state()
        state.dest = state.home
        lines = " ".join(str(line) for line in install._plan_lines(state.check, state.dest,
                                                                     state))
        self.assertIn("No setup reads BIOS files in the home folder.", lines)

    def test_systems_seen_and_left_unchanged_keep_the_exact_plan(self):
        """Opening Choose systems on a --system plan and
        going back turned the exact plan into an estimate."""
        state = checked_state()
        state.cli_systems = ["nintendo-gba"]
        state.systems = [row for row in state.systems if row["system"] == "nintendo-gba"]
        state.ticked = {"nintendo-gba"}
        state.checked_flags = install.tui_flags(state)
        exact = install.tui_view(state, 80, 24)
        rows = install.tui_rows(state)
        state.focus["plan"] = next(i for i, row in enumerate(rows) if row.action == "systems")
        press(state, "enter")
        self.assertEqual(state.screen, "checking")
        # The check of every system comes back, the ticks kept.
        for event in [*FILES, *SYSTEMS, CHECK]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={
                "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
            install.tui_receive(state, ("ended", state.run_id, 0, []))
        self.assertEqual((state.screen, state.ticked), ("systems", {"nintendo-gba"}))
        press(state, "esc")
        self.assertEqual(state.screen, "plan")
        self.assertEqual(install.tui_view(state, 80, 24), exact)
        # Ticks changed: an estimate, without the whole list's counts.
        state.focus["plan"] = next(i for i, row in enumerate(install.tui_rows(state))
                                   if row.action == "systems")
        press(state, "enter")
        for event in [*FILES, *SYSTEMS, CHECK]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={
                "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
            install.tui_receive(state, ("ended", state.run_id, 0, []))
        state.ticked = {"sony-playstation"}
        press(state, "esc")
        text = " ".join(install.tui_view(state, 120, 40))
        self.assertIn("About", text)
        self.assertNotIn(f"{CHECK['present']} in place,", text)

    def test_the_copy_browser_leaves_the_card_being_installed_to(self):
        """The card installed to was focused and taken,
        and WSL rows read /mnt/d where every other screen writes D:."""
        dest_card, old = self.root / "d", self.root / "e"
        make_card(dest_card, "Onion")
        old.mkdir()
        state = install.TuiState(os_type="wsl", home=self.root / "home")
        (self.root / "home").mkdir()
        state.platform, state.dest = "retroarch", dest_card / "BIOS"
        with mock.patch.object(install, "_mounted_cards", return_value=[dest_card, old]), \
                mock.patch.dict(install._WSL, {"active": True, "root": str(self.root)}):
            install._open_from_browser(state)
            rows = install.tui_rows(state)
            self.assertEqual(rows[state.focus["browse"]].value, old)
            # Not offered at all, as line mode's Copy from leaves it out.
            self.assertNotIn("D: (Onion card)", [row.label for row in rows])
            self.assertIn("E: (card or drive)", [row.label for row in rows])
            # Reached through its folders all the same, it is refused.
            install._browse_to(state, dest_card)
            state.focus["browse"] = 0
            press(state, "enter")
        self.assertEqual(state.screen, "browse")
        self.assertIn("That is the card being installed to", state.status)
        self.assertEqual(state.from_folders, [])

    def test_typing_a_filter_names_the_keys_that_end_it(self):
        """While typing, the bar named Tick and Help,
        the focus stayed on None, F1 ended the typing, and a filter that
        matched nothing said nothing."""
        state = checked_state()
        press(state, "down", "enter")
        self.assertEqual(state.screen, "systems")
        press(state, "/")
        rows = install.tui_rows(state)
        self.assertEqual(rows[state.focus["systems"]].action, "filter")
        bar = install.tui_view(state, 80, 24)[-1]
        self.assertEqual(bar.strip(), "Enter Done  Esc Clear")
        press(state, "s", "e", "g", "a", " ", "?")
        self.assertEqual(state.filters["systems"], "sega ?")
        self.assertIn("No system matches 'sega ?'.", " ".join(install.tui_view(state, 80, 24)))
        press(state, "f1")
        self.assertTrue(state.help)
        press(state, "x")
        self.assertEqual((state.help, state.editing), (False, "systems"))

    def test_a_computer_finds_its_own_setups(self):
        """Windows and mac matched nothing, RetroBat
        came 27th on Windows, and a Batocera SHARE drive was not found."""
        names = {install._row_name(row) for row in install.setup_list([], set(), "windows",
                                                                      "windows")}
        self.assertEqual(names, {"retroarch", "retrobat", "emudeck", "bizhawk"})
        self.assertEqual({install._row_name(row) for row in install.setup_list(
            [], set(), "mac", "darwin")}, {"retroarch"})
        for os_type in ("windows", "wsl"):
            rows = [install._row_name(row) for row in install.setup_list([], set(), "", os_type)]
            self.assertEqual(rows[:3], ["retroarch", "retrobat", "emudeck"], os_type)
        share = self.root / "SHARE"
        (share / "system").mkdir(parents=True)
        (share / "system" / "batocera.conf").write_text("system.hostname=BATOCERA\n")
        with mock.patch.object(install, "_mounted_cards", return_value=[share]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.dict(install._DETECTED_OS, {}):
            setups, mounted = install.found_setups("linux")
        self.assertEqual(setups, [("batocera", share / "bios", "Batocera SHARE drive (SHARE)")])
        self.assertEqual(mounted, {("batocera", share / "bios")})

    def test_a_pack_preview_installs_from_the_pack(self):
        """"23 files to download" on a --from-pack run."""
        state = checked_state()
        state.stack.append("preview")
        state.dry = dict(CHECK)
        install.LOCAL.pack = mock.Mock(name="pack")
        self.assertIn("to install from the pack", install._pager_items(state)[0])

    @in_full
    def test_scroll_is_named_only_where_the_text_scrolls(self):
        """"Up/Down Scroll" over nine lines that fit."""
        state = checked_state()
        state.stack = ["result"]
        state.summary = {"installed": 1, "up_to_date": 0, "pending": 0, "failed": [],
                         "kept": [], "skipped": [], "left_out": [], "interrupted": False}
        state.code = 0
        self.assertNotIn("Scroll", install.tui_view(state, 80, 40)[-1])
        state.summary["failed"] = [{"dest": f"f{n}.bin", "reason": f"r{n}"} for n in range(20)]
        self.assertIn("Scroll", install.tui_view(state, 80, 12)[-1])

    def test_gptokeyb_names_select_then_start(self):
        """"Start+Select" on the bars, "Select, then
        Start" in the help and the docs."""
        state = checked_state()
        state.pad = "gptokeyb"
        state.stack.append("checking")
        self.assertIn("Select+Start Quit", install.tui_view(state, 80, 24)[-1])
        self.assertEqual(install.TUI_ROUTES["gptokeyb"].stop[1], "B or Select+Start")

    def test_nothing_to_confirm_is_titled_so(self):
        """Confirm over nothing to confirm, offline."""
        state = checked_state()
        state.stack.append("confirm")
        state.dry = dict(CHECK)
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            self.assertIn("Nothing to install", install.tui_view(state, 80, 24)[0])

    def test_another_folder_for_a_card_setup_asks_for_its_card(self):
        """A full Onion card offered another folder for
        RetroArch, and the result said to choose another folder."""
        onion = self.root / "ONION"
        make_card(onion, "Onion")
        state = checked_state({"free": 1024, "writable": True, "cores": []})
        state.dest = onion / "BIOS"
        with mock.patch.object(install, "_mounted_cards", return_value=[onion]), \
                mock.patch.dict(install._DETECTED_OS, {("retroarch", onion / "BIOS"): "Onion"}):
            plan = " ".join(install.tui_view(state, 120, 40))
            self.assertIn("Free some space on the card first.", plan)
            rows = install.tui_rows(state)
            state.focus["plan"] = next(i for i, row in enumerate(rows) if row.action == "folder")
            press(state, "enter")
            view = " ".join(install.tui_view(state, 120, 40))
            state.stack = ["result"]
            state.tail = ["Needed: 87.9 KB. Free: 36.0 KB."]
            _title, lines = install.tui_outcome(state)
        self.assertEqual(state.card_bound, ("Onion", "BIOS"))
        self.assertIn("The BIOS folder chosen for Onion:", view)
        self.assertIn("Free some space on the card, then run again.", lines)

    def test_the_dest_example_is_this_systems(self):
        """/media/$USER/SHARE/bios on macOS and Windows."""
        self.assertEqual(install.drive_example("darwin", "SHARE", "bios"), "/Volumes/SHARE/bios")
        self.assertEqual(install.drive_example("wsl", "SHARE", "bios"), "/mnt/e/bios")
        self.assertEqual(install.drive_example("windows", "SHARE", "bios", "batocera"),
                         "\\\\BATOCERA\\share\\bios")
        self.assertEqual(install.drive_example("windows", "<card>"), "E:\\")
        self.assertEqual(install.drive_example("linux", "<card>"), "/media/$USER/<card>")

    def test_the_copy_browser_opens_on_a_path_without_dot_dot(self):
        """--from t/../packx opened the browser on t/.."""
        packx = self.root / "packx"
        packx.mkdir()
        state, _effects = install.tui_start(
            _args(**{"from": [str(self.root / "t" / ".." / "packx")]}), "linux", detect=False)
        self.assertEqual(state.from_folders, [packx])

    def test_no_clause_semicolon_in_what_the_installer_prints(self):
        self.assertNotIn("; ", " ".join(install.build_parser().format_help().split()))
        source = Path(install.__file__).read_text(encoding="utf-8")
        for said in ("to fetch them; a file", "every board; --target", "with the system; ",
                     "no core list; ", "{retrodeck_json}; assuming", "REGION_ALIASES)}; ",
                     "extracted; ~/.config", "read-only; 1 once"):
            self.assertNotIn(said, source)

    def test_the_docs_say_what_the_installer_does(self):
        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        menu = page[re.search(r"RetroArch: \d+ files, [\d.]+ [KMG]B[.,]", page).start():]
        menu = menu[:menu.index("```")]
        self.assertIn("BIOS folder:", menu)
        self.assertIn("f) copy from a folder or an old card", menu)
        # The owner's request of 2026-10-27: game data counted apart, g.
        # test_doc_pages checks that the figures add up.
        self.assertRegex(menu, r"\d+ BIOS files \([\d.]+ [KMG]B\)(,| and) \d+ game data files")
        self.assertRegex(menu, r"g\) Game data: kept \(\d+ files")
        env = page[page.index("## Environment overrides"):]
        self.assertIn("`TERMINFO`", env)
        self.assertIn("`TERMINFO_DIRS`", env)
        script = (REPO_ROOT / "scripts" / "generate_installer_doc.py").read_text(encoding="utf-8")
        self.assertEqual([n for n, line in enumerate(script.splitlines(), 1) if len(line) > 100],
                         [])


class OneDeviceRegistry(unittest.TestCase):
    """One device spelled
    several ways found one system, one press took it, MinUI listed brands."""

    def found(self, typed: str, os_type: str = "linux") -> set:
        return {row.value[1] if row.action == "cardsystem" else row.value
                for row in install.setup_list([], set(), typed, os_type)}

    def test_one_spelling_per_device(self):
        keys = {}
        for name in install._DEVICES:
            keys.setdefault(install._device_key(name), []).append(name)
        self.assertEqual({key: names for key, names in keys.items() if len(names) > 1}, {})
        for system, devices in install._SETUP_DEVICES.items():
            with self.subTest(system=system):
                self.assertEqual([name for name in devices if name not in install._DEVICES], [])

    def test_every_spelling_finds_every_system_that_runs_it(self):
        rk2023 = {"ArkOS", "KOLOS", "JELOS", "rocknix"}
        cubexx = {"muOS", "knulli", "rocknix", "minui"}
        flip2 = {"knulli", "rocknix"}
        for typed, systems in (("Powkiddy RK2023", rk2023), ("RK2023", rk2023),
                               ("rk-2023", rk2023), ("RG CubeXX", cubexx),
                               ("RGCUBEXX", cubexx), ("Anbernic RG CubeXX", cubexx),
                               ("Retroid Pocket Flip 2", flip2), ("flip2", flip2)):
            with self.subTest(typed=typed):
                self.assertEqual(self.found(typed), systems)
        self.assertIn("ArkOS", self.found("Anbernic RG353V"))
        self.assertTrue({"Onion", "minui", "myminui", "Allium"} <= self.found("Miyoo Mini"))
        self.assertTrue({"Onion", "minui"} <= self.found("Miyoo Mini+"))
        self.assertIn("minui", self.found("TrimUI Brick"))
        self.assertIn("Anbernic stock firmware", self.found("rg35xx"))
        self.assertIn("JELOS", self.found("rgb10 max 3"))

    def test_android_is_this_machine_only_on_android(self):
        self.assertNotIn("retroarch", self.found("android"))
        self.assertNotIn("retroarch", self.found("retroid pocket 5"))
        self.assertIn("retroarch", self.found("android", "android"))

    def test_a_device_several_systems_run_is_never_taken_in_one_press(self):
        out = io.StringIO()
        with mock.patch.object(install, "_ask",
                               side_effect=["Powkiddy RK2023", "", "0", "35", "q"]), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            install._choose_platform("Which?", "retroarch")
        text = out.getvalue()
        self.assertIn("4 setups run on 'Powkiddy RK2023':", text)
        # Enter after the matches takes none, and 0 and 35 are numbers.
        self.assertEqual(text.count("Type a number from 1 to 34"), 3)
        self.assertNotIn("run on '0'", text)
        self.assertNotIn("run on '35'", text)

    def test_the_line_menu_is_the_screen_list_numbered(self):
        for setups in ([], [("retroarch", SYSTEM_DIR, "RetroArch")]):
            with self.subTest(found=bool(setups)):
                rows = install.setup_list(setups, set(), "", "linux")
                self.assertEqual([name for name, _label in install._line_setups(setups, None,
                                                                                 "linux")],
                                 [install._row_name(row) for row in rows])
        labels = dict(install._line_setups())
        self.assertIn("RG28XX", labels["minui"])
        self.assertNotIn("(Anbernic, Miyoo", labels["minui"])
        self.assertIn("RG35XX Plus", labels["Anbernic stock firmware"])
        self.assertNotIn("RetroArch files", labels["JELOS"])

    def test_forty_columns_keep_the_name_whole_and_a_device_count(self):
        rows = {row.label: row for row in install.setup_list([], set(), "", "linux")}
        for label in ("KNULLI, SD card", "ROCKNIX, SD card", "CrossMix-OS, SD card",
                      "AmberELEC, SD card", "JELOS, SD card"):
            with self.subTest(row=label):
                line = str(install._row_line(rows[label], False, 38))
                self.assertIn(label, line)
                self.assertTrue(line.rstrip() != ("  " + label).rstrip(), line)
        # its one device, cut, where "1 device" named none.
        self.assertTrue(str(install._row_line(rows["CrossMix-OS, SD card"], False, 38))
                        .rstrip().endswith("TrimUI Smar..."))


class CardFoldersAndNarrowBars(unittest.TestCase):
    """Card folders, refusals and bars at 40 columns, as the screens show
    them."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        patcher = mock.patch.dict(install._DETECTED_OS, {})
        patcher.start()
        self.addCleanup(patcher.stop)

    def start(self, mounts=(), found=(), **given) -> tuple:
        with mock.patch.object(install, "_mounted_cards", return_value=list(mounts)), \
                mock.patch.object(install, "detect_platforms", return_value=list(found)), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            return install.tui_start(_args(**given), "linux")

    def test_a_card_found_by_its_files_gets_its_folder_without_a_question(self):
        """Create the folder? for the Onion card's own
        BIOS, which line mode created."""
        onion = self.root / "ONIONB"
        make_card(onion, "Onion")
        shutil.rmtree(onion / "BIOS")
        state, effects = self.start([onion], platform="onion")
        self.assertEqual(effects, [("fetch", "retroarch")])
        self.assertEqual(state.dest, onion / "BIOS")
        self.assertIn("BIOS is created on ONIONB", state.card_note)

    def test_a_refused_dest_says_the_remedy_that_works(self):
        rocknix = self.root / "ROCKNIX"
        make_card(rocknix, "ROCKNIX")
        stick = self.root / "STICK"
        (stick / "photos").mkdir(parents=True)
        for named, plat, dest, words, never in (
                ("knulli", "knulli", rocknix / "roms" / "bios", "--platform rocknix", "<card>"),
                ("onion", "retroarch", stick, "Name the top folder of the Onion card",
                 "<card>/BIOS")):
            with self.subTest(named=named):
                with contextlib.redirect_stderr(io.StringIO()) as err, \
                        self.assertRaises(SystemExit):
                    install.card_dest(named, plat, dest)
                self.assertIn(words, err.getvalue())
                self.assertNotIn(never, err.getvalue())
        minui = self.root / "MINUI"
        make_card(minui, "MinUI")
        (minui / "Bios").mkdir()
        state = install.TuiState()
        install._card_status(state, install.card_choice("minui", "minui", minui / "Bios"),
                             given=True)
        self.assertIn(f"Run it again with --dest {minui}.", state.status)

    def test_wsl_names_drives_in_line_mode_messages(self):
        """/mnt/f in a refusal where D:\\ was typed."""
        mnt = self.root / "mnt"
        make_card(mnt / "f", "muOS")
        (mnt / "g" / "photos").mkdir(parents=True)
        with mock.patch.dict(install._WSL, {"active": True, "root": str(mnt)}), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            with contextlib.redirect_stderr(io.StringIO()) as err, \
                    self.assertRaises(SystemExit):
                install.card_dest("onion", "retroarch", mnt / "f")
            self.assertIn("F:\\ is a muOS card", err.getvalue())
            note = install.card_choice("knulli", "knulli", mnt / "g").note
            self.assertIn("G:\\bios", note)
            self.assertNotIn(str(mnt), note)
            self.assertEqual(install._last_name(str(mnt / "g" / "old")), "old")

    def test_choose_the_card_below_only_when_one_is_mounted(self):
        muos = self.root / "MUOS"
        make_card(muos, "muOS")
        stick = self.root / "USBSTICK"
        (stick / "photos").mkdir(parents=True)
        with mock.patch.object(install, "_mounted_cards", return_value=[muos, stick]):
            state, _effects = self.start([muos, stick], platform="onion")
            rows = install.tui_rows(state)
            state.focus["folder"] = next(index for index, row in enumerate(rows)
                                         if row.action == "browse")
            install.tui_update(state, Key("enter"))
            self.assertEqual(state.screen, "browse")
            self.assertIn("No Onion card is mounted", state.status)
            focused = install.tui_rows(state)[state.focus["browse"]]
            self.assertEqual(focused.value, stick)

    def test_type_a_path_says_f1_and_f1_says_more(self):
        muos = self.root / "MUOS"
        make_card(muos, "muOS")
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            state, _effects = self.start(platform="onion")
        stick = self.root / "STICK"
        stick.mkdir()
        state.stack.append("path")
        install._card_status(state, install.card_choice("Onion", "retroarch", stick))
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("F1 says more.", text)
        self.assertNotIn("? says more", text)
        install.tui_update(state, Key("f1"))
        self.assertTrue(state.help)
        help_text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("Onion keeps .tmp_update at the root of its card", help_text)

    def test_batocera_on_a_computer_offers_its_share(self):
        stick = self.root / "SHARE"
        stick.mkdir()
        state, _effects = self.start([stick])
        state.stack = ["platforms"]
        state.focus["platforms"] = install._platform_focus(state, "batocera")
        with mock.patch.object(install, "_mounted_cards", return_value=[stick]):
            install.tui_update(state, Key("enter"))
            rows = install.tui_rows(state)
            text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertEqual(state.screen, "folder")
        self.assertNotIn("/userdata/bios", text)
        self.assertIn("SHARE drive", text)
        self.assertEqual([row.action for row in rows], ["share", "browse", "type"])
        self.assertEqual(rows[0].value, stick / "bios")

    def test_the_first_screen_bar_says_quit(self):
        state, _effects = self.start()
        self.assertEqual(state.stack, ["platforms"])
        self.assertIn("B/Esc Quit", install._TUI_VIEWS["platforms"](state, 80, 24)[2])
        state.stack = ["setup", "platforms"]
        self.assertIn("B/Esc Back", install._TUI_VIEWS["platforms"](state, 80, 24)[2])

    def test_a_pad_result_prints_no_command(self):
        """A shell command on a controller-only screen."""
        state = _installed_state(self.root / "bios")
        state.summary["kept"] = [{"folder": str(self.root / "kept"), "files": 1}]
        state.pad = "muxterm"
        _title, lines = install.tui_outcome(state)
        text = " ".join(lines)
        self.assertNotIn("install.py", text)
        self.assertIn("kept in", text)
        state.pad = "keys"
        self.assertIn("Same choice without questions:", install.tui_outcome(state)[1])

    def test_the_checking_screen_is_titled_as_the_plan(self):
        state = install.TuiState()
        state.platform, state.dest = "retroarch", self.root / "bios"
        install._DETECTED_OS[("retroarch", state.dest)] = "ArkOS"
        state.stack = ["checking"]
        text = " ".join(install.tui_view(state, 80, 24))
        self.assertIn("ArkOS (RetroArch files):", text)

    def test_the_backup_line_survives_forty_columns(self):
        """Under the pack and copy split it was cut."""
        state = checked_state()
        state.found = [found("gba_bios.bin", "/media/old")]
        lines = [str(line) for line in install._plan_lines(state.check, state.dest, state)]
        self.assertTrue(any("copied from this machine" in line for line in lines), lines)
        counts = next(index for index, line in enumerate(lines) if " in place, " in line)
        self.assertTrue(lines[counts + 1].startswith("The 1 wrong copy is replaced"), lines)

    def test_an_empty_folder_is_said_once(self):
        old = self.root / "USBSTICK"
        old.mkdir()
        state = checked_state()
        state.from_folders = [old]
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: install.OFFLINE_FLAG_VALUE}):
            lines = [str(line) for line in install._plan_lines(state.check, state.dest,
                                                              state)]
        said = [line for line in lines if "USBSTICK" in line]
        self.assertEqual(said, ["USBSTICK holds none of these files: run the installer again "
                                "with a pack (--from-pack) or without --offline."])

    def test_amberelec_keeps_its_files_on_the_games_part(self):
        self.assertEqual(install.card_where("AmberELEC", ""),
                         "on the games part of its SD card")
        files = [{"dest": "bios/a.bin"}, {"dest": "bios/Machines/b.xml"}]
        self.assertEqual(install.shown_bios_folder(self.root, files), self.root / "bios")
        self.assertEqual(install.shown_bios_folder(self.root, [{"dest": "a.bin"}]),
                         self.root)

    def test_a_save_directory_left_out_has_one_wording(self):
        files = [{"dest": "keys.txt", "root": "save", "sha1": "0" * 40, "size": 1}]
        with contextlib.redirect_stdout(io.StringIO()) as out:
            install.place_save_entries(files, self.root / "BIOS",
                                       {"platform": "retroarch", "save_directory": {
                                           "folder": "saves", "by_core": False},
                                        "base_destination": "system"},
                                       None, "RetroArch")
        self.assertIn("left out: its place is not known. Name it with --save-dir.",
                      out.getvalue())


class CardBoundaries(unittest.TestCase):
    """Three folders at most, a bind mount not
    seen, a folder named MUOS taken for a card, ismount unprobed."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)

    def choice(self, folder: Path, points=frozenset()) -> install.CardChoice:
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_mount_points", return_value=points):
            return install.card_choice("knulli", "knulli", folder)

    def test_every_folder_up_to_the_mount_is_read(self):
        muos = self.root / "MUOS"
        make_card(muos, "muOS")
        deep = muos / "a" / "b" / "c" / "d"
        deep.mkdir(parents=True)
        self.assertIn("muOS", self.choice(deep).refused)

    def test_a_bind_mount_inside_a_card_is_its_own_drive(self):
        muos = self.root / "MUOS"
        make_card(muos, "muOS")
        stick = muos / "x"
        stick.mkdir()
        self.assertTrue(self.choice(stick).refused)
        choice = self.choice(stick, frozenset({str(stick)}))
        self.assertEqual((choice.refused, choice.folder), ("", stick / "bios"))

    def test_a_folder_named_muos_beside_it_is_no_card(self):
        backups = self.root / "stage" / "backups"
        (backups / "MUOS").mkdir(parents=True)
        (backups / "knulli-new").mkdir()
        choice = self.choice(backups / "knulli-new")
        self.assertEqual(choice.refused, "")
        self.assertEqual(choice.folder, backups / "knulli-new" / "bios")

    def test_mount_points_are_probed(self):
        with mock.patch.object(install, "_probed", wraps=install._probed) as probed, \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "_mounted_cards", return_value=[]):
            install._card_boundary(self.root)
        self.assertTrue(probed.called)
        points = install._mount_points()
        if Path("/proc/self/mountinfo").exists():
            self.assertIn("/", points)



def _screen_text(state: install.TuiState, cols: int = 80, rows: int = 24) -> str:
    return "\n".join(line.rstrip() for line in install.tui_view(state, cols, rows))


class LineModeDecisions(unittest.TestCase):
    """Line mode read other decisions than the
    screen (a drive's root for Batocera, no other setup once one was found,
    no Enter default, a folder question with no way out)."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        for patcher in (mock.patch.dict(install._DETECTED_OS, {}),
                        mock.patch.dict(os.environ, {"HOME": str(self.root / "home"),
                                                     "XDG_CONFIG_HOME": str(self.root / "cfg"),
                                                     "RETROBIOS_OS": "linux"})):
            patcher.start()
            self.addCleanup(patcher.stop)

    def ask(self, *answers: str):
        asked = []
        given = iter(answers)

        def answer(prompt: str) -> str:
            asked.append(prompt)
            return next(given)

        return mock.patch.object(install, "_ask", side_effect=answer), asked

    def share_drive(self, name: str = "SHARE") -> Path:
        drive = self.root / "media" / name
        (drive / "roms").mkdir(parents=True)
        return drive

    def test_a_numbered_share_drive_is_its_bios_folder(self):
        """2) SHARE gave the drive's
        root, the screen its bios folder."""
        muos = self.root / "media" / "MUOS"
        make_card(muos, "muOS")
        share = self.share_drive()
        patcher, _asked = self.ask("1")
        with mock.patch.object(install, "_mounted_cards", return_value=[muos, share]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                patcher, contextlib.redirect_stdout(io.StringIO()) as out:
            folder = install.ask_platform_folder("linux", "batocera")
        self.assertEqual(folder, share / "bios")
        text = out.getvalue()
        self.assertIn(f"1) SHARE: bios ({share / 'bios'}, does not exist yet)", text)
        self.assertNotIn("MUOS", text)

    def test_the_folder_question_quits_on_q_and_says_what_to_type(self):
        """Q became the folder ./q, filled, and Enter
        with no default repeated the prompt with no word."""
        patcher, asked = self.ask("", "q")
        with mock.patch.object(install, "_mounted_cards", return_value=[]), patcher, \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit) as stop:
            install.ask_platform_folder("linux", "batocera")
        self.assertEqual(stop.exception.code, install.QUIT_CODE)
        self.assertIn("q to quit", asked[0])
        self.assertIn("Type a folder, or q to quit.", out.getvalue())
        self.assertFalse((Path.cwd() / "q").exists())

    def test_a_relative_folder_is_named_in_full(self):
        """BIOS folder: q, Created q, Location: q."""
        here = self.root / "work"
        here.mkdir()
        patcher, _asked = self.ask("./q")
        with mock.patch.object(install, "_mounted_cards", return_value=[]), patcher, \
                mock.patch.object(install.Path, "cwd", return_value=here), \
                mock.patch.object(install.os, "getcwd", return_value=str(here)), \
                contextlib.redirect_stdout(io.StringIO()):
            folder = install.ask_platform_folder("linux", "batocera", ask=False)
        self.assertTrue(folder.is_absolute())
        self.assertEqual(folder, here / "q")

    def test_a_card_root_question_quits_on_q(self):
        patcher, asked = self.ask("q")
        with mock.patch.object(install, "_mounted_cards", return_value=[]), patcher, \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit) as stop:
            install.card_install_dest("rocknix", "rocknix", interactive=True)
        self.assertEqual(stop.exception.code, install.QUIT_CODE)
        self.assertEqual(asked, ["Card root, Enter to look again, q to quit: "])

    def test_install_for_takes_enter_and_offers_another_setup(self):
        """No Enter default, an All the screen does
        not have, and no other setup once one was found."""
        here = self.root / "system"
        found = [("retroarch", here)]
        patcher, asked = self.ask("")
        with patcher, contextlib.redirect_stdout(io.StringIO()) as out:
            chosen = install._prompt_platform_choice(
                found, labels={("retroarch", here): "RetroArch"}, other=lambda: [])
        self.assertEqual(chosen, found)
        self.assertEqual(asked, ["> [Enter for RetroArch] "])
        self.assertIn("o) another setup or folder", out.getvalue())
        self.assertNotIn("All", out.getvalue())
        other = [("batocera", self.root / "bios")]
        patcher, _asked = self.ask("o")
        with patcher, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(install._prompt_platform_choice(found, other=lambda: other), other)

    def test_the_setups_for_a_dest_come_in_the_screens_order(self):
        """With RetroArch found, --plain --dest put Onion
        at 19, the screen at 29."""
        dest = self.root / "blank"
        dest.mkdir()
        here = self.root / "system"
        listed = {}

        def choose(title, default="", setups=None, mounted=None):
            listed["rows"] = [name for name, _label in install._line_setups(
                setups, mounted, "linux")]
            listed["default"] = default
            raise _Decided(None)

        with mock.patch.object(install, "detect_platforms",
                               return_value=[("retroarch", here)]), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_choose_platform", side_effect=choose), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(_Decided):
            install._platform_for_dest("linux", dest, True)
        with mock.patch.object(install, "detect_platforms",
                               return_value=[("retroarch", here)]), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()):
            state, _effects = install.tui_start(_args(dest=dest), "linux")
        screen = [install._row_name(row) for row in install.tui_rows(state)
                  if row.action != "filter"]
        self.assertEqual(listed["rows"], screen)
        rows = install.tui_rows(state)
        self.assertEqual(install._row_name(rows[state.focus["platforms"]]), listed["default"])

    def test_system_named_on_the_command_line_keeps_the_menu(self):
        """--system skipped the menu and its folder line."""
        files = [{"dest": "a.bin", "size": 1, "systems": ["nintendo-gba"], "cores": None},
                 {"dest": "b.bin", "size": 1, "systems": ["sega-saturn"], "cores": None}]
        given = (["nintendo-gba"], [], [])
        patcher, _asked = self.ask("")
        with patcher, contextlib.redirect_stdout(io.StringIO()) as out:
            chosen = install._prompt_custom_selection(
                "retroarch", files, [], bios_path=self.root, given=given)
        self.assertEqual(chosen, given)
        text = out.getvalue()
        self.assertIn("RetroArch: 1 file, 1 B, for 1 of 2 systems (--system).", text)
        self.assertIn("Enter) install these", text)
        self.assertIn(f"BIOS folder: {self.root}", text)

    def test_narrowing_is_said_without_an_arrow(self):
        source = Path(install.__file__).read_text(encoding="utf-8")
        self.assertNotIn("} -> {len(files)}", source)

    def test_android_typed_names_retroarch(self):
        """Android matched nothing, and nothing more."""
        patcher, _asked = self.ask("android", "q")
        with patcher, mock.patch.object(install, "detect_os", return_value="linux"), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit):
            install._choose_platform("Which setup?")
        self.assertIn("On Android, choose RetroArch", out.getvalue())

    def test_batocera_named_on_a_computer_without_questions_is_refused(self):
        """/userdata/bios taken, Cannot create, end 2
        with no error event."""
        listing = self.root / "batocera.json"
        listing.write_text(json.dumps({"manifest_version": 2, "platform": "batocera",
                                       "files": []}))
        # --manifest sets the process-wide sources: a later test fetching
        # the list must not find this one.
        self.addCleanup(install.LOCAL.reset)
        events = io.StringIO()
        with mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.EVENTS, "stream", events), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit) as stop:
            install._install(_args(platform="batocera", no_input=True, manifest=listing),
                             io.StringIO())
        self.assertEqual(stop.exception.code, 1)
        self.assertNotIn("/userdata/bios", err.getvalue())
        self.assertIn("--dest /media/$USER/SHARE/bios", err.getvalue())
        kinds = [json.loads(line)["event"] for line in events.getvalue().splitlines()]
        self.assertEqual(kinds[-1], "error")


class ScreenRowsAndFilters(unittest.TestCase):
    """Rows, filters and help as the screens draw them."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        patcher = mock.patch.dict(install._DETECTED_OS, {})
        patcher.start()
        self.addCleanup(patcher.stop)

    def start(self, mounts=(), found=(), **given) -> tuple:
        with mock.patch.object(install, "_mounted_cards", return_value=list(mounts)), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=list(found)), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            return install.tui_start(_args(**given), "linux")

    def test_a_folder_holding_a_mounted_muos_card_is_no_muos_card(self):
        """/media/me held the MUOS mount point and read as
        a muOS card, and _own_card_root walked above the mount."""
        parent = self.root / "media"
        muos = parent / "MUOS"
        make_card(muos, "muOS")
        points = frozenset({str(muos)})
        with mock.patch.object(install, "_mount_points", return_value=points), \
                mock.patch.object(install, "_mounted_cards", return_value=[muos]):
            self.assertIsNone(install.card_system(parent))
            self.assertEqual(install.card_system(muos)[1], muos / "MUOS" / "bios")
            self.assertIsNone(install._own_card_root(muos / "bios"))
            self.assertEqual(install._own_card_root(muos / "MUOS" / "bios"), muos)

    def test_batocera_share_rows_leave_out_another_systems_card(self):
        """The muOS card was the first share row."""
        muos = self.root / "MUOS"
        make_card(muos, "muOS")
        share = self.root / "SHARE"
        share.mkdir()
        state, _effects = self.start([muos, share], platform="batocera")
        with mock.patch.object(install, "_mounted_cards", return_value=[muos, share]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            rows = [(row.action, row.label) for row in install.tui_rows(state)]
        self.assertIn(("share", "SHARE: bios"), rows)
        self.assertNotIn(("share", "MUOS: bios"), rows)

    def test_a_proposed_folder_is_created_without_the_guard(self):
        """Use this folder, then Create the folder? focused
        on Choose another folder, and Enter, Enter looped."""
        state = install.TuiState(os_type="linux", home=self.root)
        usual = self.root / ".config" / "retroarch" / "system"
        state.stack, state.platform = ["platforms"], "retroarch"
        install._open_folder_screen(state, usual)
        effects = install.tui_update(state, Key("enter"))
        self.assertEqual(effects, [("fetch", "retroarch")])
        self.assertNotIn("create", state.stack)
        self.assertIn("system is created in", state.card_note)
        typed = self.root / "a" / "b" / "c"
        state = install.TuiState(os_type="linux", home=self.root)
        state.stack, state.platform = ["folder"], "retroarch"
        install._choose(state, "retroarch", typed)
        self.assertEqual(state.screen, "create")
        self.assertEqual(install.tui_rows(state)[state.focus["create"]].action, "other")

    def test_a_page_moves_by_the_rows_drawn(self):
        """At 40x12 PgDn moved six rows over four drawn,
        and muOS and ROCKNIX were never shown."""
        for cols, rows in ((40, 12), (40, 15), (80, 24)):
            with self.subTest(size=f"{cols}x{rows}"):
                state, _effects = self.start()
                state.cols, state.rows = cols, rows
                seen = set()
                for _press in range(40):
                    text = _screen_text(state, cols, rows)
                    seen |= {line.strip("|> ").split(",")[0].strip()
                             for line in text.splitlines()}
                    install.tui_update(state, Key("pgdn"))
                for name in ("muOS, SD card", "ROCKNIX, SD card", "JELOS, SD card",
                             "EmuELEC, SD card", "RetroOZ, SD card"):
                    self.assertTrue(any(line.startswith(name.split(",")[0]) for line in seen),
                                    name)

    def test_the_first_screen_says_quit_and_a_filter_says_clear(self):
        state, _effects = self.start(platform="onion")
        self.assertEqual(state.stack, ["folder"])
        bar = install.tui_view(state, 80, 24)[-1]
        self.assertIn("Esc Quit", bar)
        self.assertNotIn("Esc Back", bar)
        state, _effects = self.start()
        press(state, "/", "o", "n")
        self.assertIn("Esc Clear", install.tui_view(state, 80, 24)[-1])
        press(state, "enter")
        self.assertIn("Esc Clear", install.tui_view(state, 80, 24)[-1])

    def test_rows_at_40_columns_name_a_device(self):
        """"1 device" for CrossMix-OS."""
        state, _effects = self.start()
        text = _screen_text(state, 40, 60)
        self.assertNotIn("1 device", text)
        crossmix = next(line for line in text.splitlines() if "CrossMix-OS" in line)
        self.assertIn("TrimUI", crossmix)

    def test_a_model_finds_the_systems_that_list_its_family(self):
        """RG353V missed ROCKNIX, RG351P
        missed AmberELEC and ROCKNIX."""
        for system, devices in install._SETUP_DEVICES.items():
            for device in devices:
                for model in (device, *install._DEVICE_FAMILIES.get(device, ())):
                    rows = install.setup_list([], set(), model, "android")
                    names = {install._row_name(row) for row in rows}
                    with self.subTest(system=system, model=model):
                        self.assertIn(system, names)

    def test_the_filter_reads_system_names_as_line_mode_does(self):
        for typed, system in (("spruce os", "spruceOS"), ("unofficial os", "UnofficialOS"),
                              ("cross mix", "CrossMix-OS")):
            with self.subTest(typed=typed):
                rows = install.setup_list([], set(), typed, "linux")
                self.assertIn(system, {install._row_name(row) for row in rows})

    def test_android_on_the_filter_names_retroarch(self):
        state, _effects = self.start()
        state.filters["platforms"] = "android"
        self.assertIn("On Android, choose RetroArch", " ".join(_screen_text(state).split()))

    def test_a_wrapped_path_has_no_space_inserted(self):
        """Retroarch/ system."""
        path = "/home/moi/retroarch_system/tmp/tui_audit9/sb/nd/home/.config/retroarch/system"
        for width in range(30, 100):
            lines = install._wrap(f"{path} does not exist.", width)
            # Each line after the first is indented by two spaces.
            joined = lines[0] + "".join(line[2:] for line in lines[1:])
            with self.subTest(width=width):
                self.assertIn(path, joined)
                self.assertTrue(all("/ " not in line for line in lines), lines)

    def test_f1_names_what_the_card_lacks(self):
        """F1 said the refusal again."""
        muos = self.root / "MUOS"
        make_card(muos, "muOS")
        setup = install.card_setup("Onion", "retroarch")
        choice = install._not_the_card(setup, muos, muos, "muOS")
        self.assertIn(".tmp_update", choice.detail)

    def test_help_at_40x12_keeps_quit_and_this_help(self):
        """And Space for ticking on a keyboard."""
        state = checked_state()
        press(state, "down", "down", "down", "down", "enter")
        state.stack.append("systems")
        state.help = True
        text = _screen_text(state, 40, 12)
        self.assertIn("Quit", text)
        self.assertIn("This help", text)
        self.assertIn("X, Space, Right/Left", " ".join(text.split()))

    def test_the_copy_hint_fits_at_40_columns(self):
        """Cut after "copied,". On the CI runner /home
        held three folders, and the list cut the hint: it is kept whole,
        the list scrolling, from a folder of this test's own."""
        home = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, home, True)
        for name in ("linuxbrew", "packer", "runner"):
            (home / name).mkdir()
        state = checked_state()
        state.home = home
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_listed", return_value=[]):
            install._open_from_browser(state)
        self.assertEqual(state.browse_dir, home)
        text = " ".join(_screen_text(state, 40, 12).split())
        self.assertIn("Choose the old card, a backup folder or a ZIP.", text)
        self.assertIn("> Use this folder", text)

    def test_the_miyoo_bar_says_what_a_does(self):
        """A Tick on All and None, where A unticks."""
        state = checked_state()
        state.pad = "miyoo"
        state.stack.append("systems")
        state.focus["systems"] = next(i for i, row in enumerate(install.tui_rows(state))
                                      if row.action == "none")
        bar = install.tui_view(state, 40, 12)[-1]
        self.assertNotIn("A Tick", bar)
        state.focus["systems"] = install._first_item(state)
        self.assertIn("A Tick", install.tui_view(state, 40, 12)[-1])

    def test_system_given_is_said_and_widened(self):
        """One system named, no word on the plan and no
        way to widen it."""
        state = checked_state()
        state.cli_systems = ["gba"]
        state.systems = [row for row in state.systems if row["system"] == "nintendo-gba"]
        state.ticked = {"nintendo-gba"}
        self.assertIn("For 1 of 3 systems (--system).", " ".join(_screen_text(state).split()))
        row = next(row for row in install.tui_rows(state) if row.action == "systems")
        effects = install._activate(state, row)
        self.assertEqual(effects, [("run", "check")])
        self.assertNotIn(("--system", "gba"), install.tui_flags(state))
        self.assertTrue(state.widen)

    def test_a_local_copy_draws_no_speed(self):
        """0 B/s 0:00 left."""
        out = io.StringIO()
        term = install.Terminal(out)
        term.live = True
        progress = install.Progress(2, 100, term)
        progress.add(50, resumed=True, network=False)
        progress._draw()
        self.assertNotIn("B/s", out.getvalue())
        self.assertNotIn("left", out.getvalue())

    def test_the_offline_remedy_follows_the_files_it_is_about(self):
        unplaced = [{"reason": "no_save_directory", "frontend": "RetroArch"}]
        with mock.patch.object(install, "_offline_only", return_value=True), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit):
            install._report_outcome([self.root], 6, 0, 0, 1, False,
                                    omitted_entries=unplaced, offline=16,
                                    sources="6 files copied from OLD, 16 still missing.")
        lines = out.getvalue().splitlines()
        remedy = next(i for i, line in enumerate(lines) if "Copy them" in line
                      or "They are not in" in line)
        missing = next(i for i, line in enumerate(lines) if "still missing" in line)
        save = next(i for i, line in enumerate(lines) if "save directory" in line)
        self.assertEqual(remedy, missing + 1)
        self.assertLess(remedy, save)

    def test_first_install_says_where_to_type(self):
        page = (REPO_ROOT / "wiki" / "first-install.md").read_text(encoding="utf-8")
        self.assertNotIn("There, type its name", page)
        self.assertIn("Press / and type the device", page)

    def test_a_folder_that_cannot_be_created_ends_on_an_error_and_a_summary(self):
        """Cannot create, then end 2 and nothing else."""
        import subprocess  # noqa: PLC0415

        from test_install_offline import PAYLOAD, _offline_env, _pack

        if os.name == "nt" or os.geteuid() == 0:
            self.skipTest("a folder that refuses writes is POSIX, and root writes anyway")
        # A file in the way is refused before the plan, as not_a_folder.
        blocker = self.root / "closed"
        blocker.mkdir()
        pack = _pack(self.root, "RetroArch_v1_BIOS_Pack.zip", PAYLOAD)
        os.chmod(blocker, 0o500)
        try:
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retroarch",
                 "--dest", str(blocker / "system"), "--from-pack", str(pack), "--events"],
                env=_offline_env(), capture_output=True, text=True, timeout=120,
                check=False, stdin=subprocess.DEVNULL)
        finally:
            os.chmod(blocker, 0o700)
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        kinds = [event["event"] for event in events]
        self.assertEqual(kinds[-3:], ["error", "summary", "end"], proc.stderr)
        self.assertEqual((events[-3]["stage"], events[-3]["reason"]), ("dest", "not_writable"))
        self.assertEqual(events[-1]["code"], 2)


class EdgesTheMutantsFound(unittest.TestCase):
    """Changes to the code that every test let through: the survivors of a
    mutmut run over the device filter, the card bounds and the WSL paths."""

    def test_a_folder_below_a_drive_is_named_with_backslashes(self):
        """Only the drive itself was ever shown: D:\\Games/bios passed."""
        for root in ("/mnt", "/mnt/", "/windows", "/drvX/"):
            with self.subTest(root=root), mock.patch.dict(install._WSL,
                                                         {"active": True, "root": root}):
                base = root.rstrip("/")
                self.assertEqual(install.shown_path(Path(f"{base}/d/Games/bios")),
                                 "D:\\Games\\bios")
                self.assertEqual(install.shown_path(Path(f"{base}/e")), "E:\\")

    def test_every_path_option_is_read_through_drvfs(self):
        """--cores-dir G:\\ under WSL stayed a relative path named G:."""
        with mock.patch.dict(install._WSL, {"active": True, "root": "/mnt"}):
            args = _args(dest=Path("D:\\bios"), save_dir=Path("F:\\saves"),
                         cores_dir=Path("G:\\RetroArch\\cores"))
            install._wsl_dest(args)
        self.assertEqual((args.dest, args.save_dir, args.cores_dir),
                         (Path("/mnt/d/bios"), Path("/mnt/f/saves"),
                          Path("/mnt/g/RetroArch/cores")))

    def card(self, system: str) -> Path:
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        make_card(root / "card", system)
        return root / "card"

    def test_a_card_is_looked_for_up_to_its_mount_point_and_no_further(self):
        """Every folder up to the mount point is read:
        three at most took MUOS/a/b/c/d for a KNULLI card."""
        card = self.card("KNULLI")
        setup = install.card_setup("KNULLI", "knulli")
        deep = card / "a" / "b" / "c" / "d"
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install.os.path, "ismount", return_value=False):
            self.assertEqual(install._card_above(setup, deep), ("own", "KNULLI", card))
        mounted = frozenset({str(card / "a")})
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_mount_points", return_value=mounted), \
                mock.patch.object(install.os.path, "ismount", return_value=False):
            self.assertIsNone(install._card_above(setup, deep))

    def test_a_minui_root_is_looked_for_two_folders_up_and_no_further(self):
        card = self.card("MinUI")
        self.assertEqual(install.card_root_above(card / "Bios" / "GBA"), ("minui", card))
        self.assertIsNone(install.card_root_above(card / "Bios" / "GBA" / "x"))
        self.assertIsNone(install.card_root_above(card))

    def test_the_filter_compares_the_letters_alone(self):
        self.assertEqual(install._folded("Pokémon Évolution"), "pokemon evolution")
        self.assertFalse(install._matches("Odroid", "x"))

    def test_a_letter_no_name_holds_finds_nothing(self):
        with mock.patch.dict(install._SETUP_DEVICES, {"batocera": ("Odroid",),
                                                      "Onion": ("Miyoo Mini",)}):
            self.assertIsNone(install._setup_matches("batocera", ["Onion"], "x"))
            self.assertEqual(install._setup_matches("batocera", ["Onion"], "mini"),
                             ["Onion"])
            self.assertEqual(install._setup_matches("batocera", ["Onion"], "odroid"),
                             ["Odroid"])



class CardNamesAndHelp(_CardFixtures, unittest.TestCase):
    """What the cards, the screens and the
    docs answer, line mode's parity being in LineModeAndScreenDecideAlike."""

    def setUp(self):
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        for patcher in (mock.patch.dict(install._DETECTED_OS, {}),
                        mock.patch.object(install, "_mount_points", return_value=frozenset())):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_a_renamed_card_is_named_by_the_file_no_menu_writes(self):
        """A KNULLI card whose hostname was changed in
        its menu was a Batocera SHARE drive, Enter filled it with Batocera's
        list and --platform knulli was refused."""
        drives = self.renamed()
        expected = {
            "KNULLI renamed": ("knulli", "bios", "KNULLI"),
            "KNULLI as shipped": ("knulli", "bios", "KNULLI"),
            "renamed, no about.info": None,
            "Batocera as shipped": ("batocera", "bios", "Batocera"),
            "Batocera, no hostname": ("batocera", "bios", "Batocera"),
            "Recalbox": ("recalbox", "bios", "Recalbox"),
            "two shares": None,
        }
        for name, drive in drives.items():
            with self.subTest(drive=name):
                found = install.card_system(drive)
                want = expected[name]
                self.assertEqual(found, want and (want[0], drive / want[1], want[2]))
                doubt, _why = install.share_doubt(drive)
                self.assertEqual(bool(doubt), want is None)
        self.assertEqual(install.share_doubt(drives["renamed, no about.info"])[0],
                         ("knulli", "batocera"))
        self.assertEqual(install.share_doubt(drives["two shares"])[0],
                         ("batocera", "recalbox"))

    def test_a_share_drive_is_never_called_a_card(self):
        """"is a Batocera card"
        and "is a Recalbox card" for their SHARE drives."""
        drives = self.renamed()
        for name in ("Batocera as shipped", "Recalbox"):
            with self.subTest(drive=name):
                choice = install.card_choice("retroarch", "retroarch", drives[name])
                self.assertIn("SHARE drive, which reads", choice.note)
                self.assertNotIn(" card, which reads", choice.note)

    def test_two_cards_of_one_system_say_what_they_hold(self):
        """An old Onion card with 6 BIOS files and a new
        empty one looked the same, and Enter took the first by name."""
        old = self.root / "media" / "OLDONION"
        make_card(old, "Onion")
        for index in range(6):
            (old / "BIOS" / f"f{index}.bin").write_bytes(b"x")
        new = self.root / "media" / "ONION"
        make_card(new, "Onion")
        shutil.rmtree(new / "BIOS")
        with mock.patch.object(install, "_mounted_cards", return_value=[old, new]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()):
            setups, _mounted = install.found_setups("linux")
        self.assertEqual([label for _plat, _path, label in setups],
                         ["Onion SD card (ONION, no BIOS folder)",
                          "Onion SD card (OLDONION, 6 BIOS files)"])

    # a list or a pack that records some axes only.

    def test_a_card_plan_offers_one_remedy_first(self):
        for facts, locked in (({"free": 50 * 1024 ** 3, "writable": False, "cores": []}, True),
                              ({"free": 10, "writable": True, "cores": []}, False)):
            with self.subTest(locked=locked):
                state = checked_state(facts)
                with mock.patch.object(install, "_on_its_card", return_value=True), \
                        mock.patch.object(install, "_on_read_only_mount", return_value=locked):
                    rows = install.tui_rows(state)
                    text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
                    effects = install.tui_update(state, Key("enter"))
                self.assertEqual(rows[0].action, "recheck")
                self.assertEqual("install" in [row.action for row in rows], not locked)
                self.assertNotIn("choose another one", text)
                self.assertEqual(effects, [("run", "check")])

    def test_options_offer_no_downloads_when_nothing_is_downloaded(self):
        """Parallel downloads offered for an install from a pack."""
        state = checked_state()
        state.stack.append("options")
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: ""}):
            self.assertIn("jobs", [row.action for row in install.tui_rows(state)])
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            self.assertNotIn("jobs", [row.action for row in install.tui_rows(state)])

    def test_nothing_installable_focuses_the_copy(self):
        """Offline with nothing to copy, the plan focused
        Choose systems, whose systems need the internet too."""
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            state = checked_state()
            rows = install.tui_rows(state)
        self.assertEqual(rows[state.focus.get("plan", 0)].action, "fromcard")

    # the screens' polish.

    def test_a_long_message_scrolls_with_its_position(self):
        """At 40x12 the offline screen dropped its remedy unsaid."""
        state = fresh_state()
        state.stack = ["error"]
        state.error_title = install.TUI_OFFLINE_TITLE
        state.error = ["This run makes no network request (--offline), and the list of BIOS "
                       "files comes from the network.",
                       "Run the installer again with the list saved as a file (--manifest "
                       "FILE, a copy of install/<platform>.json) or with a pack (--from-pack "
                       "PACK), or without --offline."]
        state.cols, state.rows = 40, 12
        view = [str(line) for line in install.tui_view(state, 40, 12)]
        self.assertTrue(any(re.fullmatch(r" 1-\d+ of \d+", line) for line in view), view)
        self.assertIn("Scroll", view[-1])
        press(state, "pgdn")
        end = " ".join(" ".join(str(line) for line in install.tui_view(state, 40, 12)).split())
        self.assertIn("--offline.", end)

    def test_a_small_window_says_why_the_questions_come_line_by_line(self):
        with mock.patch.object(install, "tui_blocker",
                               return_value="the terminal is 39x12, smaller than 40x12"), \
                mock.patch.object(install, "_run", side_effect=SystemExit(0)), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.dict(install._WSL), \
                mock.patch.object(sys, "argv", ["install.py"]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit):
            install.main()
        self.assertIn("The window is 39x12: questions come line by line (40x12 for the full "
                      "screen).", out.getvalue())

    def test_one_bar_rule_per_width(self):
        """At 40 columns the plan read "A Install", Confirm "A/Enter"."""
        states = golden_states()
        for name in ("preview", "confirm", "result", "quit"):
            with self.subTest(screen=name):
                bar = str(install.tui_view(states[name], 40, 12)[-1])
                self.assertNotIn("A/Enter", bar)
                self.assertNotIn("B/Esc", bar)

    @in_full
    def test_the_folder_its_config_named_is_said_under_it(self):
        state = checked_state()
        long_dest = Path("/home/user/" + "a-long-folder-name/" * 5 + "system")
        state.dest = long_dest
        with mock.patch.object(install, "_retroarch_config_at",
                               return_value=(HOME / ".config/retroarch/retroarch.cfg", HOME)):
            lines = [str(line).strip() for line in install.tui_view(state, 80, 30)]
        at = next(index for index, line in enumerate(lines) if line.startswith("BIOS folder:"))
        tail = next(index for index, line in enumerate(lines) if line.startswith("Named by"))
        self.assertNotIn("...", " ".join(lines[at:tail]))
        self.assertIn(str(long_dest).replace("/home/user", "~")[-20:], " ".join(lines[at:tail]))
        self.assertLessEqual(tail - at, 3)

    def test_the_help_while_typing_lists_what_does_not_type(self):
        state = checked_state()
        state.stack.append("systems")
        state.editing = "systems"
        state.help = True
        help_text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("Esc Clear the filter", help_text)
        self.assertIn("Ctrl-U Clear", help_text)
        self.assertNotIn("Tick, untick", help_text)

    def test_the_plan_names_core_and_region_as_line_mode(self):
        state = checked_state()
        state.cli_systems, state.cores, state.regions = ["sony-playstation"], ["x"], ["us"]
        state.cli_cores, state.cli_regions = ["x"], ["us"]
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        # The flag after the words, never alone.
        self.assertIn("(--system), 0 of 1 cores (--core), regions ranked (--region).", text)

    def test_pc_and_short_prefixes_find_the_computer_setups(self):
        for typed in ("pc", "wi", "win"):
            with self.subTest(typed=typed):
                found = {row.value for row in install.setup_list([], set(), typed, "linux")
                         if row.action == "platform"}
                self.assertIn("retrobat", found)

    def test_a_partial_result_counts_once_then_says_the_remedy(self):
        state = _installed_state(Path("/x/system"))
        state.summary.update(installed=6, pending=16, failed=[])
        state.from_folders = [Path("/media/me/OLD")]
        with mock.patch.object(install, "_offline_only", return_value=True), \
                mock.patch.object(install, "_tui_sources",
                                  return_value="6 files copied from OLD, 16 still missing."):
            _title, lines = install.tui_outcome(state)
        self.assertEqual(lines[0], "6 files copied from OLD, 16 still missing.")
        self.assertIn("They are not in", lines[1])

    def test_q_is_said_as_a_quit(self):
        """Q reported "stopped", the word of an interrupted run."""
        state = checked_state()
        press(state, "q")
        self.assertEqual(state.exit_code, install.QUIT_CODE)
        self.assertEqual(install._closing_lines(state),
                         ["RetroBIOS: quit. Nothing was installed."])
        other = checked_state()
        install.tui_interrupt(other)
        self.assertEqual(install._closing_lines(other),
                         ["RetroBIOS: stopped. Nothing was installed."])

    def test_wide_rows_keep_the_size_near_the_name(self):
        row = install.TuiRow("system", "[x] 3DO  3do", "2 files, 4.9 KB")
        line = str(install._row_line(row, False, 118))
        self.assertLessEqual(len(line.rstrip()), install.TUI_ROW_SPREAD)

    def test_the_wsl_browser_titles_a_drive_by_its_letter(self):
        state = fresh_state()
        state.stack = ["browse"]
        state.browse_dir = Path("/mnt/e")
        with mock.patch.dict(install._WSL, {"active": True, "root": "/mnt"}), \
                mock.patch.object(install, "_browse_rows", return_value=([], "")):
            state.browse_rows = []
            title = " ".join(str(line) for line in install.tui_view(state, 80, 24)[:4])
        self.assertIn("E:\\", title)
        self.assertNotIn("/mnt/e", title)

    def test_the_card_marker_table_is_written_from_the_rules(self):
        """The table left out the
        SHARE drives. It is generated: every card rule and SHARE drive file
        is a row, about.info among them."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        self.addCleanup(sys.path.remove, str(REPO_ROOT / "scripts"))
        import generate_installer_doc  # noqa: PLC0415

        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        block = page[page.index("<!-- generated: card-markers -->"):
                     page.index("<!-- /generated: card-markers -->")]
        for rule in install._card_rules():
            self.assertIn(f"`{rule.values[0]}", block)
        for _plat, marker in install._SHARE_DRIVES:
            self.assertIn(f"`{marker}`", block)
        self.assertIn(self.ABOUT, block)
        self.assertIn("Recalbox SHARE drive", block)
        self.assertEqual(generate_installer_doc.render(page), page)

class TheAndroidResultReadsWhole(unittest.TestCase):
    """A run on Android 17 under Termux: the result named /sdcard and
    /storage/emulated/0 for one storage, saves/<core> read as a folder named
    <core>, a backup path and the restore command were split inside a word,
    and the game data line named no folder."""

    def setUp(self):
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        for patcher in (mock.patch.dict(install._SPELLED, {}, clear=True),):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_one_storage_is_named_one_way(self):
        real = self.root / "storage" / "emulated" / "0"
        (real / "RetroArch" / "system").mkdir(parents=True)
        link = self.root / "sdcard"
        link.symlink_to(real)
        bios = link / "RetroArch" / "system"
        self.assertEqual(install._destination_path(bios, "a.bin"),
                         real.resolve() / "RetroArch" / "system" / "a.bin")
        kept = install.KeptFiles()
        run = kept.plan(install._kept_slot(bios, "a.bin")[0], 3)
        folder = kept.summary()[0]["folder"]
        self.assertTrue(folder.startswith(str(link / "RetroArch" / "retrobios-backup")),
                        folder)
        self.assertEqual(install.shown_path(run), folder)
        self.assertNotIn(str(real), install.shown_path(real.resolve() / "RetroArch" / "saves"))

    def test_a_folder_per_core_is_said_in_words(self):
        where = "/sdcard/RetroArch/saves/<core>"
        line = install.saves_line("RetroArch", 106, where)
        self.assertEqual(line, "106 files read from RetroArch's save directory go to a "
                               "folder per core under /sdcard/RetroArch/saves")
        self.assertEqual(install.save_where_words("/s/saves/<system>"),
                         ("a folder per system under", "/s/saves"))
        state = checked_state()
        screen = install._saves_lines(state, {"files": 106, "folder": where})
        self.assertNotIn("<core>", " ".join(screen))
        self.assertIn("a folder per core under:", screen[0])

    def result(self, cols: int) -> list:
        state = _installed_state(Path("/sdcard/RetroArch/system"))
        state.summary["kept"] = [{"folder": "/sdcard/RetroArch/retrobios-backup/"
                                            "20261027-223524", "files": 3, "bytes": 10}]
        state.cols, state.rows = cols, 40
        return install.tui_view(state, cols, 40)

    @in_full
    def test_a_path_or_a_command_is_never_split_inside_a_word(self):
        full = "/sdcard/RetroArch/retrobios-backup/20261027-223524"
        for cols in (40, 50, 80):
            with self.subTest(cols=cols):
                lines = [str(line).strip() for line in self.result(cols)]
                words = [word for line in lines for word in line.split()]
                self.assertIn("--restore", words)
                # The command keeps it whole where its line holds it, cut to
                # its last folders and said so where not.
                if cols >= 60:
                    self.assertIn(full, words)
                else:
                    self.assertIn(install.TUI_SHORTENED, lines)
                # Prose breaks it after a separator only, never inside a name:
                # glued again, it is whole.
                self.assertIn(full, re.sub(r"/ ", "/", " ".join(lines)))
                self.assertFalse(any(line.endswith(("retrobios-ba", "20261027-"))
                                     for line in lines), lines)
        state = _installed_state(Path("/sdcard/RetroArch/system"))
        command = install._styled(f"curl -fsSL {install.BOOTSTRAP_URL} | sh -s -- --restore "
                                  "'/storage/emulated/0/a b/20261027-223524'", "command")
        state.stack.append("result")
        pieces = install._text_lines([command], 38, whole=True)
        joined = [str(piece).strip() for piece in pieces if piece.style != "cont"]
        # The address never cut, the option with its value, each line but
        # the last ending with the shell's continuation.
        self.assertIn(f"{install.BOOTSTRAP_URL} \\", joined)
        self.assertTrue(any(line.startswith("--restore '") for line in joined), joined)
        self.assertTrue(all(len(str(piece)) <= 38 for piece in pieces), pieces)

    def test_a_long_line_folds_in_the_terminal(self):
        terminal = install._TuiTerminal.__new__(install._TuiTerminal)
        terminal.frame, written = [], []
        terminal.write = written.append
        long = install._styled("x" * 50, "long")
        terminal.draw([long, install._styled("", "cont"), install._styled("next")], 40)
        out = "".join(written)
        self.assertIn("x" * 50, out)
        self.assertNotIn("\x1b[2;1H", out)
        self.assertIn("\x1b[3;1H", out)

    def test_game_data_names_the_folder_it_goes_in(self):
        entry = {"dest": "jazz2/Source/Anims.j2a", "required": True, "category": "game_data",
                 "system": "jazz-jackrabbit-2"}
        bios = Path("/sdcard/RetroArch/system")
        lines = install._omission_lines(1, [entry], bios)
        said = " ".join(lines)
        self.assertIn(f"into {bios / 'jazz2' / 'Source'}{os.sep}", said)
        # Defined on its own line, never spliced into the sentence naming
        # the file.
        self.assertIn("files a game or a game engine reads", said)
        self.assertEqual([line for line in lines if "game engine reads" in line],
                         ["  Game data: files a game or a game engine reads, of no use to "
                          "the other cores."])
        self.assertNotIn("Needed to start an emulator", said)


MOUSE_SIZES = ((40, 12), (80, 24), (120, 40))


def sgr(col: int, row: int, button: int = 0, release: bool = False) -> str:
    """An SGR mouse report, the cell counted from 1."""
    return f"\x1b[<{button};{col};{row}{'m' if release else 'M'}"


def x10(col: int, row: int, button: int = 0) -> str:
    """A legacy report: 32 plus each value."""
    return "\x1b[M" + "".join(chr(32 + value) for value in (button, col, row))


def drawn(state: install.TuiState, cols: int, rows: int) -> list:
    """The frame as the loop draws it, its targets kept as the loop keeps them."""
    state.cols, state.rows = cols, rows
    lines = install.tui_view(state, cols, rows)
    state.hits = install.tui_hits(state, lines)
    return lines


def settled(state: install.TuiState) -> None:
    """The clock moved on past TUI_TAP_SETTLE since the screen was drawn.
    A millisecond past it: shown + 0.4 - shown is 0.39999 once the clock is
    large, as a CI runner's uptime makes it, and the tap read as too early."""
    if state.hits is not None:
        state.now = max(state.now, state.hits.shown + install.TUI_TAP_SETTLE + 0.001)


def tap(state: install.TuiState, col: int, row: int, button: int = 0) -> list:
    """Press and release on one cell, columns and lines counted from 0, made
    once the screen settled (TUI_TAP_SETTLE): a reader's deliberate tap."""
    settled(state)
    effects = install.tui_update(state, install.TuiMouse(button, col + 1, row + 1))
    return effects + install.tui_update(state, install.TuiMouse(button, col + 1, row + 1,
                                                                True))


class MouseReports(unittest.TestCase):
    """Mouse reports come out of the decoder as reports, never as keys."""

    def feed(self, *chunks: str) -> list:
        decoder = install.KeyDecoder()
        found = []
        for chunk in chunks:
            found += decoder.feed(chunk)
        return found + decoder.flush()

    def test_sgr_press_release_and_wheel(self):
        Mouse = install.TuiMouse
        self.assertEqual(self.feed(sgr(10, 5), sgr(10, 5, release=True)),
                         [Mouse(0, 10, 5), Mouse(0, 10, 5, True)])
        self.assertEqual(self.feed(sgr(3, 4, 64), sgr(3, 4, 65)),
                         [Mouse(64, 3, 4), Mouse(65, 3, 4)])
        self.assertEqual(self.feed(sgr(1, 1, 2)), [Mouse(2, 1, 1)])

    def test_sgr_past_the_legacy_limit(self):
        self.assertEqual(self.feed(sgr(300, 250)), [install.TuiMouse(0, 300, 250)])

    def test_sgr_split_across_reads(self):
        report = sgr(12, 7)
        for cut in range(1, len(report)):
            with self.subTest(cut=cut):
                decoder = install.KeyDecoder()
                found = decoder.feed(report[:cut])
                found += decoder.feed(report[cut:] + "j")
                self.assertEqual(found, [install.TuiMouse(0, 12, 7), Key("char", "j")])

    def test_legacy_reports(self):
        Mouse = install.TuiMouse
        self.assertEqual(self.feed(x10(5, 6), x10(5, 6, 3), x10(5, 6, 64)),
                         [Mouse(0, 5, 6), Mouse(3, 5, 6, True), Mouse(64, 5, 6)])

    def test_legacy_bytes_are_never_keys(self):
        """A position past 95 is a byte UTF-8 replaces: the report is
        dropped, and none of its bytes is read as a key press."""
        for tail in ("�!!", "!�!", " qj"):
            with self.subTest(tail=tail):
                found = self.feed("\x1b[M" + tail, "k")
                self.assertEqual([key for key in found if key.name != "mouse"],
                                 [Key("char", "k")])

    def test_a_cut_report_is_dropped_whole(self):
        self.assertEqual(self.feed("\x1b[<0;10"), [])
        self.assertEqual(self.feed("\x1b[<0;10;1;7M", "j"), [Key("char", "j")])


class MouseEnabled(unittest.TestCase):
    """Clicks are asked for only where they can come and are wanted."""

    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    def blocker(self, env: dict, interactive: bool = True) -> str:
        stream = self.Tty() if interactive else io.StringIO()
        return install.tui_mouse_blocker(stream, stream, env)

    def test_an_xterm_like_terminal_takes_clicks(self):
        for term in ("xterm", "xterm-256color", "screen-256color", "tmux-256color",
                     "alacritty", "foot", "xterm-kitty", "rxvt-unicode-256color"):
            with self.subTest(term=term):
                self.assertEqual(self.blocker({"TERM": term}), "")

    def test_what_keeps_them_off(self):
        for env, interactive in (
                ({"TERM": "linux"}, True), ({"TERM": "dumb"}, True), ({}, True),
                ({"TERM": "vt100"}, True), ({"TERM": "xterm"}, False),
                ({"TERM": "xterm", install.TUI_PAD_ENV: "gptokeyb"}, True),
                ({"TERM": "xterm", install.TUI_MOUSE_ENV: "1"}, True)):
            with self.subTest(env=env, interactive=interactive):
                self.assertNotEqual(self.blocker(env, interactive), "")
        self.assertEqual(self.blocker({"TERM": "xterm", install.TUI_MOUSE_ENV: "0"}), "")

    def test_a_windows_console_reads_no_clicks(self):
        with mock.patch.object(install.os, "name", "nt"):
            self.assertIn("Windows", self.blocker({"TERM": "xterm"}))

    def test_the_terminal_writes_a_change_only(self):
        terminal = install._TuiTerminal.__new__(install._TuiTerminal)
        written = []
        terminal.write = written.append
        terminal.mouse_allowed, terminal.mouse, terminal.entered = True, False, True
        terminal.set_mouse(True)
        terminal.set_mouse(True)
        terminal.set_mouse(False)
        self.assertEqual(written, [install._MOUSE_ON, install._MOUSE_OFF])
        terminal.mouse_allowed = False
        terminal.set_mouse(True)
        self.assertEqual(len(written), 2)

    def test_modes_asked_for(self):
        self.assertEqual(install._MOUSE_ON, "\x1b[?1000h\x1b[?1006h")
        self.assertIn(install._MOUSE_OFF, install._SCREEN_OFF)
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        for mode in ("1002h", "1003h", "1005h", "1015h"):
            self.assertNotIn("?" + mode, source)

    def test_the_text_to_copy_keeps_the_terminal_selection(self):
        states = golden_states()
        for name in ("command", "path"):
            with self.subTest(screen=name):
                state = states[name]
                self.assertFalse(install.tui_wants_mouse(state, drawn(state, 80, 24)))
        # The result takes a tap on its Exit: its text is printed again in
        # the terminal once it closes, selected there as anywhere.
        for name in ("setup", "platforms", "plan", "systems", "options", "error", "quit",
                     "result"):
            with self.subTest(screen=name):
                state = states[name]
                self.assertTrue(install.tui_wants_mouse(state, drawn(state, 80, 24)))

    def test_a_plan_naming_a_command_keeps_the_selection(self):
        state = checked_state({"free": 50 * 1024 ** 3, "writable": False,
                               "cores": ["pcsx_rearmed"]})
        with mock.patch.object(install, "_on_read_only_mount", return_value=False):
            lines = drawn(state, 120, 40)
            self.assertIn("install.py", " ".join(lines))
            self.assertFalse(install.tui_wants_mouse(state, lines))

    def test_the_view_adds_no_text(self):
        """A frame drawn with its targets is the frame drawn without them."""
        patcher = mock.patch.object(install, "_mounted_cards", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)
        for name, state in golden_states().items():
            for cols, rows in MOUSE_SIZES:
                with self.subTest(screen=name, size=f"{cols}x{rows}"):
                    path = GOLDEN / f"{name}-{cols}x{rows}.txt"
                    if not path.exists():
                        continue
                    lines = drawn(state, cols, rows)
                    text = "\n".join(line.rstrip() for line in lines) + "\n"
                    self.assertEqual(text, path.read_text(encoding="utf-8"))


class MouseOnEveryScreen(unittest.TestCase):
    """A tap does on each screen what its key does, at each size."""

    def setUp(self):
        patcher = mock.patch.object(install, "_mounted_cards", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def twin(state: install.TuiState) -> install.TuiState:
        import copy  # noqa: PLC0415

        return copy.deepcopy(state)

    def test_rows_and_bar_buttons(self):
        checked = 0
        for name, base in golden_states().items():
            for cols, rows in MOUSE_SIZES:
                lines = drawn(base, cols, rows)
                hits = base.hits
                for line, first, end, target in hits.targets:
                    with self.subTest(screen=name, size=f"{cols}x{rows}", target=target):
                        state, keyed = self.twin(base), self.twin(base)
                        if target[0] == "row":
                            index = target[1]
                            row_list = install.tui_rows(state)
                            focus = max(0, min(state.focus.get(state.screen, 0),
                                               len(row_list) - 1))
                            self.assertEqual(lines[line].style == "focus", index == focus)
                            # The whole width, the text's end or not.
                            effects = tap(state, cols - 1, line)
                            if row_list[index].action in install.TUI_TICK_ROWS:
                                # A tick is ticked as Space ticks it, focus
                                # moved there first.
                                keyed.focus[keyed.screen] = index
                                self.assertEqual(effects,
                                                 install.tui_update(keyed, Key("char", " ")))
                                self.assertEqual((state.stack, state.ticked),
                                                 (keyed.stack, keyed.ticked))
                                continue
                            # A choice is focused by the first tap, even the
                            # row the screen opened on.
                            self.assertEqual(effects, [])
                            self.assertEqual(state.focus[state.screen], index)
                            self.assertEqual(state.stack, base.stack)
                            drawn(state, cols, rows)
                            again = next(at for at, _first, _end, mark in state.hits.targets
                                         if mark == target)
                            keyed.focus[keyed.screen] = index
                            self.assertEqual(tap(state, cols - 1, again),
                                             install.tui_update(keyed, Key("enter")))
                            self.assertEqual(state.stack, keyed.stack)
                        elif target[0] == "key":
                            label = str(lines[line])[first:end].split(" ", 1)[0]
                            self.assertIn(label, install._BAR_CLICKS)
                            effects = tap(state, first, line)
                            if install._bar_commits(base, target[1]):
                                # Install on the plan and Put it on the card:
                                # the first tap arms the entry, drawn so, the
                                # second on the same entry presses it.
                                self.assertEqual(effects, [])
                                self.assertEqual(state.stack, base.stack)
                                again = drawn(state, cols, rows)
                                self.assertIn(install.TUI_ARMED_SHORT, str(again[-1]))
                                at = next(first for row, first, _end, mark in state.hits.targets
                                          if mark == target)
                                effects = tap(state, at, line)
                            self.assertEqual(effects, install.tui_update(keyed, target[1]))
                            self.assertEqual((state.stack, state.help),
                                             (keyed.stack, keyed.help))
                        checked += 1
        self.assertGreater(checked, 200)

    def test_two_taps_activate_a_row(self):
        state = fresh_state()
        lines = drawn(state, 80, 24)
        another = next(index for index, line in enumerate(lines)
                       if "Choose another" in line or "another" in line.lower())
        self.assertEqual(tap(state, 30, another), [])
        self.assertEqual(state.screen, "setup")
        drawn(state, 80, 24)
        tap(state, 30, another)
        self.assertEqual(state.screen, "platforms")

    def test_release_acts_not_press(self):
        state = fresh_state()
        lines = drawn(state, 80, 24)
        row = next(i for i, line in enumerate(lines) if line.style != "focus"
                   and getattr(line, "mark", None) and line.mark[0] == "row")
        settled(state)
        install.tui_update(state, install.TuiMouse(0, 5, row + 1))
        self.assertIsNotNone(state.pressed)
        self.assertEqual(state.focus.get("setup", 0), 0)
        # Released on another row: a swipe, which does nothing.
        focused = next(i for i, line in enumerate(lines) if line.style == "focus")
        install.tui_update(state, install.TuiMouse(0, 5, focused + 1, True))
        self.assertEqual(state.focus.get("setup", 0), 0)
        self.assertIsNone(state.pressed)
        # A release with no press before it does nothing either.
        install.tui_update(state, install.TuiMouse(0, 5, row + 1, True))
        self.assertEqual(state.focus.get("setup", 0), 0)

    def test_legacy_release_names_no_button(self):
        state = fresh_state()
        lines = drawn(state, 80, 24)
        row = next(i for i, line in enumerate(lines) if line.style != "focus"
                   and getattr(line, "mark", None) and line.mark[0] == "row")
        decoder = install.KeyDecoder()
        settled(state)
        for event in decoder.feed(x10(5, row + 1) + x10(5, row + 1, 3)):
            install.tui_update(state, event)
        self.assertEqual(state.focus["setup"], lines[row].mark[1])

    def test_right_middle_and_modified_clicks_do_nothing(self):
        for button in (1, 2, 4, 8, 16, 32):
            with self.subTest(button=button):
                state = fresh_state()
                lines = drawn(state, 80, 24)
                row = next(i for i, line in enumerate(lines) if line.style != "focus"
                           and getattr(line, "mark", None) and line.mark[0] == "row")
                self.assertEqual(tap(state, 5, row, button), [])
                self.assertEqual(state.focus.get("setup", 0), 0)

    def test_a_click_on_another_frame_does_nothing(self):
        """Read against the frame on screen when it came: Enter, typed in
        the same read, opened the next screen before the click was read."""
        state = fresh_state()
        lines = drawn(state, 80, 24)
        row = next(i for i, line in enumerate(lines) if line.style != "focus"
                   and getattr(line, "mark", None) and line.mark[0] == "row")
        install.tui_update(state, Key("char", "?"))
        self.assertEqual(tap(state, 5, row), [])
        self.assertTrue(state.help)
        state = fresh_state()
        drawn(state, 80, 24)
        state.stack.append("platforms")
        self.assertEqual(tap(state, 5, row), [])
        self.assertEqual(state.focus.get("platforms", 0), 0)
        # The same screen with its rows changed under the frame.
        state = fresh_state()
        drawn(state, 80, 24)
        state.setups = state.setups[1:]
        tap(state, 5, row)
        self.assertEqual(state.focus.get("setup", 0), 0)
        # A frame of another size.
        state = fresh_state()
        drawn(state, 80, 24)
        state.cols = 100
        self.assertEqual(tap(state, 5, row), [])
        self.assertEqual(state.focus.get("setup", 0), 0)

    def test_a_tap_closes_the_help(self):
        state = golden_states()["help"]
        drawn(state, 80, 24)
        tap(state, 3, 5)
        self.assertFalse(state.help)

    def long_list(self, cols: int = 40, rows: int = 12) -> install.TuiState:
        state = fresh_state()
        state.stack = ["setup", "platforms"]
        drawn(state, cols, rows)
        self.assertIsNotNone(state.hits.listing)
        return state

    def test_the_wheel_scrolls_a_list_and_keeps_the_focus_in_view(self):
        for cols, rows in MOUSE_SIZES[:2]:
            with self.subTest(size=f"{cols}x{rows}"):
                state = self.long_list(cols, rows)
                first, shown, total = state.hits.listing
                self.assertEqual(state.focus.get("platforms", 0), 0)
                install.tui_update(state, install.TuiMouse(65, 5, 4))
                lines = drawn(state, cols, rows)
                newfirst, _shown, _total = state.hits.listing
                self.assertEqual(newfirst, first + install.TUI_WHEEL_LINES)
                # Out of view, the focus came to the first row in view.
                self.assertEqual(state.focus["platforms"], newfirst)
                focused = [line.mark[1] for line in lines if line.style == "focus"]
                self.assertEqual(focused, [newfirst])
                # Down again: the row in focus is still in view, and stays.
                state.focus["platforms"] = newfirst + shown - 1
                drawn(state, cols, rows)
                install.tui_update(state, install.TuiMouse(64, 5, 4))
                drawn(state, cols, rows)
                self.assertEqual(state.hits.listing[0], first)
                self.assertEqual(state.focus["platforms"], first + shown - 1)
                # To the end and no further.
                for _notch in range(total):
                    install.tui_update(state, install.TuiMouse(65, 5, 4))
                    drawn(state, cols, rows)
                self.assertEqual(state.hits.listing[0], total - shown)
                # A key afterwards moves the focus from where the wheel put it.
                at = state.focus["platforms"]
                install.tui_update(state, Key("down"))
                self.assertEqual(state.focus["platforms"], at + 1)

    def test_the_wheel_scrolls_a_text(self):
        state = golden_states()["preview"]
        state.dry_files = [{**FILES[0], "dest": f"file{n}.bin"} for n in range(40)]
        drawn(state, 40, 12)
        self.assertEqual(state.hits.scroll, "pager")
        install.tui_update(state, install.TuiMouse(65, 5, 4))
        self.assertEqual(state.focus["preview"], install.TUI_WHEEL_LINES)
        install.tui_update(state, install.TuiMouse(64, 5, 4))
        self.assertEqual(state.focus["preview"], 0)
        install.tui_update(state, install.TuiMouse(64, 5, 4))
        self.assertEqual(state.focus["preview"], 0)

    def test_the_wheel_scrolls_a_long_message(self):
        state = golden_states()["error"]
        state.error = [f"Line {n} of a long message." for n in range(30)]
        drawn(state, 40, 12)
        self.assertEqual(state.hits.scroll, "error")
        focus = state.focus.get("error", 0)
        install.tui_update(state, install.TuiMouse(65, 5, 4))
        self.assertEqual(state.focus["error_text"], install.TUI_WHEEL_LINES)
        self.assertEqual(state.focus.get("error", 0), focus)

    def test_a_tap_on_the_count_shows_the_next_page(self):
        state = self.long_list()
        lines = drawn(state, 40, 12)
        where = next(i for i, line in enumerate(lines)
                     if getattr(line, "mark", None) and line.mark[0] == "scroll")
        before = state.hits.listing[0]
        tap(state, 2, where)
        drawn(state, 40, 12)
        self.assertGreater(state.hits.listing[0], before)
        last = len(install.tui_rows(state)) - 1
        for _page in range(40):
            if state.focus["platforms"] == last:
                break
            tap(state, 2, where)
            drawn(state, 40, 12)
        self.assertEqual(state.focus["platforms"], last)
        # From the last page it goes back to the first.
        tap(state, 2, where)
        drawn(state, 40, 12)
        self.assertEqual((state.focus["platforms"], state.hits.listing[0]), (0, 0))

    def test_a_tap_on_a_row_ends_the_typing_of_a_filter(self):
        state = self.long_list(80, 24)
        install.tui_update(state, Key("char", "/"))
        install.tui_update(state, Key("char", "r"))
        lines = drawn(state, 80, 24)
        row = next(i for i, line in enumerate(lines) if line.style != "focus"
                   and getattr(line, "mark", None) and line.mark[0] == "row"
                   and line.mark[2][0] == "platform")
        tap(state, 5, row)
        self.assertEqual(state.editing, "")
        self.assertEqual(state.focus["platforms"], lines[row].mark[1])
        self.assertEqual(state.filters["platforms"], "r")


@unittest.skipUnless(pyte and pty and hasattr(pty, "fork"),
                     "screen tests need pyte (pip install pyte==0.8.2) and a pty")
class MouseOnAPty(unittest.TestCase):
    """The real install.py --tui, clicked through a pseudo-terminal."""

    repo = EndToEnd.repo
    start = EndToEnd.start

    @staticmethod
    def line_of(term: Pty, needle: str) -> int:
        return next(index for index, line in enumerate(term.screen.display) if needle in line)

    def click(self, term: Pty, col: int, row: int) -> None:
        # A deliberate tap, after the screen settled: a press sooner is the
        # second of a double tap on the screen before.
        time.sleep(install.TUI_TAP_SETTLE)
        term.send(sgr(col + 1, row + 1), sgr(col + 1, row + 1, release=True))

    def test_taps_choose_a_row_and_press_the_bar(self):
        self.repo()
        term = self.start()
        term.wait("Where to install?")
        term.settle()
        self.assertIn(install._MOUSE_ON.encode(), term.raw)
        row = self.line_of(term, "Another setup")
        self.click(term, 60, row)
        term.settle()
        self.assertTrue(term.screen.buffer[row][3].reverse, term.text())
        self.assertIn("Where to install?", term.text())
        self.click(term, 60, row)
        term.wait("Which setup?")
        # The bar's ? Help, pressed by a click.
        bar = term.screen.display[-1]
        self.click(term, bar.index("? Help") + 1, len(term.screen.display) - 1)
        term.wait("Any key or a tap closes this help")
        self.click(term, 10, 5)
        term.wait("Which setup?")
        # Legacy reports move the focus the same way.
        row = self.line_of(term, " > ") + 2
        time.sleep(install.TUI_TAP_SETTLE)
        term.send(x10(20, row + 1), x10(20, row + 1, 3))
        term.settle()
        self.assertTrue(term.screen.buffer[row][3].reverse, term.text())
        term.send("q")
        self.assertEqual(term.close(), install.QUIT_CODE)
        raw = term.raw
        self.assertGreater(raw.rfind(b"\x1b[?1000l"), raw.rfind(b"\x1b[?1000h"))

    def test_no_clicks_asked_when_turned_off(self):
        for name, value in ((install.TUI_MOUSE_ENV, "1"), (install.TUI_PAD_ENV, "gptokeyb")):
            with self.subTest(env=name):
                self.repo()
                self.env[name] = value
                term = self.start()
                term.wait("RetroBIOS")
                term.settle()
                term.send("\x03")
                term.close()
                self.assertNotIn(b"\x1b[?1000h", term.raw)

    def test_line_mode_asks_for_no_clicks(self):
        self.repo()
        term = self.start("--plain")
        term.settle(quiet=1.0)
        term.send("\x03")
        term.close()
        self.assertNotIn(b"\x1b[?1000h", term.raw)
        self.assertNotIn(b"\x1b[?1006h", term.raw)

    def test_a_crash_gives_the_clicks_back(self):
        """The crash path ends in _tui_cleanup, as every other way out."""
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        given = open(slave, encoding="utf-8", closefd=False)  # noqa: SIM115
        shown = open(slave, "w", encoding="utf-8", closefd=False)  # noqa: SIM115
        self.addCleanup(given.close)
        self.addCleanup(shown.close)
        terminal = install._TuiTerminal(given, shown)
        terminal.mouse_allowed = True
        terminal.enter()
        terminal.set_mouse(True)
        problems = install._tui_cleanup(terminal, [], {}, fresh_state())
        self.assertEqual(problems, [])
        raw = b""
        while select.select([master], [], [], 0.2)[0]:
            raw += os.read(master, 65536)
        for mode in (b"1000", b"1006"):
            self.assertGreater(raw.rfind(b"\x1b[?" + mode + b"l"),
                               raw.rfind(b"\x1b[?" + mode + b"h"))


def _painted_roles(text: str, style: str = "", colour: bool = True) -> list[tuple[str, str]]:
    """(characters, SGR parameters) of each run tui_paint draws for text,
    the parameters "" where the terminal's own colours are used."""
    out = install.tui_paint(text, style, colour)
    runs: list[tuple[str, str]] = []
    current = ""
    for part in re.split(r"(\x1b\[[0-9;]*m)", out):
        if part.startswith("\x1b["):
            codes = part[2:-1]
            current = "" if codes in ("0", "") else codes[2:] if codes.startswith("0;") else codes
        elif part:
            runs.append((part, current))
    return runs


def _role_of(text: str, word: str, style: str = "", colour: bool = True) -> str:
    """The SGR parameters word is drawn in, inside text."""
    at = text.index(word)
    seen = 0
    for chars, codes in _painted_roles(text, style, colour):
        if seen <= at < seen + len(chars):
            return codes
        seen += len(chars)
    raise AssertionError(f"{word!r} not drawn in {text!r}")


def _game_state() -> install.TuiState:
    """The plan of checked_state, its PlayStation extra marked game data and
    read from the save directory, the check's events fed in."""
    state = checked_state()
    manifest = json.loads(json.dumps(state.manifest))
    for entry in manifest["files"]:
        if entry["dest"] == "pcsx/extra.bin":
            entry.update(category="game_data", root="save")
    manifest["save_directory"] = {"folder": "saves", "by_core": True}
    state.manifest = manifest
    state.saves = {"event": "saves", "files": 1, "folder": "/home/user/.config/retroarch/saves"}
    return state


class TapsGameDataAndExitCodes(_CardFixtures, unittest.TestCase):
    """What the screens answer, line mode's
    parity being in LineModeAndScreenDecideAlike."""

    def setUp(self):
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        for patcher in (mock.patch.dict(install._DETECTED_OS, {}),
                        mock.patch.object(install, "_mount_points", return_value=frozenset())):
            patcher.start()
            self.addCleanup(patcher.stop)

    # Root cause 1: a tap follows the row's kind.

    def systems_state(self) -> install.TuiState:
        state = checked_state()
        state.mouse = True
        rows = install.tui_rows(state)
        state.focus["plan"] = next(i for i, row in enumerate(rows) if row.action == "systems")
        install.tui_update(state, Key("enter"))
        self.assertEqual(state.screen, "systems")
        return state

    @staticmethod
    def line_of(state: install.TuiState, action: str, value: object = None) -> int:
        return next(at for at, _first, _end, mark in state.hits.targets
                    if mark[0] == "row" and mark[2][0] == action
                    and (value is None or mark[2][1] == value))

    def test_a_tap_on_a_system_ticks_it_and_never_continues(self):
        """Two taps on a system opened Confirm, and the
        next tap installed every file, the system meant to be left out with
        them."""
        for cols, rows in ((40, 12), (80, 24)):
            with self.subTest(size=f"{cols}x{rows}"):
                state = self.systems_state()
                before = set(state.ticked)
                drawn(state, cols, rows)
                line = self.line_of(state, "system", "sony-playstation")
                effects = tap(state, 10, line)
                self.assertEqual(effects, [])
                self.assertNotIn("sony-playstation", state.ticked)
                drawn(state, cols, rows)
                effects = tap(state, 10, self.line_of(state, "system", "sony-playstation"))
                self.assertEqual((effects, state.screen), ([], "systems"))
                self.assertEqual(state.ticked, before)
                drawn(state, cols, rows)
                effects = tap(state, 10, self.line_of(state, "system", "nintendo-gba"))
                self.assertEqual((effects, state.screen), ([], "systems"))
                self.assertNotIn("nintendo-gba", state.ticked)

    def test_the_row_a_screen_opens_on_takes_two_taps(self):
        """Confirm opens with Install in focus: one tap there installed."""
        state = checked_state()
        state.mouse = True
        state.stack.append("confirm")
        state.dry = dict(state.check)
        drawn(state, 80, 24)
        line = self.line_of(state, "install")
        self.assertEqual(tap(state, 5, line), [])
        self.assertEqual(state.screen, "confirm")
        drawn(state, 80, 24)
        self.assertEqual(tap(state, 5, line), [("run", "install")])
        # A key between the taps: the next tap focuses again.
        state = checked_state()
        state.stack.append("confirm")
        state.dry = dict(state.check)
        drawn(state, 80, 24)
        tap(state, 5, line)
        install.tui_update(state, Key("down"))
        install.tui_update(state, Key("up"))
        drawn(state, 80, 24)
        self.assertEqual(tap(state, 5, line), [])

    def test_the_help_and_the_bar_say_how_to_tap(self):
        state = self.systems_state()
        bar = str(install.tui_view(state, 80, 24)[-1])
        self.assertIn("A/Enter/tap Tick", bar)
        state.help = True
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("Tap Tick or untick a row, as A", text)
        self.assertIn("Any key or a tap closes this help", text)
        plan = checked_state()
        plan.mouse, plan.help = True, True
        text = " ".join(" ".join(install.tui_view(plan, 80, 24)).split())
        self.assertIn("Tap A row or Install: click or tap twice", text)
        # The tick entry of the bar is pressed by a tap too.
        state.help = False
        lines = drawn(state, 80, 24)
        bar_line = str(lines[-1])
        state.focus["systems"] = next(i for i, row in enumerate(install.tui_rows(state))
                                      if row.action == "system")
        drawn(state, 80, 24)
        ticked = set(state.ticked)
        tap(state, bar_line.index("A/Enter/tap"), len(lines) - 1)
        self.assertNotEqual(state.ticked, ticked)
        # No mouse, no word of a tap.
        plain = checked_state()
        plain.help = True
        self.assertNotIn("Tap", " ".join(install.tui_view(plain, 80, 24)))

    @in_full
    def test_the_result_is_left_by_a_tap(self):
        """The result gave the mouse back, and on Termux
        leaving it took the keyboard. A tap on its Exit closes it, and its
        commands are printed again in the terminal."""
        state = _installed_state(SYSTEM_DIR)
        lines = drawn(state, 80, 24)
        self.assertTrue(install.tui_wants_mouse(state, lines))
        bar = str(lines[-1])
        effects = tap(state, bar.index("Exit"), len(lines) - 1)
        self.assertEqual((effects, state.exit_code), ([], 0))
        farewell = "\n".join(install.tui_farewell(state))
        self.assertIn("Same choice without questions:", farewell)
        self.assertIn("python3 install.py --platform retroarch", farewell)

    # Root cause 2: one narrowed list drives every count.

    @in_full
    def test_the_game_data_row_and_the_save_line_follow_the_choice(self):
        """With only the GBA ticked, the plan said 1 game
        data file and a save file of the PlayStation."""
        state = _game_state()
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertIn("Game data: kept", text)
        self.assertIn("1 file read from RetroArch's save directory", text)
        state.ticked = {"nintendo-gba"}
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertNotIn("Game data:", text)
        self.assertNotIn("save directory", text)
        self.assertIn("About 1 file, 16.0 KB, for 1 of 3 systems", text)
        # Toggled, the row counts the same game data, left out.
        state = _game_state()
        row = next(row for row in install.tui_rows(state) if row.action == "gamedata")
        self.assertEqual((row.label, row.right), ("Game data: kept", "1 file, 4 B"))
        state.no_game_data = True
        row = next(row for row in install.tui_rows(state) if row.action == "gamedata")
        self.assertEqual((row.label, row.right), ("Game data: left out", "1 file, 4 B"))
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertIn("1 game data file left out.", text)
        self.assertNotIn("No game data", text)

    def test_the_game_data_row_keeps_its_state_at_40_columns(self):
        """"kept," then "left o" at 40x12."""
        state = _game_state()
        state.manifest["files"] += [
            {"dest": f"game/{index}.dat", "size": 50 * 1024 ** 2, "category": "game_data",
             "systems": ["sony-playstation"], "cores": None} for index in range(50)]
        for left in (False, True):
            state.no_game_data = left
            state.checked_dests |= {f"game/{index}.dat" for index in range(50)}
            row = next(row for row in install.tui_rows(state) if row.action == "gamedata")
            line = str(install._row_line(row, False, 38))
            word = "left out" if left else "kept"
            self.assertRegex(line, rf"^  Game data: {word} +51(, | files, )2\.4 GB$")

    @in_full
    def test_data_files_are_named_apart(self):
        """Data files beside BIOS files and game data, the
        parts adding up to the count above, each kind said once."""
        state = _game_state()
        state.check = {**state.check, "data_missing": 7, "data_bytes": 2048}
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertIn("3 BIOS files (1.0 MB), 1 game data file (4 B) and 7 data files "
                      "(2.0 KB).", text)
        self.assertIn("Game data: files a game or a game engine reads, of no use to the "
                      "other cores. Data files: the files an emulator reads from a data "
                      "folder of its own, such as Dolphin's Sys and PPSSPP's assets.", text)

    @in_full
    def test_confirm_counts_the_kinds_apart(self):
        """Extra criteria: the plan split BIOS files and game
        data, Confirm did not."""
        state = _game_state()
        state.stack.append("confirm")
        state.dry = dict(state.check)
        state.dry_files = list(state.files)
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertIn("3 BIOS files (1.0 MB) and 1 game data file (4 B).", text)

    def test_no_game_data_given_has_no_row(self):
        """--no-game-data given, the screen offered the
        game data back, line mode did not."""
        state = _game_state()
        state.no_game_data = state.cli_no_game_data = True
        self.assertFalse(any(row.action == "gamedata" for row in install.tui_rows(state)))
        options = install._option_rows(state)
        self.assertIn("Game data: left out", [row.label for row in options])

    def test_the_40_column_plan_keeps_its_folder(self):
        """At 40x12 and 40x15 the game data definition
        pushed the BIOS folder off the plan."""
        state = _game_state()
        for rows in (12, 15):
            with self.subTest(rows=rows):
                text = "\n".join(install.tui_view(state, 40, rows))
                self.assertIn("BIOS folder:", text)

    # Root cause 3: the version note.

    def test_the_version_note_is_on_the_plan_the_result_and_the_farewell(self):
        """Line mode said it, the
        screen dropped the version event."""
        said = ("This list was built for RetroBat 8.3.1, this machine runs 8.2.0.1. "
                "RetroBat's own BIOS check reads the list of the version it runs, and "
                "may show some files as not matching it.")
        state = fresh_state()
        state.stack = ["setup"]
        with mock.patch.object(install.Path, "exists", return_value=True):
            install.tui_update(state, Key("enter"))
        install.tui_receive(state, ("manifest", "retroarch", MANIFEST))
        for event in [{"event": "version", "platform": "retroarch", "list_version": "8.3.1",
                       "installed_version": "8.2.0.1", "message": said},
                      *FILES, *SYSTEMS, CHECK]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={
                "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
            install.tui_receive(state, ("ended", state.run_id, 1, []))
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertIn(said, text)
        result = _installed_state(SYSTEM_DIR)
        result.version = state.version
        self.assertIn(said, install.tui_outcome(result)[1])
        self.assertIn(said, install.tui_farewell(result))
        plain = checked_state()
        self.assertNotIn("This list was built", " ".join(install.tui_view(plain, 120, 40)))

    # Root cause 4: the commands the screen prints.

    def test_a_command_shown_keeps_offline_from_the_variable(self):
        """Sudo resets the environment, and the root
        command the screen gave fetched what the offline run left out."""
        state = checked_state({"free": 50 * 1024 ** 3, "writable": False, "cores": []})
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
                mock.patch.object(install, "_on_read_only_mount", return_value=False):
            text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
            self.assertRegex(text, r"sudo python3 install\.py --platform retroarch .*--offline")
            self.assertTrue(install.tui_command(state).endswith("--offline"))
            argv = install.tui_argv(state, "check", "python3", "install.py")
            self.assertLessEqual(argv.count("--offline"), 1)
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "--offline"}):
            self.assertEqual(install.tui_command(state).count("--offline"), 1)

    # Root cause 5: a chosen quit.

    def test_a_chosen_quit_exits_2_and_ctrl_c_130(self):
        """Q and Quit ended on 130, Ctrl-C's code."""
        for keys, code in ((["q"], 2), (["esc", "enter"], 2), (["ctrl-c"], 130),
                           (["ctrl-d"], 130)):
            with self.subTest(keys=keys):
                state = fresh_state()
                state.stack = ["setup"]
                for key in keys:
                    install.tui_update(state, Key("char", key) if len(key) == 1 else Key(key))
                self.assertEqual(state.exit_code, code)
        state = checked_state()
        rows = install.tui_rows(state)
        state.focus["plan"] = next(i for i, row in enumerate(rows) if row.action == "quit")
        install.tui_update(state, Key("enter"))
        self.assertEqual(state.exit_code, 2)
        self.assertTrue(install.tui_quit_chosen(state))
        self.assertEqual(install.tui_farewell(state), ["RetroBIOS: quit. Nothing was installed."])
        idle = fresh_state()
        self.assertEqual(install.tui_idle_code(idle), 2)

    # Root cause 6: paths and commands kept whole.

    def test_a_wrapped_command_still_keeps_the_mouse_off(self):
        """The one-liner's URL wrapped in its middle, the
        launcher was not found in the joined text and the mouse stayed on."""
        state = checked_state({"free": 50 * 1024 ** 3, "writable": False, "cores": []})
        for bootstrap in ("sh", ""):
            for cols in (40, 60, 80):
                with self.subTest(bootstrap=bootstrap, cols=cols), \
                        mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": bootstrap}), \
                        mock.patch.object(install, "_on_read_only_mount", return_value=False):
                    lines = drawn(state, cols, 30)
                    self.assertFalse(install.tui_wants_mouse(state, lines))
                    if bootstrap:
                        url = install.BOOTSTRAP_URL
                        words = [word for line in lines for word in str(line).split()]
                        self.assertIn(url, words)

    def test_a_path_one_cell_too_wide_for_its_indent_loses_it(self):
        """"syste" / "m", folded by the terminal."""
        path = "/home/moi/abcdefghijklmnopqrstuvw/.config/retroarch/system"
        width = len(path) + 1
        lines = install._wrap(f"BIOS folder: {path}", width, whole="text")
        # Broken after a separator, the rest at the one indent of every
        # folder line: never inside a name.
        self.assertEqual(lines, ["BIOS folder: /home/moi/abcdefghijklmnopqrstuvw/.config/",
                                 "  retroarch/system"])
        # A command keeps the option with its value, the path whole where
        # the line holds them.
        command = install._wrap(f"  python3 install.py --dest {path}", width + 10,
                                whole="command")
        self.assertIn(f"    --dest {path}", command)
        self.assertTrue(all(len(line) <= width + 10 for line in command), command)

    def test_the_result_spells_each_folder_one_way(self):
        """The save folder as ~/ beside full paths."""
        state = _installed_state(SYSTEM_DIR)
        state.done_saves = {"event": "saves", "files": 2,
                            "folder": "/home/user/.config/retroarch/saves/<core>"}
        _title, lines = install.tui_outcome(state)
        self.assertIn("/home/user/.config/retroarch/saves", [line.strip() for line in lines])
        self.assertFalse(any(line.startswith("~") for line in lines))

    def test_minui_names_the_folder_of_its_plan(self):
        """Plan Bios, result the card's root."""
        card = self.root / "MINUI"
        state = _installed_state(card)
        state.platform = "minui"
        state.manifest = {"manifest_version": 2, "platform": "minui",
                          "files": [{"dest": "Bios/MGBA/gba_bios.bin", "size": 3},
                                    {"dest": "Bios/PS/scph5501.bin", "size": 3}]}
        _title, lines = install.tui_outcome(state)
        self.assertIn(f"BIOS folder: {card / 'Bios'}", lines)
        state.stack = ["checking"]
        self.assertIn(str(card / "Bios"), screen_text(install.tui_view(state, 120, 40)))

    # Root cause 7: colour roles read the words.

    def test_each_painted_span_of_the_plan_has_its_role(self):
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            title = "3 files need the internet, which RETROBIOS_INSTALL_OFFLINE=1 does not use"
            self.assertEqual(_role_of(title, "=1", "title")[-2:], "1")
            self.assertNotIn("35", _role_of(title, "1 does", "title"))
            self.assertIn("35", _role_of(title, "3 files", "title"))
        first = checked_state()
        first.check = {**first.check, "present": 0, "wrong_hash": 0, "missing": 4}
        line = next(line for line in install._plan_lines(first.check, first.dest, first)
                    if str(line).startswith("0 in place"))
        self.assertEqual(_role_of(str(line), "4 missing", line.style), "")
        later = checked_state()
        line = next(line for line in install._plan_lines(later.check, later.dest, later)
                    if str(line).startswith("1 in place"))
        self.assertEqual(_role_of(str(line), "3 missing", getattr(line, "style", "")), "33")
        option = "BIOS folder: ~/.config/retroarch/system   --dest"
        self.assertEqual(_role_of(option, "~/.config"), "1")
        self.assertEqual(_role_of(option, "--dest"), "")

    def test_each_painted_span_of_the_result_has_its_role(self):
        self.assertEqual(_role_of("6 files copied from OLD, 16 still missing.",
                                  "6 files copied", "title"), "1;32")
        self.assertEqual(_role_of("6 files copied from OLD, 16 still missing.",
                                  "16 still missing", "title"), "1;33")
        self.assertEqual(_role_of("6 game data files left out.", "left out"), "")
        self.assertEqual(_role_of("23 files installed.", "23 files installed", "title"),
                         "1;32")

    def test_nothing_a_beginner_looks_for_is_faint(self):
        """The filter row and Back, Quit on the bar."""
        state = install.TuiState(os_type="linux", home=HOME)
        state.stack = ["platforms"]
        self.assertEqual(install._filter_row(state).style, "")
        bar = " A/Enter Choose  B/Esc Quit  / Filter  ? Help"
        for colour in (True, False):
            with self.subTest(colour=colour):
                self.assertEqual(_role_of(bar, "Quit", "hint", colour), "")
                self.assertEqual(_role_of(bar, "Choose", "hint", colour), "")
                self.assertEqual(_role_of(bar, "B/Esc", "hint", colour), "2")

    # Every other item.

    def test_a_legacy_report_past_column_161_is_read_from_the_bytes(self):
        """Column 163, row 137 typed [M#é, and a press
        followed by q lost the q."""
        press = b"\x1b[M" + bytes([32, 32 + 163, 32 + 137])
        release = b"\x1b[M" + bytes([35, 32 + 163, 32 + 137])
        for data, want in ((press + release, [install.TuiMouse(0, 163, 137),
                                              install.TuiMouse(3, 163, 137, True)]),
                           (press + b"q", [install.TuiMouse(0, 163, 137), Key("char", "q")])):
            for cut in range(1, len(data) + 1):
                with self.subTest(data=data, cut=cut):
                    reader, decoder = install.TerminalInput(), install.KeyDecoder()
                    keys = decoder.feed(reader.decode(data[:cut]))
                    keys += decoder.feed(reader.decode(data[cut:])) + decoder.flush()
                    self.assertEqual(keys, want)

    def test_the_setup_list_aligns_its_devices(self):
        """Three right edges at 120 columns, devices
        starting anywhere from column 20 to 70 at 80."""
        state = install.TuiState(os_type="linux", home=HOME)
        state.stack = ["platforms"]
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            for cols, rows in ((80, 60), (120, 60)):
                with self.subTest(cols=cols):
                    lines = [str(line) for line in install.tui_view(state, cols, rows)]
                    starts = {line.index(" ", line.index(", SD card") + 9) + 1
                              + len(line[line.index(", SD card") + 9:])
                              - len(line[line.index(", SD card") + 9:].lstrip())
                              for line in lines if ", SD card " in line}
                    self.assertEqual(len(starts), 1, lines)
                    self.assertTrue(all(len(line.rstrip()) <= 80 for line in lines))

    def test_the_copy_browser_never_offers_the_card_installed_to(self):
        onion = self.root / "media" / "ONION"
        make_card(onion, "Onion")
        old = self.root / "media" / "OLD"
        old.mkdir(parents=True)
        state = checked_state()
        state.dest = onion / "BIOS"
        with mock.patch.object(install, "_mounted_cards", return_value=[old, onion]):
            install._open_from_browser(state)
            values = [row.value for row in install.tui_rows(state) if row.action == "dir"]
        self.assertIn(old, values)
        self.assertNotIn(onion, values)

    def test_a_card_two_systems_fit_is_offered_as_either(self):
        """The first screen said nothing was found, and
        with a KNULLI list "No KNULLI card is mounted" beside it."""
        card = self.renamed()["renamed, no about.info"]
        with mock.patch.object(install, "_mounted_cards", return_value=[card]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, _effects = install.tui_start(_args(), "linux")
            self.assertEqual(state.screen, "setup")
            rows = install.tui_rows(state)
            self.assertEqual([row.value for row in rows if row.action == "doubt"],
                             [("knulli", card), ("batocera", card)])
            text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
            self.assertNotIn("Nothing was found here", text)
            self.assertIn("could be a KNULLI card or a Batocera SHARE drive", text)
            install.tui_update(state, Key("enter"))
            self.assertEqual((state.platform, state.dest), ("knulli", card / "bios"))
            folder = install.TuiState(os_type="linux", home=HOME)
            folder.platform, folder.card_bound = "knulli", install.card_bound("knulli",
                                                                              "knulli")
            install._open_folder_screen(folder, None)
            rows = install.tui_rows(folder)
            text = " ".join(" ".join(install.tui_view(folder, 120, 40)).split())
        self.assertEqual(rows[folder.focus["folder"]].value, card)
        self.assertNotIn("No KNULLI card is mounted", text)
        self.assertNotIn("Look again", text)

    def test_the_wsl_folder_question_offers_the_windows_side(self):
        """Under WSL only the Linux home was offered."""
        sides = install.other_side("wsl", "retroarch")
        self.assertEqual(len(sides), 1)
        self.assertTrue(sides[0][0].startswith("Windows RetroArch: "))
        self.assertEqual(install.other_side("linux", "retroarch"), [])
        state = install.TuiState(os_type="wsl", home=HOME)
        state.platform, state.stack = "retroarch", ["folder"]
        state.folder_default, state.folder_kind = SYSTEM_DIR, "usual"
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            rows = install.tui_rows(state)
        self.assertIn(sides[0][1], [row.value for row in rows if row.action == "drive"])

    @in_full
    def test_named_by_sits_under_its_folder(self):
        """The offline remedy and the narrowing came
        between the folder and what named it."""
        cfg = self.root / "home" / ".config" / "retroarch"
        cfg.mkdir(parents=True)
        (cfg / "retroarch.cfg").write_text(f'system_directory = "{self.root / "sys"}"\n')
        state = checked_state()
        state.dest = self.root / "sys"
        state.cli_systems = ["sony-playstation"]
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
                mock.patch.object(install, "_retroarch_config_at",
                                  return_value=(str(cfg / "retroarch.cfg"), cfg)):
            lines = [str(line).strip() for line in install.tui_view(state, 120, 40)]
        folder = next(i for i, line in enumerate(lines) if line.startswith("BIOS folder:"))
        named = next(i for i, line in enumerate(lines) if line.startswith("Named by"))
        # Nothing between the folder, wrapped or not, and what named it. A
        # long path wraps after the label, a longer one inside the path.
        self.assertEqual("".join(lines[folder:named]).replace(" ", ""),
                         f"BIOS folder: {state.dest}".replace(" ", ""), lines)
        self.assertLess(named, next(i for i, line in enumerate(lines)
                                    if line.startswith(("For ", "Copy them"))))

    def test_options_name_a_save_folder_the_setup_knows(self):
        """Save folder: not known, beside a RetroArch
        whose save folder the same machine names."""
        state = checked_state()
        state.manifest = {**state.manifest, "save_directory": {"folder": "saves",
                                                               "by_core": True}}
        state.saves = None
        place = install.SavePlace(Path("/home/user/.config/retroarch/saves"), True, True)
        with mock.patch.object(install, "save_directory_for", return_value=place):
            label = next(row.label for row in install._option_rows(state)
                         if row.action == "savedir")
        self.assertEqual(label, "Save folder: ~/.config/retroarch/saves")

    def test_the_result_counts_what_it_replaced_and_its_kinds(self):
        """The plan said 2 wrong copies are replaced, the
        result counted none, and the old card's result split no kind."""
        state = _installed_state(SYSTEM_DIR)
        state.summary = {**state.summary, "kept": [{"folder": "/x", "files": 2, "bytes": 3}]}
        _title, lines = install.tui_outcome(state)
        self.assertEqual(lines[0], "5 files installed, 2 of them replaced.")
        old = _installed_state(SYSTEM_DIR)
        old.finished = [("scph5500.bin", True, ""), ("gba_bios.bin", True, "")]
        old.local_dests = {"scph5500.bin": ("/media/OLD", ""), "gba_bios.bin": ("/media/OLD", "")}
        old.summary = {**old.summary, "installed": 2, "pending": 3}
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            _title, lines = install.tui_outcome(old)
        self.assertIn("Installed: 2 BIOS files.", lines)

    def test_the_wiki_says_where_clicks_are_off(self):
        """The page promised the mouse on Windows."""
        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        text = " ".join(page.split())
        self.assertIn("Clicks are off in the Windows console the PowerShell command runs in",
                      text)
        for term in ("`dumb`", "`unknown`", "`linux`", "`vt`", "`cons`", "`ansi`"):
            self.assertIn(term, text)
        self.assertIn("| `RETROBIOS_NO_MOUSE` | Set to any value but `0` or an empty one", text)
        self.assertEqual(install.tui_mouse_blocker(
            MouseEnabled.Tty(), MouseEnabled.Tty(),
            {"TERM": "xterm", install.TUI_MOUSE_ENV: ""}), "")
        first = (REPO_ROOT / "wiki" / "first-install.md").read_text(encoding="utf-8")
        self.assertIn("On a touch screen, tap a row twice to open it, once to tick a box.",
                      " ".join(first.split()))

    def test_the_exit_codes_name_a_chosen_quit(self):
        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        two = next(line for line in page.splitlines() if line.startswith("| `2` |"))
        self.assertIn("a quit chosen before the install", two)
        self.assertIn("`RETROBIOS_IDLE_EXIT`", two)
        last = next(line for line in page.splitlines() if line.startswith("| `130` |"))
        self.assertNotIn("A quit chosen", last)


@unittest.skipUnless(pyte and pty and hasattr(pty, "fork"),
                     "the pty runs need pyte and a pty")
class TapsOnAPty(unittest.TestCase):
    """Taps on the real install.py --tui."""

    repo = EndToEnd.repo
    start = EndToEnd.start
    line_of = staticmethod(MouseOnAPty.line_of)
    click = MouseOnAPty.click

    def test_taps_on_systems_tick_and_write_nothing(self):
        repo = self.repo()
        term = self.start()
        term.wait("Where to install?")
        term.send("\r")
        term.wait("> Install")
        row = self.line_of(term, "Choose systems")
        self.click(term, 20, row)
        term.settle()
        self.click(term, 20, row)
        term.wait("RetroBIOS: Choose systems")
        bar = term.settle().splitlines()[-1]
        self.assertIn("A/Enter/tap Tick", bar)
        row = self.line_of(term, "sony-playstation")
        self.click(term, 20, row)
        self.assertIn("[ ] sony-playstation", term.settle())
        self.click(term, 20, row)
        self.assertIn("[x] sony-playstation", term.settle())
        self.click(term, 20, self.line_of(term, "nintendo-gba"))
        screen = term.settle()
        self.assertIn("[ ] nintendo-gba", screen)
        self.assertIn("RetroBIOS: Choose systems", screen)
        self.assertEqual(repo.installed(), [])
        term.send("q")
        self.assertEqual(term.close(), install.QUIT_CODE)
        self.assertEqual(repo.installed(), [])

    def test_the_result_is_left_by_a_tap_on_exit(self):
        self.repo()
        term = self.start()
        term.wait("Where to install?")
        term.send("\r")
        term.wait("files to download")
        row = self.line_of(term, "> Install")
        self.click(term, 20, row)
        term.settle()
        self.click(term, 20, row)
        term.wait("files installed.")
        term.settle()
        mark = term.raw.rfind(b"files installed")
        self.assertGreater(term.raw.rfind(b"\x1b[?1000h"), term.raw.rfind(b"\x1b[?1000l"))
        bar = term.screen.display[-1]
        self.click(term, bar.index("Exit"), len(term.screen.display) - 1)
        self.assertEqual(term.close(), 0)
        self.assertIn("Next: start RetroArch and play.", term.after())
        self.assertGreater(term.raw.rfind(b"\x1b[?1000l"), mark)


class OneChoicePerRun(unittest.TestCase):
    """One choice for the run, taps that
    never commit what was not seen, and the words that fit."""

    setUp = LineModeAndScreenDecideAlike.setUp
    line_run = LineModeAndScreenDecideAlike.line_run
    listing = LineModeAndScreenDecideAlike.listing
    entry = staticmethod(LineModeAndScreenDecideAlike.entry)

    @staticmethod
    def receive(state: install.TuiState, events: list, facts: dict | None = None) -> None:
        """A check's events, then its end."""
        for event in events:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value=facts or {
                "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
            install.tui_receive(state, ("ended", state.run_id, 1, []))

    def game_manifest(self) -> dict:
        """Three systems, each with one BIOS file and one game data file."""
        files = []
        for system in ("nintendo-ds", "sega-dreamcast", "sony-playstation"):
            files += [{"dest": f"{system}.bin", "size": 100, "systems": [system],
                       "cores": None},
                      {"dest": f"{system}/game.dat", "size": 1000, "systems": [system],
                       "cores": None, "category": install.GAME_DATA}]
        # Dreamcast holds only game data.
        files = [entry for entry in files if entry["dest"] != "sega-dreamcast.bin"]
        return {"manifest_version": 2, "platform": "retroarch", "categorized": True,
                "files": files}

    def game_events(self, manifest: dict, left_out: bool = False,
                    only: tuple = ()) -> list:
        """The events of a check over manifest, game data left out or not,
        the files of only those systems when given (--emulator)."""
        kept = [entry for entry in manifest["files"]
                if not only or entry["systems"][0] in only]
        files = [entry for entry in kept
                 if not (left_out and entry.get("category") == install.GAME_DATA)]
        events = [{"event": "file", "platform": "retroarch", "dest": entry["dest"],
                   "systems": entry["systems"], "size": entry["size"], "state": "missing"}
                  for entry in files]
        systems = sorted({entry["systems"][0] for entry in files})
        events += [{"event": "system", "platform": "retroarch", "system": system,
                    "name": system, "files": 1, "present": 0, "missing": 1, "wrong_hash": 0,
                    "bytes_needed": 100} for system in systems]
        games = [entry["dest"] for entry in kept if entry.get("category") == install.GAME_DATA]
        events.append({"event": "summary", "mode": "check", "installed": 0, "up_to_date": 0,
                       "pending": len(files), "failed": [], "skipped": [],
                       "left_out": [{"category": install.GAME_DATA, "label": "game data",
                                     "files": len(games), "dests": games}]
                       if left_out else [], "kept": [], "interrupted": False})
        events.append({"event": "check", "platform": "retroarch", "name": "RetroArch",
                       "bios_dir": str(SYSTEM_DIR), "files": len(files), "present": 0,
                       "missing": len(files), "wrong_hash": 0,
                       "bytes_needed": sum(entry["size"] for entry in files),
                       "data_missing": 0, "not_installable": 0})
        return events

    def game_plan(self, only: tuple = ()) -> install.TuiState:
        state = fresh_state()
        state.stack = ["setup"]
        manifest = self.game_manifest()
        with mock.patch.object(install.Path, "exists", return_value=True):
            install.tui_update(state, Key("enter"))
        install.tui_receive(state, ("manifest", "retroarch", manifest))
        self.receive(state, self.game_events(manifest, only=only))
        return state

    # Root cause 2: one choice for the whole run.

    def test_the_game_data_row_keeps_the_systems_ticked(self):
        """The plan's game data row set the ticks back to
        every system, and the install wrote all of them."""
        state = self.game_plan()
        state.ticked = {"nintendo-ds"}
        rows = install.tui_rows(state)
        state.focus["plan"] = next(index for index, row in enumerate(rows)
                                   if row.action == "gamedata")
        self.assertEqual(install.tui_update(state, Key("enter")), [("run", "check")])
        self.receive(state, self.game_events(self.game_manifest(), left_out=True))
        self.assertEqual(state.ticked, {"nintendo-ds"})
        self.assertIn(("--system", "nintendo-ds"), install.tui_flags(state))
        self.assertIn(("--no-game-data", None), install.tui_flags(state))

    def test_every_check_of_the_same_list_keeps_the_choice(self):
        """A folder to copy from added, the
        save folder chosen or Check again set the ticks back to every system
        too, as the game data row did."""
        for how in ("from", "savedir", "recheck"):
            with self.subTest(how=how):
                state = self.game_plan()
                state.ticked = {"nintendo-ds"}
                if how == "from":
                    state.browse_for, state.browse_dir = "from", self.root
                    state.stack.append("browse")
                    install._activate(state, install.TuiRow("use", "Use this folder"))
                elif how == "savedir":
                    state.browse_for, state.browse_dir = "save", self.root
                    state.stack.append("browse")
                    install._activate(state, install.TuiRow("use", "Use this folder"))
                else:
                    install._activate(state, install.TuiRow("recheck", "Check again"))
                self.assertEqual(state.screen, "checking")
                self.receive(state, self.game_events(self.game_manifest()))
                self.assertEqual(state.ticked, {"nintendo-ds"})

    def test_a_choice_the_toggle_empties_says_so_and_offers_choose_systems(self):
        """Dreamcast alone, game data left out: the plan
        promised the whole list and Install refused."""
        state = self.game_plan()
        state.ticked = {"sega-dreamcast"}
        rows = install.tui_rows(state)
        state.focus["plan"] = next(index for index, row in enumerate(rows)
                                   if row.action == "gamedata")
        install.tui_update(state, Key("enter"))
        self.receive(state, self.game_events(self.game_manifest(), left_out=True))
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("sega-dreamcast holds only game data: nothing is left to install.", text)
        actions = [row.action for row in install.tui_rows(state)]
        self.assertNotIn("install", actions)
        self.assertEqual(actions[0], "systems")
        # Kept again, the same system comes back.
        state.focus["plan"] = actions.index("gamedata")
        install.tui_update(state, Key("enter"))
        self.receive(state, self.game_events(self.game_manifest()))
        self.assertEqual(state.ticked, {"sega-dreamcast"})

    def test_the_row_counts_the_list_the_check_read(self):
        """Under --emulator the row counted the game
        data of every system, line mode's g the emulator's alone."""
        state = self.game_plan(only=("nintendo-ds",))
        row = next(row for row in install.tui_rows(state) if row.action == "gamedata")
        self.assertEqual(row.right, "1 file, 1000 B")
        # Line mode, the same list narrowed as --emulator narrows it.
        manifest = self.game_manifest()
        listing = self.listing("retroarch", [
            self.entry(entry["dest"], b"x" * entry["size"], entry["systems"],
                       **({"category": entry["category"]} if "category" in entry else {}))
            for entry in manifest["files"] if entry["systems"] == ["nintendo-ds"]],
            categorized=True)
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False, dry_run=True), [""])
        self.assertIn("g) Game data: kept (1 file, 1000 B)", text)

    def test_line_mode_names_the_game_data_of_the_systems_chosen(self):
        """--system with --no-game-data named the game
        data of the whole list."""
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"]),
                 self.entry("doom/doom1.wad", b"wad" * 10, ["doom"], category="game_data")]
        listing = self.listing("retroarch", files, categorized=True)
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False, dry_run=True, no_input=True,
                                           system=["nintendo-gba"], no_game_data=True), [])
        self.assertNotIn("doom1.wad", text)
        self.assertNotIn("game data file left out", text)
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False, dry_run=True, no_input=True,
                                           system=["doom"], no_game_data=True), [])
        # The choice holds no file: said, never "All files up to date", nor
        # "unknown system" for a system the list names.
        self.assertIn("doom holds only game data: nothing is left to install.", text)
        self.assertNotIn("All files up to date", text)
        self.assertNotIn("unknown system", text)

    def test_the_run_head_counts_three_kinds_and_defines_them(self):
        """A run without the menu split two kinds beside
        the plan's three, from a second counting function."""
        self.assertFalse(hasattr(install, "split_words"))
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"]),
                 self.entry("doom/doom1.wad", b"wad" * 10, ["doom"], category="game_data")]
        listing = self.listing("retroarch", files, categorized=True)
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False, dry_run=True, no_input=True),
                                     [])
        head = text[:text.index("Checking existing files")]
        self.assertIn("1 BIOS file (3 B) and 1 game data file (30 B).", head)
        self.assertIn("Game data: files a game or a game engine reads", head)

    def test_the_cores_of_the_systems_chosen_come_first(self):
        """With --system sony-playstation, Cores opened
        on every core of the list."""
        state = checked_state()
        state.cli_systems = ["sony-playstation"]
        state.stack.append("cores")
        values = [row.value for row in install.tui_rows(state) if row.action == "core"]
        self.assertEqual(values, ["pcsx_rearmed"])
        rows = install.tui_rows(state)
        more = next(i for i, row in enumerate(rows) if row.action == "morecores")
        self.assertEqual(rows[more].label, "Cores of the other systems: 1")
        state.focus["cores"] = more
        install.tui_update(state, Key("enter"))
        self.assertEqual([row.value for row in install.tui_rows(state)
                          if row.action == "core"], ["mesen", "pcsx_rearmed"])

    def test_line_mode_counts_the_systems_that_hold_a_file(self):
        """"2 of 8" in line mode, "1 of 8" on the screen."""
        files = [self.entry("ds.bin", b"ds", ["nintendo-ds"]),
                 self.entry("dc/game.dat", b"dc", ["sega-dreamcast"], category="game_data"),
                 self.entry("psx.bin", b"psx", ["sony-playstation"])]
        listing = self.listing("retroarch", files, categorized=True,
                               system_titles={"nintendo-ds": "Nintendo DS",
                                              "sega-dreamcast": "Sega Dreamcast",
                                              "sony-playstation": "Sony PlayStation"})
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False, dry_run=True),
                                     ["c", "1,2", "g"])
        last = text[text.rindex("Counted again"):]
        self.assertIn("for 1 of 2 systems.", last)
        # The screen, the same choice: DS and Dreamcast ticked, game data
        # left out on the plan.
        state = self.game_plan()
        state.ticked = {"nintendo-ds", "sega-dreamcast"}
        rows = install.tui_rows(state)
        state.focus["plan"] = next(index for index, row in enumerate(rows)
                                   if row.action == "gamedata")
        install.tui_update(state, Key("enter"))
        self.receive(state, self.game_events(self.game_manifest(), left_out=True))
        self.assertIn("for 1 of 2 systems", str(install.tui_view(state, 80, 24)[2]))

    # Root cause 3: copies and packs.

    def test_confirm_counts_the_copies_a_folder_holds(self):
        """Confirm called the files packx holds
        downloads, offline and online."""
        state = checked_state()
        state.found = [found(event["dest"], "/media/old") for event in FILES]
        state.stack.append("confirm")
        state.dry, state.dry_files = dict(CHECK), list(FILES)
        for env in ({install.OFFLINE_VARIABLE: install.OFFLINE_FLAG_VALUE}, {}):
            with self.subTest(offline=bool(env)), mock.patch.dict(os.environ, env):
                text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
                self.assertIn("4 found in old, nothing to download", text)
                self.assertNotIn("need the internet", text)
                self.assertNotIn("to download,", text)

    def test_an_old_card_holding_every_file_in_place_is_not_called_empty(self):
        """"packx holds none of these files" when all 22
        were in place."""
        state = checked_state()
        state.check = {**CHECK, "present": 5, "missing": 0, "wrong_hash": 0,
                       "bytes_needed": 0}
        state.files = []
        state.from_folders = [Path("/media/packx")]
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("Nothing to copy from packx: every file is in place.", text)
        self.assertNotIn("holds none of these files", text)

    def test_the_plan_says_what_the_pack_lacks_before_a_size(self):
        """"8358 files to install from the pack, 6.6 GB"
        from a pack that held none of them."""
        state = checked_state()

        class Lacking:
            name = "RetroArch_BIOS_Pack.zip"

            @staticmethod
            def find(entry: dict) -> tuple | None:
                return (None, entry) if entry["dest"] == "gba_bios.bin" else None

        with mock.patch.object(install.LOCAL, "pack", Lacking()):
            text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
            self.assertIn("1 file to install from the pack, 16.0 KB", text)
            self.assertIn("3 of these 4 files are not in RetroArch_BIOS_Pack.zip", text)
            Lacking.find = staticmethod(lambda entry: None)
            text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
            self.assertIn("RetroArch_BIOS_Pack.zip holds none of these 4 files", text)
            self.assertNotIn("install", [row.action for row in install.tui_rows(state)])

    def test_a_failed_pack_install_leaves_no_folder_behind(self):
        """405 empty folders and a saves folder."""
        pack_dir = self.root / "downloads"
        pack_dir.mkdir()
        pack = pack_dir / "RetroArch_BIOS_Pack.zip"
        with zipfile.ZipFile(pack, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"files": []}))
        files = [self.entry(f"deep/folder{n}/file.bin", b"x", ["nintendo-gba"])
                 for n in range(3)]
        listing = self.listing("retroarch", files)
        dest = self.root / "new" / "system"
        dest.parent.mkdir()
        text, _asked = self.line_run(_args(manifest=listing, from_pack=[pack], dest=dest,
                                           declared_only=False, yes=True, no_input=True), [])
        self.assertIn("RetroArch_BIOS_Pack.zip holds none of these 3 files", text)
        self.assertFalse(dest.exists(), list(dest.rglob("*")) if dest.exists() else [])

    # Root cause 4: Choose another folder.

    def test_choose_another_folder_opens_the_folder_screen(self):
        """With --dest the create screen is alone on the
        stack, and Choose another folder asked Quit?."""
        state = fresh_state()
        state.platform, state.dest = "retroarch", self.root / "missing" / "bios"
        state.stack = ["create"]
        state.facts = {"nearest": self.root, "risky": False}
        state.focus["create"] = 1
        install.tui_update(state, Key("enter"))
        self.assertEqual(state.screen, "folder")
        self.assertEqual(install.tui_view(state, 80, 24)[0].strip(),
                         "RetroBIOS: Which folder?")

    # Root cause 5: text that fits.

    def test_the_version_note_stays_on_the_40x12_plan_and_in_every_farewell(self):
        note = "This list was built for RetroBat 8.3.1, this machine runs 8.2.0.1."
        state = checked_state()
        state.version = note
        state.files = []
        state.check = {**CHECK, "present": 5, "missing": 0, "wrong_hash": 0,
                       "bytes_needed": 0}
        text = " ".join(" ".join(install.tui_view(state, 40, 12)).split())
        self.assertIn(note, text)
        state.exit_code = 0
        self.assertIn(note, install.tui_farewell(state))
        state.exit_code, state.quit_asked = install.QUIT_CODE, True
        self.assertIn(note, install.tui_farewell(state))

    @in_full
    def test_the_help_defines_game_data_at_40_columns(self):
        """The row was a choice nothing explained on the
        Miyoo's screen."""
        state = _game_state()
        state.mouse = True
        state.help = True
        for rows in (12, 15):
            with self.subTest(rows=rows):
                text = " ".join(" ".join(install.tui_view(state, 40, rows)).split())
                self.assertIn("Game data: files a game or a game engine reads", text)
        # Data files too, each said whole: in a few words at 40x12.
        state.check = {**state.check, "data_missing": 7, "data_bytes": 2048}
        text = " ".join(" ".join(install.tui_view(state, 40, 12)).split())
        self.assertIn("Game data: what a game reads, of no use to other cores. Data files: "
                      "an emulator's own data folder.", text)
        text = " ".join(" ".join(install.tui_view(state, 40, 15)).split())
        self.assertIn("such as Dolphin's Sys and PPSSPP's assets.", text)

    def test_the_40_column_bar_keeps_help_and_the_help_its_tap_line(self):
        state = checked_state()
        state.mouse = True
        state.stack.append("systems")
        state.focus["systems"] = 1
        bar = str(install.tui_view(state, 40, 12)[-1])
        self.assertIn("? Help", bar)
        state.help = True
        text = " ".join(" ".join(install.tui_view(state, 40, 12)).split())
        self.assertIn("Tap Tick or untick a row, as A", text)

    def test_one_spelling_of_a_folder_on_the_plan_and_the_result(self):
        """"/home...i_audit13/rb/bios" on the plan, the
        same folder whole and folded inside a name on the result."""
        dest = Path("/home/moi/retroarch_system/tmp/tui_audit13/rb/bios")
        for cols in (40, 80):
            with self.subTest(cols=cols):
                plan = checked_state()
                plan.dest = dest
                result = _installed_state(dest)
                spelled = []
                for state in (plan, result):
                    lines = [str(line).strip() for line in install.tui_view(state, cols, 24)]
                    at = next(i for i, line in enumerate(lines)
                              if line.startswith("BIOS folder:"))
                    pieces = [lines[at]]
                    while pieces[-1].endswith("/") and lines[at + len(pieces)]:
                        pieces.append(lines[at + len(pieces)])
                    spelled.append(pieces)
                    # A command's path may be cut to fit, said so: a folder
                    # in prose never is.
                    self.assertNotIn("...", " ".join(
                        line for line in lines if install.tui_command(state)[:10] not in line
                        and not line.startswith("--")))
                    self.assertTrue(all(len(piece) <= cols - 2 for piece in pieces), pieces)
                self.assertEqual(spelled[0], spelled[1])
                self.assertEqual("".join(spelled[0]), f"BIOS folder: {dest}")

    def test_a_long_path_fits_without_its_indent(self):
        """A pack path of 75 cells folded at 80 columns
        under an indent of 6."""
        path = "/home/moi/retroarch_system/tmp/tui_audit13/pack/MinUI_2025-11_BIOS_Pack.zip"
        self.assertEqual(len(path), 75)
        lines = install._wrap(f"    python3 install.py --from-pack {path}", 95,
                              whole="command")
        self.assertIn(f"      --from-pack {path}", lines)

    @in_full
    def test_the_definition_is_said_once_and_never_spliced(self):
        state = checked_state()
        state.systems = []
        state.manifest = {**MANIFEST, "categorized": True, "omitted_files": [
            {"dest": "jazz2/Source/Anims.j2a", "system": "jazz-jackrabbit-2",
             "required": True, "category": "game_data"}]}
        state.check = {**CHECK, "not_installable": 1}
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertEqual(text.count("files a game or a game engine reads"), 1, text)
        self.assertIn("Not available here: jazz2/Source/Anims.j2a (Jazz Jackrabbit 2), game "
                      "data its game reads.", text)

    @in_full
    def test_the_headline_counts_every_file_once(self):
        """"8358 files and 2636 data files", and the
        definition dropped at 80 columns."""
        state = _game_state()
        state.check = {**state.check, "data_missing": 7, "data_bytes": 2048}
        lines = [str(line).strip() for line in install.tui_view(state, 80, 24)]
        text = " ".join(" ".join(lines).split())
        self.assertIn("11 files to download, 1.0 MB", text)
        self.assertNotIn("and 7 data files", lines[2])
        self.assertIn("Data files: the files an emulator reads", text)

    @in_full
    def test_the_save_line_never_ends_on_its_colon(self):
        """"...goes to a folder per core under:" with no
        folder at 60x20."""
        state = _game_state()
        state.saves = {"event": "saves", "files": 1,
                       "folder": "/home/user/.config/retroarch/saves/<core>"}
        shown = 0
        for rows in range(12, 30):
            with self.subTest(rows=rows):
                lines = [str(line).strip() for line in install.tui_view(state, 60, rows)]
                for index, line in enumerate(lines):
                    if line.endswith("under:"):
                        shown += 1
                        self.assertTrue(lines[index + 1].startswith("~/"), lines)
        self.assertGreater(shown, 0)

    def test_the_result_says_how_to_copy_and_counts_one_kind_once(self):
        state = _installed_state(SYSTEM_DIR)
        state.manifest = {**MANIFEST, "categorized": True}
        state.mouse = True
        state.finished = [(event["dest"], True, "") for event in FILES]
        state.summary = {**state.summary, "installed": 4}
        _title, lines = install.tui_outcome(state)
        self.assertEqual(lines[0], "4 BIOS files installed.")
        self.assertFalse(any(line.startswith("Installed:") for line in lines), lines)
        self.assertEqual(lines[-1], install.TUI_RESULT_COPY)
        self.assertNotIn(install.TUI_RESULT_COPY, install.tui_farewell(state))
        state.help = True
        self.assertIn("Shift+drag", " ".join(install.tui_view(state, 80, 24)))

    def test_the_old_card_result_splits_what_is_missing(self):
        """"16 still missing" where 6 were game data."""
        state = _game_state()
        state.from_folders = [Path("/media/OLD")]
        state.local_dests = {"gba_bios.bin": ("/media/OLD", "")}
        state.finished = [("gba_bios.bin", True, "")]
        state.download = {"files": 4}
        state.stack, state.run = ["result"], "install"
        state.summary = {"event": "summary", "mode": "install", "installed": 1,
                         "up_to_date": 0, "pending": 3, "failed": [], "skipped": [],
                         "left_out": [], "kept": [], "interrupted": False}
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE:
                                          install.OFFLINE_FLAG_VALUE}):
            _title, lines = install.tui_outcome(state)
        # The wrong copy the check found is left in place: named as one,
        # never counted as missing.
        self.assertIn("1 file copied from OLD, 2 still missing, 1 wrong copy left.", lines)
        self.assertIn("Still missing: 1 BIOS file and 1 game data file.", lines)

    # Root cause 6: every other word.

    def test_drives_are_named_once_under_wsl_and_windows(self):
        """"D:: bios" and "D:\\: bios"."""
        with mock.patch.dict(install._WSL, {"active": True}):
            mount = Path(install._WSL["root"]) / "d"
            self.assertEqual(install._drive_folder(mount, "bios"), "D:\\bios")
        windows = PureWindowsPath("D:\\")
        with mock.patch.object(install, "_mount_name", return_value="D:\\"), \
                mock.patch.object(install, "shown_path", side_effect=str):
            self.assertEqual(install._drive_folder(windows, "bios"), "D:\\bios")
        stick = Path("/media/moi/USBSTICK")
        self.assertEqual(install._drive_folder(stick, "bios"), "USBSTICK: bios")

    def test_the_linux_side_is_named_by_its_side(self):
        self.assertEqual(install.side_name("wsl", "retroarch"), "Linux RetroArch")
        self.assertEqual(install.side_name("linux", "retroarch"), "RetroArch")
        state = fresh_state()
        state.os_type, state.platform = "wsl", "retroarch"
        state.stack = ["setup", "folder"]
        state.folder_default, state.folder_kind = SYSTEM_DIR, "usual"
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_is_dir", return_value=False):
            text = "\n".join(install.tui_view(state, 100, 30))
        self.assertIn("Linux RetroArch usually reads its BIOS files from:", text)
        self.assertIn("(does not exist yet)", text)

    def test_a_folder_created_where_no_setup_is_says_so(self):
        """"system is created in C:\\RetroArch-Win64, where
        RetroArch reads it" with no RetroArch there."""
        state = fresh_state()
        missing = self.root / "RetroArch-Win64" / "system"
        with mock.patch.object(install, "_start_check", return_value=[]):
            install._choose(state, "retroarch", missing, proposed=True)
        self.assertIn("a folder that does not exist yet", state.card_note)
        self.assertNotIn("reads it", state.card_note)
        here = self.root / "pc" / "bios"
        with mock.patch.object(install, "_start_check", return_value=[]):
            install._choose(state, "retroarch", here, proposed=True)
        self.assertIn("where RetroArch reads it", state.card_note)

    def test_the_needed_list_counts_one_more_system_in_words(self):
        """On the list of files an emulator needs too."""
        entries = [{"dest": f"s{n}.bin", "system": f"system-{n}", "required": True}
                   for n in range(9)]
        said = " ".join(install._needed_lines(entries, "Needed"))
        self.assertIn("... and 1 more system (--check --verbose lists them all)", said)

    @in_full
    def test_the_farewell_names_the_option_not_the_screen(self):
        state = _installed_state(SYSTEM_DIR)
        state.manifest = {**state.manifest, "save_directory": {"folder": "saves",
                                                               "by_core": True}}
        state.summary = {**state.summary, "skipped": [
            {"reason": "no_save_directory", "label": "", "files": 1, "required": False}]}
        farewell = " ".join(install.tui_farewell(state))
        self.assertIn("Name it with --save-dir next time.", farewell)
        self.assertNotIn("Options", farewell)

    def test_more_systems_is_counted_in_words(self):
        """"... and 1 more systems"."""
        entries = [{"dest": f"s{n}.bin", "size": 10, "systems": [f"system-{n:02d}"]}
                   for n in range(install.PLAN_LARGEST_SYSTEMS + 1)]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            install._print_plan(entries, SYSTEM_DIR, install.Terminal(io.StringIO()))
        self.assertIn("... and 1 more system:", out.getvalue())

    def test_the_systems_question_aligns_and_explains_after_the_list(self):
        rows = [("mattel-intellivision", []), ("nec-pc-engine", []),
                (install.OTHER_SYSTEMS, [])]
        labels = {"mattel-intellivision": "Mattel Intellivision  mattel-intellivision",
                  "nec-pc-engine": "NEC PC Engine  nec-pc-engine",
                  install.OTHER_SYSTEMS: install.OTHER_TITLE + "  " + "x" * 10}
        out = io.StringIO()
        with contextlib.redirect_stdout(out), \
                mock.patch.object(install, "_ask", return_value=""):
            install._pick("Systems:", rows, labels=labels, note="A note.",
                          sizer=lambda files: "1 file")
        lines = out.getvalue().splitlines()
        listed = [line for line in lines if line.endswith("1 file")]
        self.assertEqual(len({line.index("1 file") for line in listed}), 1, listed)
        self.assertGreater(lines.index("A note."), lines.index(listed[-1]))

    def test_the_yes_stop_says_one_thing_with_a_list_or_without(self):
        """"the file list" said of a
        pack, and two wordings for one stop."""
        pack = self.root / "RetroArch_BIOS_Pack.zip"
        with zipfile.ZipFile(pack, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"files": []}))
        env = {"HOME": str(self.root / "home"), "XDG_CONFIG_HOME": str(self.root / "cfg"),
               "RETROBIOS_OS": "linux"}
        said = install_run("--from-pack", str(pack), "--yes", env=env)
        self.assertEqual(said.returncode, 1, said.stdout + said.stderr)
        self.assertIn("No supported platform detected: RetroArch was not found here, and "
                      "the pack does not say where it goes.", said.stderr)
        # The standalone emulators' lists come from the network: offline,
        # no request leaves the machine.
        alone = install_run("--yes", env={**env, install.OFFLINE_VARIABLE: "1"})
        self.assertIn("No supported platform detected", alone.stdout + alone.stderr)
        hint = install._manual_usage_hint("linux")
        self.assertTrue(hint[0].startswith("  Name the setup with --platform and its folder "
                                           "with --dest"), hint)
        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        self.assertIn("every run without questions stops before reading it", page)
        self.assertIn("none stops it too, with `reason` `not_found`", page)
        self.assertIn("So is a platform named by a file list or a pack", page)


class TheUsageNamesTheInstaller(unittest.TestCase):
    """The Windows one-liner's --help said "usage: retrobios-install-<guid>.py",
    the name install.ps1 gives its copy."""

    def test_a_copy_under_a_temporary_name_says_install_py(self):
        scratch = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, scratch, True)
        copy = scratch / "retrobios-install-33826e0b-37cc-4ad3-a6c4-6ed168e3fe9e.py"
        shutil.copyfile(REPO_ROOT / "install.py", copy)
        env = {**os.environ, "RETROBIOS_BOOTSTRAP": "ps1"}
        for option in ("--help", "--no-such-option"):
            with self.subTest(option=option):
                proc = subprocess.run([sys.executable, str(copy), option], env=env,
                                      capture_output=True, text=True, timeout=60,
                                      stdin=subprocess.DEVNULL, check=False)
                said = proc.stdout + proc.stderr
                self.assertIn("usage: install.py", said)
                self.assertNotIn("retrobios-install-", said)
        with mock.patch.object(sys, "argv", [str(copy), "--help"]):
            self.assertEqual(install.build_parser().prog, "install.py")


class TapsSeenBeforeTheyAct(unittest.TestCase):
    """A tap acts on the
    frame it was made on, and never commits on one tap."""

    def test_a_release_on_a_later_frame_does_nothing(self):
        state = checked_state()
        state.mouse = True
        lines = drawn(state, 80, 24)
        row = next(i for i, line in enumerate(lines)
                   if getattr(line, "mark", None) and line.mark[0] == "row"
                   and line.mark[2][0] == "systems")
        settled(state)
        install.tui_update(state, install.TuiMouse(0, 5, row + 1))
        self.assertIsNotNone(state.pressed)
        # The screen changes under the finger before it comes up.
        state.stack.append("options")
        drawn(state, 80, 24)
        state.stack.pop()
        drawn(state, 80, 24)
        effects = install.tui_update(state, install.TuiMouse(0, 5, row + 1, True))
        self.assertEqual(effects, [])
        self.assertIsNone(state.tapped)

    def test_the_bar_install_arms_then_presses(self):
        state = checked_state()
        state.mouse = True
        lines = drawn(state, 80, 24)
        bar = len(lines) - 1
        self.assertEqual(tap(state, 3, bar), [])
        self.assertEqual(state.screen, "plan")
        armed = drawn(state, 80, 24)
        self.assertIn(f"A/Enter Install: {install.TUI_ARMED}", str(armed[-1]))
        self.assertEqual(tap(state, 3, bar), [("run", "install")])

    def test_a_tapped_quit_quits_with_the_quit_code(self):
        state = checked_state()
        state.mouse = True
        state.stack.append("checking")
        state.running, state.run = True, "check"
        lines = drawn(state, 80, 24)
        self.assertFalse(str(lines[-1]).strip().startswith("Ctrl-C"))
        at = str(lines[-1]).index("Ctrl-C")
        # One tap: quitting writes nothing, and the settle time keeps a
        # double tap on the screen before from reaching it.
        tap(state, at, len(lines) - 1)
        self.assertEqual(state.exit_code, install.QUIT_CODE)

    def test_two_taps_on_a_region_leave_it_unticked_where_it_was(self):
        state = checked_state()
        state.mouse = True
        install.tui_update(state, Key("char", "o"))
        install.tui_update(state, Key("enter"))
        self.assertEqual(state.screen, "regions")
        lines = drawn(state, 80, 24)
        before = [row.value for row in install.tui_rows(state)]
        row = next(i for i, line in enumerate(lines)
                   if getattr(line, "mark", None) and line.mark[0] == "row"
                   and line.mark[2][1] == "north-america")
        tap(state, 5, row)
        drawn(state, 80, 24)
        self.assertEqual(state.regions, ["north-america"])
        self.assertEqual([row.value for row in install.tui_rows(state)], before)
        tap(state, 5, row)
        self.assertEqual(state.regions, [])
        bar = str(drawn(state, 80, 24)[-1])
        self.assertIn("A/Enter/tap Tick", bar)
        state.help = True
        self.assertIn("as A", " ".join(install.tui_view(state, 80, 24)))


class DoubleTapsAcrossScreens(unittest.TestCase):
    """The second tap of a double tap acted on the screen
    the first one opened, at every gap measured (0, 80, 150 and 250 ms).
    A press within TUI_TAP_SETTLE of a new screen is dropped, and a slow
    deliberate second tap still acts."""

    GAPS = (0.0, 0.08, 0.15, 0.25)

    @staticmethod
    def bar_cell(lines: list) -> tuple[int, int]:
        return len(str(lines[-1])) - len(str(lines[-1]).lstrip()), len(lines) - 1

    def double_tap(self, state: install.TuiState, gap: float) -> list:
        """Two taps gap seconds apart on the bar's first entry, the screen
        drawn after each event as the loop draws it."""
        lines = drawn(state, 80, 24)
        col, row = self.bar_cell(lines)
        state.now = state.hits.shown + 2.0
        effects = []
        for release in (False, True):
            effects += install.tui_update(state, install.TuiMouse(0, col + 1, row + 1, release))
        first = state.now
        drawn(state, 80, 24)
        state.now = first + gap
        for release in (False, True):
            effects += install.tui_update(state, install.TuiMouse(0, col + 1, row + 1, release))
            drawn(state, 80, 24)
        return effects

    def one_tap(self, state: install.TuiState) -> list:
        lines = drawn(state, 80, 24)
        col, row = self.bar_cell(lines)
        return tap(state, col, row)

    def plan_on(self, action: str) -> install.TuiState:
        state = checked_state()
        state.mouse = True
        rows = install.tui_rows(state)
        state.focus["plan"] = next(i for i, row in enumerate(rows) if row.action == action)
        return state

    def both(self, make, gap: float) -> tuple:
        once = make()
        one = self.one_tap(once)
        twice = make()
        return one, once, self.double_tap(twice, gap), twice

    def test_continue_on_the_first_screen(self):
        def make() -> install.TuiState:
            state = fresh_state()
            state.mouse = True
            return state
        for gap in self.GAPS:
            with self.subTest(gap=gap):
                with mock.patch.object(install.Path, "exists", return_value=True):
                    one, once, two, twice = self.both(make, gap)
                self.assertNotEqual(once.stack, ["setup"])
                self.assertEqual(two, one)
                self.assertEqual(twice.stack, once.stack)

    def test_open_on_the_plan_keeps_the_systems_ticked(self):
        for gap in self.GAPS:
            with self.subTest(gap=gap):
                one, once, two, twice = self.both(lambda: self.plan_on("systems"), gap)
                self.assertEqual(once.screen, "systems")
                self.assertEqual((twice.stack, twice.ticked), (once.stack, once.ticked))
                self.assertEqual(two, one)

    def test_choose_on_copy_from(self):
        for gap in self.GAPS:
            with self.subTest(gap=gap):
                one, once, two, twice = self.both(lambda: self.plan_on("fromcard"), gap)
                self.assertEqual(once.screen, "browse")
                self.assertEqual((twice.stack, twice.browse_dir),
                                 (once.stack, once.browse_dir))
                self.assertEqual(two, one)

    def test_a_slow_second_tap_acts(self):
        once = self.plan_on("systems")
        self.double_tap(once, 0.0)
        slow = self.plan_on("systems")
        self.double_tap(slow, install.TUI_TAP_SETTLE + 0.2)
        self.assertEqual(once.screen, "systems")
        # On Choose systems the first entry ticks: the slow tap pressed it
        # once more, and the box is back as it was.
        self.assertEqual(slow.screen, "systems")
        self.assertEqual(slow.ticked, once.ticked ^ {
            install.tui_rows(once)[once.focus["systems"]].value})

    def test_a_release_whose_press_came_before_the_frame_does_nothing(self):
        state = self.plan_on("systems")
        lines = drawn(state, 80, 24)
        col, row = self.bar_cell(lines)
        state.now = state.hits.shown + 2.0
        install.tui_update(state, install.TuiMouse(0, col + 1, row + 1))
        # Another screen drawn between the press and its release.
        state.stack.append("options")
        drawn(state, 80, 24)
        state.now += 1.0
        self.assertEqual(install.tui_update(state, install.TuiMouse(0, col + 1, row + 1, True)),
                         [])
        self.assertEqual(state.screen, "options")

    def test_the_settle_time_is_documented(self):
        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        self.assertIn(f"{round(install.TUI_TAP_SETTLE * 1000)} ms", page)


class TwoTapsOnlyWhereFilesAreWritten(unittest.TestCase):
    """With the settle time in place, a second
    tap is asked only of an entry that writes files with nothing to look at
    after it, drawn in the accent and said in the help at every size."""

    def test_install_on_the_plan_arms_in_the_accent(self):
        state = checked_state()
        state.mouse = True
        lines = drawn(state, 80, 24)
        self.assertEqual(tap(state, 2, len(lines) - 1), [])
        armed = str(drawn(state, 80, 24)[-1])
        entry = f"A/Enter Install: {install.TUI_ARMED}"
        self.assertIn(entry, armed)
        painted = install.tui_paint(armed, "hint", True)
        self.assertIn(f"{install.COLOUR_ROLES['accent']}m{entry}\x1b[0m", painted)
        self.assertEqual(tap(state, 2, len(lines) - 1), [("run", "install")])

    def test_a_tap_settles_on_a_clock_as_large_as_a_runners(self):
        """CI's monotonic clock counts the runner's uptime: shown + 0.4 - shown
        came out under 0.4 there and every deliberate tap was dropped."""
        state = fresh_state()
        state.mouse = True
        state.now = 1234567.123456789
        lines = drawn(state, 80, 24)
        tap(state, str(lines[-1]).index("B/Esc"), len(lines) - 1)
        self.assertEqual(state.screen, "quit")

    def test_quit_takes_two_activations(self):
        state = fresh_state()
        state.mouse = True
        lines = drawn(state, 80, 24)
        tap(state, str(lines[-1]).index("B/Esc"), len(lines) - 1)
        self.assertEqual(state.screen, "quit")
        state.focus["quit"] = next(i for i, row in enumerate(install.tui_rows(state))
                                   if row.action == "quit")
        lines = drawn(state, 80, 24)
        tap(state, 2, len(lines) - 1)
        self.assertEqual(state.exit_code, install.QUIT_CODE)

    def test_install_from_choose_systems_takes_two_activations(self):
        state = checked_state()
        state.mouse = True
        rows = install.tui_rows(state)
        state.focus["plan"] = next(i for i, row in enumerate(rows) if row.action == "systems")
        install.tui_update(state, Key("enter"))
        self.assertEqual(state.screen, "systems")
        lines = drawn(state, 80, 24)
        # A tap on the bar's first entry ticks, B goes
        # back, and Install counts the choice on Confirm first.
        self.assertEqual(tap(state, 2, len(lines) - 1), [])
        self.assertEqual(state.screen, "systems")
        lines = drawn(state, 80, 24)
        self.assertEqual(tap(state, str(lines[-1]).index("B/Esc"), len(lines) - 1), [])
        self.assertEqual(state.screen, "plan")
        lines = drawn(state, 80, 24)
        state.focus["plan"] = 0
        lines = drawn(state, 80, 24)
        self.assertEqual(tap(state, 2, len(lines) - 1), [("run", "confirm")])
        self.assertEqual(state.screen, "confirm")
        # Counted for the choice: another plan than the check's, so Confirm
        # waits for its own Install.
        install.tui_receive(state, ("event", state.run_id, {
            **CHECK, "files": 1, "present": 0, "missing": 1, "wrong_hash": 0,
            "bytes_needed": 16384}))
        install.tui_receive(state, ("ended", state.run_id, 1, []))
        lines = drawn(state, 80, 24)
        self.assertIn("A/Enter Install", str(lines[-1]))
        self.assertEqual(tap(state, 2, len(lines) - 1), [("run", "install")])

    def test_the_help_says_it_at_every_size(self):
        for cols, rows in ((40, 12), (60, 20), (80, 24)):
            with self.subTest(size=(cols, rows)):
                state = checked_state()
                state.mouse = True
                state.help = True
                text = " ".join(" ".join(str(line).split())
                                for line in install.tui_view(state, cols, rows))
                self.assertIn("A row or Install: click or tap twice", text)


@unittest.skipUnless(pyte and pty and hasattr(pty, "fork"),
                     "screen tests need pyte (pip install pyte==0.8.2) and a pty")
class TapsOnAPtySeeFirst(unittest.TestCase):
    """Taps that never commit a row not yet seen, on the real install.py
    --tui."""

    repo = EndToEnd.repo
    start = EndToEnd.start
    line_of = staticmethod(MouseOnAPty.line_of)
    click = MouseOnAPty.click

    def bar_entry(self, term: Pty, word: str) -> tuple[int, int]:
        line = len(term.screen.display) - 1
        return term.screen.display[line].index(word), line

    def test_one_tap_on_the_bar_install_installs_nothing(self):
        repo = self.repo()
        term = self.start()
        term.wait("Where to install?")
        term.send("\r")
        term.wait("> Install")
        term.settle()
        self.click(term, *self.bar_entry(term, "Install"))
        self.assertIn(install.TUI_ARMED, term.settle().splitlines()[-1])
        self.assertEqual(repo.installed(), [])
        self.click(term, *self.bar_entry(term, "Install"))
        term.wait("files installed")
        term.send("q")
        term.close()

    def test_a_double_tap_on_continue_neither_quits_nor_installs(self):
        repo = self.repo()
        term = self.start()
        term.wait("Where to install?")
        term.settle()
        col, line = self.bar_entry(term, "Continue")
        report = sgr(col + 1, line + 1) + sgr(col + 1, line + 1, release=True)
        term.send(report + report)
        term.settle()
        term.send(report)
        term.settle(0.6)
        self.assertIsNone(os.waitpid(term.pid, os.WNOHANG)[0] or None)
        self.assertEqual(repo.installed(), [])
        term.send("q")
        if "Quit?" in term.settle():
            term.send("\r")
        self.assertIn(term.close(), (install.QUIT_CODE, 0))

    def test_a_double_tap_on_continue_stays_on_what_it_opened(self):
        # at 0, 80, 150 and 250 ms the second tap pressed
        # B/Esc Back on the Checking screen, back to the first screen.
        for gap in (0.0, 0.08, 0.15, 0.25):
            with self.subTest(gap=gap):
                repo = self.repo()
                term = self.start()
                term.wait("Where to install?")
                term.settle()
                time.sleep(install.TUI_TAP_SETTLE)
                col, line = self.bar_entry(term, "Continue")
                press = sgr(col + 1, line + 1)
                release = sgr(col + 1, line + 1, release=True)
                os.write(term.fd, (press + release).encode())
                time.sleep(gap)
                os.write(term.fd, (press + release).encode())
                screen = term.settle(0.8)
                self.assertNotIn("Where to install?", screen)
                self.assertNotIn("Quit?", screen)
                term.wait("> Install")
                self.assertEqual(repo.installed(), [])
                term.send("q")
                term.close()

    def test_continue_then_install_in_one_cell_stops_on_confirm(self):
        repo = self.repo()
        term = self.start()
        term.wait("Where to install?")
        term.send("\r")
        term.wait("> Install")
        row = self.line_of(term, "Choose systems")
        self.click(term, 20, row)
        term.settle()
        self.click(term, 20, row)
        term.wait("RetroBIOS: Choose systems")
        row = self.line_of(term, "sony-playstation")
        self.click(term, 20, row)
        term.settle()
        col, line = self.bar_entry(term, "Done")
        report = sgr(col + 1, line + 1) + sgr(col + 1, line + 1, release=True)
        # A double tap: the first goes back to the plan, the second lands on
        # its Back inside the settle time and does nothing.
        time.sleep(install.TUI_TAP_SETTLE)
        term.send(report + report)
        screen = term.wait("for 1 of 2 systems")
        screen = term.settle(0.6)
        self.assertIn("RetroBIOS: RetroArch", screen)
        self.assertEqual(repo.installed(), [])
        # Install on the plan counts the choice on Confirm, which waits.
        col, line = self.bar_entry(term, "Install")
        report = sgr(col + 1, line + 1) + sgr(col + 1, line + 1, release=True)
        time.sleep(install.TUI_TAP_SETTLE)
        term.send(report + report)
        term.wait("Counted again for these choices")
        screen = term.settle(0.6)
        self.assertIn("RetroBIOS: Confirm", screen)
        self.assertEqual(repo.installed(), [])
        # A tap made later installs: Confirm is the look before the install.
        time.sleep(install.TUI_TAP_SETTLE)
        term.send(report)
        term.wait("files installed")
        self.assertNotEqual(repo.installed(), [])
        term.send("q")
        term.close()

    def test_the_game_data_row_keeps_the_ticks_to_the_install(self):
        from test_install_tui import GameDataRepository  # noqa: PLC0415

        repo = self.repo(GameDataRepository)
        term = self.start()
        term.wait("Where to install?")
        term.send("\r")
        term.wait("> Install")
        for _step in range(8):
            if "> Choose systems" in term.settle():
                break
            term.send("\x1b[B")
        term.send("\r")
        term.wait("RetroBIOS: Choose systems")
        term.send("n")
        for _step in range(8):
            if "> [ ] nintendo-gba" in term.settle():
                break
            term.send("\x1b[B")
        term.send(" ")
        term.settle()
        term.send("\x1b")
        term.wait("> Install")
        for _step in range(8):
            if "> Game data: kept" in term.settle():
                break
            term.send("\x1b[B")
        term.send("\r")
        term.wait("Game data: left out")
        for _step in range(8):
            if "> Install" in term.settle():
                break
            term.send("\x1b[A")
        term.send("\r")
        # The changed choices are counted again on Confirm, which has no
        # Install row until its dry run ends: Enter sent on the title alone
        # fell on "Counting the files" and did nothing on a slow runner.
        term.wait("Counted again for these choices")
        term.settle()
        term.send("\r")
        term.wait("files installed")
        self.assertEqual(repo.installed(), ["gba_bios.bin", "mgba/extra.bin"])
        term.send("q")
        term.close()

    def test_two_taps_on_a_region_untick_it_where_it_was(self):
        self.repo()
        term = self.start()
        term.wait("Where to install?")
        term.send("\r")
        term.wait("> Install")
        term.send("o")
        term.wait("Preferred regions")
        term.send("\r")
        term.wait("RetroBIOS: Preferred regions")
        row = self.line_of(term, "North America")
        self.click(term, 20, row)
        screen = term.settle()
        self.assertIn("[1] North America", screen.splitlines()[row])
        self.click(term, 20, row)
        screen = term.settle()
        self.assertIn("[ ] North America", screen.splitlines()[row])
        self.assertNotIn("[1]", screen)
        term.send("q")
        term.close()


class ChoiceStateInBothModes(unittest.TestCase):
    """One choice state in both modes, the
    cards found first, packs that hold nothing, and words that fit."""

    setUp = LineModeAndScreenDecideAlike.setUp
    line_run = LineModeAndScreenDecideAlike.line_run
    listing = LineModeAndScreenDecideAlike.listing
    entry = staticmethod(LineModeAndScreenDecideAlike.entry)
    receive = staticmethod(OneChoicePerRun.receive)
    game_manifest = OneChoicePerRun.game_manifest
    game_events = OneChoicePerRun.game_events
    game_plan = OneChoicePerRun.game_plan

    @staticmethod
    def screen(state: install.TuiState, cols: int = 80, rows: int = 24) -> str:
        return " ".join(" ".join(str(line).split())
                        for line in install.tui_view(state, cols, rows))

    def toggle_game_data(self, state: install.TuiState) -> None:
        rows = install.tui_rows(state)
        state.focus["plan"] = next(index for index, row in enumerate(rows)
                                   if row.action == "gamedata")
        self.assertEqual(install.tui_update(state, Key("enter")), [("run", "check")])
        self.receive(state, self.game_events(self.game_manifest(),
                                             left_out=state.no_game_data))

    def test_the_game_data_toggle_never_unticks_a_system_for_good(self):
        """DS and Dreamcast ticked, game data left out
        then kept: Dreamcast was gone, and so was the row to turn it back."""
        state = self.game_plan()
        state.ticked = {"nintendo-ds", "sega-dreamcast"}
        self.toggle_game_data(state)
        self.assertEqual(state.ticked, {"nintendo-ds"})
        self.assertIn("for 1 of 2 systems", self.screen(state))
        row = next(row for row in install.tui_rows(state) if row.action == "gamedata")
        self.assertEqual((row.label, row.right), ("Game data: left out", "2 files, 2.0 KB"))
        self.toggle_game_data(state)
        self.assertEqual(state.ticked, {"nintendo-ds", "sega-dreamcast"})
        self.assertIn("for 2 of 3 systems", self.screen(state))
        # Line mode, the same choice: c, the two systems, g twice.
        manifest = self.game_manifest()
        listing = self.listing("retroarch", [
            self.entry(entry["dest"], b"x" * entry["size"], entry["systems"],
                       **({"category": entry["category"]} if "category" in entry else {}))
            for entry in manifest["files"]], categorized=True)
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False, dry_run=True),
                                     ["c", "1,2", "g", "g"])
        self.assertIn("for 1 of 2 systems", text)
        self.assertIn("for 2 of 3 systems", text.rsplit("for 1 of 2 systems", 1)[1])

    def game_listing(self) -> Path:
        manifest = self.game_manifest()
        return self.listing("retroarch", [
            self.entry(entry["dest"], b"x" * entry["size"], entry["systems"],
                       **({"category": entry["category"]} if "category" in entry else {}))
            for entry in manifest["files"]], categorized=True)

    def test_line_mode_offers_no_enter_for_an_emptied_choice(self):
        """Dreamcast alone, game data left out: line mode
        said "0 files, 0 B, for 0 of 2 systems", offered Enter and a command
        that installs nothing, then refused the Enter."""
        text, asked = self.line_run(_args(manifest=self.game_listing(), dest=self.here,
                                          declared_only=False),
                                    ["c", "2", "g", ""])
        menu = text.rsplit("Counted again for these choices", 1)[1]
        self.assertIn("RetroArch: sega-dreamcast holds only game data: nothing is left to "
                      "install.", menu)
        self.assertNotIn("0 files, 0 B", menu)
        self.assertNotIn("Enter)", menu)
        self.assertNotIn("Same choice without questions", menu)
        # Enter is not an answer here: asked again, never refused after.
        self.assertIn("Type c, f, g or q.", menu)
        self.assertEqual(asked[-1], "> ")

    def test_a_kept_choice_in_place_offers_no_install(self):
        """One system ticked, its files in place, the
        plan said "About 0 files" over Install, and Confirm "Everything is
        in place" over Install too."""
        state = checked_state()
        state.ticked = {"nintendo-famicom-disk"}
        text = self.screen(state)
        self.assertIn("(ファミコン) is in place: nothing is left to install.", text)
        self.assertNotIn("About 0 files", text)
        actions = [row.action for row in install.tui_rows(state)]
        self.assertNotIn("install", actions)
        self.assertEqual(actions[0], "systems")
        # Confirm counted nothing to install: Close, never Install.
        state.stack.append("confirm")
        state.dry = {**CHECK, "present": 1, "missing": 0, "wrong_hash": 0,
                     "bytes_needed": 0, "files": 1}
        state.dry_files = []
        self.assertEqual([row.action for row in install.tui_rows(state)], ["close", "back"])
        install.tui_update(state, Key("enter"))
        self.assertEqual(state.exit_code, 0)

    def test_offline_the_plan_counts_the_systems_ticked(self):
        """Offline, one system ticked, the plan counted
        every file of the list beside "For your 1 of 3 systems"."""
        state = checked_state()
        folder = str(self.root / "from1")
        state.from_folders = [self.root / "from1"]
        state.found = [found("gba_bios.bin", folder)]
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            state.ticked = {"nintendo-gba"}
            text = self.screen(state, 100, 40)
            self.assertIn("About 1 file, 16.0 KB, for 1 of 3 systems ", text)
            self.assertNotIn("found in from1", text)
            self.assertNotIn("Run the installer again", text)
            state.ticked = {"sony-playstation"}
            text = self.screen(state, 100, 40)
        self.assertIn("3 files need the internet, which RETROBIOS_INSTALL_OFFLINE=1 does not "
                      "use, for 1 of 3 systems", text)
        self.assertNotIn("About 0 files", text)

    def easyroms(self, name: str = "EASYROMS") -> Path:
        """A handheld's games part as a computer mounts it, with the folders
        its system writes there (install._GAMES_PART_RULES): ArkOS's
        EASYROMS, AmberELEC's GAMES."""
        return games_part(self.root / "media" / name)

    def test_an_arkos_card_is_found_and_comes_first(self):
        """An EASYROMS partition mounted, "Nothing was
        found here", and two presses of Enter filled this computer's
        ~/.config/retroarch/system for a RetroArch that was not there. An
        AmberELEC GAMES is AmberELEC's own card."""
        for name in ("EASYROMS",):
            with self.subTest(card=name):
                card = self.easyroms(name)
                home = self.root / "home"
                with mock.patch.object(install, "_mounted_cards", return_value=[card]), \
                        mock.patch.object(install, "detect_platforms", return_value=[]), \
                        mock.patch.object(install, "detect_frontends", return_value=[]), \
                        mock.patch.object(install.Path, "home", return_value=home):
                    state, _effects = install.tui_start(_args(), "linux")
                    text = self.screen(state)
                    # Named on the first screen, its plan one Enter away.
                    self.assertIn(f"> ArkOS SD card ({name}", text)
                    self.assertNotIn("Nothing was found here", text)
                    install.tui_update(state, Key("enter"))
                    self.assertEqual(state.dest, card / "bios")
                    self.assertEqual(state.platform, "retroarch")
                    install.tui_update(state, Key("enter"))
                self.assertEqual(state.dest, card / "bios")
                shutil.rmtree(card)

    def lacking_pack(self, held: list[tuple[str, bytes]]) -> Path:
        pack_dir = self.root / "downloads"
        pack_dir.mkdir(exist_ok=True)
        pack = pack_dir / "RetroArch_BIOS_Pack.zip"
        with zipfile.ZipFile(pack, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"files": []}))
            for dest, payload in held:
                archive.writestr(dest, payload)
        return pack

    def test_line_mode_names_what_the_pack_lacks_before_its_plan(self):
        """--dry-run promised 23 files, --check said to
        fetch them, the install counted 23 beside the size of 20 and advised
        retrying files that always fail."""
        files = [self.entry(f"bios{n}.bin", b"x" * (n + 1), ["nintendo-gba"])
                 for n in range(4)]
        listing = self.listing("retroarch", files)
        pack = self.lacking_pack([("bios0.bin", b"x")])
        dest = self.root / "card" / "system"
        common = dict(manifest=listing, from_pack=[pack], dest=dest, declared_only=False,
                      no_input=True)
        text, _asked = self.line_run(_args(**common, dry_run=True), [])
        lacks = "3 of these 4 files are not in RetroArch_BIOS_Pack.zip"
        self.assertIn(lacks, text)
        self.assertLess(text.index(lacks), text.index("Would copy"))
        self.assertIn("Would copy 1 file (1 B) from the pack", text)
        text, _asked = self.line_run(_args(**common, check=True), [])
        self.assertIn(lacks, text)
        self.assertNotIn("to fetch them", text)
        self.assertIn("to copy 1 of them from RetroArch_BIOS_Pack.zip", text)
        options = ("--platform", "retroarch", "--manifest", str(listing), "--dest", str(dest),
                   "--yes", "--verbose")
        proc = install_run(*options, "--from-pack", str(pack))
        text = proc.stdout + proc.stderr
        self.assertIn("Copying 1 file (1 B) from RetroArch_BIOS_Pack.zip...", text)
        self.assertNotIn("retry only those", text)
        self.assertIn("RetroArch_BIOS_Pack.zip does not hold them: a newer pack", text)
        # A pack holding none: no copy, no folder.
        shutil.rmtree(dest.parent, ignore_errors=True)
        proc = install_run(*options, "--from-pack", str(self.lacking_pack([])))
        text = proc.stdout + proc.stderr
        self.assertNotIn("Copying 0 files", text)
        self.assertIn("RetroArch_BIOS_Pack.zip does not hold them", text)
        self.assertFalse(dest.exists())

    def test_a_pack_holding_none_offers_no_install_with_data_files(self):
        """Data files left, the pack holding none of the
        files nor the trees: Install was offered and failed every file, and
        the result never named the data files."""
        state = checked_state()
        state.check = {**state.check, "data_missing": 7, "data_bytes": 2048}
        state.manifest = {**MANIFEST, "data_directories": [
            {"ref": "dolphin", "dest": "dolphin-emu/Sys", "files": {}}]}

        class Empty:
            name = "RetroArch_BIOS_Pack.zip"
            members: dict = {}

            @staticmethod
            def find(entry: dict) -> None:
                return None

            @staticmethod
            def tree(prefix: str):
                return iter(())

        with mock.patch.object(install.LOCAL, "pack", Empty()):
            actions = [row.action for row in install.tui_rows(state)]
            self.assertNotIn("install", actions)
            self.assertEqual(actions[0], "fromcard")
            text = self.screen(state)
            self.assertIn("RetroArch_BIOS_Pack.zip holds none of these 11 files", text)
            # The result of an install run anyway names them.
            state.stack = ["result"]
            state.summary = {"installed": 0, "up_to_date": 0, "pending": 4, "kept": [],
                             "failed": [{"dest": event["dest"], "reason": "not in the pack"}
                                        for event in state.files]}
            state.code = 2
            _title, lines = install.tui_outcome(state)
        self.assertIn("7 data files not installed: not in RetroArch_BIOS_Pack.zip.", lines)

    @in_full
    def test_a_command_at_40_columns_breaks_between_shell_words(self):
        """The terminal folded commands inside a word,
        "--platform" ended a line with its value on the next."""
        words = ["--platform", "retroarch", "--dest", "/a/b/c/system", "--manifest",
                 "/home/moi/x.json", "--system", "nintendo-gba"]
        text = "printf '%s\\n' " + " ".join(words)
        with mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": "sh"}):
            lines = install._wrap(text, 38, whole="command")
        self.assertGreater(len(lines), 1)
        self.assertTrue(all(install.cell_width(line) <= 38 for line in lines), lines)
        self.assertTrue(all(line.endswith(" \\") for line in lines[:-1]), lines)
        for line in lines:
            # An option never ends a line without its value.
            self.assertFalse((line[:-2] if line.endswith(" \\") else line).rstrip().endswith(
                ("--platform", "--dest", "--manifest", "--system")), lines)
        # The shell reads the lines as the command: the same words.
        proc = subprocess.run(["sh", "-c", "\n".join(lines)], capture_output=True, text=True,
                              check=True)
        self.assertEqual(proc.stdout.split(), words)
        # A path wider than a line keeps its last folders, said so, and the
        # address of the one-liner is never cut.
        state = _installed_state(Path("/home/moi/retroarch_system/tmp/tui_audit14/sb/a/b/bios"))
        state.summary["kept"] = [{"folder": "/home/moi/retroarch_system/tmp/tui_audit14/sb/"
                                            "retrobios-backup/2026", "files": 1, "bytes": 1}]
        with mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": "sh"}):
            screen = [str(line) for line in install.tui_view(state, 40, 40)]
        self.assertTrue(all(install.cell_width(line) <= 40 for line in screen), screen)
        self.assertIn(install.TUI_SHORTENED, " ".join(screen))
        self.assertIn(install.BOOTSTRAP_URL, " ".join(screen))
        state.exit_code = 0
        farewell = "\n".join(install.tui_farewell(state))
        self.assertIn("/home/moi/retroarch_system/tmp/tui_audit14/sb/a/b/bios", farewell)

    @in_full
    def test_a_folder_on_its_own_line_has_one_indent(self):
        """The save folder at the label's indent, the
        BIOS folder under it, a path's last piece without its indent."""
        state = checked_state()
        state.dest = Path("/home/moi/retroarch_system/tmp/tui_audit14/sb/esmiyoo/home/"
                          ".config/retroarch/system")
        state.saves = {"files": 1, "folder": "/home/moi/retroarch_system/tmp/tui_audit14/"
                                             "sb/and2/storage/RetroArch/saves/<core>"}
        for cols in (40, 80):
            with self.subTest(cols=cols):
                lines = [str(line) for line in install.tui_view(state, cols, 40)]
                folder = next(i for i, line in enumerate(lines) if "BIOS folder:" in line)
                under = next(i for i, line in enumerate(lines) if "under:" in line)
                for at in (folder, under):
                    pieces = []
                    for line in lines[at + 1:]:
                        if not line.strip() or "/" not in line or " " in line.strip():
                            break
                        pieces.append(line)
                    indents = {len(piece) - len(piece.lstrip()) for piece in pieces}
                    self.assertLessEqual(len(indents), 1, pieces)
                    if pieces:
                        self.assertEqual(indents, {3}, pieces)

    def test_no_shift_where_there_is_no_shift_key(self):
        """"Shift and a drag" on Android."""
        for os_type, said in (("linux", True), ("android", False)):
            with self.subTest(os_type=os_type):
                state = _installed_state(SYSTEM_DIR)
                state.os_type, state.mouse = os_type, True
                _title, lines = install.tui_outcome(state)
                self.assertEqual(any("Shift" in line for line in lines), said)
                self.assertIn(install.TUI_RESULT_AGAIN, lines[-1])
                state.help = True
                text = " ".join(install.tui_view(state, 80, 24))
                self.assertEqual("Shift+drag" in text, said)

    def test_the_40x12_setup_never_ends_mid_sentence(self):
        state = fresh_state()
        state.notes = [install.TUI_ESDE_NOTE]
        text = [str(line).strip() for line in install.tui_view(state, 40, 12)]
        self.assertIn(install.TUI_ESDE_SHORT, text)
        self.assertFalse(any(line.startswith("ES-DE found") for line in text), text)
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn(install.TUI_ESDE_NOTE, text)

    def test_the_40x12_plan_keeps_its_folder_and_version_note(self):
        """The plan named ~/.var/app/ as the folder, and
        the version note was absent."""
        state = checked_state()
        state.dest = HOME / ".var/app/org.libretro.RetroArch/config/retroarch/system"
        state.version = "This list was built for RetroBat 8.3.1, this machine runs 8.2.0.1."
        lines = [str(line).strip() for line in install.tui_view(state, 40, 12)]
        joined = "".join(line for line in lines if line.endswith("/") or "system" in line)
        self.assertIn("~/.var/app/org.libretro.RetroArch/config/retroarch/system", joined)
        self.assertIn(state.version, " ".join(" ".join(lines).split()))
        self.assertTrue(any(re.fullmatch(r"1-\d+ of \d+", line) for line in lines), lines)
        self.assertIn("> Install", lines)

    def test_one_count_said_once_in_both_modes(self):
        """"22 files installed." over "22 files copied
        from packx.", and line mode's Location, wrong hash and zero count."""
        state = _installed_state(SYSTEM_DIR)
        state.summary["installed"] = 5
        state.finished = [(f"f{n}.bin", True, "") for n in range(5)]
        state.local_dests = {f"f{n}.bin": ("/media/packx", "") for n in range(5)}
        _title, lines = install.tui_outcome(state)
        self.assertEqual(lines[0], "5 files copied from packx.")
        self.assertNotIn("5 files installed.", lines)
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"])]
        listing = self.listing("retroarch", files)
        proc = install_run("--platform", "retroarch", "--manifest", str(listing),
                           "--dest", str(self.here), "--check", "--offline", "--verbose")
        self.assertIn("0 in place, 1 missing, 0 wrong copies", proc.stdout)
        self.assertNotIn("present (", proc.stdout)
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        self.assertNotIn('say(f"Location', source)
        self.assertNotIn("already up to date.\")\n", source.split("\nDone.", 1)[-1][:300])

    def test_quit_names_stay_once(self):
        """"A/Enter Stay  B/Esc Stay"."""
        state = fresh_state()
        state.stack.append("quit")
        state.focus["quit"] = 1
        self.assertEqual(str(install.tui_view(state, 80, 24)[-1]).count("Stay"), 1)

    def test_the_yes_stop_example_keeps_yes(self):
        """A script copying the example stopped at a
        question."""
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"])]
        listing = self.listing("retroarch", files)
        proc = install_run("--yes", "--manifest", str(listing), "--offline",
                           env={"HOME": str(self.root / "home"), "RETROBIOS_OS": "linux"})
        example = next(line for line in proc.stderr.splitlines()
                       if "--platform retroarch --dest" in line)
        self.assertIn(" --yes", example)

    def test_the_systems_question_fits_the_terminal(self):
        """53 of 66 rows wider than 80 columns."""
        rows = [(f"system-{n}", [{"dest": f"{n}.bin", "size": 10 ** n}]) for n in range(6)]
        labels = {"system-0": "Sega Dreamcast-based arcade boards, each "
                              "them  sega-dreamcast-arcade",
                  **{f"system-{n}": f"Short {n}" for n in range(1, 6)}}
        with mock.patch.object(install.shutil, "get_terminal_size",
                               return_value=os.terminal_size((80, 24))), \
                mock.patch.object(install, "_ask", return_value=""), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            install._pick("Systems:", rows, labels=labels)
        printed = out.getvalue().splitlines()
        self.assertTrue(all(install.cell_width(line) <= 80 for line in printed), printed)
        # The long label on its own line, its size under it in the column.
        at = next(i for i, line in enumerate(printed) if "sega-dreamcast-arcade" in line)
        self.assertNotIn("B", printed[at].split("arcade", 1)[1])
        sizes = {line.index("1 file") for line in printed[at + 1:] if "1 file" in line}
        self.assertEqual(len(sizes), 1, printed)

    def test_the_save_dir_sentence_is_written_once(self):
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        self.assertEqual(source.count('"Name it with --save-dir next time."'), 1)
        self.assertEqual(source.count("args.declared_only or len(files) + game_data_cut"), 1)

    def test_a_missing_folder_does_not_exist_yet_on_every_row(self):
        """Line mode said "(created)" of folders nobody
        created, and the screen said "does not exist yet" of the Windows row
        alone."""
        drives = [self.root / "media" / "D", self.root / "media" / "E"]
        for drive in drives:
            drive.mkdir(parents=True)
        (drives[1] / "bios").mkdir()
        with mock.patch.object(install, "_mounted_cards", return_value=drives), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "_ask", return_value="q"), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.suppress(SystemExit):
            install.ask_platform_folder("linux", "retroarch")
        text = out.getvalue()
        self.assertNotIn(", created)", text)
        self.assertNotIn("(created)", text)
        self.assertIn(f"D: bios (drive, {drives[0] / 'bios'}, does not exist yet)", text)
        self.assertIn(f"E: bios (drive, {drives[1] / 'bios'})\n", text)
        state = fresh_state()
        state.platform = "retroarch"
        with mock.patch.object(install, "_mounted_cards", return_value=drives):
            install._open_folder_screen(state, SYSTEM_DIR)
            labels = [row.label for row in install.tui_rows(state) if row.action == "drive"]
        self.assertEqual(labels, ["D: bios (drive, does not exist yet)", "E: bios (drive)"])

    def test_line_mode_puts_the_arkos_card_first(self):
        card = self.easyroms()
        text, asked = self.line_run(_args(manifest=self.game_listing(), dry_run=True,
                                          declared_only=False), [""], mounts=[card])
        # Found as the screen finds it, under Enter.
        self.assertIn(f"Found ArkOS at {card / 'bios'} (RetroArch files)", text)
        self.assertNotIn("Nothing was found here", text)
        self.assertIn("Enter for ArkOS SD card (EASYROMS)", asked[0])
        self.assertIn(f"BIOS folder: {card / 'bios'}", text)



class DriveIsACardByItsFiles(unittest.TestCase):
    """A drive is a handheld's card only by
    the files its system writes, one settle from the frame shown, one
    vocabulary and one count per run, and the focus after an action."""

    setUp = LineModeAndScreenDecideAlike.setUp
    line_run = LineModeAndScreenDecideAlike.line_run
    listing = LineModeAndScreenDecideAlike.listing
    entry = staticmethod(LineModeAndScreenDecideAlike.entry)
    receive = staticmethod(OneChoicePerRun.receive)
    game_manifest = OneChoicePerRun.game_manifest
    game_events = OneChoicePerRun.game_events
    game_plan = OneChoicePerRun.game_plan
    game_listing = ChoiceStateInBothModes.game_listing
    screen = staticmethod(ChoiceStateInBothModes.screen)

    def drive(self, name: str, folders: tuple) -> Path:
        root = self.root / "media" / name
        for folder in folders:
            (root / folder).mkdir(parents=True)
        return root

    def first_screen(self, mounts: list) -> install.TuiState:
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install.Path, "home", return_value=self.root / "home"):
            state, _effects = install.tui_start(_args(), "linux")
        return state

    def folder_screen(self, mounts: list) -> tuple[install.TuiState, str, list]:
        """RetroArch chosen on the first screen: (state, Which folder? at
        80x40, its rows)."""
        state = self.first_screen(mounts)
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            install.tui_update(state, Key("enter"))
            self.assertEqual(state.screen, "folder")
            return state, self.screen(state, 80, 40), install.tui_rows(state)

    def test_a_data_drive_or_a_stick_is_no_card(self):
        """A data drive holding bios/, snes/ and Music/
        was "a card in the reader", and three presses of Enter put the list
        on it. A stick with bios/ alone is no card either: both are listed,
        never under Enter, and a plain line says why."""
        data = self.drive("DATA", ("bios", "snes", "Music"))
        stick = self.drive("STICK", ("bios",))
        mounts = [data, stick]
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            self.assertEqual(install.unproven_drives(), [data, stick])
        state = self.first_screen(mounts)
        self.assertEqual(state.setups, [])
        self.assertIn("Nothing was found here", self.screen(state))
        state, text, rows = self.folder_screen(mounts)
        self.assertNotIn(rows[0].value, (data / "bios", stick / "bios"))
        self.assertIn(self.UNPROVEN_TWO, text)
        self.assertIn(data / "bios", [row.value for row in rows])
        text, asked = self.line_run(_args(manifest=self.game_listing(), dry_run=True,
                                          declared_only=False), ["1", ""], mounts=mounts)
        self.assertNotIn("in the reader", text)
        self.assertIn(self.UNPROVEN_TWO, text)
        self.assertIn("Enter for the default above", asked[-2])
        self.assertNotIn(f"BIOS folder: {data / 'bios'}", text)

    # The note on drives with a bios folder and no handheld's folder.
    UNPROVEN_TWO = ("DATA and STICK have a bios folder but no folder a handheld system "
                    "writes. Pick one below if the BIOS files go there.")
    UNPROVEN_ONE = ("DATA has a bios folder but no folder a handheld system writes. Pick "
                    "it below if the BIOS files go there.")

    def test_the_layouts_handhelds_write_are_cards(self):
        """ArkOS's EASYROMS, AmberELEC's GAMES and EmuELEC's EEROMS, each
        with the folders its own image writes there. ArkOS's reads
        RetroArch's list, the two others are their systems' own cards."""
        arkos = games_part(self.root / "media" / "EASYROMS")
        amber = games_part(self.root / "media" / "GAMES")
        emuelec = self.drive("EEROMS", ("bios", "nes", "bezels"))
        (emuelec / "bezels" / "default.cfg").write_text("")
        mounts = [arkos, amber, emuelec]
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            self.assertEqual([install.games_part(mount).name for mount in mounts],
                             ["ArkOS", "AmberELEC", "EmuELEC"])
            # The three are their systems' own cards.
            self.assertEqual([install.card_system(mount) for mount in mounts],
                             [("retroarch", arkos / "bios", "ArkOS"),
                              ("amberelec", amber, "AmberELEC"),
                              ("emuelec", emuelec, "EmuELEC")])
            # One of these the system calls fixed is a disk, not a card.
            with mock.patch.object(install, "_drive_not_removable", return_value=True):
                self.assertEqual([install.card_system(mount) for mount in mounts],
                                 [None, None, None])

    def test_a_dest_on_a_games_part_reads_its_rom_folders(self):
        """--dest EASYROMS/bios --for-games from a computer: detection never
        ran on the card, the generic RetroArch folders were tried, and the
        run kept every file of the list."""
        arkos = games_part(self.root / "media" / "EASYROMS")
        index = {"setups": {"arkos": {}, "retroarch": {}}}
        with mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "_drive_not_removable", return_value=False):
            self.assertEqual(install.games_setups(index, "retroarch", arkos / "bios"), ["arkos"])
            self.assertEqual(install.games_setups(index, "retroarch", self.root / "bios"),
                             ["retroarch"])
            # Its games are offered without --for-games: EASYROMS keeps no
            # roms folder, its console folders sit beside bios.
            self.assertTrue(install._may_hold_games(arkos / "bios"))

    def test_a_card_beside_a_data_drive_comes_first(self):
        """The ArkOS card and the data drive mounted,
        the data drive sorted first and took Enter. The card comes first in
        both modes, the drive listed after it with its note."""
        data = self.drive("DATA", ("bios", "snes", "Music"))
        card = games_part(self.root / "media" / "EASYROMS")
        mounts = [data, card]
        state = self.first_screen(mounts)
        # The card is the setup found, under Enter.
        text = self.screen(state)
        self.assertIn("> ArkOS SD card (EASYROMS", text)
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            install.tui_update(state, Key("enter"))
        self.assertEqual(state.dest, card / "bios")
        text, asked = self.line_run(_args(manifest=self.game_listing(), dry_run=True,
                                          declared_only=False), [""], mounts=mounts)
        self.assertIn("Enter for ArkOS SD card (EASYROMS)", asked[0])
        self.assertIn(f"BIOS folder: {card / 'bios'}", text)

    def test_two_cards_are_spoken_of_in_the_plural(self):
        """"Cards are in the reader (DATA, EASYROMS):
        choose its system", then "The card in the reader" of one of two."""
        arkos = games_part(self.root / "media" / "EASYROMS")
        second = games_part(self.root / "media" / "ROMS2")
        mounts = [arkos, second]
        state = self.first_screen(mounts)
        # Each card its folders prove is a setup found, by its own name.
        text = self.screen(state)
        self.assertIn("ArkOS SD card (EASYROMS", text)
        self.assertIn("ArkOS SD card (ROMS2", text)
        text, asked = self.line_run(_args(manifest=self.game_listing(), dry_run=True,
                                          declared_only=False), [], mounts=mounts)
        self.assertIn("1) ArkOS SD card (EASYROMS", text)
        self.assertIn("2) ArkOS SD card (ROMS2", text)
        self.assertNotIn("in the reader", text)

    def test_a_fixed_partition_is_told_from_a_card(self):
        """Every mount under /media and /mnt, and on
        Windows every drive letter, was a card. A whole partition of a disk
        sysfs calls fixed is not, a USB or MMC one is, a folder bound in
        place says nothing, and Windows answers by GetDriveTypeW."""
        sys_root = self.root / "sys"
        devices = sys_root / "devices"
        for disk, part, removable in (("pci0/nvme0n1", "nvme0n1p2", "0"),
                                      ("pci0/usb2/2-1/sdb", "sdb1", "0"),
                                      ("mmc0/mmcblk0", "mmcblk0p1", "0"),
                                      ("pci0/sdc", "sdc1", "1")):
            (devices / disk / part).mkdir(parents=True)
            (devices / disk / part / "partition").write_text("1\n")
            (devices / disk / "removable").write_text(f"{removable}\n")
        block = sys_root / "dev" / "block"
        block.mkdir(parents=True)
        for number, target in (("259:2", "pci0/nvme0n1/nvme0n1p2"),
                               ("8:17", "pci0/usb2/2-1/sdb/sdb1"),
                               ("179:1", "mmc0/mmcblk0/mmcblk0p1"),
                               ("8:33", "pci0/sdc/sdc1")):
            (block / number).symlink_to(devices / target)
        mountinfo = "\n".join([
            "40 1 259:2 / /media/me/DATA rw - ext4 /dev/nvme0n1p2 rw",
            "41 1 8:17 / /media/me/EASYROMS rw - vfat /dev/sdb1 rw",
            "42 1 179:1 / /media/me/GAMES rw - exfat /dev/mmcblk0p1 rw",
            "43 1 8:33 / /media/me/STICK rw - vfat /dev/sdc1 rw",
            "44 1 259:2 /home/me/cards/X /media/me/BOUND rw - ext4 /dev/nvme0n1p2 rw",
            "45 1 0:74 / /mnt/d rw - 9p D:\\134 rw"])
        told = {name: install._fixed_partition(Path(point), mountinfo, sys_root)
                for name, point in (("DATA", "/media/me/DATA"), ("USB", "/media/me/EASYROMS"),
                                    ("MMC", "/media/me/GAMES"), ("STICK", "/media/me/STICK"),
                                    ("BOUND", "/media/me/BOUND"), ("WSL", "/mnt/d"),
                                    ("unmounted", "/media/me/NONE"))}
        self.assertEqual(told, {"DATA": True, "USB": False, "MMC": False, "STICK": False,
                                "BOUND": False, "WSL": False, "unmounted": False})
        for kind, fixed in ((2, False), (3, True), (4, True)):
            kernel = types.SimpleNamespace(GetDriveTypeW=lambda root, kind=kind: kind)
            fake = types.SimpleNamespace(windll=types.SimpleNamespace(kernel32=kernel))
            with mock.patch.object(install.os, "name", "nt"), \
                    mock.patch.dict(sys.modules, {"ctypes": fake}):
                self.assertEqual(install._drive_not_removable(PureWindowsPath("D:\\")), fixed)


# install.py whose tui_view takes SLOW seconds on the first frame of each
# screen, as a slower device takes to lay one out.
SLOW_VIEW = """
import os, sys, time
sys.argv[0] = {install!r}
sys.path.insert(0, {repo!r})
import install
slow = float(os.environ["SLOW"])
real, seen = install.tui_view, [None]
def view(state, cols, rows):
    key = (state.screen, len(state.stack))
    if key != seen[0]:
        seen[0] = key
        time.sleep(slow)
    return real(state, cols, rows)
install.tui_view = view
sys.exit(install.main())
"""


@unittest.skipUnless(pyte and pty and hasattr(pty, "fork"),
                     "screen tests need pyte (pip install pyte==0.8.2) and a pty")
class TheSettleRunsFromTheFrameShown(unittest.TestCase):
    """The settle was stamped before the layout, so on
    a slow one the second click of a double click on Options' Back reached
    the plan's Quit."""

    repo = EndToEnd.repo
    bar_entry = TapsOnAPtySeeFirst.bar_entry

    def test_a_double_click_on_back_stays_on_the_plan_after_a_slow_layout(self):
        repo = self.repo()
        wrapper = repo.root / "slowview.py"
        wrapper.write_text(SLOW_VIEW.format(install=str(REPO_ROOT / "install.py"),
                                            repo=str(REPO_ROOT)))
        env = {**self.env, "SLOW": "0.5"}
        term = Pty([], env, 80, 24, program=[sys.executable, str(wrapper)])
        self.addCleanup(lambda: term.status is None and os.kill(term.pid, 9))
        term.wait("Where to install?")
        term.send("\r")
        term.wait("> Install")
        term.settle()
        term.send("o")
        term.wait("RetroBIOS: Options")
        term.settle()
        time.sleep(1.0)
        col, line = self.bar_entry(term, "Back")
        report = sgr(col + 1, line + 1) + sgr(col + 1, line + 1, release=True)
        os.write(term.fd, report.encode())
        time.sleep(0.2)
        os.write(term.fd, report.encode())
        time.sleep(1.0)
        screen = term.settle(0.6)
        self.assertNotIn("Quit?", screen)
        self.assertIn("RetroBIOS: RetroArch", screen.splitlines()[0])
        self.assertEqual(repo.installed(), [])
        term.send("q")
        if "Quit?" in term.settle():
            term.send("\r")
        term.close()


class OnePowerShellRule(unittest.TestCase):
    """The words of a command asked RETROBIOS_BOOTSTRAP
    or the detected system, its line ends RETROBIOS_BOOTSTRAP or os.name:
    with RETROBIOS_OS=windows on Linux one command had PowerShell's quotes
    and sh's line ends, and pasted into either shell it broke."""

    def test_the_words_and_the_line_ends_read_one_rule(self):
        cases = ((None, "windows", True), ("sh", "windows", False), ("ps1", "linux", True),
                 (None, "linux", False), ("sh", "linux", False))
        for bootstrap, os_type, powershell in cases:
            with self.subTest(bootstrap=bootstrap, os_type=os_type):
                hint = install.Invocation()
                hint.os_type, hint.options = os_type, [("--system", "it's")]
                env = {key: value for key, value in os.environ.items()
                       if key != "RETROBIOS_BOOTSTRAP"}
                if bootstrap:
                    env["RETROBIOS_BOOTSTRAP"] = bootstrap
                with mock.patch.dict(os.environ, env, clear=True):
                    self.assertEqual(hint.powershell(), powershell)
                    text = hint.command("retroarch", Path("/home/me/My Games/bios"))
                    # Line mode's wrap reads the run's Invocation, the
                    # screen's the one that made its command.
                    with mock.patch.object(install, "_INVOCATION", hint):
                        wrapped = install._command_wrap(text, 40)
                    drawn = [str(line) for line in install._text_lines(
                        [install._command_line(text, hint)], 40)]
                for lines in (wrapped, drawn):
                    lines = [line for line in lines if line.strip()]
                    ends = {line.rstrip()[-1] for line in lines[:-1]}
                    self.assertEqual(ends, {"`" if powershell else "\\"})
                    words = " ".join(lines)
                    self.assertIn("'it''s'" if powershell else shlex.quote("it's"), words)


class EachDataTreeReadOnce(unittest.TestCase):
    """The count line, the check, the events and the
    install each read and hashed every data tree in place, twice per run
    on an SD card through a reader."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.dest = self.root / "bios"
        bios = b"bios bytes"
        (self.dest / "gba_bios.bin").parent.mkdir(parents=True)
        (self.dest / "gba_bios.bin").write_bytes(bios)
        trees = []
        for ref, files, held in (("dolphin-sys", {"Sys/a.bin": b"a", "Sys/b.bin": b"bb"}, 2),
                                 ("ppsspp", {"assets/c.bin": b"ccc", "assets/d.bin": b"d"}, 1)):
            for rel, data in list(files.items())[:held]:
                (self.dest / ref / rel).parent.mkdir(parents=True, exist_ok=True)
                (self.dest / ref / rel).write_bytes(data)
            trees.append({"ref": ref, "dest": ref, "type": "zip",
                          "url": f"https://example.invalid/{ref}.zip",
                          "systems": ["nintendo-gba"],
                          "files": {rel: {"sha1": hashlib.sha1(data).hexdigest(),
                                          "size": len(data)} for rel, data in files.items()}})
        self.list = self.root / "retroarch.json"
        self.list.write_text(json.dumps({
            "manifest_version": 2, "platform": "retroarch", "data_directories": trees,
            "files": [{"dest": "gba_bios.bin", "sha1": hashlib.sha1(bios).hexdigest(),
                       "size": len(bios), "repo_path": "bios/gba_bios.bin", "cores": None,
                       "systems": ["nintendo-gba"]}]}))

    def test_each_tree_is_hashed_once_per_run(self):
        real = install.data_directory_state
        for mode in ("check", "events", "dry_run", "yes"):
            with self.subTest(mode=mode):
                calls = []

                def counted(entry, bios_path, calls=calls):
                    calls.append(entry["ref"])
                    return real(entry, bios_path)

                given = {"events": True, "check": True} if mode == "events" else {mode: True}
                stream = io.StringIO() if mode == "events" else None
                with mock.patch.object(install, "data_directory_state", counted), \
                        mock.patch.object(install.EVENTS, "stream", stream), \
                        mock.patch.object(install, "detect_os", return_value="linux"), \
                        mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
                        contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()), \
                        contextlib.suppress(SystemExit):
                    try:
                        install._install(_args(platform="retroarch", dest=self.dest,
                                               manifest=self.list, no_input=True,
                                               declared_only=False, **given), io.StringIO())
                    finally:
                        install.LOCAL.reset()
                self.assertEqual(sorted(calls), ["dolphin-sys", "ppsspp"])


class OneVocabularyOneCount(unittest.TestCase):
    """Line mode said "in
    place" then "up to date", "wrong copies" then "wrong hash", counted
    twice, left the data files out of its last line, and the screen focused
    Install for a pack holding none of the files."""

    setUp = LineModeAndScreenDecideAlike.setUp
    line_run = LineModeAndScreenDecideAlike.line_run
    listing = LineModeAndScreenDecideAlike.listing
    entry = staticmethod(LineModeAndScreenDecideAlike.entry)
    screen = staticmethod(ChoiceStateInBothModes.screen)

    def two_files(self) -> tuple[Path, Path, Path]:
        """A list of two files, the first in place, the second in an old
        folder: (list, BIOS folder, old folder)."""
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"]),
                 self.entry("scph5501.bin", b"psx bytes", ["sony-playstation"])]
        listing = self.listing("retroarch", files)
        dest = self.root / "bios"
        dest.mkdir()
        (dest / "gba_bios.bin").write_bytes(b"gba")
        old = self.root / "OLD"
        old.mkdir()
        (old / "scph5501.bin").write_bytes(b"psx bytes")
        return listing, dest, old

    def run_line(self, listing: Path, dest: Path, answers: list, **given) -> str:
        # --verbose's text: the counts compared are lines the default leaves out.
        given.setdefault("verbose", True)
        from_ = given.pop("from_", None)
        args = _args(manifest=listing, dest=dest, declared_only=False, **given)
        if from_:
            given["from_"] = from_
        if "from_" in given:
            setattr(args, "from", given.pop("from_"))
        # Offline as the variable makes it: no request leaves the test. The
        # end of the run is written to the stdout the run was given.
        given_answers = iter(answers)

        def answer(prompt: str) -> str:
            try:
                return next(given_answers)
            except StopIteration:
                raise _Decided(prompt) from None

        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        invocation = install.Invocation()
        invocation.os_type = "linux"
        invocation.record(args)
        end = io.StringIO()
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
                mock.patch.object(install, "_INVOCATION", invocation), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(install, "_is_terminal", return_value=True), \
                mock.patch.object(install, "_ask", side_effect=answer), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                contextlib.suppress(_Decided, SystemExit):
            install._install(args, end)
        return out.getvalue() + err.getvalue() + end.getvalue()

    def test_the_line_mode_words_are_the_screens(self):
        listing, dest, old = self.two_files()
        (old / "scph5501.bin").rename(dest / "scph5501.bin")
        for given in ({"no_input": True}, {"check": True}, {"dry_run": True}):
            with self.subTest(**given):
                text = self.run_line(listing, dest, [""], offline=True, **given)
                self.assertIn("2 in place, 0 missing, 0 wrong copies", text)
                self.assertIn("Every file on the list is in place", text)
                self.assertNotIn("up to date", text)
                self.assertNotIn("0 files installed", text)
        state = checked_state()
        state.stack = ["result"]
        state.summary = {"installed": 0, "up_to_date": 2, "pending": 0, "kept": [],
                         "failed": []}
        state.code = 0
        _title, lines = install.tui_outcome(state)
        self.assertEqual(lines[0], "Every file on the list is in place.")

    def test_check_names_a_wrong_copy_as_such(self):
        listing, dest, _old = self.two_files()
        (dest / "scph5501.bin").write_bytes(b"other")
        text = self.run_line(listing, dest, [], check=True, offline=True)
        self.assertIn("1 in place, 0 missing, 1 wrong copy", text)
        self.assertIn("wrong copy: scph5501.bin", text)
        self.assertNotIn("wrong hash", text)
        self.assertNotIn("A file with a", text)

    def test_line_mode_with_from_counts_once(self):
        """No found count before Enter, the
        plan said again after it, Copying twice, the result's count twice,
        and no command on a Finished with files missing."""
        listing, dest, old = self.two_files()
        (dest / "gba_bios.bin").unlink()
        text = self.run_line(listing, dest, [""], from_=[old], offline=True)
        menu, after = text.split("\nChecking existing files...", 1)
        self.assertIn("RetroArch: 1 found in OLD, 1 needs the internet.", menu)
        self.assertNotIn("2 files (", after)
        self.assertEqual(after.count("Copying"), 1, after)
        self.assertIn(f"Finished with files missing. 1 file copied from {old}, "
                      "1 still missing.", after)
        self.assertNotIn("installed,", after)
        self.assertIn("Same choice without questions:", after)
        # Every file found: one count, as the screen's "22 files copied
        # from packx."
        (dest / "scph5501.bin").unlink()
        (old / "gba_bios.bin").write_bytes(b"gba")
        text = self.run_line(listing, dest, [""], from_=[old], offline=True)
        menu, after = text.split("\nChecking existing files...", 1)
        self.assertIn("RetroArch: 2 found in OLD, nothing to download.", menu)
        self.assertIn(f"Done. 2 files copied from {old}.", after)
        self.assertNotIn("files installed", after)

    def test_the_last_offline_line_counts_the_data_files(self):
        """"0 in place, 10994 missing", then "Nothing
        installed: 8358 files need the internet"."""
        listing, dest, _old = self.two_files()
        listed = json.loads(listing.read_text())
        listed["data_directories"] = [{
            "ref": "bluemsx", "dest": "", "type": "zip",
            "url": "https://example.invalid/blueMSX.zip", "systems": ["nintendo-gba"],
            "files": {f"Machines/{n}.txt": {"sha1": hashlib.sha1(b"%d" % n).hexdigest(),
                                            "size": 1} for n in range(2)}}]
        listing.write_text(json.dumps(listed))
        text = self.run_line(listing, dest, [""], offline=True)
        self.assertIn("1 in place, 3 missing, 0 wrong copies", text)
        self.assertIn("Nothing installed: 3 files need the internet", text)

    @in_full
    def test_a_pack_holding_none_offers_no_install(self):
        """A data tree whose folder is the BIOS folder
        itself (blueMSX) made any pack hold a data file: Install focused,
        and the result counted 8252 failed beside 10888 missing."""
        pack = self.root / "RetroArch_BIOS_Pack.zip"
        with zipfile.ZipFile(pack, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"files": []}))
            archive.writestr("other-system.bin", b"x")
        state = checked_state()
        state.check = {**state.check, "data_missing": 2, "data_bytes": 2}
        state.manifest = {**MANIFEST, "data_directories": [
            {"ref": "bluemsx", "dest": "", "files": {
                "Machines/a.txt": {"sha1": "0" * 40, "size": 1},
                "Machines/b.txt": {"sha1": "0" * 40, "size": 1}}}]}
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        install.LOCAL.pack = install.PackSource([pack])
        rows = install.tui_rows(state)
        self.assertNotIn("install", [row.action for row in rows])
        self.assertEqual(rows[state.focus.get("plan", 0)].action, "fromcard")
        text = self.screen(state)
        self.assertIn("RetroArch_BIOS_Pack.zip holds none of these 6 files", text)
        self.assertIn("1 in place, 5 missing, 1 wrong copy", text)


class FocusAfterAnAction(unittest.TestCase):
    """One tap on the focused
    Install row armed nothing visible, the result's Put RetroBIOS on this
    card was cut at 40x12, the Game data row lost the focus once changed,
    and a choice already in place opened on Options."""

    @staticmethod
    def row_of(lines: list, action: str) -> int:
        return next(index for index, line in enumerate(lines)
                    if getattr(line, "mark", None) and line.mark[0] == "row"
                    and line.mark[2][0] == action)

    def test_one_tap_on_the_focused_install_row_arms_it_visibly(self):
        for cols, rows in ((80, 24), (40, 12)):
            with self.subTest(size=(cols, rows)):
                state = checked_state()
                state.mouse = True
                lines = drawn(state, cols, rows)
                row = self.row_of(lines, "install")
                self.assertTrue(str(lines[row]).lstrip().startswith("> Install"))
                self.assertEqual(tap(state, 4, row), [])
                armed = drawn(state, cols, rows)
                self.assertIn(install.TUI_ARMED_SHORT, str(armed[-1]))
                self.assertIn(install.TUI_ARMED_SHORT, str(armed[row]))
                self.assertEqual(armed[row].style, "focus")
                painted = install.tui_paint(str(armed[-1]), "hint", True)
                self.assertIn(f"{install.COLOUR_ROLES['accent']}m", painted)
                # The second tap, on the row or on the bar, installs.
                self.assertEqual(tap(state, 4, row), [("run", "install")])

    def test_a_row_armed_then_the_bar_installs_and_a_key_disarms(self):
        state = checked_state()
        state.mouse = True
        lines = drawn(state, 80, 24)
        tap(state, 4, self.row_of(lines, "install"))
        drawn(state, 80, 24)
        self.assertEqual(tap(state, 2, len(lines) - 1), [("run", "install")])
        state = checked_state()
        state.mouse = True
        lines = drawn(state, 80, 24)
        tap(state, 4, self.row_of(lines, "install"))
        install.tui_update(state, Key("down"))
        install.tui_update(state, Key("up"))
        self.assertNotIn(install.TUI_ARMED_SHORT, " ".join(map(str, drawn(state, 80, 24))))

    def test_put_retrobios_on_this_card_fits_40x12(self):
        """The result offering the app, drawn and tapped as the loop does
        (tui_view, tui_hits, tui_mouse), at 40x12 and 80x24: no line cut
        inside a word, the armed bar whole, one Exit on the bar and the
        help naming B as the bar does."""
        root, bios = _app_card(self, "muOS")
        for cols, rows in ((40, 12), (80, 24)):
            with self.subTest(size=(cols, rows)):
                state = _installed_state(bios)
                state.mouse = True
                with mock.patch.object(install, "_tui_app_ready", return_value=True):
                    lines = drawn(state, cols, rows)
                    text = [str(line).rstrip() for line in lines]
                    row = self.row_of(lines, "addapp")
                    offer = text[row].strip()
                    self.assertIn(offer, ("Put RetroBIOS on this card",
                                          install.APP_OFFER))
                    self.assertEqual(text[-1].split(), ["A/Enter", "Exit"]
                                     if cols >= install.TUI_LONG_BAR_WIDTH else ["A", "Exit"])
                    # One tap focuses the row: a second puts the app on the
                    # card, which the row and the bar say, B kept.
                    tap(state, 4, row)
                    armed = [str(line).rstrip() for line in drawn(state, cols, rows)]
                    self.assertTrue(armed[row].lstrip().startswith("> Put"))
                    self.assertIn("Exit", armed[-1])
                    self.assertIn("B/Esc" if cols >= install.TUI_LONG_BAR_WIDTH else "B",
                                  armed[-1].split())
                    self.assertIn(f"{install.TUI_ARMED_SHORT}  B", armed[-1])
                    self.assertTrue(armed[row].strip().endswith(install.TUI_ARMED_SHORT),
                                    armed[row])
                    for line in (*armed, *text):
                        self.assertLessEqual(install.cell_width(line), cols)
                        self.assertFalse(line.endswith(("aga", "fro", "(update f")), line)
                    state.tapped = None
                    install.tui_update(state, Key("f1"))
                    help_text = " ".join(" ".join(str(line).split())
                                         for line in drawn(state, cols, rows))
                    self.assertIn("Exit", help_text)
                    self.assertNotIn("Backspace Quit", help_text)
                    install.tui_update(state, Key("f1"))

    def test_the_game_data_row_keeps_the_focus_when_changed(self):
        audit = OneChoicePerRun()
        state = audit.game_plan()
        rows = install.tui_rows(state)
        state.focus["plan"] = next(i for i, row in enumerate(rows) if row.action == "gamedata")
        for left_out, expected in ((True, "Game data: left out"), (False, "Game data: kept")):
            self.assertEqual(install.tui_update(state, Key("enter")), [("run", "check")])
            audit.receive(state, audit.game_events(audit.game_manifest(), left_out=left_out))
            rows = install.tui_rows(state)
            self.assertEqual(rows[state.focus["plan"]].label, expected)

    def test_a_choice_already_in_place_opens_on_choose_systems(self):
        state = checked_state()
        state.focus["plan"] = next(i for i, row in enumerate(install.tui_rows(state))
                                   if row.action == "systems")
        install.tui_update(state, Key("enter"))
        self.assertEqual(state.screen, "systems")
        state.ticked_before = set(state.ticked)
        state.ticked = {"nintendo-famicom-disk"}
        with mock.patch.object(install, "_choice_in_place", return_value="in place"):
            install.tui_update(state, Key("esc"))
            self.assertEqual(state.screen, "plan")
            rows = install.tui_rows(state)
            self.assertEqual(rows[state.focus["plan"]].label, "Choose systems")


class TextThatFits(unittest.TestCase):
    """A pack's name cut in a
    command, folder lines at two indents, the 40x12 plan dropping the
    version note, and the --from plan without its kinds."""

    def test_a_pack_path_keeps_its_name_whole(self):
        pack = "/home/user/Downloads/RetroArch_BIOS_Pack.zip"
        text = ("curl -fsSL https://abdess.github.io/retrobios/i | sh -s -- --platform "
                f"retroarch --dest /media/moi/ONION/BIOS --from-pack {pack} --offline")
        for width in (38, 50, 78):
            with self.subTest(width=width), \
                    mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": "sh"}):
                lines = install._command_wrap(text, width)
                joined = " ".join(lines)
                self.assertIn("RetroArch_BIOS_Pack.zip", joined)
                self.assertNotRegex(joined, r"\.\.\.[^/ ]*Pack\.zip")
                for line in lines:
                    self.assertLessEqual(install.cell_width(line), width, line)

    def test_a_folder_on_its_own_line_keeps_one_indent(self):
        base = "/home/me/very/long/folder/names/for/an/android/storage/RetroArch"
        items = [f"BIOS folder: {base}/system",
                 "1 file read from RetroArch's save directory goes to a folder per core:",
                 f"  {base}/saves"]
        for width in (38, 70, 78):
            for whole in (False, True):
                with self.subTest(width=width, whole=whole):
                    lines = [str(line) for line in install._text_lines(items, width, whole)]
                    folders = [line for line in lines if "/" in line
                               and not line.startswith("BIOS folder:")]
                    self.assertTrue(folders)
                    for line in folders:
                        self.assertEqual(len(line) - len(line.lstrip(" ")), 2, lines)

    def test_the_40x12_plan_keeps_the_version_note(self):
        state = checked_state()
        state.dest = Path("/home/moi/retroarch_system/tmp/tui_audit15/rb2/bios")
        install.tui_receive(state, ("event", state.run_id, {
            "event": "version", "platform": "retroarch", "list_version": "1.22.2",
            "installed_version": "1.21.0",
            "message": "This list was built for RetroArch 1.22.2, this machine runs 1.21.0. "
                       "Some files may differ from what this version reads."}))
        state.run = "check"
        narrow = " ".join(" ".join(str(line).split())
                          for line in install.tui_view(state, 40, 12))
        self.assertIn("List for RetroArch 1.22.2, this is 1.21.0.", narrow)
        self.assertIn("BIOS folder:", narrow)
        wide = " ".join(" ".join(str(line).split()) for line in install.tui_view(state, 80, 24))
        self.assertIn("This list was built for RetroArch 1.22.2, this machine runs 1.21.0.", wide)


class TheFromPlanSaysItsKinds(unittest.TestCase):
    """Every file found in the folder, the plan named
    the Game data row and said neither the kinds nor what game data is."""

    @in_full
    def test_the_kinds_and_the_definition_stay(self):
        audit = OneChoicePerRun()
        state = audit.game_plan()
        folder = "/media/moi/packx"
        state.from_folders = [Path(folder)]
        state.found = [found(event["dest"], folder) for event in state.files
                       if event["state"] != "present"]
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            text = " ".join(" ".join(str(line).split())
                            for line in install.tui_view(state, 80, 24))
        self.assertIn("found in packx, nothing to download", text)
        self.assertIn("2 BIOS files", text)
        self.assertIn("3 game data files", text)
        self.assertIn("Game data: files a game or a game engine reads", text)
        self.assertNotIn("Not in packx", text)


class TheSystemsQuestionFits(unittest.TestCase):
    """The size column was placed
    for the longest size, so 60 of 66 systems took two lines and 26 still
    passed 80 columns."""

    def question(self, cols: int) -> list[str]:
        manifest = json.loads((REPO_ROOT / "install" / "retroarch.json").read_text())
        files = manifest["files"]
        systems = install.systems_in_order(install.listed_systems(files), files, manifest,
                                           None)
        out = io.StringIO()
        with mock.patch.object(install.shutil, "get_terminal_size",
                               return_value=os.terminal_size((cols, 24))), \
                mock.patch.object(install, "_ask", return_value=""), \
                contextlib.redirect_stdout(out):
            install._choose_narrowing(files, [], manifest, None)
        text = out.getvalue()
        # Up to the question that follows it, the cores' or none.
        ends = [at for at in (text.find("\nCores:"), text.find("\nThe platform's own"))
                if at >= 0]
        return (text[text.index("Systems:"):min(ends, default=len(text))].splitlines(),
                systems, files)

    def test_the_question_fits_80_and_40_columns(self):
        for cols in (80, 40):
            with self.subTest(cols=cols):
                lines, systems, files = self.question(cols)
                numbered = [line for line in lines if re.match(r" +\d+\) ", line)]
                self.assertEqual(len(numbered), len(systems))
                for line in lines:
                    self.assertLessEqual(install.cell_width(line), cols, line)
                shared = sum(1 for system in systems if "shared" in install._system_sized(
                    [f for f in files if install._chosen(f, {system})]))
                # One line a system, a second for its shared files: the
                # 80-column question took 127 lines for 66 systems.
                # At 40 columns a shared size takes a line more: its first
                # part alone was printed beside a long name, the shared
                # files unsaid.
                limit = (len(systems) + shared + 10 if cols == 80
                         else 2 * len(systems) + shared + 12)
                self.assertLessEqual(len(lines), limit)
                for line, after in zip(lines, lines[1:] + [""]):
                    if line.rstrip().endswith(","):
                        self.assertTrue(after.startswith(" ") and not re.match(
                            r" +\d+\) ", after), (cols, line, after))

    def test_a_row_that_fits_keeps_one_line(self):
        lines, _systems, _files = self.question(80)
        row = next(index for index, line in enumerate(lines) if "Amstrad CPC" in line)
        self.assertIn("4 files, 112.0 KB", lines[row])
        self.assertTrue(re.match(r" +\d+\) ", lines[row + 1]))


class ProvenCardsAndCounts(unittest.TestCase):
    """A card its markers prove is that
    system's card everywhere, counts and states that tell the truth, one
    width for every layout, line mode's order and words as the screen's,
    and a tap that shows it was seen."""

    setUp = LineModeAndScreenDecideAlike.setUp
    line_run = LineModeAndScreenDecideAlike.line_run
    listing = LineModeAndScreenDecideAlike.listing
    entry = staticmethod(LineModeAndScreenDecideAlike.entry)
    both = LineModeAndScreenDecideAlike.both
    drive = DriveIsACardByItsFiles.drive
    first_screen = DriveIsACardByItsFiles.first_screen
    folder_screen = DriveIsACardByItsFiles.folder_screen
    game_listing = ChoiceStateInBothModes.game_listing
    game_manifest = OneChoicePerRun.game_manifest
    receive = staticmethod(OneChoicePerRun.receive)
    screen = staticmethod(ChoiceStateInBothModes.screen)

    def amberelec(self, name: str = "GAMES") -> Path:
        return games_part(self.root / "media" / name)

    def emuelec(self, name: str = "EEROMS") -> Path:
        card = self.drive(name, ("bios", "nes", "bezels"))
        (card / "bezels" / "default.cfg").write_text("")
        return card

    def line_from(self, args: argparse.Namespace, answers: list,
                  folders: list[Path] = ()) -> tuple[str, list]:
        """(text, prompts) of line mode at a terminal, the result included,
        the folders --from names read first, as main() reads them: --verbose's
        text."""
        args.verbose = True
        given, asked = iter(answers), []

        def answer(prompt: str) -> str:
            asked.append(prompt)
            try:
                return next(given)
            except StopIteration:
                raise _Decided(prompt) from None

        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        if folders:
            setattr(args, "from", [str(folder) for folder in folders])
        invocation = install.Invocation()
        invocation.os_type = "linux"
        invocation.record(args)
        stream = io.StringIO()
        with mock.patch.object(install, "_INVOCATION", invocation), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(install, "_is_terminal", return_value=True), \
                mock.patch.object(install, "_ask", side_effect=answer), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                contextlib.suppress(_Decided, SystemExit):
            install._install(args, stream)
        return out.getvalue() + err.getvalue() + stream.getvalue(), asked

    # Root cause 1: a card its markers prove is that system's card.

    def test_a_games_part_is_its_systems_card_in_both_modes(self):
        """The GAMES card AmberELEC's folders prove, and
        the EEROMS card EmuELEC's prove, read "A card is in the reader:
        choose its system" with RetroArch focused, and two presses of Enter
        put RetroArch's list on them."""
        for plat, name, make in (("amberelec", "AmberELEC", self.amberelec),
                                 ("emuelec", "EmuELEC", self.emuelec)):
            with self.subTest(system=name):
                card = make()
                state = self.first_screen([card])
                text = self.screen(state)
                self.assertIn(f"{name} SD card ({card.name})", text)
                self.assertNotIn("in the reader", text)
                self.assertIn(f"BIOSfolder:{card / 'bios'}", "".join(text.split()))
                (line, screen, said) = self.both([card], [])
                self.assertEqual(line, (plat, card))
                self.assertEqual(screen, (plat, card))
                self.assertIn(f"Found {name}", said)
                shutil.rmtree(card)

    def test_their_own_routes_take_the_card_they_prove(self):
        """--platform amberelec said it "cannot tell an
        AmberELEC card by its files" of the card holding gamedata/ and
        homebrew/, and line mode offered no Enter for it."""
        for plat, name, make in (("amberelec", "AmberELEC", self.amberelec),
                                 ("emuelec", "EmuELEC", self.emuelec)):
            with self.subTest(system=name):
                card = make()
                stick = self.drive(f"{name}STICK", ("bios",))
                with mock.patch.object(install, "_mounted_cards", return_value=[card, stick]), \
                        mock.patch.object(install, "_mount_points", return_value=frozenset()):
                    self.assertEqual(install.mounted_cards_of(name, plat), [card])
                    self.assertEqual(install.blank_cards_of(name, plat), [stick])
                    choice = install.card_choice(name, plat, card)
                    self.assertEqual((choice.refused, choice.folder), ("", card))
                    self.assertNotIn("cannot tell", choice.note)
                (line, screen, said) = self.both([card, stick], [], platform=plat)
                self.assertEqual(line, (plat, card))
                self.assertEqual(screen, (plat, card))
                self.assertIn(f"Found {name} at {card / 'bios'}", said)
                self.assertNotIn("cannot tell", said)
                # Asked for its card, the one its files prove is offered.
                with mock.patch.object(install, "_mounted_cards", return_value=[card, stick]), \
                        mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                        contextlib.redirect_stdout(io.StringIO()) as out:
                    dest = install.card_install_dest(name, plat, True, False)
                self.assertEqual(dest, card)
                self.assertIn(f"{name} card found at {card.name}", out.getvalue())
                with mock.patch.object(install, "_mounted_cards", return_value=[card, stick]), \
                        mock.patch.object(install, "_mount_points", return_value=frozenset()):
                    state = screen_keys(_args(platform=plat, declared_only=False), [])
                    view = " ".join(install.tui_view(state, 80, 24))
                self.assertNotIn("cannot tell", view)
                shutil.rmtree(card)
                shutil.rmtree(stick)

    def test_an_arkos_card_from_any_year_is_a_card(self):
        """ArkOS's default trees of 2020 hold no themes/
        (9664c869 none of themes and launchimages, 495eb210 and c14afbe5
        launchimages only), and the 12262020 update skipped the themes of a
        card with under 1 GB free. Every tree holds bgmusic/. A data drive
        holding neither stays no card."""
        layouts = {
            "ARK_9664c869": ("bios", "bgmusic", "ports", "snes", "System Volume Information"),
            "ARK_495eb210": ("bios", "bgmusic", "launchimages", "ports", "snes"),
            "ARK_c14afbe5": ("bios", "bgmusic", "launchimages", "psx"),
            "ARK_f41b9485": ("bios", "bgmusic", "launchimages", "themes", "backup", "nes"),
            "ARK_FULL1226": ("bios", "launchimages", "nes"),
        }
        cards = [self.drive(name, folders) for name, folders in layouts.items()]
        data = self.drive("DATA", ("bios", "snes", "Music", "themes"))
        music = self.drive("MUSIC", ("bgmusic", "launchimages"))
        mounts = [*cards, data, music]
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            self.assertEqual([install.card_system(card) for card in cards],
                             [("retroarch", card / "bios", "ArkOS") for card in cards])
            self.assertEqual([install.games_part(card).name for card in cards],
                             ["ArkOS"] * len(cards))
            self.assertIsNone(install.games_part(data))
            self.assertIsNone(install.games_part(music))
            self.assertEqual(install.unproven_drives(), [data])
            with mock.patch.object(install, "_drive_not_removable", return_value=True):
                self.assertEqual([install.card_system(card) for card in cards],
                                 [None] * len(cards))

    # Root cause 2: counts and states that tell the truth.

    def wrong_copy_run(self, answers: list) -> tuple[str, list, Path]:
        """An offline run whose BIOS folder holds a wrong copy of the right
        size of a.bin, a folder named with --from holding b.bin."""
        good_a, good_b = b"A" * 64, b"B" * 64
        listing = self.listing("retroarch", [self.entry("a.bin", good_a, ["nintendo-gba"]),
                                             self.entry("b.bin", good_b, ["nintendo-gba"])])
        dest = self.root / "dest"
        dest.mkdir()
        (dest / "a.bin").write_bytes(b"Z" * 64)
        old = self.root / "old"
        old.mkdir()
        (old / "b.bin").write_bytes(good_b)
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            text, asked = self.line_from(_args(manifest=listing, dest=dest, platform="retroarch",
                                               declared_only=False), answers, [old])
        return text, asked, dest

    def test_the_head_never_calls_a_wrong_copy_in_place(self):
        """A wrong copy of the right size was in place
        for the head, which said "1 found in old, nothing to download" over
        a run that left it."""
        text, _asked, dest = self.wrong_copy_run([""])
        self.assertIn("RetroArch: 1 found in old, 1 needs the internet.", text)
        self.assertNotIn("nothing to download", text)
        self.assertEqual((dest / "a.bin").read_bytes(), b"Z" * 64)

    def test_a_wrong_copy_left_is_said_as_one(self):
        """The result said "1 still missing" of a file
        --check counts as a wrong copy."""
        text, _asked, _dest = self.wrong_copy_run([""])
        self.assertIn("Finished with files missing.", text)
        self.assertIn("1 file copied from", text)
        self.assertIn(", 1 wrong copy left.", text)
        self.assertNotIn("still missing", text.rsplit("Finished", 1)[1])

    def test_a_count_agrees_with_its_verb(self):
        """"1 need the internet" on the plan, and on
        line mode's data tree line."""
        self.assertEqual(install.agree(1, "needs", "need"), "1 needs")
        self.assertEqual(install.agree(2, "needs", "need"), "2 need")
        self.assertEqual(install._plural(2, "wrong copy"), "2 wrong copies")
        self.assertEqual(install._plural(1, "wrong copy"), "1 wrong copy")
        self.assertEqual(install._plural(2, "day"), "2 days")
        state = checked_state()
        folder = "/media/OLD"
        state.from_folders = [Path(folder)]
        state.found = [found(dest, folder) for dest in ("scph5500.bin", "pcsx/extra.bin",
                                                        "gba_bios.bin")]
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            text = self.screen(state, 100, 30)
        self.assertIn("3 found in OLD, 1 needs the internet", text)
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        self.assertNotRegex(source, r"\} need the internet")

    def test_line_mode_says_what_is_still_missing_before_the_remedy(self):
        """"They are not in OLD" followed "Installed: 6
        BIOS files", where the screen puts "Still missing:" between them."""
        bios, game = b"B" * 32, b"G" * 32
        listing = self.listing("retroarch", [
            self.entry("a.bin", bios, ["nintendo-gba"]),
            self.entry("b.bin", b"C" * 32, ["nintendo-gba"]),
            self.entry("g.dat", game, ["sega-dreamcast"], category="game_data")],
            categorized=True)
        dest = self.root / "dest"
        dest.mkdir()
        old = self.root / "OLD"
        old.mkdir()
        (old / "a.bin").write_bytes(bios)
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            text, _asked = self.line_from(_args(manifest=listing, dest=dest,
                                                platform="retroarch", declared_only=False),
                                          [""], [old])
        end = text.rsplit("Finished with files missing", 1)[-1]
        self.assertIn("Still missing: 1 BIOS file and 1 game data file.", end)
        self.assertLess(end.index("Still missing:"), end.index(f"They are not in {old}"))
        self.assertLess(end.index("Installed:"), end.index("Still missing:"))

    def test_a_rerun_with_everything_in_place_offers_nothing(self):
        """Line mode offered "Enter) install what is
        found", then said "Everything is in place." twice."""
        data = b"A" * 64
        listing = self.listing("retroarch", [self.entry("a.bin", data, ["nintendo-gba"])])
        dest = self.root / "dest"
        dest.mkdir()
        (dest / "a.bin").write_bytes(data)
        text, asked = self.line_from(_args(manifest=listing, dest=dest, platform="retroarch",
                                           declared_only=False), [])
        self.assertEqual(asked, [])
        self.assertNotIn("Enter)", text)
        self.assertIn("RetroArch: 1 file, every one in place: nothing to install.", text)
        self.assertEqual(text.count(install.EVERYTHING_IN_PLACE), 1)

    def test_line_mode_names_the_files_it_cannot_supply(self):
        """"Not installable: 37 files (1 required, not
        found: 37)" read as a sum, and line mode never named the file the
        screen names, nor its folder."""
        listing = self.listing("retroarch", [
            self.entry("a.bin", b"A" * 8, ["nintendo-gba"])], categorized=True,
            omitted_files=[
                {"dest": "jazz2/Source/Anims.j2a", "name": "Anims.j2a",
                 "system": "jazz-jackrabbit-2", "required": True, "reason": "not_found",
                 "category": "game_data"},
                {"dest": "x.bin", "name": "x.bin", "system": "nintendo-gba",
                 "required": False, "reason": "not_found"}])
        dest = self.root / "dest"
        dest.mkdir()
        text, _asked = self.line_run(_args(manifest=listing, dest=dest, platform="retroarch",
                                           declared_only=False, dry_run=True), [])
        self.assertIn("Not available here: jazz2/Source/Anims.j2a (Jazz Jackrabbit 2), game "
                      "data its game reads. Copy it from an owned copy of the game into "
                      f"{dest / 'jazz2' / 'Source'}{os.sep}.", text)
        self.assertEqual(install.not_installable_words(37, 1, {"not_found": 37}),
                         "Not installable: 37 files are not in the collection, 1 of them "
                         "required.")
        self.assertEqual(install.not_installable_words(1, 1, {"not_found": 1}),
                         "Not installable: 1 file is not in the collection, required.")
        self.assertIn("Why: no save directory (2), not found (3).",
                      install.not_installable_words(5, 0, {"not_found": 3,
                                                           "no_save_directory": 2}))

    def test_a_system_emptied_by_no_game_data_is_named(self):
        """--system nintendo-ds,sega-dreamcast with
        --no-game-data: "For 1 of 8 systems (--system)", Dreamcast unsaid
        until after Enter."""
        manifest = self.game_manifest()
        words = (f"{install.system_title('sega-dreamcast', manifest)} holds only game data: "
                 "left out (--no-game-data).")
        listing = self.game_listing()
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False, dry_run=True,
                                           system=["nintendo-ds", "sega-dreamcast"],
                                           no_game_data=True), [])
        head = text.split("Enter)", 1)[0]
        self.assertIn(words, head)
        state = install.TuiState(os_type="linux", home=HOME)
        state.manifest = manifest
        state.no_game_data = True
        state.cli_systems = ["nintendo-ds", "sega-dreamcast"]
        state.systems = [{"system": "nintendo-ds", "name": "Nintendo DS", "files": 1,
                          "present": 0, "missing": 1, "wrong_hash": 0, "bytes_needed": 1}]
        state.ticked = {"nintendo-ds"}
        state.dest = self.here
        state.platform = "retroarch"
        state.check = {**CHECK, "files": 1, "present": 0, "missing": 1, "wrong_hash": 0}
        state.stack = ["plan"]
        self.assertIn(words, self.screen(state, 100, 40))

    def test_a_run_with_failures_counts_once(self):
        """"Done. 44 files installed." then "38 files
        copied from E:\\, 4 downloaded, 2 still missing." gave two counts,
        the two that failed as missing. Each mode says one, failures named."""
        out = io.StringIO()
        sources = install.sources_line([("/media/OLD", 38)], 0, 4, 0, failed=2)
        self.assertEqual(sources, "38 files copied from /media/OLD, 4 downloaded, 2 failed.")
        with contextlib.redirect_stdout(out), contextlib.suppress(SystemExit):
            install._report_outcome([self.here], 42, 0, 2, 0, False,
                                    failures=[("x.bin", "timed out"), ("y.bin", "timed out")],
                                    sources=sources)
        text = out.getvalue()
        self.assertIn(f"Finished with errors. {sources}", text)
        self.assertNotIn("42 files installed", text)
        self.assertNotIn("still missing", text)
        state = checked_state()
        state.from_folders = [Path("/media/OLD")]
        state.local_dests = {"gba_bios.bin": ("/media/OLD", "")}
        state.finished = [("gba_bios.bin", True, ""), ("scph5500.bin", False, "timed out")]
        state.stack, state.run = ["result"], "install"
        state.summary = {"event": "summary", "mode": "install", "installed": 1,
                         "up_to_date": 0, "pending": 1,
                         "failed": [{"dest": "scph5500.bin", "reason": "timed out"}],
                         "skipped": [], "left_out": [], "kept": [], "interrupted": False}
        title, lines = install.tui_outcome(state)
        self.assertEqual(title, "Finished with errors")
        self.assertEqual(lines[0], "1 file copied from OLD, 1 failed.")
        self.assertNotIn("1 installed, 1 failed.", lines)

    def test_check_never_says_a_missing_file_was_opened(self):
        """"missing: nintendo-ds_0.bin" then "opened at
        ..." read as a file that was opened."""
        entry = {"dest": "a.bin", "systems": ["nintendo-gba"], "cores": None}
        self.assertEqual(install.opened_line(entry, {}, self.here),
                         f"expected at {self.here / 'a.bin'}")
        named = {**entry, "cores": ["mgba"]}
        self.assertEqual(install.opened_line(named, {}, self.here),
                         f"read by mgba at {self.here / 'a.bin'}")

    # Root cause 3: one width with a floor.

    def test_a_terminal_of_no_size_has_the_fallback(self):
        """Python 3.8 gives a pty of no size as 0 and 0.
        The plan printed "0 systems, the largest first:" and the progress
        line lost every figure but its percentage."""
        with mock.patch.object(install.shutil, "get_terminal_size",
                               return_value=os.terminal_size((0, 0))):
            self.assertEqual(install.terminal_size(), (80, 24))
            out = io.StringIO()
            term = types.SimpleNamespace(live=True, quiet=False, stream=out,
                                         bold=str, dim=str)
            progress = install.Progress(1, 1400, term)
            progress.bytes = progress.files = 1400
            progress.files = 1
            progress._draw()
            self.assertIn("(1/1 files)", out.getvalue())
            self.assertIn("[####", out.getvalue())
            with contextlib.redirect_stdout(io.StringIO()) as plan:
                install._print_plan([], self.here, term, copied=["  1 file copied"])
            self.assertNotIn("the largest first", plan.getvalue())
        with mock.patch.object(install.shutil, "get_terminal_size",
                               return_value=os.terminal_size((8, 3))):
            self.assertEqual(install.terminal_size(), (install.LINE_MIN_COLS, 3))

    def systems_question(self, cols: int) -> list[str]:
        manifest = json.loads((REPO_ROOT / "install" / "retroarch.json").read_text())
        out = io.StringIO()
        with mock.patch.object(install.shutil, "get_terminal_size",
                               return_value=os.terminal_size((cols, 24))), \
                mock.patch.object(install, "_ask", return_value=""), \
                contextlib.redirect_stdout(out):
            install._choose_narrowing(manifest["files"], [], manifest, None)
        text = out.getvalue()
        ends = [at for at in (text.find("\nCores:"), text.find("\nThe platform's own"))
                if at >= 0]
        return text[text.index("Systems:"):min(ends, default=len(text))].splitlines()

    def test_the_systems_question_stays_inside_the_terminal(self):
        """6 lines of 81 cells at 80 columns, 16 of 41 at
        40, "shared" and "platform" alone on a line."""
        for cols in (100, 80, 60, 40, 30):
            with self.subTest(cols=cols):
                lines = self.systems_question(cols)
                for line in lines:
                    self.assertLess(install.cell_width(line), cols, line)
                    if line.strip() and not line.endswith(":"):
                        self.assertTrue(len(install._glued_words(line)) > 1
                                        or re.match(r" *\d+\) ", line), (cols, line))
                note = " ".join(line.strip() for line in lines[lines.index(
                    next(line for line in lines if line.startswith("'Other"))):])
                self.assertIn("this platform does not list", note)

    def test_the_setup_list_never_folds_inside_a_word(self):
        """At 39 columns "Miy" / "oo Flip"."""
        for cols in (80, 39, 30):
            with self.subTest(cols=cols):
                with mock.patch.object(install.shutil, "get_terminal_size",
                                       return_value=os.terminal_size((cols, 11))), \
                        mock.patch.object(install, "_install_standalone_folders",
                                          return_value=False):
                    text, _asked = self.line_run(_args(declared_only=False), [])
                block = text.split("Which setup?", 1)[1].split("  q) quit", 1)[0]
                lines = [line for line in block.splitlines() if line.strip()]
                self.assertTrue(lines)
                for line in lines:
                    self.assertLess(install.cell_width(line), cols, line)
                self.assertIn("Miyoo Flip", " ".join(" ".join(lines).split()))

    # Root cause 4: line mode in the screen's order and words.

    def test_on_wsl_the_card_comes_first_in_both_modes(self):
        """Line mode numbered Windows RetroArch 1) and
        the card 2), where the screen put the card first. One order for
        both: the other side first, then the drives (an ArkOS card is now a
        setup found)."""
        data = self.drive("DATA", ("bios", "snes"))
        windows = Path("/mnt/c/RetroArch-Win64/system")
        side = [("Windows RetroArch: C:\\RetroArch-Win64\\system", windows)]
        with mock.patch.object(install, "_mounted_cards", return_value=[data]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "other_side", return_value=side), \
                mock.patch.object(install, "_ask", return_value="q"), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.suppress(SystemExit):
            install.ask_platform_folder("wsl", "retroarch")
        state = self.first_screen([data])
        self.assertRegex(out.getvalue(), r"\n    1\) Windows RetroArch")
        self.assertRegex(out.getvalue(), r"\n    2\) DATA: bios \(drive")
        with mock.patch.object(install, "_mounted_cards", return_value=[data]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "other_side", return_value=side):
            state.os_type = "wsl"
            install.tui_update(state, Key("enter"))
            rows = [row for row in install.tui_rows(state) if row.action == "drive"]
        self.assertEqual([row.value for row in rows], [windows, data / "bios"])

    def test_nothing_found_is_said_once(self):
        """"Nothing was found here." twice, and after "A
        card is in the reader"."""
        # The standalone emulators' lists come from the network: none here.
        with mock.patch.object(install, "_install_standalone_folders", return_value=False):
            text, _asked = self.line_run(_args(declared_only=False), [])
        self.assertEqual(text.count("Nothing was found here."), 1)
        card = games_part(self.root / "media" / "EASYROMS")
        text, _asked = self.line_run(_args(declared_only=False), [], mounts=[card])
        # The card its folders prove is found.
        self.assertIn("ArkOS SD card (EASYROMS)", text)
        self.assertNotIn("Nothing was found here", text)

    def test_the_bios_only_drive_note_is_one_plain_sentence(self):
        """"listed, not chosen", "(card or drive)" under
        a note saying no card, two parentheses side by side, and "keeps
        them" after a title."""
        data = self.drive("DATA", ("bios", "snes", "Music"))
        stick = self.drive("STICK", ("bios",))
        mounts = [data, stick]
        state, text, rows = self.folder_screen(mounts)
        self.assertIn("DATA and STICK have a bios folder but no folder a handheld system "
                      "writes. Pick one below if the BIOS files go there.", text)
        labels = [row.label for row in rows]
        self.assertIn("DATA: bios (drive)", labels)
        self.assertIn("STICK: bios (drive)", labels)
        line, _asked = self.line_run(_args(manifest=self.game_listing(), dry_run=True,
                                           declared_only=False), ["1", ""], mounts=mounts)
        for said in (text, line):
            self.assertNotIn("listed, not chosen", said)
            self.assertNotIn("card or drive", said)
            self.assertNotIn(") (", said)
            self.assertNotIn("keeps them", said)

    def test_the_same_choice_is_one_command_in_both_modes(self):
        """The screen wrote --manifest before --from,
        line mode after it."""
        hint = install.Invocation()
        hint.os_type = "linux"
        hint.options = [("--from", "/media/OLD"), ("--offline", None),
                        ("--manifest", "/x/list.json"), ("--system", "a")]
        self.assertEqual(hint.command("retroarch", "/dest"),
                         "python3 install.py --platform retroarch --dest /dest --manifest "
                         "/x/list.json --system a --from /media/OLD --offline")
        state = checked_state()
        state.manifest_given, state.manifest_path = True, Path("/x/list.json")
        state.from_folders = [Path("/media/OLD")]
        args = _args(manifest="/x/list.json", platform="retroarch", dest=SYSTEM_DIR,
                     declared_only=False, offline=False)
        setattr(args, "from", ["/media/OLD"])
        line = install.Invocation()
        line.os_type = "linux"
        line.record(args)
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            line.options.append(("--offline", None))
            self.assertEqual(install.tui_command(state), line.command("retroarch", SYSTEM_DIR))

    # Root cause 5: interaction.

    def test_a_tap_on_a_focused_row_shows_it_was_seen(self):
        """One tap on the focused Onion row showed
        nothing, a second continued."""
        state = fresh_state()
        state.stack = ["setup"]
        state.mouse = True
        lines = drawn(state, 80, 24)
        row = next(index for index, line in enumerate(lines)
                   if str(line).lstrip().startswith("> "))
        self.assertEqual(tap(state, 4, row), [])
        lines = drawn(state, 80, 24)
        self.assertIn(f"A/Enter Continue: {install.TUI_ARMED}", str(lines[-1]))
        self.assertIn(f"RetroArch: {install.TUI_ARMED}", str(lines[row]))
        self.assertNotEqual(tap(state, 4, row), [])

    def test_a_phone_bar_names_the_enter_key(self):
        """Termux at 40 columns said "A Continue", and
        the a key does nothing."""
        state = install.TuiState(os_type="android", home=HOME)
        state.pad = install.tui_pad_route("android", {})
        self.assertEqual(state.pad, "both")
        bar = str(install.tui_view(state, 40, 12)[-1])
        self.assertIn("Enter", bar)
        self.assertNotRegex(bar, r"(^| )A ")
        self.assertIn("A/Enter", str(install.tui_view(state, 80, 24)[-1]))
        state.pad = "gptokeyb"
        self.assertRegex(str(install.tui_view(state, 40, 12)[-1]), r"(^| )A ")

    def test_which_folder_keeps_its_folder_at_40_by_12(self):
        """With two drives holding bios, Which folder?
        at 40x12 dropped the folder "Use this folder" stands for."""
        data = self.drive("DATA", ("bios", "snes", "Music"))
        stick = self.drive("STICK", ("bios",))
        for mounts in ([data, stick], [data]):
            with self.subTest(mounts=[mount.name for mount in mounts]):
                state, _text, _rows = self.folder_screen(mounts)
                with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                        mock.patch.object(install, "_mount_points", return_value=frozenset()):
                    small = " ".join(str(line) for line in install.tui_view(state, 40, 12))
                folder = str(state.folder_default)
                self.assertIn("reads its BIOS files", small)
                # The folder wraps after a separator wherever the temporary
                # path's length puts it, and a long one keeps its last
                # folders after "...": read its tail with the breaks out.
                tail = "/".join(Path(folder).parts[-2:])
                self.assertIn(tail, "".join(small.split()))

    # The owner's note: Cores drew every box empty when no core narrows the
    # run, read as "nothing is ticked, tick them all".

    def cores_screen(self, **given) -> install.TuiState:
        state = checked_state()
        state.cores = list(given.get("cores", []))
        state.cli_cores = list(state.cores)
        press(state, "o")
        state.focus["options"] = next(index for index, row in enumerate(
            install.tui_rows(state)) if row.action == "cores")
        press(state, "enter")
        self.assertEqual(state.screen, "cores")
        return state

    @staticmethod
    def boxes(state: install.TuiState) -> dict:
        return {row.value: row.label[:3] for row in install.tui_rows(state)
                if row.action == "core"}

    def test_cores_open_every_one_ticked(self):
        state = self.cores_screen()
        self.assertEqual(self.boxes(state), {"mesen": "[x]", "pcsx_rearmed": "[x]"})
        self.assertEqual(install.tui_rows(state)[state.focus["cores"]].value, "mesen")
        self.assertEqual(install.tui_flags(state), [])

    def test_one_untick_narrows_to_the_others(self):
        state = self.cores_screen()
        press(state, " ")
        self.assertEqual(self.boxes(state), {"mesen": "[ ]", "pcsx_rearmed": "[x]"})
        self.assertEqual(install.tui_flags(state), [("--core", "pcsx_rearmed")])
        press(state, " ")
        self.assertEqual(self.boxes(state), {"mesen": "[x]", "pcsx_rearmed": "[x]"})
        self.assertEqual(state.cores, [])
        press(state, " ", "esc")
        self.assertEqual(state.screen, "options")
        row = next(row for row in install.tui_rows(state) if row.action == "cores")
        self.assertEqual(row.label, "Cores: 1 of 2")
        state.stack = ["setup", "plan"]
        self.assertIn("1 of 2 cores", " ".join(install.tui_view(state, 100, 30)))

    def test_none_then_all_as_the_systems_list(self):
        state = self.cores_screen()
        rows = install.tui_rows(state)
        state.focus["cores"] = next(i for i, row in enumerate(rows) if row.action == "none")
        press(state, "enter")
        self.assertEqual(self.boxes(state), {"mesen": "[ ]", "pcsx_rearmed": "[ ]"})
        state.focus["cores"] = next(i for i, row in enumerate(rows) if row.action == "done")
        press(state, "enter")
        self.assertEqual(state.screen, "cores")
        self.assertIn("No core is ticked", str(state.status))
        state.focus["cores"] = next(i for i, row in enumerate(rows) if row.action == "all")
        press(state, "enter")
        self.assertEqual(self.boxes(state), {"mesen": "[x]", "pcsx_rearmed": "[x]"})
        self.assertEqual(install.tui_flags(state), [])

    def test_core_ticks_only_the_cores_it_names(self):
        state = self.cores_screen(cores=["pcsx_rearmed"])
        self.assertEqual(self.boxes(state), {"mesen": "[ ]", "pcsx_rearmed": "[x]"})
        state.stack = ["setup", "plan"]
        self.assertIn("--core", " ".join(install.tui_view(state, 100, 30)))

    def test_both_modes_count_the_cores_kept_alike(self):
        listing = self.listing("retroarch", [
            self.entry("a.bin", b"A" * 8, ["nintendo-gba"]),
            self.entry("m.bin", b"M" * 8, ["nintendo-gba"], cores=["mgba"]),
            self.entry("v.bin", b"V" * 8, ["nintendo-gba"], cores=["vba_next"]),
            self.entry("p.bin", b"P" * 8, ["sony-playstation"])])
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False, dry_run=True),
                                     ["c", "", "2"])
        self.assertIn("Every core's extra files are kept: Enter keeps them all", text)
        head = text.rsplit("Counted again for these choices", 1)[1]
        self.assertIn("1 of 2 cores", head)
        self.assertEqual(install.cores_words(0, 2), "0 of 2 cores")
        self.assertEqual(install.cores_words(2, 2), "all cores")

    # Root cause 6: the pages say what the installer shows.

    @unittest.skipIf(sys.version_info < (3, 9),
                     "the site generator needs Python 3.9")
    def test_which_pack_names_the_first_screen(self):
        """Which-pack said the command opens a screen
        where Install and Choose systems are, the second screen."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        self.addCleanup(sys.path.remove, str(REPO_ROOT / "scripts"))
        import generate_site  # noqa: PLC0415

        words = " ".join(generate_site.first_screen_words())
        found, nothing = fresh_state(), install.TuiState(os_type="linux", home=HOME)
        found.stack = ["setup"]
        self.assertIn(install.tui_view(found, 80, 24)[0].split(": ", 1)[1].strip(), words)
        self.assertIn(install.tui_view(nothing, 80, 24)[0].split(": ", 1)[1].strip(), words)
        self.assertLess(words.index(install.TUI_FOUND_TITLE),
                        words.index(install.TUI_INSTALL_ROW))
        self.assertNotIn("opens a screen", words)
        # Nothing found, Which folder? comes before the plan.
        self.assertIn(f"**{install.TUI_FOLDER_TITLE}**", words)
        self.assertLess(words.index(install.TUI_FOLDER_TITLE),
                        words.index(install.TUI_INSTALL_ROW))


def core_list(path: Path, files: list) -> Path:
    path.write_text(json.dumps({"manifest_version": 2, "platform": "retroarch",
                                "categorized": True, "base_destination": "system",
                                "save_directory": {"folder": "saves", "by_core": True},
                                "files": files}), encoding="utf-8")
    return path


class CoresListAndFolderFailures(unittest.TestCase):
    """The cores the run accepts, one tick
    list, a folder failure said as it happened, every proven card named,
    reads that show, and tests that leave the host alone."""

    setUp = LineModeAndScreenDecideAlike.setUp
    line_run = LineModeAndScreenDecideAlike.line_run
    entry = staticmethod(LineModeAndScreenDecideAlike.entry)
    drive = DriveIsACardByItsFiles.drive
    first_screen = DriveIsACardByItsFiles.first_screen
    line_from = ProvenCardsAndCounts.line_from

    # Root cause 1: the cores a choice is made among are the run's.

    def files(self) -> list:
        entry = self.entry
        return [
            entry("scph5501.bin", b"S" * 8, ["sony-playstation"]),
            entry("pcsx/extra.bin", b"P" * 4, ["sony-playstation"], cores=["pcsx_rearmed"]),
            entry("fc/disksys.rom", b"F" * 8, ["nintendo-famicom-disk"], cores=["mesen"]),
            # Read from the save directory alone: set aside where it is not known.
            entry("3ds/aes_keys.txt", b"K" * 4, ["nintendo-3ds"], cores=["azahar"],
                  root="save"),
            # Game data alone: --no-game-data leaves its core no file.
            entry("quake/pak0.pak", b"Q" * 4, ["other"], cores=["tyrquake"],
                  category="game_data"),
        ]

    def check_events(self, *extra: str) -> list:
        listing = core_list(self.root / "cores.json", self.files())
        dest = self.root / "dest"
        dest.mkdir(exist_ok=True)
        done = install_run("--platform", "retroarch", "--dest", str(dest), "--manifest",
                           str(listing), "--check", "--events", *extra,
                           env={"HOME": str(self.root / "home"),
                                "RETROBIOS_INSTALL_OFFLINE": "1"})
        return [json.loads(line) for line in done.stdout.splitlines() if line.startswith("{")]

    def cores_state(self, events: list, no_game_data: bool = False) -> install.TuiState:
        state = checked_state()
        state.manifest = {"manifest_version": 2, "platform": "retroarch", "categorized": True,
                          "files": self.files()}
        state.set_aside = set(next(event for event in events
                                   if event["event"] == "set_aside")["dests"])
        state.no_game_data = no_game_data
        return state

    def test_cores_lists_what_the_run_accepts_and_an_untick_runs(self):
        """Cores listed 189 cores where --core accepted 181,
        and an untick sent the 8 save-folder-only cores: "unknown core"."""
        events = self.check_events()
        self.assertEqual(next(e for e in events if e["event"] == "set_aside")["dests"],
                         ["3ds/aes_keys.txt"])
        state = self.cores_state(events)
        self.assertNotIn("azahar", install.tui_choices(state)["cores"])
        state.stack = ["setup", "plan", "options", "cores"]
        row = next(r for r in install.tui_rows(state) if r.value == "mesen")
        install._tick(state, row, False)
        cores = [value for flag, value in install.tui_flags(state) if flag == "--core"]
        self.assertEqual(sorted(cores), ["pcsx_rearmed", "tyrquake"])
        listing = self.root / "cores.json"
        done = install_run("--platform", "retroarch", "--dest", str(self.root / "dest"),
                           "--manifest", str(listing), "--dry-run",
                           *[f"--core={core}" for core in cores],
                           env={"HOME": str(self.root / "home"),
                                "RETROBIOS_INSTALL_OFFLINE": "1"})
        self.assertNotIn("unknown core", done.stdout + done.stderr)

    def test_both_modes_count_out_of_the_cores_the_run_keeps(self):
        """Line mode said "1 of 181 cores", the screen
        "1 of 189", and 22 more under --no-game-data."""
        for no_game_data in (False, True):
            with self.subTest(no_game_data=no_game_data):
                extra = ("--no-game-data",) if no_game_data else ()
                state = self.cores_state(self.check_events(*extra), no_game_data)
                expected = ["mesen", "pcsx_rearmed"] + ([] if no_game_data else ["tyrquake"])
                self.assertEqual(install.tui_choices(state)["cores"], expected)
                listing = core_list(self.root / "line.json", self.files())
                # A folder not named system: the save directory is not known.
                text, _asked = self.line_run(
                    _args(manifest=listing, dest=self.root / "dest", declared_only=False,
                          dry_run=True, no_game_data=no_game_data), ["c", "", "1"])
                head = text.rsplit("Counted again for these choices", 1)[1]
                self.assertIn(f"1 of {len(expected)} cores", head)
                state.cores = ["mesen"]
                self.assertIn(f"1 of {len(expected)}",
                              next(r.label for r in install.tui_rows(
                                  self.options(state)) if r.action == "cores"))

    @staticmethod
    def text(state: install.TuiState, cols: int, rows: int) -> str:
        """The frame drawn, its folded lines joined into one text."""
        return " ".join(" ".join(str(line).split()) for line in
                        install.tui_view(state, cols, rows))

    @staticmethod
    def options(state: install.TuiState) -> install.TuiState:
        state.stack = ["setup", "plan", "options"]
        return state

    def test_an_untick_keeps_the_other_systems_cores(self):
        """With --system sony-playstation, one untick on
        pcsx_rearmed cleared mesen, drawn ticked under the other systems."""
        state = checked_state()
        state.ticked = {"sony-playstation"}
        state.stack = ["setup", "plan", "options", "cores"]
        state.cores_all = True
        boxes = {r.value: r.label[:3] for r in install.tui_rows(state) if r.action == "core"}
        self.assertEqual(boxes, {"mesen": "[x]", "pcsx_rearmed": "[x]"})
        row = next(r for r in install.tui_rows(state) if r.value == "pcsx_rearmed")
        install._tick(state, row, None)
        boxes = {r.value: r.label[:3] for r in install.tui_rows(state) if r.action == "core"}
        self.assertEqual(boxes, {"mesen": "[x]", "pcsx_rearmed": "[ ]"})
        # The --core given is the cores ticked, exactly.
        self.assertEqual([v for f, v in install.tui_flags(state) if f == "--core"], ["mesen"])

    def test_a_core_of_another_system_is_not_all_cores(self):
        """Mesen ticked alone with the PlayStation chosen
        read "Cores: all", the run keeping none of pcsx_rearmed's files."""
        state = checked_state()
        state.ticked = {"sony-playstation"}
        state.cores = ["mesen"]
        options = self.options(state)
        self.assertIn("Cores: 0 of 1", [r.label for r in install.tui_rows(options)])
        state.stack = ["setup", "plan"]
        self.assertIn("0 of 1 cores", self.text(state, 100, 30))
        self.assertEqual(install.core_count_words(["mesen"], ["pcsx_rearmed"]), "0 of 1 cores")

    def test_none_then_done_says_why_on_a_long_list(self):
        """On 189 cores the status and the sentence were
        dropped, Done with nothing ticked did nothing visible."""
        state = checked_state()
        state.manifest = {**MANIFEST, "files": [
            *MANIFEST["files"],
            *({"dest": f"x/{n}.bin", "size": 1, "systems": ["sony-playstation"],
               "cores": [f"core{n:03}"]} for n in range(60))]}
        state.stack = ["setup", "plan", "options", "cores"]
        state.focus["cores"] = install._first_item(state)
        press(state, "n")
        done = next(i for i, r in enumerate(install.tui_rows(state)) if r.action == "done")
        state.focus["cores"] = done
        press(state, "enter")
        self.assertEqual(state.screen, "cores")
        for cols, rows in ((80, 24), (40, 12)):
            text = self.text(state, cols, rows)
            self.assertIn("No core is ticked", text)
            self.assertIn("Untick the cores", text)
        press(state, "esc")
        self.assertEqual(state.screen, "cores")

    def test_core_rows_say_what_each_core_adds(self):
        """Line mode counted each core's files, the
        screen named the cores alone."""
        state = checked_state()
        state.stack = ["setup", "plan", "options", "cores"]
        rows = {r.value: r.right for r in install.tui_rows(state) if r.action == "core"}
        self.assertEqual(rows["pcsx_rearmed"], "1 file, 4 B")
        state.cores_all = True
        rows = {r.value: r.right for r in install.tui_rows(state) if r.action == "core"}
        self.assertEqual(rows["mesen"], "1 file, 8.0 KB")

    def test_one_core_has_no_cores_row(self):
        """A list with one core offered Cores, where line
        mode asks nothing."""
        state = checked_state()
        state.manifest = {**MANIFEST, "files": [
            entry for entry in MANIFEST["files"] if entry["dest"] != "fc/disksys.rom"]}
        self.assertNotIn("cores", [r.action for r in install.tui_rows(self.options(state))])

    # Root cause 2: one tick list.

    def test_the_three_lists_open_and_answer_alike(self):
        """Choose systems opened on None, A unticking
        every system, Cores closed on A, regions ticked on A."""
        for route in ("both", "gptokeyb", "muxterm", "miyoo"):
            for screen, opener in (("systems", ("plan", "systems")),
                                   ("cores", ("options", "cores")),
                                   ("regions", ("options", "regions"))):
                with self.subTest(route=route, screen=screen):
                    state = checked_state()
                    state.pad = route
                    if opener[0] == "options":
                        press(state, "o")
                    state.focus[state.screen] = next(
                        i for i, r in enumerate(install.tui_rows(state))
                        if r.action == opener[1])
                    press(state, "enter")
                    self.assertEqual(state.screen, screen)
                    rows = install.tui_rows(state)
                    focused = rows[state.focus[screen]]
                    self.assertIn(focused.action, install.TUI_TICK_ROWS)
                    self.assertEqual([r.action for r in rows[-2:]], ["none", "done"])
                    hint = install._TUI_VIEWS[screen](state, 78, 21)[2]
                    self.assertEqual(hint[:2], ("A/Enter Tick", "B/Esc Done"))
                    before = install.tui_flags(state)
                    press(state, "enter")
                    self.assertEqual(state.screen, screen)
                    self.assertNotEqual(install.tui_flags(state), before)

    # Root cause 3: a folder failure as it happened.

    def test_a_folder_that_cannot_be_created_ends_on_its_reason(self):
        """The result said "22 files not fetched
        (RETROBIOS_INSTALL_OFFLINE=1)" and sent the user for a pack."""
        for os_type in ("linux", "android"):
            with self.subTest(os_type=os_type):
                state = checked_state()
                state.os_type = os_type
                install.tui_update(state, Key("enter"))
                for event in ({"event": "error", "stage": "dest", "reason": "not_writable",
                               "platform": "retroarch",
                               "message": f"{SYSTEM_DIR} cannot be created: Permission denied"},
                              {"event": "summary", "mode": "install", "installed": 0,
                               "up_to_date": 0, "pending": 4, "failed": [], "skipped": [],
                               "left_out": [], "kept": [], "interrupted": False}):
                    install.tui_receive(state, ("event", state.run_id, event))
                install.tui_receive(state, ("ended", state.run_id, 2, []))
                title, lines = install.tui_outcome(state)
                text = " ".join(map(str, lines))
                self.assertEqual(title, "Nothing installed")
                self.assertIn("cannot be created (permission denied)", text)
                self.assertNotIn("not fetched", text)
                self.assertNotIn("not in", text.split("cannot be created")[0])
                self.assertEqual("termux-setup-storage" in text, os_type == "android")
                self.assertNotIn("sudo", text if os_type == "android" else "")

    def test_android_never_offers_sudo_and_a_phone_plan_says_why(self):
        """Termux was offered sudo, and at 40x12 the plan
        offered Install anyway with no word of why."""
        hint = install.Invocation()
        hint.os_type = "android"
        remedy = install.write_remedy(Path("/storage/emulated/0/RetroArch/system"),
                                      "retroarch", hint)
        self.assertEqual(remedy, [install.TERMUX_STORAGE_WORDS])
        state = checked_state({"free": 50 * 1024 ** 3, "writable": False, "cores": []})
        state.os_type = "android"
        for cols, rows in ((40, 12), (80, 24)):
            text = self.text(state, cols, rows)
            self.assertIn("This folder cannot be written to", text)
            self.assertNotIn("sudo", text)

    # Root cause 4: every proven card named, the real marker said.

    def test_an_arkos_card_is_found_beside_an_amberelec_card(self):
        """An ArkOS card its bgmusic
        or launchimages prove was named nowhere, and its route said it
        could not tell it."""
        games = games_part(self.root / "media" / "GAMES")
        for marker in ("bgmusic", "launchimages"):
            with self.subTest(marker=marker):
                ark = self.drive(f"ARK_{marker}", ("bios", "nes", marker))
                self.assertEqual(install.card_system(ark), ("retroarch", ark / "bios", "ArkOS"))
                for name in ("ArkOS", "dArkOS"):
                    setup = install.card_setup(name, "retroarch")
                    self.assertEqual(install._card_is(setup, ark)[0], "own", name)
                state = self.first_screen([games, ark])
                text = self.text(state, 80, 24)
                self.assertIn(f"ArkOS SD card (ARK_{marker})", text)
                self.assertIn("AmberELEC SD card (GAMES)", text)

    def test_the_emuelec_refusal_names_its_file(self):
        """The refusal named bezels, which AmberELEC's
        card holds too."""
        games = games_part(self.root / "media" / "GAMES")
        (games / "bezels").mkdir()
        setup = install.card_setup("EmuELEC", "emuelec")
        choice = install._not_the_card(setup, games, games, "AmberELEC")
        self.assertIn("bezels/default.cfg", choice.detail)

    # Root cause 5: the reads before the menu show.

    def test_the_reads_before_the_menu_show_a_count(self):
        """A rerun read every file before the menu, one at
        a time and with nothing on screen."""
        payload = b"R" * 16
        (self.here / "a.bin").write_bytes(payload)
        listing = core_list(self.root / "read.json",
                            [self.entry("a.bin", payload, ["sony-playstation"])])
        with mock.patch.object(install, "_live_stdout", return_value=True):
            text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                               declared_only=False), [])
        self.assertIn("\r  read 1/1", text)
        self.assertLess(text.index("read 1/1"), text.index("every one in place"))

    # Root cause 6: every other item.

    @in_full
    def test_offline_the_plan_promises_no_replacement_it_cannot_make(self):
        """Offline, the plan said a wrong copy no folder
        holds "is replaced"."""
        state = checked_state()
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            text = self.text(state, 100, 30)
        self.assertIn("1 wrong copy", text)
        self.assertNotIn("wrong copy is replaced", text)

    def test_options_name_the_plans_bios_folder(self):
        """AmberELEC's Options read the games part, its
        plan the bios folder below it."""
        state = checked_state()
        state.manifest = {**MANIFEST, "files": [
            {**entry, "dest": f"bios/{entry['dest']}"} for entry in MANIFEST["files"]]}
        state.dest = Path("/media/me/GAMES")
        row = next(r for r in install.tui_rows(self.options(state)) if r.action == "folder")
        self.assertEqual(row.label, "BIOS folder: /media/me/GAMES/bios")

    def test_finished_with_errors_says_a_rerun_retries(self):
        """The screen never said a rerun retries the files
        that failed, and line mode named each failure twice."""
        state = checked_state()
        install.tui_update(state, Key("enter"))
        install.tui_receive(state, ("event", state.run_id, {
            "event": "summary", "mode": "install", "installed": 3, "up_to_date": 0,
            "pending": 1, "failed": [{"dest": "gba_bios.bin", "reason": "timed out"}],
            "skipped": [], "left_out": [], "kept": [], "interrupted": False}))
        install.tui_receive(state, ("ended", state.run_id, 1, []))
        title, lines = install.tui_outcome(state)
        self.assertEqual(title, "Finished with errors")
        self.assertIn("Run it again to retry only those.", lines)
        # Line mode: the FAILED line of the progress names it, the end not again.
        install.SAID_FAILED.clear()
        install.SAID_FAILED.add("gba_bios.bin")
        self.addCleanup(install.SAID_FAILED.clear)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out), \
                contextlib.suppress(SystemExit):
            install._report_outcome([Path("/b")], 3, 0, 1, 0, False,
                                    failures=[("gba_bios.bin", "timed out")])
        self.assertNotIn("gba_bios.bin", out.getvalue())
        self.assertIn("Run the same command again to retry only those.", out.getvalue())

    def test_below_40_columns_no_word_is_broken(self):
        """The reason line, Found and Install for were
        left to the terminal, which broke "/media/moi/" and "ONION/BIOS"."""
        with mock.patch.object(install, "terminal_size", return_value=(39, 11)), \
                mock.patch.object(install, "_is_terminal", return_value=True):
            for text in ("  Found Onion at /media/moi/ONION/BIOS (RetroArch files)",
                         "The window is 39x11: questions come line by line "
                         "(40x12 for the full screen)."):
                lines = install.fold_line(text).split("\n")
                self.assertTrue(all(len(line) <= 38 for line in lines), lines)
                self.assertEqual(" ".join(" ".join(lines).split()), " ".join(text.split()))

    def test_the_narrowing_line_is_a_sentence(self):
        """The plan read "--region." on a line alone."""
        state = checked_state()
        state.regions = ["japan"]
        text = self.text(state, 100, 30)
        self.assertIn("For this choice: regions ranked.", text)
        self.assertNotIn(" --region.", text)

    def test_offline_choice_of_systems_is_never_about_0_files(self):
        """"About 0 files, 0 B, for 10 of 11 systems"."""
        state = checked_state()
        state.ticked = {"sony-playstation"}
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            text = self.text(state, 100, 30)
        self.assertNotIn("About 0 files", text)
        self.assertIn("need the internet", text)

    def test_a_phone_bar_after_a_tap_keeps_quit_and_one_wording(self):
        """At 40 columns on Android the armed bar dropped
        Esc Quit and said "click", the row "tap again"."""
        state = fresh_state()
        state.os_type = "android"
        state.mouse = True
        state.stack = ["setup"]
        install.tui_view(state, 40, 12)
        state.tapped = install._tapped_row(state)
        frame = install.tui_view(state, 40, 12)
        text = "\n".join(map(str, frame))
        self.assertNotIn("click", text)
        self.assertIn("tap again", text)
        self.assertIn("Esc Quit", str(frame[-1]))

    def test_the_offline_screen_names_the_setups_list(self):
        """The offline screen said install/<platform>.json
        for AmberELEC, chosen one screen before."""
        inbox: queue.Queue = queue.Queue()
        install.LOCAL.reset()
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            install._tui_fetch("amberelec", inbox, io.StringIO())
        message = inbox.get_nowait()
        self.assertIn("install/amberelec.json", " ".join(message[3]))

    # Root cause 7: the tests leave the host alone.

    def test_no_connection_leaves_the_loopback_nor_a_card_comes_in(self):
        """261 connections to GitHub left this module,
        and tests failed with an AmberELEC card in the reader."""
        import socket  # noqa: PLC0415

        log = Path(os.environ["RETROBIOS_TEST_NETLOG"])
        before = log.read_text(encoding="utf-8")
        self.addCleanup(log.write_text, before, encoding="utf-8")
        with self.assertRaisesRegex(OSError, "makes no request"):
            socket.create_connection(("192.0.2.1", 80), timeout=1)
        child = subprocess.run(
            [sys.executable, "-c", "import os, socket\n"
             "print(os.path.ismount('/media/x'), os.path.ismount('/mnt/d'))\n"
             "socket.create_connection(('192.0.2.1', 80), 1)"],
            capture_output=True, text=True, check=False, timeout=60)
        self.assertEqual(child.stdout.strip(), "False False")
        self.assertIn("makes no request", child.stderr)
        self.assertEqual(len(log.read_text(encoding="utf-8").splitlines()),
                         len(before.splitlines()) + 2)
        self.assertFalse(os.path.ismount("/media/x"))


class GamesOnTheCard(unittest.TestCase):
    """For the games on this card: the first choice where the card holds
    games, the whole list one press away (--for-games)."""

    @in_full
    def test_a_card_with_games_opens_on_them(self):
        state = games_state()
        self.assertTrue(state.for_games)
        self.assertEqual(state.games_choice, "probe")
        argv = install.tui_argv(state, "check", "py", "i.py")
        self.assertEqual(argv[4:], ["--for-games", "--check", "--events"])
        rows = install.tui_rows(state)
        self.assertEqual([row.action for row in rows[:4]],
                         ["install", "games", "startonly", "gameslist"])
        self.assertEqual(rows[1].label, "For the games on this card: yes")
        self.assertEqual(rows[1].right, "412 games")
        text = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn("For the 412 games on this card.", text)
        self.assertIn("2 games get every BIOS of their system: Show the games.", text)

    def test_a_card_without_games_keeps_the_whole_list(self):
        state = fresh_state()
        with mock.patch.object(install.Path, "exists", return_value=True):
            install.tui_update(state, Key("enter"))
        install.tui_receive(state, ("games_here", "retroarch", SYSTEM_DIR, 0))
        install.tui_receive(state, ("manifest", "retroarch", MANIFEST))
        self.assertFalse(state.for_games)
        self.assertNotIn("--for-games", install.tui_argv(state, "check", "py", "i.py"))
        self.assertNotIn("games", [row.action for row in install.tui_rows(checked_state())])

    def test_a_look_at_another_folder_is_ignored(self):
        state = fresh_state()
        with mock.patch.object(install.Path, "exists", return_value=True):
            install.tui_update(state, Key("enter"))
        install.tui_receive(state, ("games_here", "retroarch", HOME / "other", 5))
        self.assertIsNone(state.for_games)

    def test_everything_is_one_press_away(self):
        state = games_state()
        state.focus["plan"] = 1
        self.assertEqual(press(state, "enter"), [("run", "check")])
        self.assertFalse(state.for_games)
        self.assertEqual(state.games_choice, "user")
        self.assertNotIn("--for-games", install.tui_argv(state, "check", "py", "i.py"))
        self.assertEqual(state.refocus, "games")

    def test_only_what_starts_adds_its_flag(self):
        state = games_state()
        state.focus["plan"] = 2
        self.assertEqual(press(state, "enter"), [("run", "check")])
        self.assertIn("--required-only", install.tui_argv(state, "check", "py", "i.py"))
        self.assertEqual(install.tui_command(state).split()[-2:],
                         ["--for-games", "--required-only"])

    def test_show_the_games_names_those_that_fell_back(self):
        state = games_state()
        state.focus["plan"] = 3
        press(state, "enter")
        self.assertEqual(state.screen, "games")
        items = install._pager_items(state)
        self.assertTrue(any(line.endswith("(GBA): 12 games, 8 recognised, Europe only")
                            for line in items), items)
        self.assertIn("GBA/demo.gba: not recognised", items)
        press(state, "enter")
        self.assertEqual(state.screen, "plan")

    def test_the_result_names_them_too(self):
        state = games_state()
        state.stack.append("result")
        state.code = 0
        state.download = {"event": "download", "files": 4, "bytes": 1064964}
        state.summary = {"event": "summary", "mode": "install", "installed": 4,
                         "up_to_date": 1, "pending": 0, "failed": [], "skipped": [],
                         "left_out": [], "kept": [], "interrupted": False}
        lines = install.tui_outcome(state)[1]
        self.assertIn("Not recognised, every BIOS of their system kept: GBA/demo.gba, "
                      "GBA/hack.gba.", lines)

    def test_the_command_line_decides_and_names_a_folder(self):
        args = _args()
        args.for_games, args.required_only = Path("games"), True
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            state, _effects = install.tui_start(args, "linux", detect=False)
        self.assertEqual(state.games_choice, "cli")
        flags = install.tui_flags(state)
        self.assertIn(("--for-games", str(Path("games").absolute())), flags)
        self.assertIn(("--required-only", None), flags)
        state.platform, state.dest = "retroarch", SYSTEM_DIR
        install.tui_receive(state, ("games_here", "retroarch", SYSTEM_DIR, 0))
        self.assertTrue(state.for_games)

    def test_another_folder_is_looked_at_from_what_was_read(self):
        state = games_state()
        state.dest = HOME / "card" / "BIOS"
        with mock.patch.object(install, "games_probe", return_value=0) as probe:
            self.assertEqual(install._start_check(state), [("run", "check")])
        probe.assert_called_once_with("retroarch", HOME / "card" / "BIOS", network=False,
                                      os_type="linux")
        self.assertFalse(state.for_games)
        self.assertEqual(state.games_probed, ("retroarch", HOME / "card" / "BIOS"))

    def test_the_fetch_looks_at_the_card_before_the_list_arrives(self):
        inbox: queue.Queue = queue.Queue()

        def fetched(plat, held, log):
            held.put(("manifest", plat, MANIFEST))

        with mock.patch.object(install, "_tui_fetch", side_effect=fetched), \
                mock.patch.object(install, "games_probe", return_value=3) as probe:
            install._tui_fetch_games("retroarch", inbox, io.StringIO(), SYSTEM_DIR, True)
        probe.assert_called_once_with("retroarch", SYSTEM_DIR, attempts=1)
        self.assertEqual(inbox.get()[0], "games_here")
        self.assertEqual(inbox.get()[0], "manifest")

    def test_reading_the_games_is_counted_while_the_check_runs(self):
        state = fresh_state()
        state.platform, state.dest, state.stack = "retroarch", SYSTEM_DIR, ["checking"]
        state.manifest, state.run, state.running = MANIFEST, "check", True
        install.tui_receive(state, ("event", state.run_id, {
            "event": "games_reading", "files_done": 40, "files_total": 412}))
        self.assertIn("Reading the games: 40 of 412",
                      "\n".join(install.tui_view(state, 80, 24)))

    def test_what_the_games_need_not_known_is_said(self):
        state = games_state()
        state.games = None
        state.games_unavailable = {"event": "games_unavailable", "platform": "retroarch",
                                   "reason": "offline", "message": "the games index is "
                                   "not on this machine"}
        self.assertIn("What the games need is not known: the games index is not on this "
                      "machine. Every file is kept.", install.games_plan_words(state))

    def test_every_size_draws_the_rows(self):
        state = games_state()
        for cols, rows in SIZES:
            with self.subTest(size=f"{cols}x{rows}"):
                state.cols, state.rows = cols, rows
                lines = install.tui_view(state, cols, rows)
                self.assertTrue(any("For the games" in line for line in lines), lines)


@unittest.skipUnless(pyte and pty, "the end-to-end screens need pyte and a pty")
class GamesEndToEnd(unittest.TestCase):
    """The real --tui on a card with games, against a loopback repository."""

    def test_the_plan_opens_on_the_games_and_installs_only_them(self):
        import test_install_games as games  # noqa: PLC0415

        card = games.Card()
        self.addCleanup(card.close)
        card.game("SEGACD", "sonic.iso", games.mcd_iso(100))
        root = card.root / "repo"
        (root / "install").mkdir(parents=True)
        shutil.copytree(card.lists / "games", root / "install" / "games")
        listed = games.manifest()
        (root / "bios").mkdir()
        for entry in listed["files"]:
            payload = entry["dest"].encode().ljust(entry["size"], b".")[:entry["size"]]
            (root / entry["repo_path"]).write_bytes(payload)
        (root / "install" / "retroarch.json").write_text(json.dumps(listed))
        handler = functools.partial(_QuietHandler, directory=str(root))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        env = {**os.environ, "TERM": "xterm", "HOME": str(card.root), "RETROBIOS_OS": "linux",
               "RETROBIOS_BASE_URL": f"http://127.0.0.1:{server.server_address[1]}",
               "RETROBIOS_CACHE": str(card.cache)}
        for name in ("DISPLAY", "WAYLAND_DISPLAY", "SSH_CONNECTION", "SSH_TTY", "NO_COLOR",
                     install.TUI_PAD_ENV, install.OFFLINE_VARIABLE, *install._STEAM_MARKERS):
            env.pop(name, None)
        term = Pty(["--platform", "retroarch", "--dest", str(card.bios)], env)
        self.addCleanup(lambda: term.status is None and os.kill(term.pid, 9))
        screen = term.wait("For the games on this card: yes", timeout=40)
        self.assertIn("For the 1 game on this card.", screen)
        term.send("\r")
        term.wait("A/Enter Exit", timeout=40)
        term.send("\r")
        self.assertEqual(term.close(), 0)
        written = sorted(p.name for p in card.bios.rglob("*") if p.is_file())
        self.assertEqual(written, ["bios_CD_E.bin", "cd_extra.bin"])

# The most words each screen may show by default, one count per size of
# SIZES (owner, 2026-11-09: a beginner lost the important line in text). A
# path is no word. The plan, Confirm and the result say what happens, where
# and what next; their counts, notes and commands wait on Details. A list
# shows more rows on a taller window. A change that adds words to a screen
# raises its numbers here and says why: the result names its failed files
# (review of 2026-11-10), what the user acts on.
SCREEN_WORDS = {
    "setup": (29, 36, 34, 34), "platforms": (23, 27, 89, 225), "folder": (27, 27, 25, 25),
    "folder-card": (52, 52, 50, 50), "browse": (17, 17, 15, 15), "path": (23, 23, 25, 25),
    "create": (23, 23, 21, 21), "checking": (18, 18, 17, 17), "plan": (31, 31, 31, 31),
    "plan-in-place": (22, 22, 19, 19), "systems": (36, 37, 36, 36),
    "options": (40, 42, 59, 59), "regions": (45, 44, 42, 42), "cores": (47, 47, 45, 45),
    "preview": (29, 29, 28, 28), "command": (22, 22, 16, 16), "confirm": (22, 22, 20, 20),
    "installing": (32, 32, 31, 31), "result": (33, 33, 31, 31), "error": (37, 34, 32, 31),
    "quit": (14, 14, 12, 12), "help": (24, 26, 26, 26), "plan-games": (36, 46, 54, 54),
    "games": (36, 45, 44, 44), "plan-details": (30, 30, 29, 29),
    "result-details": (30, 30, 19, 19),
}


def screen_words(lines: list) -> int:
    """Words of a drawn screen, its title and bar included, a path left out."""
    return sum(1 for line in lines for token in str(line).split()
               if re.search(r"[A-Za-z0-9]", token) and "/" not in token)


class ScreenWordBudgets(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(install, "_mounted_cards", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_every_screen_keeps_to_its_budget(self):
        states = golden_states()
        self.assertEqual(sorted(states), sorted(SCREEN_WORDS),
                         "a screen without a word budget, or a budget without its screen")
        for name, state in states.items():
            for (cols, rows), budget in zip(SIZES, SCREEN_WORDS[name]):
                with self.subTest(screen=name, size=f"{cols}x{rows}"):
                    state.cols, state.rows = cols, rows
                    words = screen_words(install.tui_view(state, cols, rows))
                    self.assertLessEqual(words, budget)

    def test_the_default_path_says_what_where_and_next_first(self):
        """The plan opens on what it installs and where, the result on what
        happened, where and the next step: nothing between them."""
        plan = [str(line).strip() for line in install.tui_view(checked_state(), 80, 24)]
        self.assertEqual(plan[2:4], ["4 files to download, 1.0 MB",
                                     "BIOS folder: ~/.config/retroarch/system"])
        self.assertEqual(plan[4], "")
        done = result_states()["done"]
        lines = [str(line).strip() for line in install.tui_view(done, 80, 24)]
        self.assertEqual(lines[2:5], ["4 files installed. 1 file already in place.",
                                      f"BIOS folder: {SYSTEM_DIR}",
                                      "Next: start RetroArch and play."])


class DetailsScreen(unittest.TestCase):
    """What the plan, Confirm and the result leave out by default, one key
    or one row away, and every line of --verbose in one place or the other."""

    def setUp(self):
        patcher = mock.patch.object(install, "_mounted_cards", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def text(self, state: install.TuiState, cols: int = 80, rows: int = 24) -> str:
        return "\n".join(str(line) for line in install.tui_view(state, cols, rows))

    def test_d_opens_the_plans_details_and_b_comes_back(self):
        state = checked_state()
        self.assertNotIn("Free space", self.text(state))
        press(state, "d")
        self.assertEqual(state.screen, "details")
        shown = self.text(state)
        for line in ("1 in place, 3 missing, 1 wrong copy", "Free space: 50.0 GB",
                     "The 1 wrong copy is replaced"):
            self.assertIn(line, shown)
        press(state, "esc")
        self.assertEqual(state.screen, "plan")

    def test_a_controller_reaches_them_by_the_row(self):
        state = checked_state()
        rows = install.tui_rows(state)
        state.focus["plan"] = [row.action for row in rows].index("details")
        self.assertIn("A/Enter Show", self.text(state))
        press(state, "enter")
        self.assertEqual(state.screen, "details")
        press(state, "enter")
        self.assertEqual(state.screen, "plan")

    def test_the_results_details_are_said_after_exit_once_opened(self):
        state = golden_states_result()
        self.assertIn("Y/o Details", self.text(state))
        self.assertNotIn("Same choice without questions", "\n".join(install.tui_farewell(state)))
        press(state, "o")
        self.assertEqual(state.screen, "details")
        self.assertIn("Same choice without questions:", self.text(state))
        press(state, "esc")
        self.assertEqual(state.screen, "result")
        press(state, "enter")
        farewell = "\n".join(install.tui_farewell(state))
        self.assertIn("Same choice without questions:", farewell)
        self.assertIn("failed: scph5500.bin (HTTP 404)", farewell)

    def test_confirm_has_its_details_too(self):
        state = golden_states()["confirm"]
        self.assertNotIn("Free space", self.text(state))
        press(state, "d")
        self.assertEqual(state.screen, "details")
        self.assertIn("Nothing is written before Install.", self.text(state))
        self.assertIn("Free space: 50.0 GB", self.text(state))

    def test_every_line_is_on_the_screen_or_its_details(self):
        """The screen and its Details together say what --verbose says on
        the screen alone: no line is lost."""
        for name in ("plan", "plan-games", "plan-in-place", "confirm", "result"):
            with self.subTest(screen=name):
                state = golden_states()[name]
                whole = (install._plan_text(state) if state.screen == "plan"
                         else install._confirm_text(state) if state.screen == "confirm"
                         else install.tui_outcome(state)[1])
                shown = install._shown(state, whole)
                state.stack.append("details")
                told = install.details_lines(state)
                self.assertEqual(sorted(map(str, whole)),
                                 sorted(map(str, [*shown, *[line for line in told
                                                           if install._is_detail(line)]])))

    def test_verbose_draws_them_in_place_and_offers_no_row(self):
        state = checked_state()
        state.passthrough = [("--verbose", None)]
        text = self.text(state)
        self.assertIn("Free space: 50.0 GB", text)
        self.assertNotIn("details", [row.action for row in install.tui_rows(state)])

    def test_installing_lists_the_files_that_went_well_with_verbose(self):
        state = golden_states()["installing"]
        self.assertNotIn("gba_bios.bin", self.text(state))
        self.assertIn("FAILED scph5500.bin (HTTP 404)", self.text(state))
        state.passthrough = [("--verbose", None)]
        self.assertIn("ok     gba_bios.bin", self.text(state))


class WhatToActOnStaysOnTheScreen(unittest.TestCase):
    """A failure, a file an emulator needs that the collection lacks, a
    remedy to choose: on the screen by default, never only on Details
    (review of 2026-11-10)."""

    def setUp(self):
        patcher = mock.patch.object(install, "_mounted_cards", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def text(self, state: install.TuiState) -> str:
        return " ".join(" ".join(install.tui_view(state, 80, 24)).split())

    def test_a_failed_file_is_named_on_the_result_and_after_exit(self):
        state = golden_states_result()
        self.assertIn("failed: scph5500.bin (HTTP 404)", self.text(state))
        press(state, "enter")
        self.assertIn("failed: scph5500.bin (HTTP 404)", "\n".join(install.tui_farewell(state)))

    def needs(self, state: install.TuiState) -> install.TuiState:
        state.manifest = {**MANIFEST, "omitted_files": [
            {"dest": "lost.bin", "system": "sony-playstation", "required": True},
            {"dest": "spare.bin", "system": "sony-playstation", "required": False}]}
        return state

    def test_a_file_an_emulator_needs_is_counted_on_the_plan(self):
        state = self.needs(checked_state())
        said = "1 file an emulator needs is not available here (Details names it)."
        self.assertIn(said, self.text(state))
        press(state, "d")
        self.assertIn("lost.bin", self.text(state))
        # With --verbose the names are on the plan, and the count not again.
        state = self.needs(checked_state())
        state.passthrough = [("--verbose", None)]
        self.assertNotIn(said, self.text(state))
        self.assertIn("lost.bin", self.text(state))

    def test_a_file_an_emulator_needs_is_counted_on_the_result(self):
        state = self.needs(result_states()["done"])
        self.assertIn("1 file an emulator needs is not available here (Details names it).",
                      self.text(state))

    def test_the_save_folder_remedy_is_on_the_result(self):
        state = result_states()["done"]
        state.manifest = {**MANIFEST, "save_directory": {"folder": "saves", "by_core": True}}
        state.summary["skipped"] = [{"reason": "no_save_directory", "files": 2}]
        text = self.text(state)
        self.assertIn("2 files read from RetroArch's save directory left out. "
                      f"{install.TUI_SAVE_REMEDY}", text)
        self.assertNotIn("Its place is not known.", text)
        press(state, "o")
        self.assertIn("Its place is not known.", self.text(state))

    def test_the_save_folder_remedy_is_on_the_plan(self):
        state = checked_state()
        state.manifest = {**MANIFEST, "save_directory": {"folder": "saves", "by_core": True}}
        state.check_summary = {"skipped": [{"reason": "no_save_directory", "files": 2}]}
        self.assertIn("Choose it in Options, Save folder (--save-dir).", self.text(state))

    def test_files_that_could_not_be_read_are_counted_where_no_row_says_so(self):
        unread = [{"event": "unreadable", "platform": "retroarch", "folder": "/media/OLD",
                   "path": "/media/OLD/scph5501.bin", "member": "",
                   "reason": "Permission denied"}]
        state = checked_state()
        state.unreadable = list(unread)
        # The plan's row names them: the count waits on Details.
        self.assertIn("Show the files that could not be read", self.text(state))
        # Everything in place: no row, the count on the plan.
        done = checked_state()
        done.check = {**CHECK, "present": 5, "missing": 0, "wrong_hash": 0,
                      "bytes_needed": 0, "not_installable": 0}
        done.unreadable = list(unread)
        self.assertNotIn("unreadable", [row.action for row in install.tui_rows(done)])
        self.assertIn("1 file in OLD could not be read.", self.text(done))

    def test_another_drive_to_add_is_said_on_the_plan(self):
        state = checked_state()
        state.scanned = [{"event": "scanned", "folder": "E:\\", "files": 200000,
                          "truncated": True, "other_drives": ["E:\\D"]}]
        text = self.text(state)
        self.assertIn("E:\\D is another drive: add it to copy from it too.", text)
        self.assertNotIn("Read the first", text)


if __name__ == "__main__":
    unittest.main()
