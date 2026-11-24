"""The terminal and its input: when the screen can open, the keys, the pad
routes, Windows without the POSIX modules, terminals the screen cannot draw,
the idle exit and the terminal given back after a crash."""

from __future__ import annotations

import tests

import contextlib
import errno
import fcntl
import io
import os
import re
import shutil
import struct
import sys
import tempfile
import termios
import time
import types
import unittest
from pathlib import Path
from unittest import mock

import install
from tests.netguard import module_guard
from tests.tuisupport import (
    _args, CHECK, checked_state, FILES, fresh_state, GOLDEN, golden_states, install_run, Key, press,
    REPO_ROOT, ROUTES, SIZES, SYSTEM_DIR, _terminfo_entry, _terminfo_folder, WindowsOs,
)


# No connection off the loopback and no card of the host reaches a test,
# in this process or one it starts: the module fails at its end when one is tried.
setUpModule, tearDownModule = module_guard("test_tui_terminal")


try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except ImportError:
    given = None


def keys(*names: str) -> list:
    return [Key("char", name[5:]) if name.startswith("char:") else Key(name) for name in names]


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
            "both": "A/Enter Install  B/Esc Back  Y/o Change  ? Help",
            "keys": "Enter Install  Esc Back  o Change  ? Help",
            "gptokeyb": "A Install  B Back  Y Change",
            "evmapy": "A Install  B Back  Y Change",
            "muxterm": "Start Install  B Back",
            "miyoo": "A Install  R2 Back  L2 Change",
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
        root = Path(tempfile.mkdtemp())
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
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work, True)
        with mock.patch.object(install._TuiTerminal, "draw", breaking_draw), \
                mock.patch.object(install.tempfile, "mkdtemp", return_value=str(work)), \
                mock.patch.object(install, "tui_start", return_value=(fresh_state(), [])), \
                mock.patch.object(install, "open_list_and_pack"), \
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
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work, True)
        with mock.patch.object(install, "_TuiTerminal", Quiet), \
                mock.patch.object(install.tempfile, "mkdtemp", return_value=str(work)), \
                mock.patch.object(install, "tui_start", return_value=(state, [])), \
                mock.patch.object(install, "open_list_and_pack"), \
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
        try:
            with open(os.dup(slave), "w", encoding="utf-8") as screen:
                terminal = mock.Mock(fd=slave, stdout=screen)
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
            os.close(slave)
            if master >= 0:
                os.close(master)


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
                mock.patch.object(install, "open_list_and_pack"), \
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


# POSIX modules a Windows Python does not have: importing one raises there.
POSIX_ONLY = ("termios", "tty", "pty", "fcntl", "select", "resource", "pwd", "grp")


# The signal names a Windows Python defines.
WINDOWS_SIGNALS = ("SIGABRT", "SIGBREAK", "SIGFPE", "SIGILL", "SIGINT", "SIGSEGV",
                   "SIGTERM")


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
        work = Path(tempfile.mkdtemp())
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

        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work, True)
        with SimulatedWindows() as windows, \
                mock.patch.object(install._TuiTerminal, "draw", breaking_draw), \
                mock.patch.object(install, "_drop_closed_terminal"), \
                mock.patch.object(install.tempfile, "mkdtemp", return_value=str(work)), \
                mock.patch.object(install, "tui_start", return_value=(fresh_state(), [])), \
                mock.patch.object(install, "open_list_and_pack"), \
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


if __name__ == "__main__":
    unittest.main()
