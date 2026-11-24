"""The mouse on the full screen: its reports, taps on every screen, what a tap
shows before it acts and the second tap where files are written."""

from __future__ import annotations

import tests

import io
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import install
from tests.installsupport import make_card
from tests.netguard import module_guard
from tests.tuisupport import (
    _args, _CardFixtures, CHECK, checked_state, drawn, FILES, fresh_state, _game_state, GOLDEN,
    golden_states, HOME, in_full, _installed_state, Key, MANIFEST, PLAN, REPO_ROOT, screen_text,
    settled, sgr, SYSTEM_DIR, SYSTEMS, tap, x10,
)


# No connection off the loopback and no card of the host reaches a test,
# in this process or one it starts: the module fails at its end when one is tried.
setUpModule, tearDownModule = module_guard("test_tui_mouse")


MOUSE_SIZES = ((40, 12), (80, 24), (120, 40))


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
        for name in ("setup", "platforms", "plan", "systems", "change", "error", "quit",
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
        import copy

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
                            if row_list[index].action == "heading":
                                # A heading names the rows under it: no
                                # choice, nothing happens.
                                self.assertEqual(effects, [])
                                self.assertEqual((state.stack, state.focus),
                                                 (base.stack, base.focus))
                                continue
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


class TapsGameDataAndExitCodes(_CardFixtures, unittest.TestCase):
    """What the screens answer, line mode's
    parity being in LineModeAndScreenDecideAlike."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
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
                      *FILES, *SYSTEMS, CHECK, PLAN]:
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
        state.offline = True
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
        # A returning user's version note follows the quit line: still a
        # chosen quit, so it goes to stderr where the launcher looks.
        state.version = "List for RetroArch v2026.11.10, this is v2026.11.01."
        self.assertTrue(install.tui_quit_chosen(state))
        self.assertEqual(install.tui_farewell(state)[0], "RetroBIOS: quit. Nothing was installed.")
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
            state.folder_scan = install.scan_folder(state)
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
        state.facts["config"] = (str(cfg / "retroarch.cfg"), cfg)
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
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
        old.offline = True
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


if __name__ == "__main__":
    unittest.main()
