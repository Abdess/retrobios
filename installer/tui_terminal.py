"""The terminal under the full screen: its modes, suspend and signals, and a terminal that closes."""
from __future__ import annotations

import codecs
import errno
import functools
import io
import os
import signal
import sys
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, TextIO

from installer.terminal import _enable_ansi
from installer.text import _pad, cell_width, screen_text
from installer.tui_engine import _EngineRun
from installer.tui_keys import KeyDecoder, TerminalInput, TuiKey, decode_windows_key
from installer.tui_paint import ascii_text, tui_paint
from installer.tui_routes import _terminal_size, colour_blocker, tui_mouse_blocker
from installer.tui_state import TUI_MAX_WIDTH, TuiState

if TYPE_CHECKING:
    from installer.tui_keys import TuiMouse


# An arrow key arrives as Esc and two more characters, Esc alone as itself:
# past this wait an Esc with nothing after it is the key.
TUI_ESC_WAIT = 0.04


# Turned on by the interface, so a pasted path arrives as one piece and its
# newline does not submit it half typed.
_SCREEN_ON = "\x1b[?1049h\x1b[?25l\x1b[?2004h\x1b[2J"
# The mouse modes are turned off on every way out, turned on or not: a
# shell left with them on reads each click as a line of garbage.
_SCREEN_OFF = "\x1b[?1006l\x1b[?1000l\x1b[?2004l\x1b[0m\x1b[?25h\x1b[?1049l"
# Presses and releases (1000), reported in SGR form (1006): a column past
# 223 does not fit the legacy form's byte. Never 1003 (every motion): a
# touch screen has no hover, and nothing here depends on one.
_MOUSE_ON = "\x1b[?1000h\x1b[?1006h"
_MOUSE_OFF = "\x1b[?1006l\x1b[?1000l"


class _TuiTerminal:
    """The terminal in raw mode: keys in, frames out, put back as found."""

    def __init__(self, stdin: TextIO, stdout: TextIO) -> None:
        self.stdin, self.stdout = stdin, stdout
        self.fd = stdin.fileno()
        self.saved: list | None = None
        self.decoder = KeyDecoder()
        self.input = TerminalInput(getattr(stdin, "encoding", None) or "utf-8")
        self.encoding = getattr(stdout, "encoding", None) or "utf-8"
        locale_name = os.environ.get("LC_ALL") or os.environ.get("LANG") or ""
        try:
            utf8 = codecs.lookup(self.encoding).name == "utf-8"
        except LookupError:
            utf8 = False
        # Python turns a C locale into UTF-8 for itself, not for the
        # terminal: a console font there has no CJK, often no accents.
        self.ascii = not utf8 or locale_name in ("C", "POSIX")
        # The same text without colour: NO_COLOR, a dumb or unset TERM, a
        # description naming fewer than 8 colours, an output no terminal.
        self.colour = not colour_blocker(os.environ, stdout) and _enable_ansi()
        self.ended = False
        self.heard = 0.0
        self.frame: list[tuple[str, str]] = []
        self.entered = False
        # Whether clicks may be asked for here (tui_mouse_blocker), and
        # whether they are now: off on a screen whose text is copied.
        self.mouse_allowed = not tui_mouse_blocker(stdin, stdout)
        self.mouse = False

    def set_mouse(self, on: bool) -> None:
        """Ask for clicks or give them back to the terminal, written only
        when that changes."""
        on = on and getattr(self, "mouse_allowed", False) and self.entered
        if on != getattr(self, "mouse", False):
            self.mouse = on
            self.write(_MOUSE_ON if on else _MOUSE_OFF)

    def enter(self) -> None:
        if os.name != "nt":
            import termios

            # Entered again after a stop, the mode to go back to stays the
            # one found the first time.
            if self.saved is None:
                self.saved = termios.tcgetattr(self.fd)
            mode = termios.tcgetattr(self.fd)
            mode[0] &= ~(termios.ICRNL | termios.INLCR | termios.IGNCR | termios.IXON)
            # ISIG off: Ctrl-C arrives as a key and is forwarded once, by hand.
            mode[3] &= ~(termios.ICANON | termios.ECHO | termios.ISIG | termios.IEXTEN)
            mode[6][termios.VMIN] = 1
            mode[6][termios.VTIME] = 0
            termios.tcsetattr(self.fd, termios.TCSANOW, mode)
        self.entered = True
        self.write(_SCREEN_ON)

    def leave(self) -> None:
        """The main screen and the mode found, the mode even when the write
        fails: a closed window answers EIO."""
        try:
            # Never entered (stopped while it started): the main screen and
            # the cursor are as they were, nothing is written over them.
            if getattr(self, "entered", True):
                self.entered = False
                # The mouse modes go with the screen (_SCREEN_OFF), and come
                # back with the next frame once entered again.
                self.mouse = False
                self.write(_SCREEN_OFF)
        finally:
            if self.saved is not None:
                import termios

                saved, self.saved = self.saved, None
                termios.tcsetattr(self.fd, termios.TCSADRAIN, saved)

    def write(self, text: str) -> None:
        self.stdout.write(text.encode(self.encoding, "replace").decode(self.encoding))
        self.stdout.flush()

    def size(self) -> tuple[int, int]:
        return _terminal_size(self.stdout)

    def draw(self, lines: list[str], cols: int) -> None:
        """Rewrite the lines that changed since the last frame, and only those."""
        out = [] if self.frame else ["\x1b[H\x1b[2J"]
        frame = [(str(line), getattr(line, "style", "")) for line in lines]
        covered = 0
        for index, (text, style) in enumerate(frame):
            if style == "cont" and covered:
                # A row the long line above folds into.
                covered -= 1
                continue
            covered = (max(0, -(-cell_width(text) // max(1, cols)) - 1)
                       if style == "long" else 0)
            if index < len(self.frame) and self.frame[index] == (text, style):
                continue
            text = screen_text(text)
            if getattr(self, "ascii", False):
                text = ascii_text(text)
            if style == "focus":
                text = _pad(text, min(cols, TUI_MAX_WIDTH) - (index == len(frame) - 1))
            out.append(f"\x1b[{index + 1};1H"
                       f"{tui_paint(text, style, getattr(self, 'colour', False))}\x1b[0m\x1b[K")
        self.frame = frame
        if out:
            self.write("".join(out))

    def keys(self, timeout: float) -> list[TuiKey | TuiMouse]:
        if os.name == "nt":
            return self._console_keys(timeout)
        if self.ended:
            time.sleep(timeout)
            return []
        import select

        if not select.select([self.fd], [], [], timeout)[0]:
            # A paste whose end never came, after a second of silence.
            if self.decoder.paste is not None and time.monotonic() - self.heard > 1:
                return self.decoder.close_paste()
            return []
        keys = self._read()
        while self.decoder.buffer and not self.ended:
            if select.select([self.fd], [], [], TUI_ESC_WAIT)[0]:
                keys += self._read()
            else:
                self.input.flush()
                keys += self.decoder.flush()
                break
        return keys

    def _read(self) -> list[TuiKey | TuiMouse]:
        data = os.read(self.fd, 4096)
        self.heard = time.monotonic()
        if not data:
            # The terminal went away: what Ctrl-D at a question does.
            self.ended = True
            return [TuiKey("ctrl-d")]
        return self.decoder.feed(self.input.decode(data))

    def _console_keys(self, timeout: float) -> list[TuiKey | TuiMouse]:
        import importlib

        # typeshed declares msvcrt for win32 only: the module is read as the
        # runtime holds it.
        msvcrt = importlib.import_module("msvcrt")
        kbhit: Callable[[], bool] = msvcrt.kbhit
        getwch: Callable[[], str] = msvcrt.getwch
        end = time.monotonic() + timeout
        keys: list[TuiKey | TuiMouse] = []
        while True:
            while kbhit():
                key = decode_windows_key(getwch(), getwch)
                if key is not None:
                    keys.append(key)
            if keys or time.monotonic() >= end:
                return keys
            time.sleep(0.01)


CTRL_Z_NO_SHELL = ("Ctrl-Z is ignored: no shell started this installer, and none could "
                   "bring it back.")


def tui_ctrl_z(state: TuiState) -> bool:
    """Whether a Ctrl-Z typed on the screen stops it: only where a shell
    with job control can resume it, the installer's process group being one
    of its jobs, not its session's own. Started from a terminal app's -e,
    a desktop entry or a launcher's sh -c, nothing ever sent SIGCONT, and
    the screen and its launcher stayed stopped for good. Otherwise the key is
    ignored and the bar says why."""
    if (hasattr(signal, "SIGSTOP") and hasattr(os, "getsid")
            and os.getpgrp() != os.getsid(0)):
        return True
    state.status, state.status_more = CTRL_Z_NO_SHELL, ""
    return False


def tui_suspend(runs: list[_EngineRun], whole: bool) -> None:
    """Stop the screen and the runs it started until fg continues them.

    whole is a Ctrl-Z typed on the screen, which stops what the terminal's
    Ctrl-Z stops: every process of the foreground group. The installer
    stopping alone left install.sh, run as `sh install.sh` or `curl | sh`,
    waiting on it, and the shell never got its prompt back. A kill -TSTP
    sent to the installer stops the installer alone. The runs are stopped
    either way, an install having gone on writing behind a stopped screen.
    """
    for run in runs:
        run.pause(True)
    if whole:
        # SIGSTOP and not SIGTSTP: a group no shell watches over (the
        # installer started on a terminal of its own) discards SIGTSTP.
        os.killpg(os.getpgrp(), signal.SIGSTOP)
    else:
        os.kill(os.getpid(), signal.SIGSTOP)
    for run in runs:
        run.pause(False)


class _TuiSignals:
    """What the signal handlers saw, read by the screen between frames."""

    def __init__(self) -> None:
        self.interrupt = False
        self.resized = False
        # True from SIGTSTP, "key" from Ctrl-Z read as a key.
        self.suspend: bool | str = False
        self.resume = False
        self.term = 0

    def on_stop(self, signum: int, _frame: object) -> None:
        self.term = self.term or signum

    def on_interrupt(self, _signum: int, _frame: object) -> None:
        self.interrupt = True

    def on_resize(self, _signum: int, _frame: object) -> None:
        self.resized = True

    def on_suspend(self, _signum: int, _frame: object) -> None:
        self.suspend = True

    def on_resume(self, _signum: int, _frame: object) -> None:
        self.resume = True


# What a write to a closed window or a closed pipe answers.
_CLOSED_TERMINAL = frozenset({errno.EIO, errno.EPIPE, errno.ENXIO})


def _closed_terminal(exc: BaseException, terminal: _TuiTerminal | None = None) -> bool:
    """Whether exc is the terminal gone: an OSError, or a termios.error,
    whose first argument is the errno, answering EIO, EPIPE or ENXIO, and,
    given the terminal, that terminal no longer answering. A failing SD
    card answers EIO too, and that read error is kept in a crash log."""
    if isinstance(exc, OSError):
        closed = exc.errno in _CLOSED_TERMINAL
    elif type(exc).__name__ == "error" and type(exc).__module__ == "termios":
        closed = bool(exc.args) and exc.args[0] in _CLOSED_TERMINAL
    else:
        closed = False
    return closed and (terminal is None or _terminal_gone(terminal))


def _terminal_gone(terminal: _TuiTerminal) -> bool:
    """Whether the terminal hung up: a closed window answers EIO to
    tcgetattr and to a write, a live one its settings. A Windows console
    has no settings to ask, and an empty write to it reaches nothing: the
    error is taken as it reads."""
    if os.name == "nt":
        return True
    import termios

    try:
        termios.tcgetattr(terminal.fd)
        terminal.stdout.write("")
        terminal.stdout.flush()
    except (termios.error, OSError, ValueError):
        return True
    return False


def _drop_closed_terminal() -> None:
    """Point stdout and stderr at nothing once the terminal is gone, so what
    they still hold is flushed somewhere at exit."""
    try:
        null = os.open(os.devnull, os.O_WRONLY)
    except OSError:
        # No null device to point them at: the flush at exit fails as before.
        return
    try:
        for stream in (sys.stdout, sys.stderr):
            try:
                fd = stream.fileno()
            except (ValueError, AttributeError, io.UnsupportedOperation):
                # A stream with no descriptor (a test's StringIO) has no
                # terminal behind it to lose.
                continue
            os.dup2(null, fd)
    finally:
        os.close(null)


def _tui_cleanup(
    terminal: _TuiTerminal, runs: list[_EngineRun], handlers: dict, state: TuiState,
) -> list[str]:
    """Stop the child, put the terminal and the signal handlers back: what failed."""
    failures: tuple = (OSError, ValueError)
    if os.name != "nt":
        import termios

        failures += (termios.error,)
    problems: list[str] = []

    def step(action: Callable[[], object]) -> None:
        try:
            action()
        except failures as exc:
            problems.append(str(exc) or type(exc).__name__)

    for name in ("SIGTERM", "SIGHUP", "SIGTSTP"):
        number = getattr(signal, name, None)
        if number is not None:
            step(functools.partial(signal.signal, number, signal.SIG_IGN))
    # An install stopped by a signal still gets to write its summary.
    for run in runs:
        step(functools.partial(run.stop, 10 if state.running and state.run == "install"
                               else 0))
    step(terminal.leave)
    for number, previous in handlers.items():
        step(functools.partial(signal.signal, number, previous))
    return problems
