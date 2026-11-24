"""Whether the full screen runs here, and the keys, pads and mouse each input route reads."""
from __future__ import annotations

import argparse
import io
import os
import sys
from collections.abc import Mapping
from typing import TYPE_CHECKING, NamedTuple, TextIO

from installer.invocation import LISTING_FLAGS
from installer.terminal import TUI_MIN_COLS, TUI_MIN_ROWS, _enable_ansi, terminal_few_colours, terminal_without_ansi
from installer.text import screen_text

if TYPE_CHECKING:
    from installer.tui_state import TuiState

# Set for a child run handed the interface's own copy of the file list.
TUI_LIST_ENV = "RETROBIOS_TUI_LIST"
# Set for a child run whose choice options are the install record's, kept
# on the screen: a part of them that cannot apply is left out, as line mode
# leaves it out of a record it reads, never refused.
TUI_RECORD_ENV = "RETROBIOS_TUI_RECORDED"


TUI_MOUSE_ENV = "RETROBIOS_NO_MOUSE"


def _env_on(env: Mapping[str, str], name: str) -> bool:
    return env.get(name, "") not in ("", "0")


def plain_requested(args: argparse.Namespace, env: Mapping[str, str] | None = None) -> bool:
    """Whether the line questions were asked for: --plain, RETROBIOS_PLAIN, ACCESSIBLE."""
    env = os.environ if env is None else env
    return bool(args.plain) or _env_on(env, "RETROBIOS_PLAIN") or _env_on(env, "ACCESSIBLE")


# Each handheld launcher names the buttons that reach the interface
# (ports/shared/tui.txt exports RB_PAD as this), so the bar names those
# buttons and no others.
TUI_PAD_ENV = "RETROBIOS_PAD"


class TuiRoute(NamedTuple):
    """How one input route names the keys, read by the screen and by
    scripts/generate_installer_doc.py for the key table of the page.

    bar maps a key of the bottom line, written in the "both" form ("A/Enter
    Install"), to the route's own name, None for a key the route lacks: a PC
    user read "A/Enter", a muOS player was told a Select+Start that muxterm
    does not have. help names each action of the help screen, the buttons
    first, then the keys a keyboard plugged in also has, None for an action
    the route lacks. stop is what stops an install the second time, then the
    first time.
    """

    bar: Mapping[str, str | None]
    help: Mapping[str, str | None]
    stop: tuple[str, str]


# retrobios.gptk: A Enter, B Esc, X Space, Y Tab, L1 and R1 a page, Start
# Enter, Select Esc, Select then Start the kill.
_GPTOKEYB = TuiRoute(
    {"A/Enter": "A", "B/Esc": "B", "X/Space": "X", "Y/o": "Y", "?": None, "/": None,
     "Ctrl-C": "Select+Start", "Enter": "A", "Esc": "B", "Ctrl-U": None},
    {"move": "D-pad, Up/Down", "page": "L1/R1, PgUp/PgDn", "ok": "A, Start, Enter",
     "tick": "X, Space, Right/Left", "options": "Y, Tab, o", "back": "B, Select, Esc",
     "stop": "B, Esc, Ctrl-C", "kill": "Select, then Start", "enter": "A, Enter",
     "esc": "B, Esc"},
    ("B", "B or Select+Start"))
# keys is a keyboard's, and both names the button and the key where nothing
# says which one is held. The others are the values of RETROBIOS_PAD.
TUI_ROUTES: dict[str, TuiRoute] = {
    "keys": TuiRoute(
        {"A/Enter": "Enter", "B/Esc": "Esc", "X/Space": "Space", "Y/o": "o"},
        {"move": "Up/Down, k/j", "page": "PgUp/PgDn", "ok": "Enter",
         "tick": "Space, Right/Left", "options": "o, Tab", "back": "Esc, Backspace",
         "stop": "Esc, Ctrl-C", "kill": None, "enter": "Enter", "esc": "Esc"},
        ("Esc or Ctrl-C", "Esc or Ctrl-C")),
    "both": TuiRoute(
        {},
        {"move": "Up/Down, k/j", "page": "PgUp/PgDn, L1/R1", "ok": "A/Enter, Start",
         "tick": "X, Space, Right/Left", "options": "Y, o, Tab", "back": "B/Esc, Backspace",
         "stop": "B/Esc, Ctrl-C", "kill": "Select+Start", "enter": "Enter", "esc": "Esc"},
        ("B or Ctrl-C", "B, Ctrl-C or Select+Start")),
    "gptokeyb": _GPTOKEYB,
    # gptokeyb2 with retrobios.gptk inside muxterm, which no longer reads the
    # pad: the gptokeyb buttons. muxterm keeps PgUp and PgDn for its
    # scrollback, and the launcher sends nothing on L1 and R1 there: Left and
    # Right page.
    "gptokeyb_muxterm": _GPTOKEYB._replace(help={**_GPTOKEYB.help,
                                                 "page": "D-pad Left/Right",
                                                 "tick": "X, Space"}),
    # muxterm's own keys: Start Enter, B Backspace, Y Space, Menu closes the
    # terminal. A, X, L1 and R1 send nothing, Select shows its keyboard, and
    # the D-pad's Left and Right page a list.
    "muxterm": TuiRoute(
        {"A/Enter": "Start", "B/Esc": "B", "X/Space": "Y", "Y/o": None, "?": None,
         "/": None, "Ctrl-C": "Menu", "Enter": "Start", "Esc": None, "Ctrl-U": None},
        {"move": "D-pad, Up/Down", "page": "D-pad Left/Right", "ok": "Start, Enter",
         "tick": "Y, Space", "options": "o, Tab", "back": "B, Esc, Backspace",
         "stop": "B, Esc, Ctrl-C", "kill": None, "enter": "Start, Enter", "esc": "Esc"},
        ("B", "B")),
    # RetroBIOS.sh.keys: the gptokeyb buttons, and no combo that ends the run.
    "evmapy": TuiRoute(
        {"A/Enter": "A", "B/Esc": "B", "X/Space": "X", "Y/o": "Y", "?": None, "/": None,
         "Ctrl-C": None, "Enter": "A", "Esc": "B", "Ctrl-U": None},
        {"move": "D-pad, Up/Down", "page": "L1/R1, PgUp/PgDn", "ok": "A, Start, Enter",
         "tick": "X, Space, Right/Left", "options": "Y, Tab, o",
         "back": "B, Select, Esc", "stop": "B, Esc, Ctrl-C", "kill": None,
         "enter": "A, Enter", "esc": "B, Esc"},
        ("B", "B")),
    # Buttons that are keys already: A Space, Start Enter, L2 Tab, R2
    # Backspace. B is Left Ctrl, a modifier: alone it sends no byte to a
    # terminal (the console's keyboard driver only records its state), so
    # the interface never sees it, nor X, Y and Select (Shift, Alt, Ctrl).
    "miyoo": TuiRoute(
        {"A/Enter": "A", "B/Esc": "R2", "X/Space": "A", "Y/o": "L2", "?": None, "/": None,
         "Ctrl-C": None, "Enter": "Start", "Esc": None, "Ctrl-U": None},
        {"move": "D-pad, Up/Down", "page": "L1/R1, PgUp/PgDn", "ok": "A, Start, Enter",
         "tick": "A, Space, Right/Left", "options": "L2, Tab, o",
         "back": "R2, Esc, Backspace", "stop": "R2, Esc, Ctrl-C", "kill": None,
         "enter": "Start, Enter", "esc": "Esc"},
        ("R2", "R2")),
}
TUI_PAD_ROUTES = tuple(name for name in TUI_ROUTES if name not in ("keys", "both"))
# Set by Steam for what it starts, and by gamescope: a controller may be
# all there is, mapped by Steam Input to keys nobody here can name.
_STEAM_MARKERS = ("SteamGamepadUI", "SteamDeck", "SteamGameId", "GAMESCOPE_WAYLAND_DISPLAY")


# Seconds the interface waits for a first key, no run going, before it
# closes, set by a launcher whose mapper may never open the pad: the screen
# would otherwise hold a handheld that has no other way out.
TUI_IDLE_ENV = "RETROBIOS_IDLE_EXIT"
TUI_IDLE_WORDS = "No button pressed, closing."


def tui_idle_exit(env: Mapping[str, str] | None = None) -> float | None:
    """The seconds RETROBIOS_IDLE_EXIT names, None when unset or not a
    positive number."""
    env = os.environ if env is None else env
    try:
        seconds = float(env.get(TUI_IDLE_ENV, "").strip())
    except ValueError:
        return None
    return seconds if 0 < seconds < float("inf") else None


def tui_pad_route(os_type: str, env: Mapping[str, str] | None = None) -> str:
    """The keys the hints name: a launcher's pad route, "keys" at a desktop,
    "both" (button and key) where nothing says which one is held."""
    env = os.environ if env is None else env
    named = env.get(TUI_PAD_ENV, "").strip().lower()
    if named:
        return named if named in TUI_PAD_ROUTES else "both"
    if any(env.get(name) for name in _STEAM_MARKERS):
        return "both"
    if os_type in ("windows", "darwin", "wsl"):
        return "keys"
    # A Linux console is where a handheld draws: a desktop or a remote
    # shell is a keyboard's.
    if os_type == "linux" and env.get("TERM") != "linux" and any(
            env.get(name) for name in ("DISPLAY", "WAYLAND_DISPLAY", "SSH_CONNECTION",
                                       "SSH_TTY")):
        return "keys"
    return "both"


def _terminal_size(stream: TextIO) -> tuple[int, int]:
    try:
        size = os.get_terminal_size(stream.fileno())
    except (OSError, ValueError, AttributeError, io.UnsupportedOperation):
        return 0, 0
    return size.columns, size.lines


def colour_blocker(env: Mapping[str, str], stream: TextIO) -> str:
    """Why the full-screen interface draws without colour, "" when it paints
    with the roles of COLOUR_ROLES. The text is the same either way."""
    if env.get("NO_COLOR"):
        return "NO_COLOR is set"
    isatty = getattr(stream, "isatty", None)
    if not (isatty and isatty()):
        return "the output is not a terminal"
    if os.name != "nt" and env.get("TERM", "") in ("", "dumb"):
        return "TERM is dumb or not set"
    return terminal_few_colours(env)


def _tui_flag_blocker(args: argparse.Namespace) -> str:
    """The option of a run without questions, said as the reason."""
    for flag, given in (
        ("--check", args.check), ("--dry-run", args.dry_run),
        *((flag, getattr(args, attr)) for flag, attr in LISTING_FLAGS),
        ("--events", args.events),
        ("--quiet", args.quiet), ("--yes", args.yes), ("--no-input", args.no_input),
        ("--restore", args.restore is not None),
        ("--pack", getattr(args, "pack", None) is not None),
    ):
        if given:
            return f"{flag} runs without questions"
    return ""


def _tui_keys_blocker(stdin: TextIO) -> str:
    """Why single key presses cannot be read here, "" when they can."""
    if os.name == "nt":
        import importlib

        try:
            importlib.import_module("msvcrt")
        except ImportError:
            return "this Python has no msvcrt to read keys"
        if not _enable_ansi():
            return "this console does not draw escape sequences (Windows 10 or later does)"
        return ""
    try:
        import termios
    except ImportError:
        return "this Python has no termios to read keys"
    try:
        termios.tcgetattr(stdin.fileno())
    except (termios.error, OSError, ValueError, AttributeError,
            io.UnsupportedOperation) as exc:
        return f"single key presses cannot be read here ({exc})"
    return ""


class TuiObstacle(NamedTuple):
    """What keeps the full screen from running here: its kind ("flag",
    "stream", "term", "drawing", "size", "keys"), the reason in words, and
    the TERM or the size it was decided on."""
    kind: str
    text: str
    term: str = ""
    size: tuple[int, int] = (0, 0)


def tui_obstacle(
    args: argparse.Namespace, stdin: TextIO | None = None, stdout: TextIO | None = None,
    env: Mapping[str, str] | None = None,
) -> TuiObstacle | None:
    """What keeps the full-screen interface from running here, None when nothing does."""
    env = os.environ if env is None else env
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    flag_blocker = _tui_flag_blocker(args)
    if flag_blocker:
        return TuiObstacle("flag", flag_blocker)
    for name, stream in (("input", stdin), ("output", stdout)):
        isatty = getattr(stream, "isatty", None)
        if not (isatty and isatty()):
            return TuiObstacle("stream", f"the {name} is not a terminal")
    term = env.get("TERM", "")
    if os.name != "nt" and term in ("", "dumb"):
        return TuiObstacle("term", "TERM is dumb or not set", term=term)
    drawing = terminal_without_ansi(env)
    if drawing:
        return TuiObstacle("drawing", drawing, term=term)
    # A pseudo-terminal nobody sized reports 0x0: script(1) fed from a pipe
    # is one, and the line questions run there as they always have.
    cols, rows = _terminal_size(stdout)
    if cols < TUI_MIN_COLS or rows < TUI_MIN_ROWS:
        return TuiObstacle("size", f"the terminal is {cols}x{rows}, smaller than "
                           f"{TUI_MIN_COLS}x{TUI_MIN_ROWS}", size=(cols, rows))
    keys = _tui_keys_blocker(stdin)
    return TuiObstacle("keys", keys) if keys else None


def tui_blocker(
    args: argparse.Namespace, stdin: TextIO | None = None, stdout: TextIO | None = None,
    env: Mapping[str, str] | None = None,
) -> str:
    """Why the full-screen interface cannot run here, "" when it can."""
    obstacle = tui_obstacle(args, stdin, stdout, env)
    return obstacle.text if obstacle else ""


def line_mode_reason(obstacle: TuiObstacle | None) -> str:
    """Why the questions come line by line, in one line, for a terminal the
    full screen cannot draw on: its size or its TERM. "" for a run that
    asks nothing (--check, a pipe), and for a pseudo-terminal nobody sized
    (script fed from a pipe is 0x0), which is no window."""
    if obstacle is None:
        return ""
    if obstacle.kind == "size":
        cols, rows = obstacle.size
        if not (cols and rows):
            return ""
        return (f"The window is {cols}x{rows}: questions come line by line "
                f"({TUI_MIN_COLS}x{TUI_MIN_ROWS} for the full screen).")
    if obstacle.kind == "term":
        term = screen_text(obstacle.term)
        return (f"TERM={term}: questions come line by line." if term
                else "TERM is not set: questions come line by line.")
    if obstacle.kind == "drawing":
        return f"{obstacle.text}: questions come line by line."
    return ""


# TERM values of terminals that report no mouse the xterm way: the Linux
# console (gpm is its own protocol), the DEC VTs and BSD consoles.
_NO_MOUSE_TERMS = ("linux", "vt", "cons", "ansi")


def tui_mouse_blocker(
    stdin: TextIO | None = None, stdout: TextIO | None = None,
    env: Mapping[str, str] | None = None,
) -> str:
    """Why the full screen leaves the mouse to the terminal, "" when it
    asks for clicks. A pad route has no pointer and its mapper may send
    anything a report would be confused with, and RETROBIOS_NO_MOUSE keeps
    the terminal's own selection everywhere."""
    env = os.environ if env is None else env
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    if _env_on(env, TUI_MOUSE_ENV):
        return f"{TUI_MOUSE_ENV} is set"
    if env.get(TUI_PAD_ENV, "").strip():
        return f"{TUI_PAD_ENV} names a controller route"
    if os.name == "nt":
        # msvcrt.getwch reads keys, never a console mouse record.
        return "a Windows console reports no clicks as keys"
    for name, stream in (("input", stdin), ("output", stdout)):
        isatty = getattr(stream, "isatty", None)
        if not (isatty and isatty()):
            return f"the {name} is not a terminal"
    term = env.get("TERM", "").strip().lower()
    if term in ("", "dumb", "unknown") or term.startswith(_NO_MOUSE_TERMS):
        return f"TERM={term} reports no clicks" if term else "TERM is not set"
    return ""


def tui_wants_mouse(state: TuiState, lines: list[str]) -> bool:
    """Whether the frame takes clicks: not where a command or the result is
    shown, so the terminal's own selection copies it as it always has, nor
    where a path is typed, which a middle or right click pastes into."""
    if state.help:
        return True
    if state.screen == "result":
        # A tap on the bar's Exit closes it, where a touch screen has no
        # Enter: the result is printed again in the terminal once the
        # screen closes, its commands selected there as anywhere.
        return True
    if state.screen in ("command", "path"):
        return False
    # Read from the frame's model: a command wrapped over lines was missed
    # by a match on the drawn text, its URL cut in two.
    return not any(getattr(line, "command", False) for line in lines)
