"""The terminal: what the output stream shows, its size, its colours and its TERM description."""
from __future__ import annotations

import os
import re
import shutil
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TextIO


def _kernel32() -> Any:
    """kernel32 from ctypes.windll, which typeshed declares for win32 only.
    AttributeError where the system has no windll."""
    import importlib

    return importlib.import_module("ctypes").windll.kernel32


def _enable_ansi() -> bool:
    """Whether escape sequences reach the terminal as colour and redraws.

    Windows 10 consoles interpret them once virtual terminal processing is
    switched on. Older ones print them raw, so the answer is then no.
    """
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = _kernel32()
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except (AttributeError, OSError):
        return False


# The roles text is painted with, from the 16 basic colours only: a
# handheld's Linux console has no more. The screens and the line questions
# name a role, never a code. Magenta is the hue that stays legible on black
# and on white in the xterm, VGA, Tango and Campbell palettes, so it is the
# accent, bold. Yellow reads poorly on white: it paints a status word, never
# a sentence. Bold red is bright red on the Linux console, where plain red on
# black is the weakest pair.
COLOUR_ROLES = {
    "accent": "1;35",
    "success": "32",
    "warning": "33",
    "failure": "1;31",
    "muted": "2",
    "strong": "1",
    # The accent reversed: the row in focus, its > kept for no colour.
    "selected": "7;35",
}

# The words a status takes its role from, wherever it is said. A count of
# zero is no news and stays plain: "0 missing" is not a warning.
_STATUS_WORDS = tuple((re.compile(pattern), role) for pattern, role in (
    (r"(?<!of )\b[1-9][\d,]* (?:files? )?(?:installed|in place|already in place"
     r"|ok|copied|downloaded)\b|\bDone\b|\bEvery file on the list is in place\b|^ *ok\b", "success"),
    (r"(?<!of )\b[1-9][\d,]* (?:files? )?(?:failed|refused)\b|\bFAILED\b|\bfailed:"
     r"|\bFinished with errors\b|\bNothing was installed\b|\bSomething went wrong\b",
     "failure"),
    (r"(?<!of )\b[1-9][\d,]* (?:files? )?(?:(?:still )?missing|wrong cop(?:y|ies)|not fetched"
     r"|left out|not downloaded)\b|\bFinished with files missing\b|\bNothing installed\b"
     r"|\bStopped\b|\bLeft out\b|\bNot enough space\b", "warning"),
))


def _apart(spans: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """The spans in order, none empty, the longer kept where two overlap."""
    kept: list[tuple[int, int, str]] = []
    for span in sorted(spans, key=lambda span: (span[0], -span[1])):
        if span[1] > span[0] and (not kept or span[0] >= kept[-1][1]):
            kept.append(span)
    return kept


def status_spans(text: str) -> list[tuple[int, int, str]]:
    """(start, end, role) of the status words in text, in order, apart."""
    return _apart([(match.start(), match.end(), role) for pattern, role in _STATUS_WORDS
                   for match in pattern.finditer(text)])


def _sgr(role: str) -> str:
    """The SGR sequence of a role, or of roles joined by + ("strong+success")."""
    return "\033[0;" + ";".join(COLOUR_ROLES[name] for name in role.split("+")) + "m"


def painted(text: str, spans: list[tuple[int, int, str]], base: str = "") -> str:
    """text with each span in its role and the rest in the base role, a code
    written where the role changes and the colours reset at the end. The
    characters are those of text, in the same order. A span in "plain"
    takes the terminal's own colours."""
    pieces: list[tuple[str, str]] = []
    at = 0
    for start, end, role in spans:
        pieces += [(text[at:start], base), (text[start:end], role)]
        at = end
    pieces.append((text[at:], base))
    out: list[str] = []
    current = ""
    for piece, role in pieces:
        role = "" if role == "plain" else role
        if not piece:
            continue
        if role != current:
            out.append(_sgr(role) if role else "\033[0m")
            current = role
        out.append(piece)
    if current:
        out.append("\033[0m")
    return "".join(out)


_SGR = re.compile(r"\x1b\[[0-9;]*m")


def unpainted(text: str) -> str:
    """text without its SGR codes."""
    return _SGR.sub("", text)


class Terminal:
    """What the output stream can show: a live line, colour, or neither.

    A pipe or a log gets plain lines, and NO_COLOR and TERM=dumb or unset are
    honoured, as is a terminal whose description moves no cursor the ANSI way
    (vt52), or names fewer than 8 colours (vt100), which keeps the line live
    and plain.
    As no-color.org reads it, an empty NO_COLOR is not set: `NO_COLOR= cmd`
    turned colour off. FORCE_COLOR or CLICOLOR_FORCE paints a pipe, for a
    log viewer that shows colour, and never makes the line live.
    """

    def __init__(self, stream: TextIO | None = None, quiet: bool = False) -> None:
        self.stream = stream or sys.stdout
        self.quiet = quiet
        isatty = getattr(self.stream, "isatty", None)
        # An unset TERM is a dumb one, as the full screen reads it. A Windows
        # console sets none and draws the sequences once _enable_ansi is on.
        term = os.environ.get("TERM", "")
        self.live = (bool(isatty and isatty()) and term != "dumb"
                     and (bool(term) or os.name == "nt")
                     and not terminal_without_ansi(os.environ))
        forced = any(os.environ.get(name, "0") not in ("", "0")
                     for name in ("FORCE_COLOR", "CLICOLOR_FORCE"))
        self.colour = (
            ((self.live and not terminal_few_colours(os.environ)) or forced)
            and not os.environ.get("NO_COLOR") and _enable_ansi()
        )
        if not self.colour:
            self.live = self.live and os.name != "nt"

    def paint(self, text: str, role: str) -> str:
        return f"\033[{COLOUR_ROLES[role]}m{text}\033[0m" if self.colour else text

    def status(self, text: str) -> str:
        """text with its status words in their roles (status_spans)."""
        return painted(text, status_spans(text)) if self.colour else text

    def ok(self, text: str) -> str:
        return self.paint(text, "success")

    def bad(self, text: str) -> str:
        return self.paint(text, "failure")

    def dim(self, text: str) -> str:
        return self.paint(text, "muted")

    def bold(self, text: str) -> str:
        return self.paint(text, "strong")


# The fewest columns a line question lays itself out in: below it a row is
# all number, and the terminal folds what is printed whatever it is.
LINE_MIN_COLS = 20


def terminal_size() -> tuple[int, int]:
    """(columns, lines) of the terminal line mode prints to, the one reading
    every layout of it makes. Python 3.8 gives a pty of no size as 0 and 0,
    where 3.11 falls back to 80 and 24: a list laid out in 0 columns never
    ended, the plan printed an empty heading, and the progress line lost
    every figure but its percentage."""
    size = shutil.get_terminal_size((80, 24))
    return max(size.columns or 80, LINE_MIN_COLS), size.lines or 24


# Where ncurses finds a terminal's compiled description after $TERMINFO,
# ~/.terminfo and $TERMINFO_DIRS.
_TERMINFO_DIRS = ("/etc/terminfo", "/lib/terminfo", "/usr/share/terminfo",
                  "/usr/lib/terminfo", "/usr/share/lib/terminfo")
# cursor_address, string capability 10 of term(5).
_TERMINFO_CUP = 10
# max_colors, numeric capability 13.
_TERMINFO_COLORS = 13


def _terminfo_folders(env: Mapping[str, str]) -> list[Path]:
    folders = [Path(env["TERMINFO"])] if env.get("TERMINFO") else []
    if env.get("HOME"):
        folders.append(Path(env["HOME"]) / ".terminfo")
    # An empty entry stands for the system's folders, which come last anyway.
    folders += [Path(part) for part in env.get("TERMINFO_DIRS", "").split(":") if part]
    return folders + [Path(folder) for folder in _TERMINFO_DIRS]


def _terminfo_header(data: bytes) -> tuple[int, int, int, int, int] | None:
    """Of a compiled term(5) entry: the width of a number, the counts of
    names bytes, booleans, numbers and strings. None when data is none."""
    if len(data) < 12:
        return None
    # The legacy format stores numbers in 2 bytes, the extended one in 4.
    width = {0o432: 2, 0o1036: 4}.get(int.from_bytes(data[0:2], "little", signed=True))
    if width is None:
        return None
    names, bools, numbers, strings = (int.from_bytes(data[at:at + 2], "little", signed=True)
                                      for at in (2, 4, 6, 8))
    return width, names, bools, numbers, strings


def terminfo_number(data: bytes, index: int) -> int | None:
    """Numeric capability index of a compiled term(5) entry, -1 when the
    entry lacks it, None when data is no compiled entry."""
    header = _terminfo_header(data)
    if header is None:
        return None
    width, names, bools, numbers, _strings = header
    if index >= numbers:
        return -1
    start = 12 + names + bools
    start += start % 2 + index * width
    if start + width > len(data):
        return None
    value = int.from_bytes(data[start:start + width], "little", signed=True)
    return value if value >= 0 else -1


def terminfo_string(data: bytes, index: int) -> str | None:
    """String capability index of a compiled term(5) entry, "" when the
    entry lacks it, None when data is no compiled entry."""
    def short(at: int) -> int:
        return int.from_bytes(data[at:at + 2], "little", signed=True)

    header = _terminfo_header(data)
    if header is None:
        return None
    width, names, bools, numbers, strings = header
    offsets = 12 + names + bools
    offsets += offsets % 2 + numbers * width
    if index >= strings:
        return ""
    at = short(offsets + 2 * index)
    if at < 0:
        return ""
    start = offsets + 2 * strings + at
    end = data.find(b"\0", start)
    if end < 0:
        return None
    return data[start:end].decode("latin-1")


def _terminfo_data(term: str, env: Mapping[str, str]) -> bytes | None:
    """TERM's compiled description, the first found, None when none is:
    Windows, Android and many handheld images carry none."""
    if not term or "/" in term or term.startswith("."):
        return None
    for folder in _terminfo_folders(env):
        # Linux files xterm under x/, macOS under 78/.
        for sub in (term[0], f"{ord(term[0]):02x}"):
            try:
                return (folder / sub / term).read_bytes()
            except (OSError, ValueError):
                continue
    return None


def terminal_cursor_address(term: str, env: Mapping[str, str]) -> str | None:
    """How TERM's description here moves the cursor, "" when it cannot,
    None when no description is found, and the screen is not held back
    for it."""
    data = _terminfo_data(term, env)
    return None if data is None else terminfo_string(data, _TERMINFO_CUP)


def terminal_colours(term: str, env: Mapping[str, str]) -> int | None:
    """The colours TERM's description here names, 0 when it names none
    (vt100), None when no description is found or it cannot be read."""
    data = _terminfo_data(term, env)
    if data is None:
        return None
    count = terminfo_number(data, _TERMINFO_COLORS)
    return None if count is None else max(count, 0)


def terminal_few_colours(env: Mapping[str, str]) -> str:
    """Why TERM's description here leaves colour off, "" when it does not:
    no description is no refusal, as for the cursor."""
    if os.name == "nt":
        return ""
    term = env.get("TERM", "")
    count = terminal_colours(term, env)
    if count is not None and count < 8:
        return f"TERM={term} names {count} colours, fewer than 8"
    return ""


def terminal_without_ansi(env: Mapping[str, str]) -> str:
    """Why TERM's description here says the ANSI sequences the screen and
    the progress line write would print as text, "" when it does not."""
    if os.name == "nt":
        return ""
    term = env.get("TERM", "")
    cup = terminal_cursor_address(term, env)
    if cup == "":
        return f"TERM={term} cannot move the cursor"
    if cup is not None and not cup.startswith(("\x1b[", "\x9b")):
        return f"TERM={term} does not take the escape sequences the screen is drawn with"
    return ""


TUI_MIN_COLS = 40


TUI_MIN_ROWS = 12
