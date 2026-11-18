"""Colours, the progress line and the terminal facts the output depends on."""
from __future__ import annotations

import os
import re
import shutil
import sys
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TextIO

from installer.events import EVENTS
from installer.text import format_size


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


class _Output:
    """What a run's text says. By default: what will happen, where, the
    progress, the result and the next step. --verbose adds every step, list
    and reason, the lines a beginner lost the result among. where_said is
    set once the BIOS folder was named before the result."""

    verbose = False
    where_said = False


OUTPUT = _Output()


def detail(*args: Any, **kwargs: Any) -> None:
    """Print a line only --verbose shows."""
    if OUTPUT.verbose:
        print(*args, **kwargs)


def format_duration(seconds: float) -> str:
    """0:42, 3:05 or 1:02:09."""
    seconds = max(0, int(seconds + 0.5))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02}:{secs:02}" if hours else f"{minutes}:{secs:02}"


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


class Progress:
    """Bytes and files across the parallel downloads, shown as they move.

    On a terminal one line redraws in place: a bar, the bytes, the speed and
    the time left. Elsewhere each finished file gets its line with --verbose,
    as a log wants it. Failures are always printed, quiet or not.
    """

    BAR = 24

    def __init__(self, total_files: int, total_bytes: int, term: Terminal,
                 events: bool = True) -> None:
        self.total_files = total_files
        self.expected_bytes = total_bytes
        self.total_bytes = max(total_bytes, 1)
        self.term = term
        self.files = 0
        self.bytes = 0
        self.resumed = 0
        # Bytes that came from this machine and not the network: a copy
        # found here, the pack, a resumed partial copy.
        self.local = 0
        # Files written to their place, which a stopped run counts: the
        # queue's length said "118 files installed" over 8 on disk.
        self.installed = 0
        # The entries of those files, which the end of the run counts apart.
        self.landed: list[dict] = []
        self.start = time.monotonic()
        self._drawn = 0.0
        self._evented = self.start
        self._lock = threading.Lock()
        # A data tree's archive draws the line and writes no event: the
        # progress events count the files of the download event.
        self.events = events

    def expect(self, total_bytes: int) -> None:
        """The size the transfer turns out to have, once its server says it."""
        with self._lock:
            self.expected_bytes = total_bytes
            self.total_bytes = max(total_bytes, 1)

    def add(self, count: int, resumed: bool = False, network: bool | None = None) -> None:
        """count bytes written, resumed ones left out of the speed. network
        is whether they came over the network, by default unless resumed."""
        with self._lock:
            self.bytes += count
            if resumed:
                self.resumed += count
            fetched = not resumed if network is None else network
            if not fetched:
                self.local += count
            now = time.monotonic()
            if self.term.live and not self.term.quiet and now - self._drawn >= 0.1:
                self._drawn = now
                self._draw()
            if self.events and EVENTS.on and now - self._evented >= EVENT_PROGRESS_INTERVAL:
                self._evented = now
                EVENTS.emit("progress", files_done=self.files, files_total=self.total_files,
                            bytes_done=self.bytes, bytes_total=self.expected_bytes)
                self.emit_transfer()

    def emit_transfer(self) -> None:
        """The transfer event: of the bytes done, those this machine held
        and those the network brought."""
        EVENTS.emit("transfer", bytes_local=self.local,
                    bytes_network=self.bytes - self.local)

    def forget_resumed(self, count: int) -> None:
        with self._lock:
            self.resumed -= count
            self.local -= count

    def transferred(self) -> int:
        """Bytes fetched by this run, a resumed partial copy excluded."""
        return self.bytes - self.resumed

    def done(self, dest: str, ok: bool, reason: str = "") -> None:
        with self._lock:
            self.files += 1
            line = None
            if not ok and not self.term.quiet:
                why = f" ({reason})" if reason else ""
                line = f"  {self.term.bad('FAILED')} {dest}{why}"
                SAID_FAILED.add(dest)
            elif not self.term.live and not self.term.quiet and OUTPUT.verbose:
                line = f"  [{self.files}/{self.total_files}] {dest} {self.term.ok('ok')}"
            if line is not None:
                self._clear()
                print(line, file=self.term.stream, flush=True)
            if self.term.live and not self.term.quiet:
                self._draw()

    def finish(self) -> None:
        with self._lock:
            self._clear()

    def elapsed(self) -> float:
        return time.monotonic() - self.start

    def _clear(self) -> None:
        if self.term.live and not self.term.quiet:
            print("\r\033[K", end="", file=self.term.stream, flush=True)

    def _draw(self) -> None:
        share = min(self.bytes / self.total_bytes, 1.0)
        elapsed = self.elapsed()
        # A resumed partial copy was on disk before the run started: counted
        # in the share, never in the speed.
        speed = self.transferred() / elapsed if elapsed > 0 else 0
        left = (self.total_bytes - self.bytes) / speed if speed > 0 else 0
        # Copies from a folder here count in no speed: "0 B/s  0:00 left"
        # was drawn under them, as the screen does not.
        timed = [f"{format_size(int(speed))}/s", f"{format_duration(left)} left"] \
            if self.transferred() > 0 else []
        parts = [
            f"{share * 100:5.1f}%",
            f"{format_size(self.bytes)} / {format_size(self.total_bytes)}",
            *timed,
            f"({self.files}/{self.total_files} files)",
        ]
        # One physical line, whatever the width: \r\033[K clears only the
        # line the cursor is on, so a wrapped line left a ghost per redraw
        # on an 80-column console. The bar gives way first, then the least
        # telling figures.
        width = terminal_size()[0] - 1
        while True:
            tail = "  ".join(parts)
            room = width - len(tail) - 6
            if room >= 10 or len(parts) == 1:
                break
            parts.pop()
        if room >= 10:
            bar_width = min(self.BAR, room)
            filled = int(share * bar_width)
            text = f"  [{'#' * filled}{'-' * (bar_width - filled)}] {tail}"
        else:
            text = f"  {tail}"
        print(f"\r\033[K{text[:width]}", end="", file=self.term.stream, flush=True)


# --events: one JSON object per line on stdout, for a program driving the
# installer (the handheld port shows its screens from them). Each kind has
# exactly these keys besides "event", in this order, and nothing else.
EVENT_SCHEMA = 1

# Seconds between two progress events while bytes arrive.
EVENT_PROGRESS_INTERVAL = 0.5

# The files a FAILED line of the progress named in this run: the end of
# the run names the others.
SAID_FAILED: set[str] = set()

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
