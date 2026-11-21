"""Line mode's output and questions: what a run prints, its progress line and the answers it reads."""
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, TextIO

from installer.events import EVENTS, EVENT_PROGRESS_INTERVAL
from installer.host_fs import _host_path
from installer.terminal import TUI_MIN_COLS, Terminal, terminal_size
from installer.text import _split_word, cell_width, format_duration, format_size


def _typed_folder(raw: str) -> Path:
    """A folder typed at a question, read as a shell reads an argument.

    Explorer's "Copy as path" puts quotes around it, and users quote a path
    with spaces: kept, they sent the files into a folder named `"` under
    the current directory, and the run said Done.
    """
    text = raw.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        text = text[1:-1].strip()
    # Under WSL, D: and D:\ are the Windows drive the screen calls D:.
    return _host_path(os.path.expandvars(os.path.expanduser(text)))


def _ask(prompt: str) -> str:
    """An answer, or a stop: Ctrl+D at a question is Ctrl+C.

    Both used to leave with 0, so `install.sh && retroarch` went on with no
    BIOS. They now end where Ctrl+C ends everywhere else, on 130.
    """
    try:
        return input(prompt).strip()
    except EOFError:
        print()
        raise KeyboardInterrupt from None


# A quit chosen at a question or on the screen: nothing was installed, as
# gh ends a prompt cancelled. 130 is 128 plus SIGINT, which shells read as a
# run killed by Ctrl-C, and 0 let `install.sh && retroarch` start RetroArch
# on no BIOS. Ctrl-C and Ctrl-D keep 130.
QUIT_CODE = 2


def _quit() -> None:
    """q at a question ends the run on QUIT_CODE."""
    sys.exit(QUIT_CODE)


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


# The files a FAILED line of the progress named in this run: the end of
# the run names the others.
SAID_FAILED: set[str] = set()


# Answers that stop: every menu before this one taught q as quit.
_REFUSALS = ("n", "q", "quit", "exit", "stop", "abort")


def fold_line(text: str, hang: str = "  ") -> str:
    """A line wrapped between words at the terminal's width, the lines after
    the first indented by hang under its own lead, a word wider than a line
    cut after a slash: left to the terminal, below 40 columns "Found Onion
    at /media/moi/ONION/BIOS" broke inside "(RetroArch files)" and a folder
    inside its name."""
    width = terminal_size()[0]
    cols = max(width - 1, 8)
    if cell_width(text) <= cols or width >= TUI_MIN_COLS or not _is_terminal(sys.stdout):
        # A pipe or a log folds nothing, and from 40 columns a folder is left
        # whole for the terminal to fold, copied as one line.
        return text
    lead = text[:len(text) - len(text.lstrip(" "))]
    prefix = lead + hang
    lines: list[str] = []
    line = lead
    for word in text.split():
        joined = f"{line} {word}" if line.strip() else line + word
        if cell_width(joined) <= cols:
            line = joined
            continue
        if line.strip():
            lines.append(line)
        pieces = _split_word(word, max(cols - len(prefix), 1))
        lines += [prefix + piece for piece in pieces[:-1]]
        line = prefix + pieces[-1]
    lines.append(line)
    return "\n".join(lines)


def _live_stdout() -> bool:
    """Whether the standard output draws a moving line (Terminal.live)."""
    return Terminal(sys.stdout).live


def _is_terminal(stream: TextIO) -> bool:
    isatty = getattr(stream, "isatty", None)
    try:
        return bool(isatty and isatty())
    except (OSError, ValueError):
        return False


def _confirm(prompt: str) -> bool:
    """Yes unless the answer refuses: n, no, or one of the quit words."""
    answer = _ask(prompt).strip().lower()
    return not (answer.startswith("n") or answer in _REFUSALS)


def _answer_yes(prompt: str) -> bool:
    """Yes only to y or yes: a removal is never the default answer."""
    return _ask(prompt).strip().lower() in ("y", "yes")


class ReadCounter:
    """Files read so far, as event_kind events and on the live line: the
    program driving the installer gets the count the terminal gets."""

    def __init__(self, total: int, term: Terminal | None, event_kind: str,
                 noun: str = "") -> None:
        self.total = total
        self.event_kind = event_kind
        self.noun = noun
        self.done = 0
        self.evented = 0.0
        self.drawn = 0.0
        live = term is not None and term.live and not term.quiet
        self.stream = term.stream if live and term is not None else None

    def step(self, final: bool = False) -> None:
        now = time.monotonic()
        if EVENTS.on and (final or now - self.evented >= EVENT_PROGRESS_INTERVAL):
            self.evented = now
            EVENTS.emit(self.event_kind, files_done=self.done, files_total=self.total)
        if self.stream is not None and (final or now - self.drawn >= 0.1):
            self.drawn = now
            print(f"\r  read {self.done}/{self.total}{self.noun}", end="", file=self.stream,
                  flush=True)

    def end(self) -> None:
        if self.total:
            self.step(final=True)
            if self.stream is not None:
                print("\r\033[K", end="", file=self.stream, flush=True)
