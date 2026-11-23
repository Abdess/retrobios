"""A download's progress, redrawn as a bar on a terminal or one line in a log."""

from __future__ import annotations

import os
import shutil
import sys

from core.sizes import size_text


class ProgressBar:
    """Draws each part's progress on standard output.

    A redrawn bar only on a terminal: written to a log, 32,768 redraws of a
    2 GiB part made one line of nearly 3 MB.
    """

    def __init__(self) -> None:
        self.live = sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
        self.label = ""
        self.done = 0
        self.shown = -1

    def start(self, label: str) -> None:
        """Begin the bar of one part, named *label*."""
        self.label = label
        self.done = 0
        self.shown = -1

    def update(self, done: int, total: int) -> None:
        """Count *done* bytes and redraw the bar when the percentage moves."""
        self.done = done
        if total <= 0 or not self.live:
            return
        pct = done * 100 // total
        if pct == self.shown:
            return
        self.shown = pct
        columns = shutil.get_terminal_size((80, 24)).columns
        line = progress_line(self.label, done, total, columns)
        print(f"\r\033[K{line}", end="", flush=True)

    def finish(self) -> None:
        """End the bar's line, or write the one line a log gets."""
        if self.live:
            print()
        else:
            print(f"  {self.label}{self.done:,} bytes")


def progress_line(label: str, done: int, total: int, columns: int) -> str:
    """One physical line shorter than the terminal: a wrapped line leaves a
    copy of itself on every redraw, since \\r goes back one row only. The
    bar shrinks first, then goes."""
    pct = done * 100 // total
    figures = f" {pct}% ({size_text(done)}/{size_text(total)})"
    room = min(50, columns - 1 - len(f"  {label}[]") - len(figures))
    if room < 10:
        return f"  {label}{figures.strip()}"[: columns - 1]
    filled = room * pct // 100
    return f"  {label}[{'=' * filled}{' ' * (room - filled)}]{figures}"
