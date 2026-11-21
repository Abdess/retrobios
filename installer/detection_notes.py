"""What detection says, kept as lines the screen reads and printed as it comes in line mode."""
from __future__ import annotations

import contextlib
import sys
from collections.abc import Iterator
from typing import TextIO

# Each line detection said, in order, other than a folder it could not look
# in (_DETECTION_REFUSED keeps those): a system found with no folder, a
# configuration naming a folder nobody can type, an Android folder out of
# reach, a card that fits two systems.
DETECTION_NOTES: list[str] = []
# Set while the full screen runs detection: it shows the notes and the
# refusals itself, and a line printed under it would tear the screen.
_HELD = {"active": False}


def echo_detection(line: str, stream: TextIO | None = None) -> None:
    """Print a line detection says, unless the screen shows it itself."""
    if not _HELD["active"]:
        print(line, file=stream if stream is not None else sys.stderr)


def note_detection(line: str, stream: TextIO | None = None) -> None:
    """Keep a line detection says, and print it in line mode."""
    DETECTION_NOTES.append(line)
    echo_detection(line, stream)


@contextlib.contextmanager
def detection_held() -> Iterator[None]:
    """Detection that keeps its lines without printing them."""
    outer = _HELD["active"]
    _HELD["active"] = True
    try:
        yield
    finally:
        _HELD["active"] = outer
