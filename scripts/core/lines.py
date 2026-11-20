"""Line numbers of offsets in a text, read from one index of line starts."""

from __future__ import annotations

import bisect


class LineIndex:
    """1-based line of any offset of *text*, by binary search.

    Counting the newlines before each match is O(n) per lookup: a parser
    that reports the line of every match of a file reads it once here.
    """

    def __init__(self, text: str) -> None:
        self._starts = [0]
        position = text.find("\n")
        while position != -1:
            self._starts.append(position + 1)
            position = text.find("\n", position + 1)

    def line(self, offset: int) -> int:
        return bisect.bisect_right(self._starts, offset)

    def start(self, line: int) -> int:
        """Offset of the first character of a 1-based line."""
        return self._starts[line - 1]
