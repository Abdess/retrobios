"""C and C++ source read the way the compiler reads it: comments apart from
code, string and character literals kept whole, macro calls split into their
arguments (MAME, FBNeo and flycast drivers)."""

from __future__ import annotations

import re

_COMMENT_OR_LITERAL = re.compile(
    r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', re.S
)


class DriverSourceError(ValueError):
    """The driver source does not have the shape the reader knows."""


def blank_comments(text: str, keep_lines: bool = True) -> str:
    """Text with every comment blanked, literals untouched.

    By default a comment becomes as many spaces as it has characters, its
    newlines kept: offsets and line numbers survive, so a block found in the
    result is cited at its line in the file, and a ROM_START written inside
    a comment is not a block. With `keep_lines` false a comment becomes one
    space, as translation phase 3 does: a directive a comment spans several
    lines of stays one line.
    """

    def blank(match: re.Match[str]) -> str:
        found = match.group(0)
        if found[0] in "\"'":
            return found
        return re.sub(r"[^\n]", " ", found) if keep_lines else " "

    return _COMMENT_OR_LITERAL.sub(blank, text)


def call_span(text: str, start: int) -> tuple[list[str], int]:
    """The top-level arguments of the call whose opening parenthesis ends at
    *start*, literals kept whole, and the offset just past its parenthesis."""
    args: list[str] = []
    current: list[str] = []
    depth, i, n = 1, start, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            current.append(text[i : j + 1])
            i = j + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                args.append("".join(current).strip())
                return args, i + 1
        elif c == "," and depth == 1:
            args.append("".join(current).strip())
            current = []
            i += 1
            continue
        current.append(c)
        i += 1
    raise DriverSourceError("unterminated macro call")


def call_args(text: str, start: int) -> list[str]:
    """The top-level arguments of the call whose opening parenthesis ends at
    *start*, literals kept whole."""
    return call_span(text, start)[0]
