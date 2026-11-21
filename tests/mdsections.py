"""Sections of the markdown pages, for the tests that read them."""

from __future__ import annotations

import re

FENCED = re.compile(r"^```.*?^```", re.S | re.M)


def blank_fences(text: str) -> str:
    """The text with each fenced block's characters turned to spaces, lines
    kept: a shell comment in a fence is no heading."""
    return FENCED.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def section(text: str, heading: str, *, stop: int | None = None) -> str:
    """The body under a heading, up to the next heading of level stop or
    higher (the heading's own level by default).

    The heading is its text, or the full line with its hashes, which then
    fix its level. A trailing ``{ #anchor }`` is optional either way."""
    title = heading.lstrip("#")
    hashes = heading[: len(heading) - len(title)]
    title = title.strip()
    start = re.search(rf"(?m)^({hashes or '#+'}) {re.escape(title)}(?:\s*\{{[^}}]*\}})?\n", text)
    if start is None:
        raise AssertionError(f"no section {heading!r}")
    rest = text[start.end():]
    end = re.search(rf"(?m)^#{{1,{stop or len(start.group(1))}}} ", blank_fences(rest))
    return rest[: end.start()] if end else rest
