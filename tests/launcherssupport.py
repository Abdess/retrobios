"""Source texts the launcher test modules build: blocks placed at their lines, C# files by path."""

from __future__ import annotations

import tests

import textwrap

from scraper.csharp_source import Source


def placed(blocks: dict[int, str]) -> str:
    """Each block starting at its line, blank lines between."""
    lines: list[str] = []
    for start, block in sorted(blocks.items()):
        if len(lines) >= start:
            raise AssertionError(f"block at line {start} overlaps the previous one")
        lines += [""] * (start - 1 - len(lines))
        lines += block.splitlines()
    return "\n".join(lines) + "\n"


def _sources(**texts: str) -> dict[str, Source]:
    return {
        path: Source(path, textwrap.dedent(text).lstrip("\n")) for path, text in texts.items()
    }
