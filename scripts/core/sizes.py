"""Byte counts as the README, the site and the release notes print them."""

from __future__ import annotations


def size_text(count: int) -> str:
    """A byte count in the largest binary unit it reaches, one decimal: 29.2 MB.

    The installer prints the same text (installer/text.py format_size), so a
    figure reads alike on every surface.
    """
    for unit, scale in (("GB", 1024**3), ("MB", 1024**2), ("KB", 1024)):
        if count >= scale:
            return f"{count / scale:.1f} {unit}"
    return f"{count} B"
