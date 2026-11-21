"""Counts and lists said in English, the same way on every page and report."""

from __future__ import annotations

from collections.abc import Sequence


def count_text(number: int, noun: str, plural: str = "") -> str:
    """A count and its noun, singular for one: "1 hash", "1,234 hashes"."""
    plural = plural or noun + ("es" if noun.endswith(("sh", "ch", "s", "x")) else "s")
    return f"{number:,} {noun if number == 1 else plural}"


def series(items: Sequence[str], last: str = "and") -> str:
    """"a", "a and b", "a, b and c", with *last* before the final item and no
    comma before it. Empty for no item."""
    if len(items) < 2:
        return "".join(items)
    return ", ".join(items[:-1]) + f" {last} {items[-1]}"
