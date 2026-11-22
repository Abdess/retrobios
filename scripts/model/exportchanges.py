"""The kinds of change an export writes into a platform's file, and how each is said."""

from __future__ import annotations

from typing import NamedTuple

from core.text import count_text


class ChangeKind(NamedTuple):
    """One kind of change, its count key in the report and its two wordings."""

    key: str
    noun: str
    plural: str
    terse: str
    plain: str


# In the order both sentences name them. `terse` is the run's summary,
# `plain` the exports page.
CHANGE_KINDS = (
    ChangeKind("added", "file", "", "added", "added"),
    ChangeKind("hash_updated", "hash", "", "updated to the emulator source", "updated"),
    ChangeKind("required_aligned", "required flag", "",
               "aligned with the code", "aligned with the code"),
    ChangeKind("hash_filled", "hash", "", "added to an existing entry", "added"),
    ChangeKind("size_updated", "size", "", "updated to the emulator source", "updated"),
    ChangeKind("size_removed", "size", "", "removed", "removed"),
    ChangeKind("hash_cleared", "hash", "", "removed", "removed"),
    ChangeKind("not_kept", "entry", "entries", "removed, the format cannot state them",
               "not written, the format cannot state them"),
    ChangeKind("md5_lists", "md5 list", "",
               "written, any listed value passes", "written, any listed value passes"),
)


def change_phrases(counts: dict, plain: bool = False) -> list[str]:
    """Each change the counts hold, as "2 hashes removed", none for a zero."""
    return [
        f"{count_text(counts[kind.key], kind.noun, kind.plural)} "
        f"{kind.plain if plain else kind.terse}"
        for kind in CHANGE_KINDS
        if counts[kind.key]
    ]
