"""Keyword options a function takes through a TypedDict, checked as named parameters are."""

from __future__ import annotations

from collections.abc import Mapping


def reject_unknown(function: str, options: Mapping[str, object], known: frozenset[str]) -> None:
    """Refuse a keyword the options do not declare, as a named parameter would."""
    for key in options:
        if key not in known:
            raise TypeError(f"{function}() got an unexpected keyword argument '{key}'")
