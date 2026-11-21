"""A view derived from a dict, built once and rebuilt when the dict changes."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Generic, TypeVar

T = TypeVar("T")


class DerivedView(Generic[T]):
    """One slot: the dict a view was built from, its size then, and the view.

    The dict itself is held, never its id(): a database freed and replaced
    by another at the same address got the old view back, answering from a
    collection that no longer existed. A size change rebuilds too, for a
    dict grown in place. Arguments after the dict reach `build` and are not
    part of the key.
    """

    def __init__(self, build: Callable[..., T]) -> None:
        self._build = build
        self._slot: tuple[dict, int, T] | None = None

    def __call__(self, source: dict, *extra: Any) -> T:
        slot = self._slot
        if slot is not None and slot[0] is source and slot[1] == len(source):
            return slot[2]
        view = self._build(source, *extra)
        self._slot = (source, len(source), view)
        return view

    def clear(self) -> None:
        self._slot = None
