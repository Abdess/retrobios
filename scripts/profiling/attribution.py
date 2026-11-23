"""Which declared repository a cited part belongs to, by its role word."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import TypeVar

T = TypeVar("T")


def field_role(field: str) -> str:
    """source or upstream: the profile field a repository comes from."""
    return "upstream" if field == "upstream" else "source"


def answers(field: str, mode: str, role: str) -> bool:
    """Whether a part written under *role* means this repository: the field
    it comes from, or the build mode a keyed source declares it under."""
    return bool(role) and role in (field_role(field), mode)


def owner_order(
    repositories: Iterable[T], role: str, declared: Callable[[T], tuple[str, str]]
) -> list[T]:
    """Repositories in the order a cited part claims them.

    Those its role names come first, then the rest, each group in
    declaration order: between two trees that carry the cited path, the
    one declared first owns a part that names none. `declared` gives the
    (field, build mode) a repository was declared under.
    """
    items = list(repositories)
    if not role:
        return items
    return sorted(items, key=lambda item: not answers(*declared(item), role))
