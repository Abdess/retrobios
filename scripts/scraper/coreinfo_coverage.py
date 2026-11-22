"""Which core-info firmware the collection holds, by the resolver's rule."""

from __future__ import annotations

from typing import TYPE_CHECKING

from resolve.localfile import resolve_local_file

if TYPE_CHECKING:
    from .base_scraper import BiosRequirement


def is_held(req: BiosRequirement, db: dict) -> bool:
    """Whether the collection holds *req*: its md5 first, its name only
    when the .info notes declare none."""
    basename = req.destination.rsplit("/", 1)[-1] or req.name
    entry = {"name": basename, "md5": req.md5, "destination": req.destination}
    local, status = resolve_local_file(entry, db, dest_hint=req.destination)
    return local is not None and status not in ("not_found", "hash_mismatch")


def split_by_holding(
    reqs: list[BiosRequirement], db: dict,
) -> tuple[list[BiosRequirement], list[BiosRequirement]]:
    """The requirements the collection holds, then those it lacks."""
    found: list[BiosRequirement] = []
    missing: list[BiosRequirement] = []
    for req in reqs:
        (found if is_held(req, db) else missing).append(req)
    return found, missing
