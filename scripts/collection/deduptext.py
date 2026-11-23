"""The terminal report of a deduplication run."""

from __future__ import annotations

import os
from collections.abc import Iterator

from collection.dedup import DedupResult, GroupOutcome
from core.sizes import size_text


def _group_lines(group: GroupOutcome, dry_run: bool) -> Iterator[str]:
    """One settled content: what went, what stayed, and why."""
    if dry_run:
        for path in group.removed:
            yield f"  WOULD REMOVE: {path}"
    for failure in group.failed:
        yield f"  WARNING: cannot remove {failure.path}: {failure.error}"
    if not (group.aliases or group.planned):
        return
    action = "Would remove" if dry_run else "Removed"
    yield f"  {os.path.basename(group.canonical)} (keep: {group.canonical})"
    if group.planned:
        yield f"    {action} {len(group.removed)} copies"
    if group.clone_names:
        yield f"    MAME clones: {group.clone_names}"
    if group.kept_names:
        yield f"    Kept under other names: {group.kept_names}"


def report_lines(result: DedupResult) -> Iterator[str]:
    """Every line of the run's report, in order."""
    for group in result.groups.values():
        yield from _group_lines(group, result.dry_run)
    prefix = "Would remove" if result.dry_run else "Removed"
    yield f"\n{prefix}: {result.total_removed} files"
    yield f"Space {'to save' if result.dry_run else 'saved'}: {size_text(result.total_saved)}"
    if result.empty_dirs_removed:
        yield f"Cleaned {result.empty_dirs_removed} empty directories"
    if result.clone_map:
        verb = "Would write" if result.dry_run else "Wrote"
        yield f"\n{verb} MAME clone map: {result.clone_map_path}"
        clones = sum(len(entry["clones"]) for entry in result.clone_map.values())
        yield f"  {len(result.clone_map)} canonical ZIPs with {clones} clones"
