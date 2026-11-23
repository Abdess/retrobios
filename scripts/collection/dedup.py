"""Deduplication of bios/: one canonical file per content, the other copies removed."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from collection.clonemap import record_clone_map
from collection.duplicates import plan_group_removals, scan_duplicates
from collection.scan import primary_rank
from model.database import clone_map_path, read_clone_map


@dataclass(frozen=True)
class RemovalFailure:
    """A copy the run meant to remove and could not."""

    path: str
    error: str


@dataclass
class GroupOutcome:
    """What the run did with one content held by several files.

    `planned` is the plan, `removed` what left the disk (or would, in a dry
    run) and `failed` what stayed against the plan.
    """

    canonical: str
    planned: list[str]
    removed: list[str]
    failed: list[RemovalFailure]
    aliases: list[str]
    clone_names: list[str]
    kept_names: list[str]
    saved: int


@dataclass
class DedupResult:
    """One deduplication run: each settled group and what the run wrote."""

    dry_run: bool
    clone_map_path: str
    groups: dict[str, GroupOutcome] = field(default_factory=dict)
    empty_dirs_removed: int = 0
    clone_map: dict[str, dict] = field(default_factory=dict)

    @property
    def total_removed(self) -> int:
        return sum(len(group.removed) for group in self.groups.values())

    @property
    def total_saved(self) -> int:
        return sum(group.saved for group in self.groups.values())

    @property
    def failed(self) -> list[RemovalFailure]:
        return [failure for group in self.groups.values() for failure in group.failed]


def _remove_copies(
    canonical: str, true_dupes_to_remove: list[str], dry_run: bool
) -> tuple[list[str], list[RemovalFailure]]:
    """Remove (or keep, in a dry run) each copy beside the canonical file."""
    removed: list[str] = []
    failed: list[RemovalFailure] = []
    for dup in true_dupes_to_remove:
        if dup == canonical:
            continue
        if not os.path.exists(dup):
            continue
        if not dry_run:
            try:
                os.remove(dup)
            except OSError as e:
                failed.append(RemovalFailure(dup, str(e)))
                continue
            # Clean up empty .variants/ directories
            parent = os.path.dirname(dup)
            if os.path.basename(parent) == ".variants" and not os.listdir(parent):
                os.rmdir(parent)
        removed.append(dup)
    return removed, failed


def _settle_group(
    paths: list[str],
    true_dupes_to_remove: list[str],
    clone_names: list[str],
    dry_run: bool,
    bios_dir: str,
) -> GroupOutcome:
    """Keep the best copy of one content and remove the others.

    Only the names the clone map records are MAME clones. A removed variant
    is one of the copies, and another name kept beside the canonical file
    is one an emulator looks for: reporting either as a MAME clone named a
    file that stays, or a clone map entry that does not exist.
    """
    def rank(path: str) -> tuple:
        return primary_rank(Path(path), Path(bios_dir))

    # Find the best canonical across all paths
    all_paths = [p for p in paths if p not in true_dupes_to_remove]
    if not all_paths:
        # All copies were marked for removal: keep the best one
        all_paths_sorted = sorted(paths, key=rank)
        all_paths = [all_paths_sorted[0]]
        true_dupes_to_remove = [p for p in paths if p != all_paths[0]]

    canonical = sorted(all_paths, key=rank)[0]
    canonical_name = os.path.basename(canonical)

    all_names = set(os.path.basename(p) for p in paths)
    alias_names = sorted(all_names - {canonical_name})

    size = os.path.getsize(canonical)
    removed, failed = _remove_copies(canonical, true_dupes_to_remove, dry_run)
    kept_names = sorted(
        {os.path.basename(p) for p in paths if p not in true_dupes_to_remove}
        - {canonical_name}
    )
    return GroupOutcome(
        canonical=canonical,
        planned=true_dupes_to_remove,
        removed=removed,
        failed=failed,
        aliases=alias_names,
        clone_names=clone_names,
        kept_names=kept_names,
        saved=size * len(removed),
    )


def _remove_empty_dirs(bios_dir: str) -> int:
    """Remove the directories the removals left empty, bottom up."""
    empty_cleaned = 0
    for root, dirs, files in os.walk(bios_dir, topdown=False):
        if not files and not dirs and root != bios_dir:
            os.rmdir(root)
            empty_cleaned += 1
    return empty_cleaned


def deduplicate(bios_dir: str, dry_run: bool = False) -> DedupResult:
    """Remove true duplicates, map MAME device clones.

    True duplicates (same name, different dirs): removes copies.
    MAME clones (different names, same content, same dir): creates mapping.

    Raises CloneMapUnreadable before removing anything when the existing
    clone map cannot be read.
    """
    clone_path = clone_map_path(bios_dir)
    # Read before anything is removed: the map is cumulative, and a run that
    # stopped on an unreadable one after deleting clones would lose them.
    previous = read_clone_map(clone_path)

    result = DedupResult(dry_run=dry_run, clone_map_path=clone_path)
    mame_clones: dict[str, dict] = {}  # canonical_name -> {sha1, clones: [names]}

    for sha1, paths in sorted(scan_duplicates(bios_dir).items()):
        if len(paths) <= 1:
            continue

        group_clones: dict[str, dict] = {}
        true_dupes_to_remove = plan_group_removals(sha1, paths, group_clones, bios_dir)
        mame_clones.update(group_clones)

        if not true_dupes_to_remove:
            continue

        clone_names = [name for entry in group_clones.values() for name in entry["clones"]]
        result.groups[sha1] = _settle_group(
            paths, true_dupes_to_remove, clone_names, dry_run, bios_dir
        )

    if not dry_run:
        result.empty_dirs_removed = _remove_empty_dirs(bios_dir)
    if mame_clones:
        result.clone_map = record_clone_map(mame_clones, previous, clone_path, dry_run)
    return result
