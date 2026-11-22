"""Deduplication of bios/: one canonical file per content, the other copies removed."""

from __future__ import annotations

import os
from pathlib import Path

from collection.clonemap import record_clone_map
from collection.duplicates import plan_group_removals, scan_duplicates
from collection.scan import primary_rank
from core.sizes import size_text
from model.database import CloneMapUnreadable, clone_map_path, read_clone_map


def _remove_copies(canonical: str, true_dupes_to_remove: list[str], dry_run: bool) -> list[str]:
    """Remove (or name, in a dry run) each copy beside the canonical file."""
    removed: list[str] = []
    for dup in true_dupes_to_remove:
        if dup == canonical:
            continue
        if not os.path.exists(dup):
            continue
        if dry_run:
            print(f"  WOULD REMOVE: {dup}")
        else:
            try:
                os.remove(dup)
            except OSError as e:
                print(f"  WARNING: cannot remove {dup}: {e}")
                continue
            # Clean up empty .variants/ directories
            parent = os.path.dirname(dup)
            if os.path.basename(parent) == ".variants" and not os.listdir(parent):
                os.rmdir(parent)
        removed.append(dup)
    return removed


def _settle_group(
    paths: list[str],
    true_dupes_to_remove: list[str],
    clone_names: list[str],
    dry_run: bool,
    bios_dir: str,
) -> dict:
    """Keep the best copy of one content and remove the others.

    Only the names the clone map records are MAME clones. A removed variant
    is one of the copies, and another name kept beside the canonical file
    is one an emulator looks for: printing either as a MAME clone named a
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
    removed = _remove_copies(canonical, true_dupes_to_remove, dry_run)

    if alias_names or true_dupes_to_remove:
        action = "Would remove" if dry_run else "Removed"
        dn = os.path.basename(canonical)
        print(f"  {dn} (keep: {canonical})")
        if true_dupes_to_remove:
            print(f"    {action} {len(true_dupes_to_remove)} copies")
        if clone_names:
            print(f"    MAME clones: {clone_names}")
        kept_names = sorted(
            {os.path.basename(p) for p in paths if p not in true_dupes_to_remove}
            - {canonical_name}
        )
        if kept_names:
            print(f"    Kept under other names: {kept_names}")
    return {
        "canonical": canonical,
        "removed": removed,
        "aliases": alias_names,
        "saved": size * len(removed),
    }


def _remove_empty_dirs(bios_dir: str) -> int:
    """Remove the directories the removals left empty, bottom up."""
    empty_cleaned = 0
    for root, dirs, files in os.walk(bios_dir, topdown=False):
        if not files and not dirs and root != bios_dir:
            os.rmdir(root)
            empty_cleaned += 1
    return empty_cleaned


def deduplicate(bios_dir: str, dry_run: bool = False) -> dict:
    """Remove true duplicates, map MAME device clones.

    True duplicates (same name, different dirs): removes copies.
    MAME clones (different names, same content, same dir): creates mapping.

    Returns dict of {sha1: {"canonical": path, "removed": [paths], "aliases": [names]}}
    """
    clone_path = clone_map_path(bios_dir)
    # Read before anything is removed: the map is cumulative, and a run that
    # stopped on an unreadable one after deleting clones would lose them.
    try:
        previous = read_clone_map(clone_path)
    except CloneMapUnreadable as e:
        raise SystemExit(f"{e} before deduplicating again") from e

    sha1_groups = scan_duplicates(bios_dir)
    results: dict[str, dict] = {}
    total_removed = 0
    total_saved = 0
    mame_clones: dict[str, dict] = {}  # canonical_name -> {sha1, clones: [names]}

    for sha1, paths in sorted(sha1_groups.items()):
        if len(paths) <= 1:
            continue

        group_clones: dict[str, dict] = {}
        true_dupes_to_remove = plan_group_removals(sha1, paths, group_clones, bios_dir)
        mame_clones.update(group_clones)

        if not true_dupes_to_remove:
            continue

        clone_names = [name for entry in group_clones.values() for name in entry["clones"]]
        settled = _settle_group(paths, true_dupes_to_remove, clone_names, dry_run, bios_dir)
        total_removed += len(settled["removed"])
        total_saved += settled.pop("saved")
        results[sha1] = settled

    # Clean up empty directories
    empty_cleaned = 0 if dry_run else _remove_empty_dirs(bios_dir)

    prefix = "Would remove" if dry_run else "Removed"
    print(f"\n{prefix}: {total_removed} files")
    print(
        f"Space {'to save' if dry_run else 'saved'}: {size_text(total_saved)}"
    )
    if not dry_run and empty_cleaned:
        print(f"Cleaned {empty_cleaned} empty directories")

    if mame_clones:
        record_clone_map(mame_clones, previous, clone_path, dry_run)

    return results
