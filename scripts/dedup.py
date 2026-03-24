"""Deduplicate bios/ directory — keep one canonical file per unique content.

Usage:
    python scripts/dedup.py [--dry-run] [--bios-dir bios]

Two types of deduplication:

1. TRUE DUPLICATES: Same filename in different directories (e.g., naomi.zip
   in both Arcade/ and Sega/Dreamcast/). Keeps one canonical copy, removes
   the others. resolve_local_file finds files by hash, not path.

2. MAME DEVICE CLONES: Different filenames with identical content in the same
   MAME directory (e.g., bbc_m87.zip and bbc_24bbc.zip are identical ZIPs).
   These are NOT aliases — MAME loads each by its unique name. Instead of
   deleting, we create a _mame_clones.json mapping so generate_pack.py can
   pack all names from a single canonical file.

After dedup, run generate_db.py --force to rebuild database indexes.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import compute_hashes

DEFAULT_BIOS_DIR = "bios"

# Directories where deduplication must NOT be applied.
NODEDUP_DIRS = {
    "RPG Maker",
    "ScummVM",
}


def path_priority(path: str) -> tuple:
    """Lower score = better candidate to keep as canonical.

    Prefers: shorter path, non-variant, non-MAME (system-specific over generic).
    """
    parts = Path(path).parts
    is_variant = ".variants" in parts
    is_mame = "MAME" in parts
    is_arcade = "Arcade" in parts
    return (is_variant, is_mame, is_arcade, len(parts), path)


def _in_nodedup_dir(path: str) -> bool:
    parts = Path(path).parts
    return any(nodedup in parts for nodedup in NODEDUP_DIRS)


def _is_mame_dir(path: str) -> bool:
    """Check if a path is in a MAME-specific directory."""
    parts = Path(path).parts
    return "MAME" in parts or "Arcade" in parts


def scan_duplicates(bios_dir: str) -> dict[str, list[str]]:
    """Find all files grouped by SHA1, excluding no-dedup directories."""
    sha1_to_paths: dict[str, list[str]] = defaultdict(list)

    for root, dirs, files in os.walk(bios_dir):
        for name in files:
            path = os.path.join(root, name)
            if _in_nodedup_dir(path):
                continue
            sha1 = compute_hashes(path)["sha1"]
            sha1_to_paths[sha1].append(path)

    return sha1_to_paths


def deduplicate(bios_dir: str, dry_run: bool = False) -> dict:
    """Remove true duplicates, map MAME device clones.

    True duplicates (same name, different dirs): removes copies.
    MAME clones (different names, same content, same dir): creates mapping.

    Returns dict of {sha1: {"canonical": path, "removed": [paths], "aliases": [names]}}
    """
    sha1_groups = scan_duplicates(bios_dir)
    results = {}
    total_removed = 0
    total_saved = 0
    mame_clones: dict[str, dict] = {}  # canonical_name -> {sha1, clones: [names]}

    for sha1, paths in sorted(sha1_groups.items()):
        if len(paths) <= 1:
            continue

        # Separate by filename — same name = true duplicate, different name = clone
        by_name: dict[str, list[str]] = defaultdict(list)
        for p in paths:
            by_name[os.path.basename(p)].append(p)

        # True duplicates: same filename in multiple directories
        true_dupes_to_remove = []
        for name, name_paths in by_name.items():
            if len(name_paths) > 1:
                name_paths.sort(key=path_priority)
                true_dupes_to_remove.extend(name_paths[1:])

        # Different filenames, same content — need special handling
        unique_names = sorted(by_name.keys())
        if len(unique_names) > 1:
            # Check if these are all in MAME/Arcade dirs AND all ZIPs
            all_mame_zip = (
                all(
                    any(_is_mame_dir(p) for p in name_paths)
                    for name_paths in by_name.values()
                )
                and all(n.endswith(".zip") for n in unique_names)
            )
            if all_mame_zip:
                # MAME device clones: different ZIP names, same ROM content
                # Keep one canonical, remove clones, record in clone map
                canonical_name = min(unique_names, key=len)
                clone_names = sorted(n for n in unique_names if n != canonical_name)
                if clone_names:
                    mame_clones[canonical_name] = {
                        "sha1": sha1,
                        "clones": clone_names,
                        "total_copies": sum(len(by_name[n]) for n in clone_names),
                    }
                    for clone_name in clone_names:
                        for p in by_name[clone_name]:
                            true_dupes_to_remove.append(p)
            else:
                # Non-MAME different names (e.g., 64DD_IPL_US.n64 vs IPL_USA.n64)
                # Keep ALL — each name may be needed by a different emulator
                # Only remove true duplicates (same name in multiple dirs)
                pass

        if not true_dupes_to_remove:
            continue

        # Find the best canonical across all paths
        all_paths = [p for p in paths if p not in true_dupes_to_remove]
        if not all_paths:
            # All copies were marked for removal — keep the best one
            all_paths_sorted = sorted(paths, key=path_priority)
            all_paths = [all_paths_sorted[0]]
            true_dupes_to_remove = [p for p in paths if p != all_paths[0]]

        canonical = sorted(all_paths, key=path_priority)[0]
        canonical_name = os.path.basename(canonical)

        all_names = set(os.path.basename(p) for p in paths)
        alias_names = sorted(all_names - {canonical_name})

        size = os.path.getsize(canonical)

        results[sha1] = {
            "canonical": canonical,
            "removed": [],
            "aliases": alias_names,
        }

        for dup in true_dupes_to_remove:
            if dup == canonical:
                continue
            if not os.path.exists(dup):
                continue
            if dry_run:
                print(f"  WOULD REMOVE: {dup}")
            else:
                os.remove(dup)
                # Clean up empty .variants/ directories
                parent = os.path.dirname(dup)
                if os.path.basename(parent) == ".variants" and not os.listdir(parent):
                    os.rmdir(parent)
            results[sha1]["removed"].append(dup)
            total_removed += 1
            total_saved += size

        if alias_names or true_dupes_to_remove:
            action = "Would remove" if dry_run else "Removed"
            dn = os.path.basename(canonical)
            print(f"  {dn} (keep: {canonical})")
            if true_dupes_to_remove:
                print(f"    {action} {len(true_dupes_to_remove)} copies")
            if alias_names:
                print(f"    MAME clones: {alias_names}")

    # Clean up empty directories
    if not dry_run:
        empty_cleaned = 0
        for root, dirs, files in os.walk(bios_dir, topdown=False):
            if not files and not dirs and root != bios_dir:
                os.rmdir(root)
                empty_cleaned += 1

    prefix = "Would remove" if dry_run else "Removed"
    print(f"\n{prefix}: {total_removed} files")
    print(f"Space {'to save' if dry_run else 'saved'}: {total_saved / 1024 / 1024:.1f} MB")
    if not dry_run and empty_cleaned:
        print(f"Cleaned {empty_cleaned} empty directories")

    # Write MAME clone mapping
    if mame_clones:
        clone_path = os.path.join(bios_dir, "_mame_clones.json")
        if dry_run:
            print(f"\nWould write MAME clone map: {clone_path}")
            print(f"  {len(mame_clones)} canonical ZIPs with "
                  f"{sum(len(v['clones']) for v in mame_clones.values())} clones")
        else:
            with open(clone_path, "w") as f:
                json.dump(mame_clones, f, indent=2, sort_keys=True)
            print(f"\nWrote MAME clone map: {clone_path}")
            print(f"  {len(mame_clones)} canonical ZIPs with "
                  f"{sum(len(v['clones']) for v in mame_clones.values())} clones")

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Deduplicate bios/ directory")
    parser.add_argument("--dry-run", action="store_true", help="Preview without deleting")
    parser.add_argument("--bios-dir", default=DEFAULT_BIOS_DIR)
    args = parser.parse_args()

    print(f"Scanning {args.bios_dir}/ for duplicates...")
    if args.dry_run:
        print("(DRY RUN)\n")

    deduplicate(args.bios_dir, dry_run=args.dry_run)

    if not args.dry_run:
        print("\nRun 'python scripts/generate_db.py --force' to rebuild database.")


if __name__ == "__main__":
    main()
