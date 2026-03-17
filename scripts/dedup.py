#!/usr/bin/env python3
"""Deduplicate bios/ directory - keep one canonical file per unique SHA1.

Usage:
    python scripts/dedup.py [--dry-run] [--bios-dir bios]

For each group of files with the same SHA1:
- Keeps the file with the shortest, most canonical path
- Removes duplicates
- Records all alternate names in database.json aliases

After dedup, generate_pack.py resolves files by hash and writes them
with the correct destination name - no duplicates needed on disk.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import compute_hashes

DEFAULT_BIOS_DIR = "bios"

# Directories where deduplication must NOT be applied.
# RPG Maker RTP files are referenced by exact name in game scripts -
# removing a "duplicate" breaks games that reference that specific filename.
# ScummVM themes/extra also have name-dependent loading.
NODEDUP_DIRS = {
    "RPG Maker",
    "ScummVM",
}


def path_priority(path: str) -> tuple:
    """Lower score = better candidate to keep as canonical.

    Prefers:
    - Shorter paths
    - Non-.variants paths
    - Non-nested paths (fewer /)
    - Lowercase names (more standard)
    """
    parts = path.split("/")
    is_variant = ".variants" in path
    depth = len(parts)
    name = os.path.basename(path)
    # Prefer non-variant, shallow, short name
    return (is_variant, depth, len(name), path)


def _in_nodedup_dir(path: str) -> bool:
    """Check if a file is inside a no-dedup directory."""
    return any(nodedup in path for nodedup in NODEDUP_DIRS)


def scan_duplicates(bios_dir: str) -> dict[str, list[str]]:
    """Find all files grouped by SHA1, excluding no-dedup directories."""
    sha1_to_paths = defaultdict(list)

    for root, dirs, files in os.walk(bios_dir):
        for name in files:
            path = os.path.join(root, name)
            if _in_nodedup_dir(path):
                continue
            sha1 = compute_hashes(path)["sha1"]
            sha1_to_paths[sha1].append(path)

    return sha1_to_paths


def deduplicate(bios_dir: str, dry_run: bool = False) -> dict:
    """Remove duplicate files, keeping one canonical copy per SHA1.

    Returns dict of {sha1: {"canonical": path, "removed": [paths], "aliases": [names]}}
    """
    sha1_groups = scan_duplicates(bios_dir)
    results = {}
    total_removed = 0
    total_saved = 0

    for sha1, paths in sorted(sha1_groups.items()):
        if len(paths) <= 1:
            continue

            paths.sort(key=path_priority)
        canonical = paths[0]
        duplicates = paths[1:]

        all_names = set()
        for p in paths:
            all_names.add(os.path.basename(p))

        canonical_name = os.path.basename(canonical)
        alias_names = sorted(all_names - {canonical_name})

        size = os.path.getsize(canonical)

        results[sha1] = {
            "canonical": canonical,
            "removed": [],
            "aliases": alias_names,
        }

        for dup in duplicates:
            if dry_run:
                print(f"  WOULD REMOVE: {dup}")
            else:
                os.remove(dup)
            results[sha1]["removed"].append(dup)
            total_removed += 1
            total_saved += size

        if alias_names:
            action = "Would remove" if dry_run else "Removed"
            print(f"  {canonical_name} (keep: {canonical})")
            print(f"    {action} {len(duplicates)} copies, aliases: {alias_names}")

    if not dry_run:
        for root, dirs, files in os.walk(bios_dir, topdown=False):
            if not files and not dirs:
                try:
                    os.rmdir(root)
                except OSError:
                    pass

    print(f"\n{'Would remove' if dry_run else 'Removed'}: {total_removed} files")
    print(f"Space {'to save' if dry_run else 'saved'}: {total_saved / 1024 / 1024:.1f} MB")

    return results


def main():
    parser = argparse.ArgumentParser(description="Deduplicate BIOS files")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--bios-dir", default=DEFAULT_BIOS_DIR)
    args = parser.parse_args()

    if not os.path.isdir(args.bios_dir):
        print(f"Error: {args.bios_dir} not found", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {args.bios_dir}/ for duplicates...")
    if args.dry_run:
        print("(DRY RUN)\n")

    deduplicate(args.bios_dir, args.dry_run)


if __name__ == "__main__":
    main()
