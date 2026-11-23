#!/usr/bin/env python3
"""Migrate current flat structure AND other branches to bios/Manufacturer/Console/ hierarchy.

Usage:
    python scripts/migrate.py [--dry-run] [--source DIR] [--target DIR] [--include-branches]

Reads existing directories like "Sony - PlayStation" and moves files to
"bios/Sony/PlayStation/". With --include-branches, also extracts unique BIOS files
from all remote branches (RetroArch, RetroPie, Recalbox, batocera, Other).
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from devtools.biosmigrate import extract_from_branches, migrate_local, unmapped_directories


def main() -> None:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Migrate BIOS files to Manufacturer/Console structure"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without moving files",
    )
    parser.add_argument("--source", default=".", help="Source directory (repo root)")
    parser.add_argument(
        "--target", default="bios", help="Target directory for organized BIOS files"
    )
    parser.add_argument(
        "--include-branches",
        action="store_true",
        help="Also extract BIOS files from all remote branches",
    )
    args = parser.parse_args()

    source = Path(args.source)
    target = Path(args.target)

    if not source.is_dir():
        print(f"Error: Source directory '{source}' not found", file=sys.stderr)
        sys.exit(1)

    print(f"Migrating from {source}/ to {target}/Manufacturer/Console/")
    if args.dry_run:
        print("(DRY RUN - no files will be moved)\n")
    else:
        print()

    print("=== Phase 1: Local files (libretro branch) ===")
    moved, skipped, errors, existing_hashes = migrate_local(
        source, target, args.dry_run, print
    )
    action = "Would copy" if args.dry_run else "Copied"
    print(f"\n{action} {moved} files, skipped {skipped}")

    if args.include_branches:
        print("\n=== Phase 2: Extracting from other branches ===")
        branch_count = extract_from_branches(target, args.dry_run, existing_hashes, print)
        print(f"\n{action} {branch_count} additional files from branches")
        moved += branch_count

    for name in unmapped_directories(source):
        print(f"\nWARNING: Unmapped directory: {name}")

    print(f"\nTotal: {moved} files migrated, {len(existing_hashes)} unique hashes")

    if errors:
        print(f"Errors: {len(errors)}")
        for f, e in errors:
            print(f"  {f}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
