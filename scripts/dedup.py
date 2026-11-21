"""Deduplicate bios/: keep one canonical file per unique content.

Usage:
    python scripts/dedup.py [--dry-run] [--bios-dir bios]

Two types of deduplication:

1. TRUE DUPLICATES: Same filename in different directories (e.g., naomi.zip
   in both Arcade/ and Sega/Dreamcast/). Keeps one canonical copy, removes
   the others. resolve_local_file finds files by hash, not path.

2. MAME DEVICE CLONES: Different filenames with identical content in the same
   MAME directory (e.g., bbc_m87.zip and bbc_24bbc.zip are identical ZIPs).
   These are NOT aliases: MAME loads each by its unique name. Instead of
   deleting, we create a _mame_clones.json mapping so generate_pack.py can
   pack all names from a single canonical file.

After dedup, run generate_db.py --force to rebuild database indexes.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from collection.dedup import deduplicate
from core.cli import add_repo_inputs, require_directory


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Deduplicate bios/ directory")
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview without deleting"
    )
    add_repo_inputs(parser, "bios")
    args = parser.parse_args()
    require_directory(args.bios_dir)

    print(f"Scanning {args.bios_dir}/ for duplicates...")
    if args.dry_run:
        print("(DRY RUN)\n")

    deduplicate(args.bios_dir, dry_run=args.dry_run)

    if not args.dry_run:
        print("\nRun 'python scripts/generate_db.py --force' to rebuild database.")


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
