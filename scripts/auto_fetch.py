#!/usr/bin/env python3
"""Auto-fetch missing BIOS files from multiple sources.

Pipeline:
1. Cross-reference database.json (already exists under different name/path?)
2. Scan old branches (git show origin/branch:path)
3. Search public BIOS repos on GitHub
4. Search archive.org collections
5. Print an issue body for the files still missing (--create-issues).
   It posts nothing.

Usage:
    python scripts/auto_fetch.py --platform retroarch [--dry-run]
    python scripts/auto_fetch.py --all [--dry-run]
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from model.cliargs import platform_arg, require_platform
from core.cli import add_repo_inputs, require_directory
from model.registry import list_registered_platforms
from model.database import load_database
from model.platforms import load_platform_config
from model.safeparse import require_yaml
from acquire.fetch import fetch_missing, find_missing, generate_issue_body, lookup_sha1s

yaml = require_yaml()


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Auto-fetch missing BIOS files")
    parser.add_argument("--platform", "-p", type=platform_arg, help="Platform to check")
    parser.add_argument("--all", action="store_true", help="Check all platforms")
    parser.add_argument(
        "--dry-run", action="store_true", help="Don't download, just report"
    )
    add_repo_inputs(parser, "db", "platforms", "bios")
    parser.add_argument(
        "--create-issues", action="store_true", help="Output GitHub Issue bodies"
    )
    parser.add_argument(
        "--sha1", action="append", metavar="SHA1",
        help="look for one file by its sha1 in the database, Software Heritage and "
             "archive.org, and save what is found under tmp/acquire/ (repeatable)",
    )
    args = parser.parse_args()
    require_directory(args.bios_dir)
    if args.sha1:
        if args.platform or args.all or args.create_issues:
            parser.error("--sha1 looks for files by hash alone: it takes no "
                         "--platform, --all or --create-issues")
        db = load_database(args.db) if os.path.exists(args.db) else {"files": {}}
        sys.exit(lookup_sha1s(args.sha1, db, args.dry_run))

    if not os.path.exists(args.db):
        print(f"Error: {args.db} not found. Run generate_db.py first.", file=sys.stderr)
        sys.exit(1)

    db = load_database(args.db)

    if args.all:
        platforms = list_registered_platforms(
            args.platforms_dir,
        )
    elif args.platform:
        require_platform(args.platform, args.platforms_dir)
        platforms = [args.platform]
    else:
        parser.error("Specify --platform or --all")
        return

    all_still_missing = {}

    for platform in sorted(platforms):
        print(f"\n{'=' * 60}")
        print(f"Platform: {platform}")
        print(f"{'=' * 60}")

        try:
            config = load_platform_config(platform, args.platforms_dir)
        except FileNotFoundError:
            print("  Config not found, skipping")
            continue

        missing = find_missing(config, db)
        if not missing:
            print("  All BIOS files present!")
            continue

        print(f"  {len(missing)} missing files")
        result = fetch_missing(missing, db, args.bios_dir, args.dry_run)

        if result["still_missing"]:
            all_still_missing[config.get("platform") or platform] = result["still_missing"]

        stats = result["stats"]
        print(
            f"\n  Results: {stats['found']} found, {stats['not_found']} not found, "
            f"{stats['errors']} not fully searched, "
            f"{stats['unverifiable']} without a cryptographic hash"
        )

    if args.create_issues and all_still_missing:
        print(f"\n{'=' * 60}")
        print("GitHub Issue Bodies")
        print(f"{'=' * 60}")
        for platform, missing in all_still_missing.items():
            print(f"\n--- Issue for {platform} ---\n")
            print(generate_issue_body(missing, platform))


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
