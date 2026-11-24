#!/usr/bin/env python3
"""Validate BIOS file contributions in Pull Requests.

Usage:
    python scripts/validate_pr.py [files...]
    python scripts/validate_pr.py --changed   # Auto-detect changed files via git

Multi-layer validation:
1. Hash verified against known databases (System.dat, batocera-systems)
2. File size within limits and within the sizes declared for its name
3. File referenced in ≥1 platform config
4. Duplicate detection against database.json
5. Security checks (no executables, reasonable sizes)

Outputs a structured report suitable for PR comments.
"""

from __future__ import annotations

import argparse
import json
import os
import sys


sys.path.insert(0, os.path.dirname(__file__))
from model.database import load_optional_database
from core.cli import add_repo_inputs, require_directory
from resolve.reviewhashes import load_platform_hashes, load_profile_hashes
from resolve.review import validate_file
from devtools.reviewfiles import ChangedFilesUnreadable, SelectionError, files_to_validate, place
from devtools.reviewreport import json_rows, markdown_report, text_lines


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Validate BIOS file contributions")
    parser.add_argument("files", nargs="*", help="Files to validate")
    parser.add_argument(
        "--changed", action="store_true", help="Auto-detect changed BIOS files"
    )
    add_repo_inputs(parser, "db", "platforms", "emulators")
    # One output format: --json beside --markdown printed JSON and dropped
    # the markdown without a word.
    formats = parser.add_mutually_exclusive_group()
    formats.add_argument(
        "--markdown", action="store_true", help="Output as markdown (for PR comments)"
    )
    formats.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument(
        "--place", action="store_true",
        help="copy each recognised file from outside bios/ to the folder and name "
        "the report gives, or to .variants/ beside the name it varies",
    )
    args = parser.parse_args()

    # The database, platforms and profiles are read from the repository
    # root. Run from elsewhere, every file read as referenced by no platform
    # and placed outside bios/. The files named are read from where they
    # were typed.
    from core.paths import REPO_ROOT
    from model.cliargs import work_from_repo_root

    if os.path.realpath(os.getcwd()) != os.path.realpath(REPO_ROOT):
        args.files = [os.path.abspath(f) for f in args.files]
    work_from_repo_root(args, parser, ["db", "platforms_dir", "emulators_dir"])

    try:
        files = files_to_validate(args.files, args.changed)
    except SelectionError as exc:
        parser.error(str(exc))
    except ChangedFilesUnreadable as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)
    if not files:
        if args.changed and not args.json:
            print("No changed BIOS files detected")
        if args.json:
            print("[]")
        return

    db = load_optional_database(args.db)
    require_directory(args.platforms_dir, "--platforms-dir")
    platform_hashes = load_platform_hashes(args.platforms_dir, db)
    profile_hashes = load_profile_hashes(args.emulators_dir, db)

    results = [validate_file(f, db, platform_hashes, profile_hashes) for f in files]

    if args.json:
        print(json.dumps(json_rows(results), indent=2))
    elif args.markdown:
        print(markdown_report(results))
    else:
        for line in text_lines(results):
            print(line)

    if args.place:
        place(results)

    if not all(r.passed for r in results):
        sys.exit(1)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
