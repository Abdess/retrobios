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
import shutil
import sys
from pathlib import Path


sys.path.insert(0, os.path.dirname(__file__))
from model.database import load_optional_database
from core.cli import add_repo_inputs, require_directory

try:
    import yaml
except ImportError:
    yaml = None
from core.gitclone import compare_base, git_lines
from resolve.review import (
    ValidationResult,
    load_platform_hashes,
    load_profile_hashes,
    validate_file,
)


def get_changed_files() -> list[str]:
    """BIOS files this checkout changes against the project's main line.

    Committed changes are read against the project's main line: the remote
    that names the project (upstream/<base> first, then origin/<base>), or
    the project's main fetched when no remote does. Uncommitted and
    untracked files count too,
    since CONTRIBUTING has the file copied into bios/ before any commit.
    A git that fails outright is an error, never "nothing changed".
    """
    changed: list[str] = []
    base = compare_base()
    committed = git_lines("diff", "--name-only", f"{base}...HEAD") if base else None
    compared = committed is not None
    changed.extend(committed or [])
    staged = git_lines("diff", "--cached", "--name-only")
    local = git_lines("diff", "--name-only")
    untracked = git_lines("ls-files", "--others", "--exclude-standard", "--", "bios")
    if staged is None and local is None and untracked is None:
        raise RuntimeError("git cannot read this checkout")
    for found in (staged, local, untracked):
        changed.extend(found or [])
    if not compared:
        print(
            "no upstream/ or origin/ main line to compare against, reading the "
            "staged, modified and untracked files only",
            file=sys.stderr,
        )
    return [f for f in dict.fromkeys(changed) if f.startswith("bios/") and os.path.isfile(f)]


def expand_folders(paths: list[str]) -> list[str]:
    """Each folder named replaced by the files under it, subfolders included.

    A card's BIOS folder was refused as "Not a regular file", and the
    contributor had to list its files by hand. A link inside the folder
    stays listed, so it is refused like a named one, and an empty folder
    stays as itself to be reported.
    """
    out: list[str] = []
    for path in paths:
        if not os.path.isdir(path) or os.path.islink(path):
            out.append(path)
            continue
        found = sorted(
            str(f) for f in Path(path).rglob("*") if f.is_symlink() or f.is_file()
        )
        out.extend(found or [path])
    return out


def _files_to_validate(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> list:
    """The files named on the command line, or the changed ones."""
    if args.changed and args.files:
        # Named files were dropped for the git diff, and the run reported
        # "No changed BIOS files detected" about files it never looked at.
        parser.error("--changed reads the git diff: name files or pass --changed, not both")
    if not args.changed:
        if not args.files:
            parser.error("No files specified. Use --changed or provide file paths.")
        return expand_folders(args.files)
    try:
        files = get_changed_files()
    except (RuntimeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)
    if not files and not args.json:
        print("No changed BIOS files detected")
    return files


def place(results: list[ValidationResult]) -> list[str]:
    """Copy each placeable file to its destination, never over a file.

    The report named the folder of each file and left 40 copies from a card
    to be made by hand, each .variants/ name retyped. The source is copied,
    not moved: it is often a card or another tree the contributor keeps.
    """
    placed = []
    for r in results:
        if not (r.passed and r.destination and not r.outcome):
            continue
        target = Path(r.destination)
        if target.exists():
            print(f"not placed: {target} exists", file=sys.stderr)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(r.filepath, target)
        placed.append(r.destination)
        print(f"placed {r.filepath} at {r.destination}", file=sys.stderr)
    return placed


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

    files = _files_to_validate(args, parser)
    if not files:
        if args.json:
            print("[]")
        return

    db = load_optional_database(args.db)
    require_directory(args.platforms_dir, "--platforms-dir")
    platform_hashes = load_platform_hashes(args.platforms_dir, db)
    profile_hashes = load_profile_hashes(args.emulators_dir, db)

    results = []
    for f in files:
        result = validate_file(f, db, platform_hashes, profile_hashes)
        results.append(result)

    all_passed = all(r.passed for r in results)

    if args.json:
        output = [
            {
                "file": r.filepath,
                "passed": r.passed,
                # A file that failed, unread or refused, is not a new one.
                "outcome": r.outcome or ("new" if r.passed else "failed"),
                "destination": r.destination,
                "sha1": r.sha1,
                "md5": r.md5,
                "size": r.size,
                "checks": [{"status": s, "message": m} for s, m in r.checks],
            }
            for r in results
        ]
        print(json.dumps(output, indent=2))
    elif args.markdown:
        lines = ["## BIOS Validation Report", ""]
        held = sum(r.outcome == "held" for r in results)
        unknown = sum(r.outcome == "unknown" for r in results)
        review = ", ".join(part for part in (
            f"{held} already held" if held else "",
            f"{unknown} not recognised" if unknown else "",
        ) if part)
        status = ("some checks failed" if not all_passed
                  else f"no check failed, to review: {review}" if review
                  else "all checks passed")
        lines.append(f"**Status**: {status}")
        lines.append("")

        for r in results:
            lines.append(r.to_markdown())
            lines.append("")

        print("\n".join(lines))
    else:
        for r in results:
            print(f"\n[{r.status}] {r.filepath}")
            if r.sha1:
                print(f"  SHA1: {r.sha1}")
                print(f"  MD5:  {r.md5}")
                print(f"  Size: {r.size:,}")
            for s, m in r.checks:
                marker = (
                    "ok"
                    if s == "PASS"
                    else "fail"
                    if s == "FAIL"
                    else "warn"
                    if s == "WARN"
                    else "info"
                )
                print(f"  [{marker}] {m}")

    if args.place:
        place(results)

    if not all_passed:
        sys.exit(1)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
