#!/usr/bin/env python3
"""Rehash every file database.json names and repair a confirmed bit flip.

git status never shows a flipped bit: the index compares size and mtime, and
a flip changes neither. Only reading the bytes again finds it. Every file
the database names is hashed and compared with its recorded SHA-1. A
mismatch is read a second time: two reads that disagree are a host misread
and nothing on disk changes.

A confirmed mismatch is handled by where the file comes from:

- committed and unmodified for git: restored from its blob in HEAD, once
  the blob's object id and its content SHA-1 both check out, then hashed
  again. Only with --apply.
- modified for git (git status lists it): a working change some session
  made, left alone and reported.
- gitignored (a large-files release asset) or untracked: flagged, never
  repaired.
- a blob in HEAD whose content is not the recorded SHA-1: the database and
  git disagree, flagged.

Run it on an idle host: a busy CPU here computes wrong hashes, which is the
fault this looks for. autorun.py's load guard holds the weekly job until the
host is idle.

Usage:
    python scripts/bios_integrity.py
    python scripts/bios_integrity.py --apply
    python scripts/bios_integrity.py --apply --json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collection.gitrestore import GitFailed
from collection.integrity import check
from core.cli import add_repo_inputs


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n\n")[0])
    parser.add_argument("--apply", action="store_true",
                        help="restore confirmed flips of committed files from HEAD")
    add_repo_inputs(parser, "db")
    parser.add_argument("--json", action="store_true", help="machine-readable report")
    args = parser.parse_args()

    from model.database import load_database

    root = Path.cwd()
    try:
        report = check(root, load_database(args.db), args.apply)
    except GitFailed as exc:
        print(f"ERROR: {exc}. Nothing was restored past this point.", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        for f in report.findings:
            print(f"{f.verdict.upper():9} {f.path}: {f.reason}")
        counts = ", ".join(f"{n} {v}" for v, n in sorted(report.counts().items()))
        print(f"{report.checked} files hashed" + (f", {counts}" if counts else ", all match"))
    return 0 if report.clean else 1


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
