#!/usr/bin/env python3
"""Rebuild retired.json from the history of database.json (model/retired.py).

Usage:
    python scripts/retired_files.py --backfill
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from core.cli import run_cli
from core.artifacts import write_if_changed
from core.paths import REPO_ROOT
from model.retired import FIRST_ADDRESSED, RETIRED_FILE, dump, merge, retired_between


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True,
                          check=True).stdout


def backfill() -> dict[str, dict]:
    """Every sha1 that left database.json in the commits since content
    addresses were published, with the day of the commit that dropped it."""
    revisions = [line.split() for line in _git(
        "log", "--reverse", "--format=%H %cs", f"{FIRST_ADDRESSED}^..HEAD", "--", "database.json",
    ).splitlines() if line.strip()]
    records: dict[str, dict] = {}
    previous: dict | None = None
    for commit, day in revisions:
        current = json.loads(_git("show", f"{commit}:database.json"))
        if previous is not None:
            records = merge(records, retired_between(previous, current, day), current)
        previous = current
    return records


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n\n")[0])
    parser.add_argument("--backfill", action="store_true",
                        help="rebuild the record from the history of database.json")
    parser.add_argument("--output", default=str(RETIRED_FILE),
                        help="the record to write (default: retired.json)")
    args = parser.parse_args()
    if not args.backfill:
        parser.print_help()
        return 2
    records = backfill()
    current = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
    records = merge(records, {}, current)
    write_if_changed(args.output, dump(records))
    print(f"{len(records)} files left the collection since {FIRST_ADDRESSED}")
    return 0


if __name__ == "__main__":
    run_cli(main)
