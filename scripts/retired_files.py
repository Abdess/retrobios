#!/usr/bin/env python3
"""Rebuild retired.json from the history of database.json (model/retired.py).

Usage:
    python scripts/retired_files.py --backfill
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from core.cli import run_cli
from core.artifacts import write_if_changed
from core.paths import DB_FILE, REPO_ROOT
from model.database import load_database
from model.retired import FIRST_ADDRESSED, RETIRED_FILE, dump, merge
from collection.retiredhistory import backfill


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
    current = load_database(str(REPO_ROOT / DB_FILE))
    records = merge(records, {}, current)
    write_if_changed(args.output, dump(records))
    print(f"{len(records)} files left the collection since {FIRST_ADDRESSED}")
    return 0


if __name__ == "__main__":
    run_cli(main)
