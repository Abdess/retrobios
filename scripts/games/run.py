"""One games index run: render, hold the coverage floor, then write or check install/games/."""

from __future__ import annotations

import argparse
import sys

from games.changes import describe_change
from games.coverage import floor_failures, print_coverage
from games.publish import pending, write
from games.render import render


def index(args: argparse.Namespace) -> int:
    """Render the index, then write it, or with --check name what would change."""
    files, coverage = render(args.output_dir)
    if not (args.quiet or args.check):
        print_coverage(coverage, files)
    failures = floor_failures(coverage)
    for failure in failures:
        print(f"FLOOR {failure}", file=sys.stderr)
    changed, stale = pending(files, args.output_dir)
    if args.check:
        for path in changed:
            print(f"STALE {path}", file=sys.stderr)
            current = path.read_text(encoding="utf-8") if path.exists() else None
            for line in describe_change(current, files[path]):
                print(f"  {line}", file=sys.stderr)
        for path in stale:
            print(f"STALE {path}", file=sys.stderr)
            print("  no longer generated", file=sys.stderr)
        if changed or stale:
            print("Run python scripts/generate_games_index.py to write them.", file=sys.stderr)
        return 1 if changed or stale or failures else 0
    write(files, changed, stale)
    print(f"{len(changed)} written, {len(stale)} removed")
    return 1 if failures else 0

