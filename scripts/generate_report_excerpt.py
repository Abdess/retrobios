#!/usr/bin/env python3
"""Write the verify excerpt of wiki/reading-reports.md from a real run.

Usage:
    python scripts/generate_report_excerpt.py           # rewrite the block
    python scripts/generate_report_excerpt.py --check   # exit 1 when stale

The page quotes `verify.py --platform retrodeck` to show how a report reads.
Written by hand, it went stale with every file the collection gained: three
times on 2026-11-12, each time a red test. The block between
`<!-- generated: verify-retrodeck -->` and its closing marker is the run's
own output: its first line, the entries a reader learns the shapes from
(the first UNTESTED line, the first DISCREPANCY with the line under it),
then every count line.
"""

from __future__ import annotations

import argparse
import sys

from core.artifacts import write_text_atomic
from core.paths import REPO_ROOT
from sitegen.reportexcerpt import BLOCK, PAGE, excerpt, run


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False,
                                     description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--check", action="store_true",
                        help="exit 1, writing nothing, when the block is not the run's")
    args = parser.parse_args()
    text = PAGE.read_text(encoding="utf-8")
    found = BLOCK.search(text)
    if found is None:
        print(f"{PAGE.relative_to(REPO_ROOT)}: no verify-retrodeck block", file=sys.stderr)
        return 1
    body = "\n".join(excerpt(run())) + "\n"
    if found.group(2) == body:
        return 0
    if args.check:
        print(f"STALE {PAGE.relative_to(REPO_ROOT)}: the verify excerpt is not the run's. "
              "Run python scripts/generate_report_excerpt.py", file=sys.stderr)
        return 1
    write_text_atomic(str(PAGE), text[:found.start(2)] + body + text[found.end(2):])
    print(f"Wrote {PAGE.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
