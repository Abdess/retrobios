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
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "wiki" / "reading-reports.md"
BLOCK = re.compile(
    r"(<!-- generated: verify-retrodeck -->\n```\n)(.*?)(```\n<!-- /generated: verify-retrodeck -->)",
    re.S)
# The count lines, in the order verify prints them.
COUNTS = ("  Core files:", "  Bundled with their emulator", "  Core files held",
          "  Game data:", "  Game data held", "  Launcher reads", "  Launcher records",
          "  No external files:", "  Ground truth:", "    ")


def excerpt(lines: list[str]) -> list[str]:
    """The lines of a verify run the page shows."""
    kept = [lines[0]]
    untested = next((line for line in lines if line.startswith("  UNTESTED")), None)
    if untested:
        kept.append(untested)
    for index, line in enumerate(lines):
        if line.startswith("  DISCREPANCY") and index + 1 < len(lines) \
                and lines[index + 1].startswith("    "):
            kept += [line, lines[index + 1]]
            break
    counts_from = next(i for i, line in enumerate(lines) if line.startswith("  Core files:"))
    kept += [line for line in lines[counts_from:] if line.startswith(COUNTS)]
    return kept


def run() -> list[str]:
    proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "verify.py"),
                           "--platform", "retrodeck"], capture_output=True, text=True,
                          cwd=ROOT, check=False)
    lines = proc.stdout.splitlines()
    if not lines or not lines[0].startswith("RetroDECK:"):
        raise SystemExit(f"verify did not run: {proc.stderr[-300:]}")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False,
                                     description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--check", action="store_true",
                        help="exit 1, writing nothing, when the block is not the run's")
    args = parser.parse_args()
    text = PAGE.read_text(encoding="utf-8")
    found = BLOCK.search(text)
    if found is None:
        print(f"{PAGE.relative_to(ROOT)}: no verify-retrodeck block", file=sys.stderr)
        return 1
    body = "\n".join(excerpt(run())) + "\n"
    if found.group(2) == body:
        return 0
    if args.check:
        print(f"STALE {PAGE.relative_to(ROOT)}: the verify excerpt is not the run's. "
              "Run python scripts/generate_report_excerpt.py", file=sys.stderr)
        return 1
    PAGE.write_text(text[:found.start(2)] + body + text[found.end(2):], encoding="utf-8")
    print(f"Wrote {PAGE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
