"""The lines of a verify run that wiki/reading-reports.md quotes."""

from __future__ import annotations

import re
import subprocess
import sys

from core.paths import REPO_ROOT

PAGE = REPO_ROOT / "wiki" / "reading-reports.md"
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
    proc = subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "verify.py"),
                           "--platform", "retrodeck"], capture_output=True, text=True,
                          cwd=REPO_ROOT, check=False)
    lines = proc.stdout.splitlines()
    if not lines or not lines[0].startswith("RetroDECK:"):
        raise SystemExit(f"verify did not run: {proc.stderr[-300:]}")
    return lines
