#!/usr/bin/env python3
"""Run the checks validate.yml runs on a pull request, in its order.

Usage:
    python scripts/pr_checks.py
    python scripts/pr_checks.py --list

Each step runs even when an earlier one failed, as CI runs them, and the
summary names every step that failed or could not run. A step whose tool is
absent (npm, python3.8, vermin) is reported as not run, with what provides it.
"""

from __future__ import annotations

import argparse
from devtools.prchecks import STEPS, run, shown


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true", help="print the steps and exit")
    args = parser.parse_args()
    if args.list:
        for step in STEPS:
            print(shown(step))
        return 0
    return run()


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
