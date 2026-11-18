#!/usr/bin/env python3
"""Check buildbot system directory for changes against local registry.

Compares the live buildbot assets/system/.index against _data_dirs.yml
entries using HTTP ETag headers for change detection.

Usage:
    python scripts/check_buildbot_system.py
    python scripts/check_buildbot_system.py --update
    python scripts/check_buildbot_system.py --json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from core.cli import InputMissing
from scraper.buildbot_system import (
    DEFAULT_REGISTRY,
    check,
    pending,
    print_report,
    unanswered,
    update_changed,
)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Check buildbot system directory for changes",
    )
    parser.add_argument(
        "--update", action="store_true", help="Auto-refresh changed entries"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Machine-readable JSON output",
    )
    parser.add_argument(
        "--registry", default=DEFAULT_REGISTRY,
        help="the data directory registry to check (default: %(default)s)",
    )
    args = parser.parse_args()
    # Read after the buildbot answered, a mistyped path ended on a trace.
    if not os.path.isfile(args.registry):
        raise InputMissing(f"Registry not found: {args.registry}")

    report = check(args.registry)

    if args.json_output:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)

    if args.update:
        failed = update_changed(report)
        if failed:
            print(f"ERROR: refresh failed for {', '.join(failed)}", file=sys.stderr)
            sys.exit(1)

    # Unreachable upstream means the freshness question was not answered, and
    # a zero exit says it was answered "fresh". An asset whose HEAD went
    # unanswered is the same question left open, as check_freshness counts
    # UNKNOWN. A new asset nobody tracks, or a tracked one the buildbot
    # dropped, is a change to act on: a zero exit there let the online
    # pipeline call the system directory current.
    if report.get("error") or pending(report) or unanswered(report):
        raise SystemExit(1)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
