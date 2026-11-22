#!/usr/bin/env python3
"""Refresh everything check_freshness.py reports as STALE, in parallel.

check_freshness.py already answers "what is out of date". This script turns
that answer into actions: it parses the JSON report, matches each stale
subject to the command that pulls its upstream, runs them concurrently, and
leaves every write in the working tree for human review. Nothing is ever
committed.

Mapping (stale -> command):
    platforms/<name>        python -m scripts.scraper.<module>_scraper
                            -o platforms/<name>.yml
                            then the native refresh below: the original
                            the export patches must be the one just scraped,
                            then python scripts/verify.py --platform <name>,
                            whose summary the report prints: a rescrape can
                            add systems whose files are missing
    native/<name>           python scripts/generate_truth.py --platform <name>, then
                            python scripts/export_native.py --platform <name>
                            --refresh-cache, then the export itself, which
                            rewrites exports/<name>
    targets/<name>          python -m scripts.scraper.targets.<module>
                            -o platforms/targets/<name>.yml
    data/<key>              python scripts/refresh_data_dirs.py --key <key>
                            --force
    catalogs/mame recipes   python -m scripts.scraper.romset_dat_importer
                            --source mame --fetch
    catalogs/fbneo recipes  python -m scripts.scraper.romset_dat_importer
                            --source fbneo --fetch
    catalogs/no-intro games python -m scripts.scraper.game_dat_importer
    catalogs/redump games   --source <source> --fetch --refresh --floor
    ci/install.py pin       python scripts/pin_installer.py

A platform that inherits from a rescraped one (retropie and lakka from
retroarch) reads the parent's file: its jobs start once the parent's chain
has ended, and its export is rewritten even when no row named it.

Surfaced only (no refresh): data rows that are not a _data_dirs.yml key
(the registry itself, buildbot assets it does not track), coreinfo gaps, redump/no-intro/tosec packs,
the other CI pins (PyPI, pinned actions), profile_sync, rom-folder
pins (moved by hand, then python -m scripts.scraper.romfolders --setup NAME
reads them again). Each needs
a human read (new .info file, manual DAT download, PyPI version bump).

Usage:
    python scripts/refresh_stale.py --dry-run
    python scripts/refresh_stale.py --only platforms,targets
    python scripts/refresh_stale.py --jobs 6
    python scripts/refresh_stale.py --findings tmp/freshness.json --only data
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from freshness.stalefindings import load_findings, run_check_freshness
from freshness.stalecommands import AUTO_AREAS, MANUAL_AREAS
from freshness.stalejob import LOG_DIR
from freshness.staleplan import plan_jobs, platform_registry
from freshness.stalereport import plan_payload, plan_text, render, results_payload
from freshness.stalerun import github_token_env, run_jobs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--only",
        help="comma-separated areas to check: " + ",".join(AUTO_AREAS)
        + " (refreshed, a row no command covers is listed for a human), "
        + ",".join(MANUAL_AREAS) + " (listed for a human)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="list what would be refreshed without running any command",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=4,
        help="parallel refreshers (default: 4)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="machine-readable summary (jobs, surfaced, ignored), the plan with --dry-run",
    )
    parser.add_argument(
        "--findings",
        metavar="FILE",
        help="read the check_freshness.py --json report from FILE instead of "
        "running it (rows outside --only are left out)",
    )
    parser.add_argument(
        "--freshness-arg",
        action="append",
        default=[],
        help="extra flag to pass through to check_freshness.py (repeatable)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    all_areas = AUTO_AREAS + MANUAL_AREAS
    if args.only:
        areas = tuple(a.strip() for a in args.only.split(",") if a.strip())
        unknown = sorted(set(areas) - set(all_areas))
        if unknown:
            parser.error(
                f"unknown area: {', '.join(unknown)}. Areas: {', '.join(all_areas)}"
            )
    else:
        areas = all_areas

    try:
        if args.findings:
            findings = load_findings(Path(args.findings), areas)
        else:
            findings = run_check_freshness(areas, args.freshness_arg)
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 2

    jobs, surfaced, ignored = plan_jobs(findings, platform_registry())

    if args.dry_run and args.json:
        print(json.dumps(plan_payload(jobs, surfaced, ignored), indent=2))
        return 0
    if args.dry_run:
        print(plan_text(jobs, surfaced, ignored))
        return 0

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    results = run_jobs(jobs, github_token_env(), args.jobs)

    if args.json:
        print(json.dumps(results_payload(results, surfaced, ignored), indent=2))
    else:
        print(render(results, surfaced, ignored))

    return 0 if all(r.returncode == 0 for r in results) else 1


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
