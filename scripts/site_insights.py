#!/usr/bin/env python3
"""What readers look for and do not find, from totals only.

Four sources, none of which names a person:

- Google Search Console: the searches that showed the site, by page,
  against the period of the same length just before.
- GoatCounter: page views, the domains readers came from, and the actions
  website/src/scripts/count.ts counts (searches that found nothing,
  "Did this page help?", downloads, broken links). wiki/privacy.md says
  what is sent.
- GitHub: repository traffic (14 days) and release download counts,
  all-time counters compared with the snapshot the previous run left in
  .cache/insights/downloads.json.
- The collection: which searched file names it holds, and which no
  emulator profile declares.

The report is Markdown on stdout. Credentials stay outside the repository:

    ~/.config/retrobios/gsc-service-account.json   Search Console, read only
    ~/.config/retrobios/goatcounter-api-token.txt   GoatCounter, statistics and export
    GITHUB_TOKEN or gh auth token                   GitHub

Usage:
    python scripts/site_insights.py
    python scripts/site_insights.py --days 90 --output report.md
    python scripts/site_insights.py --skip gsc,github
    python scripts/site_insights.py --downloads-snapshot tmp/downloads.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from model.database import load_database
from model.profiles import load_emulator_profiles
from core.cli import run_cli
from core.paths import DB_FILE, EMULATORS_DIR, REPO_ROOT
from sitegen.insights import (
    SOURCES,
    Readings,
    SourceUnavailable,
    collection_names,
    downloads_snapshot,
    fetch_github,
    fetch_goatcounter,
    fetch_queries,
    load_snapshot,
    report,
    save_snapshot,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], allow_abbrev=False)
    parser.add_argument("--days", type=int, default=28, help="days to read, ending 3 days ago (default 28)")
    parser.add_argument("--skip", default="", help=f"sources to leave out, among {', '.join(SOURCES)}")
    parser.add_argument("--output", type=Path, help="write the report here instead of stdout")
    parser.add_argument("--downloads-snapshot", type=Path, default=REPO_ROOT / ".cache" / "insights" / "downloads.json",
                        help="release download counts of the previous run, rewritten after each run")
    args = parser.parse_args()
    skip = {name.strip() for name in args.skip.split(",") if name.strip()}
    unknown = skip - set(SOURCES)
    if unknown:
        parser.error(f"unknown source(s): {', '.join(sorted(unknown))}")
    if args.days < 1:
        parser.error("--days must be at least 1")
    # Search Console data settles two to three days after the fact.
    end = dt.date.today() - dt.timedelta(days=3)
    start = end - dt.timedelta(days=args.days - 1)
    held, declared = collection_names(load_database(str(REPO_ROOT / DB_FILE)),
                                      load_emulator_profiles(str(REPO_ROOT / EMULATORS_DIR)))
    now = dt.datetime.now(dt.timezone.utc)
    # Read before any source: a damaged snapshot ended the run after the
    # others had been fetched, and their readings were lost.
    snapshot = load_snapshot(args.downloads_snapshot) if "github" not in skip else None
    readings = Readings(start, end, now, held, declared)
    # A source that cannot be read is left out and named, the others kept:
    # a GitHub rate limit threw away what Search Console had given.
    left_out: list[str] = []
    if "gsc" not in skip:
        try:
            readings = replace(readings, queries=fetch_queries(start, end),
                               previous=fetch_queries(*readings.previous_span))
        except SourceUnavailable as error:
            left_out.append(f"Search Console: {error}")
    if "goatcounter" not in skip:
        try:
            readings = replace(readings, goat=fetch_goatcounter(start, now.date()), goat_end=now.date())
        except SourceUnavailable as error:
            left_out.append(f"GoatCounter: {error}")
    if "github" not in skip:
        try:
            readings = replace(readings, github=fetch_github(), snapshot=snapshot)
        except SourceUnavailable as error:
            left_out.append(f"GitHub: {error}")
    readings = replace(readings, left_out=tuple(left_out))
    text = report(readings)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    if readings.github is not None:
        save_snapshot(args.downloads_snapshot, downloads_snapshot(readings.github["downloads"], now))
    for line in left_out:
        print(f"Not read, {line}", file=sys.stderr)
    return 1 if left_out else 0


if __name__ == "__main__":
    run_cli(main)
