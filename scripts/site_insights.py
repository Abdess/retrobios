#!/usr/bin/env python3
"""What readers look for and do not find, from totals only.

Four sources, none of which names a person:

- Google Search Console: the searches that showed the site, by page.
- GoatCounter: page views, the domains readers came from, and the actions
  website/src/scripts/count.ts counts (searches that found nothing,
  "Did this page help?", downloads, broken links). wiki/privacy.md says
  what is sent.
- GitHub: repository traffic (14 days) and release download counts.
- The collection: which searched file names it holds, and which no
  emulator profile declares.

The report is Markdown on stdout. Credentials stay outside the repository:

    ~/.config/retrobios/gsc-service-account.json   Search Console, read only
    ~/.config/retrobios/goatcounter-api-token.txt   GoatCounter, read only
    GITHUB_TOKEN or gh auth token                   GitHub

Usage:
    python scripts/site_insights.py
    python scripts/site_insights.py --days 90 --output report.md
    python scripts/site_insights.py --skip gsc,github
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from model.database import load_database
from model.profiles import load_emulator_profiles
from core.cli import run_cli
from core.paths import REPO_ROOT
from sitegen.insights import (
    SOURCES,
    collection_names,
    fetch_github,
    fetch_goatcounter,
    fetch_queries,
    report,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], allow_abbrev=False)
    parser.add_argument("--days", type=int, default=28, help="days to read, ending 3 days ago (default 28)")
    parser.add_argument("--skip", default="", help=f"sources to leave out, among {', '.join(SOURCES)}")
    parser.add_argument("--output", type=Path, help="write the report here instead of stdout")
    args = parser.parse_args()
    skip = {name.strip() for name in args.skip.split(",") if name.strip()}
    unknown = skip - set(SOURCES)
    if unknown:
        parser.error(f"unknown source(s): {', '.join(sorted(unknown))}")
    # Search Console data settles two to three days after the fact.
    end = dt.date.today() - dt.timedelta(days=3)
    start = end - dt.timedelta(days=args.days - 1)
    held, declared = collection_names(load_database(str(REPO_ROOT / "database.json")),
                                      load_emulator_profiles(str(REPO_ROOT / "emulators")))
    queries = None if "gsc" in skip else fetch_queries(start, end)
    goat = None if "goatcounter" in skip else fetch_goatcounter(start, dt.date.today())
    github = None if "github" in skip else fetch_github()
    text = report(start, end, queries, goat, github, held, declared)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    run_cli(main)
