#!/usr/bin/env python3
"""Validate the built RetroBIOS site as a navigable, accessible data product.

This complements Starlight's own link check (starlight-links-validator,
which fails the build) with checks on the rendered HTML: metadata,
heading structure, image alternatives, duplicate IDs, structured data, local
resources, links and fragments, the budgets of what a visitor downloads, and
a get/ download page for every registered platform.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from core.paths import PLATFORMS_DIR
from sitegen.validate import validate_site


def main() -> None:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=__doc__.replace("``", ""),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--site-dir", default="website/dist",
        help="the built site (default: %(default)s)",
    )
    parser.add_argument(
        "--base", default="/retrobios/",
        help="the path the site is served under (default: %(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default=PLATFORMS_DIR, type=Path,
        help="registry whose platforms each need a get/ page (default: %(default)s)",
    )
    parser.add_argument(
        "--record", default="release.json", type=Path,
        help="release record the get/ pages link (default: %(default)s)",
    )
    parser.add_argument(
        "--max-errors", type=int, default=100,
        help="stop listing after this many errors (default: %(default)s)",
    )
    args = parser.parse_args()
    from core.cli import require_directory

    require_directory(str(args.platforms_dir), "--platforms-dir")

    try:
        issues = validate_site(Path(args.site_dir), args.base, args.platforms_dir, args.record)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Site validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    if issues:
        for issue in issues[: args.max_errors]:
            print(f"ERROR {issue}", file=sys.stderr)
        if len(issues) > args.max_errors:
            print(
                f"ERROR ... {len(issues) - args.max_errors} additional issue(s)",
                file=sys.stderr,
            )
        print(f"{len(issues)} rendered-site issue(s)", file=sys.stderr)
        raise SystemExit(1)

    html_count = sum(1 for _ in Path(args.site_dir).rglob("*.html"))
    print(f"Rendered site is valid: {html_count} HTML pages, all local links resolved.")


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
