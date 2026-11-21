#!/usr/bin/env python3
"""Compare scraped platform YAMLs against ground-truth YAMLs.

Usage:
    python scripts/diff_truth.py --all
    python scripts/diff_truth.py --platform retroarch
    python scripts/diff_truth.py --platform retroarch --json
    python scripts/diff_truth.py --all --format markdown
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from core.cli import add_repo_inputs
from core.paths import TRUTH_DIR
from exporter.diffreport import format_markdown, format_terminal
from exporter.truthdiff import NoDiffInput, platform_diff
from model.cliargs import platform_arg, selected_platforms
from model.targets import truth_target_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Compare scraped vs truth YAMLs")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--all", action="store_true", help="diff all registered platforms"
    )
    group.add_argument("--platform", "-p", type=platform_arg, help="diff a single platform")
    # One output form: --json beside --format markdown printed JSON and
    # dropped the markdown without a word.
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--json", action="store_true", dest="json_output", help="JSON output"
    )
    output.add_argument(
        "--format", choices=["terminal", "markdown"], default="terminal",
        help="report format (default: %(default)s)",
    )
    output.add_argument(
        "--markdown", action="store_const", const="markdown", dest="format",
        help="same as --format markdown, the spelling validate_pr uses",
    )
    parser.add_argument(
        "--truth-dir", default=TRUTH_DIR,
        help="directory of the truth models generate_truth writes (default: "
             "%(default)s)",
    )
    add_repo_inputs(parser, "platforms")
    parser.add_argument(
        "--target", "-t",
        help="read the models generate_truth --target wrote, each under the "
        "target as its platform files it",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()

    platforms = selected_platforms(args)

    reports: list[dict] = []
    formatter = format_markdown if args.format == "markdown" else format_terminal
    compared = 0

    for platform in platforms:
        truth_dir = (
            truth_target_dir(args.truth_dir, [platform], args.target, args.platforms_dir)
            if args.target else args.truth_dir
        )
        try:
            report = platform_diff(platform, truth_dir, args.platforms_dir)
        except NoDiffInput as exc:
            print(f"skip {platform}: {exc}", file=sys.stderr)
            continue
        compared += 1

        if args.json_output:
            reports.append(report)
        else:
            print(formatter(report))
            print()

    if args.json_output:
        json.dump(reports, sys.stdout, indent=2)
        print()

    # A named platform must be compared; --all must compare at least one.
    if compared < (len(platforms) if args.platform else 1):
        print(f"compared {compared} of {len(platforms)} platform(s)", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
