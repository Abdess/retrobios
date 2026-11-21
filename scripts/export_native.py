#!/usr/bin/env python3
"""Rewrite each platform's own BIOS file, corrected by the ground truth.

The output is the file the platform maintains, not a rendering of our data
in its syntax: what the truth can prove is applied, what it says nothing
about is left alone, and what it knows and the platform lacks is added. The
formats that carry code are patched rather than regenerated, so the checker
a platform ships keeps working.

Usage:
    python scripts/export_native.py --all --fetch           # into exports/
    python scripts/export_native.py --platform recalbox --upstream-dir up/
    python scripts/export_native.py --platform retrobat --refresh-cache
"""

from __future__ import annotations

import argparse
import contextlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.cli import add_repo_inputs
from core.paths import TRUTH_DIR
from exporter.originals import DEFAULT_CACHE
from exporter.runner import run
from model.cliargs import platform_arg, selected_platforms
from model.registry import load_data_dir_registry
from packs.datadirs import hold_data_dirs


def main() -> None:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Rewrite each platform's own BIOS file, corrected.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true", help="every platform")
    group.add_argument("--platform", "-p", type=platform_arg, help="a single platform")
    parser.add_argument(
        "--output-dir", default="exports",
        help="directory the updated platform files go to (default: %(default)s)",
    )
    parser.add_argument(
        "--truth-dir", default=TRUTH_DIR,
        help="directory of the truth models generate_truth writes (default: "
             "%(default)s)",
    )
    add_repo_inputs(parser, "platforms")
    parser.add_argument(
        "--upstream-dir",
        default=DEFAULT_CACHE,
        help="where the platforms' own files are read and cached",
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="download a platform's file when it is not in the cache, "
        "or when the cache came from another URL",
    )
    parser.add_argument(
        "--refresh-cache",
        action="store_true",
        help="download every platform file again and write no export",
    )
    args = parser.parse_args()

    platforms = selected_platforms(args)

    with contextlib.ExitStack() as held:
        if not args.refresh_cache:
            # Removal candidates are proved against data/: a refresh swapping
            # a tree mid-walk listed entries only that tree holds as removable.
            hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))
        code = run(
            platforms,
            args.truth_dir,
            args.output_dir,
            args.platforms_dir,
            args.upstream_dir,
            args.fetch,
            args.refresh_cache,
        )
    sys.exit(code)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
