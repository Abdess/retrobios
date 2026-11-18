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
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from model.cliargs import platform_arg, require_platform
from model.registry import list_registered_platforms, load_data_dir_registry, load_platform_registry
from exporter import discover_exporters
from exporter.native import export_platform, refresh_cache
from exporter.originals import DEFAULT_CACHE


def run(
    platforms: list[str],
    truth_dir: str,
    output_dir: str,
    platforms_dir: str,
    upstream_dir: str,
    allow_fetch: bool,
    refresh_only: bool = False,
) -> int:
    exporters = discover_exporters()
    registry = load_platform_registry(platforms_dir)
    failures = 0
    skipped: list[str] = []

    for platform in sorted(platforms):
        exporter_class = exporters.get(platform)
        if not exporter_class and (registry.get(platform) or {}).get("native_list") == "none":
            # The platform's code names no BIOS file: there is no list of its
            # own to hand back corrected.
            print(f"  SKIP {platform}: names no BIOS file of its own (native_list: none)")
            continue
        if not exporter_class:
            skipped.append(platform)
            print(f"  SKIP {platform}: no exporter")
            continue

        if refresh_only:
            ok, messages = refresh_cache(
                platform,
                exporter_class,
                Path(truth_dir),
                platforms_dir,
                Path(upstream_dir),
            )
        else:
            ok, messages = export_platform(
                platform,
                exporter_class,
                Path(truth_dir),
                Path(output_dir),
                platforms_dir,
                Path(upstream_dir),
                allow_fetch,
            )
        label = "OK  " if ok else "FAIL"
        print(f"  {label} {platform}")
        for message in messages:
            print(f"       {message}")
        if not ok:
            failures += 1

    if skipped:
        print(f"\n{len(skipped)} platform(s) without an exporter: {', '.join(skipped)}")
        failures += len(skipped)

    return 1 if failures else 0


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
        "--truth-dir", default="dist/truth",
        help="directory of the truth models generate_truth writes (default: "
             "%(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default="platforms",
        help="platform YAML directory (default: %(default)s)",
    )
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

    if args.all:
        platforms = list_registered_platforms(
            args.platforms_dir,
        )
    else:
        require_platform(args.platform, args.platforms_dir)
        platforms = [args.platform]

    if not args.refresh_cache:
        import contextlib

        from packs.datadirs import hold_data_dirs

        # Removal candidates are proved against data/: a refresh swapping a
        # tree mid-walk listed entries only that tree holds as removable.
        # The process exit releases the hold.
        held = contextlib.ExitStack()
        hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))

    sys.exit(
        run(
            platforms,
            args.truth_dir,
            args.output_dir,
            args.platforms_dir,
            args.upstream_dir,
            args.fetch,
            args.refresh_cache,
        )
    )


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
