#!/usr/bin/env python3
"""Cross-reference emulator profiles against platform configs.

Identifies BIOS files that emulators need but platforms don't declare,
providing gap analysis for extended coverage.

Usage:
    python scripts/cross_reference.py
    python scripts/cross_reference.py --emulator dolphin
    python scripts/cross_reference.py --json
    python scripts/cross_reference.py --platform retroarch --target switch
    python scripts/cross_reference.py --all --target switch
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from core.cli import add_repo_inputs
from model.cliargs import platform_arg, list_emulator_profiles, require_platform
from model.profiles import ProfileSelectionError, load_emulator_profiles, select_emulator_profiles
from model.database import load_database
from model.registry import load_data_dir_registry
from model.safeparse import require_yaml

from packs.crossreflaunchers import LAUNCHER_READS_KEY, LAUNCHER_UNPROVEN_KEY, launcher_rows
from packs.crossrefrun import scope_gaps
from packs.crossrefscope import TreeScope, tree_scope
from packs.crossreftext import print_launcher_reads, print_launcher_unproven, print_report

yaml = require_yaml()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Emulator vs platform gap analysis")
    add_repo_inputs(parser, "emulators", "platforms", "db")
    parser.add_argument("--emulator", "-e", help="Analyze single emulator")
    parser.add_argument(
        "--platform", "-p", type=platform_arg, help="Restrict analysis to one platform's cores"
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Analyze the emulators every platform runs (the default without --platform)",
    )
    parser.add_argument(
        "--target", "-t",
        help="Hardware target (e.g., switch, rpi4): with --platform, the cores built "
        "for it there, otherwise the cores each platform with the target builds for it",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--list-emulators", action="store_true", help="List available emulators"
    )
    return parser


def _refuse_empty_scope(args: argparse.Namespace, emulator: str | None, tree: TreeScope) -> None:
    """Why the scope holds no profile, said before ending the run."""
    platform_scope = tree.platform
    if (emulator and args.target and platform_scope is not None
            and emulator in platform_scope.run_anywhere):
        raise SystemExit(
            f"ERROR: {emulator} is not built for {args.platform}'s "
            f"{args.target} target; {args.platform} runs it elsewhere "
            f"(drop --target to see its files)"
        )
    if emulator and args.platform:
        raise SystemExit(f"ERROR: {emulator} is not run by {args.platform}")
    if emulator:
        raise SystemExit(
            f"ERROR: no platform with the {args.target} target builds {emulator} "
            f"for it (drop --target to see its files)"
        )
    if args.target and not args.platform:
        print(f"No platform runs a profiled emulator on {args.target}.", file=sys.stderr)
    else:
        print(f"{args.platform or 'The tree'} runs no profiled emulator.", file=sys.stderr)


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    from model.cliargs import work_from_repo_root

    work_from_repo_root(args, parser, ["emulators_dir", "platforms_dir", "db"])
    if args.list_emulators:
        ignored = [flag for flag, on in (
            ("--emulator", args.emulator), ("--platform", args.platform),
            ("--all", args.all), ("--target", args.target), ("--json", args.json),
        ) if on]
        if ignored:
            parser.error(f"--list-emulators does not apply {', '.join(ignored)}")
        list_emulator_profiles(args.emulators_dir)
        return
    if args.platform and args.all:
        parser.error("--platform and --all are mutually exclusive")
    if args.platform:
        require_platform(args.platform, args.platforms_dir)

    import contextlib

    from packs.datadirs import hold_data_dirs

    # Files resolve against data/: the trees stay put until the process
    # ends, which releases the hold.
    held = contextlib.ExitStack()
    registry = load_data_dir_registry(args.platforms_dir)
    hold_data_dirs(held, registry)

    profiles = load_emulator_profiles(args.emulators_dir)
    # Every profile's names and aliases, whatever --emulator or --platform keeps.
    all_profiles = profiles
    emulator = args.emulator
    if emulator:
        # A typo answered "No emulator profiles found" with exit 0.
        try:
            ((emulator, _),) = select_emulator_profiles(
                [args.emulator],
                load_emulator_profiles(args.emulators_dir, skip_aliases=False),
            )
        except ProfileSelectionError as exc:
            raise SystemExit(f"ERROR: {exc}") from None
        profiles = {k: v for k, v in profiles.items() if k == emulator}

    tree = tree_scope(args.platform, args.target, args.platforms_dir, profiles)
    if not tree.profiles:
        _refuse_empty_scope(args, emulator, tree)
        return

    db = load_database(args.db)
    report = scope_gaps(tree, db, args.platforms_dir, args.platform)
    launcher_reads, unproven = launcher_rows(
        tree.selected, args.platforms_dir, db, all_profiles, registry, emulator,
    )

    if args.json:
        print(json.dumps(
            {**report, LAUNCHER_READS_KEY: launcher_reads, LAUNCHER_UNPROVEN_KEY: unproven},
            indent=2,
        ))
        return
    if emulator:
        scope = emulator
    elif args.platform:
        scope = f"the emulators {args.platform} runs"
    elif args.target:
        scope = f"the emulators built for {args.target}"
    else:
        scope = "all emulators"
    print_report(report, scope, show_clean=bool(args.emulator))
    print_launcher_reads(launcher_reads)
    print_launcher_unproven(unproven)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
