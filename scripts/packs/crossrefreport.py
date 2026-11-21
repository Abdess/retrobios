"""A cross_reference run: its options checked, its scope chosen, its report printed."""

from __future__ import annotations

import argparse
import contextlib
import json

from model.cliargs import list_emulator_profiles, require_platform, work_from_repo_root
from model.database import load_database
from model.profiles import ProfileSelectionError, load_emulator_profiles, select_emulator_profiles
from model.registry import load_data_dir_registry
from packs.crossreflaunchers import LAUNCHER_READS_KEY, LAUNCHER_UNPROVEN_KEY, launcher_rows
from packs.crossrefrun import scope_gaps
from packs.crossrefscope import refuse_empty_scope, tree_scope
from packs.crossreftext import print_launcher_reads, print_launcher_unproven, print_report
from packs.datadirs import hold_data_dirs


def _list_emulators(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """--list-emulators reads no other option: one given beside it is refused."""
    ignored = [flag for flag, on in (
        ("--emulator", args.emulator), ("--platform", args.platform),
        ("--all", args.all), ("--target", args.target), ("--json", args.json),
    ) if on]
    if ignored:
        parser.error(f"--list-emulators does not apply {', '.join(ignored)}")
    list_emulator_profiles(args.emulators_dir)


def _scope_label(args: argparse.Namespace, emulator: str | None) -> str:
    if emulator:
        return emulator
    if args.platform:
        return f"the emulators {args.platform} runs"
    if args.target:
        return f"the emulators built for {args.target}"
    return "all emulators"


def run_gap_report(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Check the options, then print the gap report of the scope they name."""
    work_from_repo_root(args, parser, ["emulators_dir", "platforms_dir", "db"])
    if args.list_emulators:
        _list_emulators(args, parser)
        return
    if args.platform and args.all:
        parser.error("--platform and --all are mutually exclusive")
    if args.platform:
        require_platform(args.platform, args.platforms_dir)

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
        refuse_empty_scope(args, emulator, tree)
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
    print_report(report, _scope_label(args, emulator), show_clean=bool(args.emulator))
    print_launcher_reads(launcher_reads)
    print_launcher_unproven(unproven)
