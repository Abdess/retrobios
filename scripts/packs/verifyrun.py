"""A verify run: its options checked, then the emulator, system or platform mode."""

from __future__ import annotations

import argparse
import contextlib

from model.cliargs import (
    comma_list,
    requested_regions,
    require_platform,
    resolve_system_ids,
    run_listing,
    selected_platforms,
    work_from_repo_root,
)
from model.database import load_database
from model.registry import load_data_dir_registry
from packs.emulatorcheck import verify_emulator, verify_system
from packs.strictgate import exit_if_strict
from packs.verifyoptions import check_mode, refuse_listing_narrowings
from packs.verifyplatforms import PlatformRun, verify_platforms
from packs.verifyprint import print_emulator_run, print_platform_results


def _run_emulator_mode(args: argparse.Namespace, db: dict, regions: list[str]) -> None:
    print_emulator_run(args, verify_emulator(
        comma_list(args.emulator), args.emulators_dir, db, args.standalone,
        regions=regions, platforms_dir=args.platforms_dir,
        required_only=args.required_only,
    ))


def _run_system_mode(args: argparse.Namespace, db: dict, regions: list[str]) -> None:
    print_emulator_run(args, verify_system(
        comma_list(args.system), args.emulators_dir, db, args.standalone,
        regions=regions, platforms_dir=args.platforms_dir,
        required_only=args.required_only,
    ))


def _run_platform_mode(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    db: dict,
    regions: list[str],
    platform_systems: list[str] | None,
) -> None:
    results = verify_platforms(selected_platforms(args, parser), db, PlatformRun(
        platforms_dir=args.platforms_dir,
        emulators_dir=args.emulators_dir,
        target=args.target,
        is_all=args.all,
        regions=regions,
        system_filter=platform_systems,
        no_game_data=getattr(args, "no_game_data", False),
        required_only=args.required_only,
        json_output=args.json,
    ))
    print_platform_results(args, results)
    exit_if_strict(args.strict, [r for r, _ in results.group_results])


def run_verify(
    held: contextlib.ExitStack, parser: argparse.ArgumentParser, args: argparse.Namespace
) -> None:
    """Check the options, hold the data trees in `held` and run the mode asked for."""
    work_from_repo_root(args, parser, ["db", "platforms_dir", "emulators_dir"])
    if args.platform:
        require_platform(args.platform, args.platforms_dir)
    if args.offline:
        from resolve import packfiles as packresolve

        packresolve.set_offline(True)

    regions = requested_regions(args.region, parser)

    if refuse_listing_narrowings(args, parser):
        run_listing(args, parser, args.list_platforms)
        return

    system_mode = check_mode(args, parser)
    platform_systems = resolve_system_ids(args, parser)
    # The trees stay put while names resolve against them and files are read.
    from packs.datadirs import hold_data_dirs

    hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))

    db = load_database(args.db)

    if args.emulator:
        _run_emulator_mode(args, db, regions)
    elif system_mode:
        _run_system_mode(args, db, regions)
    else:
        _run_platform_mode(args, parser, db, regions, platform_systems)
