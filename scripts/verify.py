#!/usr/bin/env python3
"""Platform-native BIOS verification engine.

Replicates the exact verification logic of each platform:
- RetroArch/Lakka/RetroPie: file existence only (core_info.c path_is_valid)
- Batocera: MD5 + checkInsideZip, no required distinction (batocera-systems:1062-1091)
- Recalbox: MD5 + mandatory/hashMatchMandatory, 3-color severity (Bios.cpp:109-130)
- RetroBat: same as Batocera
- EmuDeck: MD5 whitelist per system
- RetroDECK: MD5 per file via component manifests
- RomM: size + any hash, no ZIP inspection (firmware.py verify_file_hashes)
- ROCKNIX: MD5 + checkInsideZip with altmd5 (rocknix-systems checkBios)
- MiSTer FPGA: MD5 of the file at its destination, no ZIP inspection
- BizHawk: SHA1 firmware hash verification

Cross-references emulator profiles to detect undeclared files used by available cores.

Usage:
    python scripts/verify.py --all
    python scripts/verify.py --platform batocera
    python scripts/verify.py --all --json
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys


sys.path.insert(0, os.path.dirname(__file__))
from core.cli import add_emulator_selection, add_repo_inputs
from model.cliargs import (
    LISTING_FLAGS,
    comma_list,
    mode_conflicts,
    platform_arg,
    refuse_beside_mode,
    requested_regions,
    run_listing,
    work_from_repo_root,
    require_platform,
    resolve_system_ids,
    selected_platforms,
)
from model.registry import load_data_dir_registry
from model.database import load_database
from model.safeparse import require_yaml


from packs.emulatorcheck import verify_emulator, verify_system
from packs.report import print_emulator_result, print_platform_result
from packs.strictgate import emulator_strict_failure, platform_strict_failure
from packs.verifyoutput import json_details, write_pack_destinations
from packs.verifyplatforms import PlatformResults, PlatformRun, verify_platforms
from packs.verifysummary import overall_summary

yaml = require_yaml()


def _refuse_listing_narrowings(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> str | None:
    """A listing reads --platform at most: anything else given beside it,
    another listing included, is refused (generate_pack applies the same
    table). The listing asked for, if any."""
    listings = [(flag, getattr(args, flag[2:].replace("-", "_"))) for flag in LISTING_FLAGS]
    given = {flag for flag, on in (
        *listings,
        ("--platform", args.platform),
        ("--all", args.all),
        ("--emulator", args.emulator),
        ("--system", args.system),
        ("--region", getattr(args, "region", None)),
        ("--target", getattr(args, "target", None)),
        ("--standalone", args.standalone),
        ("--json", args.json),
        ("--strict", args.strict),
        ("--verbose", args.verbose),
        ("--destinations", args.destinations),
        ("--offline", args.offline),
        ("--no-game-data", getattr(args, "no_game_data", False)),
        ("--required-only", args.required_only),
    ) if on}
    return refuse_beside_mode(listings, given, LISTING_FLAGS, parser)


def _refuse_mode_flags(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """A flag the chosen mode does not read is refused, never ignored."""
    for refused, message in (
        *mode_conflicts(args),
        (args.destinations and args.system,
         "--destinations describes the full pack and is incompatible with --system"),
        (args.destinations and not (args.platform or args.all),
         "--destinations requires --platform or --all"),
        (args.destinations and getattr(args, "region", None),
         "--destinations describes the full pack and is incompatible with --region"),
        (args.destinations and args.required_only,
         "--destinations describes the full pack and is incompatible with --required-only"),
    ):
        if refused:
            parser.error(message)


def main() -> None:
    with contextlib.ExitStack() as held:
        _main(held)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Platform-native BIOS verification")
    parser.add_argument("--platform", "-p", type=platform_arg, help="Platform name")
    parser.add_argument(
        "--all", action="store_true", help="Verify every registered platform"
    )
    add_emulator_selection(parser)
    parser.add_argument(
        "--list-platforms", action="store_true", help="List available platforms"
    )
    parser.add_argument("--target", "-t", help="Hardware target (e.g., switch, rpi4)")
    parser.add_argument(
        "--region", help="Region priority list, best first (e.g. us,eu,jp)"
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="List available targets for the platform",
    )
    parser.add_argument(
        "--no-game-data", action="store_true",
        help="Report on the pack built with --no-game-data: game data left "
        "out and named, firmware only",
    )
    parser.add_argument(
        "--required-only", action="store_true",
        help="Report on the pack built with --required-only: files the code "
        "runs without are left out",
    )
    add_repo_inputs(parser, "db", "platforms", "emulators")
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show emulator ground truth details",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--offline", action="store_true",
        help="Report as an offline build packs: a release asset the cache "
        "lacks is missing. Without it, it counts as fetched at build time",
    )
    parser.add_argument(
        "--destinations", metavar="FILE",
        help="With --platform or --all, also write the paths each pack holds "
        "according to this report to FILE (JSON), for comparison with the archive",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 on a required file missing: where the frontend checks "
        "hashes for a platform, without HLE for --emulator and --system. A file "
        "present with an unconfirmed hash is a warning, not a failure",
    )
    return parser


def _check_mode(args: argparse.Namespace, parser: argparse.ArgumentParser) -> bool:
    """Refuse a request naming no mode or several, and say if it is the system mode."""
    _refuse_mode_flags(args, parser)
    return bool(args.system) and not (args.platform or args.all)


def _run_emulator_mode(args: argparse.Namespace, db: dict, requested_regions: list[str]) -> None:
    names = comma_list(args.emulator)
    result = verify_emulator(
        names, args.emulators_dir, db, args.standalone,
        regions=requested_regions, platforms_dir=args.platforms_dir,
        required_only=args.required_only,
    )
    if args.json:
        result["details"] = json_details(result["details"], args.verbose)
        print(json.dumps(result, indent=2))
    else:
        print_emulator_result(result, verbose=args.verbose)
    _exit_if_strict_emulator(args.strict, result)


def _run_system_mode(args: argparse.Namespace, db: dict, requested_regions: list[str]) -> None:
    system_ids = comma_list(args.system)
    result = verify_system(
        system_ids, args.emulators_dir, db, args.standalone,
        regions=requested_regions, platforms_dir=args.platforms_dir,
        required_only=args.required_only,
    )
    if args.json:
        result["details"] = json_details(result["details"], args.verbose)
        print(json.dumps(result, indent=2))
    else:
        print_emulator_result(result, verbose=args.verbose)
    _exit_if_strict_emulator(args.strict, result)


def _print_platform_results(args: argparse.Namespace, results: PlatformResults) -> None:
    group_results = results.group_results
    if not args.json:
        for result, group in group_results:
            print_platform_result(result, group, verbose=args.verbose)
            print()
        if len(group_results) > 1:
            print(overall_summary(group_results))

    if args.destinations:
        write_pack_destinations(args.destinations, results.groups, group_results)

    if args.json:
        for r in results.all_results.values():
            r["details"] = json_details(r["details"], args.verbose)
        print(json.dumps(results.all_results, indent=2))


def _run_platform_mode(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    db: dict,
    requested_regions: list[str],
    platform_systems: list[str] | None,
) -> None:
    results = verify_platforms(selected_platforms(args, parser), db, PlatformRun(
        platforms_dir=args.platforms_dir,
        emulators_dir=args.emulators_dir,
        target=args.target,
        is_all=args.all,
        regions=requested_regions,
        system_filter=platform_systems,
        no_game_data=getattr(args, "no_game_data", False),
        required_only=args.required_only,
    ))
    _print_platform_results(args, results)
    _exit_if_strict(args.strict, [r for r, _ in results.group_results])


def _main(held: contextlib.ExitStack) -> None:
    parser = _build_parser()
    args = parser.parse_args()
    work_from_repo_root(args, parser, ["db", "platforms_dir", "emulators_dir"])
    if args.platform:
        require_platform(args.platform, args.platforms_dir)
    if args.offline:
        from resolve import packfiles as packresolve

        packresolve.set_offline(True)

    regions = requested_regions(args.region, parser)

    if _refuse_listing_narrowings(args, parser):
        run_listing(args, parser, args.list_platforms)
        return

    system_mode = _check_mode(args, parser)
    platform_systems = resolve_system_ids(args, parser)
    # The trees stay put while names resolve against them and files are read.
    from packs.datadirs import hold_data_dirs

    hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))

    db = load_database(args.db)

    if args.emulator:
        _run_emulator_mode(args, db, regions)
        return

    if system_mode:
        _run_system_mode(args, db, regions)
        return

    # Platform mode (existing)
    _run_platform_mode(args, parser, db, regions, platform_systems)


def _exit_if_strict(strict: bool, results: list[dict]) -> None:
    """Exit 1 under --strict when a platform result counts a critical file."""
    failure = platform_strict_failure(results)
    if strict and failure:
        print(failure, file=sys.stderr)
        sys.exit(1)


def _exit_if_strict_emulator(strict: bool, result: dict) -> None:
    """Exit 1 under --strict when an emulator lacks a file it cannot run without."""
    failure = emulator_strict_failure(result)
    if strict and failure:
        print(failure, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
