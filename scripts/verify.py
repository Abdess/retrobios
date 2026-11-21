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
from pathlib import Path


sys.path.insert(0, os.path.dirname(__file__))
from core.cli import add_emulator_selection, add_repo_inputs
from resolve.contentlayout import TARGET_KEY
from model.targets import (
    canonical_target_name,
    target_scope,
)
from model.cliargs import (
    LISTING_FLAGS,
    comma_list,
    platform_arg,
    refuse_beside_mode,
    requested_regions,
    run_listing,
    work_from_repo_root,
    require_platform,
    selected_platforms,
)
from model.systems import resolve_system_arg
from model.profiles import (
    load_emulator_profiles,
)
from model.registry import load_data_dir_registry
from resolve.grouping import group_identical_platforms
from model.database import load_database
from model.platforms import load_platform_config
from resolve.cores import (
    without_profile_blind,
    platform_scope_systems,
    system_scope_error,
)
from model.safeparse import require_yaml


from packs.coverage import verify_platform
from packs.emulatorcheck import verify_emulator, verify_system
from packs.report import (
    NOT_FIRMWARE,
    core_required_missing,
    discrepancy_keys,
    split_undeclared,
    print_emulator_result,
    print_platform_result,
)
from packs.verdicts import Severity, Status

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
        (args.standalone and not (args.emulator or args.system),
         "--standalone requires --emulator or --system"),
        (args.standalone and args.platform,
         "--standalone is incompatible with --platform"),
        (args.target and not (args.platform or args.all),
         "--target requires --platform or --all"),
        (args.target and (args.emulator or (args.system and not args.platform)),
         "--target is incompatible with --emulator and --system"),
        (args.destinations and args.system,
         "--destinations describes the full pack and is incompatible with --system"),
        (args.destinations and not (args.platform or args.all),
         "--destinations requires --platform or --all"),
        # Game data is categorized against a platform's list and its cores.
        (getattr(args, "no_game_data", False) and not (args.platform or args.all),
         "--no-game-data requires --platform or --all"),
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
    # --system beside --platform narrows that platform, as in generate_pack.
    system_mode = bool(args.system) and not args.platform
    modes = sum(1 for x in (args.platform, args.all, args.emulator, system_mode) if x)
    if modes == 0:
        parser.error("Specify --platform, --all, --emulator, or --system")
    if modes > 1:
        parser.error(
            "--platform, --all, --emulator, and --system are mutually exclusive"
        )
    _refuse_mode_flags(args, parser)
    return system_mode


def _platform_system_filter(
    args: argparse.Namespace, parser: argparse.ArgumentParser,
) -> list[str] | None:
    if not (args.platform and args.system):
        return None
    config = load_platform_config(args.platform, args.platforms_dir)
    try:
        return resolve_system_arg(
            args.system, list(config.get("systems", {})), config,
            f"--platform {args.platform} --list-systems",
        )
    except ValueError as exc:
        parser.error(f"--system {args.system}: {exc}")
    return None


def _run_emulator_mode(args: argparse.Namespace, db: dict, requested_regions: list[str]) -> None:
    names = comma_list(args.emulator)
    result = verify_emulator(
        names, args.emulators_dir, db, args.standalone,
        regions=requested_regions, platforms_dir=args.platforms_dir,
        required_only=args.required_only,
    )
    if args.json:
        result["details"] = _json_details(result["details"], args.verbose)
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
        result["details"] = _json_details(result["details"], args.verbose)
        print(json.dumps(result, indent=2))
    else:
        print_emulator_result(result, verbose=args.verbose)
    _exit_if_strict_emulator(args.strict, result)


def _target_scope(
    args: argparse.Namespace,
    platforms: list[str],
    emu_profiles: dict,
    platform_systems: list[str] | None,
) -> tuple[dict[str, set[str] | None], list[str]]:
    """The cores of each platform on --target, and the platforms that have it."""
    if not args.target:
        return {}, platforms
    target_cores_cache, platforms = target_scope(
        platforms, args.target, args.platforms_dir, is_all=args.all
    )
    # A system the target leaves no core for was reported 0/0 with exit 0,
    # where generate_pack refuses the same request.
    if platform_systems:
        config = load_platform_config(args.platform, args.platforms_dir)
        if not platform_scope_systems(
            config, emu_profiles, target_cores_cache.get(args.platform), platform_systems
        ):
            reason = system_scope_error(
                config, args.platform, platform_systems, args.target
            )
            print(f"ERROR: {reason}", file=sys.stderr)
            sys.exit(1)
    return target_cores_cache, platforms


def _print_platform_results(
    args: argparse.Namespace,
    groups: list[tuple[list[str], str]],
    group_results: list[tuple[dict, list[str]]],
    all_results: dict[str, dict],
) -> None:
    if not args.json:
        for result, group in group_results:
            print_platform_result(result, group, verbose=args.verbose)
            print()
        if len(group_results) > 1:
            print(_overall_summary(group_results))

    if args.destinations:
        destinations = {}
        for (result, names), (group, _rep) in zip(group_results, groups):
            for name, key in zip(names, group):
                destinations[name] = {
                    "platform": key, "pack_destinations": result["pack_destinations"],
                }
        Path(args.destinations).write_text(json.dumps(destinations, indent=1, sort_keys=True))

    if args.json:
        for r in all_results.values():
            r["details"] = _json_details(r["details"], args.verbose)
        print(json.dumps(all_results, indent=2))


def _run_platform_mode(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    db: dict,
    requested_regions: list[str],
    platform_systems: list[str] | None,
) -> None:
    platforms = selected_platforms(args, parser)

    # Load emulator profiles once for cross-reference (not per-platform)
    emu_profiles = load_emulator_profiles(args.emulators_dir)
    data_registry = load_data_dir_registry(args.platforms_dir)

    target_cores_cache, platforms = _target_scope(
        args, platforms, emu_profiles, platform_systems,
    )

    # generate_pack refuses these on a platform whose cores no profile
    # describes, and the report answers the same request the same way.
    platforms = without_profile_blind(
        platforms,
        [
            flag for flag, given in (
                ("--region", requested_regions),
                ("--no-game-data", getattr(args, "no_game_data", False)),
            ) if given
        ],
        args.platforms_dir,
        emu_profiles,
        target_cores_cache if args.target else None,
        args.all,
    )

    # Group identical platforms (same function as generate_pack)
    groups = group_identical_platforms(
        platforms, args.platforms_dir, target_cores_cache if args.target else None
    )

    all_results = {}
    group_results: list[tuple[dict, list[str]]] = []
    for group_platforms, representative in groups:
        config = load_platform_config(representative, args.platforms_dir)
        tc = target_cores_cache.get(representative) if args.target else None
        if tc is not None:
            # A core a roms folder offers on other boards only is not placed
            # there, as generate_pack builds the board's pack.
            config = {**config, TARGET_KEY: canonical_target_name(
                [representative], args.target, args.platforms_dir)}
        result = verify_platform(
            config,
            db,
            args.emulators_dir,
            emu_profiles,
            target_cores=tc,
            data_dir_registry=data_registry,
            regions=requested_regions,
            system_filter=platform_systems,
            no_game_data=getattr(args, "no_game_data", False),
            required_only=args.required_only,
        )
        names = [
            load_platform_config(p, args.platforms_dir).get("platform", p)
            for p in group_platforms
        ]
        group_results.append((result, names))
        for p in group_platforms:
            all_results[p] = result

    _print_platform_results(args, groups, group_results, all_results)
    _exit_if_strict(args.strict, [r for r, _ in group_results])


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
    platform_systems = _platform_system_filter(args, parser)
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


def _json_details(details: list[dict], verbose: bool) -> list[dict]:
    """The entries a JSON report lists: what needs attention, or every one.

    --verbose shows each entry with its ground truth in the text report. It
    used to be accepted beside --json and dropped, the output byte for byte
    the same, so a script asking for the passing entries got nothing.
    """
    return list(details) if verbose else [
        d for d in details if d["status"] != Status.OK or d.get("release_asset")
    ]


def _exit_if_strict(strict: bool, results: list[dict]) -> None:
    """Exit 1 under --strict when a platform result counts a critical file:
    a required file missing where the frontend reads hashes.

    A file present whose hash the frontend does not confirm is UNTESTED, a
    warning (Batocera's BiosStatus calls it so): reported, not failed.
    """
    critical = sum(r["severity_counts"].get(Severity.CRITICAL, 0) for r in results)
    if strict and critical:
        print(f"ERROR: {critical} required file(s) missing where the frontend "
              "checks hashes", file=sys.stderr)
        sys.exit(1)


def _exit_if_strict_emulator(strict: bool, result: dict) -> None:
    """Exit 1 under --strict when an emulator lacks a file it cannot run without.

    The emulator, not a frontend, is the judge here: a required file with no
    HLE fallback that the collection does not hold stops the core.
    """
    missing = sorted({
        d["name"] for d in result["details"]
        if d["status"] == Status.MISSING and d.get("required", True)
        and not d.get("hle_fallback")
    })
    if strict and missing:
        print(f"ERROR: {len(missing)} required file(s) missing: "
              f"{', '.join(missing)}", file=sys.stderr)
        sys.exit(1)


def _overall_summary(group_results: list[tuple[dict, list[str]]]) -> str:
    """The closing lines of a multi-platform run, worst severity first.

    Each count names the platforms carrying it, and the core files a core
    cannot run without are counted too: a reader of the summary alone used
    to conclude nothing required was missing, and could not tell where the
    one warning was without reading the whole output.
    """
    platforms = sum(len(group) for _, group in group_results)

    def where(counts: dict[str, int]) -> str:
        named = [f"{name} {count}" for name, count in counts.items() if count]
        return f" ({', '.join(named)})" if named else ""

    def on(groups: tuple[str, ...]) -> str:
        """The platforms a file is missing on, by the shorter side."""
        if len(group_results) < 2 or len(groups) * 2 <= len(group_results):
            return ", ".join(groups)
        others = [" / ".join(g) for _, g in group_results if " / ".join(g) not in groups]
        return "every platform" + (f" but {', '.join(others)}" if others else "")

    parts = []
    for severity, label in ((Severity.CRITICAL, "critical"), (Severity.WARNING, "warning"),
                            (Severity.INFO, "info")):
        counts = {
            " / ".join(group): r["severity_counts"].get(severity, 0)
            for r, group in group_results
        }
        parts.append(f"{sum(counts.values())} {label}{where(counts)}")
    # Shipped files whose bytes contradict a declaration or a core's own
    # check: the body printed 19 of them under a last line that read clean.
    counts = {
        " / ".join(group): len(discrepancy_keys(r.get("details", [])))
        for r, group in group_results
    }
    total = sum(counts.values())
    parts.append(f"{total} {'discrepancy' if total == 1 else 'discrepancies'}{where(counts)}")
    lines = [f"{platforms} platforms: {', '.join(parts)}"]

    # Grouped by file, not by platform: sfiii2a.zip missing everywhere was
    # counted and printed once per platform, 24 files for 10 distinct ones.
    holders: dict[str, list[str]] = {}
    for r, group in group_results:
        for name in sorted({
            u["name"] for u in core_required_missing(split_undeclared(
                r.get("undeclared_files", []))[1])
        }):
            holders.setdefault(name, []).append(" / ".join(group))
    if holders:
        by_platforms: dict[tuple[str, ...], list[str]] = {}
        for name, groups in sorted(holders.items()):
            by_platforms.setdefault(tuple(groups), []).append(name)
        detail = "; ".join(
            f"{', '.join(names)} ({on(groups)})"
            for groups, names in sorted(by_platforms.items(),
                                        key=lambda item: (-len(item[0]), item[1]))
        )
        lines.append(f"{len(holders)} core file(s) a core cannot run without are "
                     f"missing: {detail}")
    for category, label in NOT_FIRMWARE.items():
        counts = {
            " / ".join(group): len((r.get("missing_not_firmware") or {}).get(category, []))
            for r, group in group_results
        }
        total = sum(counts.values())
        if total:
            lines.append(f"{total} platform entries missing, not firmware, {label}{where(counts)}")
    return "\n".join(lines)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
