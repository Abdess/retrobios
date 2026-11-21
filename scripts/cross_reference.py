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
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(__file__))
from core.cli import add_repo_inputs
from core.text import count_text
from model.cliargs import platform_arg, list_emulator_profiles, require_platform
from model.profiles import ProfileSelectionError, load_emulator_profiles, select_emulator_profiles
from model.database import load_database
from model.registry import list_registered_platforms, load_data_dir_registry
from model.platforms import load_platform_config
from model.safeparse import require_yaml
from resolve.standalone import standalone_set
from resolve.launchers import (
    LauncherLayer,
    declared_destinations,
    launcher_unproven,
)

from packs.crossref import (
    build_supplemental_index,
    cross_reference,
    global_report_scope,
    launcher_reads_not_held,
    platform_configs,
    profile_breakdown,
)

yaml = require_yaml()


# The --json key of the launcher reads category, beside the emulator keys.
LAUNCHER_READS_KEY = "_launcher_reads_not_held"
# The --json key of the launcher records a config file does not prove.
LAUNCHER_UNPROVEN_KEY = "_launcher_unproven"


def print_launcher_unproven(rows: list[dict]) -> None:
    """The launcher records resting on a config file the code does not prove.

    Neither a pack, a manifest nor a severity reads them: each is listed
    with the links it lacks.
    """
    if not rows:
        return
    platforms = sorted({r["platform"] for r in rows})
    print(f"\nLauncher records unproven: {len(rows)} across {count_text(len(platforms), 'platform')}")
    for platform in platforms:
        print(f"\n{platform}")
        for row in (r for r in rows if r["platform"] == platform):
            print(f"    [{row['index']}] {row['emulator']} {row['kind']}: {row['passes_to']}")
            for link in row["missing"]:
                print(f"        missing {link}")


def print_launcher_reads(rows: list[dict]) -> None:
    """The launcher reads gap category, after the profile gaps.

    A name its reader declares unsourceable is listed apart, with the
    reason: it is no file left to find.
    """
    unsourceable = [r for r in rows if r.get("unsourceable")]
    rows = [r for r in rows if not r.get("unsourceable")]
    platforms = sorted({r["platform"] for r in rows})
    print(f"\nLauncher reads, not held: {count_text(len(rows), 'name')} "
          f"across {count_text(len(platforms), 'platform')}")
    for platform in platforms:
        print(f"\n{platform}")
        for row in (r for r in rows if r["platform"] == platform):
            first = row["readers"][0]
            more = f" (+{count_text(len(row['readers']) - 1, 'record')})" if len(row["readers"]) > 1 else ""
            casing = f", held as {row['held_as']}" if row.get("held_as") else ""
            print(
                f"    {row['name']} [{', '.join(row['emulators'])}, {first['kind']}, "
                f"{first['source_ref']}]{more}{casing}"
            )
    if not unsourceable:
        return
    platforms = sorted({r["platform"] for r in unsourceable})
    print(
        f"\nLauncher reads, unsourceable: {count_text(len(unsourceable), 'name')} "
        f"across {count_text(len(platforms), 'platform')}"
    )
    for row in unsourceable:
        print(
            f"    {row['platform']}: {row['name']} [{', '.join(row['emulators'])}, "
            f"{row['readers'][0]['source_ref']}]: {row['unsourceable']}"
        )


def print_report(
    report: dict, scope: str = "all emulators", show_clean: bool = False
) -> None:
    """Print a human-readable gap analysis report.

    `scope` names what the totals cover: under --platform, the emulators
    that platform runs, not all of them. `show_clean` lists an emulator with
    nothing undeclared too: asked about by name, it was the whole answer and
    the report used to leave it out.
    """
    print("Emulator vs Platform Gap Analysis")
    print("=" * 60)
    print("* marks a file the emulator requires")

    total_gaps = 0
    totals: dict[str, int] = {"bios": 0, "data": 0, "large_file": 0, "missing": 0}
    # A runtime component bundled with its emulator is left out of the
    # collection by design, as verify and the gaps page say: not a file to find.
    bundled = 0

    for _emu_name, data in sorted(report.items()):
        gaps = data["gaps"]
        if gaps == 0 and not show_clean:
            continue

        # Counted once, for the heading and the total alike: a file installed
        # with its emulator is neither one to source nor one the pack brings,
        # held or not (validation.deliverable leaves it out of every pack).
        bundled_gaps = [g for g in data["gap_details"] if g.get("bundled")]
        emulator_bundled = len(bundled_gaps)
        counts = {key: data.get(f"gap_{key}", 0) for key in totals}
        for g in bundled_gaps:
            counts[g.get("source", "missing")] -= 1
        counts["bundled"] = emulator_bundled
        parts = [f"{count} {key}" for key, count in counts.items() if count]
        status = ", ".join(parts) if parts else "OK"

        systems = ", ".join(data["systems"])
        print(f"\n{data['emulator']}" + (f" ({systems})" if systems else ""))
        print(f"  {data['total_files']} files in profile: {profile_breakdown(data)}")
        print(f"  Gaps: {status}")

        for g in data["gap_details"]:
            req = "*" if g["required"] else " "
            src = g.get("source", "missing").upper()
            if g.get("bundled"):
                src = "BUNDLED"
            # One line per file: a note spanning lines fell to column 0
            # between entries and read as an emulator heading.
            note = f": {' '.join(str(g['note']).split())}" if g["note"] else ""
            archive_info = ""
            if g.get("archive"):
                fc = g.get("archive_file_count", 0)
                rc = g.get("archive_required_count", 0)
                archive_info = f" ({fc} files, {rc} required)"
            if g.get("alternatives") and not g.get("in_repo"):
                archive_info += f" (or {', '.join(g['alternatives'])})"
            print(f"    {req} {g['name']} [{src}]{archive_info}{note}")

        total_gaps += gaps
        for key in totals:
            totals[key] += counts[key]
        bundled += emulator_bundled

    print(f"\n{'=' * 60}")
    print(f"Total: {total_gaps} undeclared files across {scope}")
    available = totals["bios"] + totals["data"] + totals["large_file"]
    print(f"  {available} available (bios: {totals['bios']}, data: {totals['data']}, "
          f"large_file: {totals['large_file']})")
    print(f"  {totals['missing']} missing (need to be sourced)")
    if bundled:
        print(f"  {bundled} bundled with their emulator, not packed")


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


@dataclass(frozen=True)
class _PlatformScope:
    """The profiles a --platform run compares, and how the platform runs them."""

    profiles: dict[str, dict]
    standalone_cores: set[str]
    config: dict
    relevant: set[str]
    run_anywhere: set[str]


def _platform_scope(args: argparse.Namespace, profiles: dict[str, dict]) -> _PlatformScope:
    from model.targets import target_scope
    from resolve.cores import resolve_platform_cores

    # A typo ended in a traceback where verify and slots name the closest
    # target, and is refused the way they refuse it.
    target_cores = target_scope(
        [args.platform], args.target, args.platforms_dir
    )[0].get(args.platform)
    config = load_platform_config(args.platform, args.platforms_dir)
    relevant = resolve_platform_cores(config, profiles, target_cores=target_cores)
    run_anywhere = (
        set(resolve_platform_cores(config, profiles)) if args.target else relevant
    )
    return _PlatformScope(
        {k: v for k, v in profiles.items() if k in relevant},
        standalone_set(config),
        config,
        relevant,
        run_anywhere,
    )


@dataclass(frozen=True)
class _TreeScope:
    """What a run compares: the profiles, the platforms whose lists and
    launchers they are measured against (None for every platform), and the
    standalone layout of those platforms."""

    profiles: dict[str, dict]
    standalone_cores: set[str]
    selected: list[str] | None
    platform: _PlatformScope | None = None


def _target_platforms_scope(args: argparse.Namespace, profiles: dict[str, dict]) -> _TreeScope:
    """--target without --platform: every platform that has the target, each
    with the cores it builds for it, the way verify and generate_pack read
    --all --target. A target no platform has ends the run."""
    from model.targets import target_scope
    from resolve.cores import resolve_platform_cores
    from resolve.standalone import merged_standalone_set

    cache, kept = target_scope(
        list_registered_platforms(args.platforms_dir), args.target, args.platforms_dir,
        is_all=True,
    )
    configs = {name: load_platform_config(name, args.platforms_dir) for name in kept}
    relevant: set[str] = set()
    for name, config in configs.items():
        relevant |= set(resolve_platform_cores(config, profiles, target_cores=cache.get(name)))
    return _TreeScope(
        {k: v for k, v in profiles.items() if k in relevant},
        merged_standalone_set(configs.values()),
        kept,
    )


def _tree_scope(args: argparse.Namespace, profiles: dict[str, dict]) -> _TreeScope:
    """The scope --platform, --target or neither asks for."""
    if args.platform:
        scope = _platform_scope(args, profiles)
        return _TreeScope(scope.profiles, scope.standalone_cores, [args.platform], scope)
    if args.target:
        return _target_platforms_scope(args, profiles)
    # The tree as every platform runs it: a profile some platform runs
    # standalone keeps its standalone entries. Laid out as libretro only,
    # eka2l1, dolphin and xenia-edge lost 133 files no platform declares.
    from resolve.standalone import merged_standalone_set

    return _TreeScope(
        profiles,
        merged_standalone_set(
            load_platform_config(name, args.platforms_dir)
            for name in list_registered_platforms(args.platforms_dir)
        ),
        None,
    )


def _refuse_empty_scope(args: argparse.Namespace, emulator: str | None, tree: _TreeScope) -> None:
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


def _launcher_rows(
    args: argparse.Namespace,
    selected: list[str] | None,
    db: dict,
    all_profiles: dict[str, dict],
    registry: dict,
    emulator: str | None,
) -> tuple[list[dict], list[dict]]:
    """The names a launcher reads that the collection lacks, and the
    launcher records nothing proves."""
    # Counted apart from the profile gaps: a name only a launcher reads is
    # reported, not yet judged.
    launcher_reads = launcher_reads_not_held(
        {
            name: load_platform_config(name, args.platforms_dir)
            for name in (selected or list_registered_platforms(args.platforms_dir))
        },
        db, all_profiles, registry, emulator or "",
    )

    unproven = [
        row for row in launcher_unproven(
            {
                name: load_platform_config(name, args.platforms_dir)
                for name in (selected or list_registered_platforms(args.platforms_dir))
            },
            all_profiles,
        )
        if not emulator or any(
            emulator in LauncherLayer._profiles_named(part, all_profiles, set(all_profiles))
            for part in row["emulator"].split(", ")
        )
    ]
    return launcher_reads, unproven


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

    tree = _tree_scope(args, profiles)
    profiles = tree.profiles
    platform_scope = tree.platform
    if not profiles:
        _refuse_empty_scope(args, emulator, tree)
        return

    selected = tree.selected
    db = load_database(args.db)
    declared, global_scope = global_report_scope(
        platform_configs(args.platforms_dir, selected), db)
    global_scope["standalone_cores"] = tree.standalone_cores
    data_names = build_supplemental_index()
    report = cross_reference(
        profiles, declared, db, data_names, **global_scope,
        platform=(
            platform_scope.config.get("_key", args.platform) if platform_scope else ""
        ),
        # What the platform's launchers open, as verify and the builder read it.
        launcher_layer=LauncherLayer(
            platform_scope.config, profiles, platform_scope.relevant, db,
            declared_destinations(platform_scope.config),
        ) if platform_scope else None,
    )

    launcher_reads, unproven = _launcher_rows(
        args, selected, db, all_profiles, registry, emulator,
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
