#!/usr/bin/env python3
"""Generate platform-specific BIOS ZIP packs.

Usage:
    python scripts/generate_pack.py --platform retroarch [--output-dir dist/]
    python scripts/generate_pack.py --all [--output-dir dist/]

Reads platform YAML config + database.json -> creates ZIP with correct
file layout for each platform. Handles inheritance, shared groups, variants,
and 3-tier storage (embedded/external/user_provided).
"""

from __future__ import annotations

import sys

# The README's first command. Under 3.8 it stopped on a SyntaxError that read
# like a damaged file. The build needs 3.9, as pipeline.py says.
if sys.version_info < (3, 9):
    sys.exit(f"generate_pack.py needs Python 3.9 or newer, this is {sys.version.split()[0]}")

import argparse
import contextlib
import os

sys.path.insert(0, os.path.dirname(__file__))
from core.artifacts import ArtifactLockBusy
from core.cli import add_emulator_selection, add_repo_inputs, require_directory
from core.ziptools import build_zip_contents_index
from model.cliargs import (
    LISTING_FLAGS,
    comma_list,
    mode_conflicts,
    platform_arg,
    refuse_beside_mode,
    requested_regions,
    require_platform,
    resolve_system_ids,
    run_listing,
)
from model.database import load_database
from model.registry import (
    list_registered_platforms,
    list_release_pack_platforms,
    load_data_dir_registry,
)
from packs.archive import DamagedArchiveError
from packs.datadirs import hold_data_dirs
from packs.datatrees import MISSING_DATA_DIRS
from packs.emulatorpack import generate_emulator_pack, generate_system_pack
from packs.md5pack import generate_md5_pack
from packs.outputdir import holds_other_kind, pack_output_lock
from packs.packcheck import run_verify_packs
from packs.platformrun import run_platform_mode
from packs.targets import generate_target_manifests
from resolve import packfiles as packresolve
from resolve.packfiles import (
    ACCEPTED_HASHES,
    lookup_hashes,
    parse_hash_file,
    parse_hash_input,
)

DEFAULT_OUTPUT_DIR = "dist"


def _refuse_for_verify_packs(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """What --verify-packs cannot be combined with, refused before any lock.

    These lived in the --all-variants checks, which return at once without
    that flag: --verify-packs --manifest or --split went through, and a run
    with neither --platform nor --all failed after locking the directory.
    """
    if not args.verify_packs:
        return
    if args.manifest:
        parser.error("--verify-packs is incompatible with --manifest")
    if not (args.platform or args.all):
        parser.error("--verify-packs requires --platform or --all")
    # The check that follows the build reads the full pack's name.
    for flag, given in (
        ("--system", args.system),
        ("--one-per-slot", args.one_per_slot),
        ("--split", args.split),
    ):
        if given:
            parser.error(f"{flag} is incompatible with --verify-packs")


def _argument_conflicts(args: argparse.Namespace) -> list[tuple[bool, str]]:
    """Each refused combination of arguments with its message, in the order
    they are checked: the first one that applies is the error reported."""
    has_platform = bool(args.platform)
    has_all = args.all
    has_emulator = bool(args.emulator)
    has_system = bool(args.system)
    md5_file = getattr(args, "from_md5_file", None)
    has_from_md5 = bool(args.from_md5 or md5_file)
    # A mode either applies a narrowing flag or refuses it. Swallowing one
    # answers about an artifact the caller did not ask for, and the name on
    # disk then asserts a narrowing the contents do not carry.
    # --source and --group-by default to None so a typed default value is
    # seen: compared with "full", `--emulator X --source full` went through.
    source_given = getattr(args, "source", None) is not None
    with_platform = has_system and (has_platform or has_all)
    no_game_data = getattr(args, "no_game_data", False)
    one_per_slot = getattr(args, "one_per_slot", False)
    return [
        (bool(args.from_md5 and md5_file), "--from-md5 and --from-md5-file are mutually exclusive"),
        (has_from_md5 and has_all, "--from-md5 requires --platform or --emulator, not --all"),
        (has_from_md5 and has_system, "--from-md5 and --system are mutually exclusive"),
        (has_from_md5 and args.split, "--split and --from-md5 are mutually exclusive"),
        *mode_conflicts(args, (("--from-md5", has_from_md5),)),
        (args.split and not (has_platform or has_all), "--split requires --platform or --all"),
        (args.split and has_emulator, "--split is incompatible with --emulator"),
        (args.group_by is not None and not args.split, "--group-by requires --split"),
        (args.manifest and not (has_platform or has_all),
         "--manifest requires --platform or --all"),
        (args.manifest and has_emulator, "--manifest is incompatible with --emulator"),
        (args.manifest and args.split, "--manifest is incompatible with --split"),
        (getattr(args, "region", None) and has_from_md5,
         "--region and --from-md5 are mutually exclusive"),
        (source_given and (has_emulator or (has_system and not has_platform)),
         "--source requires --platform or --all"),
        (has_from_md5 and args.manifest, "--manifest is incompatible with --from-md5"),
        (has_from_md5 and args.target, "--target is incompatible with --from-md5"),
        (has_from_md5 and args.required_only, "--required-only is incompatible with --from-md5"),
        (has_from_md5 and source_given, "--source is incompatible with --from-md5"),
        (with_platform and args.manifest, "--system is incompatible with --manifest"),
        (with_platform and args.split, "--system is incompatible with --split"),
        (no_game_data and has_from_md5, "--no-game-data is incompatible with --from-md5"),
        (one_per_slot and has_from_md5, "--one-per-slot and --from-md5 are mutually exclusive"),
        (one_per_slot and args.manifest, "--one-per-slot is incompatible with --manifest"),
        (one_per_slot and has_emulator, "--one-per-slot is incompatible with --emulator"),
        (one_per_slot and has_system, "--one-per-slot is incompatible with --system"),
    ]


def _validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Validate argument combinations and mutual exclusion rules."""
    _refuse_for_verify_packs(args, parser)
    for refused, message in _argument_conflicts(args):
        if refused:
            parser.error(message)


def _refuse_for_all_variants(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Flags --all-variants would override, or modes that never read it."""
    if not args.all_variants:
        return
    # It builds the six source x required combinations itself: a --source
    # or --required-only beside it would be overridden, and the modes that
    # build one pack (emulator, system, hashes) never read it.
    for flag, given in (
        ("--source", args.source is not None),
        ("--required-only", args.required_only),
        ("--no-game-data", getattr(args, "no_game_data", False)),
        ("--emulator", args.emulator),
        ("--from-md5", args.from_md5 or args.from_md5_file),
    ):
        if given:
            parser.error(f"{flag} is incompatible with --all-variants")
    if args.system and not (args.platform or args.all):
        parser.error("--all-variants requires --platform or --all")


def _refuse_refresh_data(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Only the platform pack path refreshes the data directories.

    Elsewhere the cache on disk was packed as it stood, and --offline wins
    over the refresh without a word.
    """
    if args.refresh_data and args.no_refresh_data:
        parser.error("--refresh-data is incompatible with --no-refresh-data")
    for name, given in (("--refresh-data", args.refresh_data),
                        ("--no-refresh-data", args.no_refresh_data)):
        if not given:
            continue
        for flag, on in (
            ("--offline", args.offline),
            ("--emulator", args.emulator),
            ("--system", args.system and not (args.platform or args.all)),
            ("--from-md5", args.from_md5 or args.from_md5_file),
        ):
            if on:
                parser.error(f"{name} is incompatible with {flag}")


def _refuse_unapplied_flags(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Refuse every flag the requested mode would not apply.

    A mode applies a narrowing flag or refuses it: a swallowed flag answers
    about an artifact the caller did not name. Run before any quick-exit
    mode, since --verify-packs and --manifest-targets return early.
    """
    # Parsed before the quick-exit modes: --verify-packs returns early and
    # still needs the region priority list to narrow its expectation.
    args.regions = requested_regions(args.region, parser)
    if args.region and args.manifest_targets:
        parser.error("--region is incompatible with --manifest-targets")
    if args.one_per_slot and args.manifest_targets:
        parser.error("--one-per-slot is incompatible with --manifest-targets")
    _refuse_refresh_data(args, parser)

    _refuse_for_all_variants(args, parser)
    refuse_beside_mode(
        (
            ("--manifest-targets", args.manifest_targets),
            ("--verify-packs", args.verify_packs and not args.all_variants),
            ("--list-platforms", args.list),
            ("--list-emulators", args.list_emulators),
            ("--list-systems", args.list_systems),
            ("--list-targets", args.list_targets),
        ),
        _given_flags(args), QUICK_MODE_FLAGS, parser,
    )


# What each mode that returns early reads. Anything else given beside it is
# refused: the mode would answer about an artifact the caller did not name.
QUICK_MODE_FLAGS: dict[str, set[str]] = {
    # Checks packs already on disk against the platform's own list, narrowed
    # by region and target and by nothing else.
    "--verify-packs": {
        "--platform", "--all", "--target", "--region", "--no-game-data",
    },
    # One manifest per hardware target, from the target files themselves.
    "--manifest-targets": set(),
    **LISTING_FLAGS,
}


def _given_flags(args: argparse.Namespace) -> set[str]:
    """Flags that select or narrow what a run produces, as typed."""
    flags = {
        "--platform": args.platform,
        "--all": args.all,
        "--emulator": args.emulator,
        "--system": args.system,
        "--standalone": args.standalone,
        "--split": args.split,
        "--group-by": args.group_by is not None,
        "--manifest": args.manifest,
        "--manifest-targets": args.manifest_targets,
        "--verify-packs": args.verify_packs,
        "--all-variants": args.all_variants,
        "--from-md5": args.from_md5,
        "--from-md5-file": args.from_md5_file,
        "--required-only": args.required_only,
        "--no-game-data": getattr(args, "no_game_data", False),
        "--source": args.source is not None,
        "--target": args.target,
        "--region": args.region,
        "--one-per-slot": args.one_per_slot,
        "--list-platforms": args.list,
        "--list-emulators": args.list_emulators,
        "--list-systems": args.list_systems,
        "--list-targets": args.list_targets,
        "--refresh-data": args.refresh_data,
        "--no-refresh-data": args.no_refresh_data,
    }
    return {flag for flag, on in flags.items() if on}


def main() -> None:
    # One run's account: tests call main() repeatedly in one process, and a
    # notice left by an earlier run failed a later one that missed nothing.
    MISSING_DATA_DIRS.clear()
    with contextlib.ExitStack() as held:
        try:
            _main(held)
        except (DamagedArchiveError, ArtifactLockBusy) as exc:
            # Emulator, system and hash modes have no per-platform loop to
            # report a damaged archive: the run stops with the file to
            # restore. A busy output directory refuses the run.
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(1)
    if MISSING_DATA_DIRS:
        print(
            "ERROR: packs written without data directories that are not cached: "
            f"{', '.join(sorted(MISSING_DATA_DIRS))} (run refresh_data_dirs.py)",
            file=sys.stderr,
        )
        sys.exit(1)


def _build_parser() -> argparse.ArgumentParser:
    """The command line of generate_pack.py."""
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Generate platform BIOS ZIP packs")
    parser.add_argument(
        "--platform", "-p", type=platform_arg,
        help="Platform name (e.g., retroarch)",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Generate the release packs (release_pack in the registry), or with"
        " --manifest the install manifests of every platform",
    )
    add_emulator_selection(parser)
    add_repo_inputs(parser, "platforms", "db", "bios")
    parser.add_argument(
        "--output-dir", "-o", default=DEFAULT_OUTPUT_DIR,
        help="directory the packs and manifests go to (default: %(default)s)",
    )
    add_repo_inputs(parser, "emulators")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="No network at all: data directories and release assets come "
        "from the cache only, so a gitignored file never fetched is missing "
        "(--no-refresh-data keeps the trees as cached and still fetches assets)",
    )
    parser.add_argument(
        "--refresh-data",
        action="store_true",
        help="Force re-download all data directories",
    )
    parser.add_argument(
        "--no-refresh-data",
        action="store_true",
        help="Pack the data directories as cached, still fetching release assets",
    )
    # install.py's name. --list stays for the scripts that already type it.
    parser.add_argument(
        "--list-platforms", "--list", dest="list", action="store_true",
        help="List available platforms",
    )
    parser.add_argument(
        "--required-only",
        action="store_true",
        help="Only include required files, skip optional",
    )
    parser.add_argument(
        "--no-game-data",
        action="store_true",
        help="Leave out game data (the platform's entries a core reads as a "
        "game's files, and the cores' game data files): firmware only",
    )
    parser.add_argument(
        "--source",
        choices=["platform", "truth", "full"],
        default=None,
        help="File source: platform (YAML only), truth (emulator profiles), full "
             "(both, the default)",
    )
    parser.add_argument(
        "--all-variants",
        action="store_true",
        help="Generate all 6 source x required combinations",
    )
    parser.add_argument(
        "--split", action="store_true", help="Generate one ZIP per system/manufacturer"
    )
    parser.add_argument(
        "--group-by",
        choices=["system", "manufacturer"],
        default=None,
        help="Grouping for --split (default: system)",
    )
    parser.add_argument("--target", "-t", help="Hardware target (e.g., switch, rpi4)")
    parser.add_argument(
        "--region",
        help="Region priority list, best first (e.g. us,eu,jp)",
    )
    parser.add_argument(
        "--one-per-slot",
        action="store_true",
        help="Keep one BIOS per system and region where the core declares an order",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="List available targets for the platform",
    )
    parser.add_argument(
        "--from-md5",
        help="Hash(es) to look up or pack, comma-separated: CRC32, MD5, SHA-1 or SHA-256",
    )
    parser.add_argument(
        "--from-md5-file",
        help="File with hashes, one per line, alone or beside a file name as md5sum writes it",
    )
    parser.add_argument(
        "--manifest",
        action="store_true",
        help="Output JSON manifests instead of ZIP packs",
    )
    parser.add_argument(
        "--manifest-targets",
        action="store_true",
        help="Convert target YAMLs to installer JSON",
    )
    parser.add_argument(
        "--verify-packs",
        action="store_true",
        help="Extract and verify pack integrity (path + hash)",
    )
    return parser


def _run_quick_mode(
    args: argparse.Namespace, parser: argparse.ArgumentParser, held: contextlib.ExitStack,
) -> bool:
    """Run a mode that builds nothing (a check of existing packs, the target
    lists, a listing). True when one ran."""
    # Quick-exit modes: --verify-packs alone = verify existing packs only
    # Combined with --all-variants, generation runs first then verify
    if args.verify_packs and not args.all_variants:
        # The check resolves core files against data/ like the build did,
        # and a refresh swapping a tree mid-check would judge another tree.
        hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))
        with pack_output_lock(args.output_dir, exclusive=False):
            if not run_verify_packs(args):
                sys.exit(1)
        return True
    if args.manifest_targets:
        if holds_other_kind(args.output_dir, "targets"):
            sys.exit(1)
        with pack_output_lock(args.output_dir):
            generate_target_manifests(
                os.path.join(args.platforms_dir, "targets"), args.output_dir
            )
        return True
    return run_listing(args, parser, args.list)


def _run_hash_mode(args: argparse.Namespace) -> None:
    """--from-md5 and --from-md5-file: look the hashes up, or pack them."""
    try:
        hashes = (
            parse_hash_input(args.from_md5)
            if args.from_md5
            else parse_hash_file(args.from_md5_file)
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"ERROR: --from-md5-file {args.from_md5_file}: {exc.strerror}", file=sys.stderr)
        sys.exit(1)
    if not hashes:
        print(
            f"ERROR: no hash in the input. Accepted: {ACCEPTED_HASHES}",
            file=sys.stderr,
        )
        sys.exit(1)
    db = load_database(args.db)
    if not args.platform and not args.emulator:
        # A lookup that found nothing is an answer a script must see.
        if lookup_hashes(
            hashes, db, args.bios_dir, args.emulators_dir, args.platforms_dir
        ):
            sys.exit(1)
        return
    zip_contents = build_zip_contents_index(db)
    with pack_output_lock(args.output_dir):
        result = generate_md5_pack(
            hashes=hashes,
            db=db,
            bios_dir=args.bios_dir,
            output_dir=args.output_dir,
            zip_contents=zip_contents,
            platform_name=args.platform,
            platforms_dir=args.platforms_dir,
            emulator_name=args.emulator,
            emulators_dir=args.emulators_dir,
            standalone=getattr(args, "standalone", False),
        )
    if not result:
        sys.exit(1)


def _run_profile_mode(args: argparse.Namespace, db: dict, zip_contents: dict) -> None:
    """--emulator, or --system without a platform: the emulators' own layout."""
    # Emulator mode
    if args.emulator:
        names = comma_list(args.emulator)
        with pack_output_lock(args.output_dir):
            built = generate_emulator_pack(
                names,
                args.emulators_dir,
                db,
                args.bios_dir,
                args.output_dir,
                args.standalone,
                zip_contents=zip_contents,
                required_only=args.required_only,
                regions=getattr(args, "regions", None),
                offline=args.offline,
                platforms_dir=args.platforms_dir,
            )
        if built is None:
            sys.exit(1)
        return

    # System mode (standalone, without platform context)
    system_ids = comma_list(args.system)
    with pack_output_lock(args.output_dir):
        built = generate_system_pack(
            system_ids,
            args.emulators_dir,
            db,
            args.bios_dir,
            args.output_dir,
            args.standalone,
            zip_contents=zip_contents,
            required_only=args.required_only,
            regions=getattr(args, "regions", None),
            offline=args.offline,
            platforms_dir=args.platforms_dir,
        )
    if built is None:
        sys.exit(1)


def _requested_platforms(args: argparse.Namespace, parser: argparse.ArgumentParser) -> list[str]:
    """The platforms a platform run builds for."""
    if args.all and args.manifest:
        # Install manifests cover every registered platform: the installer
        # serves each one, with or without a release pack.
        return list_registered_platforms(args.platforms_dir)
    if args.all:
        # A release publishes the packs the registry marks release_pack and
        # nothing else: a pack built for another platform is one nobody uploads.
        platforms = list_release_pack_platforms(args.platforms_dir)
        if not platforms:
            parser.error("no registered platform has release_pack: true")
        return platforms
    if not args.platform:
        parser.error("Specify --platform or --all")
    return [args.platform]


def _main(held: contextlib.ExitStack) -> None:
    parser = _build_parser()
    args = parser.parse_args()
    from model.cliargs import work_from_repo_root

    work_from_repo_root(
        args, parser,
        ["db", "platforms_dir", "bios_dir", "output_dir", "emulators_dir", "from_md5_file"],
    )
    packresolve.set_offline(bool(args.offline))
    if args.platform:
        require_platform(args.platform, args.platforms_dir)
    require_directory(args.bios_dir)

    _refuse_unapplied_flags(args, parser)
    _refuse_for_verify_packs(args, parser)
    if _run_quick_mode(args, parser, held):
        return

    _validate_args(args, parser)
    args.system_ids = resolve_system_ids(args, parser)
    # Unset until every refusal has run, so a typed default value is seen.
    args.source = args.source or "full"
    args.group_by = args.group_by or "system"

    # Hash lookup / pack mode
    # A platform run may refresh the trees below, under the exclusive lock:
    # it takes the shared ones after that. Every other mode reads them now.
    if not (args.platform or args.all) or args.offline or args.no_refresh_data:
        hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))
    if args.from_md5 or getattr(args, "from_md5_file", None):
        _run_hash_mode(args)
        return

    db = load_database(args.db)
    zip_contents = build_zip_contents_index(db)
    if args.emulator or (args.system and not args.platform and not args.all):
        _run_profile_mode(args, db, zip_contents)
        return
    if not run_platform_mode(args, _requested_platforms(args, parser), held, db, zip_contents):
        sys.exit(1)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
