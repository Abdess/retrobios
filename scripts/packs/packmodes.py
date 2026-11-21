"""Run modes of generate_pack.py: checks, listings, hash and profile packs, platform runs."""

from __future__ import annotations

import argparse
import contextlib
import os
import sys

from core.cli import require_directory
from core.ziptools import build_zip_contents_index
from model.cliargs import (
    comma_list,
    require_platform,
    resolve_system_ids,
    run_listing,
    work_from_repo_root,
)
from model.database import load_database
from model.registry import load_data_dir_registry
from packs.datadirs import hold_data_dirs
from packs.emulatorpack import (
    EmulatorPackOutcome,
    build_emulator_pack,
    build_system_pack,
    print_emulator_pack,
)
from packs.md5pack import generate_md5_pack
from packs.outputdir import holds_other_kind, pack_output_lock
from packs.packcheck import run_verify_packs
from packs.packoptions import refuse_for_verify_packs, refuse_unapplied_flags, validate_args
from packs.platformrun import requested_platforms, run_platform_mode
from packs.targets import generate_target_manifests
from resolve import packfiles as packresolve
from resolve.packfiles import (
    ACCEPTED_HASHES,
    lookup_hashes,
    parse_hash_file,
    parse_hash_input,
)


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
            outcome = build_emulator_pack(
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
                progress=print,
            )
        _account(outcome, args.uncached_trees)
        return

    # System mode (standalone, without platform context)
    system_ids = comma_list(args.system)
    with pack_output_lock(args.output_dir):
        outcome = build_system_pack(
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
            progress=print,
        )
    _account(outcome, args.uncached_trees)


def _account(outcome: EmulatorPackOutcome, uncached: set[str]) -> None:
    """Print a profile pack, add its data directory notices to the run, stop on failure."""
    built = print_emulator_pack(outcome)
    uncached.update(outcome.data_dir_notices)
    if built is None:
        sys.exit(1)


def run_pack_command(
    parser: argparse.ArgumentParser, held: contextlib.ExitStack,
) -> argparse.Namespace:
    """One run of generate_pack.py, from its command line to the mode it names.

    Returns its arguments, with ``uncached_trees``: the data directories the
    run's packs or manifests carry and the cache does not hold.
    """
    args = parser.parse_args()
    args.uncached_trees = set()
    work_from_repo_root(
        args, parser,
        ["db", "platforms_dir", "bios_dir", "output_dir", "emulators_dir", "from_md5_file"],
    )
    packresolve.set_offline(bool(args.offline))
    if args.platform:
        require_platform(args.platform, args.platforms_dir)
    require_directory(args.bios_dir)

    refuse_unapplied_flags(args, parser)
    refuse_for_verify_packs(args, parser)
    if _run_quick_mode(args, parser, held):
        return args

    validate_args(args, parser)
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
        return args

    db = load_database(args.db)
    zip_contents = build_zip_contents_index(db)
    if args.emulator or (args.system and not args.platform and not args.all):
        _run_profile_mode(args, db, zip_contents)
        return args
    if not run_platform_mode(args, requested_platforms(args, parser), held, db, zip_contents):
        sys.exit(1)
    return args
