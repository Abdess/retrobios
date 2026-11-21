"""Option checks of generate_pack.py: the combinations each mode refuses."""

from __future__ import annotations

import argparse

from model.cliargs import (
    LISTING_FLAGS,
    mode_conflicts,
    refuse_beside_mode,
    requested_regions,
)


def refuse_for_verify_packs(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
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
        *_counts_conflicts(args, has_platform or has_all, has_system or has_from_md5),
    ]


def _counts_conflicts(
    args: argparse.Namespace, platform_run: bool, narrowed: bool,
) -> list[tuple[bool, str]]:
    """--counts describes the full platform packs: another mode refuses it."""
    counts = bool(getattr(args, "counts", None))
    return [
        (counts and not platform_run, "--counts requires --platform or --all"),
        (counts and args.manifest, "--counts is incompatible with --manifest"),
        (counts and args.split, "--counts is incompatible with --split"),
        (counts and narrowed,
         "--counts describes the full pack and is incompatible with --system and --from-md5"),
    ]


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Validate argument combinations and mutual exclusion rules. The
    --verify-packs refusals ran before the quick-exit modes."""
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


def refuse_unapplied_flags(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
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
        "--counts": getattr(args, "counts", None),
        "--refresh-data": args.refresh_data,
        "--no-refresh-data": args.no_refresh_data,
    }
    return {flag for flag, on in flags.items() if on}
