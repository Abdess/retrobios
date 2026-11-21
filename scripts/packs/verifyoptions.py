"""The verify options a mode reads, and the ones it refuses beside it."""

from __future__ import annotations

import argparse

from model.cliargs import LISTING_FLAGS, mode_conflicts, refuse_beside_mode


def refuse_listing_narrowings(
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


def refuse_mode_flags(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
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


def check_mode(args: argparse.Namespace, parser: argparse.ArgumentParser) -> bool:
    """Refuse a request naming no mode or several, and say if it is the system mode."""
    refuse_mode_flags(args, parser)
    return bool(args.system) and not (args.platform or args.all)
