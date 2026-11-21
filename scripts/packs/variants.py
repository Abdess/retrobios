"""The source x required variants a run builds, and the truth pack nothing fills."""

from __future__ import annotations

import argparse
import sys

from model.platforms import load_platform_config
from resolve.cores import resolve_platform_cores

# The source x required combinations --all-variants builds, in build order.
ALL_VARIANTS: tuple[tuple[str, bool], ...] = (
    ("full", False), ("full", True),
    ("platform", False), ("platform", True),
    ("truth", False), ("truth", True),
)


def run_variants(args: argparse.Namespace) -> tuple[tuple[str, bool], ...]:
    """The variants a run builds: all six, or the one its flags name."""
    return ALL_VARIANTS if args.all_variants else ((args.source, args.required_only),)


def pack_label(source: str, required_only: bool) -> str:
    """The variant tag orchestrate.reports.parse_pack_counts reads after a pack name."""
    return f"[source={source}, required]" if required_only else f"[source={source}]"


def truth_layer_is_empty(
    platform: str, platforms_dir: str, emu_profiles: dict, target_cores: set[str] | None
) -> bool:
    """Whether a platform runs no core a profile describes.

    MiSTer declares `cores: []`: its truth pack held nothing, passed its
    check and was published under a name claiming a content.
    """
    config = load_platform_config(platform, platforms_dir)
    return not resolve_platform_cores(config, emu_profiles or {}, target_cores=target_cores)


def skip_empty_truth(
    args: argparse.Namespace,
    source: str,
    representative: str,
    emu_profiles: dict,
    tc: set[str] | None,
    failed: list[str],
) -> bool:
    """Leave out a truth pack that would be empty, refuse it when asked for."""
    if source != "truth" or not truth_layer_is_empty(
        representative, args.platforms_dir, emu_profiles, tc
    ):
        return False
    if args.all_variants:
        print(f"  {representative}: no core profile, no truth pack")
    else:
        print(
            f"ERROR: {representative} runs no core a profile describes; "
            "a truth pack would hold nothing",
            file=sys.stderr,
        )
        failed.append(representative)
    return True
