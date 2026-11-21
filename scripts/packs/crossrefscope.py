"""The profiles a gap report compares and the platforms it measures them against."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass

from model.platforms import load_platform_config
from model.registry import list_registered_platforms
from model.targets import target_scope
from resolve.cores import resolve_platform_cores
from resolve.standalone import merged_standalone_set, standalone_set


@dataclass(frozen=True)
class PlatformScope:
    """The profiles a --platform run compares, and how the platform runs them."""

    profiles: dict[str, dict]
    standalone_cores: set[str]
    config: dict
    relevant: set[str]
    run_anywhere: set[str]


def platform_scope(
    platform: str, target: str | None, platforms_dir: str, profiles: dict[str, dict],
) -> PlatformScope:
    """The scope of a --platform run, narrowed to its --target cores."""
    # A typo ended in a traceback where verify and slots name the closest
    # target, and is refused the way they refuse it.
    target_cores = target_scope(
        [platform], target, platforms_dir
    )[0].get(platform)
    config = load_platform_config(platform, platforms_dir)
    relevant = resolve_platform_cores(config, profiles, target_cores=target_cores)
    run_anywhere = (
        set(resolve_platform_cores(config, profiles)) if target else relevant
    )
    return PlatformScope(
        {k: v for k, v in profiles.items() if k in relevant},
        standalone_set(config),
        config,
        relevant,
        run_anywhere,
    )


@dataclass(frozen=True)
class TreeScope:
    """What a run compares: the profiles, the platforms whose lists and
    launchers they are measured against (None for every platform), and the
    standalone layout of those platforms."""

    profiles: dict[str, dict]
    standalone_cores: set[str]
    selected: list[str] | None
    platform: PlatformScope | None = None


def target_platforms_scope(
    target: str, platforms_dir: str, profiles: dict[str, dict],
) -> TreeScope:
    """--target without --platform: every platform that has the target, each
    with the cores it builds for it, the way verify and generate_pack read
    --all --target. A target no platform has ends the run."""
    cache, kept = target_scope(
        list_registered_platforms(platforms_dir), target, platforms_dir,
        is_all=True,
    )
    configs = {name: load_platform_config(name, platforms_dir) for name in kept}
    relevant: set[str] = set()
    for name, config in configs.items():
        relevant |= set(resolve_platform_cores(config, profiles, target_cores=cache.get(name)))
    return TreeScope(
        {k: v for k, v in profiles.items() if k in relevant},
        merged_standalone_set(configs.values()),
        kept,
    )


def tree_scope(
    platform: str | None, target: str | None, platforms_dir: str, profiles: dict[str, dict],
) -> TreeScope:
    """The scope --platform, --target or neither asks for."""
    if platform:
        scope = platform_scope(platform, target, platforms_dir, profiles)
        return TreeScope(scope.profiles, scope.standalone_cores, [platform], scope)
    if target:
        return target_platforms_scope(target, platforms_dir, profiles)
    # The tree as every platform runs it: a profile some platform runs
    # standalone keeps its standalone entries. Laid out as libretro only,
    # eka2l1, dolphin and xenia-edge lost 133 files no platform declares.
    return TreeScope(
        profiles,
        merged_standalone_set(
            load_platform_config(name, platforms_dir)
            for name in list_registered_platforms(platforms_dir)
        ),
        None,
    )


def refuse_empty_scope(args: argparse.Namespace, emulator: str | None, tree: TreeScope) -> None:
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
