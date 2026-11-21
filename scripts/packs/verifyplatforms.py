"""Verify the platforms a run selects, one result per group of identical platforms."""

from __future__ import annotations

from dataclasses import dataclass, field

from model.platforms import load_platform_config
from model.profiles import load_emulator_profiles
from model.registry import load_data_dir_registry
from model.targets import canonical_target_name, target_scope
from packs.coverage import verify_platform
from resolve.contentlayout import TARGET_KEY
from resolve.cores import platforms_with_systems, without_profile_blind
from resolve.grouping import group_identical_platforms


@dataclass(frozen=True)
class PlatformRun:
    """What a platform-mode run asks of each platform it verifies."""

    platforms_dir: str
    emulators_dir: str
    target: str | None = None
    is_all: bool = False
    regions: list[str] = field(default_factory=list)
    system_filter: list[str] | None = None
    no_game_data: bool = False
    required_only: bool = False


@dataclass
class PlatformResults:
    """The groups verified, each result with its platform names, and each platform's result."""

    groups: list[tuple[list[str], str]]
    group_results: list[tuple[dict, list[str]]]
    all_results: dict[str, dict]


def run_target_scope(
    run: PlatformRun, platforms: list[str], emu_profiles: dict,
) -> tuple[dict[str, set[str] | None], list[str]]:
    """The cores of each platform on --target, and the platforms that have
    it and a system of the --system list. A system the target leaves no
    core for was reported 0/0 with exit 0, where generate_pack refuses the
    same request."""
    target_cores_cache, platforms = target_scope(
        platforms, run.target, run.platforms_dir, is_all=run.is_all
    )
    if run.system_filter:
        platforms = platforms_with_systems(
            platforms, run.system_filter, emu_profiles, target_cores_cache,
            run.platforms_dir, run.target, run.is_all,
        )
    return target_cores_cache, platforms


def verify_platforms(platforms: list[str], db: dict, run: PlatformRun) -> PlatformResults:
    """Each group of identical platforms verified once, as generate_pack builds it."""
    # Load emulator profiles once for cross-reference (not per-platform)
    emu_profiles = load_emulator_profiles(run.emulators_dir)
    data_registry = load_data_dir_registry(run.platforms_dir)

    target_cores_cache, platforms = run_target_scope(run, platforms, emu_profiles)

    # generate_pack refuses these on a platform whose cores no profile
    # describes, and the report answers the same request the same way.
    platforms = without_profile_blind(
        platforms,
        [
            flag for flag, given in (
                ("--region", run.regions),
                ("--no-game-data", run.no_game_data),
            ) if given
        ],
        run.platforms_dir,
        emu_profiles,
        target_cores_cache if run.target else None,
        run.is_all,
    )

    # Group identical platforms (same function as generate_pack)
    groups = group_identical_platforms(
        platforms, run.platforms_dir, target_cores_cache if run.target else None
    )

    all_results = {}
    group_results: list[tuple[dict, list[str]]] = []
    for group_platforms, representative in groups:
        config = load_platform_config(representative, run.platforms_dir)
        tc = target_cores_cache.get(representative) if run.target else None
        if tc is not None:
            # A core a roms folder offers on other boards only is not placed
            # there, as generate_pack builds the board's pack.
            config = {**config, TARGET_KEY: canonical_target_name(
                [representative], run.target, run.platforms_dir)}
        result = verify_platform(
            config,
            db,
            run.emulators_dir,
            emu_profiles,
            target_cores=tc,
            data_dir_registry=data_registry,
            regions=run.regions,
            system_filter=run.system_filter,
            no_game_data=run.no_game_data,
            required_only=run.required_only,
        )
        names = [
            load_platform_config(p, run.platforms_dir).get("platform", p)
            for p in group_platforms
        ]
        group_results.append((result, names))
        for p in group_platforms:
            all_results[p] = result
    return PlatformResults(groups, group_results, all_results)
