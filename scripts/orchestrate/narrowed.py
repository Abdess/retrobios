"""Step 5 on the narrowed platform packs, built in memory and compared with verify."""

from __future__ import annotations

import contextlib
import io

from core.paths import DB_FILE, EMULATORS_DIR, PLATFORMS_DIR
from orchestrate.compare import comparison_inputs, set_difference_lines
from orchestrate.labels import STEP_LABELS, step_title
from packs.archive import is_pack_note

# How each pack_narrowings() dimension of a platform pack is compared by
# check_narrowed_packs, or why it is not. A test reads the builder's
# signature against these two tables, so a new narrowing fails it until it
# is compared or a reason is written here. Emulator packs have their own
# table, EMULATOR_NARROWINGS_COMPARED.
NARROWINGS_COMPARED = frozenset({"regions", "target_name", "required_only", "no_game_data"})
NARROWINGS_NOT_COMPARED = {
    "standalone": "an emulator pack mode, compared by check_emulator_packs",
    "source": "verify has no platform-only or truth-only report to compare with",
    "one_per_slot": "verify has no slot choice to compare with",
}


def matrix_coverage(full: bool, count: int) -> range | list[int]:
    """Which of *count* variants of one dimension a run compares.

    The full matrix takes every one. The default takes the first, the last
    and one in between, which reaches each code path the dimension takes
    (an empty selection, a single system, a large one) without its cost.
    """
    if full or count <= 3:
        return range(count)
    return sorted({0, count // 2, count - 1})


def narrowed_variants(
    platform: str, config: dict, profiles: dict, platforms_dir: str, full: bool,
) -> list[tuple[str, dict]]:
    """(label, builder arguments) of each narrowed pack compared for a platform.

    Every region a file of the platform's cores declares, every hardware
    target, every system, --no-game-data and --required-only. Without
    *full*, regions, targets and systems are sampled (matrix_coverage).
    """
    from resolve import regions as resolve_regions
    from model.targets import list_available_targets

    regions = sorted({
        r for entry in resolve_regions.platform_region_index(config, profiles).values()
        for r in entry["regions"]
    })
    targets = [t["name"] for t in list_available_targets(platform, platforms_dir)]
    systems = sorted(config.get("systems") or {})
    variants: list[tuple[str, dict]] = [
        ("--required-only", {"required_only": True}),
        ("--no-game-data", {"no_game_data": True}),
    ]
    variants += [
        (f"--region {regions[i]}", {"regions": [regions[i]]})
        for i in matrix_coverage(full, len(regions))
    ]
    variants += [
        (f"--target {targets[i]}", {"target_name": targets[i]})
        for i in matrix_coverage(full, len(targets))
    ]
    variants += [
        (f"--system {systems[i]}", {"system_filter": [systems[i]]})
        for i in matrix_coverage(full, len(systems))
    ]
    return variants


def check_narrowed_packs(
    emulators_dir: str = EMULATORS_DIR, platforms_dir: str = PLATFORMS_DIR,
    db_path: str = DB_FILE, full: bool = False,
) -> bool:
    """Build each narrowed platform pack in memory and compare it with verify.

    The paths the pack writes against the ones verify credits for the same
    narrowing, as check_pack_destinations compares the full packs. Both sides
    run offline: a release asset the cache lacks is missing on each.

    Coverage: --required-only and --no-game-data for every platform, and
    --region, --target and --system. Measured on 2026-11-05, the full matrix
    is 1,150 packs and took 25 minutes, one to two seconds a pack, most
    of it platform-wide work (slot overrides, the gap report) that each build
    redoes. A run therefore takes the first, middle and last region, target
    and system of each platform, 155 packs in about 3 minutes: each value of
    a dimension runs the same code, so three reach every path a narrowing
    takes (the empty end, one system, a large one). *full* (--full-narrowings)
    compares every value. NARROWINGS_NOT_COMPARED says why --source and
    --one-per-slot are not compared.
    """
    from packs import archive
    from packs import platformpack
    from resolve import packfiles as packresolve
    from packs import coverage
    from model.platforms import load_platform_config
    from model.targets import load_target_config

    print(f"\n--- {step_title(STEP_LABELS['consistency'])}, narrowed packs ---")
    db, zip_contents, profiles, registry, groups = comparison_inputs(
        db_path, emulators_dir, platforms_dir
    )
    all_ok = True
    compared = 0
    with packresolve.offline():
        for _members, platform in groups:
            config = load_platform_config(platform, platforms_dir)
            for label, narrowing in narrowed_variants(
                platform, config, profiles, platforms_dir, full,
            ):
                target = narrowing.get("target_name")
                target_cores = (
                    load_target_config(platform, target, platforms_dir) if target else None
                )
                record = archive.PackRecord()
                with contextlib.redirect_stderr(io.StringIO()):
                    built = platformpack.build_platform_pack(
                        platform, platforms_dir, db, "bios", "",
                        emulators_dir=emulators_dir, zip_contents=zip_contents,
                        data_registry=registry, emu_profiles=profiles,
                        target_cores=target_cores, offline=True, record=record,
                        **narrowing,
                    )
                    report = coverage.verify_platform(
                        load_platform_config(platform, platforms_dir), db,
                        emulators_dir, profiles, target_cores=target_cores,
                        data_dir_registry=registry,
                        **{k: v for k, v in narrowing.items() if k != "target_name"},
                    ) if built.zip_path else None
                compared += 1
                name = f"{platform} {label}"
                if report is None:
                    # The builder declines a system no core of the platform runs.
                    print(f"  {name}: the builder wrote no pack: {built.refusal}")
                    all_ok = False
                    continue
                credited = set(report["pack_destinations"])
                trees = set(record.trees) - credited
                written = {
                    m for m in record.members
                    if not is_pack_note(m) and m not in trees
                }
                lines = set_difference_lines(name, credited, written)
                if lines:
                    print("\n".join(lines))
                    all_ok = False
    scope = "full matrix" if full else "sampled"
    print(f"  {compared} narrowed platform packs compared ({scope}), "
          f"{'all equal' if all_ok else 'differences above'}")
    return all_ok
