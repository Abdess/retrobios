"""What the step 5 comparisons share: the inputs they read, the members set aside, the difference lines."""

from __future__ import annotations

import os

from core.paths import EMULATORS_DIR
from model.registry import load_data_dir_registry


def tree_members(
    platform: str, platforms_dir: str, emulators_dir: str = EMULATORS_DIR,
) -> dict[str, int]:
    """Archive path -> size of every file the platform's data trees can add."""
    from packs import datatrees
    from model.profiles import load_emulator_profiles
    from model.platforms import load_platform_config
    from packs.archive import Placed
    from packs.paths import flat_arcname

    config = load_platform_config(platform, platforms_dir)
    base_dest = config.get("base_destination", "")
    registry = load_data_dir_registry(platforms_dir)
    core_trees = datatrees.core_data_trees(
        config, load_emulator_profiles(emulators_dir), platform, registry,
    )
    members: dict[str, int] = {}
    for src, full in datatrees.data_directory_members(
        config.get("systems", {}), registry,
        platform, base_dest, Placed(False),
        core_trees=core_trees,
    ):
        members[flat_arcname(full, base_dest, True)] = os.path.getsize(src)
    return members


def set_difference_lines(label: str, credited: set[str], written: set[str]) -> list[str]:
    """The paths one side has and the other lacks, ten of each at most."""
    lines = []
    for side, paths in (("verify only", credited - written), ("pack only", written - credited)):
        if paths:
            shown = ", ".join(sorted(paths)[:10])
            more = f" (+{len(paths) - 10})" if len(paths) > 10 else ""
            lines.append(f"  {label}: {side} {len(paths)}: {shown}{more}")
    return lines


def comparison_inputs(
    db_path: str, emulators_dir: str, platforms_dir: str,
) -> tuple[dict, dict, dict, dict, list[tuple[list[str], str]]]:
    """What the in-memory pack comparisons read: the database, its ZIP
    index, the profiles, the data-directory registry and the platform groups."""
    from core.ziptools import build_zip_contents_index
    from resolve.grouping import group_identical_platforms
    from model.registry import list_registered_platforms
    from model.database import load_database
    from model.profiles import load_emulator_profiles

    db = load_database(db_path)
    groups = group_identical_platforms(list_registered_platforms(platforms_dir), platforms_dir)
    return (db, build_zip_contents_index(db), load_emulator_profiles(emulators_dir),
            load_data_dir_registry(platforms_dir), groups)
