"""Contested and doubly declared destinations, platform by platform."""

from __future__ import annotations

from core.paths import PLATFORMS_DIR
from core.ziptools import build_zip_contents_index
from model.platforms import load_platform_config
from model.registry import load_data_dir_registry
from packs.slots import Conflict, find_conflicts
from resolve.collisions import Collision, find_collisions
from resolve.cores import resolve_platform_cores
from resolve.standalone import standalone_set as platform_standalone_set


def scan_platform(
    platform: str, profiles: dict, db: dict, platforms_dir: str = PLATFORMS_DIR,
    target_cores: set[str] | None = None, zip_index: dict | None = None,
    data_registry: dict | None = None,
) -> list[Conflict]:
    """Conflicts on one platform, using the cores that platform actually runs."""
    config = load_platform_config(platform, platforms_dir)
    keys = resolve_platform_cores(config, profiles, target_cores=target_cores)
    relevant = {k: profiles[k] for k in keys if k in profiles}
    # The same evidence the builder and the verifier resolve with: without
    # the ZIP index and the data-directory registry the arbitration judged
    # with less than the tools that read its verdict.
    return find_conflicts(
        config,
        relevant,
        db,
        config.get("base_destination", ""),
        platform_standalone_set(config),
        build_zip_contents_index(db) if zip_index is None else zip_index,
        load_data_dir_registry(platforms_dir) if data_registry is None else data_registry,
    )


def scan_platforms(
    names: list[str], profiles: dict, db: dict, platforms_dir: str,
    target_cores: dict[str, set[str] | None], data_registry: dict,
) -> tuple[dict[str, list[Conflict]], dict[str, list[Collision]]]:
    """The platforms with a contested destination, and those declaring one twice."""
    zip_index = build_zip_contents_index(db)
    found: dict[str, list[Conflict]] = {}
    collided: dict[str, list[Collision]] = {}
    for name in names:
        conflicts = scan_platform(
            name, profiles, db, platforms_dir, target_cores.get(name),
            zip_index, data_registry,
        )
        if conflicts:
            found[name] = conflicts
        collisions = find_collisions(
            load_platform_config(name, platforms_dir),
            db,
            zip_index,
            data_registry,
        )
        if collisions:
            collided[name] = collisions
    return found, collided
