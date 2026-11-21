"""The profile gaps of one gap report scope, measured as verify and the builder measure them."""

from __future__ import annotations

from packs.crossref import (
    build_supplemental_index,
    cross_reference,
    global_report_scope,
    platform_configs,
)
from packs.crossrefscope import TreeScope
from resolve.launchers import LauncherLayer, declared_destinations


def scope_gaps(
    tree: TreeScope, db: dict, platforms_dir: str, platform: str | None,
    all_profiles: dict[str, dict],
) -> dict:
    """Each profile of the scope with the files its platforms leave undeclared."""
    platform_scope = tree.platform
    declared, global_scope = global_report_scope(
        platform_configs(platforms_dir, tree.selected), db, all_profiles)
    global_scope["standalone_cores"] = tree.standalone_cores
    data_names = build_supplemental_index()
    return cross_reference(
        tree.profiles, declared, db, data_names, **global_scope,
        platform=(
            platform_scope.config.get("_key", platform) if platform_scope else ""
        ),
        # What the platform's launchers open, as verify and the builder read it.
        launcher_layer=LauncherLayer(
            platform_scope.config, tree.profiles, platform_scope.relevant, db,
            declared_destinations(platform_scope.config),
        ) if platform_scope else None,
    )
