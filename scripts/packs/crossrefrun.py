"""The profile gaps of one gap report scope, measured as verify and the builder measure them."""

from __future__ import annotations

from packs.crossref import (
    cross_reference,
    emulator_profiles,
    global_report_scope,
    platform_configs,
    whole_tree_gaps,
)
from packs.crossrefscope import TreeScope
from packs.supplemental import build_supplemental_index
from resolve.launchers import LauncherLayer, declared_destinations


def scope_gaps(
    tree: TreeScope, db: dict, platforms_dir: str, platform: str | None,
    all_profiles: dict[str, dict],
) -> dict:
    """Each profile of the scope with the files its platforms leave undeclared."""
    platform_scope = tree.platform
    configs = platform_configs(platforms_dir, tree.selected)
    data_names = build_supplemental_index()
    if platform_scope is None:
        return whole_tree_gaps(configs, db, all_profiles, data_names, tree.profiles)
    declared, global_scope = global_report_scope(configs, db, all_profiles)
    # The platform's own layout, its per-core directory markers kept.
    global_scope["standalone_cores"] = tree.standalone_cores
    return cross_reference(
        emulator_profiles(tree.profiles), declared, db, data_names, **global_scope,
        platform=platform_scope.config.get("_key", platform),
        # What the platform's launchers open, as verify and the builder read it.
        launcher_layer=LauncherLayer(
            platform_scope.config, tree.profiles, platform_scope.relevant, db,
            declared_destinations(platform_scope.config),
        ),
    )
