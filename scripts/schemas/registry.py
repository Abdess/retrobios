"""platforms/_registry.yml: its schema, the release packs and the save directory blocks."""

from __future__ import annotations

import core.paths
from core.paths import PLATFORMS_DIR
from model.platforms import load_platform_config
from model.registry import load_platform_registry
from model.safeparse import yaml_load
from schemas.validators import schema_errors, schema_validator


def registry_contract() -> list[str]:
    """The registry against its schema, and a release that still ships a pack.

    `release_pack` is the only list of the ZIPs a release publishes: a
    registry where no platform carries it would cut a release with no pack
    at all, and every download link would lead to the command.
    """
    registry_path = core.paths.REPO_ROOT / PLATFORMS_DIR / "_registry.yml"
    if not registry_path.is_file():
        return []
    with registry_path.open(encoding="utf-8") as handle:
        registry = yaml_load(handle) or {}
    label = str(registry_path.relative_to(core.paths.REPO_ROOT))
    out = schema_errors(schema_validator("registry.schema.json"), registry, label)
    platforms = registry.get("platforms") or {}
    if isinstance(platforms, dict) and not any(
        isinstance(entry, dict) and entry.get("release_pack") is True
        for entry in platforms.values()
    ):
        out.append(f"{label}: no platform has release_pack: true")
    return out


def save_directory_blocks() -> list[str]:
    """Each registry save_directory is null or a folder and a by_core flag.

    The folder names the pack folder and the save directory's default place
    beside the BIOS directory: a relative path that never climbs. ``by_system`` (a save
    folder per launched system) needs the platform file's libretro_systems,
    and ``by_core_for`` names the cores a launcher sorts by core.
    """
    platforms = load_platform_registry(core.paths.REPO_ROOT / PLATFORMS_DIR)
    out: list[str] = []
    for name, entry in sorted(platforms.items()):
        if not isinstance(entry, dict) or "save_directory" not in entry:
            continue
        block = entry["save_directory"]
        if block is None:
            continue
        folder = block.get("folder") if isinstance(block, dict) else None
        sorted_cores = block.get("by_core_for", []) if isinstance(block, dict) else None
        if (
            not isinstance(block, dict)
            or not {"folder", "by_core"} <= set(block) <= {
                "folder", "by_core", "by_system", "by_core_for", "pack_folder",
            }
            or not isinstance(block.get("pack_folder", "x"), str)
            or "/" in str(block.get("pack_folder", ""))
            or not isinstance(folder, str)
            or not folder
            or "\\" in folder
            or any(part in ("", ".", "..") for part in folder.split("/"))
            or not isinstance(block.get("by_core"), bool)
            or not isinstance(block.get("by_system", False), bool)
            or not isinstance(sorted_cores, list)
            or not all(isinstance(core, str) and core for core in sorted_cores)
        ):
            out.append(
                f"platforms/_registry.yml: {name}.save_directory must be null or "
                "{folder: <relative path>, by_core: <bool>, by_system: <bool>, "
                "by_core_for: [<core>]}"
            )
            continue
        if block.get("by_system") and not _libretro_systems(name):
            out.append(
                f"platforms/_registry.yml: {name}.save_directory.by_system and "
                f"platforms/{name}.yml lists no libretro_systems"
            )
        in_pack = block.get("pack_folder") or folder
        taken = bios_tree_below(name, in_pack)
        if taken:
            out.append(
                f"platforms/_registry.yml: {name}.save_directory puts the save "
                f"files in {in_pack}/, which the BIOS tree uses ({taken}): "
                "name another pack_folder"
            )
    return out


def bios_tree_below(platform: str, folder: str) -> str:
    """A destination the platform declares below ``folder``, or empty."""
    try:
        config = load_platform_config(platform, str(core.paths.REPO_ROOT / PLATFORMS_DIR))
    except FileNotFoundError:
        return ""
    prefix = f"{folder}/".lower()
    return next(
        (
            str(entry["destination"])
            for system in (config.get("systems") or {}).values()
            for entry in system.get("files") or []
            if str(entry.get("destination") or "").lower().startswith(prefix)
        ),
        "",
    )


def _libretro_systems(platform: str) -> dict:
    """The platform file's core -> systems table, inheritance included."""
    try:
        config = load_platform_config(platform, str(core.paths.REPO_ROOT / PLATFORMS_DIR))
    except FileNotFoundError:
        return {}
    return config.get("libretro_systems") or {}
