"""Loading a platform's configuration: inheritance, shared groups, registry cores, rom folders."""

from __future__ import annotations

import os

from core.paths import PLATFORMS_DIR, REPO_ROOT, comparable_destination
from model.sources import source_yaml_file


_shared_yml_cache: dict[str, dict] = {}
_platform_config_cache: dict[tuple[str, str], dict] = {}

# The directory a config was loaded from, read by the steps that consult
# its other files (the RetroArch targets of a downloaded-only core).
PLATFORMS_DIR_KEY = "_platforms_dir"


def config_platforms_dir(config: dict) -> str:
    """The directory a config was loaded from, the repository's for a config
    built by hand."""
    return str(config.get(PLATFORMS_DIR_KEY) or REPO_ROOT / PLATFORMS_DIR)


def _inherited_yaml(platform_name: str, platforms_dir: str) -> tuple[dict, list[str]]:
    """The platform's YAML merged over its parents', and the chain of names.

    Built from fresh copies: merging over the parent's cached config shared
    its systems, so a child's overrides rewrote the parent for the rest of
    the run.
    """
    config_file = os.path.join(platforms_dir, f"{platform_name}.yml")
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Platform config not found: {config_file}")

    config = source_yaml_file(config_file) or {}
    if "inherits" not in config:
        return config, [platform_name]

    merged, chain = _inherited_yaml(config["inherits"], platforms_dir)
    # A version names one platform's release, never its parent's: Lakka
    # read as RetroArch v1.22.2 in its manifest, pack name and site page.
    # dat_version stays, it is the version of the inherited list itself.
    merged.pop("version", None)
    merged.update(
        {k: v for k, v in config.items() if k not in ("inherits", "overrides")}
    )
    if "overrides" in config and "systems" in config["overrides"]:
        merged.setdefault("systems", {})
        for sys_id, override in config["overrides"]["systems"].items():
            if sys_id in merged["systems"]:
                merged["systems"][sys_id] = {
                    **merged["systems"][sys_id],
                    **override,
                }
            else:
                merged["systems"][sys_id] = override
    return merged, [platform_name, *chain]


def inheritance_chain(platform: str, platforms_dir: str | os.PathLike[str]) -> list[str]:
    """The platform and every platform its file inherits from, nearest first.

    Stops at a file that does not exist or at a name already walked.
    """
    chain: list[str] = []
    name: str | None = platform
    while name and name not in chain:
        path = os.path.join(platforms_dir, f"{name}.yml")
        if not os.path.isfile(path):
            break
        chain.append(name)
        inherits = (source_yaml_file(path) or {}).get("inherits")
        name = str(inherits) if inherits else None
    return chain


def _cached_platform_yaml(path: str) -> dict:
    """A registry or shared-group file, parsed once per real path."""
    real = os.path.realpath(path)
    if real not in _shared_yml_cache:
        _shared_yml_cache[real] = source_yaml_file(path) or {}
    return _shared_yml_cache[real]


def _merge_registry_cores(config: dict, reg_entry: dict, depth: int) -> None:
    """Merge cores (union for lists, override for all_libretro), a
    parent's only where the platform names none."""
    reg_cores = reg_entry.get("cores")
    if reg_cores is None or not (depth == 0 or "cores" not in config):
        return
    cfg_cores = config.get("cores")
    if reg_cores == "all_libretro":
        config["cores"] = "all_libretro"
    elif isinstance(reg_cores, list) and isinstance(cfg_cores, list):
        merged_set = {str(c) for c in cfg_cores} | {str(c) for c in reg_cores}
        config["cores"] = sorted(merged_set)
    elif isinstance(reg_cores, list) and cfg_cores is None:
        config["cores"] = reg_cores


def _apply_shared_groups(config: dict, shared_groups: dict) -> None:
    """Add each included shared group's files to the systems naming it."""
    # A shared group's file joins a system unless the platform already has
    # it there. Case only makes two names one where the filesystem folds it:
    # Lakka and RetroPie run on Linux, and np2kai opens 2608_bd.wav beside
    # System.dat's 2608_BD.WAV.
    def fold(destination: str) -> str:
        return comparable_destination(destination, bool(config.get("case_insensitive_fs")))

    for system in config.get("systems", {}).values():
        for group_name in system.get("includes", []):
            if group_name not in shared_groups:
                continue
            existing = {
                (f.get("name"), f.get("destination", f.get("name")))
                for f in system.get("files", [])
            }
            existing_lower = {
                fold(f.get("destination", f.get("name", "")))
                for f in system.get("files", [])
            }
            for gf in shared_groups[group_name]:
                key = (gf.get("name"), gf.get("destination", gf.get("name")))
                dest_lower = fold(gf.get("destination", gf.get("name", "")))
                if key not in existing and dest_lower not in existing_lower:
                    # Marked as ours: the platform's own file does not
                    # carry it, and an export must not count it kept.
                    system.setdefault("files", []).append(
                        {**gf, "shared_group": group_name}
                    )
                    existing.add(key)


def _mark_composite_archives(config: dict) -> None:
    """Mark every .zip entry as hashed by its members.

    Recalbox hashes a .zip by its members, so a plain md5 never answers one
    of its archive declarations: the resolver reads the mark per entry.
    """
    config["systems"] = {
        sys_id: {
            **system,
            "files": [
                {**f, "zip_digest": "composite"}
                if str(f.get("name", "")).lower().endswith(".zip")
                else f
                for f in system.get("files", [])
            ],
        }
        for sys_id, system in config.get("systems", {}).items()
    }


def _tag_platform_systems(config: dict) -> None:
    """Each entry carries the system that declares it.

    A hashless name match is narrowed to the maker folder that system names
    (resolve_local_file). A system that names its own cores (EmuELEC,
    AmberELEC, KNULLI) also passes them on, so another emulator's tree is
    foreign to its entries. Fresh dicts, since a YAML anchor can share one
    entry between systems.
    """
    config["systems"] = {
        sys_id: {
            **system,
            "files": [
                {
                    **f,
                    "platform_system": sys_id,
                    **(
                        {"platform_cores": list(system["cores"])}
                        if system.get("cores")
                        else {}
                    ),
                }
                for f in system["files"]
            ],
        }
        if isinstance(system, dict) and system.get("files")
        else system
        for sys_id, system in config.get("systems", {}).items()
    }


def _attach_rom_folders(config: dict, platform_name: str, platforms_dir: str) -> None:
    """Where the platform's games live, as its rom folders file records it
    from the OS's own source (platforms/romfolders/<key>.yml, roms_root)."""
    romfolders = os.path.join(platforms_dir, "romfolders", f"{platform_name}.yml")
    if not os.path.exists(romfolders):
        return
    data = source_yaml_file(romfolders) or {}
    roms_root = data.get("roms_root")
    if isinstance(roms_root, dict):
        config["_roms_root"] = roms_root
    folders = data.get("folders")
    if isinstance(folders, list):
        config["_rom_folders"] = [row for row in folders if isinstance(row, dict)]


def load_platform_config(platform_name: str, platforms_dir: str = PLATFORMS_DIR) -> dict:
    """Load a platform config with inheritance and shared group resolution.

    This is the SINGLE implementation used by generate_pack, generate_readme,
    verify, and auto_fetch. No other copy should exist.
    """
    cache_key = (platform_name, os.path.realpath(platforms_dir))
    if cache_key in _platform_config_cache:
        return _platform_config_cache[cache_key]

    config, chain = _inherited_yaml(platform_name, platforms_dir)

    shared_path = os.path.join(platforms_dir, "_shared.yml")
    # Merge metadata from _registry.yml. The registry is our curated source,
    # while the scraped YAML may be incomplete (missing cores, metadata fields).
    # Registry fields supplement (not replace) the scraped config.
    registry_path = os.path.join(platforms_dir, "_registry.yml")
    if os.path.exists(registry_path):
        reg = _cached_platform_yaml(registry_path)
        # The platform's own entry first, then its parents' for what it does
        # not say: RetroPie's status, scraper and install are its own, its
        # verification mode is RetroArch's.
        for depth, name in enumerate(chain):
            reg_entry = reg.get("platforms", {}).get(name, {})
            _merge_registry_cores(config, reg_entry, depth)

            # Merge all registry fields absent from config (except cores,
            # handled above with union logic). No hardcoded list: any field
            # added to the registry is automatically available in the config.
            for key, val in reg_entry.items():
                if key != "cores" and key not in config:
                    config[key] = val

    if os.path.exists(shared_path):
        shared = _cached_platform_yaml(shared_path)
        _apply_shared_groups(config, shared.get("shared_groups", {}))

    if config.get("zip_digest") == "composite":
        _mark_composite_archives(config)

    _tag_platform_systems(config)

    # The registry key, which per-platform profile fields (installed_on,
    # not_bundled_on) name: the display name differs (MiSTer FPGA).
    config["_key"] = platform_name
    config[PLATFORMS_DIR_KEY] = platforms_dir
    _attach_rom_folders(config, platform_name, platforms_dir)
    _platform_config_cache[cache_key] = config
    return config


def native_layer(config: dict | None) -> dict | None:
    """The platform config without what we add to it.

    A shared group's files join the config for the pack, but the platform's
    file does not carry them: counted kept, they were written into
    libretro's System.dat (N88EXT0-3.ROM) as if libretro declared them. What
    a core needs from a group reaches the export through the truth, as an
    addition the format's gates apply to. A scraper's mirror of an entry
    under another system (RomM's tg16 firmware under turbografx-cd), and a
    file our scraper adds from the cores' source (Dolphin's DSP ROMs in
    RetroArch's config), are not in the platform's file either.
    """
    if config is None:
        return None
    systems = {
        sys_id: {
            **system,
            "files": [
                f for f in system.get("files", [])
                if not ({"shared_group", "mirror_of", "curated"} & f.keys())
            ],
        }
        for sys_id, system in config.get("systems", {}).items()
    }
    return {**config, "systems": systems}
