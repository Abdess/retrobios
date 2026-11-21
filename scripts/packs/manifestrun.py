"""Install manifests written for platform groups, with their aliases and standalone layouts."""

from __future__ import annotations

import argparse
import json
import os
import sys

from core.artifacts import write_if_changed
from model.platforms import load_platform_config
from model.registry import load_platform_registry
from model.safeparse import require_yaml
from packs.datatrees import uncached_warning
from packs.manifest import generate_install_list
from packs.naming import pack_narrowings, platform_target
from packs.scope import platform_list_version
from packs.standalone import STANDALONE_DIR, standalone_copies
from packs.variants import run_variants, skip_empty_truth
from resolve.cores import resolve_platform_cores

yaml = require_yaml()


def write_standalone_layouts(output_dir: str, platform: str, layouts: dict) -> str:
    """install/standalone/<platform>.json, what --standalone reads beside the
    list. Its [dest, sha1] items take their download from that list."""
    path = os.path.join(output_dir, STANDALONE_DIR, f"{platform}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    write_if_changed(path, json.dumps({
        "schema": 1, "platform": platform, "standalone_layouts": layouts,
    }, indent=2))
    return path


def _alias_manifest(
    manifest: dict,
    alias_plat: str,
    platforms_dir: str,
    platform_registry: dict,
    emu_profiles: dict,
) -> dict:
    """The representative's manifest under a grouped platform's own name."""
    alias_manifest = dict(manifest)
    alias_manifest["platform"] = alias_plat
    alias_cfg = load_platform_config(alias_plat, platforms_dir)
    alias_manifest["display_name"] = alias_cfg.get("platform", alias_plat)
    alias_manifest["version"] = platform_list_version(alias_cfg, alias_plat)
    alias_manifest["base_destination"] = alias_cfg.get("base_destination", "")
    alias_registry = platform_registry.get(alias_plat, {})
    alias_install = alias_registry.get("install", {})
    alias_manifest["detect"] = alias_install.get("detect", [])
    # Placed and completed as the representative's are:
    # copied raw, an alias's copies named no source.
    alias_manifest["standalone_copies"] = standalone_copies(
        alias_install.get("standalone_copies", []),
        {name: emu_profiles[name]
         for name in resolve_platform_cores(alias_cfg, emu_profiles)},
        manifest["files"],
    )
    return alias_manifest


def report_uncached(uncached: dict[str, str], recorded: set[str] | None) -> None:
    """Name each data directory a list carries and the cache does not hold,
    once, and record it for the run's exit code."""
    for ref_key, local_path in uncached.items():
        print(uncached_warning(ref_key, local_path))
    if recorded is not None:
        recorded.update(uncached)


def run_manifest_mode(
    args: argparse.Namespace,
    groups: list[tuple[list[str], str]],
    db: dict,
    zip_contents: dict,
    emu_profiles: dict,
    target_cores_cache: dict[str, set[str] | None],
) -> bool:
    """Generate JSON manifests instead of ZIP packs. False when a platform
    has none."""
    registry_path = os.path.join(args.platforms_dir, "_registry.yml")
    os.makedirs(args.output_dir, exist_ok=True)
    platform_registry = load_platform_registry(args.platforms_dir)

    failed: list[str] = []
    for source, required_only in run_variants(args):
        for group_platforms, representative in groups:
            print(f"\nGenerating manifest for {representative} [source={source}]...")
            tc = target_cores_cache.get(representative) if args.target else None
            if skip_empty_truth(args, source, representative, emu_profiles, tc, failed):
                continue
            layouts: dict = {}
            uncached: dict[str, str] = {}
            try:
                manifest = generate_install_list(
                    representative,
                    args.platforms_dir,
                    db,
                    args.bios_dir,
                    registry_path,
                    emulators_dir=args.emulators_dir,
                    zip_contents=zip_contents,
                    emu_profiles=emu_profiles,
                    target_cores=tc,
                    source=source,
                    regions=getattr(args, "regions", None),
                    target_name=platform_target(
                        representative, args.target, args.platforms_dir
                    ),
                    offline=args.offline,
                    required_only=required_only,
                    no_game_data=getattr(args, "no_game_data", False),
                    standalone_out=layouts,
                    uncached_out=uncached,
                )
                report_uncached(uncached, getattr(args, "uncached_trees", None))
                narrow_suffix = "".join(
                    tag.lower()
                    for tag, _label in pack_narrowings(
                        source,
                        getattr(args, "regions", None),
                        platform_target(representative, args.target, args.platforms_dir),
                        False,
                        required_only,
                        no_game_data=getattr(args, "no_game_data", False),
                    )
                )
                out_path = os.path.join(
                    args.output_dir,
                    f"{representative}{narrow_suffix}.json",
                )
                write_if_changed(out_path, json.dumps(manifest, indent=2))
                print(
                    f"  {out_path}: {manifest['total_files']} files, "
                    f"{manifest['total_size']} bytes, "
                    f"{manifest['total_omitted']} safely omitted"
                )
                for plat in group_platforms if layouts else ():
                    print(f"  {write_standalone_layouts(args.output_dir, plat, layouts)}: "
                          f"{len(layouts)} standalone builds")
                # Create aliases for grouped platforms (e.g., lakka -> retroarch)
                for alias_plat in group_platforms:
                    if alias_plat != representative:
                        alias_path = os.path.join(
                            args.output_dir,
                            f"{alias_plat}{narrow_suffix}.json",
                        )
                        alias_manifest = _alias_manifest(
                            manifest, alias_plat, args.platforms_dir,
                            platform_registry, emu_profiles,
                        )
                        write_if_changed(alias_path, json.dumps(alias_manifest, indent=2))
                        print(f"  {alias_path}: alias of {representative}")
            except (FileNotFoundError, OSError, yaml.YAMLError) as e:
                print(f"  ERROR: {e}", file=sys.stderr)
                failed.append(representative)

    # A platform whose manifest could not be built has none, and install.py
    # serves whatever an older run left there: that is a failed run.
    if failed:
        print(f"ERROR: no manifest for {', '.join(sorted(set(failed)))}", file=sys.stderr)
        return False
    return True
