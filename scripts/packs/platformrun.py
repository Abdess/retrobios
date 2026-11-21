"""A platform run: packs or manifests built for each group of platforms, then checked."""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from pathlib import Path

from core.text import count_text
from model.platforms import load_platform_config
from model.profiles import load_emulator_profiles
from model.registry import (
    list_registered_platforms,
    list_release_pack_platforms,
    load_data_dir_registry,
)
from model.safeparse import require_yaml
from model.targets import target_scope
from packs.datadirs import hold_data_dirs
from packs.finalize import verify_and_finalize_packs
from packs.manifest import generate_manifest
from packs.manifestrun import run_manifest_mode
from packs.naming import pack_narrowings, platform_pack_name, platform_target
from packs.outputdir import holds_other_kind, pack_output_lock
from packs.packcheck import run_verify_packs
from packs.platformpack import generate_pack, generate_split_packs
from packs.runscope import settle_scope
from packs.scope import pack_systems
from packs.targets import target_list
from packs.variants import pack_label, run_variants, skip_empty_truth
from resolve.cores import platforms_with_systems, without_profile_blind
from resolve.grouping import group_identical_platforms

yaml = require_yaml()


def produced(split: bool, zip_path: str | None, zip_paths: list[str] | None) -> bool:
    """Whether the build wrote what the run asked for."""
    return bool(zip_paths if split else zip_path)


def run_platform_packs(
    args: argparse.Namespace,
    groups: list[tuple[list[str], str]],
    db: dict,
    zip_contents: dict,
    data_registry: dict | None,
    emu_profiles: dict,
    target_cores_cache: dict[str, set[str] | None],
    system_filter: list[str] | None,
) -> bool:
    """Generate ZIP packs for platform groups and verify. False when a pack
    was not written or failed its check."""
    registry_path = os.path.join(args.platforms_dir, "_registry.yml")
    # Per pack, the systems each of its files is for, written into its
    # manifest.json once the pack is verified (pack_systems).
    systems_for: dict[str, dict] = {}
    # The packs this run writes, the only ones it verifies and rewrites.
    built: set[str] = set()

    failed: list[str] = []
    for source, required_only in run_variants(args):
        for group_platforms, representative in groups:
            aliases = [p for p in group_platforms if p != representative]
            if aliases:
                all_names = [
                    load_platform_config(p, args.platforms_dir).get("platform", p)
                    for p in group_platforms
                ]
                label = " / ".join(all_names)
                print(f"\nGenerating pack for {label} {pack_label(source, required_only)}...")
            else:
                print(f"\nGenerating pack for {representative} {pack_label(source, required_only)}...")

            zip_path = None
            zip_paths: list = []
            tc = target_cores_cache.get(representative) if args.target else None
            named_target = platform_target(representative, args.target, args.platforms_dir)
            if skip_empty_truth(args, source, representative, emu_profiles, tc, failed):
                continue
            try:
                if args.split:
                    zip_paths = generate_split_packs(
                        representative,
                        args.platforms_dir,
                        db,
                        args.bios_dir,
                        args.output_dir,
                        group_by=args.group_by,
                        emulators_dir=args.emulators_dir,
                        zip_contents=zip_contents,
                        data_registry=data_registry,
                        emu_profiles=emu_profiles,
                        target_cores=tc,
                        required_only=required_only,
                        source=source,
                        regions=getattr(args, "regions", None),
                        target_name=named_target,
                        one_per_slot=args.one_per_slot,
                        offline=args.offline,
                        no_game_data=getattr(args, "no_game_data", False),
                    )
                    print(f"  Split into {len(zip_paths)} packs")
                else:
                    # A group's pack is written under the group's name from
                    # the start: built under the representative's and then
                    # renamed, it overwrote and carried away a
                    # `--platform retroarch` pack already in the directory,
                    # and os.rename refused an existing target on Windows.
                    group_name = (
                        group_pack_name(
                            args, group_platforms, representative, (source, required_only),
                            named_target, system_filter,
                        )
                        if aliases else None
                    )
                    zip_path = generate_pack(
                        representative,
                        args.platforms_dir,
                        db,
                        args.bios_dir,
                        args.output_dir,
                        emulators_dir=args.emulators_dir,
                        zip_contents=zip_contents,
                        data_registry=data_registry,
                        emu_profiles=emu_profiles,
                        target_cores=tc,
                        required_only=required_only,
                        system_filter=system_filter,
                        source=source,
                        regions=getattr(args, "regions", None),
                        target_name=named_target,
                        one_per_slot=args.one_per_slot,
                        offline=args.offline,
                        pack_name=group_name,
                        no_game_data=getattr(args, "no_game_data", False),
                    )
            except (FileNotFoundError, OSError, yaml.YAMLError) as e:
                print(f"  ERROR: {e}", file=sys.stderr)
                failed.append(representative)
            else:
                # A builder that declined (no system left under the target)
                # produced nothing: the run must say so, not verify whatever
                # the output directory already held and exit 0.
                if not produced(args.split, zip_path, zip_paths):
                    failed.append(representative)
                    continue
                built.update(
                    os.path.relpath(path, args.output_dir)
                    for path in ([zip_path] if zip_path else zip_paths)
                )
                if zip_path and not system_filter:
                    # The install list of the same choices names each file's
                    # systems: the pack records them, so a pack alone (a
                    # handheld without Wi-Fi) can be narrowed by system.
                    board_list = Path(args.platforms_dir) / "targets" / f"{representative}.yml"
                    systems_for[os.path.basename(zip_path)] = pack_systems(generate_manifest(
                        representative, args.platforms_dir, db, args.bios_dir,
                        registry_path, emulators_dir=args.emulators_dir,
                        zip_contents=zip_contents, emu_profiles=emu_profiles,
                        target_cores=tc, source=source,
                        regions=getattr(args, "regions", None), target_name=named_target,
                        offline=args.offline, required_only=required_only,
                        data_registry=data_registry,
                        no_game_data=getattr(args, "no_game_data", False),
                    ), target_list(board_list) if board_list.is_file() else None)

    all_ok = finalize_platform_packs(args, db, data_registry, built, systems_for, system_filter)
    if failed:
        # Verification only sees the ZIPs that exist, so a pack that was never
        # written does not fail it.
        print(f"ERROR: no pack for {', '.join(sorted(set(failed)))}", file=sys.stderr)
        return False
    return all_ok


def group_pack_name(
    args: argparse.Namespace,
    group_platforms: list[str],
    representative: str,
    variant: tuple[str, bool],
    named_target: str | None,
    system_filter: list[str] | None,
) -> str:
    """The file name of a pack shared by a group of identical platforms."""
    source, required_only = variant
    narrowings = pack_narrowings(
        source,
        getattr(args, "regions", None),
        named_target,
        args.one_per_slot,
        required_only,
        no_game_data=getattr(args, "no_game_data", False),
    )
    return platform_pack_name(
        representative, args.platforms_dir, narrowings, system_filter, group=group_platforms
    )


def finalize_platform_packs(
    args: argparse.Namespace,
    db: dict,
    data_registry: dict | None,
    built: set[str],
    systems_for: dict[str, dict],
    system_filter: list[str] | None,
) -> bool:
    """Verify the packs this run wrote and write their manifests."""
    print("\nVerifying packs and generating manifests...")
    skip_conf = bool(system_filter or args.split)
    all_ok = verify_and_finalize_packs(
        args.output_dir,
        db,
        platforms_dir=args.platforms_dir,
        emulators_dir=args.emulators_dir,
        built=built,
        pack_systems_by_name=systems_for,
        skip_conformance=skip_conf,
        data_registry=data_registry,
        regions=getattr(args, "regions", None),
        target_name=args.target,
        no_game_data=getattr(args, "no_game_data", False),
    )
    if args.split:
        for entry in os.listdir(args.output_dir):
            sub = os.path.join(args.output_dir, entry)
            if os.path.isdir(sub) and entry.endswith("_Split"):
                ok = verify_and_finalize_packs(
                    sub,
                    db,
                    platforms_dir=args.platforms_dir,
                    emulators_dir=args.emulators_dir,
                    built={
                        os.path.basename(name) for name in built
                        if os.path.dirname(name) == entry
                    },
                    skip_conformance=True,
                    data_registry=data_registry,
                    regions=getattr(args, "regions", None),
                )
                all_ok = all_ok and ok
    return all_ok


def refresh_data_directories(args: argparse.Namespace, data_registry: dict) -> None:
    """Bring the data directory caches up to date before a build reads them."""
    from packs.datadirs import refresh_all

    results = refresh_all(data_registry, force=args.refresh_data)
    updated = sum(1 for v in results.values() if v)
    if updated:
        print(f"Refreshed {count_text(updated, 'data directory', 'data directories')}")
    failed = sorted(k for k, v in results.items() if v is None)
    if failed:
        print(f"WARNING: data directory refresh failed: {', '.join(failed)}")


def _narrowing_flags(args: argparse.Namespace) -> list[str]:
    """The narrowing flags given that a profile-blind platform cannot apply."""
    return [
        flag for flag, given in (
            ("--region", getattr(args, "regions", None)),
            ("--one-per-slot", getattr(args, "one_per_slot", False)),
            ("--no-game-data", getattr(args, "no_game_data", False)),
        ) if given
    ]


def run_platform_mode(
    args: argparse.Namespace,
    platforms: list[str],
    held: contextlib.ExitStack,
    db: dict,
    zip_contents: dict,
) -> bool:
    """--platform or --all: packs or manifests in each platform's layout.
    False when the run failed."""
    system_filter = getattr(args, "system_ids", None)

    # A mistyped target is refused before the output lock and the data
    # directory refresh: checked after them, `--target swich` waited on a
    # pipeline's caches before saying the target does not exist.
    target_cores_cache, platforms = target_scope(
        platforms, args.target, args.platforms_dir, is_all=args.all
    )

    emu_profiles = load_emulator_profiles(args.emulators_dir)
    if system_filter:
        platforms = settle_scope(platforms_with_systems(
            platforms, system_filter, emu_profiles, target_cores_cache,
            args.platforms_dir, args.target, args.all,
        ), sys.stderr)
    platforms = settle_scope(without_profile_blind(
        platforms,
        _narrowing_flags(args),
        args.platforms_dir,
        emu_profiles,
        target_cores_cache if args.target else None,
        args.all,
    ), sys.stdout)

    data_registry = load_data_dir_registry(args.platforms_dir)
    # The output directory is claimed before the data directory refresh: a
    # refresh waits for every run that holds a cache, so a second build
    # during a pipeline sat silent for hours instead of being refused.
    with pack_output_lock(args.output_dir):
        if data_registry and not args.offline and not args.no_refresh_data:
            refresh_data_directories(args, data_registry)
        if data_registry:
            hold_data_dirs(held, data_registry)

        groups = group_identical_platforms(
            platforms, args.platforms_dir, target_cores_cache if args.target else None
        )

        if args.manifest:
            if holds_other_kind(args.output_dir, "manifest"):
                return False
            if not run_manifest_mode(
                args, groups, db, zip_contents, emu_profiles, target_cores_cache
            ):
                return False
        elif not run_platform_packs(
            args,
            groups,
            db,
            zip_contents,
            data_registry,
            emu_profiles,
            target_cores_cache,
            system_filter,
        ):
            return False
    if not args.manifest and args.verify_packs:
        with pack_output_lock(args.output_dir, exclusive=False):
            return run_verify_packs(args)
    return True


def requested_platforms(args: argparse.Namespace, parser: argparse.ArgumentParser) -> list[str]:
    """The platforms a platform run builds for."""
    if args.all and args.manifest:
        # Install manifests cover every registered platform: the installer
        # serves each one, with or without a release pack.
        return list_registered_platforms(args.platforms_dir)
    if args.all:
        # A release publishes the packs the registry marks release_pack and
        # nothing else: a pack built for another platform is one nobody uploads.
        platforms = list_release_pack_platforms(args.platforms_dir)
        if not platforms:
            parser.error("no registered platform has release_pack: true")
        return platforms
    if not args.platform:
        parser.error("Specify --platform or --all")
    return [args.platform]
