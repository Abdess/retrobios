#!/usr/bin/env python3
"""Generate platform-specific BIOS ZIP packs.

Usage:
    python scripts/generate_pack.py --platform retroarch [--output-dir dist/]
    python scripts/generate_pack.py --all [--output-dir dist/]

Reads platform YAML config + database.json -> creates ZIP with correct
file layout for each platform. Handles inheritance, shared groups, variants,
and 3-tier storage (embedded/external/user_provided).
"""

from __future__ import annotations

import sys

# The README's first command. Under 3.8 it stopped on a SyntaxError that read
# like a damaged file. The build needs 3.9, as pipeline.py says.
if sys.version_info < (3, 9):
    sys.exit(f"generate_pack.py needs Python 3.9 or newer, this is {sys.version.split()[0]}")

from collections.abc import Iterator

import argparse
import contextlib
import json
import os
from pathlib import Path
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(__file__))
from resolve.cores import resolve_platform_cores as _platform_cores
from model.profiles import (
    load_emulator_profiles,
)
from model.cliargs import (
    platform_arg,
    require_platform,
    list_emulator_profiles,
    list_platform_system_ids,
    print_platform_listing,
    list_system_ids,
)
from core.cli import add_emulator_selection, add_repo_inputs, require_directory
from model.targets import (
    target_listing_line,
    target_scope,
)
from model.systems import (
    resolve_system_arg,
    select_systems,
)
from core.artifacts import (
    write_if_changed,
    artifact_lock,
    repository_output_lock,
    ArtifactLockBusy,
)
from core.ziptools import build_zip_contents_index
from resolve.cores import (
    platform_scope_systems,
    system_scope_error,
    without_profile_blind,
)
from resolve.grouping import group_identical_platforms
from model.registry import (
    list_registered_platforms,
    list_release_pack_platforms,
    load_data_dir_registry,
    load_platform_registry,
)
from model.database import load_database
from model.platforms import load_platform_config
from model.safeparse import require_yaml
from resolve import packfiles as packresolve
from packs.datadirs import hold_data_dirs
from model import region

from packs.integrity import verify_pack_against_platform
from resolve.packfiles import (
    ACCEPTED_HASHES,
    parse_hash_input,
    parse_hash_file,
    lookup_hashes,
)

from packs.archive import DamagedArchiveError
from packs.platformpack import generate_split_packs
from packs.datatrees import MISSING_DATA_DIRS
from packs.emulatorpack import generate_emulator_pack, generate_system_pack
from packs.finalize import baseline_shortfall, verify_and_finalize_packs
from packs.manifest import generate_install_list, generate_manifest
from packs.md5pack import generate_md5_pack
from packs.naming import (
    expected_pack_names,
    pack_narrowings,
    pack_variant,
    platform_pack_name,
    platform_target,
)
from packs.platformpack import generate_pack
from packs.scope import pack_systems, platform_list_version
from packs.standalone import STANDALONE_DIR, standalone_copies
from packs.targets import generate_target_manifests, target_list


yaml = require_yaml()

DEFAULT_OUTPUT_DIR = "dist"


def _json_artifact_kind(path: Path) -> str | None:
    """"manifest" for an install manifest, "targets" for a per-target core
    list, None for anything else. The two share their file names: install.py
    fetches install/<platform>.json and install/targets/<platform>.json."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not data:
        return None
    if "manifest_version" in data:
        return "manifest"
    if all(v is None or isinstance(v, list) for v in data.values()):
        return "targets"
    return None


def _refuse_mixed_output(output_dir: str, writing: str) -> None:
    """Stop before one kind of installer JSON overwrites the other.

    Both are named <platform>.json, so --manifest-targets aimed at install/
    replaced install/retroarch.json, the file every installer downloads, with
    a target table, and the reverse replaced a target list by a manifest.
    """
    directory = Path(output_dir)
    if not directory.is_dir():
        return
    other = "targets" if writing == "manifest" else "manifest"
    held = sorted(
        p.name for p in directory.glob("*.json") if _json_artifact_kind(p) == other
    )
    if not held:
        return
    what = {
        "manifest": "install manifests (install/ in the repository)",
        "targets": "per-target core lists (install/targets/ in the repository)",
    }
    flag = "--manifest" if writing == "manifest" else "--manifest-targets"
    print(
        f"ERROR: {output_dir} holds {what[other]}: {', '.join(held[:3])}"
        f"{', ...' if len(held) > 3 else ''}. {flag} writes {what[writing]} under the "
        f"same file names; pass the --output-dir that holds those instead.",
        file=sys.stderr,
    )
    sys.exit(1)


def _resolve_systems(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Turn --system into the platform's system ids, before any work.

    With --platform the platform's own names count too (Batocera's psx), the
    mapping the install manifest carries. With --all each name must be one
    of our ids some platform declares. Checked inside the build, a typo cost
    the lock and a refresh of every data directory first, then ended on a
    WARNING and exit 1, and a list with one known name ignored the others.
    """
    if not args.system or not (args.platform or args.all):
        return
    if args.platform:
        config = load_platform_config(args.platform, args.platforms_dir)
        systems = list(config.get("systems", {}))
        listing = f"--platform {args.platform} --list-systems"
    else:
        config = None
        systems = sorted({
            sid
            for name in list_registered_platforms(args.platforms_dir)
            for sid in load_platform_config(name, args.platforms_dir).get("systems", {})
        })
        listing = "--platform <name> --list-systems"
    try:
        args.system_ids = resolve_system_arg(args.system, systems, config, listing)
    except ValueError as exc:
        parser.error(f"--system {args.system}: {exc}")


def _platforms_with_systems(
    args: argparse.Namespace,
    platforms: list[str],
    system_filter: list[str],
    emu_profiles: dict,
    target_cores_cache: dict[str, set[str] | None],
) -> list[str]:
    """The platforms a --system list leaves a system to pack, before any lock.

    Under --all a platform without one is out of scope, as a platform
    without the target is: `--all --system sony-playstation-2` built every
    PS2 pack and exited 1 on MiSTer, which has no PS2. Under --platform the
    request is refused here, with its reason.
    """
    kept = []
    for name in platforms:
        config = load_platform_config(name, args.platforms_dir)
        tc = target_cores_cache.get(name) if args.target else None
        if platform_scope_systems(config, emu_profiles, tc, system_filter):
            kept.append(name)
            continue
        if not args.all:
            reason = system_scope_error(config, name, system_filter, args.target)
            print(f"ERROR: {reason}", file=sys.stderr)
            sys.exit(1)
        declared = select_systems(config.get("systems", {}), system_filter)
        reason = (
            system_scope_error(config, name, system_filter, args.target)
            if declared and args.target
            else f"no system {', '.join(system_filter)}"
        )
        print(f"INFO: Skipping {name}: {reason}")
    if not kept:
        where = f" on target {args.target}" if args.target else ""
        print(f"ERROR: no platform packed here runs {', '.join(system_filter)}{where}",
              file=sys.stderr)
        sys.exit(1)
    return kept


def _refuse_for_verify_packs(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """What --verify-packs cannot be combined with, refused before any lock.

    These lived in the --all-variants checks, which return at once without
    that flag: --verify-packs --manifest or --split went through, and a run
    with neither --platform nor --all failed after locking the directory.
    """
    if not args.verify_packs:
        return
    if args.manifest:
        parser.error("--verify-packs is incompatible with --manifest")
    if not (args.platform or args.all):
        parser.error("--verify-packs requires --platform or --all")
    # The check that follows the build reads the full pack's name.
    for flag, given in (
        ("--system", args.system),
        ("--one-per-slot", args.one_per_slot),
        ("--split", args.split),
    ):
        if given:
            parser.error(f"{flag} is incompatible with --verify-packs")


def _argument_conflicts(args: argparse.Namespace) -> list[tuple[bool, str]]:
    """Each refused combination of arguments with its message, in the order
    they are checked: the first one that applies is the error reported."""
    has_platform = bool(args.platform)
    has_all = args.all
    has_emulator = bool(args.emulator)
    has_system = bool(args.system)
    md5_file = getattr(args, "from_md5_file", None)
    has_from_md5 = bool(args.from_md5 or md5_file)
    # A mode either applies a narrowing flag or refuses it. Swallowing one
    # answers about an artifact the caller did not ask for, and the name on
    # disk then asserts a narrowing the contents do not carry.
    # --source and --group-by default to None so a typed default value is
    # seen: compared with "full", `--emulator X --source full` went through.
    source_given = getattr(args, "source", None) is not None
    with_platform = has_system and (has_platform or has_all)
    # Game data is categorized against a platform's list and the cores it
    # runs: a pack of one emulator or of a system's emulators has neither.
    no_game_data = getattr(args, "no_game_data", False)
    one_per_slot = getattr(args, "one_per_slot", False)
    return [
        (bool(args.from_md5 and md5_file), "--from-md5 and --from-md5-file are mutually exclusive"),
        (has_from_md5 and has_all, "--from-md5 requires --platform or --emulator, not --all"),
        (has_from_md5 and has_system, "--from-md5 and --system are mutually exclusive"),
        (has_from_md5 and args.split, "--split and --from-md5 are mutually exclusive"),
        # --platform/--all and --system can combine (system filters within platform)
        # --emulator is exclusive with everything else
        (has_emulator and (has_platform or has_all or has_system),
         "--emulator is mutually exclusive with --platform, --all, and --system"),
        (has_platform and has_all, "--platform and --all are mutually exclusive"),
        (not (has_platform or has_all or has_emulator or has_system or has_from_md5),
         "Specify --platform, --all, --emulator, --system, or --from-md5"),
        (args.standalone and not (
            has_emulator or (has_system and not has_platform and not has_all)
        ), "--standalone requires --emulator or --system (without --platform)"),
        (args.split and not (has_platform or has_all), "--split requires --platform or --all"),
        (args.split and has_emulator, "--split is incompatible with --emulator"),
        (args.group_by is not None and not args.split, "--group-by requires --split"),
        (args.target and not (has_platform or has_all), "--target requires --platform or --all"),
        (args.target and has_emulator, "--target is incompatible with --emulator"),
        (args.manifest and not (has_platform or has_all),
         "--manifest requires --platform or --all"),
        (args.manifest and has_emulator, "--manifest is incompatible with --emulator"),
        (args.manifest and args.split, "--manifest is incompatible with --split"),
        (getattr(args, "region", None) and has_from_md5,
         "--region and --from-md5 are mutually exclusive"),
        (source_given and (has_emulator or (has_system and not has_platform)),
         "--source requires --platform or --all"),
        (has_from_md5 and args.manifest, "--manifest is incompatible with --from-md5"),
        (has_from_md5 and args.target, "--target is incompatible with --from-md5"),
        (has_from_md5 and args.required_only, "--required-only is incompatible with --from-md5"),
        (has_from_md5 and source_given, "--source is incompatible with --from-md5"),
        (with_platform and args.manifest, "--system is incompatible with --manifest"),
        (with_platform and args.split, "--system is incompatible with --split"),
        (no_game_data and not (has_platform or has_all),
         "--no-game-data requires --platform or --all"),
        (no_game_data and has_from_md5, "--no-game-data is incompatible with --from-md5"),
        (one_per_slot and has_from_md5, "--one-per-slot and --from-md5 are mutually exclusive"),
        (one_per_slot and args.manifest, "--one-per-slot is incompatible with --manifest"),
        (one_per_slot and has_emulator, "--one-per-slot is incompatible with --emulator"),
        (one_per_slot and has_system, "--one-per-slot is incompatible with --system"),
    ]


def _validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Validate argument combinations and mutual exclusion rules."""
    _refuse_for_verify_packs(args, parser)
    for refused, message in _argument_conflicts(args):
        if refused:
            parser.error(message)


def _run_manifest_mode(
    args: argparse.Namespace,
    groups: list[tuple[list[str], str]],
    db: dict,
    zip_contents: dict,
    emu_profiles: dict,
    target_cores_cache: dict[str, set[str] | None],
) -> None:
    """Generate JSON manifests instead of ZIP packs."""
    registry_path = os.path.join(args.platforms_dir, "_registry.yml")
    os.makedirs(args.output_dir, exist_ok=True)
    platform_registry = load_platform_registry(args.platforms_dir)

    variants = ALL_VARIANTS if args.all_variants else ((args.source, args.required_only),)

    failed: list[str] = []
    for source, required_only in variants:
        for group_platforms, representative in groups:
            print(f"\nGenerating manifest for {representative} [source={source}]...")
            tc = target_cores_cache.get(representative) if args.target else None
            if _skip_empty_truth(args, source, representative, emu_profiles, tc, failed):
                continue
            layouts: dict = {}
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
                )
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
                    print(f"  {_write_standalone_layouts(args.output_dir, plat, layouts)}: "
                          f"{len(layouts)} standalone builds")
                # Create aliases for grouped platforms (e.g., lakka -> retroarch)
                for alias_plat in group_platforms:
                    if alias_plat != representative:
                        alias_path = os.path.join(
                            args.output_dir,
                            f"{alias_plat}{narrow_suffix}.json",
                        )
                        alias_manifest = dict(manifest)
                        alias_manifest["platform"] = alias_plat
                        alias_cfg = load_platform_config(alias_plat, args.platforms_dir)
                        alias_manifest["display_name"] = alias_cfg.get(
                            "platform", alias_plat
                        )
                        alias_manifest["version"] = platform_list_version(
                            alias_cfg, alias_plat
                        )
                        alias_manifest["base_destination"] = alias_cfg.get(
                            "base_destination", ""
                        )
                        alias_registry = platform_registry.get(alias_plat, {})
                        alias_install = alias_registry.get("install", {})
                        alias_manifest["detect"] = alias_install.get("detect", [])
                        # Placed and completed as the representative's are:
                        # copied raw, an alias's copies named no source.
                        alias_manifest["standalone_copies"] = standalone_copies(
                            alias_install.get("standalone_copies", []),
                            {name: emu_profiles[name]
                             for name in _platform_cores(alias_cfg, emu_profiles)},
                            manifest["files"],
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
        sys.exit(1)


@contextlib.contextmanager
def _pack_output_lock(output_dir: str, exclusive: bool = True) -> Iterator[None]:
    """Hold the output directory for the duration of a pack run, and the
    repository's fixed outputs when it is one of them (install/)."""
    try:
        with artifact_lock(output_dir, exclusive=exclusive), \
                repository_output_lock(output_dir) if exclusive else contextlib.nullcontext():
            yield
    except ArtifactLockBusy as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


@dataclass(frozen=True)
class _PackCheck:
    """What --verify-packs checks every pack against."""

    db: dict
    platforms_dir: str
    emulators_dir: str
    profiles: dict
    regions: list[str] | None
    data_registry: dict
    no_game_data: bool


def _verify_packs_scope(args: argparse.Namespace) -> tuple[list[str], dict[str, set[str] | None]]:
    """The platforms --verify-packs checks, and the cores of the target."""
    if args.platform:
        platforms = [args.platform]
    elif args.all:
        # The packs --all builds: a platform without release_pack has no pack
        # to check, and its absence from the directory is no failure.
        platforms = list_release_pack_platforms(args.platforms_dir)
    else:
        raise ValueError("--verify-packs requires --platform or --all")

    # The target is checked as the build checks it: a mistyped one, or one
    # the platform does not publish, was dropped and the full pack verified
    # under it, `all OK` for a pack no build had made.
    target_cores_cache, platforms = target_scope(
        platforms, args.target, args.platforms_dir, is_all=args.all
    )
    return platforms, target_cores_cache


def _run_verify_packs(args: argparse.Namespace) -> None:
    """Verify each pack in the output directory against its platform.

    Delegates to verify_pack_against_platform so the command answers the same
    question the pipeline asks: baseline files, core extras and structure. A
    second implementation here answered a narrower one and reported OK while
    the core extras went unchecked.
    """
    verify_db = load_database(args.db)
    platforms, target_cores_cache = _verify_packs_scope(args)

    all_ok = True
    check = _PackCheck(
        verify_db, args.platforms_dir, args.emulators_dir,
        load_emulator_profiles(args.emulators_dir), getattr(args, "regions", None),
        load_data_dir_registry(args.platforms_dir), getattr(args, "no_game_data", False),
    )
    # After an --all-variants build every variant is named, so none of the
    # six packs the run wrote passes unmentioned.
    expected = expected_pack_names(
        platforms,
        args.platforms_dir,
        check.regions,
        args.target,
        ALL_VARIANTS if args.all_variants else (("full", False),),
        no_game_data=check.no_game_data,
    )
    on_disk = (
        set(os.listdir(args.output_dir)) if os.path.isdir(args.output_dir) else set()
    )

    verified = 0
    failing: list[str] = []
    for platform_name in platforms:
        found = sorted(expected[platform_name] & on_disk)
        verified += len(found)
        if not found:
            # Naming a platform is asking about its pack: FAIL, with the
            # command that builds it. With --all, a platform whose pack was
            # not built is out of scope and skipped.
            if args.platform:
                print(
                    f"  {platform_name}: FAIL (no pack in {args.output_dir}; build it with "
                    f"python scripts/generate_pack.py --platform {platform_name} "
                    f"--output-dir {args.output_dir})"
                )
                all_ok = False
                failing.append(f"{platform_name} (no pack)")
            else:
                print(f"  {platform_name}: SKIP (no pack in {args.output_dir})")
            continue
        tc = target_cores_cache.get(platform_name)
        # A group pack and a pack built for the platform alone can both be
        # present, and each one is a pack of this platform.
        for pack_name in found:
            variant = pack_variant(pack_name)
            if variant is None:
                # One BIOS per slot: the slot choice is not replayed here.
                print(
                    f"  {platform_name} [{pack_name}]: hashes checked during the build; "
                    "one per slot by design, so not compared to the platform's full list"
                )
                continue
            source, required_only = variant
            zip_path = os.path.join(args.output_dir, pack_name)
            result = verify_pack_against_platform(
                zip_path,
                platform_name,
                check.platforms_dir,
                db=check.db,
                emulators_dir=check.emulators_dir,
                emu_profiles=check.profiles,
                regions=check.regions,
                data_registry=check.data_registry,
                target_cores=tc,
                source=source,
                required_only=required_only,
                no_game_data=check.no_game_data,
            )
            (ok, _checked, _present, errors, bl_checked, bl_present,
             core_checked, core_present, bl_excluded, bl_absent) = result
            # These explain a baseline short of its total: a dump whose hash
            # the frontend refuses is left out on purpose, and a file the
            # collection does not hold cannot be packed (verify reports it).
            shortfall = ", ".join(baseline_shortfall(bl_excluded, bl_absent))
            excluded = f" ({shortfall})" if shortfall else ""
            counts = (
                f"{bl_present}/{bl_checked} baseline{excluded}, "
                f"{core_present}/{core_checked} cores"
            )
            if ok:
                print(f"  {platform_name} [{pack_name}]: OK ({counts})")
            else:
                print(f"  {platform_name} [{pack_name}]: FAIL ({counts}, {len(errors)} errors)")
                for err in errors:
                    print(f"    {err}")
                all_ok = False
                failing.append(f"{platform_name} ({pack_name})")

    if not _verification_summary(failing, verified, args.output_dir) or not all_ok:
        sys.exit(1)


def _verification_summary(failing: list[str], verified: int, output_dir: str) -> bool:
    """Print how --verify-packs ended. False when nothing was verified."""
    if failing:
        # Named at the end, where the log is read, and on stderr, as the
        # build path does: a failing pack sat among its own error lines.
        print(
            f"ERROR: packs failed verification: {', '.join(failing)}",
            file=sys.stderr,
        )
    elif verified:
        print(f"Verified {verified} pack{'s' if verified != 1 else ''}: all OK")
    if not verified:
        # Every platform skipped is no check at all: a mistyped or purged
        # output directory read as a passed integrity check.
        print(f"ERROR: no pack to verify in {output_dir}", file=sys.stderr)
        return False
    return True


# The source x required combinations --all-variants builds, in build order.
ALL_VARIANTS: tuple[tuple[str, bool], ...] = (
    ("full", False), ("full", True),
    ("platform", False), ("platform", True),
    ("truth", False), ("truth", True),
)


def _pack_label(source: str, required_only: bool) -> str:
    """The variant tag pipeline.parse_pack_counts reads after a pack name."""
    return f"[source={source}, required]" if required_only else f"[source={source}]"


def _truth_layer_is_empty(
    platform: str, platforms_dir: str, emu_profiles: dict, target_cores: set[str] | None
) -> bool:
    """Whether a platform runs no core a profile describes.

    MiSTer declares `cores: []`: its truth pack held nothing, passed its
    check and was published under a name claiming a content.
    """
    config = load_platform_config(platform, platforms_dir)
    return not _platform_cores(config, emu_profiles or {}, target_cores=target_cores)


def _skip_empty_truth(
    args: argparse.Namespace,
    source: str,
    representative: str,
    emu_profiles: dict,
    tc: set[str] | None,
    failed: list[str],
) -> bool:
    """Leave out a truth pack that would be empty, refuse it when asked for."""
    if source != "truth" or not _truth_layer_is_empty(
        representative, args.platforms_dir, emu_profiles, tc
    ):
        return False
    if args.all_variants:
        print(f"  {representative}: no core profile, no truth pack")
    else:
        print(
            f"ERROR: {representative} runs no core a profile describes; "
            "a truth pack would hold nothing",
            file=sys.stderr,
        )
        failed.append(representative)
    return True


def _produced(split: bool, zip_path: str | None, zip_paths: list[str] | None) -> bool:
    """Whether the build wrote what the run asked for."""
    return bool(zip_paths if split else zip_path)


def _run_platform_packs(
    args: argparse.Namespace,
    groups: list[tuple[list[str], str]],
    db: dict,
    zip_contents: dict,
    data_registry: dict | None,
    emu_profiles: dict,
    target_cores_cache: dict[str, set[str] | None],
    system_filter: list[str] | None,
) -> None:
    """Generate ZIP packs for platform groups and verify."""
    variants = ALL_VARIANTS if args.all_variants else ((args.source, args.required_only),)
    registry_path = os.path.join(args.platforms_dir, "_registry.yml")
    # Per pack, the systems each of its files is for, written into its
    # manifest.json once the pack is verified (pack_systems).
    systems_for: dict[str, dict] = {}
    # The packs this run writes, the only ones it verifies and rewrites.
    built: set[str] = set()

    failed: list[str] = []
    for source, required_only in variants:
        for group_platforms, representative in groups:
            aliases = [p for p in group_platforms if p != representative]
            if aliases:
                all_names = [
                    load_platform_config(p, args.platforms_dir).get("platform", p)
                    for p in group_platforms
                ]
                label = " / ".join(all_names)
                print(f"\nGenerating pack for {label} {_pack_label(source, required_only)}...")
            else:
                print(f"\nGenerating pack for {representative} {_pack_label(source, required_only)}...")

            zip_path = None
            zip_paths: list = []
            tc = target_cores_cache.get(representative) if args.target else None
            named_target = platform_target(representative, args.target, args.platforms_dir)
            if _skip_empty_truth(args, source, representative, emu_profiles, tc, failed):
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
                        _group_pack_name(
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
                if not _produced(args.split, zip_path, zip_paths):
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

    all_ok = _finalize_platform_packs(args, db, data_registry, built, systems_for, system_filter)
    if failed:
        # Verification only sees the ZIPs that exist, so a pack that was never
        # written does not fail it.
        print(f"ERROR: no pack for {', '.join(sorted(set(failed)))}", file=sys.stderr)
        sys.exit(1)
    if not all_ok:
        sys.exit(1)


def _group_pack_name(
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


def _finalize_platform_packs(
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


def _refuse_for_all_variants(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Flags --all-variants would override, or modes that never read it."""
    if not args.all_variants:
        return
    # It builds the six source x required combinations itself: a --source
    # or --required-only beside it would be overridden, and the modes that
    # build one pack (emulator, system, hashes) never read it.
    for flag, given in (
        ("--source", args.source is not None),
        ("--required-only", args.required_only),
        ("--no-game-data", getattr(args, "no_game_data", False)),
        ("--emulator", args.emulator),
        ("--from-md5", args.from_md5 or args.from_md5_file),
    ):
        if given:
            parser.error(f"{flag} is incompatible with --all-variants")
    if args.system and not (args.platform or args.all):
        parser.error("--all-variants requires --platform or --all")


def _refuse_refresh_data(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Only the platform pack path refreshes the data directories.

    Elsewhere the cache on disk was packed as it stood, and --offline wins
    over the refresh without a word.
    """
    if args.refresh_data and args.no_refresh_data:
        parser.error("--refresh-data is incompatible with --no-refresh-data")
    for name, given in (("--refresh-data", args.refresh_data),
                        ("--no-refresh-data", args.no_refresh_data)):
        if not given:
            continue
        for flag, on in (
            ("--offline", args.offline),
            ("--emulator", args.emulator),
            ("--system", args.system and not (args.platform or args.all)),
            ("--from-md5", args.from_md5 or args.from_md5_file),
        ):
            if on:
                parser.error(f"{name} is incompatible with {flag}")


def _refuse_unapplied_flags(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Refuse every flag the requested mode would not apply.

    A mode applies a narrowing flag or refuses it: a swallowed flag answers
    about an artifact the caller did not name. Run before any quick-exit
    mode, since --verify-packs and --manifest-targets return early.
    """
    # Parsed before the quick-exit modes: --verify-packs returns early and
    # still needs the region priority list to narrow its expectation.
    args.regions = []
    if args.region:
        try:
            args.regions = region.parse_requested(args.region)
        except ValueError as exc:
            parser.error(str(exc))
        if args.manifest_targets:
            parser.error("--region is incompatible with --manifest-targets")
    if args.one_per_slot and args.manifest_targets:
        parser.error("--one-per-slot is incompatible with --manifest-targets")
    _refuse_refresh_data(args, parser)

    _refuse_for_all_variants(args, parser)
    mode = next(
        (
            name for name, on in (
                ("--manifest-targets", args.manifest_targets),
                ("--verify-packs", args.verify_packs and not args.all_variants),
                ("--list-platforms", args.list),
                ("--list-emulators", args.list_emulators),
                ("--list-systems", args.list_systems),
                ("--list-targets", args.list_targets),
            ) if on
        ),
        None,
    )
    if mode is None:
        return
    given = _given_flags(args)
    for flag in sorted(given - QUICK_MODE_FLAGS[mode] - {mode}):
        parser.error(f"{flag} is incompatible with {mode}")


# What each mode that returns early reads. Anything else given beside it is
# refused: the mode would answer about an artifact the caller did not name.
QUICK_MODE_FLAGS: dict[str, set[str]] = {
    # Checks packs already on disk against the platform's own list, narrowed
    # by region and target and by nothing else.
    "--verify-packs": {
        "--platform", "--all", "--target", "--region", "--no-game-data",
    },
    # One manifest per hardware target, from the target files themselves.
    "--manifest-targets": set(),
    "--list-platforms": set(),
    "--list-emulators": set(),
    "--list-systems": {"--platform"},
    "--list-targets": {"--platform"},
}


def _given_flags(args: argparse.Namespace) -> set[str]:
    """Flags that select or narrow what a run produces, as typed."""
    flags = {
        "--platform": args.platform,
        "--all": args.all,
        "--emulator": args.emulator,
        "--system": args.system,
        "--standalone": args.standalone,
        "--split": args.split,
        "--group-by": args.group_by is not None,
        "--manifest": args.manifest,
        "--manifest-targets": args.manifest_targets,
        "--verify-packs": args.verify_packs,
        "--all-variants": args.all_variants,
        "--from-md5": args.from_md5,
        "--from-md5-file": args.from_md5_file,
        "--required-only": args.required_only,
        "--no-game-data": getattr(args, "no_game_data", False),
        "--source": args.source is not None,
        "--target": args.target,
        "--region": args.region,
        "--one-per-slot": args.one_per_slot,
        "--list-platforms": args.list,
        "--list-emulators": args.list_emulators,
        "--list-systems": args.list_systems,
        "--list-targets": args.list_targets,
        "--refresh-data": args.refresh_data,
        "--no-refresh-data": args.no_refresh_data,
    }
    return {flag for flag, on in flags.items() if on}


def main() -> None:
    # One run's account: tests call main() repeatedly in one process, and a
    # notice left by an earlier run failed a later one that missed nothing.
    MISSING_DATA_DIRS.clear()
    with contextlib.ExitStack() as held:
        try:
            _main(held)
        except DamagedArchiveError as exc:
            # Emulator, system and hash modes have no per-platform loop to
            # report it: the run stops with the file to restore.
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(1)
    if MISSING_DATA_DIRS:
        print(
            "ERROR: packs written without data directories that are not cached: "
            f"{', '.join(sorted(MISSING_DATA_DIRS))} (run refresh_data_dirs.py)",
            file=sys.stderr,
        )
        sys.exit(1)


def _build_parser() -> argparse.ArgumentParser:
    """The command line of generate_pack.py."""
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Generate platform BIOS ZIP packs")
    parser.add_argument(
        "--platform", "-p", type=platform_arg,
        help="Platform name (e.g., retroarch)",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Generate the release packs (release_pack in the registry), or with"
        " --manifest the install manifests of every platform",
    )
    add_emulator_selection(parser)
    add_repo_inputs(parser, "platforms", "db", "bios")
    parser.add_argument(
        "--output-dir", "-o", default=DEFAULT_OUTPUT_DIR,
        help="directory the packs and manifests go to (default: %(default)s)",
    )
    add_repo_inputs(parser, "emulators")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="No network at all: data directories and release assets come "
        "from the cache only, so a gitignored file never fetched is missing "
        "(--no-refresh-data keeps the trees as cached and still fetches assets)",
    )
    parser.add_argument(
        "--refresh-data",
        action="store_true",
        help="Force re-download all data directories",
    )
    parser.add_argument(
        "--no-refresh-data",
        action="store_true",
        help="Pack the data directories as cached, still fetching release assets",
    )
    # install.py's name. --list stays for the scripts that already type it.
    parser.add_argument(
        "--list-platforms", "--list", dest="list", action="store_true",
        help="List available platforms",
    )
    parser.add_argument(
        "--required-only",
        action="store_true",
        help="Only include required files, skip optional",
    )
    parser.add_argument(
        "--no-game-data",
        action="store_true",
        help="Leave out game data (the platform's entries a core reads as a "
        "game's files, and the cores' game data files): firmware only",
    )
    parser.add_argument(
        "--source",
        choices=["platform", "truth", "full"],
        default=None,
        help="File source: platform (YAML only), truth (emulator profiles), full "
             "(both, the default)",
    )
    parser.add_argument(
        "--all-variants",
        action="store_true",
        help="Generate all 6 source x required combinations",
    )
    parser.add_argument(
        "--split", action="store_true", help="Generate one ZIP per system/manufacturer"
    )
    parser.add_argument(
        "--group-by",
        choices=["system", "manufacturer"],
        default=None,
        help="Grouping for --split (default: system)",
    )
    parser.add_argument("--target", "-t", help="Hardware target (e.g., switch, rpi4)")
    parser.add_argument(
        "--region",
        help="Region priority list, best first (e.g. us,eu,jp)",
    )
    parser.add_argument(
        "--one-per-slot",
        action="store_true",
        help="Keep one BIOS per system and region where the core declares an order",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="List available targets for the platform",
    )
    parser.add_argument(
        "--from-md5",
        help="Hash(es) to look up or pack, comma-separated: CRC32, MD5, SHA-1 or SHA-256",
    )
    parser.add_argument(
        "--from-md5-file",
        help="File with hashes, one per line, alone or beside a file name as md5sum writes it",
    )
    parser.add_argument(
        "--manifest",
        action="store_true",
        help="Output JSON manifests instead of ZIP packs",
    )
    parser.add_argument(
        "--manifest-targets",
        action="store_true",
        help="Convert target YAMLs to installer JSON",
    )
    parser.add_argument(
        "--verify-packs",
        action="store_true",
        help="Extract and verify pack integrity (path + hash)",
    )
    return parser


def _run_quick_mode(
    args: argparse.Namespace, parser: argparse.ArgumentParser, held: contextlib.ExitStack,
) -> bool:
    """Run a mode that builds nothing (a check of existing packs, the target
    lists, a listing). True when one ran."""
    # Quick-exit modes: --verify-packs alone = verify existing packs only
    # Combined with --all-variants, generation runs first then verify
    if args.verify_packs and not args.all_variants:
        # The check resolves core files against data/ like the build did,
        # and a refresh swapping a tree mid-check would judge another tree.
        hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))
        with _pack_output_lock(args.output_dir, exclusive=False):
            _run_verify_packs(args)
        return True
    if args.manifest_targets:
        _refuse_mixed_output(args.output_dir, "targets")
        with _pack_output_lock(args.output_dir):
            generate_target_manifests(
                os.path.join(args.platforms_dir, "targets"), args.output_dir
            )
        return True
    if args.list:
        print_platform_listing(args.platforms_dir)
        return True
    if args.list_emulators:
        list_emulator_profiles(args.emulators_dir)
        return True
    if args.list_systems:
        if args.platform:
            list_platform_system_ids(args.platform, args.platforms_dir)
        else:
            list_system_ids(args.emulators_dir)
        return True
    if args.list_targets:
        if not args.platform:
            parser.error("--list-targets requires --platform")
        from model.targets import list_available_targets

        targets = list_available_targets(args.platform, args.platforms_dir)
        if not targets:
            print(f"No targets configured for platform '{args.platform}'")
            return True
        for t in targets:
            print(target_listing_line(t))
        return True
    return False


def _run_hash_mode(args: argparse.Namespace) -> None:
    """--from-md5 and --from-md5-file: look the hashes up, or pack them."""
    try:
        hashes = (
            parse_hash_input(args.from_md5)
            if args.from_md5
            else parse_hash_file(args.from_md5_file)
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"ERROR: --from-md5-file {args.from_md5_file}: {exc.strerror}", file=sys.stderr)
        sys.exit(1)
    if not hashes:
        print(
            f"ERROR: no hash in the input. Accepted: {ACCEPTED_HASHES}",
            file=sys.stderr,
        )
        sys.exit(1)
    db = load_database(args.db)
    if not args.platform and not args.emulator:
        # A lookup that found nothing is an answer a script must see.
        if lookup_hashes(
            hashes, db, args.bios_dir, args.emulators_dir, args.platforms_dir
        ):
            sys.exit(1)
        return
    zip_contents = build_zip_contents_index(db)
    with _pack_output_lock(args.output_dir):
        result = generate_md5_pack(
            hashes=hashes,
            db=db,
            bios_dir=args.bios_dir,
            output_dir=args.output_dir,
            zip_contents=zip_contents,
            platform_name=args.platform,
            platforms_dir=args.platforms_dir,
            emulator_name=args.emulator,
            emulators_dir=args.emulators_dir,
            standalone=getattr(args, "standalone", False),
        )
    if not result:
        sys.exit(1)


def _run_profile_mode(args: argparse.Namespace, db: dict, zip_contents: dict) -> None:
    """--emulator, or --system without a platform: the emulators' own layout."""
    # Emulator mode
    if args.emulator:
        names = [n.strip() for n in args.emulator.split(",") if n.strip()]
        with _pack_output_lock(args.output_dir):
            built = generate_emulator_pack(
                names,
                args.emulators_dir,
                db,
                args.bios_dir,
                args.output_dir,
                args.standalone,
                zip_contents=zip_contents,
                required_only=args.required_only,
                regions=getattr(args, "regions", None),
                offline=args.offline,
                platforms_dir=args.platforms_dir,
            )
        if built is None:
            sys.exit(1)
        return

    # System mode (standalone, without platform context)
    system_ids = [s.strip() for s in args.system.split(",") if s.strip()]
    with _pack_output_lock(args.output_dir):
        built = generate_system_pack(
            system_ids,
            args.emulators_dir,
            db,
            args.bios_dir,
            args.output_dir,
            args.standalone,
            zip_contents=zip_contents,
            required_only=args.required_only,
            regions=getattr(args, "regions", None),
            offline=args.offline,
            platforms_dir=args.platforms_dir,
        )
    if built is None:
        sys.exit(1)


def _requested_platforms(args: argparse.Namespace, parser: argparse.ArgumentParser) -> list[str]:
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


def _refresh_data_directories(args: argparse.Namespace, data_registry: dict) -> None:
    """Bring the data directory caches up to date before a build reads them."""
    from packs.datadirs import refresh_all

    results = refresh_all(data_registry, force=args.refresh_data)
    updated = sum(1 for v in results.values() if v)
    if updated:
        print(f"Refreshed {updated} data director{'ies' if updated > 1 else 'y'}")
    failed = sorted(k for k, v in results.items() if v is None)
    if failed:
        print(f"WARNING: data directory refresh failed: {', '.join(failed)}")


def _run_platform_mode(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    held: contextlib.ExitStack,
    db: dict,
    zip_contents: dict,
) -> None:
    """--platform or --all: packs or manifests in each platform's layout."""
    system_filter = getattr(args, "system_ids", None)

    # Platform mode
    platforms = _requested_platforms(args, parser)

    # A mistyped target is refused before the output lock and the data
    # directory refresh: checked after them, `--target swich` waited on a
    # pipeline's caches before saying the target does not exist.
    target_cores_cache, platforms = target_scope(
        platforms, args.target, args.platforms_dir, is_all=args.all
    )

    emu_profiles = load_emulator_profiles(args.emulators_dir)
    if system_filter:
        platforms = _platforms_with_systems(
            args, platforms, system_filter, emu_profiles, target_cores_cache
        )
    platforms = without_profile_blind(
        platforms,
        [
            flag for flag, given in (
                ("--region", getattr(args, "regions", None)),
                ("--one-per-slot", getattr(args, "one_per_slot", False)),
                ("--no-game-data", getattr(args, "no_game_data", False)),
            ) if given
        ],
        args.platforms_dir,
        emu_profiles,
        target_cores_cache if args.target else None,
        args.all,
    )

    data_registry = load_data_dir_registry(args.platforms_dir)
    # The output directory is claimed before the data directory refresh: a
    # refresh waits for every run that holds a cache, so a second build
    # during a pipeline sat silent for hours instead of being refused.
    with _pack_output_lock(args.output_dir):
        if data_registry and not args.offline and not args.no_refresh_data:
            _refresh_data_directories(args, data_registry)
        if data_registry:
            hold_data_dirs(held, data_registry)

        groups = group_identical_platforms(
            platforms, args.platforms_dir, target_cores_cache if args.target else None
        )

        if args.manifest:
            _refuse_mixed_output(args.output_dir, "manifest")
            _run_manifest_mode(
                args, groups, db, zip_contents, emu_profiles, target_cores_cache
            )
        else:
            _run_platform_packs(
                args,
                groups,
                db,
                zip_contents,
                data_registry,
                emu_profiles,
                target_cores_cache,
                system_filter,
            )
    if not args.manifest and args.verify_packs:
        with _pack_output_lock(args.output_dir, exclusive=False):
            _run_verify_packs(args)


def _main(held: contextlib.ExitStack) -> None:
    parser = _build_parser()
    args = parser.parse_args()
    from model.cliargs import work_from_repo_root

    work_from_repo_root(
        args, parser,
        ["db", "platforms_dir", "bios_dir", "output_dir", "emulators_dir", "from_md5_file"],
    )
    packresolve.set_offline(bool(args.offline))
    if args.platform:
        require_platform(args.platform, args.platforms_dir)
    require_directory(args.bios_dir)

    _refuse_unapplied_flags(args, parser)
    _refuse_for_verify_packs(args, parser)
    if _run_quick_mode(args, parser, held):
        return

    _validate_args(args, parser)
    _resolve_systems(args, parser)
    # Unset until every refusal has run, so a typed default value is seen.
    args.source = args.source or "full"
    args.group_by = args.group_by or "system"

    # Hash lookup / pack mode
    # A platform run may refresh the trees below, under the exclusive lock:
    # it takes the shared ones after that. Every other mode reads them now.
    if not (args.platform or args.all) or args.offline or args.no_refresh_data:
        hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))
    if args.from_md5 or getattr(args, "from_md5_file", None):
        _run_hash_mode(args)
        return

    db = load_database(args.db)
    zip_contents = build_zip_contents_index(db)
    if args.emulator or (args.system and not args.platform and not args.all):
        _run_profile_mode(args, db, zip_contents)
        return
    _run_platform_mode(args, parser, held, db, zip_contents)


def _write_standalone_layouts(output_dir: str, platform: str, layouts: dict) -> str:
    """install/standalone/<platform>.json, what --standalone reads beside the
    list. Its [dest, sha1] items take their download from that list."""
    path = os.path.join(output_dir, STANDALONE_DIR, f"{platform}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    write_if_changed(path, json.dumps({
        "schema": 1, "platform": platform, "standalone_layouts": layouts,
    }, indent=2))
    return path


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
