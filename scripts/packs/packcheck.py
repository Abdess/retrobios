"""--verify-packs: each pack in an output directory checked against its platform."""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass

from core.text import count_text
from model.database import load_database
from model.profiles import load_emulator_profiles
from model.registry import list_release_pack_platforms, load_data_dir_registry
from model.targets import target_scope
from packs.finalize import baseline_shortfall
from packs.integrity import verify_pack_against_platform
from packs.naming import expected_pack_names, pack_variant
from packs.variants import ALL_VARIANTS


@dataclass(frozen=True)
class PackCheck:
    """What --verify-packs checks every pack against."""

    db: dict
    platforms_dir: str
    emulators_dir: str
    profiles: dict
    regions: list[str] | None
    data_registry: dict
    no_game_data: bool


def verify_packs_scope(args: argparse.Namespace) -> tuple[list[str], dict[str, set[str] | None]]:
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


def _check_pack(
    check: PackCheck, platform_name: str, pack_name: str, zip_path: str,
    tc: set[str] | None,
) -> list[str] | None:
    """Check one pack and print its line. Its errors, or None when it passed."""
    variant = pack_variant(pack_name)
    if variant is None:
        # One BIOS per slot: the slot choice is not replayed here.
        print(
            f"  {platform_name} [{pack_name}]: hashes checked during the build; "
            "one per slot by design, so not compared to the platform's full list"
        )
        return None
    source, required_only = variant
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
        return None
    print(f"  {platform_name} [{pack_name}]: FAIL ({counts}, {len(errors)} errors)")
    for err in errors:
        print(f"    {err}")
    return errors


def run_verify_packs(args: argparse.Namespace) -> bool:
    """Verify each pack in the output directory against its platform. False
    when one failed or none was found.

    Delegates to verify_pack_against_platform so the command answers the same
    question the pipeline asks: baseline files, core extras and structure. A
    second implementation here answered a narrower one and reported OK while
    the core extras went unchecked.
    """
    verify_db = load_database(args.db)
    platforms, target_cores_cache = verify_packs_scope(args)

    all_ok = True
    check = PackCheck(
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
            zip_path = os.path.join(args.output_dir, pack_name)
            if _check_pack(check, platform_name, pack_name, zip_path, tc) is not None:
                all_ok = False
                failing.append(f"{platform_name} ({pack_name})")

    return verification_summary(failing, verified, args.output_dir) and all_ok


def verification_summary(failing: list[str], verified: int, output_dir: str) -> bool:
    """Print how --verify-packs ended. False when nothing was verified."""
    if failing:
        # Named at the end, where the log is read, and on stderr, as the
        # build path does: a failing pack sat among its own error lines.
        print(
            f"ERROR: packs failed verification: {', '.join(failing)}",
            file=sys.stderr,
        )
    elif verified:
        print(f"Verified {count_text(verified, 'pack')}: all OK")
    if not verified:
        # Every platform skipped is no check at all: a mistyped or purged
        # output directory read as a passed integrity check.
        print(f"ERROR: no pack to verify in {output_dir}", file=sys.stderr)
        return False
    return True
