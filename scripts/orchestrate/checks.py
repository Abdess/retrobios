"""Steps 5 and 6: verify against the packs it describes, then the packs' integrity."""

from __future__ import annotations

import argparse
import sys

from core.paths import PLATFORMS_DIR
from model.registry import list_release_pack_platforms
from orchestrate import runner
from orchestrate.consistency import check_consistency, check_pack_destinations
from orchestrate.emulatorpacks import check_emulator_packs
from orchestrate.labels import STEP_LABELS, skip_notice, step_title
from orchestrate.narrowed import check_narrowed_packs
from orchestrate.results import SKIPPED
from orchestrate.splitcheck import check_split_packs


def integrity_command(args: argparse.Namespace) -> list[str]:
    """Step 6: check the packs step 4 built, under the same expectation."""
    cmd = [
        sys.executable, "scripts/generate_pack.py", "--all", "--verify-packs",
        "--output-dir", args.output_dir,
    ]
    # Without the target a targeted run reported every system the target
    # removed as missing from a pack that was exactly right. Without
    # --all-variants the five narrowed packs were never opened, and an empty
    # _Platform pack passed.
    if args.target:
        cmd.extend(["--target", args.target])
    if args.all_variants:
        cmd.append("--all-variants")
    return cmd


def check_steps(
    args: argparse.Namespace,
    results: dict,
    *,
    pack_counts_file: str,
    destinations_file: str,
) -> bool:
    """Steps 5 and 6: verify against the packs, then the packs' integrity."""
    all_ok = True
    # Step 5: Consistency check. verify describes the full pack, and a run that
    # built only a reduced one (--source platform or truth) has nothing to
    # compare it with, and says so instead of failing on an empty parse.
    full_pack_built = args.source == "full" or args.all_variants
    if pack_counts_file and not full_pack_built:
        skip_notice("consistency", "no full pack built")
        results["consistency"] = SKIPPED
    elif pack_counts_file:
        ok = check_consistency(
            destinations_file, pack_counts_file,
            set(list_release_pack_platforms(PLATFORMS_DIR)),
        )
        # Counts can agree while the paths differ, both ways at once.
        ok = check_pack_destinations(destinations_file, pack_counts_file) and ok
        ok = check_emulator_packs(full=args.full_narrowings) and ok
        ok = check_narrowed_packs(full=args.full_narrowings) and ok
        ok = check_split_packs() and ok
        print(
            f"--- {step_title(STEP_LABELS['consistency'])}, counts and paths: "
            f"{'OK' if ok else 'FAILED'} ---"
        )
        results["consistency"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("consistency")
        results["consistency"] = SKIPPED

    # Step 6: Pack integrity (extract + hash verification)
    if not args.skip_packs and not full_pack_built:
        # The check reads the full pack's name, while a reduced pack holds fewer
        # files than the platform declares by design.
        skip_notice("pack_integrity", "no full pack built")
        results["pack_integrity"] = SKIPPED
    elif not args.skip_packs:
        ok, _ = runner.run(integrity_command(args), STEP_LABELS["pack_integrity"])
        results["pack_integrity"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("pack_integrity", "--skip-packs")
        results["pack_integrity"] = SKIPPED
    return all_ok
