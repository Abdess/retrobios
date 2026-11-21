"""Steps 0 to 2e: schemas, database, catalogs and recipes, upstream refreshes, truth and export."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

from orchestrate import runner
from orchestrate.labels import STEP_LABELS, skip_notice
from orchestrate.results import SKIPPED


def database_steps(results: dict) -> bool:
    """Steps 0 to 1c: schemas, database, dump catalogs, romset recipes."""
    all_ok = True
    # Step 0: the schema check PR validation runs. Without it a profile with
    # `cores: [81]` unquoted passed the whole pipeline and failed CI on push.
    # jsonschema is tooling only, so its absence skips the step.
    if importlib.util.find_spec("jsonschema") is None:
        # The skip names the install and what still runs the check, or a
        # contributor read SKIPPED, then COMPLETE, and met the failure on push.
        skip_notice(
            "validate_schemas",
            "jsonschema not installed. PR validation runs this check: "
            'pip install "jsonschema[format-nongpl]"',
        )
        results["validate_schemas"] = SKIPPED
    else:
        ok, _ = runner.run(
            [sys.executable, "scripts/validate_schemas.py", "--source-only"],
            STEP_LABELS["validate_schemas"],
        )
        results["validate_schemas"] = ok
        all_ok = all_ok and ok

    # Step 1: Generate database
    ok, _ = runner.run(
        [
            sys.executable,
            "scripts/generate_db.py",
            "--force",
            "--bios-dir",
            "bios",
            "--output",
            "database.json",
        ],
        STEP_LABELS["generate_db"],
    )
    results["generate_db"] = ok
    if not ok:
        print("\nDatabase generation failed, aborting.")
        sys.exit(1)

    # Step 1b: Dump-catalog coverage (offline, reads provenance/ snapshots),
    # and which missing dumps the collection already produces: recorded in
    # derivable.json, which the site reads instead of rereading bios/.
    ok, _ = runner.run(
        [sys.executable, "scripts/provenance_report.py", "--derive",
         "--write-derivable", "derivable.json"],
        STEP_LABELS["provenance"],
    )
    results["provenance"] = ok
    all_ok = all_ok and ok

    # Step 1c: Which emulator version each arcade archive corresponds to, and
    # which pinned archive the collection could rebuild from ROMs it holds.
    # Read-only: writing reconstructions is an explicit --write invocation.
    ok, _ = runner.run(
        [sys.executable, "scripts/romset_recipes.py"],
        STEP_LABELS["romset_recipes"],
    )
    # A recipe for every archive database.json lists (recipes/archives.json):
    # only an archive whose sha1 moved is read again, so the step costs the
    # archives added since the last run.
    captured, _ = runner.run(
        [sys.executable, "scripts/romset_recipes.py", "--capture"],
        f"{STEP_LABELS['romset_recipes']} (archive recipes)",
    )
    ok = ok and captured
    results["romset_recipes"] = ok
    all_ok = all_ok and ok
    return all_ok


def refresh_steps(args: argparse.Namespace, results: dict) -> bool:
    """Steps 2 to 2b2: data directories, hash scrapers, release assets."""
    all_ok = True
    # Step 2: Refresh data directories
    if not args.offline:
        ok, _ = runner.run(
            [sys.executable, "scripts/refresh_data_dirs.py"],
            STEP_LABELS["refresh_data"],
        )
        results["refresh_data"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("refresh_data", "--offline")
        results["refresh_data"] = SKIPPED

    # Step 2a: Refresh MAME BIOS hashes
    if not args.offline:
        ok, _ = runner.run(
            [sys.executable, "-m", "scripts.scraper.mame_hash_scraper"],
            STEP_LABELS["mame_hashes"],
        )
        results["mame_hashes"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("mame_hashes", "--offline")
        results["mame_hashes"] = SKIPPED

    # Step 2a2: Refresh FBNeo BIOS hashes
    if not args.offline:
        ok, _ = runner.run(
            [sys.executable, "-m", "scripts.scraper.fbneo_hash_scraper"],
            STEP_LABELS["fbneo_hashes"],
        )
        results["fbneo_hashes"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("fbneo_hashes", "--offline")
        results["fbneo_hashes"] = SKIPPED

    # Step 2b: Check buildbot system directory (non-blocking)
    if args.check_buildbot and not args.offline:
        ok, _ = runner.run(
            [sys.executable, "scripts/check_buildbot_system.py"],
            STEP_LABELS["check_buildbot"],
        )
        results["check_buildbot"] = ok
    else:
        if args.check_buildbot:
            skip_notice("check_buildbot", "--offline")
        results["check_buildbot"] = SKIPPED

    # Step 2b2: The release must serve the bytes the manifests describe. The
    # installer compares Content-Length with the manifest size, so an asset
    # uploaded before its local file was rebuilt fails every install of it.
    if not args.offline:
        ok, _ = runner.run(
            [sys.executable, "scripts/check_release_assets.py"],
            STEP_LABELS["check_release_assets"],
        )
        results["check_release_assets"] = ok
        all_ok = all_ok and ok
    else:
        skip_notice("check_release_assets", "--offline")
        results["check_release_assets"] = SKIPPED
    return all_ok


def truth_steps(args: argparse.Namespace, results: dict) -> bool:
    """Steps 2c to 2e: truth model, its diff, the native export."""
    all_ok = True
    # Step 2c: Generate truth YAMLs
    # A targeted run writes each platform's model under the target as that
    # platform files it, and the diff is told the target and reads the same place.
    truth_dir = Path(args.output_dir) / "truth"

    if args.with_truth or args.with_export:
        truth_cmd = [
            sys.executable,
            "scripts/generate_truth.py",
            "--all",
            "--output-dir",
            str(Path(args.output_dir) / "truth"),
        ]
        if args.target:
            truth_cmd.extend(["--target", args.target])
        ok, _ = runner.run(truth_cmd, STEP_LABELS["generate_truth"])
        # A native file is one per platform, never per target: the export
        # corrects it against the full model, which a targeted run does not
        # write.
        if ok and args.with_export and args.target:
            ok, _ = runner.run(truth_cmd[:-2], "2c generate truth (export model)")
        results["generate_truth"] = ok
        all_ok = all_ok and ok
    else:
        results["generate_truth"] = SKIPPED

    # Step 2d: Diff truth vs scraped
    if args.with_truth or args.with_export:
        diff_cmd = [sys.executable, "scripts/diff_truth.py", "--all"]
        diff_cmd.extend(["--truth-dir", str(truth_dir)])
        if args.target:
            diff_cmd.extend(["--target", args.target])
        ok, _ = runner.run(diff_cmd, STEP_LABELS["diff_truth"])
        results["diff_truth"] = ok
        all_ok = all_ok and ok
    else:
        results["diff_truth"] = SKIPPED

    # Step 2e: Export native formats
    if args.with_export:
        export_cmd = [
            sys.executable,
            "scripts/export_native.py",
            "--all",
            # exports/ is committed with the code, like README.md and
            # install/: written under the pack directory it went stale on
            # every green run.
            "--truth-dir",
            str(Path(args.output_dir) / "truth"),
        ]
        # Seven of the formats carry code, so the export patches the
        # platform's own file rather than regenerating it. Offline that
        # file has to be in the cache already.
        if not args.offline:
            export_cmd.append("--fetch")
        ok, _ = runner.run(export_cmd, STEP_LABELS["export_native"])
        results["export_native"] = ok
        all_ok = all_ok and ok
    else:
        results["export_native"] = SKIPPED

    return all_ok
