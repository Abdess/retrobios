#!/usr/bin/env python3
"""Run the full retrobios pipeline.

Steps, numbered as the run prints them:
  0    validate_schemas.py          profiles and platform YAMLs, as PR CI checks them
  1    generate_db.py --force       rebuild database.json from bios/
  1b   provenance_report.py         dump-catalog coverage, derivable.json
  1c   romset_recipes.py            archive identification, reconstruction targets,
                                    and --capture: recipes/archives.json
  2    refresh_data_dirs.py         Dolphin Sys, PPSSPP assets and the other trees
  2a   mame_hash_scraper            MAME BIOS hashes, and device sets on a new release
  2a2  fbneo_hash_scraper           FBNeo BIOS hashes
  2b   check_buildbot_system.py     buildbot freshness (--check-buildbot)
  2b2  check_release_assets.py      large-files release vs gitignored files
  2c   generate_truth.py            truth models (--with-truth, --with-export)
  2d   diff_truth.py                truth vs scraped platforms
  2e   export_native.py             corrected native files (--with-export)
  3    verify.py --all              every platform, native logic
  3a   identity.py --strict         one content under two identities
  3b   slots.py                     destinations both layers claim
  4    generate_pack.py --all       ZIP packs
  4b   generate_pack.py --manifest  install manifests
  4c   --manifest-targets           per-target core lists
  4d   bundled_only.py --strict     copies only an emulator install provides
  4e   generate_games_index.py      install/games/: what the games-on-card mode reads
  5    consistency check            verify == pack: counts, paths, emulator and system packs,
                                    narrowed platform packs (see check_narrowed_packs)
  6    --verify-packs               pack integrity, extraction and hashes
  7    generate_readme.py           README.md and CONTRIBUTING.md
       generate_installer_doc.py    run samples and tables of wiki/installer.md
       generate_report_excerpt.py   the verify excerpt of wiki/reading-reports.md
  8    generate_site.py             site pages, into the Starlight project in website/
  8b   npm run build (website/)     rendered as the site deploy renders it, then validate_site.py

--offline skips 2 to 2b2 and the network side of 2e and 4: release assets
come from .cache/large/ only.

Usage:
    python scripts/pipeline.py                    # every registered platform
    python scripts/pipeline.py --skip-packs       # skip steps 4, 4b, 4c, 5 and 6
    python scripts/pipeline.py --skip-docs        # skip steps 7, 8 and 8b
    python scripts/pipeline.py --offline          # no network, see above
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# The build scripts need CPython 3.9, which builds the same database,
# manifests and packs as 3.12.
# On an older interpreter the run got through the first steps and failed in
# the packs, so it stops before step 0. A test compiles every script under
# this floor.
if sys.version_info < (3, 9):
    sys.exit(f"pipeline.py needs Python 3.9 or newer, this is {sys.version.split()[0]}")

sys.path.insert(0, str(Path(__file__).parent))
from core.github import github_token
from orchestrate.build import index_steps, pack_steps, verify_steps
from orchestrate.checks import check_steps
from orchestrate.docs import docs_steps
from orchestrate.guards import (
    refuse_offline_export_without_originals,
    refuse_offline_without_caches,
    refuse_unapplied_flags,
)
from orchestrate.locks import hold_outputs
from orchestrate.prepare import database_steps, refresh_steps, truth_steps
from orchestrate.results import StepResults, print_summary
from orchestrate.runner import enter_repo_root, pack_output_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Run the full retrobios pipeline")
    parser.add_argument(
        "--skip-packs",
        action="store_true",
        help="Skip steps 4, 4b, 4c, 5 and 6: packs, manifests and their checks. "
        "Step 4d still gates the run, step 4e still rewrites install/games/, and "
        "steps 7 to 8b rewrite README.md and the site unless --skip-docs is given",
    )
    parser.add_argument(
        "--skip-docs", action="store_true",
        help="Skip steps 7, 8 and 8b: README, installer page and site"
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="No network: skips steps 2 to 2b2 and packs only the release "
        "assets already in .cache/large/"
    )
    parser.add_argument(
        "--output-dir",
        help="Pack output directory (default: dist/ at the repository root)",
    )
    parser.add_argument("--target", "-t", help="Hardware target (e.g., switch, rpi4)")
    parser.add_argument(
        "--source", choices=["platform", "truth", "full"], default=None,
        help="packs to build: the platform list, the profiles, or both (default: "
             "full)",
    )
    parser.add_argument(
        "--all-variants", action="store_true",
        help="Build the six source x required packs of each platform; "
        "not with --source or --skip-packs",
    )
    parser.add_argument(
        "--full-narrowings", action="store_true",
        help="Step 5 compares every region, target and system of each "
        "platform, and every region of each emulator and system pack, not a "
        "sample of three (about 25 minutes)",
    )
    parser.add_argument(
        "--check-buildbot",
        action="store_true",
        help="Check buildbot system directory for changes",
    )
    parser.add_argument(
        "--with-truth",
        action="store_true",
        help="Generate truth YAMLs and diff against scraped",
    )
    parser.add_argument(
        "--with-export",
        action="store_true",
        help="Export native formats (implies --with-truth)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    refuse_unapplied_flags(parser, args)
    args.output_dir = pack_output_dir(args.output_dir)
    enter_repo_root()
    refuse_offline_without_caches(parser, args)
    refuse_offline_export_without_originals(parser, args)
    if not args.offline:
        # Read once and put in the environment every step inherits: the
        # scrapers and refresh_data_dirs went anonymous unless the user had
        # exported GITHUB_TOKEN by hand, though gh was logged in.
        github_token()
    held = hold_outputs(args)

    total_start = time.monotonic()
    results = StepResults(total_start)

    all_ok = database_steps(args, results)
    all_ok = refresh_steps(args, results) and all_ok
    all_ok = truth_steps(args, results) and all_ok
    ok, destinations_file = verify_steps(args, results, held)
    all_ok = all_ok and ok
    ok, pack_counts_file = pack_steps(args, results)
    all_ok = all_ok and ok
    all_ok = index_steps(results) and all_ok
    all_ok = check_steps(
        args, results, pack_counts_file=pack_counts_file,
        destinations_file=destinations_file,
    ) and all_ok
    all_ok = docs_steps(args, results) and all_ok

    print_summary(results, total_start, all_ok)
    held.close()
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
