#!/usr/bin/env python3
"""Confront every transcribed layer with what its upstream serves today.

Each layer the repository transcribes moves on its own schedule: platform
lists, hardware targets, core-info, buildbot system assets, dump catalogs,
romset DATs, the CI toolchain. This script asks each of them the same
question, is the local copy the one upstream serves, and answers with one
row per subject.

Platform and target files are re-scraped through the scrapers' own write path
into a throwaway copy, then diffed against the committed file. The diff
decides, not a version string: a scraper that pins a new tag but produces
the same entries is reported as a version change and nothing else.

The native export patches each platform's own file, kept in a local cache.
That cache is checked against the platform file it was transcribed with: an
original cached before the last rescrape, or under another pin, is no longer
the file our data describes.

Emulator profiles are covered by profile_sync, which is slow (one API pass
per profile). ``--profiles`` runs it here and folds its verdict in.

Usage:
    python scripts/check_freshness.py
    python scripts/check_freshness.py --only platforms,targets
    python scripts/check_freshness.py --json
    python scripts/check_freshness.py --profiles
    python scripts/check_freshness.py --offline      # local age checks only
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import upstream
from core.cli import InputMissing, add_repo_inputs, require_directory
from core.paths import REPO_ROOT, TRUTH_DIR
from exporter.originals import DEFAULT_CACHE
from freshness.catalogs import check_catalogs
from freshness.ci import check_ci
from freshness.coreinfo import CORE_INFO_RECORD, check_coreinfo, core_info_blobs, record_core_info
from freshness.data import check_data
from freshness.findings import AREAS, SKIPPED, Finding
from freshness.native import check_native
from freshness.pinbuilds import check_pin_builds
from freshness.platforms import check_emulatorjs, check_platforms
from freshness.profiles import check_profiles, check_source_paths
from freshness.report import exit_code, render, unknown_areas_message
from freshness.romfolders import check_romfolders
from freshness.targets import check_lakka_release, check_targets
from model.profiles import load_emulator_profiles


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n\n")[0])
    # Joined with ", " so argparse wraps between names: one comma-joined
    # token was cut inside "coreinfo".
    parser.add_argument(
        "--only", metavar="AREAS",
        help="comma-separated areas, among: " + ", ".join(AREAS),
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--profiles", action="store_true",
        help="also run profile_sync (slow)",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="no network, local ages only",
    )
    parser.add_argument("--jobs", type=int, default=4, help="parallel scrapers")
    parser.add_argument(
        "--cache-dir", default=upstream.CACHE_DIR,
        help="download cache directory (default: %(default)s)",
    )
    parser.add_argument(
        "--native-cache-dir", default=DEFAULT_CACHE,
        help="where the platforms' own files are cached (default: %(default)s)",
    )
    parser.add_argument(
        "--truth-dir", default=TRUTH_DIR,
        help="directory of the truth models generate_truth writes (default: "
             "%(default)s)",
    )
    add_repo_inputs(parser, "platforms", "emulators")
    parser.add_argument(
        "--record-coreinfo", nargs="*", metavar="CORE",
        help="record the current .info of CORE (every core when none is named) "
             f"as reviewed in {CORE_INFO_RECORD.relative_to(REPO_ROOT)}, then exit",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.record_coreinfo is not None:
        blobs = core_info_blobs(args.cache_dir, args.offline)
        if not blobs:
            raise InputMissing(
                f"core-info listing not in {args.cache_dir}: run without --offline"
                if args.offline else "core-info listing unavailable: the GitHub API did not answer"
            )
        done = record_core_info(blobs, args.record_coreinfo)
        print(f"recorded {len(done)} .info file(s) as reviewed")
        return 0

    areas = tuple(a.strip() for a in args.only.split(",")) if args.only else AREAS
    unknown = sorted(set(areas) - set(AREAS))
    if unknown:
        parser.error(unknown_areas_message(unknown))

    require_directory(args.platforms_dir, "--platforms-dir")
    platforms_dir = Path(args.platforms_dir)
    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    findings: list[Finding] = []
    with tempfile.TemporaryDirectory(prefix="freshness-", dir=REPO_ROOT / "tmp" if (REPO_ROOT / "tmp").is_dir() else None) as scratch:
        workdir = Path(scratch)
        if "platforms" in areas:
            findings.extend(
                [Finding("platforms", "scrapers", SKIPPED, detail="offline")]
                if args.offline
                else check_platforms(platforms_dir, workdir, args.jobs)
            )
            findings.append(check_emulatorjs(platforms_dir, args.offline))
        if "native" in areas:
            findings.extend(
                check_native(platforms_dir, Path(args.native_cache_dir), Path(args.truth_dir))
            )
        if "targets" in areas:
            findings.extend(check_targets(platforms_dir, workdir, profiles, args.jobs, args.offline))
            findings.append(check_lakka_release(platforms_dir, args.cache_dir, args.offline))
    if "romfolders" in areas:
        findings.extend(check_romfolders(platforms_dir, args.cache_dir, args.offline))
    if "coreinfo" in areas:
        findings.extend(check_coreinfo(profiles, args.cache_dir, args.offline))
    if "data" in areas:
        findings.extend(check_data(platforms_dir, args.offline))
    if "catalogs" in areas:
        findings.extend(check_catalogs(args.cache_dir, args.offline))
    if "ci" in areas:
        findings.extend(check_ci(args.cache_dir, args.offline))
    if "profiles" in areas:
        findings.append(check_source_paths(profiles))
        findings.extend(check_pin_builds(profiles, platforms_dir, args.cache_dir, args.offline))
        findings.extend(check_profiles(args.profiles, args.offline))

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(render(findings))
    return exit_code(findings)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
