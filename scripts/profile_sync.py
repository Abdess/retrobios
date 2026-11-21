#!/usr/bin/env python3
"""Confront emulator profiles with their upstream source.

Anchors every source_ref of a profile against the commit the profile was
written at and against upstream HEAD, separating what is mechanically
recalable from what needs the code read again.
"""

from __future__ import annotations

import argparse
import os
import sys


sys.path.insert(0, os.path.dirname(__file__))

from core import upstream
from model import profiles as emulator_profiles
from core.cli import add_repo_inputs
from profiling import quota, selection
from profiling.bump import DEFAULT_CACHE
from profiling.flagchecks import refuse_flag_combinations
from profiling.realignpass import run_realign
from profiling.run import emit_reports, read_selected
from profiling.sourcepaths import refresh_source_paths
from profiling.versioncheck import run_versions
from profiling.worktree import refuse_dirty_tree


def build_parser() -> argparse.ArgumentParser:
    """Command line: selection, output, detection, writes, network."""
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Confront emulator profiles with their upstream source"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    # Repeatable: a stored value kept only the last of several --emulator.
    group.add_argument("--emulator", action="append", help="a profile, repeatable")
    group.add_argument("--all", action="store_true", help="every profile")
    group.add_argument(
        "--changed", action="store_true",
        help="the profiles the branch adds or edits against --base, "
        "uncommitted ones included",
    )
    group.add_argument(
        "--added", action="store_true",
        help="the profiles the branch adds against --base, as CI checks them",
    )
    parser.add_argument(
        "--base",
        help="revision --changed and --added compare with, through its merge "
        "base with HEAD (default: the project's main line, upstream/main or "
        "origin/main when that remote names the project, fetched otherwise)",
    )
    add_repo_inputs(parser, "emulators")
    parser.add_argument("--system", help="keep profiles covering this system")
    parser.add_argument("--type", dest="type_", help="keep profiles of this type")
    parser.add_argument("--stale-before", help="keep profiles profiled before a date")
    parser.add_argument("--limit", type=int, help="stop after N profiles")
    parser.add_argument(
        "--changed-only", action="store_true",
        help="list only the profiles with refs to review",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 when a profile has refs to review or cannot be checked as "
        "written (no repository answers, no pin), as for a new profile in CI",
    )
    parser.add_argument(
        "--json", action="store_true", dest="as_json",
        help="JSON report",
    )
    parser.add_argument(
        "--markdown", action="store_true",
        help="write a markdown report to --report-dir",
    )
    parser.add_argument(
        "--report-dir",
        default="reports",
        help="directory for the markdown report (default: reports)",
    )
    parser.add_argument(
        "--fetch-plan", action="store_true",
        help="print the upstream URLs a reader has to open",
    )
    parser.add_argument(
        "--full-diff", action="store_true",
        help="print the upstream diff of every cited file since the pin",
    )
    parser.add_argument("--ref", help="restrict --full-diff to one cited path")
    parser.add_argument(
        "--context", type=int, default=3,
        help="lines of context around each diff hunk (default: %(default)s)",
    )
    parser.add_argument(
        "--check-version", action="store_true",
        help="compare core_version with the latest tag and release",
    )
    parser.add_argument(
        "--verify-version", action="store_true",
        help="read core_version again from version_basis at the pin and "
        "exit 1 when the code states another",
    )
    parser.add_argument(
        "--set-version", action="store_true",
        help="write core_version from version_basis at the pin, the nearest "
        "tag asked of git again",
    )
    parser.add_argument(
        "--detect-new-files", action="store_true",
        help="name files upstream loads that the profile does not list",
    )
    parser.add_argument(
        "--watch-hashes", action="store_true",
        help="report hash literals that changed in the cited files",
    )
    parser.add_argument(
        "--tree-diff", action="store_true",
        help="list files added, removed or renamed upstream since the pin",
    )
    parser.add_argument(
        "--triage", action="store_true",
        help="rank the profiles by how much there is to reread",
    )
    parser.add_argument(
        "--backfill-commits", action="store_true",
        help="write source_commit for profiles that only carry profiled_date",
    )
    parser.add_argument(
        "--rebase-refs",
        action="store_true",
        help="rewrite shifted refs for HEAD and move source_commit with them, "
        "all or nothing",
    )
    parser.add_argument(
        "--attribute-refs",
        action="store_true",
        help="open each cited path with source or upstream, the repository its "
        "lines are in, for profiles that declare both",
    )
    parser.add_argument(
        "--bump-commit",
        action="store_true",
        help="move source_commit to HEAD when every ref already anchors there",
    )
    parser.add_argument(
        "--realign-prose",
        action="store_true",
        help="recale prose citations from the pin their text was written at",
    )
    parser.add_argument(
        "--accept-changed",
        action="store_true",
        help="recale CHANGED refs too, after their diff has been read",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="print the writes and leave the profiles untouched",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="write even when emulators/ has uncommitted changes",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="read only what the cache holds, no network access",
    )
    parser.add_argument(
        "--fresh", action="store_true",
        help="ask the forges again for branch tips, tags and releases instead "
        "of the answers cached in the last six hours",
    )
    parser.add_argument(
        "--cache-dir", default=DEFAULT_CACHE,
        help="download cache directory (default: %(default)s)",
    )
    return parser


def main() -> None:
    """Build one report per selected profile, then apply writes and output."""
    args = build_parser().parse_args()
    refuse_flag_combinations(args)
    if args.fresh:
        # Tips cached before an upstream commit hid it for six hours: EKA2L1,
        # trzy/Supermodel and VICE read as behind their real HEAD.
        upstream.MOVING_TTL = 0
    profiles = emulator_profiles.load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    if args.verify_version or args.set_version:
        run_versions(args, profiles, selection.version_selection(args, profiles))
        return
    selected = selection.select_profiles(profiles, args)
    quota.check_quota(len(selected), args.offline)

    writes = (
        args.backfill_commits or args.rebase_refs or args.bump_commit
        or args.realign_prose or args.attribute_refs
    )
    if writes and not args.dry_run and not args.force:
        refuse_dirty_tree(args.emulators_dir, list(selected))

    if args.realign_prose:
        run_realign(args, selected)
        return

    reports, failed, complete = read_selected(args, selected, writes)

    # --changed-only narrows every output, not the text report alone: the
    # documented `--all --changed-only --json` listed every profile.
    shown = [
        report for report in reports
        if not args.changed_only or report.needs_review() or report.name in failed
    ]
    complete = emit_reports(args, selected, reports, shown) is not False and complete
    refresh_source_paths(args)
    if not complete:
        raise SystemExit(130)
    if failed or (args.strict and any(
        report.needs_review() or report.uncheckable() for report in reports
    )):
        raise SystemExit(1)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
