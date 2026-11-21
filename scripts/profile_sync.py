#!/usr/bin/env python3
"""Confront emulator profiles with their upstream source.

Anchors every source_ref of a profile against the commit the profile was
written at and against upstream HEAD, separating what is mechanically
recalable from what needs the code read again.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path


sys.path.insert(0, os.path.dirname(__file__))

from core import upstream
from profiling import version_basis
from model.systems import norm_system_id, system_index
from core.github import github_token
from model.profiles import is_emulator, load_emulator_profiles
from core.cli import add_repo_inputs, suggest_names
from profiling.bump import DEFAULT_CACHE, write_version
from profiling.realign import realign_prose
from profiling.reports import ProfileReport
from profiling.run import WRITTEN_PROFILES, emit_reports, read_one_profile
from profiling.triage import PROGRESS_SECONDS, Progress, print_interrupted
from profiling.yamledit import YamlWriteError

ANON_QUOTA = 60


def _refuse_dirty_tree(emulators_dir: str, names: list[str]) -> None:
    """Writes need a clean copy of each profile they touch to roll back to.

    Only the selected profiles count: a pass writing one profile after
    another used to refuse every profile after the first it wrote.
    """
    try:
        dirty = emulators_dir_is_dirty(emulators_dir, names)
    except RuntimeError as e:
        print(f"{e}. Pass --force to write anyway.", file=sys.stderr)
        raise SystemExit(1) from e
    if dirty:
        # Another session may own the change, so the refusal names the files:
        # --force writes over them.
        one = len(dirty) == 1
        print(
            f"{', '.join(dirty)} {'has' if one else 'have'} uncommitted changes: "
            f"commit {'it' if one else 'them'} or pass --force, which writes over "
            f"{'it' if one else 'them'}.",
            file=sys.stderr,
        )
        raise SystemExit(1)


def emulators_dir_is_dirty(emulators_dir: str, names: list[str] | None = None) -> list[str]:
    """The files of the profile directory that carry uncommitted changes.

    Paths read as the status prints them, from the repository root.

    ``names`` narrows the question to those profiles. Git is asked from
    inside the directory, so a profile tree that lives in another
    repository answers for itself. A directory git cannot read is never
    reported clean: the writes have nothing to roll back to.
    """
    paths = [f"{name}.yml" for name in names] if names is not None else ["."]
    result = subprocess.run(
        ["git", "-C", emulators_dir, "status", "--porcelain", "--", *paths],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"cannot read the git status of {emulators_dir}: {result.stderr.strip()}"
        )
    return sorted(
        line[3:].split(" -> ")[-1].strip('"')
        for line in result.stdout.splitlines()
        if line.strip()
    )


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


def _git_lines(args: list[str]) -> list[str]:
    from core.gitclone import GitRefused, required_git_lines

    try:
        return required_git_lines(*args)
    except GitRefused as exc:
        raise SystemExit(f"ERROR: {exc}") from exc


def branch_profiles(emulators_dir: str, base: str, added_only: bool) -> list[str]:
    """Names of the profiles the branch adds (or edits) against ``base``.

    The diff starts at the merge base, so commits main gained since the
    branch point are not counted, and ends at the working tree, so a
    profile not yet committed is checked too. A rename reads as an addition.
    """
    if subprocess.run(["git", "rev-parse", "--verify", "--quiet", base],
                      capture_output=True, check=False).returncode:
        remote = base.split("/", 1)[0] if "/" in base else "upstream"
        raise SystemExit(f"ERROR: {base} is not in this clone: run git fetch {remote} first")
    merge_base = _git_lines(["merge-base", base, "HEAD"])[0]
    paths = _git_lines([
        "diff", "--name-only", "--no-renames",
        "--diff-filter=A" if added_only else "--diff-filter=AM",
        merge_base, "--", emulators_dir,
    ])
    paths += _git_lines([
        "ls-files", "--others", "--exclude-standard", "--full-name",
        "--", emulators_dir,
    ])
    top = Path(_git_lines(["rev-parse", "--show-toplevel"])[0])
    root = Path(emulators_dir).resolve()
    return sorted({
        full.stem
        for path in paths
        if (full := (top / path).resolve()).suffix == ".yml" and full.parent == root
    })


def project_base() -> str:
    """The project's main line, the base --changed compares with by default.

    In a fork's clone origin/main is the fork: once the branch is pushed it
    is HEAD, and --changed --strict found nothing and passed while the PR's
    CI then failed. validate_pr.py resolves the same line the same way.
    """
    from core.gitclone import fallback_lines, git_lines, project_main_line

    line = project_main_line()
    if line:
        return line
    for candidates in fallback_lines():
        for candidate in candidates:
            if git_lines("rev-parse", "--verify", "--quiet", candidate):
                return candidate
    return "HEAD"


def select_profiles(profiles: dict, args: argparse.Namespace) -> dict:
    """Profiles matching the selection flags."""
    if args.changed or args.added:
        base = args.base or project_base()
        names = branch_profiles(args.emulators_dir, base, args.added)
        selected = {name: profiles[name] for name in names if name in profiles}
        if not selected:
            verb = "adds" if args.added else "adds or edits"
            print(f"the branch {verb} no profile against {base}", file=sys.stderr)
        return selected
    if args.emulator:
        names = [args.emulator] if isinstance(args.emulator, str) else args.emulator
        unknown = [name for name in names if name not in profiles]
        if unknown:
            # Suggested from what the listing it names shows: counted over the
            # alias and test profiles too, "lists all 553" pointed at 530 lines.
            listed = sorted(
                name for name, profile in profiles.items()
                if is_emulator(profile)
            )
            raise SystemExit(
                f"ERROR: unknown profile {', '.join(unknown)}. "
                + suggest_names(unknown, listed, "python scripts/verify.py --list-emulators")
            )
        return {name: profiles[name] for name in dict.fromkeys(names)}

    # --system matches as verify.py --list-systems lists and --system selects:
    # by normalized id, so `saturn` reaches the profiles declaring sega-saturn.
    wanted_system = norm_system_id(args.system) if args.system else None
    selected = {}
    for name, profile in sorted(profiles.items()):
        if not is_emulator(profile):
            continue
        if wanted_system and wanted_system not in {
            norm_system_id(str(s)) for s in profile.get("systems") or []
        }:
            continue
        if args.type_ and profile.get("type") != args.type_:
            continue
        if args.stale_before:
            profiled = str(profile.get("profiled_date") or "")
            if not profiled or profiled >= args.stale_before:
                continue
        selected[name] = profile
        if args.limit and len(selected) >= args.limit:
            break
    if not selected:
        # A misspelt filter selected nothing and the run said nothing: it
        # read as "no profile of that system needs a re-read".
        filters = ", ".join(
            f"{flag} {value}" for flag, value in (
                ("--system", args.system), ("--type", args.type_),
                ("--stale-before", args.stale_before),
            ) if value
        )
        hint = ""
        if args.system:
            # Suggested from the spellings the named listing prints.
            systems = sorted(spelling for spelling, _ in system_index(profiles).values())
            hint = " " + suggest_names([args.system], systems, "python scripts/verify.py --list-systems")
        elif args.type_:
            kinds = sorted({str(p.get("type")) for p in profiles.values() if p.get("type")})
            hint = f" Types: {', '.join(kinds)}."
        raise SystemExit(f"ERROR: no profile matches {filters or 'the selection'}.{hint}")
    return selected


def _check_quota(count: int, offline: bool) -> None:
    """Refuse a run the anonymous quota cannot carry to completion."""
    if offline or github_token():
        return
    if count * 5 > ANON_QUOTA:
        print(
            f"{count} profiles need roughly {count * 5} API calls, the anonymous "
            f"quota is {ANON_QUOTA} per hour. Log in with `gh auth login`, set "
            "GITHUB_TOKEN, or use --offline.",
            file=sys.stderr,
        )
        raise SystemExit(1)


def _refuse_flag_combinations(args: argparse.Namespace) -> None:
    """Exit on a flag the chosen mode would not apply, before any request."""
    if args.verify_version or args.set_version:
        ignored = [
            flag for flag, on in (
                ("--verify-version", args.verify_version and args.set_version),
                ("--markdown", args.markdown),
                ("--fetch-plan", args.fetch_plan),
                ("--triage", args.triage),
                ("--strict", args.strict),
                ("--check-version", args.check_version),
                ("--detect-new-files", args.detect_new_files),
                ("--watch-hashes", args.watch_hashes),
                ("--full-diff", args.full_diff),
                ("--tree-diff", args.tree_diff),
                ("--backfill-commits", args.backfill_commits),
                ("--rebase-refs", args.rebase_refs),
                ("--attribute-refs", args.attribute_refs),
                ("--bump-commit", args.bump_commit),
                ("--realign-prose", args.realign_prose),
                ("--accept-changed", args.accept_changed),
                ("--dry-run", args.dry_run and not args.set_version),
            ) if on
        ]
        if ignored:
            mode = "--set-version" if args.set_version else "--verify-version"
            print(f"{mode} does not apply {', '.join(ignored)}", file=sys.stderr)
            raise SystemExit(1)
    if args.fresh and args.offline:
        print("--fresh asks the forges again, which --offline forbids.", file=sys.stderr)
        raise SystemExit(1)
    if args.accept_changed and not args.emulator:
        print(
            "--accept-changed applies to one profile at a time: its diff has "
            "to be read before its CHANGED refs can be recaled.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.attribute_refs and (
        args.rebase_refs or args.bump_commit or args.backfill_commits
        or args.realign_prose
    ):
        print(
            "--attribute-refs runs alone: it rewrites the refs the report was "
            "built from.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.realign_prose and (
        args.rebase_refs or args.bump_commit or args.backfill_commits
    ):
        print(
            "--realign-prose runs alone: the report has to be rebuilt on the "
            "realigned text before any other write.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.realign_prose:
        ignored = [
            flag for flag, on in (
                ("--json", args.as_json),
                ("--markdown", args.markdown),
                ("--fetch-plan", args.fetch_plan),
                ("--triage", args.triage),
                ("--changed-only", args.changed_only),
                ("--strict", args.strict),
                ("--check-version", args.check_version),
                ("--detect-new-files", args.detect_new_files),
                ("--watch-hashes", args.watch_hashes),
                ("--full-diff", args.full_diff),
                ("--tree-diff", args.tree_diff),
                ("--accept-changed", args.accept_changed),
            ) if on
        ]
        if ignored:
            # A mode applies a flag or refuses it, never swallows it.
            print(
                f"--realign-prose does not apply {', '.join(ignored)}",
                file=sys.stderr,
            )
            raise SystemExit(1)
    machine = [
        flag for flag, on in (
            ("--json", args.as_json),
            ("--markdown", args.markdown),
            ("--fetch-plan", args.fetch_plan),
            ("--triage", args.triage),
        ) if on
    ]
    # The version check lives on the report, so the outputs built from the
    # report (text, --json, --markdown) carry it. A URL list and a ranking
    # do not. Detection lives on the report too, and --json carries it for
    # check_freshness. The markdown table has no column for it.
    lists_only = args.fetch_plan or args.triage
    off_json = lists_only or args.markdown
    extras = [
        flag for flag, on in (
            ("--check-version", args.check_version and lists_only),
            ("--detect-new-files", args.detect_new_files and off_json),
            ("--watch-hashes", args.watch_hashes and off_json),
            ("--full-diff", args.full_diff),
            ("--tree-diff", args.tree_diff),
        ) if on
    ]
    if machine and extras:
        # The extra sections only exist in the text report. The other outputs
        # returned before reaching them and printed as if never asked.
        print(
            f"{', '.join(machine)} does not carry {', '.join(extras)}",
            file=sys.stderr,
        )
        raise SystemExit(1)


def _version_selection(args: argparse.Namespace, profiles: dict) -> dict:
    """--all reaches the alias and test profiles too: each states a version."""
    if args.all and not (args.system or args.type_ or args.stale_before or args.limit):
        return dict(sorted(profiles.items()))
    return select_profiles(profiles, args)


def format_reading(name: str, reading: version_basis.Reading) -> str:
    mode = f"[{reading.mode}] " if reading.mode else ""
    kind = f"{reading.kind} " if reading.kind else ""
    if reading.status == version_basis.DRIFT:
        said = f"declared {reading.declared}, code {reading.read}"
    elif reading.status == version_basis.MATCH:
        said = str(reading.read)
    else:
        said = f"declared {reading.declared}"
    return f"{name}: {mode}{reading.status} {said} ({kind}{reading.where})"


def run_versions(args: argparse.Namespace, profiles: dict) -> None:
    """--verify-version and --set-version: core_version against the code."""
    selected = _version_selection(args, profiles)
    if args.set_version and not args.dry_run and not args.force:
        _refuse_dirty_tree(args.emulators_dir, list(selected))
    counts: Counter = Counter()
    rows = []
    failed = False
    for name, profile in selected.items():
        readings = version_basis.check(
            profile, args.cache_dir, args.offline, profiles, recompute=args.set_version
        )
        for reading in readings:
            counts[reading.status] += 1
            rows.append({"profile": name, **asdict(reading)})
            if not args.as_json and (not args.changed_only or reading.status != version_basis.MATCH):
                print(format_reading(name, reading))
        if args.set_version:
            path = Path(args.emulators_dir) / f"{name}.yml"
            if args.dry_run:
                continue
            try:
                if write_version(path, readings):
                    print(f"{name}: core_version written")
            except YamlWriteError as exc:
                print(f"{name}: write refused: {exc}", file=sys.stderr)
                failed = True
        elif any(r.status in version_basis.FAILING for r in readings):
            failed = True
    if args.as_json:
        print(json.dumps(rows, indent=2))
    else:
        print(", ".join(f"{count} {status}" for status, count in sorted(counts.items())),
              file=sys.stderr)
    if failed:
        raise SystemExit(1)


def main() -> None:
    """Build one report per selected profile, then apply writes and output."""
    args = build_parser().parse_args()
    _refuse_flag_combinations(args)
    if args.fresh:
        # Tips cached before an upstream commit hid it for six hours: EKA2L1,
        # trzy/Supermodel and VICE read as behind their real HEAD.
        upstream.MOVING_TTL = 0
    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    if args.verify_version or args.set_version:
        run_versions(args, profiles)
        return
    selected = select_profiles(profiles, args)
    _check_quota(len(selected), args.offline)

    writes = (
        args.backfill_commits or args.rebase_refs or args.bump_commit
        or args.realign_prose or args.attribute_refs
    )
    if writes and not args.dry_run and not args.force:
        _refuse_dirty_tree(args.emulators_dir, list(selected))

    if args.realign_prose:
        _run_realign(args, selected)
        return

    # A profile that could not be compared or written is not a profile with
    # nothing to review: it stays in every output and fails the run.
    failed: set[str] = set()
    reports: list[ProfileReport] = []
    quiet = args.offline or len(selected) < 2
    if not quiet:
        print(
            f"reading {len(selected)} profiles against their forges, a line every "
            f"{PROGRESS_SECONDS} s. --offline answers from the cache alone.",
            file=sys.stderr, flush=True,
        )
    progress = Progress(len(selected), "read", quiet)
    complete = True
    try:
        for name, profile in selected.items():
            progress.step(len(reports), name)
            read_one_profile(args, name, profile, reports, failed, writes)
    except KeyboardInterrupt:
        # What was read is still worth printing: a ranking of 200 profiles
        # beats none after 15 minutes.
        print_interrupted(len(reports), len(selected), "the output covers those read")
        complete = False

    # --changed-only narrows every output, not the text report alone: the
    # documented `--all --changed-only --json` listed every profile.
    shown = [
        report for report in reports
        if not args.changed_only or report.needs_review() or report.name in failed
    ]
    complete = emit_reports(args, selected, reports, shown) is not False and complete
    _refresh_source_paths(args)
    if not complete:
        raise SystemExit(130)
    if failed or (args.strict and any(
        report.needs_review() or report.uncheckable() for report in reports
    )):
        raise SystemExit(1)


def _run_realign(args: argparse.Namespace, selected: dict) -> None:
    """--realign-prose over the selected profiles, exit 1 when one failed."""
    failed: set[str] = set()
    for name in selected:
        profile_path = Path(args.emulators_dir) / f"{name}.yml"
        if not profile_path.is_file():
            continue
        try:
            before = profile_path.read_bytes()
            for line in realign_prose(
                profile_path, args.cache_dir, args.offline, args.dry_run
            ):
                print(f"{name}: {line}")
            if profile_path.read_bytes() != before:
                WRITTEN_PROFILES.add(name)
        except upstream.UpstreamError as exc:
            print(f"{name}: {exc}", file=sys.stderr)
            failed.add(name)
        except YamlWriteError as exc:
            print(f"{name}: write refused: {exc}", file=sys.stderr)
            failed.add(name)
    _refresh_source_paths(args)
    if failed:
        raise SystemExit(1)


def _refresh_source_paths(args: argparse.Namespace) -> None:
    """Rebuild the site's record of cited source paths after a write.

    Each bump left website/src/data/source-paths.json behind its pins, and
    the site's freshness test stayed red until someone ran sitesources.py
    --fetch by hand. A run that writes nothing, or makes no request, leaves
    it alone.
    """
    if not WRITTEN_PROFILES or args.dry_run or args.offline or os.environ.get("RETROBIOS_OFFLINE"):
        return
    from model.profiles import emulator_profiles_cache
    from sitegen import sources
    from core.artifacts import write_if_changed

    # The run loaded the profiles before writing them, and the loader caches
    # by directory: read again, the record described the pins just replaced
    # (linapple, then ten profiles in one advance).
    emulator_profiles_cache.clear()
    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    held, unread = sources.build_source_paths(
        profiles, [sources.TREE_CACHE], fetch=True
    )
    held = sources.keep_unread(
        held, unread, sources.read_record(sources.SOURCE_PATHS)
    )
    sources.SOURCE_PATHS.parent.mkdir(parents=True, exist_ok=True)
    write_if_changed(
        str(sources.SOURCE_PATHS), json.dumps(held, indent=1, sort_keys=True) + "\n"
    )
    print(
        f"source paths: {sum(map(len, held.values()))} in {len(held)} trees, "
        f"{len(unread)} trees not cached: {sources.SOURCE_PATHS}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
