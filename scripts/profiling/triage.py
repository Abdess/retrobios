"""Which profiles to read first: drift scores and the triage listing."""

from __future__ import annotations

import argparse
import sys
import time

from core import upstream
from profiling.detection import cited_paths
from profiling.reports import ProfileReport, triage_state
from profiling.repos import select_repo
from profiling.versions import VersionReport, check_version


TRIAGE_PATH_SAMPLE = 5
# A pass that asks the forges says where it is at this interval: an online
# --all --triage ran 15 minutes without a word and read as hung.
PROGRESS_SECONDS = 30


DRIFT_WEIGHTS = {"GONE": 40, "CHANGED": 30, "AMBIGUOUS": 15, "SHIFTED": 1}
PIN_WEIGHT = 50


def drift_score(
    report: ProfileReport, version: VersionReport | None, commits: int
) -> int:
    """Rank profiles by how far they have drifted from their pin."""
    counts = report.counts or {}
    score = sum(DRIFT_WEIGHTS.get(k, 0) * v for k, v in counts.items())
    # Prose a reader has to settle weighs as an ambiguous ref, prose
    # --realign-prose moves by itself as a shifted one.
    score += sum(
        DRIFT_WEIGHTS["SHIFTED" if line.startswith("would recale") else "AMBIGUOUS"]
        for line in report.stale_prose or ()
    )
    if (
        version is not None and not version.tag_matches_declared
        and version.latest_release and version.latest_release != version.declared
    ):
        score += 10
    # A pin off its branch or a repository answering under another name is
    # set again before any ref can be read, so each outranks a GONE ref:
    # pcem ranked last at 0 with an orphaned upstream_commit.
    score += PIN_WEIGHT * (len(report.orphaned) + len(report.moved_repos))
    # A profile no repository answers for cannot be read at all, and
    # --strict fails on it: it ranked at 0 under the clean profiles.
    score += PIN_WEIGHT * report.uncheckable()
    score += min(commits, 20) // 4
    return score


class Progress:
    """A stderr line every PROGRESS_SECONDS while a pass asks the forges."""

    def __init__(self, total: int, doing: str, quiet: bool) -> None:
        self.total, self.doing, self.quiet = total, doing, quiet
        self.last = time.monotonic()

    def step(self, done: int, name: str) -> None:
        now = time.monotonic()
        if not self.quiet and now - self.last >= PROGRESS_SECONDS:
            print(f"{self.doing}: {done} of {self.total}, at {name}", file=sys.stderr, flush=True)
            self.last = now


def print_interrupted(done: int, total: int, what: str) -> None:
    print(f"interrupted after {done} of {total} profiles: {what}", file=sys.stderr, flush=True)


def print_triage(
    args: argparse.Namespace, selected: dict, reports: list[ProfileReport]
) -> bool:
    """Profiles ranked by drift, worst first. False when Ctrl-C cut the
    scoring short: the ranking then covers the profiles scored."""
    ranked: list[tuple[int, ProfileReport, str]] = []
    sampled = 0
    progress = Progress(len(reports), "scored", args.offline or len(reports) < 2)
    complete = True
    try:
        for done, report in enumerate(reports):
            progress.step(done, report.name)
            sampled += _score(args, selected, report, ranked)
    except KeyboardInterrupt:
        print_interrupted(len(ranked), len(reports), "the ranking covers those scored")
        complete = False
    if sampled:
        # One line for the run: a notice per profile buried the ranking
        # under 254 lines of stderr.
        print(
            f"commit count sampled on {TRIAGE_PATH_SAMPLE} cited paths for "
            f"{sampled} profiles citing more",
            file=sys.stderr,
        )
    print(f"{'score':>5s}  {'profile':30s}  state (worst first)")
    pending = 0
    for score, report, refused in sorted(ranked, key=lambda item: -item[0]):
        state = triage_state(report)
        if refused:
            state += f", {refused}"
        pending += bool(report.needs_review() or report.uncheckable())
        print(f"{score:5d}  {report.name:30s}  {state}")
    print(f"{len(ranked)} profiles, {pending} with something to review")
    return complete


def _score(
    args: argparse.Namespace, selected: dict, report: ProfileReport, ranked: list
) -> bool:
    """Append one profile's drift score to ``ranked``. True when its commit
    count was read on a sample of the paths it cites."""
    profile = selected[report.name]
    version = None
    commits = 0
    refused = ""
    sampled = False
    repo = select_repo(profile)
    if report.head and repo is not None:
        paths = cited_paths(report)
        try:
            version = check_version(profile, repo, args.cache_dir, args.offline)
            for path in paths[:TRIAGE_PATH_SAMPLE]:
                commits += upstream.commits_touching(
                    repo, path, report.pin, args.cache_dir, args.offline,
                    head=report.head,
                )
        except upstream.UpstreamError as exc:
            # One forge refusing a request (Eden's answers 403 to commit
            # lookups) leaves this profile unscored, not the whole ranking.
            refused = "commit history unreachable"
            print(f"{report.name}: {exc}", file=sys.stderr)
        sampled = len(paths) > TRIAGE_PATH_SAMPLE and not refused
    ranked.append((drift_score(report, version, commits), report, refused))
    return sampled
