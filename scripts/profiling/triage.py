"""Which profiles to read first: drift scores and the triage listing."""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field

from core import upstream
from profiling.reports import ProfileReport, report_to_dict, triage_state
from profiling.versionbasis import version_repo, version_tags
from profiling.versions import VersionReport, check_version


TRIAGE_PATH_SAMPLE = 5
# A pass that asks the forges says where it is at this interval: an online
# --all --triage ran 15 minutes without a word and read as hung.
PROGRESS_SECONDS = 30


DRIFT_WEIGHTS = {"GONE": 40, "CHANGED": 30, "AMBIGUOUS": 15, "SHIFTED": 1}
PIN_WEIGHT = 50


def drift_score(
    report: ProfileReport, versions: Sequence[VersionReport], commits: int
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
    if any(
        not version.tag_matches_declared
        and version.latest_release and version.latest_release != version.named
        for version in versions
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


@dataclass(frozen=True)
class ScoredReport:
    """One profile's drift score, and why its commit history went unread."""

    report: ProfileReport
    score: int
    refused: str = ""


@dataclass
class Scoring:
    """The scores a pass over the forges produced, worst first."""

    ranked: list[ScoredReport] = field(default_factory=list)
    # False when Ctrl-C cut the pass short: the ranking covers those scored.
    complete: bool = True


def score_reports(
    args: argparse.Namespace, selected: dict, reports: list[ProfileReport]
) -> Scoring:
    """Score every report by drift, asking the forges for versions and commits."""
    scored: list[ScoredReport] = []
    sampled = 0
    progress = Progress(len(reports), "scored", args.offline or len(reports) < 2)
    complete = True
    try:
        for done, report in enumerate(reports):
            progress.step(done, report.name)
            entry, was_sampled = _score(args, selected, report)
            scored.append(entry)
            sampled += was_sampled
    except KeyboardInterrupt:
        print_interrupted(len(scored), len(reports), "the ranking covers those scored")
        complete = False
    if sampled:
        # One line for the run: a notice per profile buried the ranking
        # under 254 lines of stderr.
        print(
            f"commit count sampled on {TRIAGE_PATH_SAMPLE} cited paths for "
            f"{sampled} profiles citing more",
            file=sys.stderr,
        )
    return Scoring(sorted(scored, key=lambda item: -item.score), complete)


def scored_to_dict(item: ScoredReport) -> dict:
    """A report's JSON form with its drift score and the history it lacked."""
    payload = report_to_dict(item.report)
    payload["drift_score"] = item.score
    payload["drift_refused"] = item.refused or None
    return payload


def render_triage(scoring: Scoring) -> None:
    """The ranking as a table, worst first."""
    print(f"{'score':>5s}  {'profile':30s}  state (worst first)")
    pending = 0
    for item in scoring.ranked:
        report = item.report
        state = triage_state(report)
        if item.refused:
            state += f", {item.refused}"
        pending += bool(report.needs_review() or report.uncheckable())
        print(f"{item.score:5d}  {report.name:30s}  {state}")
    print(f"{len(scoring.ranked)} profiles, {pending} with something to review")


def print_triage(
    args: argparse.Namespace, selected: dict, reports: list[ProfileReport]
) -> bool:
    """Profiles ranked by drift, worst first. False when Ctrl-C cut the
    scoring short: the ranking then covers the profiles scored."""
    scoring = score_reports(args, selected, reports)
    render_triage(scoring)
    return scoring.complete


def _score(
    args: argparse.Namespace, selected: dict, report: ProfileReport
) -> tuple[ScoredReport, bool]:
    """One profile's drift score, and whether its commit count was read on a
    sample of the paths it cites."""
    profile = selected[report.name]
    versions: list[VersionReport] = []
    commits = 0
    refused = ""
    sampled = False
    if report.head and version_repo(profile)[0] is not None:
        # Each cited path counted in the repository the resolver settled it
        # in, between that repository's own pin and HEAD.
        sources = report.cited_sources
        try:
            for named in version_tags(profile):
                version = check_version(named, args.cache_dir, args.offline)
                if version is not None:
                    versions.append(version)
            for source in sources[:TRIAGE_PATH_SAMPLE]:
                commits += upstream.commits_touching(
                    source.repo, source.path, source.pin, args.cache_dir, args.offline,
                    head=source.head,
                )
        except upstream.UpstreamError as exc:
            # One forge refusing a request (Eden's answers 403 to commit
            # lookups) leaves this profile unscored, not the whole ranking.
            refused = "commit history unreachable"
            print(f"{report.name}: {exc}", file=sys.stderr)
        sampled = len(sources) > TRIAGE_PATH_SAMPLE and not refused
    return ScoredReport(report, drift_score(report, versions, commits), refused), sampled
