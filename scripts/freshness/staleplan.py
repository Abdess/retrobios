"""Stale findings split into refresh jobs, rows for a human, and rows left alone."""

from __future__ import annotations

import re

from core.paths import REPO_ROOT
from freshness.stalecommands import native_chain, refresh_chain
from freshness.stalejob import LOG_DIR, Job
from model.platforms import inheritance_chain
from model.registry import load_platform_registry

PLATFORMS_REGISTRY = REPO_ROOT / "platforms" / "_registry.yml"


def platform_registry() -> dict[str, dict]:
    """Return the platforms map from _registry.yml, read once at startup."""
    return load_platform_registry(PLATFORMS_REGISTRY.parent, required=True)


def platform_parents(registry: dict[str, dict]) -> dict[str, str]:
    """Platform to the platform its YAML inherits from."""
    parents: dict[str, str] = {}
    for name in registry:
        chain = inheritance_chain(name, REPO_ROOT / "platforms")
        if len(chain) > 1:
            parents[name] = chain[1]
    return parents


def _ancestors(platform: str, parents: dict[str, str]) -> set[str]:
    found: set[str] = set()
    while platform in parents and parents[platform] not in found:
        platform = parents[platform]
        found.add(platform)
    return found


def _slug(subject: str) -> str:
    """A safe filename stem for a finding's subject."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", subject).strip("_") or "job"


def plan_jobs(
    findings: list[dict],
    registry: dict[str, dict],
    parents: dict[str, str] | None = None,
) -> tuple[list[Job], list[dict], list[dict]]:
    """Split findings into (refreshable jobs, surfaced-only, ignored).

    Surfaced-only entries carry stale state that only a human can resolve
    (new .info file, manual DAT download, PyPI bump). Ignored entries are
    anything not STALE (OK, SKIPPED, UNKNOWN, ERROR). ERROR is also surfaced
    so the final report mentions it. ``parents`` maps a platform to the one
    it inherits from: a child's jobs wait for its rescraped ancestors, and a
    child no row names gets its export rewritten after them.
    """
    if parents is None:
        parents = platform_parents(registry)
    jobs: list[Job] = []
    seen: set[tuple[str, str]] = set()
    surfaced: list[dict] = []
    ignored: list[dict] = []
    # A platform about to be rescraped refreshes its cached original itself,
    # after the scrape: a separate native job would race the scraper.
    rescraped = {
        str(f.get("subject") or "")
        for f in findings
        if f.get("status") == "STALE"
        and f.get("area") == "platforms"
        and refresh_chain("platforms", str(f.get("subject") or ""), registry) is not None
    }

    for finding in findings:
        status = finding.get("status")
        area = str(finding.get("area") or "")
        subject = str(finding.get("subject") or "")

        if status == "ERROR":
            surfaced.append(finding)
            continue
        if status != "STALE":
            ignored.append(finding)
            continue

        if area == "native" and subject in rescraped:
            ignored.append(finding)
            continue

        chain = refresh_chain(area, subject, registry)
        if chain is None:
            surfaced.append(finding)
            continue

        key = (area, " ".join(chain.command))
        if key in seen:
            # Two findings funneling to the same command (e.g. mame recipes
            # listed twice) collapse to one job.
            continue
        seen.add(key)

        log = LOG_DIR / f"{area}__{_slug(subject)}.log"
        after: frozenset[str] = frozenset()
        if area in ("platforms", "native"):
            after = frozenset(_ancestors(subject, parents) & rescraped)
        jobs.append(
            Job(area=area, subject=subject, command=chain.command, log_path=log,
                then=chain.then, after=after)
        )

    # The export of a child is built from its parent's file: rewritten once
    # the parent is, or the next check reports it stale.
    covered = {j.subject for j in jobs if j.area in ("platforms", "native")}
    for child in sorted(parents):
        after = frozenset(_ancestors(child, parents) & rescraped)
        if not after or child in covered:
            continue
        chain = native_chain(child)
        jobs.append(Job(
            area="native",
            subject=child,
            command=chain.command,
            log_path=LOG_DIR / f"native__{_slug(child)}.log",
            then=chain.then,
            after=after,
        ))

    return jobs, surfaced, ignored
