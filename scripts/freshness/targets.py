"""Hardware target files rescraped, and the core names no profile claims."""

from __future__ import annotations

import subprocess
from collections.abc import Container
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from core import upstream
from core import forgehttp
from model.profiles import upstream_profile_index
from model.sources import source_yaml_file
from model.targets import apply_target_overrides, platform_overrides, read_target_overrides
from freshness.findings import (
    ERROR, OK, SHOWN_NAMES, SKIPPED, STALE, UNKNOWN, Finding, unprofiled_cores_subject,
)
from freshness.platformdiff import diff_targets
from freshness.rescrape import scrape_into_copy
from freshness.scrapers import target_scrapers
from scraper.targets import BaseTargetScraper
from scraper.targets.lakka_targets_scraper import PLATFORM_NAME as LAKKA, REPO as LAKKA_REPO


def profile_name_index(profiles: dict[str, dict]) -> dict[str, set[str]]:
    """Upstream core name -> the profiles that claim it, as target filtering reads it."""
    return upstream_profile_index(profiles, include_aliases=True)


def unresolved_target_cores(
    targets: dict, index: Container[str], overrides: dict
) -> dict[str, list[str]]:
    """Core names a target ends up with that no profile claims.

    Read after the overrides, by the function the builder applies
    (apply_target_overrides): _default then the target, add_cores
    included. A name added by hand without a profile is the false skip
    this check exists for, and a copy that read remove_cores alone never
    saw it.
    """
    unresolved: dict[str, list[str]] = {}
    for name, entry in (targets.get("targets") or {}).items():
        cores = {str(c) for c in (entry or {}).get("cores") or []}
        for core in sorted(apply_target_overrides(cores, overrides, name)):
            if core not in index:
                unresolved.setdefault(core, []).append(name)
    return {core: sorted(names) for core, names in sorted(unresolved.items())}


def check_targets(
    platforms_dir: Path, workdir: Path, profiles: dict[str, dict], jobs: int,
    offline: bool,
) -> list[Finding]:
    targets_dir = platforms_dir / "targets"
    overrides = read_target_overrides(targets_dir)
    index = profile_name_index(profiles)
    scrapers = target_scrapers()
    findings: list[Finding] = []
    today = datetime.now(timezone.utc)

    def run(platform: str) -> list[Finding]:
        path = targets_dir / f"{platform}.yml"
        if not path.is_file():
            return [Finding("targets", platform, ERROR, detail="no target file")]
        old = source_yaml_file(path) or {}
        module = scrapers.get(platform)
        targets = old.get("targets") or {}
        if module is not None and offline:
            # Scraped, so offline means not compared: SKIPPED, as every other
            # section says it. Labelled static and OK, a list 400 days old
            # read as current.
            stamp = str(old.get("scraped_at", ""))[:10]
            out = [Finding("targets", platform, SKIPPED, local=stamp, detail="offline")]
            missing = unresolved_target_cores(old, index, platform_overrides(overrides, platform))
            out.extend(_unresolved_findings(platform, missing))
            return out
        if module is None and targets and all(
            (t or {}).get("cores", []) is None for t in targets.values()
        ):
            # Every core the platform declares runs on these targets: the list
            # is the platform's own and has nothing of its own to age. Its
            # names still need a profile each: RetroBat's winuae, jzintv or
            # sudachi without one are BIOS its pack never carries.
            out = [Finding("targets", platform, OK, local="static",
                           detail="every declared core")]
            declared = _declared_cores(platform, platforms_dir)
            missing = unresolved_target_cores(
                {"targets": {name: {"cores": declared} for name in targets}},
                index, platform_overrides(overrides, platform),
            )
            out.extend(_unresolved_findings(platform, missing))
            return out
        if module is None:
            # No scraper: a hand-written file has no upstream to diff against,
            # so only its age and its core names can be reported.
            stamp = str(old.get("scraped_at", ""))[:10]
            age = _age_days(stamp, today)
            out = [
                Finding(
                    "targets",
                    platform,
                    OK if age is not None else UNKNOWN,
                    local=f"static {stamp}",
                    detail=f"{age} days old" if age is not None else "no scrape stamp",
                )
            ]
            missing = unresolved_target_cores(old, index, platform_overrides(overrides, platform))
            out.extend(_unresolved_findings(platform, missing))
            return out
        try:
            fresh, error, _dropped = scrape_into_copy("targets", platform, path, workdir)
        except subprocess.TimeoutExpired:
            return [Finding("targets", platform, ERROR, detail="scraper timed out")]
        if error:
            return [Finding("targets", platform, ERROR, detail=error)]
        new = source_yaml_file(fresh) or {}
        diff = diff_targets(old, new)
        out = [
            Finding(
                "targets",
                platform,
                STALE if diff.content_changed else OK,
                local=str(old.get("scraped_at", ""))[:10],
                remote=str(new.get("scraped_at", ""))[:10],
                detail=diff.summary(),
            )
        ]
        missing = unresolved_target_cores(new, index, platform_overrides(overrides, platform))
        out.extend(_unresolved_findings(platform, missing))
        return out

    names = sorted(p.stem for p in targets_dir.glob("*.yml") if not p.name.startswith("_"))
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for rows in pool.map(run, names):
            findings.extend(rows)
    return findings


def check_lakka_release(platforms_dir: Path, cache_dir: str, offline: bool) -> Finding:
    """The Lakka release platforms/lakka.yml pins against the newest one.

    The target scraper reads the release lakka.yml names, so a rescrape
    never moves it: only this row says Lakka published a newer one.
    """
    subject = f"{LAKKA} release"
    try:
        local = BaseTargetScraper.pinned_version(LAKKA, str(platforms_dir))
    except (OSError, RuntimeError) as exc:
        return Finding("targets", subject, ERROR, detail=str(exc))
    if offline:
        return Finding("targets", subject, SKIPPED, local=local, detail="offline")
    repo = upstream.parse_repo(f"https://github.com/{LAKKA_REPO}")
    try:
        release = upstream.latest_release(repo, cache_dir) if repo else None
    except forgehttp.UpstreamError as exc:
        return Finding("targets", subject, UNKNOWN, local=local, detail=str(exc))
    if release is None:
        return Finding("targets", subject, UNKNOWN, local=local, detail="no release listed")
    if release.tag == local:
        return Finding("targets", subject, OK, local=local, remote=release.tag,
                       detail="newest release")
    return Finding("targets", subject, STALE, local=local, remote=release.tag,
                   detail=f"edit version: in platforms/{LAKKA}.yml, then rescrape the targets")


def _declared_cores(platform: str, platforms_dir: Path) -> list[str]:
    """The cores and standalone emulators a platform's own file names."""
    from model.platforms import load_platform_config

    try:
        config = load_platform_config(platform, str(platforms_dir))
    except (FileNotFoundError, OSError):
        return []
    cores = config.get("cores")
    names = [str(c) for c in cores] if isinstance(cores, list) else []
    return names + [str(c) for c in config.get("standalone_cores") or []]


def _unresolved_findings(platform: str, missing: dict[str, list[str]]) -> list[Finding]:
    """One row per platform: the names its targets list that no profile claims.

    A buildbot name without a profile is a core the target filter cannot
    see, and a platform's own emulator id without one is an emulator nobody has
    profiled yet. Both are actionable, so both are listed, but as one row so
    the backlog does not bury the day's changes.
    """
    if not missing:
        return []
    names = sorted(missing)
    shown = ", ".join(names[:SHOWN_NAMES]) + (
        f", ... (--json lists all {len(names)})" if len(names) > SHOWN_NAMES else ""
    )
    return [
        Finding(
            "targets",
            unprofiled_cores_subject(platform),
            STALE,
            local=f"{len(names)} without a profile",
            detail=f"cores: alias or _overrides remove_cores needed for {shown}",
            items=names,
        )
    ]


def _age_days(stamp: str, now: datetime) -> int | None:
    try:
        then = datetime.strptime(stamp[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (now - then).days
