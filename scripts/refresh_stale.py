#!/usr/bin/env python3
"""Refresh everything check_freshness.py reports as STALE, in parallel.

check_freshness.py already answers "what is out of date". This script turns
that answer into actions: it parses the JSON report, matches each stale
subject to the command that pulls its upstream, runs them concurrently, and
leaves every write in the working tree for human review. Nothing is ever
committed.

Mapping (stale -> command):
    platforms/<name>        python -m scripts.scraper.<module>_scraper
                            -o platforms/<name>.yml
                            then the native refresh below: the original
                            the export patches must be the one just scraped
    native/<name>           python scripts/export_native.py --platform <name>
                            --refresh-cache
    targets/<name>          python -m scripts.scraper.targets.<module>
                            -o platforms/targets/<name>.yml
    data/<key>              python scripts/refresh_data_dirs.py --key <key>
                            --force
    catalogs/mame recipes   python -m scripts.scraper.romset_dat_importer
                            --source mame --fetch
    catalogs/fbneo recipes  python -m scripts.scraper.romset_dat_importer
                            --source fbneo --fetch

Surfaced only (no refresh): coreinfo gaps, redump/no-intro/tosec packs,
CI pins (install.py SHA-256, PyPI, pinned actions), profile_sync. Each needs
a human read (new .info file, manual DAT download, PyPI version bump).

Usage:
    python scripts/refresh_stale.py --dry-run
    python scripts/refresh_stale.py --only platforms,targets
    python scripts/refresh_stale.py --jobs 6
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = REPO_ROOT / "tmp" / "refresh_stale"
CHECK_FRESHNESS = REPO_ROOT / "scripts" / "check_freshness.py"
PLATFORMS_REGISTRY = REPO_ROOT / "platforms" / "_registry.yml"

AUTO_AREAS = ("platforms", "native", "targets", "data", "catalogs")
MANUAL_AREAS = ("coreinfo", "ci", "profiles")

JOB_TIMEOUT = 1800  # 30 minutes per refresher; scrapers rarely exceed 10


@dataclass(frozen=True)
class Job:
    """One refresh action derived from a stale finding."""

    area: str
    subject: str
    command: list[str]
    log_path: Path
    # Commands run after `command`, in order, only while each one succeeds.
    then: tuple[tuple[str, ...], ...] = ()


@dataclass(frozen=True)
class JobResult:
    job: Job
    returncode: int
    duration: float
    tail: str  # last non-empty line of stderr or stdout


def _load_platform_registry() -> dict[str, dict]:
    """Return the platforms map from _registry.yml.

    pyyaml is already a project dependency; the registry is small so we read
    it once at startup rather than parsing each dispatch.
    """
    import yaml

    with PLATFORMS_REGISTRY.open(encoding="utf-8") as fh:
        return (yaml.safe_load(fh) or {}).get("platforms") or {}


def _run_check_freshness(areas: tuple[str, ...], extra: list[str]) -> list[dict]:
    """Run check_freshness.py --json and return its findings."""
    cmd = [sys.executable, str(CHECK_FRESHNESS), "--json"]
    if areas and set(areas) != set(AUTO_AREAS + MANUAL_AREAS):
        cmd += ["--only", ",".join(areas)]
    cmd += extra
    proc = subprocess.run(
        cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False, timeout=1800
    )
    if proc.returncode not in (0, 1):
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-3:]
        raise RuntimeError(
            "check_freshness.py failed:\n" + "\n".join(tail or ["(no output)"])
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"check_freshness.py returned unreadable JSON: {exc}") from exc


def _slug(subject: str) -> str:
    """A safe filename stem for a finding's subject."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", subject).strip("_") or "job"


def plan_jobs(
    findings: list[dict], registry: dict[str, dict]
) -> tuple[list[Job], list[dict], list[dict]]:
    """Split findings into (refreshable jobs, surfaced-only, ignored).

    Surfaced-only entries carry stale state that only a human can resolve
    (new .info file, manual DAT download, PyPI bump). Ignored entries are
    anything not STALE (OK, SKIPPED, UNKNOWN, ERROR); ERROR is also surfaced
    so the final report mentions it.
    """
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
        and _command_for("platforms", str(f.get("subject") or ""), registry)
    }

    for finding in findings:
        status = finding.get("status")
        area = finding.get("area")
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

        command = _command_for(area, subject, registry)
        if command is None:
            surfaced.append(finding)
            continue

        key = (area, " ".join(command))
        if key in seen:
            # Two findings funneling to the same command (e.g. mame recipes
            # listed twice) collapse to one job.
            continue
        seen.add(key)

        log = LOG_DIR / f"{area}__{_slug(subject)}.log"
        then: tuple[tuple[str, ...], ...] = ()
        if area == "platforms":
            then = (tuple(_native_refresh(subject)),)
        jobs.append(
            Job(area=area, subject=subject, command=command, log_path=log, then=then)
        )

    return jobs, surfaced, ignored


def _native_refresh(platform: str) -> list[str]:
    return [
        sys.executable,
        "scripts/export_native.py",
        "--platform",
        platform,
        "--refresh-cache",
    ]


def _command_for(
    area: str, subject: str, registry: dict[str, dict]
) -> list[str] | None:
    """Map a stale finding to its refresh command, or None if manual."""
    if area == "native":
        return _native_refresh(subject)

    if area == "platforms":
        entry = registry.get(subject) or {}
        scraper = entry.get("scraper")
        if not scraper:
            return None
        return [
            sys.executable,
            "-m",
            f"scripts.scraper.{scraper}_scraper",
            "-o",
            f"platforms/{subject}.yml",
        ]

    if area == "targets":
        # "<platform> cores" rows list buildbot names without a profile; no
        # scraper fixes that, a human writes `cores:` or _overrides.yml.
        if subject.endswith(" cores"):
            return None
        entry = registry.get(subject) or {}
        module = entry.get("target_scraper")
        if not module:
            return None
        return [
            sys.executable,
            "-m",
            f"scripts.scraper.targets.{module}_scraper",
            "-o",
            f"platforms/targets/{subject}.yml",
        ]

    if area == "data":
        if subject == "_data_dirs.yml":
            # The registry file itself cannot be refreshed; its entries can.
            return None
        return [
            sys.executable,
            "scripts/refresh_data_dirs.py",
            "--key",
            subject,
            "--force",
        ]

    if area == "catalogs":
        if subject == "mame recipes":
            return [
                sys.executable,
                "-m",
                "scripts.scraper.romset_dat_importer",
                "--source",
                "mame",
                "--fetch",
            ]
        if subject == "fbneo recipes":
            return [
                sys.executable,
                "-m",
                "scripts.scraper.romset_dat_importer",
                "--source",
                "fbneo",
                "--fetch",
            ]
        # redump / no-intro / tosec need manual DAT download.
        return None

    # coreinfo, ci, profiles: never auto-refresh.
    return None


def _github_token_env() -> dict[str, str]:
    """Hand `gh auth token` to the subprocess environment.

    emudeck and retropie target scrapers hit the GitHub API; without a token
    the unauthenticated rate limit (60/h) is burnt within a few platforms.
    """
    env = os.environ.copy()
    if env.get("GITHUB_TOKEN"):
        return env
    try:
        proc = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, timeout=10, check=False
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return env
    token = (proc.stdout or "").strip()
    if proc.returncode == 0 and token:
        env["GITHUB_TOKEN"] = token
    return env


def run_job(job: Job, env: dict[str, str]) -> JobResult:
    """Execute one refresh command and collect its output."""
    start = time.monotonic()
    job.log_path.parent.mkdir(parents=True, exist_ok=True)
    returncode = 0
    with job.log_path.open("w", encoding="utf-8") as log:
        for command in (job.command, *job.then):
            log.write(f"$ {' '.join(command)}\n")
            log.flush()
            try:
                proc = subprocess.run(
                    list(command),
                    cwd=REPO_ROOT,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    env=env,
                    timeout=JOB_TIMEOUT,
                    check=False,
                )
                returncode = proc.returncode
            except subprocess.TimeoutExpired:
                log.write(f"\nTIMEOUT after {JOB_TIMEOUT}s\n")
                returncode = 124
            if returncode != 0:
                break
    duration = time.monotonic() - start
    tail = _log_tail(job.log_path)
    return JobResult(job=job, returncode=returncode, duration=duration, tail=tail)


def _log_tail(path: Path) -> str:
    """Last non-empty line of a log, truncated for the summary table."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    for line in reversed(text.splitlines()):
        stripped = line.strip()
        if stripped and not stripped.startswith("$ "):
            return stripped[:120]
    return ""


def render(
    results: list[JobResult],
    surfaced: list[dict],
    ignored: list[dict],
) -> str:
    """Human-readable table of what ran and what still needs a human."""
    lines: list[str] = []
    subject_w = max((len(r.job.subject) for r in results), default=10)
    subject_w = min(max(subject_w, 10), 44)

    if results:
        lines.append("\n[refreshed]")
        lines.append(
            f"  {'STATUS':8} {'AREA':10} {'SUBJECT':{subject_w}}  "
            f"{'DUR':>7}  LOG"
        )
        for r in sorted(results, key=lambda x: (x.job.area, x.job.subject)):
            status = "OK" if r.returncode == 0 else f"FAIL ({r.returncode})"
            rel_log = r.job.log_path.relative_to(REPO_ROOT)
            lines.append(
                f"  {status:8} {r.job.area:10} {r.job.subject[:subject_w]:{subject_w}}  "
                f"{r.duration:6.1f}s  {rel_log}"
            )
            if r.returncode != 0 and r.tail:
                lines.append(f"           -> {r.tail}")

    if surfaced:
        lines.append("\n[manual review needed]")
        for f in surfaced:
            detail = str(f.get("detail") or "").strip()
            lines.append(
                f"  {f.get('status', ''):7} {f.get('area', ''):10} "
                f"{f.get('subject', ''):28}  {detail[:100]}"
            )

    if ignored:
        counts: dict[str, int] = {}
        for f in ignored:
            counts[str(f.get("status") or "?")] = counts.get(str(f.get("status") or "?"), 0) + 1
        parts = ", ".join(f"{n} {status.lower()}" for status, n in sorted(counts.items()))
        lines.append(f"\n[ignored] {parts}")

    ok = sum(1 for r in results if r.returncode == 0)
    fail = len(results) - ok
    lines.append(
        f"\nREFRESH: {ok} ok, {fail} failed, {len(surfaced)} to review manually"
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--only",
        help="comma-separated areas to check: " + ",".join(AUTO_AREAS),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="list what would be refreshed; do not run any command",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=4,
        help="parallel refreshers (default: 4)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="machine-readable summary (jobs, surfaced, ignored)",
    )
    parser.add_argument(
        "--freshness-arg",
        action="append",
        default=[],
        help="extra flag to pass through to check_freshness.py (repeatable)",
    )
    args = parser.parse_args()

    all_areas = AUTO_AREAS + MANUAL_AREAS
    if args.only:
        areas = tuple(a.strip() for a in args.only.split(",") if a.strip())
        unknown = sorted(set(areas) - set(all_areas))
        if unknown:
            parser.error(f"unknown area: {', '.join(unknown)}")
    else:
        areas = all_areas

    try:
        findings = _run_check_freshness(areas, args.freshness_arg)
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 2

    registry = _load_platform_registry()
    jobs, surfaced, ignored = plan_jobs(findings, registry)

    if args.dry_run:
        print(f"\n[plan] {len(jobs)} refreshable, {len(surfaced)} manual, "
              f"{len(ignored)} already clean/skipped")
        for job in sorted(jobs, key=lambda j: (j.area, j.subject)):
            print(f"  {job.area:10} {job.subject:28}  {' '.join(job.command)}")
            for command in job.then:
                print(f"  {'':10} {'':28}  then {' '.join(command)}")
        if surfaced:
            print("\n[manual review needed]")
            for f in surfaced:
                print(f"  {f.get('status', ''):7} {f.get('area', ''):10} "
                      f"{f.get('subject', ''):28}  {str(f.get('detail') or '')[:100]}")
        return 0

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    env = _github_token_env()
    results: list[JobResult] = []
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = [pool.submit(run_job, job, env) for job in jobs]
        for future in as_completed(futures):
            results.append(future.result())

    if args.json:
        payload = {
            "refreshed": [
                {
                    "area": r.job.area,
                    "subject": r.job.subject,
                    "returncode": r.returncode,
                    "duration_sec": round(r.duration, 2),
                    "log": str(r.job.log_path.relative_to(REPO_ROOT)),
                    "tail": r.tail,
                }
                for r in results
            ],
            "surfaced": surfaced,
            "ignored_count": len(ignored),
        }
        print(json.dumps(payload, indent=2))
    else:
        print(render(results, surfaced, ignored))

    return 0 if all(r.returncode == 0 for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
