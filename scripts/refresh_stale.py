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
                            the export patches must be the one just scraped,
                            then python scripts/verify.py --platform <name>,
                            whose summary the report prints: a rescrape can
                            add systems whose files are missing
    native/<name>           python scripts/generate_truth.py --platform <name>, then
                            python scripts/export_native.py --platform <name>
                            --refresh-cache, then the export itself, which
                            rewrites exports/<name>
    targets/<name>          python -m scripts.scraper.targets.<module>
                            -o platforms/targets/<name>.yml
    data/<key>              python scripts/refresh_data_dirs.py --key <key>
                            --force
    catalogs/mame recipes   python -m scripts.scraper.romset_dat_importer
                            --source mame --fetch
    catalogs/fbneo recipes  python -m scripts.scraper.romset_dat_importer
                            --source fbneo --fetch

A platform that inherits from a rescraped one (retropie and lakka from
retroarch) reads the parent's file: its jobs start once the parent's chain
has ended, and its export is rewritten even when no row named it.

Surfaced only (no refresh): data rows that are not a _data_dirs.yml key
(the registry itself, buildbot assets it does not track), coreinfo gaps, redump/no-intro/tosec packs,
CI pins (PyPI, pinned actions, while scripts/pin_installer.py writes the
install.py SHA-256 pin), profile_sync, rom-folder
pins (moved by hand, then python -m scripts.scraper.romfolders --setup NAME
reads them again). Each needs
a human read (new .info file, manual DAT download, PyPI version bump).

Usage:
    python scripts/refresh_stale.py --dry-run
    python scripts/refresh_stale.py --only platforms,targets
    python scripts/refresh_stale.py --jobs 6
    python scripts/refresh_stale.py --findings tmp/freshness.json --only data
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = REPO_ROOT / "tmp" / "refresh_stale"
CHECK_FRESHNESS = REPO_ROOT / "scripts" / "check_freshness.py"
PLATFORMS_REGISTRY = REPO_ROOT / "platforms" / "_registry.yml"
DATA_DIRS_REGISTRY = REPO_ROOT / "platforms" / "_data_dirs.yml"

AUTO_AREAS = ("platforms", "native", "targets", "data", "catalogs")
# A rom-folder pin is moved by hand in platforms/romfolders/_sources/,
# then `python -m scripts.scraper.romfolders --setup NAME` reads it again.
MANUAL_AREAS = ("romfolders", "coreinfo", "ci", "profiles")

JOB_TIMEOUT = 1800  # 30 minutes per refresher, scrapers rarely exceed 10


@dataclass(frozen=True)
class Job:
    """One refresh action derived from a stale finding."""

    area: str
    subject: str
    command: list[str]
    log_path: Path
    # Commands run after `command`, in order, only while each one succeeds.
    then: tuple[tuple[str, ...], ...] = ()
    # Platforms whose rescrape job must end before this one starts.
    after: frozenset[str] = frozenset()


@dataclass(frozen=True)
class JobResult:
    job: Job
    returncode: int
    duration: float
    tail: str  # last non-empty line of stderr or stdout


def _load_platform_registry() -> dict[str, dict]:
    """Return the platforms map from _registry.yml.

    pyyaml is already a project dependency, and the registry is small so we read
    it once at startup rather than parsing each dispatch.
    """
    import yaml

    with PLATFORMS_REGISTRY.open(encoding="utf-8") as fh:
        return (yaml.safe_load(fh) or {}).get("platforms") or {}


def _platform_parents(registry: dict[str, dict]) -> dict[str, str]:
    """Platform to the platform its YAML inherits from."""
    import yaml

    parents: dict[str, str] = {}
    for name in registry:
        path = REPO_ROOT / "platforms" / f"{name}.yml"
        if not path.is_file():
            continue
        with path.open(encoding="utf-8") as fh:
            parent = (yaml.safe_load(fh) or {}).get("inherits")
        if parent:
            parents[name] = str(parent)
    return parents


def _ancestors(platform: str, parents: dict[str, str]) -> set[str]:
    found: set[str] = set()
    while platform in parents and parents[platform] not in found:
        platform = parents[platform]
        found.add(platform)
    return found


@lru_cache(maxsize=1)
def _data_dir_keys() -> frozenset[str]:
    """The entries refresh_data_dirs.py --key accepts."""
    import yaml

    with DATA_DIRS_REGISTRY.open(encoding="utf-8") as fh:
        return frozenset((yaml.safe_load(fh) or {}).get("data_directories") or {})


def _run_check_freshness(areas: tuple[str, ...], extra: list[str]) -> list[dict]:
    """Run check_freshness.py --json and return its findings."""
    cmd = [sys.executable, str(CHECK_FRESHNESS), "--json"]
    if areas and set(areas) != set(AUTO_AREAS + MANUAL_AREAS):
        cmd += ["--only", ",".join(areas)]
    cmd += extra
    try:
        proc = subprocess.run(
            cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False, timeout=1800
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"check_freshness.py did not finish in {exc.timeout:.0f} s: run "
            f"`{' '.join(cmd[1:])} > report.json` alone, then pass --findings report.json"
        ) from exc
    # Exit 1 is the STALE rows, and also a crash: only a JSON list on stdout
    # tells them apart, and the crash's own message is on stderr.
    try:
        findings = json.loads(proc.stdout) if proc.returncode in (0, 1) else None
    except json.JSONDecodeError:
        findings = None
    if not isinstance(findings, list):
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-3:]
        raise RuntimeError(
            f"check_freshness.py failed (exit {proc.returncode}):\n"
            + "\n".join(tail or ["(no output)"])
        )
    return findings


def load_findings(path: Path, areas: tuple[str, ...]) -> list[dict]:
    """A saved check_freshness.py --json report, kept to the asked areas."""
    try:
        findings = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"cannot read findings from {path}: {exc}") from exc
    if not isinstance(findings, list):
        raise RuntimeError(f"{path} is not a check_freshness.py --json report")
    return [f for f in findings if f.get("area") in areas]


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
        parents = _platform_parents(registry)
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
            # The truth reads the platform file: regenerated first, or the
            # native refresh refuses it as older than the profiles.
            then = (
                tuple(_truth_refresh(subject)),
                tuple(_native_refresh(subject)),
                tuple(_export_refresh(subject)),
                tuple(_verify(subject)),
            )
        elif area == "native":
            then = (tuple(_native_refresh(subject)), tuple(_export_refresh(subject)))
        after: frozenset[str] = frozenset()
        if area in ("platforms", "native"):
            after = frozenset(_ancestors(subject, parents) & rescraped)
        jobs.append(
            Job(area=area, subject=subject, command=command, log_path=log,
                then=then, after=after)
        )

    # The export of a child is built from its parent's file: rewritten once
    # the parent is, or the next check reports it stale.
    covered = {j.subject for j in jobs if j.area in ("platforms", "native")}
    for child in sorted(parents):
        after = frozenset(_ancestors(child, parents) & rescraped)
        if not after or child in covered:
            continue
        jobs.append(Job(
            area="native",
            subject=child,
            command=_truth_refresh(child),
            log_path=LOG_DIR / f"native__{_slug(child)}.log",
            then=(tuple(_native_refresh(child)), tuple(_export_refresh(child))),
            after=after,
        ))

    return jobs, surfaced, ignored


def _verify(platform: str) -> list[str]:
    """The check a rescraped platform file is read with before it is kept."""
    return [sys.executable, "scripts/verify.py", "--platform", platform]


VERIFY_MARK = "scripts/verify.py --platform"


def verify_summary(path: Path) -> str:
    """First line verify printed in a job log, empty when it did not run."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("$ ") and VERIFY_MARK in line:
            return next(
                (rest.strip() for rest in lines[index + 1:]
                 if rest.strip() and not rest.startswith("$ ")),
                "",
            )
    return ""


def run_jobs(jobs: list[Job], env: dict[str, str], workers: int) -> list[JobResult]:
    """Run jobs in parallel, each once the rescrapes it waits for have ended.

    A failed parent still releases its children: its file is unchanged, and
    the child reads it as it is.
    """
    results: list[JobResult] = []
    ended: set[str] = set()
    waiting = list(jobs)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        running: dict = {}
        while waiting or running:
            ready = [job for job in waiting if job.after <= ended]
            for job in ready:
                waiting.remove(job)
                running[pool.submit(run_job, job, env)] = job
            if not running:
                raise RuntimeError(
                    "jobs wait on rescrapes that are not planned: "
                    + ", ".join(sorted(j.subject for j in waiting))
                )
            done, _ = wait(running, return_when=FIRST_COMPLETED)
            for future in done:
                job = running.pop(future)
                results.append(future.result())
                if job.area == "platforms":
                    ended.add(job.subject)
    return results


def _truth_refresh(platform: str) -> list[str]:
    return [sys.executable, "scripts/generate_truth.py", "--platform", platform]


def _native_refresh(platform: str) -> list[str]:
    return [
        sys.executable,
        "scripts/export_native.py",
        "--platform",
        platform,
        "--refresh-cache",
    ]


def _export_refresh(platform: str) -> list[str]:
    """Rewrite the published export from the refreshed original."""
    return [sys.executable, "scripts/export_native.py", "--platform", platform]


def _command_for(
    area: str, subject: str, registry: dict[str, dict]
) -> list[str] | None:
    """Map a stale finding to its refresh command, or None if manual."""
    if area == "native":
        # export_native refuses a truth older than the profiles, so the
        # truth comes first and the original follows (Job.then).
        return _truth_refresh(subject)

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
            *(str(a) for a in entry.get("rescrape_args") or ()),
        ]

    if area == "targets":
        # "<platform> cores" rows list buildbot names without a profile. No
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
        if subject not in _data_dir_keys():
            # "_data_dirs.yml" and "buildbot system" name the registry and
            # what it does not track yet: a human adds the entry.
            return None
        return [
            sys.executable,
            "scripts/refresh_data_dirs.py",
            "--key",
            subject,
            "--force",
        ]

    if area == "ci" and subject == "install.py pin":
        # The pin is the hash of the committed install.py, nothing to judge.
        return [sys.executable, "scripts/pin_installer.py"]

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
        if subject in ("no-intro games", "redump games"):
            # The game DATs download without a browser, unlike the BIOS ones.
            return [
                sys.executable,
                "-m",
                "scripts.scraper.game_dat_importer",
                "--source",
                subject.split()[0],
                "--fetch",
                "--refresh",
                "--floor",
            ]
        # redump / no-intro / tosec need manual DAT download.
        return None

    # coreinfo, ci, profiles: never auto-refresh.
    return None


def _github_token_env() -> dict[str, str]:
    """Hand `gh auth token` to the subprocess environment.

    emudeck and retropie target scrapers hit the GitHub API. Without a token
    the unauthenticated rate limit (60/h) is burnt within a few platforms.
    """
    from common import github_token  # noqa: PLC0415

    env = os.environ.copy()
    token = github_token()
    if token:
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

        rescraped = sorted(
            (r for r in results if r.job.area == "platforms" and r.returncode == 0),
            key=lambda r: r.job.subject,
        )
        if rescraped:
            lines.append(
                "\n[verify] a rescrape can add systems: read each report "
                "before keeping platforms/<name>.yml"
            )
            for r in rescraped:
                summary = verify_summary(r.job.log_path) or "(no verify output)"
                lines.append(f"  {r.job.subject:12} {summary}")
                lines.append(
                    f"  {'':12} python scripts/verify.py --platform {r.job.subject}"
                )

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
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--only",
        help="comma-separated areas to check: " + ",".join(AUTO_AREAS)
        + " (refreshed), " + ",".join(MANUAL_AREAS) + " (listed for a human)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="list what would be refreshed without running any command",
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
        help="machine-readable summary (jobs, surfaced, ignored), the plan with --dry-run",
    )
    parser.add_argument(
        "--findings",
        metavar="FILE",
        help="read the check_freshness.py --json report from FILE instead of "
        "running it (rows outside --only are left out)",
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
            parser.error(
                f"unknown area: {', '.join(unknown)}. Areas: {', '.join(all_areas)}"
            )
    else:
        areas = all_areas

    try:
        if args.findings:
            findings = load_findings(Path(args.findings), areas)
        else:
            findings = _run_check_freshness(areas, args.freshness_arg)
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 2

    registry = _load_platform_registry()
    jobs, surfaced, ignored = plan_jobs(findings, registry)

    if args.dry_run and args.json:
        print(json.dumps({
            "planned": [
                {
                    "area": job.area,
                    "subject": job.subject,
                    "command": job.command,
                    "after": sorted(job.after),
                    "then": [list(command) for command in job.then],
                }
                for job in sorted(jobs, key=lambda j: (j.area, j.subject))
            ],
            "surfaced": surfaced,
            "ignored_count": len(ignored),
        }, indent=2))
        return 0
    if args.dry_run:
        print(f"\n[plan] {len(jobs)} refreshable, {len(surfaced)} manual, "
              f"{len(ignored)} already clean/skipped")
        for job in sorted(jobs, key=lambda j: (j.area, j.subject)):
            print(f"  {job.area:10} {job.subject:28}  {' '.join(job.command)}")
            if job.after:
                print(f"  {'':10} {'':28}  after {', '.join(sorted(job.after))}")
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
    results = run_jobs(jobs, env, args.jobs)

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
    from common import run_cli

    run_cli(main)
