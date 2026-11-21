"""The plan and the outcome of a refresh, as a table for a human or as JSON."""

from __future__ import annotations

from pathlib import Path

from core.paths import REPO_ROOT
from freshness.stalejob import Job, JobResult

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


def _by_area(jobs: list[Job]) -> list[Job]:
    return sorted(jobs, key=lambda j: (j.area, j.subject))


def plan_payload(jobs: list[Job], surfaced: list[dict], ignored: list[dict]) -> dict:
    """What --dry-run --json prints: the planned jobs and the rows for a human."""
    return {
        "planned": [
            {
                "area": job.area,
                "subject": job.subject,
                "command": job.command,
                "after": sorted(job.after),
                "then": [list(command) for command in job.then],
            }
            for job in _by_area(jobs)
        ],
        "surfaced": surfaced,
        "ignored_count": len(ignored),
    }


def plan_text(jobs: list[Job], surfaced: list[dict], ignored: list[dict]) -> str:
    """What --dry-run prints: each job with its waits and follow-ups."""
    lines = [f"\n[plan] {len(jobs)} refreshable, {len(surfaced)} manual, "
             f"{len(ignored)} already clean/skipped"]
    for job in _by_area(jobs):
        lines.append(f"  {job.area:10} {job.subject:28}  {' '.join(job.command)}")
        if job.after:
            lines.append(f"  {'':10} {'':28}  after {', '.join(sorted(job.after))}")
        lines.extend(f"  {'':10} {'':28}  then {' '.join(command)}" for command in job.then)
    if surfaced:
        lines.append("\n[manual review needed]")
        lines.extend(f"  {f.get('status', ''):7} {f.get('area', ''):10} "
                     f"{f.get('subject', ''):28}  {str(f.get('detail') or '')[:100]}"
                     for f in surfaced)
    return "\n".join(lines)


def results_payload(results: list[JobResult], surfaced: list[dict], ignored: list[dict]) -> dict:
    """What --json prints after a run: each job's exit, duration, log and last line."""
    return {
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
