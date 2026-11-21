"""Refresh jobs run in parallel, each after the rescrapes it waits for, logged to tmp/."""

from __future__ import annotations

import os
import subprocess
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

from core.paths import REPO_ROOT
from freshness.stalejob import Job, JobResult

JOB_TIMEOUT = 1800  # 30 minutes per refresher, scrapers rarely exceed 10


def github_token_env() -> dict[str, str]:
    """Hand `gh auth token` to the subprocess environment.

    emudeck and retropie target scrapers hit the GitHub API. Without a token
    the unauthenticated rate limit (60/h) is burnt within a few platforms.
    """
    from core.github import github_token

    env = os.environ.copy()
    token = github_token()
    if token:
        env["GITHUB_TOKEN"] = token
    return env


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


def run_job(job: Job, env: dict[str, str]) -> JobResult:
    """Execute one refresh command and collect its output."""
    start = time.monotonic()
    job.log_path.parent.mkdir(parents=True, exist_ok=True)
    returncode = 0
    outputs: list[tuple[tuple[str, ...], str]] = []
    with job.log_path.open("w", encoding="utf-8") as log:
        for command in (job.command, *job.then):
            log.write(f"$ {' '.join(command)}\n")
            log.flush()
            start_offset = job.log_path.stat().st_size
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
            log.flush()
            outputs.append((tuple(command), _log_since(job.log_path, start_offset)))
            if returncode != 0:
                break
    duration = time.monotonic() - start
    tail = _log_tail(job.log_path)
    return JobResult(job=job, returncode=returncode, duration=duration, tail=tail,
                     outputs=tuple(outputs))


def _log_since(path: Path, offset: int) -> str:
    """What a log holds past *offset*: the output of the command that just ran."""
    with path.open("rb") as log:
        log.seek(offset)
        return log.read().decode("utf-8", errors="replace")


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
