"""A scraper's own write path run on a throwaway copy of the committed file."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path

from core.paths import REPO_ROOT
from freshness.scrapers import rescrape_command
from scraper.base_scraper import DROPPED_PREFIX, ERROR_PREFIX


def failure_cause(output: str, returncode: int) -> str:
    """Why a scraper run failed: its error line, not the hint printed after it.

    Output without that line (a traceback) gives its last line.
    """
    lines = output.strip().splitlines()
    cause = next((line.removeprefix(ERROR_PREFIX) for line in lines if line.startswith(ERROR_PREFIX)), None)
    if cause is not None:
        return cause
    return lines[-1] if lines else f"exit {returncode}"


def scrape_into_copy(
    area: str, name: str, source: Path, workdir: Path,
    registry: Mapping[str, Mapping] | None = None, timeout: int = 900,
) -> tuple[Path, str | None, list[str]]:
    """Run a scraper's own write path on a throwaway copy of *source*.

    The CLI merges into the file it writes, so the copy carries every field
    the scraper preserves and the diff shows only what the scrape changes.
    The third value lists the upstream entries the scraper left out.
    """
    target = workdir / source.name
    command = rescrape_command(area, name, target, registry)
    if command is None:
        raise ValueError(f"no scraper rewrites {area} {name}")
    shutil.copyfile(source, target)
    proc = subprocess.run(
        command,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        return target, failure_cause(proc.stderr or proc.stdout, proc.returncode), []
    dropped = [
        line.removeprefix(DROPPED_PREFIX)
        for line in (proc.stderr or "").splitlines()
        if line.startswith(DROPPED_PREFIX)
    ]
    return target, None, dropped
