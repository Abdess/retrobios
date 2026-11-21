"""A scraper's own write path run on a throwaway copy of the committed file."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path

from core.paths import REPO_ROOT
from freshness.scrapers import rescrape_command
from scraper.base_scraper import DROPPED_PREFIX


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
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:]
        return target, tail[0] if tail else f"exit {proc.returncode}", []
    dropped = [
        line.removeprefix(DROPPED_PREFIX)
        for line in (proc.stderr or "").splitlines()
        if line.startswith(DROPPED_PREFIX)
    ]
    return target, None, dropped
