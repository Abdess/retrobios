"""A scraper's own write path run on a throwaway copy of the committed file."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path

from core.paths import REPO_ROOT
from freshness.scrapers import rescrape_command


def scrape_into_copy(
    area: str, name: str, source: Path, workdir: Path,
    registry: Mapping[str, Mapping] | None = None, timeout: int = 900,
) -> tuple[Path, str | None]:
    """Run a scraper's own write path on a throwaway copy of *source*.

    The CLI merges into the file it writes, so the copy carries every field
    the scraper preserves and the diff shows only what the scrape changes.
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
        return target, tail[0] if tail else f"exit {proc.returncode}"
    return target, None
