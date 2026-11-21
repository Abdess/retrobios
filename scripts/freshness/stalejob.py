"""The refresh job a stale row becomes, its result, and the areas refreshed or listed."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from core.paths import REPO_ROOT

LOG_DIR = REPO_ROOT / "tmp" / "refresh_stale"

AUTO_AREAS = ("platforms", "native", "targets", "data", "catalogs")
# A rom-folder pin is moved by hand in platforms/romfolders/_sources/,
# then `python -m scripts.scraper.romfolders --setup NAME` reads it again.
MANUAL_AREAS = ("romfolders", "coreinfo", "ci", "profiles")


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
