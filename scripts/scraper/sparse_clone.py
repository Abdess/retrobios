"""A shallow sparse clone of an upstream tree, and the day-long cache of what
was read from it (the MAME and FBNeo hash scrapers)."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def fresh_cache(path: Path, hours: int = 24) -> dict[str, Any] | None:
    """The cache at `path` when it holds BIOS sets read less than `hours` ago.

    A missing, unreadable or damaged file, an empty read and a timestamp
    without a time zone all count as stale: the caller reads upstream again.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            cache = json.load(handle)
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("ignoring the cache %s: %s", path, exc)
        return None
    if not isinstance(cache, dict) or not cache.get("bios_sets"):
        return None
    try:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(cache["fetched_at"])
    except (KeyError, ValueError, TypeError):
        return None
    return cache if age < timedelta(hours=hours) else None


def _git(args: list[str], cwd: Path | None = None) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout


def sparse_clone(url: str, dest: Path, dirs: list[str], ref: str | None = None) -> str:
    """Clone `dirs` of `url` at `ref` (the default branch when None) into
    `dest`, replacing what is there, and return the commit cloned.

    Never an empty commit: returned empty, it was cached for a day and a
    merge advanced core_version and the refs while upstream_commit stayed
    on the previous release, a profile describing two revisions at once.
    """
    remove_clone(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    log.info("sparse cloning %s %s into %s", url, ref or "HEAD", dest)
    branch = ["--branch", ref] if ref else []
    _git(["clone", "--depth", "1", *branch, "--filter=blob:none", "--sparse", url, str(dest)])
    _git(["sparse-checkout", "set", *dirs], cwd=dest)
    try:
        commit = _git(["rev-parse", "HEAD"], cwd=dest).strip()
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"cannot read the commit of the clone in {dest}: {exc}") from exc
    if not commit:
        raise RuntimeError(f"the clone in {dest} names no commit")
    return commit


def remove_clone(dest: Path) -> None:
    if dest.exists():
        log.info("cleaning up %s", dest)
        shutil.rmtree(dest)
