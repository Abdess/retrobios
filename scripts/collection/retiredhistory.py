"""The files that left database.json, read back through its git history."""

from __future__ import annotations

import json
import subprocess

from core.paths import REPO_ROOT
from model.retired import FIRST_ADDRESSED, merge, retired_between


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True,
                          check=True).stdout


def backfill() -> dict[str, dict]:
    """Every sha1 that left database.json in the commits since content
    addresses were published, with the day of the commit that dropped it."""
    revisions = [line.split() for line in _git(
        "log", "--reverse", "--format=%H %cs", f"{FIRST_ADDRESSED}^..HEAD", "--", "database.json",
    ).splitlines() if line.strip()]
    records: dict[str, dict] = {}
    previous: dict | None = None
    for commit, day in revisions:
        current = json.loads(_git("show", f"{commit}:database.json"))
        if previous is not None:
            records = merge(records, retired_between(previous, current, day), current)
        previous = current
    return records
