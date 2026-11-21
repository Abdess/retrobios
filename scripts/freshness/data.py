"""The data directories and the buildbot system assets against their upstream."""

from __future__ import annotations

import contextlib
import io
from pathlib import Path

from core.paths import DATA_DIRS_FILE
from model.registry import load_data_dir_registry
from packs import datadirs
from freshness.findings import OK, SHOWN_NAMES, SKIPPED, STALE, UNKNOWN, Finding


def check_data(platforms_dir: Path, offline: bool) -> list[Finding]:
    if offline:
        return [Finding("data", "_data_dirs.yml", SKIPPED, detail="offline")]
    registry = load_data_dir_registry(platforms_dir, required=True)
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink):
        results = datadirs.refresh_all(registry, dry_run=True)
    findings = []
    for key, result in sorted(results.items()):
        if result is None:
            findings.append(Finding("data", key, UNKNOWN, detail="remote unreachable"))
        elif result:
            findings.append(Finding("data", key, STALE, detail="upstream changed, refresh_data_dirs.py fetches it"))
        else:
            findings.append(Finding("data", key, OK))
    findings.append(_check_buildbot_system(platforms_dir))
    return findings


def _check_buildbot_system(platforms_dir: Path) -> Finding:
    """The buildbot's system directory against what _data_dirs.yml tracks.

    The registry entries are refreshed above. An asset published since, or
    one the buildbot no longer serves, is only seen by reading its .index.
    """
    from scraper import buildbot_system

    with contextlib.redirect_stdout(io.StringIO()):
        report = buildbot_system.check(str(platforms_dir / Path(DATA_DIRS_FILE).name))
    if report.get("error"):
        return Finding("data", "buildbot system", UNKNOWN, detail="index unreachable")
    todo = buildbot_system.pending(report)
    if not todo:
        return Finding("data", "buildbot system", OK)
    every = [f"{e['status'].lower()} {e['zip']}" for e in todo]
    names = ", ".join(every[:SHOWN_NAMES])
    more = f", ... (--json lists all {len(todo)})" if len(todo) > SHOWN_NAMES else ""
    return Finding("data", "buildbot system", STALE, local=f"{len(todo)} to track",
                   detail=f"{names}{more} (_data_dirs.yml)", items=every)
