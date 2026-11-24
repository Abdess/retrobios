#!/usr/bin/env python3
"""Free disk space that idle session worktrees and tmp/ hold, safely.

Dry run by default, --apply deletes.

Candidates are the linked worktrees placed inside the checkout, where
sessions create theirs. A worktree elsewhere on disk and the automation
worktree (.cache/autorun/worktree) are never candidates. One is removed only
when no process runs in or holds a file of it, it is older than --hours, and
nothing tracked is modified in it except generated artifacts (database.json,
install/*.json, exports/*.json, README.md, CONTRIBUTING.md,
website/src/data/*.json). Branches are always
kept, so committed work stays reachable. A worktree with real uncommitted
code is listed, never removed.

tmp/ entries older than --hours that no process uses are removed, except
what KEPT_TMP in devtools/diskcleanup.py lists (tmp/acquire, git bundles and
patches, the TUI test environments, the Python 3.8 wrapper, the CI
guardian's state) and an entry that holds a linked worktree, which the
worktree rule judges.

The last line reports free space, and an ALERT line when it is under
--alert-gb. The exit code is 1 under that threshold, so a timer sees it.

Usage:
    python scripts/cleanup_disk.py
    python scripts/cleanup_disk.py --apply --hours 72
    python scripts/cleanup_disk.py --check
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.gitclone import main_checkout
from core.hostguard import LOW_DISK_GB
from devtools.diskcleanup import apply, busy_paths, disk_line, inside, plan


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n\n")[0])
    parser.add_argument("--apply", action="store_true", help="delete (default: dry run)")
    parser.add_argument("--hours", type=float, default=72,
                        help="keep anything younger than this (default: %(default)s)")
    parser.add_argument("--alert-gb", type=float, default=LOW_DISK_GB,
                        help="alert under this much free space (default: %(default)s)")
    parser.add_argument("--check", action="store_true",
                        help="report free space only, delete nothing")
    args = parser.parse_args()

    repo = main_checkout(Path.cwd())
    if not args.check:
        decisions = plan(repo, busy_paths(), args.hours, time.time())
        verb = "removing" if args.apply else "would remove"
        for d in decisions:
            rel = d.path.relative_to(repo) if inside(d.path, repo) else d.path
            label = verb if d.action == "remove" else f"keep ({d.reason})"
            print(f"{label:28} {rel}")
        failures = apply(repo, decisions) if args.apply else []
        for failure in failures:
            print(f"FAILED {failure}", file=sys.stderr)
        if failures:
            print(disk_line(repo, args.alert_gb)[0])
            return 2
    line, low = disk_line(repo, args.alert_gb)
    print(line)
    return 1 if low else 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
