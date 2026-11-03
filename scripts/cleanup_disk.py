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
tmp/acquire, git bundles (*.bundle, which are backups) and an entry that
holds a linked worktree, which the worktree rule judges.

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
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

GENERATED = re.compile(
    r"^(database\.json|install/.*\.json|exports/.*\.json|README\.md|CONTRIBUTING\.md"
    r"|website/src/data/[^/]+\.json)$"
)
KEPT_TMP = ("acquire",)
AUTOMATION_WORKTREE = Path(".cache") / "autorun" / "worktree"
ALERT_GB = 100


@dataclass(frozen=True)
class Decision:
    path: Path
    kind: str  # worktree, tmp
    action: str  # remove, keep
    reason: str


def git(cwd: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", "-C", str(cwd), *args], capture_output=True, text=True, check=False,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout


def main_checkout(cwd: Path) -> Path:
    """The main checkout, also when run from inside a linked worktree."""
    common = git(cwd, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    return Path(common).parent


def busy_paths() -> set[str]:
    """Every working directory and open file of every readable process."""
    found: set[str] = set()
    proc = Path("/proc")
    if not proc.is_dir():
        return found
    for pid in proc.iterdir():
        if not pid.name.isdigit():
            continue
        links = [pid / "cwd"]
        try:
            links += list((pid / "fd").iterdir())
        except OSError:
            pass
        for link in links:
            try:
                found.add(os.readlink(link))
            except OSError:
                continue
    return found


def inside(path: Path, root: Path) -> bool:
    return str(path) == str(root) or str(path).startswith(f"{root}/")


def in_use(path: Path, busy: Iterable[str]) -> bool:
    root = str(path)
    prefix = f"{root}/"
    return any(b == root or b.startswith(prefix) for b in busy)


def age_hours(path: Path, now: float) -> float:
    return (now - path.stat().st_mtime) / 3600


def real_changes(worktree: Path) -> list[str]:
    """Modified tracked paths that are neither deletions nor generated files."""
    out = git(worktree, "status", "--porcelain", "--untracked-files=no")
    paths = []
    for line in out.splitlines():
        if len(line) < 4 or line[:2].strip() == "D":
            continue
        path = line[3:].split(" -> ")[-1].strip('"')
        if not GENERATED.match(path):
            paths.append(path)
    return paths


def linked_worktrees(repo: Path) -> list[Path]:
    """Every linked worktree of the checkout, wherever it lives."""
    out = git(repo, "worktree", "list", "--porcelain")
    paths = [Path(line[len("worktree "):]) for line in out.splitlines()
             if line.startswith("worktree ")]
    return [p for p in paths if p != repo]


def session_worktrees(repo: Path) -> list[Path]:
    """Linked worktrees inside the checkout, the automation worktree aside."""
    keep = repo / AUTOMATION_WORKTREE
    return [p for p in linked_worktrees(repo) if inside(p, repo) and p != keep]


def judge_worktree(path: Path, busy: Iterable[str], hours: float, now: float) -> Decision:
    if in_use(path, busy):
        return Decision(path, "worktree", "keep", "in use")
    age = age_hours(path, now)
    if age <= hours:
        return Decision(path, "worktree", "keep", f"{age:.0f}h recent")
    real = real_changes(path)
    if real:
        return Decision(path, "worktree", "keep", f"uncommitted code: {len(real)} files")
    return Decision(path, "worktree", "remove", f"{age:.0f}h old, clean")


def judge_tmp(
    repo: Path, busy: Iterable[str], hours: float, now: float,
    worktrees: Iterable[Path] = (),
) -> list[Decision]:
    tmp = repo / "tmp"
    if not tmp.is_dir():
        return []
    worktrees = list(worktrees)
    decisions = []
    for entry in sorted(tmp.iterdir()):
        if entry.name in KEPT_TMP or entry.name.endswith(".bundle"):
            action, reason = "keep", "backup"
        elif any(inside(w, entry) for w in worktrees):
            action, reason = "keep", "holds a worktree"
        elif age_hours(entry, now) <= hours:
            action, reason = "keep", "recent"
        elif in_use(entry, busy):
            action, reason = "keep", "in use"
        else:
            action, reason = "remove", "old"
        decisions.append(Decision(entry, "tmp", action, reason))
    return decisions


def plan(repo: Path, busy: Iterable[str], hours: float, now: float) -> list[Decision]:
    busy = set(busy)
    worktrees = [judge_worktree(w, busy, hours, now) for w in session_worktrees(repo)
                 if w.is_dir()]
    return worktrees + judge_tmp(repo, busy, hours, now, linked_worktrees(repo))


def apply(repo: Path, decisions: Iterable[Decision]) -> list[str]:
    """Carry out the removals, and return the failures."""
    failures = []
    removed_worktree = False
    for d in decisions:
        if d.action != "remove":
            continue
        if d.kind == "worktree":
            git(repo, "worktree", "unlock", str(d.path), check=False)
            proc = subprocess.run(
                ["git", "-C", str(repo), "worktree", "remove", "--force", str(d.path)],
                capture_output=True, text=True, check=False,
            )
            if proc.returncode != 0:
                failures.append(f"{d.path}: {proc.stderr.strip()}")
            removed_worktree = True
            continue
        try:
            if d.path.is_dir() and not d.path.is_symlink():
                shutil.rmtree(d.path)
            else:
                d.path.unlink()
        except OSError as exc:
            failures.append(f"{d.path}: {exc}")
    if removed_worktree:
        git(repo, "worktree", "prune", check=False)
    return failures


def disk_line(path: Path, alert_gb: float) -> tuple[str, bool]:
    usage = shutil.disk_usage(path)
    free, total = usage.free / 1024 ** 3, usage.total / 1024 ** 3
    low = free < alert_gb
    line = f"disk: {free:.0f} GB free of {total:.0f} GB"
    if low:
        line += f"\nALERT: free space under {alert_gb:.0f} GB"
    return line, low


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n\n")[0])
    parser.add_argument("--apply", action="store_true", help="delete (default: dry run)")
    parser.add_argument("--hours", type=float, default=72,
                        help="keep anything younger than this (default: %(default)s)")
    parser.add_argument("--alert-gb", type=float, default=ALERT_GB,
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
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from common import run_cli

    run_cli(main)
