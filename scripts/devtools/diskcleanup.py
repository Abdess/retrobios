"""Which idle session worktrees and tmp/ entries can go, their removal, and the free space left."""

from __future__ import annotations

import contextlib
import fnmatch
import os
import shutil
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from core.generated import is_generated
from core.paths import AUTORUN_WORKTREE

# What tmp/ keeps whatever its age, by name pattern, with the reason printed.
KEPT_TMP: dict[str, str] = {
    # auto_fetch writes the files it found and verified here.
    "acquire": "backup",
    # A git bundle or a patch saved before a risky operation.
    "*.bundle": "backup",
    "*.patch": "backup",
    # The TUI pty tests run under tmp/tuienv312 and tmp/tuienv38.
    "tuienv*": "test environment",
    # The Python 3.8 wrapper the installer floor is checked with.
    "py38bin": "test environment",
    # The CI guardian's log, scripts and the runs it has already seen.
    "ci_guardian*": "CI guardian state",
}
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
        with contextlib.suppress(OSError):
            links += list((pid / "fd").iterdir())
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
        if not is_generated(path):
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
    keep = repo / AUTORUN_WORKTREE
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


def kept_reason(name: str) -> str:
    """Why tmp/ keeps an entry of this name whatever its age, or ''."""
    return next((reason for pattern, reason in KEPT_TMP.items()
                 if fnmatch.fnmatchcase(name, pattern)), "")


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
        kept = kept_reason(entry.name)
        if kept:
            action, reason = "keep", kept
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
