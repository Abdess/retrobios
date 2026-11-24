"""Git for the jobs that commit: the automation worktree, the paths each commit
may carry, and the push.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

from core.generated import matches_any
from core.gitclone import GitRefused
from core.gitclone import main_checkout as gitclone_main_checkout
from core.paths import REPO_ROOT
from unattended.jobs import AutorunError, BLOCKED, CommitRule, FAILED, token_env


BRANCH = "autorun"
REMOTE = "origin"
TARGET = "main"


# Git


def git(cwd: Path, *args: str, check: bool = True,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["git", "-C", str(cwd), *args], capture_output=True, text=True, check=False, env=env,
    )
    if check and proc.returncode != 0:
        raise AutorunError(
            FAILED, f"git {' '.join(args)}: {(proc.stderr or proc.stdout).strip()}"
        )
    return proc


def changed_files(worktree: Path) -> list[str]:
    """Every path git status reports, untracked included, ignored excluded."""
    out = git(worktree, "status", "--porcelain=v1", "-z", "--untracked-files=all").stdout
    entries = out.split("\0")
    paths: list[str] = []
    i = 0
    while i < len(entries):
        entry = entries[i]
        i += 1
        if len(entry) < 4:
            continue
        paths.append(entry[3:])
        if entry[0] in "RC":
            i += 1  # the rename source follows
    return sorted(set(paths))


def plan_commit(changed: Sequence[str], patterns: Sequence[str]) -> list[str]:
    return sorted(p for p in changed if matches_any(p, patterns))


def commit_paths(worktree: Path, files: Sequence[str], rule: CommitRule) -> str:
    """Commit exactly these files, and return the new commit."""
    if not files:
        raise ValueError("no file to commit")
    git(worktree, "add", "--", *files)
    message = ["-m", rule.subject] + (["-m", rule.body] if rule.body else [])
    git(worktree, "commit", "--quiet", *message, "--", *files)
    return git(worktree, "rev-parse", "HEAD").stdout.strip()


def _hardlink_tree(src: Path, dst: Path) -> None:
    if src.is_dir():
        shutil.copytree(src, dst, copy_function=os.link, symlinks=True)
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        os.link(src, dst)


def seed_worktree(repo: Path, worktree: Path) -> list[str]:
    """Hard-link what git does not carry: a tool deleting a file drops a link."""
    from model.largefiles import LARGE_FILES_CACHE, load_registered_paths

    seeded = []
    for rel in [LARGE_FILES_CACHE, "data", *load_registered_paths(repo / ".gitignore")]:
        src, dst = repo / rel, worktree / rel
        if src.exists() and not dst.exists():
            _hardlink_tree(src, dst)
            seeded.append(rel)
    return seeded


def ensure_worktree(repo: Path, worktree: Path) -> None:
    """Create the automation worktree on branch `autorun`, once."""
    if (worktree / ".git").exists():
        return
    git(repo, "fetch", "--quiet", REMOTE, TARGET)
    has_branch = git(
        repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{BRANCH}", check=False
    ).returncode == 0
    worktree.parent.mkdir(parents=True, exist_ok=True)
    if has_branch:
        git(repo, "worktree", "add", str(worktree), BRANCH)
    else:
        git(repo, "worktree", "add", "-b", BRANCH, str(worktree), f"{REMOTE}/{TARGET}")


def sync_worktree(worktree: Path) -> str:
    """Bring the worktree onto origin/main, and return the base it now sits on."""
    leftovers = changed_files(worktree)
    if leftovers:
        raise AutorunError(
            BLOCKED, f"worktree holds {len(leftovers)} uncommitted paths: "
            + ", ".join(leftovers[:5])
        )
    git(worktree, "fetch", "--quiet", REMOTE, TARGET)
    upstream = f"{REMOTE}/{TARGET}"
    ahead = int(git(worktree, "rev-list", "--count", f"{upstream}..HEAD").stdout)
    if ahead == 0:
        git(worktree, "merge", "--ff-only", "--quiet", upstream)
    elif (git(worktree, "merge-base", "--is-ancestor", upstream, "HEAD", check=False).returncode != 0
          and git(worktree, "rebase", "--quiet", upstream, check=False).returncode != 0):
        git(worktree, "rebase", "--abort", check=False)
        raise AutorunError(BLOCKED, f"{ahead} automation commits conflict with {upstream}")
    return git(worktree, "rev-parse", upstream).stdout.strip()


def unpushed(worktree: Path) -> int:
    if not (worktree / ".git").exists():
        return 0
    proc = git(worktree, "rev-list", "--count", f"{REMOTE}/{TARGET}..HEAD", check=False)
    return int(proc.stdout.strip() or 0) if proc.returncode == 0 else 0


def push_batch(worktree: Path, gate_base: str, regate: Callable[[], bool]) -> str:
    """Rebase the night's commits on origin/main, gate again if it moved, push."""
    git(worktree, "fetch", "--quiet", REMOTE, TARGET)
    upstream = f"{REMOTE}/{TARGET}"
    if int(git(worktree, "rev-list", "--count", f"{upstream}..HEAD").stdout) == 0:
        return ""
    if (git(worktree, "merge-base", "--is-ancestor", upstream, "HEAD", check=False).returncode != 0
            and git(worktree, "rebase", "--quiet", upstream, check=False).returncode != 0):
        git(worktree, "rebase", "--abort", check=False)
        raise AutorunError(BLOCKED, f"rebase onto {upstream} conflicts, batch kept")
    if git(worktree, "rev-parse", upstream).stdout.strip() != gate_base and not regate():
        raise AutorunError(FAILED, f"gate failed on the batch rebased onto {upstream}")
    git(worktree, "push", "--quiet", REMOTE, f"HEAD:{TARGET}", env=token_env())
    return git(worktree, "rev-parse", "HEAD").stdout.strip()


# Command line


def main_checkout() -> Path:
    """The main checkout, also when this script runs from a linked worktree."""
    try:
        return gitclone_main_checkout(REPO_ROOT)
    except GitRefused:
        return REPO_ROOT
