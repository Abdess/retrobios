"""A disposable copy of the checkout, for tests that run a writer and expect
it to refuse.

Run in the checkout, a regression made the very write the test guards
against: generate_site rewrote website/src/data/published-parts.json and the
FAQ page whatever --docs-dir said, and a pipeline whose lock probe failed
would regenerate database.json and install/. A file another session had
already changed listed the same name in `git diff --name-only` before and
after, so its edits were lost without a signal.

The copy holds every file git tracks or would track, as the working tree has
it. bios/ and data/ (17 GB and 600 MB of inputs no such test writes) are
links to the checkout's.
"""

from __future__ import annotations

import atexit
import hashlib
import os
import shutil
import subprocess
import tempfile
from functools import cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LINKED = ("bios", "data")


@cache
def scratch_checkout() -> Path:
    """The copy, built once per test process and removed at its exit."""
    root = Path(tempfile.mkdtemp(prefix="checkout-", dir=REPO_ROOT / "tmp" / "tests"))
    # A detached worktree with nothing checked out: the scripts that read
    # HEAD (the site's bootstrap pin) find this commit.
    subprocess.run(
        ["git", "worktree", "add", "--quiet", "--detach", "--no-checkout", str(root), "HEAD"],
        cwd=REPO_ROOT, capture_output=True, check=True,
    )
    atexit.register(_remove, root)
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=REPO_ROOT, capture_output=True, check=True,
    ).stdout.decode("utf-8")
    for name in filter(None, listed.split("\0")):
        source = REPO_ROOT / name
        if name.split("/", 1)[0] in LINKED or not source.is_file() or source.is_symlink():
            continue
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    for name in LINKED:
        if (REPO_ROOT / name).exists():
            (root / name).symlink_to(REPO_ROOT / name, target_is_directory=True)
    return root


def _remove(root: Path) -> None:
    subprocess.run(["git", "worktree", "remove", "--force", str(root)],
                   cwd=REPO_ROOT, capture_output=True, check=False)
    shutil.rmtree(root, ignore_errors=True)


def snapshot(root: Path) -> dict[str, str]:
    """The SHA-1 of every file under root, links not followed. A file
    written with the bytes it held is no change: what is caught is a file
    whose content a run replaced. Scratch space, caches, bytecode and lock
    files are no output."""
    seen = {}
    for directory, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != "__pycache__"
                   and Path(directory, d) not in (root / "tmp", root / ".cache")]
        for name in files:
            path = Path(directory) / name
            if name != ".lock" and not path.is_symlink():
                seen[str(path.relative_to(root))] = hashlib.sha1(path.read_bytes()).hexdigest()
    return seen
