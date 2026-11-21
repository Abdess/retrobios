"""The files a review reads and writes: a branch's changed BIOS files, folders expanded, files placed."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from core.gitclone import compare_base, git_lines

if TYPE_CHECKING:
    from resolve.review import ValidationResult


def get_changed_files() -> list[str]:
    """BIOS files this checkout changes against the project's main line.

    Committed changes are read against the project's main line: the remote
    that names the project (upstream/<base> first, then origin/<base>), or
    the project's main fetched when no remote does. Uncommitted and
    untracked files count too,
    since CONTRIBUTING has the file copied into bios/ before any commit.
    A git that fails outright is an error, never "nothing changed".
    """
    changed: list[str] = []
    base = compare_base()
    committed = git_lines("diff", "--name-only", f"{base}...HEAD") if base else None
    compared = committed is not None
    changed.extend(committed or [])
    staged = git_lines("diff", "--cached", "--name-only")
    local = git_lines("diff", "--name-only")
    untracked = git_lines("ls-files", "--others", "--exclude-standard", "--", "bios")
    if staged is None and local is None and untracked is None:
        raise RuntimeError("git cannot read this checkout")
    for found in (staged, local, untracked):
        changed.extend(found or [])
    if not compared:
        print(
            "no upstream/ or origin/ main line to compare against, reading the "
            "staged, modified and untracked files only",
            file=sys.stderr,
        )
    return [f for f in dict.fromkeys(changed) if f.startswith("bios/") and os.path.isfile(f)]


def expand_folders(paths: list[str]) -> list[str]:
    """Each folder named replaced by the files under it, subfolders included.

    A card's BIOS folder was refused as "Not a regular file", and the
    contributor had to list its files by hand. A link inside the folder
    stays listed, so it is refused like a named one, and an empty folder
    stays as itself to be reported.
    """
    out: list[str] = []
    for path in paths:
        if not os.path.isdir(path) or os.path.islink(path):
            out.append(path)
            continue
        found = sorted(
            str(f) for f in Path(path).rglob("*") if f.is_symlink() or f.is_file()
        )
        out.extend(found or [path])
    return out


def place(results: list[ValidationResult]) -> list[str]:
    """Copy each placeable file to its destination, never over a file.

    The report named the folder of each file and left 40 copies from a card
    to be made by hand, each .variants/ name retyped. The source is copied,
    not moved: it is often a card or another tree the contributor keeps.
    """
    placed = []
    for r in results:
        if not (r.passed and r.destination and not r.outcome):
            continue
        target = Path(r.destination)
        if target.exists():
            print(f"not placed: {target} exists", file=sys.stderr)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(r.filepath, target)
        placed.append(r.destination)
        print(f"placed {r.filepath} at {r.destination}", file=sys.stderr)
    return placed
