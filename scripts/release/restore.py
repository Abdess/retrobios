"""Gitignored large files restored into the checkout from the release cache."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from model.largefiles import registered_paths, restore_verified
from core.hashing import file_digest
from model.database import load_database


def gitignored_paths(gitignore: str) -> set[str]:
    """Paths the repository keeps out of git, as written in .gitignore.

    A missing file raises: read as empty, it left nothing to restore and
    nothing unsatisfied, and the run exited 0 with every asset absent.
    """
    return set(registered_paths(Path(gitignore).read_text(encoding="utf-8")))


def index_cache(cache_dir: str) -> dict[str, str]:
    """Map SHA1 to cached file path for every asset in the cache."""
    index: dict[str, str] = {}
    for name in sorted(os.listdir(cache_dir)):
        # A download in progress writes `<asset>.<random>.tmp` beside the
        # cache and renames it when done: it is partial, and may be gone by
        # the time it is opened.
        if name.endswith(".tmp"):
            continue
        path = os.path.join(cache_dir, name)
        if not os.path.isfile(path):
            continue
        index[file_digest(Path(path))] = path
    return index


def restore(
    cache_dir: str, db_path: str, gitignore: str
) -> tuple[int, list[str]]:
    ignored = gitignored_paths(gitignore)
    # No cache is not nothing to do: the paths it would have supplied are
    # still missing, and the check below is the one that must say so.
    if os.path.isdir(cache_dir):
        index = index_cache(cache_dir)
    else:
        print(f"No cache at {cache_dir}")
        index = {}
    db = load_database(db_path)
    restored = 0
    unsatisfied: list[str] = []
    for sha1, entry in db.get("files", {}).items():
        path = entry.get("path", "")
        if path not in ignored or os.path.exists(path):
            continue
        source = index.get(sha1)
        if not source:
            unsatisfied.append(path)
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not restore_verified(source, path, sha1):
            unsatisfied.append(path)
            continue
        print(f"Restored: {path}")
        restored += 1
    print(f"Total: {restored} files restored")
    if unsatisfied:
        # Every consumer downstream resolves against the disk, so a path the
        # cache cannot supply is not a smaller restore: it drops entries from
        # the manifest and inflates the missing count the README publishes.
        print(f"Unsatisfied: {len(unsatisfied)} declared paths the cache "
              "cannot supply", file=sys.stderr)
        for path in sorted(unsatisfied)[:10]:
            print(f"  {path}", file=sys.stderr)
    return restored, unsatisfied
