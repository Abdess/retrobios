"""Gitignored large files restored into the checkout from the release cache."""

from __future__ import annotations

import contextlib
import os
import sys
import tempfile
from pathlib import Path

from model.largefiles import registered_paths
from core.artifacts import copy_file_atomic, set_plain_mode
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


def _copy_verified(source: str, path: str, sha1: str) -> bool:
    """Copy *source* to *path* only if the copy hashes to *sha1*.

    The cache was hashed before the copy, and another run can replace a
    cached name in between (a re-uploaded asset): the copy is what counts.
    Whole or absent: a scan running beside a plain copy hashed the truncated
    file and published that in the database.
    """
    handle, scratch = tempfile.mkstemp(
        dir=os.path.dirname(os.path.abspath(path)),
        prefix=f".{os.path.basename(path)}.", suffix=".tmp",
    )
    os.close(handle)
    try:
        copy_file_atomic(source, scratch)
        if file_digest(Path(scratch)) != sha1:
            print(f"Changed in the cache while restoring: {source}", file=sys.stderr)
            return False
        set_plain_mode(scratch)
        os.replace(scratch, path)
        return True
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(scratch)


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
        if not _copy_verified(source, path, sha1):
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
