"""Gitignored large files restored into the checkout from the release cache."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
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


@dataclass
class Restored:
    """What a restore wrote, what it could not supply, and whether a cache was there."""

    restored: list[str] = field(default_factory=list)
    unsatisfied: list[str] = field(default_factory=list)
    cache_found: bool = True


def restore(cache_dir: str, db_path: str, gitignore: str, *, root: Path) -> Restored:
    """Write each gitignored, absent database path under root from the cache."""
    ignored = gitignored_paths(gitignore)
    result = Restored()
    # No cache is not nothing to do: the paths it would have supplied are
    # still missing, and the check below is the one that must say so.
    if os.path.isdir(cache_dir):
        index = index_cache(cache_dir)
    else:
        result.cache_found = False
        index = {}
    db = load_database(db_path)
    for sha1, entry in db.get("files", {}).items():
        path = entry.get("path", "")
        target = root / path
        if path not in ignored or target.exists():
            continue
        source = index.get(sha1)
        if not source or not restore_verified(source, str(target), sha1):
            result.unsatisfied.append(path)
            continue
        result.restored.append(path)
    return result
