"""The digest cache a scan of bios/ reuses for files whose mtime and size did not move."""

from __future__ import annotations

import json
import os
from pathlib import Path

from core.artifacts import write_text_atomic


def cache_path(bios_dir: Path) -> str:
    """The cache of the tree holding bios_dir, beside it as its keys are relative to it.

    A path fixed on the working directory let a scan of a copy (tmp/wt/bios)
    replace the repository's cache with the copy's entries, keyed bios/...
    like the real ones, and the next real run rehashed every file.
    """
    return str(bios_dir.parent / ".cache" / "db_cache.json")


def load_cache(cache_path: str) -> dict:
    """Load cache file if it exists."""
    try:
        with open(cache_path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_cache(cache_path: str, cache: dict) -> None:
    """Save the cache whole or not at all.

    Written in place, a crash while serializing left a truncated file that
    the next run read as empty and rehashed the collection from scratch.
    """
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    write_text_atomic(cache_path, json.dumps(cache))
