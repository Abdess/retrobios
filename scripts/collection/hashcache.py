"""The digest cache a scan of bios/ reuses for files whose mtime and size did not move."""

from __future__ import annotations

import json
import os

from core.artifacts import write_text_atomic

CACHE_DIR = ".cache"
CACHE_FILE = os.path.join(CACHE_DIR, "db_cache.json")


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
