"""Loading database.json and the MAME clone map written beside the collection."""

from __future__ import annotations

import json
import os
from pathlib import Path

from core.cli import InputMissing
from core.paths import REPO_ROOT


class DatabaseUnreadable(InputMissing):
    """The database a command was pointed at does not exist or is not JSON."""


def load_database(db_path: str) -> dict:
    """Load database.json and return parsed dict.

    A missing or damaged file raises DatabaseUnreadable, which run_cli turns
    into one line saying how to build it: `--db nosuch.json` ended at the
    bottom of a stack trace.
    """
    try:
        with open(db_path) as f:
            return json.load(f)
    except FileNotFoundError:
        # A mistyped --db beside the real database was told to rescan the
        # whole collection into a second file under the typo.
        import difflib

        typed = Path(db_path)
        close = difflib.get_close_matches(
            typed.name, [p.name for p in typed.parent.glob("*.json")], n=1, cutoff=0.8
        )
        if close:
            raise DatabaseUnreadable(
                f"{db_path} not found. Close match: {typed.with_name(close[0])}"
            ) from None
        raise DatabaseUnreadable(
            f"{db_path} not found. Build it with: python scripts/generate_db.py "
            f"--force --bios-dir bios --output {db_path}"
        ) from None
    except json.JSONDecodeError as exc:
        raise DatabaseUnreadable(
            f"{db_path} is not valid JSON ({exc}). Rebuild it with: "
            f"python scripts/generate_db.py --force --bios-dir bios --output {db_path}"
        ) from None


_mame_clone_map_cache: dict[str, dict[str, str]] = {}


def get_mame_clone_map(bios_dir: str | None = None) -> dict[str, str]:
    """The MAME clone map (clone_name -> canonical_name) of a scanned tree.

    dedup.py writes _mame_clones.json beside the tree it scanned, and the
    map of one tree says nothing about another: read from the repository
    root whatever ``--bios-dir`` said, an alternate tree's renamed clones
    fell out of its packs. Without a tree the repository's own is read.
    """
    if bios_dir is None:
        bios_dir = os.path.join(
            REPO_ROOT, "bios"
        )
    clone_path = os.path.join(os.path.dirname(os.path.abspath(bios_dir)), "_mame_clones.json")
    cached = _mame_clone_map_cache.get(clone_path)
    if cached is not None:
        return cached
    clone_map: dict[str, str] = {}
    if os.path.exists(clone_path):
        with open(clone_path) as f:
            data = json.load(f)
        for canonical, info in data.items():
            for clone in info.get("clones", []):
                clone_map[clone] = canonical
    _mame_clone_map_cache[clone_path] = clone_map
    return clone_map
