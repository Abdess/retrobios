"""Loading database.json and the MAME clone map written beside the collection."""

from __future__ import annotations

import json
import os
from pathlib import Path

from core.cli import InputMissing
from core.hashing import cut_md5_owner
from core.memo import DerivedView
from core.paths import DB_FILE, REPO_ROOT


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


def load_optional_database(db_path: str) -> dict | None:
    """The database, or None when the default one is absent.

    The default may be missing, a --db that was named must exist: a typo
    beside the real file was read as an empty collection.
    """
    if db_path == DB_FILE and not os.path.exists(db_path):
        return None
    return load_database(db_path)


def _index_paths(files: dict) -> dict[str, tuple[str, dict]]:
    """Normalized path -> (sha1, record)."""
    return {
        os.path.normpath(record["path"]): (sha1, record)
        for sha1, record in files.items()
        if record.get("path")
    }


_path_view = DerivedView(_index_paths)


def _path_index(db: dict) -> dict[str, tuple[str, dict]]:
    """Normalized path -> (sha1, record), built once per database."""
    return _path_view(db.get("files", {}))


def record_at(db: dict, path: str | None) -> dict | None:
    """The database record stored at a path, spelled any way normpath reads alike."""
    if not path:
        return None
    found = _path_index(db).get(os.path.normpath(path))
    return found[1] if found else None


def sha1_at(db: dict, path: str | None) -> str | None:
    """The sha1 the database keys the file at a path under."""
    if not path:
        return None
    found = _path_index(db).get(os.path.normpath(path))
    return found[0] if found else None


_HASH_INDEXES = {"md5": "by_md5", "crc32": "by_crc32", "sha256": "by_sha256"}


def record_for_hash(db: dict, kind: str, value: object) -> str | None:
    """The sha1 the database keys the file one hash value names under.

    A cut md5 (Batocera writes 29 characters) names the one held md5 it
    starts, as cut_md5_owner reads it.
    """
    if not (value and isinstance(value, str)):
        return None
    files = db.get("files", {})
    value = value.strip().lower()
    if kind == "sha1":
        return value if value in files else None
    index = db.get("indexes", {}).get(_HASH_INDEXES[kind], {})
    found = index.get(value)
    if found is None and kind == "md5":
        owner = cut_md5_owner(value, index)
        found = index.get(owner) if owner else None
    if isinstance(found, list):
        found = found[0] if found else None
    return found if found in files else None


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
