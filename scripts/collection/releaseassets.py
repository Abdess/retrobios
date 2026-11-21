"""The database entries of release assets the checkout does not hold, kept across a scan."""

from __future__ import annotations

import json
import os
from pathlib import Path


class DatabaseUnreadable(Exception):
    """The previous database exists and is not JSON: its release-asset entries cannot be kept."""


def load_gitignored_large_files(gitignore: str | Path) -> set[str]:
    """The bios/ paths a .gitignore registers as release assets."""
    from model.largefiles import load_registered_paths

    return set(load_registered_paths(gitignore))


def read_database(db_path: str) -> dict | None:
    """The previous database, None when there is none."""
    try:
        with open(db_path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        # An unreadable database is not an absent one: rewriting it from a
        # checkout without the release assets would drop every entry they
        # hold, and the manifests regenerated from it would omit them.
        raise DatabaseUnreadable(
            f"{db_path} is not valid JSON ({e}). Restore it from git "
            "or regenerate it on a checkout holding the release assets before "
            "scanning again"
        ) from e


def surviving_entries(existing_db: dict, files: dict, registered: set[str]) -> dict:
    """The entries of the previous database a scan that missed their file keeps.

    Files kept out of git live as assets of the large-files release, and
    .gitignore registers their paths. An entry survives only under that
    registered path: a bare name is shared by other files (pak0.pk3,
    history.db), and a path rewritten into the download cache is no longer
    one .gitignore knows, so the manifest would send the installer to the
    repository for it.
    """
    # A path the scan just claimed holds known bytes. An older entry naming
    # the same path describes a revision that is no longer there, and keeping
    # it would publish a hash that contradicts the file it points at.
    scanned_paths = {entry.get("path", "") for entry in files.values()}
    return {
        sha1: entry
        for sha1, entry in existing_db.get("files", {}).items()
        if sha1 not in files
        and entry.get("path", "") in registered
        and entry.get("path", "") not in scanned_paths
    }


def restore_release_assets(
    entries: dict, registered: set[str], tree: Path, *, offline: bool
) -> None:
    """Write each kept entry's asset back to its registered path under tree, fetched only when online."""
    from model.largefiles import fetch_large_file, restore_verified

    for sha1, entry in entries.items():
        path = entry.get("path", "")
        cached = fetch_large_file(
            path,
            expected_sha1=entry.get("sha1", ""),
            expected_md5=entry.get("md5", ""),
            offline=offline,
            registered=registered,
        )
        destination = str(tree / path)
        if cached and not os.path.exists(destination):
            restore_verified(cached, destination, sha1)
