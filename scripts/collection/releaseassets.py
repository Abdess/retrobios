"""The database entries of release assets the checkout does not hold, kept across a scan."""

from __future__ import annotations

import json
import os


def load_gitignored_large_files() -> set[str]:
    """The bios/ paths .gitignore registers as release assets."""
    from model.largefiles import load_registered_paths

    return set(load_registered_paths(".gitignore"))


def preserve_large_file_entries(files: dict, db_path: str) -> int:
    """Keep the entries of release assets the checkout does not hold.

    Files kept out of git live as assets of the large-files release, and
    .gitignore registers their paths. An entry survives a scan that missed
    its file only under that registered path: a bare name is shared by
    other files (pak0.pk3, history.db), and a path rewritten into the
    download cache is no longer one .gitignore knows, so the manifest
    would send the installer to the repository for it. A fetched asset is
    written back to its registered path.
    """
    from model.largefiles import fetch_large_file, restore_verified

    registered = load_gitignored_large_files()
    if not registered:
        return 0

    try:
        with open(db_path) as f:
            existing_db = json.load(f)
    except FileNotFoundError:
        return 0
    except json.JSONDecodeError as e:
        # An unreadable database is not an absent one: rewriting it from a
        # checkout without the release assets would drop every entry they
        # hold, and the manifests regenerated from it would omit them.
        raise SystemExit(
            f"{db_path} is not valid JSON ({e}). Restore it from git "
            "or regenerate it on a checkout holding the release assets before "
            "scanning again"
        ) from e

    # A path the scan just claimed holds known bytes. An older entry naming
    # the same path describes a revision that is no longer there, and keeping
    # it would publish a hash that contradicts the file it points at.
    scanned_paths = {entry.get("path", "") for entry in files.values()}

    count = 0
    for sha1, entry in existing_db.get("files", {}).items():
        path = entry.get("path", "")
        if sha1 in files or path not in registered or path in scanned_paths:
            continue
        cached = fetch_large_file(
            path,
            expected_sha1=entry.get("sha1", ""),
            expected_md5=entry.get("md5", ""),
        )
        if cached and not os.path.exists(path):
            restore_verified(cached, path, sha1)
        files[sha1] = entry
        count += 1
    return count
