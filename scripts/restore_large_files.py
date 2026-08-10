#!/usr/bin/env python3
"""Restore gitignored large files into the checkout from the release cache.

Files over 50 MB live as assets of the `large-files` release instead of in
git. A CI checkout is therefore incomplete: every consumer that resolves a
database entry against the disk (verify.py, generate_pack.py, and through
them generate_readme.py) reports those paths as missing.

Assets are matched by content, not by name: the SHA1 of each cached file is
looked up in the database, and the entry's path is written only when it is
gitignored and absent.

Usage:
    python scripts/restore_large_files.py [--cache .cache/large] [--db database.json]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import load_database


def gitignored_paths(gitignore: str) -> set[str]:
    """Paths the repository keeps out of git, as written in .gitignore."""
    try:
        with open(gitignore) as f:
            return {
                line.strip() for line in f if line.strip().startswith("bios/")
            }
    except FileNotFoundError:
        return set()


def index_cache(cache_dir: str) -> dict[str, str]:
    """Map SHA1 to cached file path for every asset in the cache."""
    index: dict[str, str] = {}
    for name in sorted(os.listdir(cache_dir)):
        path = os.path.join(cache_dir, name)
        if not os.path.isfile(path):
            continue
        digest = hashlib.sha1()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                digest.update(chunk)
        index[digest.hexdigest()] = path
    return index


def restore(cache_dir: str, db_path: str, gitignore: str) -> int:
    if not os.path.isdir(cache_dir):
        print(f"No cache at {cache_dir}, nothing to restore")
        return 0
    ignored = gitignored_paths(gitignore)
    index = index_cache(cache_dir)
    db = load_database(db_path)
    restored = 0
    for sha1, entry in db.get("files", {}).items():
        path = entry.get("path", "")
        if path not in ignored or os.path.exists(path):
            continue
        source = index.get(sha1)
        if not source:
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        shutil.copy2(source, path)
        print(f"Restored: {path}")
        restored += 1
    print(f"Total: {restored} files restored")
    return restored


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", default=".cache/large")
    parser.add_argument("--db", default="database.json")
    parser.add_argument("--gitignore", default=".gitignore")
    args = parser.parse_args()
    restore(args.cache, args.db, args.gitignore)


if __name__ == "__main__":
    main()
