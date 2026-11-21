"""Permalinks into the sources a profile cites.

A citation is only checkable if it points at the revision the profile
was written against, so a permalink is pinned, never guessed."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sitegen.sources import SOURCE_PATHS, TREE_CACHE, refresh_record


def main() -> int:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Record which cited source paths the cached upstream trees hold",
    )
    parser.add_argument(
        "--cache-dir", type=Path, action="append",
        help=f"tree listings profile_sync cached, read in the order given (default: {TREE_CACHE})",
    )
    parser.add_argument(
        "--fetch", action="store_true",
        help="fetch a tree no cache holds into the last --cache-dir",
    )
    parser.add_argument(
        "--emulators-dir", default="emulators",
        help="profiles whose citations are checked (default: %(default)s)",
    )
    parser.add_argument(
        "--output", type=Path, default=SOURCE_PATHS,
        help="record the site reads (default: %(default)s)",
    )
    args = parser.parse_args()
    cache_dirs = args.cache_dir or [TREE_CACHE]
    if not args.fetch and not any(path.is_dir() for path in cache_dirs):
        print(f"Error: no tree cache at {', '.join(map(str, cache_dirs))}", file=sys.stderr)
        return 1
    from model.profiles import load_emulator_profiles

    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    held, unread = refresh_record(profiles, cache_dirs, args.fetch, args.output)
    print(f"{sum(map(len, held.values()))} paths held in {len(held)} trees, "
          f"{len(unread)} trees not cached: {args.output}")
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
