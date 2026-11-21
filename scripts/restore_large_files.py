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
import os
import sys
from pathlib import Path

from core.cli import add_repo_inputs
from release.restore import restore


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__)
    parser.add_argument(
        "--cache", default=".cache/large",
        help="where release assets are cached (default: %(default)s)",
    )
    add_repo_inputs(parser, "db")
    parser.add_argument(
        "--gitignore", default=".gitignore",
        help="the .gitignore listing release-asset files (default: %(default)s)",
    )
    args = parser.parse_args()
    if not os.path.isfile(args.gitignore):
        parser.error(f"no file at {args.gitignore}: it lists the release assets")
    result = restore(args.cache, args.db, args.gitignore, root=Path.cwd())
    if not result.cache_found:
        print(f"No cache at {args.cache}")
    for path in result.restored:
        print(f"Restored: {path}")
    print(f"Total: {len(result.restored)} files restored")
    if result.unsatisfied:
        # Every consumer downstream resolves against the disk, so a path the
        # cache cannot supply is not a smaller restore: it drops entries from
        # the manifest and inflates the missing count the README publishes.
        print(f"Unsatisfied: {len(result.unsatisfied)} declared paths the cache "
              "cannot supply", file=sys.stderr)
        for path in sorted(result.unsatisfied)[:10]:
            print(f"  {path}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
