#!/usr/bin/env python3
"""Find the upstream revision whose copy of a file a platform pins.

A platform list pins the bytes a file had when the list was written: System.dat
names ScummVM's queen.tbl and FBNeo's hiscore.dat by an md5 that today's
upstream no longer carries. The bytes are still in the project's history. This
walks the commits that touched one path, newest first, and hashes the file at
each until one matches.

    python scripts/find_pinned_revision.py --repo https://github.com/scummvm/scummvm \\
        --path dists/engine-data/queen.tbl --md5 4f5b513b52c4ef6fb1c46e984760a3b7
    python scripts/find_pinned_revision.py ... --write bios/Other/ScummVM/.variants/queen.tbl.4f5b513b
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import upstream
from acquire.history import find_revision


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo", required=True, help="forge URL of the project")
    parser.add_argument("--path", required=True, help="path of the file in the project")
    parser.add_argument("--md5", required=True, help="md5 the platform pins")
    parser.add_argument("--write", type=Path, help="save the matching bytes here")
    parser.add_argument(
        "--cache-dir", default=upstream.CACHE_DIR,
        help="download cache directory (default: %(default)s)",
    )
    args = parser.parse_args()

    repo = upstream.parse_repo(args.repo)
    if repo is None:
        parser.error(f"not a supported forge URL: {args.repo}")
    found = find_revision(repo, args.path, args.md5, args.cache_dir)
    if found is None:
        print(f"no revision of {args.path} in {repo.slug} has md5 {args.md5}",
              file=sys.stderr)
        return 1
    sha, data = found
    print(f"{sha}  {args.path}  {args.md5.lower()}  {len(data)} bytes")
    if args.write:
        if args.write.exists() and args.write.read_bytes() != data:
            print(f"refusing to overwrite {args.write}: it holds other bytes",
                  file=sys.stderr)
            return 1
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_bytes(data)
        print(f"wrote {args.write}")
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
