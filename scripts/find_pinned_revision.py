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
import hashlib
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import upstream

# Commits listed per page and the most pages walked: a data file older than
# 2 000 commits on its own path is not one a platform list still pins.
PER_PAGE = 100
MAX_PAGES = 20


def _history_url(repo: upstream.Repo, path: str, page: int) -> str:
    quoted = urllib.parse.quote(path)
    if repo.family == "gitlab":
        project = urllib.parse.quote(repo.slug, safe="")
        return (f"{repo.api_base}/projects/{project}/repository/commits"
                f"?path={quoted}&per_page={PER_PAGE}&page={page}")
    if repo.family == "github":
        return (f"{repo.api_base}/repos/{repo.slug}/commits"
                f"?path={quoted}&per_page={PER_PAGE}&page={page}")
    return (f"{repo.api_base}/repos/{repo.slug}/commits"
            f"?path={quoted}&limit={PER_PAGE}&page={page}")


def path_history(repo: upstream.Repo, path: str, cache_dir: str) -> list[str]:
    """Commits that touched a path, newest first."""
    shas: list[str] = []
    for page in range(1, MAX_PAGES + 1):
        payload = upstream._api(_history_url(repo, path, page), cache_dir, False,
                                max_age=upstream.MOVING_TTL)
        if not isinstance(payload, list) or not payload:
            break
        shas += [str(entry.get("sha") or entry.get("id")) for entry in payload]
        if len(payload) < PER_PAGE:
            break
    return shas


def find_revision(
    repo: upstream.Repo, path: str, md5: str, cache_dir: str,
) -> tuple[str, bytes] | None:
    """The newest revision whose copy of the path has this md5, and its bytes."""
    wanted = md5.lower()
    for sha in path_history(repo, path, cache_dir):
        data = upstream._fetch(upstream.content_url(repo, sha, path))
        if data is not None and hashlib.md5(data).hexdigest() == wanted:
            return sha, data
    return None


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
