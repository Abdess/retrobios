#!/usr/bin/env python3
"""Compare the large-files release with the files the collection keeps out of git.

Every gitignored file under bios/ is served to the installer as an asset of
the large-files release, and install.py refuses a download whose
Content-Length differs from the manifest size. The manifest size is that of
the local copy, so an asset uploaded before the local file was rebuilt fails
every install of it until it is uploaded again.

Usage:
    python scripts/check_release_assets.py
    python scripts/check_release_assets.py --json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

from core.cli import add_repo_inputs
from model.database import load_database
from model.largefiles import registered_paths
from release.assets import (
    cache_hashes,
    compare,
    expected_assets,
    expected_digests,
    fetch_release,
    profile_descriptions,
    registry_bundles,
    render_notes,
)


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n")[0])
    add_repo_inputs(parser, "db")
    parser.add_argument(
        "--gitignore", default=".gitignore",
        help="the .gitignore listing release-asset files (default: %(default)s)",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--notes", metavar="FILE",
        help="write the release page rendered from the collection to FILE",
    )
    args = parser.parse_args()

    with open(args.gitignore, encoding="utf-8") as handle:
        gitignore_text = handle.read()
    db = load_database(args.db)
    expected = expected_assets(db, gitignore_text)
    try:
        assets, body, asset_digests = fetch_release()
    except (subprocess.CalledProcessError, FileNotFoundError, KeyError) as exc:
        print(f"ERROR: cannot list release assets: {exc}", file=sys.stderr)
        return 2
    bundles = registry_bundles()
    rendered = render_notes(
        db, gitignore_text, assets, body, profile_descriptions(), bundles,
        cache_hashes(set(bundles)),
    )
    if args.notes:
        with open(args.notes, "w", encoding="utf-8") as handle:
            handle.write(rendered)
    findings = compare(
        expected,
        assets,
        notes_current=rendered.strip() == body.strip(),
        registered=registered_paths(gitignore_text),
        expected_digests=expected_digests(db, gitignore_text),
        asset_digests=asset_digests,
    )

    if args.json:
        print(json.dumps(
            [
                {"kind": kind, "path": path, "expected": size, "published": published}
                for kind, path, size, published in findings
            ],
            indent=2,
        ))
    else:
        print(f"{len(expected)} gitignored files, {len(assets)} release assets")
        for kind, path, size, published in findings:
            if kind == "missing":
                print(f"  MISSING  {path} ({size} bytes)")
            elif kind == "size":
                print(f"  SIZE     {path}: local {size} != release {published}")
            elif kind == "content":
                print(f"  CONTENT  {path}: same size, other sha256 on the release")
            else:
                print("  NOTES    release description differs from the rendered page"
                      " (--notes FILE, then gh release edit large-files --notes-file FILE)")
        if not findings:
            print("  release assets and description match the collection")
    return 1 if findings else 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
