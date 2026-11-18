#!/usr/bin/env python3
"""Record what the packs of a release hold.

The README and the site print, beside each download link, how many files a
pack holds and what they weigh once extracted. Those figures have to be the
ones of the release the link serves. Read from the install manifests they
described what main would build today, and drifted from the published pack
with every commit made since the release.

The record is written from the archives themselves when a release is cut,
committed with it, and read by the generators.

Usage:
    python scripts/release_record.py dist/ --tag v2026.10.04
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core.artifacts import ArtifactLockBusy, write_text_atomic
from model.releaserecord import RECORD
from release.record import (
    NotAReleasePackError,
    UnfinishedSplitError,
    build_record,
    manifest_mismatches,
    size_text,
)


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Record what a release's packs hold")
    parser.add_argument("dist", type=Path, help="directory of the packs to publish")
    parser.add_argument("--tag", required=True, help="release tag, e.g. v2026.10.04")
    parser.add_argument(
        "--install-dir", default="install", type=Path,
        help="manifests the archives are compared with (default: %(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default="platforms",
        help="registry the pack names are rebuilt from (default: %(default)s)",
    )
    parser.add_argument(
        "--output", default=RECORD, type=Path,
        help="record to write (default: %(default)s)",
    )
    args = parser.parse_args()

    try:
        record = build_record(args.dist, args.tag, args.platforms_dir)
    except (UnfinishedSplitError, NotAReleasePackError, ArtifactLockBusy) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if not record["packs"]:
        print(f"Error: no pack in {args.dist}", file=sys.stderr)
        return 1
    for name, pack in record["packs"].items():
        print(
            f"{name:<44} download {size_text(pack['download_size']):>8}"
            f"   extracted {size_text(pack['extracted_size']):>8}"
            f"   {pack['files']:,} files   {len(pack['assets'])} asset(s)"
        )
    mismatches = manifest_mismatches(record, args.install_dir)
    for line in mismatches:
        print(f"Error: {line}", file=sys.stderr)
    if mismatches:
        return 1
    write_text_atomic(str(args.output), json.dumps(record, indent=2) + "\n")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
