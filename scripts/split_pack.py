#!/usr/bin/env python3
"""Publish a pack too large for one release asset as several ZIPs.

GitHub refuses a release file of 2 GiB or more. A pack over that is written
as parts, each a complete archive of whole files: any tool opens one, and
the parts extracted into the same folder are the pack. Members are copied
as stored, never recompressed, so the parts depend on the pack alone.

Each part also carries a short text file, its marker, at the archive root:
the pack it belongs to, its number, and the name and size of every part.
Extracted with the files, the markers let `install.py --check` name a part
that is missing from the folder.

The directory's SHA256SUMS.txt is then written over the pack files a
release publishes, the list the release signs and uploads.

Usage:
    python scripts/split_pack.py dist/
    python scripts/split_pack.py dist/RetroArch_v1.22.2_BIOS_Pack.zip
    python scripts/split_pack.py dist/ --max-size 1900M
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

from core.artifacts import ArtifactLockBusy, artifact_lock
from packs.parts import ASSET_LIMIT, parse_size, split_directory, split_pack
from release.sums import write_sums


def main() -> int:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Split packs over the release asset limit into ZIP parts"
    )
    parser.add_argument("target", type=Path, help="a pack, or a directory of packs")
    parser.add_argument(
        "--max-size", type=parse_size, default=ASSET_LIMIT, metavar="SIZE",
        help="a part stays under this many bytes (K, M, G suffixes, default 2G)",
    )
    args = parser.parse_args()
    # The packs are rewritten in place by generate_pack under this lock: a
    # build running beside the split mixes its bytes into the pack being
    # read, or writes a pack that the split then deletes.
    if not args.target.exists():
        print(f"Error: {args.target}: no such pack or directory, pass a pack or the "
              "--output-dir generate_pack wrote (default dist/)", file=sys.stderr)
        return 1
    directory = args.target if args.target.is_dir() else args.target.parent
    try:
        with artifact_lock(str(directory)):
            if args.target.is_dir():
                published = split_directory(args.target, args.max_size)
            else:
                published = split_pack(args.target, args.max_size)
            sums = write_sums(directory)
    except (ArtifactLockBusy, OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    for path in published:
        print(f"{path.stat().st_size:>13,}  {path.name}")
    if sums is not None:
        print(f"{sums}: checksums of the files to publish")
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
