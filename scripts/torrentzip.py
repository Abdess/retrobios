#!/usr/bin/env python3
"""Check or normalize a TorrentZip archive.

    python scripts/torrentzip.py --check bios/Arcade/Arcade/naomi2.zip
    python scripts/torrentzip.py --rebuild in.zip --output out.zip
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from core.torrentzip import is_torrentzip, rebuild_torrentzip


def main() -> int:
    """Entry point: 1 when a checked archive is not TorrentZip."""
    parser = argparse.ArgumentParser(allow_abbrev=False, description="TorrentZip builder and checker")
    parser.add_argument("--check", metavar="ZIP", help="report TorrentZip conformance")
    parser.add_argument("--rebuild", metavar="ZIP", help="normalize an archive")
    parser.add_argument("--output", "-o", help="output path for --rebuild")
    args = parser.parse_args()
    if not (args.check or args.rebuild):
        parser.error("nothing to do: pass --check or --rebuild")

    if args.check:
        data = Path(args.check).read_bytes()
        rebuilt = rebuild_torrentzip(args.check)
        print(f"{args.check}")
        print(f"  signature: {is_torrentzip(args.check)}")
        print(f"  md5:       {hashlib.md5(data).hexdigest()}")
        print(f"  rebuilt:   {hashlib.md5(rebuilt).hexdigest()}")
        print(f"  conform:   {data == rebuilt}")
        return 0 if data == rebuilt else 1

    data = rebuild_torrentzip(args.rebuild)
    dest = args.output or args.rebuild
    Path(dest).write_bytes(data)
    print(f"{dest}: {len(data)} bytes, md5 {hashlib.md5(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
