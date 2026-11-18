#!/usr/bin/env python3
"""Find a file stored inside other files, by its crc32 and size.

Usage:
    python scripts/find_embedded.py --crc32 c23d280e --size 2048 WinUAE.exe
    python scripts/find_embedded.py --crc32 c23d280e --size 2048 --sha1 b5c4b8c3... dumps/
    python scripts/find_embedded.py --crc32 ... --size ... --extract emulator.zip

A ROM an emulator embeds sits somewhere in its executable, an installer or
an archive, at an offset nobody documents: DCMOTO carried the MO6 images
under UPX, and a sliding search was the only way to see them. Every offset
of every file is tried with a rolling crc32, so a 30 MB executable takes
seconds rather than one crc per offset. ZIP members are read too, a folder
is walked. A hit is only a candidate until --sha1 confirms it: crc32 alone
can be met by chance in a large file. --extract writes a confirmed hit to
tmp/acquire/<sha1>, never into bios/.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from acquire.embedded import offsets, sources
from acquire.fetch import ACQUIRE_DIR


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False,
                                     description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("paths", nargs="+", type=Path, help="files, folders or ZIPs to search")
    parser.add_argument("--crc32", required=True, help="crc32 of the wanted file, in hex")
    parser.add_argument("--size", required=True, type=int, help="size of the wanted file, in bytes")
    parser.add_argument("--sha1", help="sha1 that confirms a hit")
    parser.add_argument("--extract", action="store_true",
                        help="write each confirmed hit to tmp/acquire/<sha1> (needs --sha1)")
    args = parser.parse_args()
    try:
        crc32 = int(args.crc32, 16)
    except ValueError:
        parser.error(f"--crc32 takes a hex value, not {args.crc32!r}")
    if args.extract and not args.sha1:
        parser.error("--extract writes only a hit --sha1 confirms: give --sha1")
    wanted_sha1 = args.sha1.lower() if args.sha1 else None
    confirmed = candidates = 0
    for label, data in sources(args.paths):
        for offset in offsets(data, crc32, args.size):
            window = data[offset:offset + args.size]
            sha1 = hashlib.sha1(window).hexdigest()
            if wanted_sha1 and sha1 != wanted_sha1:
                print(f"  {label} at {offset}: crc32 matches, sha1 {sha1} does not")
                candidates += 1
                continue
            confirmed += 1 if wanted_sha1 else 0
            candidates += 0 if wanted_sha1 else 1
            print(f"  {label} at {offset}: sha1 {sha1}"
                  + (" (confirmed)" if wanted_sha1 else " (crc32 only, give --sha1)"))
            if args.extract:
                ACQUIRE_DIR.mkdir(parents=True, exist_ok=True)
                out = ACQUIRE_DIR / sha1
                out.write_bytes(window)
                print(f"    written to {out}")
    if not confirmed and not candidates:
        print("Not found.")
    return 0 if confirmed or (candidates and not wanted_sha1) else 1


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from core.cli import run_cli

    run_cli(main)
