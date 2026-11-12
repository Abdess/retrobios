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
import zipfile
import zlib
from collections.abc import Iterator
from pathlib import Path

ACQUIRE_DIR = Path("tmp") / "acquire"
_POLY = 0xEDB88320
_TABLE = []
for _byte in range(256):
    _value = _byte
    for _ in range(8):
        _value = (_value >> 1) ^ _POLY if _value & 1 else _value >> 1
    _TABLE.append(_value)


def _raw(data: bytes) -> int:
    """The crc32 register over data, from 0 and without the final xor: a
    linear function, which is what lets the window roll."""
    register = 0
    for byte in data:
        register = (register >> 8) ^ _TABLE[(register ^ byte) & 0xFF]
    return register


def offsets(data: bytes, crc32: int, size: int) -> list[int]:
    """Every offset where data[offset:offset + size] has this zlib crc32."""
    if size <= 0 or len(data) < size:
        return []
    # zlib's crc32 of a window is the linear register xor a constant that
    # depends on the length alone: the crc32 of as many zero bytes.
    target = crc32 ^ zlib.crc32(bytes(size))
    leaving = [_raw(bytes([byte]) + bytes(size)) for byte in range(256)]
    table = _TABLE
    register = _raw(data[:size])
    found = [0] if register == target else []
    for start in range(len(data) - size):
        register = ((register >> 8) ^ table[(register ^ data[start + size]) & 0xFF]
                    ^ leaving[data[start]])
        if register == target:
            found.append(start + 1)
    return found


def sources(paths: list[Path]) -> Iterator[tuple[str, bytes]]:
    """(label, bytes) of each file under paths, and of each ZIP member."""
    for path in paths:
        files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
        for file in files:
            try:
                data = file.read_bytes()
            except OSError as exc:
                print(f"  {file}: not read ({exc.strerror or exc})", file=sys.stderr)
                continue
            yield str(file), data
            if zipfile.is_zipfile(file):
                try:
                    with zipfile.ZipFile(file) as archive:
                        for info in archive.infolist():
                            if not info.is_dir():
                                yield f"{file}!{info.filename}", archive.read(info)
                except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError) as exc:
                    print(f"  {file}: members not read ({exc})", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
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
    sys.exit(main())
