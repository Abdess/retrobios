#!/usr/bin/env python3
"""TorrentZip archive builder for MAME/FBNeo ROM sets.

TorrentZip is the archive format MAME romset distributions use. It fixes
every non-content variable (member order, timestamps, compression level,
extra fields, attributes), so the archive bytes are a pure function of the
member names and their contents.

That property makes it possible to rebuild a romset ZIP that matches an
upstream-published hash exactly, and to identify which romset revision a
published hash refers to.

Usage:
    from torrentzip import build_torrentzip, identify_romset

    data = build_torrentzip([("sp-s2.sp1", rom_bytes), ...])
    md5 = hashlib.md5(data).hexdigest()

CLI:
    python scripts/torrentzip.py --check bios/Arcade/Arcade/naomi2.zip
    python scripts/torrentzip.py --rebuild in.zip --output out.zip
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import zipfile
import zlib
from pathlib import Path

# TorrentZip constants: 1996-12-24 23:32:00, deflate level 9
_DOS_DATE = ((1996 - 1980) << 9) | (12 << 5) | 24
_DOS_TIME = (23 << 11) | (32 << 5) | 0
_COMMENT_PREFIX = "TORRENTZIPPED-"


def build_torrentzip(members: list[tuple[str, bytes]]) -> bytes:
    """Build a TorrentZip archive from (name, data) members.

    Members are sorted case-insensitively by name, as the format requires.
    Returns the complete archive bytes.
    """
    ordered = sorted(members, key=lambda m: m[0].lower())
    body = bytearray()
    central = bytearray()

    for name, data in ordered:
        raw = name.encode("ascii")
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        blob = compressor.compress(data) + compressor.flush()
        crc = zlib.crc32(data) & 0xFFFFFFFF
        offset = len(body)
        body += struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, 2, 8, _DOS_TIME, _DOS_DATE,
            crc, len(blob), len(data), len(raw), 0,
        )
        body += raw + blob
        central += struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, 0, 20, 2, 8, _DOS_TIME, _DOS_DATE,
            crc, len(blob), len(data), len(raw), 0, 0, 0, 0, 0, offset,
        )
        central += raw

    cd_offset = len(body)
    body += central
    comment = (
        f"{_COMMENT_PREFIX}{zlib.crc32(bytes(central)) & 0xFFFFFFFF:08X}"
    ).encode("ascii")
    body += struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, len(ordered), len(ordered),
        len(central), cd_offset, len(comment),
    )
    body += comment
    return bytes(body)


def rebuild_torrentzip(source: str | Path) -> bytes:
    """Read an archive and return its TorrentZip normalization."""
    with zipfile.ZipFile(source) as zf:
        members = [
            (info.filename, zf.read(info.filename))
            for info in zf.infolist()
            if not info.is_dir()
        ]
    return build_torrentzip(members)


def is_torrentzip(source: str | Path) -> bool:
    """Report whether an archive already carries the TorrentZip signature."""
    with zipfile.ZipFile(source) as zf:
        return zf.comment.decode("ascii", "replace").startswith(_COMMENT_PREFIX)


def identify_romset(
    recipes: dict[str, list[tuple[str, str]]],
    atoms: dict[str, bytes],
    target_md5: str,
) -> str | None:
    """Find which recipe rebuilds to a target archive MD5.

    recipes maps a label (e.g. a MAME version) to a list of
    (member name, CRC32 hex) pairs; atoms maps CRC32 hex to ROM bytes.
    Returns the matching label, or None when no recipe reproduces the hash.
    """
    target = target_md5.lower()
    for label, recipe in recipes.items():
        if any(crc.lower() not in atoms for _, crc in recipe):
            continue
        members = [(name, atoms[crc.lower()]) for name, crc in recipe]
        if hashlib.md5(build_torrentzip(members)).hexdigest() == target:
            return label
    return None


def main() -> None:
    """Entry point."""
    parser = argparse.ArgumentParser(description="TorrentZip builder and checker")
    parser.add_argument("--check", metavar="ZIP", help="report TorrentZip conformance")
    parser.add_argument("--rebuild", metavar="ZIP", help="normalize an archive")
    parser.add_argument("--output", "-o", help="output path for --rebuild")
    args = parser.parse_args()

    if args.check:
        data = Path(args.check).read_bytes()
        rebuilt = rebuild_torrentzip(args.check)
        print(f"{args.check}")
        print(f"  signature: {is_torrentzip(args.check)}")
        print(f"  md5:       {hashlib.md5(data).hexdigest()}")
        print(f"  rebuilt:   {hashlib.md5(rebuilt).hexdigest()}")
        print(f"  conform:   {data == rebuilt}")
        return

    if args.rebuild:
        data = rebuild_torrentzip(args.rebuild)
        dest = args.output or args.rebuild
        Path(dest).write_bytes(data)
        print(f"{dest}: {len(data)} bytes, md5 {hashlib.md5(data).hexdigest()}")
        return

    parser.error("nothing to do: pass --check or --rebuild")


if __name__ == "__main__":
    sys.exit(main())
