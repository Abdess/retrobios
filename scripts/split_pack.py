#!/usr/bin/env python3
"""Publish a pack too large for one release asset as several ZIPs.

GitHub refuses a release file of 2 GiB or more. A pack over that is written
as parts, each a complete archive of whole files: any tool opens one, and
the parts extracted into the same folder are the pack. Members are copied
as stored, never recompressed, so the parts depend on the pack alone.

Usage:
    python scripts/split_pack.py dist/
    python scripts/split_pack.py dist/RetroArch_Lakka_v1.22.2_BIOS_Pack.zip
    python scripts/split_pack.py dist/ --max-size 1900M
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
import zipfile
from pathlib import Path

# "Each file included in a release must be under 2 GiB."
ASSET_LIMIT = 2 * 1024**3

PACK_SUFFIX = "_BIOS_Pack.zip"
_PART_NAME = re.compile(r"^(?P<stem>.+_BIOS_Pack)\.part(?P<index>\d+)of(?P<count>\d+)\.zip$")

_LOCAL = struct.Struct("<4s2B4HL2L2H")
_CENTRAL = struct.Struct("<4s4B4HL2L5H2L")
_END = struct.Struct("<4s4H2LH")
_LOCAL_SIG = b"PK\x03\x04"
_CENTRAL_SIG = b"PK\x01\x02"
_END_SIG = b"PK\x05\x06"
_DATA_DESCRIPTOR = 0x08
_UTF8_NAME = 0x800
_CHUNK = 1024 * 1024
_MAX_ENTRIES = 0xFFFF
_MAX_FIELD = 0xFFFFFFFF


def is_part(name: str) -> bool:
    """Whether a file name is one part of a split pack."""
    return _PART_NAME.match(name) is not None


def pack_of(name: str) -> str:
    """The pack a published file belongs to, a part folded into its archive."""
    part = _PART_NAME.match(name)
    return f"{part['stem']}.zip" if part else name


def part_name(pack_name: str, index: int, count: int) -> str:
    return f"{pack_name[: -len('.zip')]}.part{index}of{count}.zip"


def _name_bytes(info: zipfile.ZipInfo) -> bytes:
    encoding = "utf-8" if info.flag_bits & _UTF8_NAME else "cp437"
    return info.orig_filename.encode(encoding)


def _weight(info: zipfile.ZipInfo) -> int:
    """Bytes a member adds to a part: both headers and its stored data."""
    name = len(_name_bytes(info))
    return _LOCAL.size + name + info.compress_size + _CENTRAL.size + name


def plan_parts(
    members: list[zipfile.ZipInfo], limit: int
) -> list[list[zipfile.ZipInfo]]:
    """Fill each part in archive order, up to the limit."""
    parts: list[list[zipfile.ZipInfo]] = [[]]
    size = _END.size
    for info in members:
        weight = _weight(info)
        if _END.size + weight >= limit:
            raise ValueError(
                f"{info.filename} needs {weight:,} bytes, more than a part of "
                f"{limit:,} can hold"
            )
        if info.compress_size > _MAX_FIELD or info.file_size > _MAX_FIELD:
            raise ValueError(f"{info.filename} needs ZIP64, which a part does not use")
        if size + weight >= limit or len(parts[-1]) >= _MAX_ENTRIES:
            parts.append([])
            size = _END.size
        parts[-1].append(info)
        size += weight
    return parts


def _dos_stamp(info: zipfile.ZipInfo) -> tuple[int, int]:
    year, month, day, hour, minute, second = info.date_time
    return (
        (hour << 11) | (minute << 5) | (second // 2),
        ((year - 1980) << 9) | (month << 5) | day,
    )


def _data_offset(source, info: zipfile.ZipInfo) -> int:
    """Where a member's stored bytes begin, read from its own local header."""
    source.seek(info.header_offset)
    header = _LOCAL.unpack(source.read(_LOCAL.size))
    if header[0] != _LOCAL_SIG:
        raise ValueError(f"{info.filename}: no local header at its offset")
    return info.header_offset + _LOCAL.size + header[10] + header[11]


def _write_part(source, members: list[zipfile.ZipInfo], dest: Path) -> None:
    directory = []
    with open(dest, "wb") as out:
        for info in members:
            name = _name_bytes(info)
            flags = info.flag_bits & ~_DATA_DESCRIPTOR
            dos_time, dos_date = _dos_stamp(info)
            offset = out.tell()
            out.write(
                _LOCAL.pack(
                    _LOCAL_SIG, info.extract_version, info.reserved, flags,
                    info.compress_type, dos_time, dos_date, info.CRC,
                    info.compress_size, info.file_size, len(name), 0,
                )
            )
            out.write(name)
            source.seek(_data_offset(source, info))
            remaining = info.compress_size
            while remaining:
                chunk = source.read(min(_CHUNK, remaining))
                if not chunk:
                    raise ValueError(f"{info.filename}: the pack ends inside it")
                out.write(chunk)
                remaining -= len(chunk)
            directory.append(
                _CENTRAL.pack(
                    _CENTRAL_SIG, info.create_version, info.create_system,
                    info.extract_version, info.reserved, flags,
                    info.compress_type, dos_time, dos_date, info.CRC,
                    info.compress_size, info.file_size, len(name), 0, 0, 0,
                    info.internal_attr, info.external_attr, offset,
                )
                + name
            )
        start = out.tell()
        for record in directory:
            out.write(record)
        out.write(
            _END.pack(
                _END_SIG, 0, 0, len(directory), len(directory),
                out.tell() - start, start, 0,
            )
        )


def _identity(archive: zipfile.ZipFile) -> list[tuple[str, int, int]]:
    return [(info.filename, info.CRC, info.file_size) for info in archive.infolist()]


def split_pack(zip_path: Path, limit: int = ASSET_LIMIT) -> list[Path]:
    """Replace a pack at or over the limit by parts that each fit under it.

    Returns the files to publish. The pack is removed only once every part
    has been read back in full and the parts together list exactly its
    members, so a failure leaves the pack as it was and no part behind.
    """
    zip_path = Path(zip_path)
    if zip_path.stat().st_size < limit:
        return [zip_path]

    with zipfile.ZipFile(zip_path) as archive:
        members = archive.infolist()
        expected = _identity(archive)
    plan = plan_parts(members, limit)
    parts = [
        zip_path.with_name(part_name(zip_path.name, index, len(plan)))
        for index in range(1, len(plan) + 1)
    ]
    try:
        with open(zip_path, "rb") as source:
            for dest, chosen in zip(parts, plan):
                _write_part(source, chosen, dest)
        found: list[tuple[str, int, int]] = []
        for dest in parts:
            with zipfile.ZipFile(dest) as archive:
                damaged = archive.testzip()
                if damaged:
                    raise ValueError(f"{dest.name}: {damaged} does not read back")
                found.extend(_identity(archive))
            if dest.stat().st_size >= limit:
                raise ValueError(f"{dest.name} reached the limit of {limit:,} bytes")
        if found != expected:
            raise ValueError(f"the parts of {zip_path.name} do not add up to it")
    except (OSError, ValueError, zipfile.BadZipFile):
        for dest in parts:
            dest.unlink(missing_ok=True)
        raise
    zip_path.unlink()
    return parts


def split_directory(directory: Path, limit: int = ASSET_LIMIT) -> list[Path]:
    """Split every pack of a directory that needs it. Returns what to publish."""
    published: list[Path] = []
    for path in sorted(Path(directory).glob(f"*{PACK_SUFFIX}")):
        published.extend(split_pack(path, limit))
    return published


def _size(text: str) -> int:
    match = re.fullmatch(r"(\d+)([KMG]?)", text.strip().upper())
    if not match:
        raise argparse.ArgumentTypeError(f"not a size: {text}")
    return int(match[1]) * 1024 ** " KMG".index(match[2] or " ")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Split packs over the release asset limit into ZIP parts"
    )
    parser.add_argument("target", type=Path, help="a pack, or a directory of packs")
    parser.add_argument(
        "--max-size", type=_size, default=ASSET_LIMIT, metavar="SIZE",
        help="a part stays under this many bytes (K, M, G suffixes; default 2G)",
    )
    args = parser.parse_args()
    try:
        if args.target.is_dir():
            published = split_directory(args.target, args.max_size)
        else:
            published = split_pack(args.target, args.max_size)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    for path in published:
        print(f"{path.stat().st_size:>13,}  {path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
