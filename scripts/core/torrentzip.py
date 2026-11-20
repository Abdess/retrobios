"""TorrentZip archive builder for MAME/FBNeo ROM sets.

TorrentZip is the archive format MAME romset distributions use. It fixes
every non-content variable (member order, timestamps, compression level,
extra fields, attributes), so the archive bytes are a pure function of the
member names and their contents.

That property makes it possible to rebuild a romset ZIP that matches an
upstream-published hash exactly, and to identify which romset revision a
published hash refers to (scripts/romrecipes/).

Usage:
    from core.torrentzip import build_torrentzip

    data = build_torrentzip([("sp-s2.sp1", rom_bytes), ...])
    md5 = hashlib.md5(data).hexdigest()

Command line: scripts/torrentzip.py.
"""

from __future__ import annotations

import functools
import hashlib
import io
import struct
import zipfile
import zlib
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, NamedTuple, Protocol


class Source(Protocol):
    """An open member: read in chunks, closed by its ``with`` block."""

    def read(self, size: int = -1, /) -> bytes: ...
    def __enter__(self) -> Source: ...
    def __exit__(self, *exc: Any) -> Any: ...


class Sink(Protocol):
    def write(self, data: bytes | bytearray, /) -> int: ...

# TorrentZip constants: 1996-12-24 23:32:00, deflate level 9
_DOS_DATE = ((1996 - 1980) << 9) | (12 << 5) | 24
_DOS_TIME = (23 << 11) | (32 << 5) | 0
_COMMENT_PREFIX = "TORRENTZIPPED-"
# Members are read and deflated this much at a time. Deflate output does not
# depend on how its input is cut, so a 2 GiB disk image streams through in
# the same bytes a one-shot compression gives.
CHUNK = 16 * 1024 * 1024
# A size or offset that does not fit 32 bits takes a ZIP64 field. No
# TorrentZip-conformant archive needs one, so their layout is untouched.
ZIP32_LIMIT = 0xFFFFFFFF
_ZIP64_MARK = 0xFFFFFFFF


class Written(NamedTuple):
    """A member as the writer read it from its source."""

    name: str
    size: int
    crc32: str
    sha1: str


def zlib_ng_version(module: object = zlib) -> str | None:
    """The zlib-ng version this interpreter deflates with, None for zlib.

    TorrentZip bytes are the output of zlib's level-9 deflate. Stock zlib
    1.2.13 to 1.3.2 reproduces every TorrentZip archive in the collection.
    zlib-ng 2.2.4 (python.org 3.14 on Windows) reproduces 479 of 1,561 and
    2.3.3 545, and the two disagree with each other.
    """
    version = getattr(module, "ZLIBNG_VERSION", None)
    if version:
        return str(version)
    runtime = str(getattr(module, "ZLIB_RUNTIME_VERSION", "") or "")
    return runtime if "zlib-ng" in runtime.lower() else None


def _deflate(stream: Source) -> tuple[bytes, Written]:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    blob = bytearray()
    crc, size, sha1 = 0, 0, hashlib.sha1()
    while chunk := stream.read(CHUNK):
        crc = zlib.crc32(chunk, crc)
        size += len(chunk)
        sha1.update(chunk)
        blob += compressor.compress(chunk)
    blob += compressor.flush()
    return bytes(blob), Written("", size, f"{crc & 0xFFFFFFFF:08x}", sha1.hexdigest())


def write_torrentzip(
    sink: Sink, members: Iterable[tuple[str, Callable[[], Source]]]
) -> list[Written]:
    """Write a TorrentZip archive to *sink*, one member in memory at a time.

    *members* pairs each name with a callable opening its bytes. Members are
    sorted case-insensitively by name, as the format requires. Returns what
    was read, in archive order, so a caller can check every member.
    """
    ordered = sorted(members, key=lambda m: m[0].lower())
    central = bytearray()
    offset = 0
    written: list[Written] = []
    for name, opener in ordered:
        raw = name.encode("ascii")
        with opener() as stream:
            blob, read = _deflate(stream)
        crc = int(read.crc32, 16)
        written.append(read._replace(name=name))
        wide = read.size >= ZIP32_LIMIT or len(blob) >= ZIP32_LIMIT
        far = offset >= ZIP32_LIMIT
        local_extra = struct.pack("<HHQQ", 1, 16, read.size, len(blob)) if wide else b""
        central_extra = (
            struct.pack("<QQ", read.size, len(blob)) if wide else b""
        ) + (struct.pack("<Q", offset) if far else b"")
        if central_extra:
            central_extra = struct.pack("<HH", 1, len(central_extra)) + central_extra
        sizes = (_ZIP64_MARK, _ZIP64_MARK) if wide else (len(blob), read.size)
        needed = 45 if wide or far else 20
        header = struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, needed, 2, 8, _DOS_TIME, _DOS_DATE,
            crc, *sizes, len(raw), len(local_extra),
        ) + raw + local_extra
        sink.write(header)
        sink.write(blob)
        central += struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, 0, needed, 2, 8, _DOS_TIME, _DOS_DATE,
            crc, *sizes, len(raw), len(central_extra), 0, 0, 0, 0,
            _ZIP64_MARK if far else offset,
        ) + raw + central_extra
        offset += len(header) + len(blob)

    cd_offset = offset
    sink.write(central)
    count = len(ordered)
    if cd_offset >= ZIP32_LIMIT or len(central) >= ZIP32_LIMIT or count >= 0xFFFF:
        end64 = cd_offset + len(central)
        sink.write(struct.pack(
            "<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, count, count,
            len(central), cd_offset,
        ))
        sink.write(struct.pack("<IIQI", 0x07064B50, 0, end64, 1))
    comment = (
        f"{_COMMENT_PREFIX}{zlib.crc32(bytes(central)) & 0xFFFFFFFF:08X}"
    ).encode("ascii")
    sink.write(struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, min(count, 0xFFFF), min(count, 0xFFFF),
        min(len(central), _ZIP64_MARK), min(cd_offset, _ZIP64_MARK), len(comment),
    ))
    sink.write(comment)
    return written


def build_torrentzip(members: list[tuple[str, bytes]]) -> bytes:
    """Build a TorrentZip archive from (name, data) members.

    Members are sorted case-insensitively by name, as the format requires.
    Returns the complete archive bytes.
    """
    sink = io.BytesIO()
    write_torrentzip(
        sink, [(name, functools.partial(io.BytesIO, data)) for name, data in members]
    )
    return sink.getvalue()


def rebuild_torrentzip(source: str | Path) -> bytes:
    """Read an archive and return its TorrentZip normalization."""
    with zipfile.ZipFile(source) as zf:
        members = [
            (info.filename, zf.read(info.filename))
            for info in zf.infolist()
            if not info.is_dir()
        ]
    return build_torrentzip(members)


def has_torrentzip_comment(comment: bytes) -> bool:
    """Report whether an archive comment is the TorrentZip signature."""
    return comment.startswith(_COMMENT_PREFIX.encode("ascii"))


def is_torrentzip(source: str | Path) -> bool:
    """Report whether an archive already carries the TorrentZip signature."""
    with zipfile.ZipFile(source) as zf:
        return has_torrentzip_comment(zf.comment)
