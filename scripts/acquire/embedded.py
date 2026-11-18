"""A file stored inside others, found at any offset by a rolling crc32."""

from __future__ import annotations

import sys
import zipfile
import zlib
from collections.abc import Iterator
from pathlib import Path


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
