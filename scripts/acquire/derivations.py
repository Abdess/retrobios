"""Catalog entries whose bytes a held dump already contains.

A catalog lists chips as they come off the board, while a collection often holds
the image an emulator reads. The Amiga 3.1 Kickstart pair 391773/391774 is
the high and low 16-bit words of amiga-os-310-a1200.rom, byte-swapped, and the
TOSEC "Basic V7" is basiclo and basichi end to end. Listed as missing, they
send a maintainer after files that are already here. Each transform below is
one the source boards use. A match is by sha1, never by size or name.
"""

from __future__ import annotations

import array
import functools
import hashlib
import os
import zipfile
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence

from core.ziptools import is_archive_path

# A held file larger than this is not read: no chip image is near it.
MAX_SOURCE_SIZE = 64 * 1024 * 1024


def _swap16(data: bytes) -> bytes:
    swapped = bytearray(data)
    swapped[0::2], swapped[1::2] = data[1::2], data[0::2]
    return bytes(swapped)


def _words(data: bytes, start: int) -> bytes:
    """Every other 16-bit word, from word `start`, bytes kept in order.

    Read as an array of 2-byte units and strided: joining slices one word
    at a time made this pass take most of an hour over the romset chips.
    """
    words = array.array("H")
    words.frombytes(data[: len(data) - len(data) % 2])
    return words[start::2].tobytes()


# (name, size of the output for an input of size n or None, transform)
TRANSFORMS: tuple[tuple[str, Callable[[int], int | None], Callable[[bytes], bytes]], ...] = (
    ("first half", lambda n: n // 2 if n % 2 == 0 else None, lambda d: d[:len(d) // 2]),
    ("second half", lambda n: n // 2 if n % 2 == 0 else None, lambda d: d[len(d) // 2:]),
    *(
        (f"quarter {q + 1}", lambda n: n // 4 if n % 4 == 0 else None,
         lambda d, q=q: d[q * len(d) // 4:(q + 1) * len(d) // 4])
        for q in range(4)
    ),
    ("even bytes", lambda n: n // 2 if n % 2 == 0 else None, lambda d: d[0::2]),
    ("odd bytes", lambda n: n // 2 if n % 2 == 0 else None, lambda d: d[1::2]),
    ("even words", lambda n: n // 2 if n % 4 == 0 else None, lambda d: _words(d, 0)),
    ("odd words", lambda n: n // 2 if n % 4 == 0 else None, lambda d: _words(d, 1)),
    ("even words, byte-swapped", lambda n: n // 2 if n % 4 == 0 else None,
     lambda d: _swap16(_words(d, 0))),
    ("odd words, byte-swapped", lambda n: n // 2 if n % 4 == 0 else None,
     lambda d: _swap16(_words(d, 1))),
    ("byte-swapped", lambda n: n if n % 2 == 0 else None, _swap16),
    ("mirrored twice", lambda n: n * 2, lambda d: d + d),
)


def _gf2_times(matrix: Sequence[int], vector: int) -> int:
    total, row = 0, 0
    while vector:
        if vector & 1:
            total ^= matrix[row]
        vector >>= 1
        row += 1
    return total


def _gf2_square(matrix: Sequence[int]) -> list[int]:
    return [_gf2_times(matrix, matrix[n]) for n in range(32)]


def crc32_combine(crc1: int, crc2: int, len2: int) -> int:
    """crc32 of A + B from crc32(A), crc32(B) and len(B), as zlib computes it."""
    if len2 <= 0:
        return crc1
    return _gf2_times(_shift_operator(len2), crc1) ^ crc2


@functools.cache
def _byte_shift(power: int) -> tuple[int, ...]:
    """The operator for 2**power zero bytes appended, as zlib squares it:
    three squarings of the one-bit operator give one byte, and each power
    is the square of the one before."""
    if power:
        return tuple(_gf2_square(list(_byte_shift(power - 1))))
    operator = [0xEDB88320] + [1 << (n - 1) for n in range(1, 32)]
    for _ in range(3):
        operator = _gf2_square(operator)
    return tuple(operator)


@functools.cache
def _shift_operator(len2: int) -> tuple[int, ...]:
    """The linear map zlib applies to crc(A) for len2 bytes appended.

    The product of the power-of-two operators the set bits of len2 select.
    Those powers are shared by every length, so each is squared once for the
    whole pass: squaring the chain again for each of the 3 600 lengths a
    romset pairs spent most of the crc work in GF(2) products.
    """
    columns = [1 << bit for bit in range(32)]
    power = 0
    while len2:
        if len2 & 1:
            matrix = _byte_shift(power)
            columns = [_gf2_times(matrix, column) for column in columns]
        len2 >>= 1
        power += 1
    return tuple(columns)


def _read(held: dict, archives: dict[str, zipfile.ZipFile] | None = None) -> bytes | None:
    """The bytes of a held file, or of a member read out of its archive.

    `archives` keeps each archive open across its members: reopened for
    every one, a MAME set of a hundred chips parsed its directory a
    hundred times.
    """
    try:
        if held.get("member"):
            if archives is None:
                with zipfile.ZipFile(held["archive"]) as zf:
                    return zf.read(held["member"])
            opened = archives.get(held["archive"])
            if opened is None:
                opened = archives[held["archive"]] = zipfile.ZipFile(held["archive"])
            return opened.read(held["member"])
        with open(held["path"], "rb") as handle:
            return handle.read()
    except (OSError, KeyError, zipfile.BadZipFile):
        return None


def _held_sources(db: dict) -> list[dict]:
    """Every file the collection holds, the members of its archives included.

    A romset holds chips a catalog lists on their own: cdi910.rom inside
    cdi910.zip is the CD-i 910 BIOS byte-swapped, and the two halves of the
    Salora Manager sit in manager.zip. Read from the top level alone, they
    stayed MISSING. A member's group is its archive, as a file's is its
    directory: the pairs a catalog splits come from one machine.
    """
    sources: list[dict] = []
    for record in db.get("files", {}).values():
        path = record.get("path", "")
        if not os.path.exists(path):
            continue
        if 0 < record.get("size", 0) <= MAX_SOURCE_SIZE:
            sources.append({**record, "group": os.path.dirname(path)})
        if not is_archive_path(path):
            continue
        try:
            with zipfile.ZipFile(path) as zf:
                infos = [i for i in zf.infolist() if not i.is_dir()]
        except (OSError, zipfile.BadZipFile):
            continue
        sources.extend(
            {
                "path": f"{path}/{info.filename}", "archive": path,
                "member": info.filename, "size": info.file_size,
                "crc32": f"{info.CRC:08x}", "group": path,
            }
            for info in infos
            if 0 < info.file_size <= MAX_SOURCE_SIZE
        )
    return sources


def derivable(entries: Iterable[dict], db: dict) -> dict[str, dict]:
    """Missing sha1 to the held file or member and the transform that
    produce its bytes. Archives stay open for the whole pass."""
    archives: dict[str, zipfile.ZipFile] = {}
    try:
        return _derivable(entries, db, archives)
    finally:
        for zf in archives.values():
            zf.close()


def _derivable(
    entries: Iterable[dict], db: dict, archives: dict[str, zipfile.ZipFile]
) -> dict[str, dict]:
    """Only held files whose size can produce a wanted size are read, and a
    concatenation is only tried within one directory or one archive: the
    chip pairs a catalog splits come from one machine.
    """
    wanted: dict[tuple[int, str], str] = {}
    by_size_crc: dict[tuple[int, int], list[str]] = defaultdict(list)
    for entry in entries:
        sha1, size = (entry.get("sha1") or "").lower(), entry.get("size")
        if sha1 and isinstance(size, int) and size > 0:
            wanted[(size, sha1)] = sha1
            crc = entry.get("crc32")
            if crc:
                by_size_crc[(size, int(str(crc), 16))].append(sha1)
    sizes = {size for size, _sha1 in wanted}
    found: dict[str, dict] = {}

    files = _held_sources(db)
    _find_transformed(files, wanted, sizes, archives, found)
    _find_concatenated(files, by_size_crc, sizes, archives, found)
    return found


def _find_transformed(
    files: list[dict],
    wanted: dict[tuple[int, str], str],
    sizes: set[int],
    archives: dict[str, zipfile.ZipFile],
    found: dict[str, dict],
) -> None:
    """Record each wanted sha1 one transform of a held file produces."""
    # The same chip sits in many archives. Its transforms are a function of
    # its bytes alone, and the first path read keeps the match, so a content
    # already transformed has nothing left to find.
    transformed: set[str] = set()
    for held in files:
        n = held["size"]
        useful = [
            (name, size_out, transform) for name, out_size, transform in TRANSFORMS
            if (size_out := out_size(n)) is not None and size_out in sizes
        ]
        if not useful:
            continue
        data = _read(held, archives)
        if data is None:
            continue
        content = hashlib.sha1(data).hexdigest()
        if content in transformed:
            continue
        transformed.add(content)
        for name, size_out, transform in useful:
            out = transform(data)
            sha1 = wanted.get((size_out, hashlib.sha1(out).hexdigest()))
            if sha1 and sha1 not in found:
                found[sha1] = {"from": [held["path"]], "transform": name}


def _find_concatenated(
    files: list[dict],
    by_size_crc: dict[tuple[int, int], list[str]],
    sizes: set[int],
    archives: dict[str, zipfile.ZipFile],
    found: dict[str, dict],
) -> None:
    """Record each wanted sha1 two held files of one group make end to end."""
    # Romsets repeat the same chip pairs: a combined crc is computed once.
    combined: dict[tuple[str, str, int], int] = {}
    by_dir: dict[str, list[dict]] = defaultdict(list)
    for held in files:
        if held.get("crc32"):
            by_dir[held["group"]].append(held)
    for group in by_dir.values():
        # A pair is only worth a crc when its sizes add up to a wanted one:
        # indexed by size, a member is paired once per size the group
        # holds, and a romset of a few hundred chips stays linear.
        by_size: dict[int, list[dict]] = defaultdict(list)
        for held in group:
            by_size[held["size"]].append(held)
        for first in group:
            for second_size, seconds in by_size.items():
                total = first["size"] + second_size
                if total not in sizes:
                    continue
                for second in seconds:
                    if first is not second:
                        _try_pair(first, second, total, combined, by_size_crc, archives, found)


def _try_pair(
    first: dict,
    second: dict,
    total: int,
    combined: dict[tuple[str, str, int], int],
    by_size_crc: dict[tuple[int, int], list[str]],
    archives: dict[str, zipfile.ZipFile],
    found: dict[str, dict],
) -> None:
    """Record the wanted sha1 first + second makes, if their crc names one."""
    key = (first["crc32"], second["crc32"], second["size"])
    crc = combined.get(key)
    if crc is None:
        crc = combined[key] = crc32_combine(
            int(first["crc32"], 16), int(second["crc32"], 16), second["size"])
    candidates = [s for s in by_size_crc.get((total, crc), [])
                  if s not in found]
    if not candidates:
        return
    a, b = _read(first, archives), _read(second, archives)
    if a is None or b is None:
        return
    sha1 = hashlib.sha1(a + b).hexdigest()
    if sha1 in candidates:
        found[sha1] = {"from": [first["path"], second["path"]],
                       "transform": "concatenated"}
