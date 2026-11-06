"""Content digests.

SHA-1 is the collection's primary key. The rest are what the various
frontends check against."""

from __future__ import annotations

import hashlib
import os
import zipfile
import zlib
from pathlib import Path
from typing import BinaryIO
from collections.abc import Iterable


_ALL_ALGORITHMS = frozenset({"sha1", "md5", "sha256", "crc32", "adler32"})

# (path, inode, size, mtime_ns, ctime_ns) -> the digests read so far.
# verify --all hashed GB_dmg.bin 13 times, once per platform and entry. The
# bytes are still read from disk, once per file and change.
_hash_cache: dict[tuple, dict[str, str]] = {}


def compute_hashes(
    filepath: str | Path,
    algorithms: frozenset[str] | None = None,
    cache: bool = True,
) -> dict[str, str]:
    """Compute file hashes. Pass *algorithms* to limit which are computed.

    cache=False reads the file again, for a second opinion on a digest.
    """
    algos = frozenset(algorithms) if algorithms else _ALL_ALGORITHMS
    if not cache:
        return _compute_hashes(filepath, algos)
    try:
        stat = os.stat(filepath)
        key: tuple | None = (
            os.path.realpath(filepath), stat.st_ino, stat.st_size,
            stat.st_mtime_ns, stat.st_ctime_ns,
        )
    except OSError:
        key = None
    known = _hash_cache.get(key) if key else None
    if known is not None and algos <= known.keys():
        return {name: known[name] for name in algos}
    result = _compute_hashes(filepath, algos)
    if key is not None:
        _hash_cache.setdefault(key, {}).update(result)
    return result


def _compute_hashes(filepath: str | Path, algos: frozenset[str]) -> dict[str, str]:
    """Read the file once and compute the requested digests."""
    sha1 = hashlib.sha1() if "sha1" in algos else None
    md5 = hashlib.md5() if "md5" in algos else None
    sha256 = hashlib.sha256() if "sha256" in algos else None
    do_crc = "crc32" in algos
    do_adler = "adler32" in algos
    crc = 0
    adler = 1  # zlib.adler32 initial value
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            if sha1:
                sha1.update(chunk)
            if md5:
                md5.update(chunk)
            if sha256:
                sha256.update(chunk)
            if do_crc:
                crc = zlib.crc32(chunk, crc)
            if do_adler:
                adler = zlib.adler32(chunk, adler)
    result: dict[str, str] = {}
    if sha1:
        result["sha1"] = sha1.hexdigest()
    if md5:
        result["md5"] = md5.hexdigest()
    if sha256:
        result["sha256"] = sha256.hexdigest()
    if do_crc:
        result["crc32"] = format(crc & 0xFFFFFFFF, "08x")
    if do_adler:
        result["adler32"] = format(adler & 0xFFFFFFFF, "08x")
    return result

def md5sum(source: str | Path | object) -> str:
    """Compute MD5 of a file path or file-like object - matches Batocera's md5sum()."""
    h = hashlib.md5()
    if hasattr(source, "read"):
        for chunk in iter(lambda: source.read(65536), b""):
            h.update(chunk)
    else:
        with open(source, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    return h.hexdigest()

_md5_composite_cache: dict[str, str] = {}

def md5_composite(filepath: str | Path) -> str:
    """Compute composite MD5 of a ZIP - matches Recalbox's Zip::Md5Composite().

    Sorts filenames alphabetically, reads each file's contents in order,
    feeds everything into a single MD5 hasher. The result is independent
    of ZIP compression level or metadata. Results are cached per path.
    """
    key = str(filepath)
    cached = _md5_composite_cache.get(key)
    if cached is not None:
        return cached
    result = md5_composite_of(filepath)
    _md5_composite_cache[key] = result
    return result


def md5_composite_of(source: str | Path | BinaryIO) -> str:
    """md5_composite without the cache, for an archive held in memory.

    A buffer has no stable name: keyed by its repr, a later buffer at the
    same address read back another archive's digest.
    """
    with zipfile.ZipFile(source) as zf:
        names = sorted(n for n in zf.namelist() if not n.endswith("/"))
        h = hashlib.md5()
        for name in names:
            info = zf.getinfo(name)
            if info.file_size > 512 * 1024 * 1024:
                continue  # skip oversized entries
            h.update(zf.read(name))
        return h.hexdigest()

def cut_md5_owner(cut: str, md5s: Iterable[str]) -> str | None:
    """The one md5 a value cut short starts, None when none or several do.

    The single rule for a cut md5, read by the scraper, the resolver and
    --from-md5. It names a dump, it never verifies one: Batocera compares
    the whole string (batocera-systems:1088), so every verdict compares
    exact digests.
    """
    if not cut or len(cut) >= 32:
        return None
    found = {md5 for md5 in md5s if md5.startswith(cut)}
    return found.pop() if len(found) == 1 else None


def parse_hash_list(raw: str | list | int | None) -> list[str]:
    """Normalize any hash field into its accepted values, lowercase.

    A field holds one value, a YAML list, or one comma-joined string
    (Recalbox md5, mesence's four sha256 for one entry), and a crc32 may carry
    a 0x prefix. Read one way here, the resolver, the gap report and
    profile_sync accept the same values.
    """
    if raw is None or raw == "":
        return []
    items = raw if isinstance(raw, list) else str(raw).split(",")
    out: list[str] = []
    for item in items:
        value = str(item).strip().lower().removeprefix("0x")
        if value and value not in out:
            out.append(value)
    return out


def parse_md5_list(raw: str | list | None) -> list[str]:
    """Normalize an md5 field into a lowercase list.

    Platform YAMLs carry Recalbox multi-hash as one comma-separated string,
    emulator profiles carry a YAML list. Both reach here.
    """
    return parse_hash_list(raw)
