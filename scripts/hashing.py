"""Content digests.

SHA-1 is the collection's primary key; the rest are what the various
frontends check against."""

from __future__ import annotations

import hashlib
import os
import zipfile
import zlib
from pathlib import Path


_ALL_ALGORITHMS = frozenset({"sha1", "md5", "sha256", "crc32", "adler32"})

def compute_hashes(
    filepath: str | Path,
    algorithms: frozenset[str] | None = None,
) -> dict[str, str]:
    """Compute file hashes. Pass *algorithms* to limit which are computed."""
    algos = algorithms or _ALL_ALGORITHMS
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
    with zipfile.ZipFile(filepath) as zf:
        names = sorted(n for n in zf.namelist() if not n.endswith("/"))
        h = hashlib.md5()
        for name in names:
            info = zf.getinfo(name)
            if info.file_size > 512 * 1024 * 1024:
                continue  # skip oversized entries
            h.update(zf.read(name))
        result = h.hexdigest()
    _md5_composite_cache[key] = result
    return result

def parse_md5_list(raw: str | list | None) -> list[str]:
    """Normalize an md5 field into a lowercase list.

    Platform YAMLs carry Recalbox multi-hash as one comma-separated string,
    emulator profiles carry a YAML list. Both reach here.
    """
    if not raw:
        return []
    values = raw if isinstance(raw, list) else str(raw).split(",")
    return [str(m).strip().lower() for m in values if str(m).strip()]
