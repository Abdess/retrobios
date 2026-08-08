"""Deterministic ZIP rebuilding for arcade BIOS and sample archives.

A ZIP's hash depends on entry order, timestamps, compression level, and
permission bits as much as on content. Packs ship archives rebuilt with
all of that fixed, so the same ROMs always produce the same pack hash
regardless of how the source set was assembled.

Usage:
    from deterministic_zip import rebuild_zip_deterministic

    sha1 = rebuild_zip_deterministic("neogeo.zip", "out/neogeo.zip")
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import zipfile
from pathlib import Path

# Fixed metadata for deterministic ZIPs
_FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)  # minimum ZIP timestamp
_FIXED_CREATE_SYSTEM = 0  # FAT/DOS (most compatible)
_FIXED_EXTERNAL_ATTR = 0o100644 << 16  # -rw-r--r--
_COMPRESS_LEVEL = 9  # deflate level 9 for determinism
_COPY_CHUNK = 1024 * 1024


def _sha1_file(path: str | Path) -> str:
    sha1 = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha1.update(chunk)
    return sha1.hexdigest()


def rebuild_zip_deterministic(
    source_zip: str | Path,
    output_zip: str | Path,
) -> str:
    """Rebuild a ZIP with fixed metadata and entries sorted by name.

    Copies one chunk at a time rather than loading the archive: arcade
    sample sets reach 279 MB, and holding a whole set plus its rebuilt
    copy in memory costs hundreds of megabytes per pack for no benefit.

    Reading through ZipFile.open verifies each entry against the CRC
    recorded in the source archive, so a corrupt entry raises
    BadZipFile instead of being copied through.

    Returns the SHA1 of the new ZIP.
    """
    with zipfile.ZipFile(str(source_zip)) as src:
        entries = sorted(
            (i for i in src.infolist() if not i.is_dir()),
            key=lambda i: i.filename,
        )
        with zipfile.ZipFile(
            str(output_zip),
            "w",
            zipfile.ZIP_DEFLATED,
            compresslevel=_COMPRESS_LEVEL,
        ) as dst:
            for info in entries:
                out_info = zipfile.ZipInfo(
                    filename=info.filename, date_time=_FIXED_DATE_TIME
                )
                out_info.compress_type = zipfile.ZIP_DEFLATED
                out_info.create_system = _FIXED_CREATE_SYSTEM
                out_info.external_attr = _FIXED_EXTERNAL_ATTR
                with src.open(info) as fsrc, dst.open(out_info, "w") as fdst:
                    shutil.copyfileobj(fsrc, fdst, _COPY_CHUNK)

    return _sha1_file(output_zip)


def verify_zip_determinism(zip_path: str | Path) -> tuple[bool, str, str]:
    """Check whether a ZIP already matches its deterministic rebuild.

    Returns (is_deterministic, original_sha1, rebuilt_sha1).
    """
    original = _sha1_file(zip_path)
    fd, tmp_path = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    try:
        rebuilt = rebuild_zip_deterministic(zip_path, tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    return original == rebuilt, original, rebuilt
