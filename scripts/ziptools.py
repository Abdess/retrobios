"""Reading archives that may be hostile.

Every limit here bounds what a crafted archive can cost without
capping a real romset: the largest pack is already several gigabytes."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
import zipfile

from hashing import md5sum


def check_inside_zip(container: str, file_name: str, expected_md5: str) -> str:
    """Check a ROM inside a ZIP -replicates Batocera checkInsideZip().

    Returns "ok", "untested", "not_in_zip", or "error".
    """
    try:
        with zipfile.ZipFile(container) as archive:
            for fname in archive.namelist():
                if fname.casefold() == file_name.casefold():
                    info = archive.getinfo(fname)
                    if info.file_size > 512 * 1024 * 1024:
                        return "error"
                    if expected_md5 == "":
                        return "ok"
                    with archive.open(fname) as entry:
                        actual = md5sum(entry)
                    return "ok" if actual == expected_md5 else "untested"
            return "not_in_zip"
    except (zipfile.BadZipFile, OSError, KeyError):
        return "error"

_zip_contents_cache: tuple[frozenset[tuple[str, float]], dict] | None = None

def build_zip_contents_index(db: dict, max_entry_size: int = 512 * 1024 * 1024) -> dict:
    """Build {inner_rom_md5: zip_file_sha1} for ROMs inside ZIP files.

    Results are cached in-process; repeated calls with unchanged ZIPs return
    the cached index.
    """
    global _zip_contents_cache

    # Build fingerprint from ZIP paths + mtimes for cache invalidation
    zip_entries: list[tuple[str, str]] = []
    for sha1, entry in db.get("files", {}).items():
        path = entry["path"]
        if path.endswith(".zip") and os.path.exists(path):
            zip_entries.append((path, sha1))

    fingerprint = frozenset((path, os.path.getmtime(path)) for path, _ in zip_entries)
    if _zip_contents_cache is not None and _zip_contents_cache[0] == fingerprint:
        return _zip_contents_cache[1]

    index: dict[str, str] = {}
    for path, sha1 in zip_entries:
        try:
            with zipfile.ZipFile(path, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir() or info.file_size > max_entry_size:
                        continue
                    h = hashlib.md5()
                    with zf.open(info.filename) as inner:
                        for chunk in iter(lambda: inner.read(65536), b""):
                            h.update(chunk)
                    index[h.hexdigest()] = sha1
        except (zipfile.BadZipFile, OSError):
            continue

    _zip_contents_cache = (fingerprint, index)
    return index

MAX_ZIP_MEMBERS = 100_000

MAX_ZIP_MEMBER_SIZE = 8 * 1024 * 1024 * 1024

MAX_ZIP_MEMBER_SIZE = 8 * 1024 * 1024 * 1024
# The largest generated pack is already ~5 GB uncompressed and the collection
# only grows; this bounds a malicious archive without capping a real one.
MAX_ZIP_TOTAL_SIZE = 64 * 1024 * 1024 * 1024

MAX_ZIP_TOTAL_SIZE = 64 * 1024 * 1024 * 1024
# DEFLATE cannot exceed roughly 1,032:1, so this rejects a declared ratio no
# real DEFLATE member can reach. Methods with a higher ceiling (bzip2, LZMA)
# are exempt and bounded by the per-member and per-archive size limits alone.
MAX_ZIP_COMPRESSION_RATIO = 1_100

MAX_ZIP_COMPRESSION_RATIO = 1_100
_BOUNDED_RATIO_METHODS = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)

def safe_extract_zip(
    zip_path: str,
    dest_dir: str,
    *,
    max_members: int = MAX_ZIP_MEMBERS,
    max_member_size: int = MAX_ZIP_MEMBER_SIZE,
    max_total_size: int = MAX_ZIP_TOTAL_SIZE,
    max_compression_ratio: int = MAX_ZIP_COMPRESSION_RATIO,
) -> None:
    """Extract a ZIP with traversal, link and resource-limit protection.

    Files are streamed to a temporary sibling and atomically installed only
    after their declared length and CRC have been checked by ``zipfile``.
    """
    dest = os.path.realpath(dest_dir)
    os.makedirs(dest, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        members = zf.infolist()
        if len(members) > max_members:
            raise ValueError(
                f"ZIP has {len(members)} members; limit is {max_members}"
            )

        declared_total = 0
        seen: set[str] = set()
        for member in members:
            # Archives written on Windows store a backslash separator. It is a
            # separator, not a filename character, so it is normalized before
            # the component checks rather than rejected.
            name = member.filename.replace("\\", "/")
            if not name or "\x00" in name:
                raise ValueError(f"Unsafe ZIP member name: {member.filename!r}")
            if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
                raise ValueError(f"Absolute ZIP member path: {name}")
            parts = [part for part in name.split("/") if part]
            if any(part in (".", "..") for part in parts):
                raise ValueError(f"ZIP traversal detected: {name}")
            normalized = "/".join(parts)
            if normalized in seen:
                raise ValueError(f"Duplicate ZIP member path: {name}")
            seen.add(normalized)

            mode = (member.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(mode)
            if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError(f"ZIP link or special file rejected: {name}")
            if member.flag_bits & 0x1:
                raise ValueError(f"Encrypted ZIP member rejected: {name}")
            if member.file_size > max_member_size:
                raise ValueError(
                    f"ZIP member {name} is {member.file_size} bytes; "
                    f"limit is {max_member_size}"
                )
            declared_total += member.file_size
            if declared_total > max_total_size:
                raise ValueError(
                    f"ZIP expands to {declared_total} bytes; limit is {max_total_size}"
                )
            if member.file_size and member.compress_type in _BOUNDED_RATIO_METHODS:
                if member.compress_size == 0:
                    raise ValueError(f"Invalid compression size for ZIP member: {name}")
                if member.file_size / member.compress_size > max_compression_ratio:
                    raise ValueError(f"Suspicious compression ratio for ZIP member: {name}")

            target = os.path.realpath(os.path.join(dest, *parts))
            if not target.startswith(dest + os.sep) and target != dest:
                raise ValueError(f"ZIP traversal detected: {name}")
            if member.is_dir() or name.endswith("/"):
                os.makedirs(target, exist_ok=True)
                continue

            os.makedirs(os.path.dirname(target), exist_ok=True)
            tmp_path = ""
            try:
                with tempfile.NamedTemporaryFile(
                    mode="wb", dir=os.path.dirname(target), delete=False
                ) as tmp_file:
                    tmp_path = tmp_file.name
                    actual_size = 0
                    with zf.open(member, "r") as source:
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            actual_size += len(chunk)
                            if actual_size > member.file_size or actual_size > max_member_size:
                                raise ValueError(
                                    f"ZIP member exceeded declared or configured size: {name}"
                                )
                            tmp_file.write(chunk)
                if actual_size != member.file_size:
                    raise ValueError(
                        f"ZIP member size mismatch for {name}: "
                        f"{actual_size} != {member.file_size}"
                    )
                os.replace(tmp_path, target)
                tmp_path = ""
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    os.unlink(tmp_path)
