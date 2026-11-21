"""Reading archives that may be hostile.

Every limit here bounds what a crafted archive can cost without
capping a real romset: the largest pack is already several gigabytes."""

from __future__ import annotations

from dataclasses import dataclass

import functools
import io
import os
import re
import stat
import sys
import tempfile
import zipfile

from core.artifacts import process_umask, write_text_atomic
from core.hashing import MAX_HASHED_MEMBER, md5sum
from core.paths import REPO_ROOT

_ARCHIVE_PATH = re.compile(r"\.zip(\.[0-9a-f]{8})?$", re.IGNORECASE)


def is_archive_path(path: str) -> bool:
    """A ZIP by its name: ``x.zip`` or a ``.variants/`` copy ``x.zip.1a2b3c4d``."""
    return bool(_ARCHIVE_PATH.search(path))


def check_inside_zip(container: str, file_name: str, expected_md5: str) -> str:
    """Check a ROM inside a ZIP, as Batocera's checkInsideZip() does.

    Returns "ok", "untested", "not_in_zip", or "error".
    """
    try:
        info = os.stat(container)
    except OSError:
        return "error"
    found = _member_md5(
        container, info.st_size, info.st_mtime_ns, file_name.casefold(),
        expected_md5 != "",
    )
    return _inside_zip_answer(found, expected_md5)


def check_inside_zip_data(data: bytes, file_name: str, expected_md5: str) -> str:
    """check_inside_zip on the bytes of an archive, such as a pack member."""
    found = _read_member_md5(
        io.BytesIO(data), file_name.casefold(), expected_md5 != ""
    )
    return _inside_zip_answer(found, expected_md5)


def _inside_zip_answer(found: str, expected_md5: str) -> str:
    if found in ("not_in_zip", "error"):
        return found
    if expected_md5 == "":
        return "ok"
    return "ok" if found == expected_md5 else "untested"


@functools.lru_cache(maxsize=8192)
def _member_md5(
    container: str, size: int, mtime_ns: int, folded: str, hashed: bool
) -> str:
    """The md5 of the member named `folded` (case-folded), or why there is none.

    One archive member is asked about by every md5 a platform accepts for it
    and by every step that checks it: `verify --all` decompressed 355
    members 4 788 times. Keyed by the archive's size and mtime, so a
    rewritten archive is read again.
    """
    return _read_member_md5(container, folded, hashed)


def _read_member_md5(source: str | io.BytesIO, folded: str, hashed: bool) -> str:
    try:
        with zipfile.ZipFile(source) as archive:
            for fname in archive.namelist():
                if fname.casefold() != folded:
                    continue
                if archive.getinfo(fname).file_size > MAX_HASHED_MEMBER:
                    return "error"
                if not hashed:
                    return "present"
                with archive.open(fname) as entry:
                    return md5sum(entry)
            return "not_in_zip"
    except (zipfile.BadZipFile, OSError, KeyError):
        return "error"


@functools.lru_cache(maxsize=4096)
def _member_crcs(path: str, mtime: float) -> frozenset[str] | None:
    try:
        with zipfile.ZipFile(path) as archive:
            return frozenset(
                format(info.CRC, "08x") for info in archive.infolist() if not info.is_dir()
            )
    except (zipfile.BadZipFile, OSError):
        return None


@functools.lru_cache(maxsize=4096)
def _member_names(path: str, mtime: float) -> frozenset[str]:
    try:
        with zipfile.ZipFile(path) as archive:
            return frozenset(
                info.filename.rsplit("/", 1)[-1].casefold()
                for info in archive.infolist() if not info.is_dir()
            )
    except (zipfile.BadZipFile, OSError):
        return frozenset()


def zip_member_names(path: str) -> frozenset[str]:
    """Casefolded base name of each member, read from the central directory."""
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return frozenset()
    return _member_names(path, mtime)


def readable_zip_member_crcs(path: str) -> frozenset[str] | None:
    """CRC-32 of each member, read from the central directory, None when
    the file is no readable archive."""
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None
    return _member_crcs(path, mtime)


def zip_member_crcs(path: str) -> frozenset[str]:
    """CRC-32 of each member, empty when the file is no readable archive."""
    return readable_zip_member_crcs(path) or frozenset()


_zip_contents_cache: tuple[tuple, dict] | None = None

# Member md5s per archive, keyed by the archive's sha1: content addressed, so
# a cached answer is never stale. Every pipeline step that resolves a
# zipped_file used to decompress the 54 845 members again, about 23 s each.
MEMBER_CACHE = os.path.join(
    REPO_ROOT, ".cache", "zip_member_md5.json"
)


def _read_member_cache(path: str) -> dict[str, list[list]]:
    import json

    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        print(f"warning: ignoring unreadable {path}: {exc}", file=sys.stderr)
        return {}
    return data if isinstance(data, dict) else {}


def _write_member_cache(path: str, data: dict[str, list[list]]) -> None:
    import json

    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        write_text_atomic(path, json.dumps(data, separators=(",", ":")))
    except OSError as exc:
        print(f"warning: could not write {path}: {exc}", file=sys.stderr)


def _members_md5(path: str) -> list[list] | None:
    """[md5, size] of each member, or None for an archive that cannot be read."""
    members: list[list] = []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if info.file_size > MAX_HASHED_MEMBER:
                    members.append([None, info.file_size])
                    continue
                with zf.open(info.filename) as inner:
                    members.append([md5sum(inner), info.file_size])
    except (zipfile.BadZipFile, OSError) as exc:
        print(f"warning: unreadable archive {path}: {exc}", file=sys.stderr)
        return None
    return members


def build_zip_contents_index(
    db: dict,
    max_entry_size: int = MAX_HASHED_MEMBER,
    cache_path: str | None = MEMBER_CACHE,
) -> dict:
    """Build {inner_rom_md5: zip_file_sha1} for ROMs inside ZIP files.

    Cached in-process, and on disk per archive sha1 when cache_path is set.
    """
    global _zip_contents_cache

    zip_entries: list[tuple[str, str]] = []
    for sha1, entry in db.get("files", {}).items():
        path = entry["path"]
        if path.endswith(".zip") and os.path.exists(path):
            zip_entries.append((path, sha1))

    # The bound and the sha1 each path carries are part of the answer: a
    # second call with a smaller bound got members the first one admitted,
    # and a regenerated database got the sha1 of the old one.
    fingerprint = (
        max_entry_size,
        frozenset((path, os.path.getmtime(path), sha1) for path, sha1 in zip_entries),
    )
    if _zip_contents_cache is not None and _zip_contents_cache[0] == fingerprint:
        return _zip_contents_cache[1]

    cached = _read_member_cache(cache_path) if cache_path else {}
    added = False
    index: dict[str, str] = {}
    for path, sha1 in zip_entries:
        members = cached.get(sha1)
        if members is None:
            members = _members_md5(path)
            if members is None:
                continue
            cached[sha1] = members
            added = True
        for md5, size in members:
            if md5 is not None and size <= max_entry_size:
                index[md5] = sha1
    if added and cache_path:
        _write_member_cache(cache_path, cached)

    _zip_contents_cache = (fingerprint, index)
    return index


MAX_ZIP_MEMBERS = 100_000

MAX_ZIP_MEMBER_SIZE = 8 * 1024 * 1024 * 1024

# The largest generated pack is already ~5 GB uncompressed and the collection
# only grows. This bounds a malicious archive without capping a real one.
MAX_ZIP_TOTAL_SIZE = 64 * 1024 * 1024 * 1024

# DEFLATE cannot exceed roughly 1,032:1, so this rejects a declared ratio no
# real DEFLATE member can reach. Methods with a higher ceiling (bzip2, LZMA)
# are exempt and bounded by the per-member and per-archive size limits alone.
MAX_ZIP_COMPRESSION_RATIO = 1_100
_BOUNDED_RATIO_METHODS = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)


@dataclass(frozen=True)
class _ZipLimits:
    """The resource bounds safe_extract_zip enforces."""

    members: int
    member_size: int
    total_size: int
    compression_ratio: int


def safe_member_parts(member: zipfile.ZipInfo) -> list[str]:
    """Path components of a member whose path and type are safe to write
    under a directory, ValueError otherwise."""
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
    file_type = stat.S_IFMT(member.external_attr >> 16)
    if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise ValueError(f"ZIP link or special file rejected: {name}")
    if member.flag_bits & 0x1:
        raise ValueError(f"Encrypted ZIP member rejected: {name}")
    return parts


def _member_path(member: zipfile.ZipInfo, seen: set[str]) -> tuple[str, list[str], int]:
    """(name, path components, mode) of a member whose path and type are safe."""
    parts = safe_member_parts(member)
    name = member.filename.replace("\\", "/")
    normalized = "/".join(parts)
    if normalized in seen:
        raise ValueError(f"Duplicate ZIP member path: {name}")
    seen.add(normalized)
    return name, parts, (member.external_attr >> 16) & 0xFFFF


def _check_member_size(
    member: zipfile.ZipInfo, name: str, declared_total: int, limits: _ZipLimits,
) -> int:
    """The declared total with this member, after its size limits are checked."""
    if member.file_size > limits.member_size:
        raise ValueError(
            f"ZIP member {name} is {member.file_size} bytes; "
            f"limit is {limits.member_size}"
        )
    declared_total += member.file_size
    if declared_total > limits.total_size:
        raise ValueError(
            f"ZIP expands to {declared_total} bytes, limit is {limits.total_size}"
        )
    if member.file_size and member.compress_type in _BOUNDED_RATIO_METHODS:
        if member.compress_size == 0:
            raise ValueError(f"Invalid compression size for ZIP member: {name}")
        if member.file_size / member.compress_size > limits.compression_ratio:
            raise ValueError(f"Suspicious compression ratio for ZIP member: {name}")
    return declared_total


def _install_member(
    zf: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    name: str,
    target: str,
    mode: int,
    umask: int,
    max_member_size: int,
) -> None:
    """Stream a member to a temporary sibling, check it, then move it in place."""
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
        # The member's own mode, else what a plain open() gives. The
        # temporary file is private and would keep 0600 otherwise.
        os.chmod(tmp_path, ((mode & 0o777) or 0o666) & ~umask)
        os.replace(tmp_path, target)
        tmp_path = ""
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


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
    limits = _ZipLimits(max_members, max_member_size, max_total_size, max_compression_ratio)
    dest = os.path.realpath(dest_dir)
    os.makedirs(dest, exist_ok=True)
    umask = process_umask()
    with zipfile.ZipFile(zip_path, "r") as zf:
        members = zf.infolist()
        if len(members) > limits.members:
            raise ValueError(
                f"ZIP has {len(members)} members, limit is {limits.members}"
            )

        declared_total = 0
        seen: set[str] = set()
        for member in members:
            name, parts, mode = _member_path(member, seen)
            declared_total = _check_member_size(member, name, declared_total, limits)

            target = os.path.realpath(os.path.join(dest, *parts))
            if not target.startswith(dest + os.sep) and target != dest:
                raise ValueError(f"ZIP traversal detected: {name}")
            if member.is_dir() or name.endswith("/"):
                os.makedirs(target, exist_ok=True)
                continue
            _install_member(zf, member, name, target, mode, umask, limits.member_size)
