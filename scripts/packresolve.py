"""Finding the bytes a pack entry names.

Resolution proper lives in common; this layer adds what only a build
needs: storage tiers, release assets for files too large to commit,
and the offline switch that forbids reaching for the network."""

from __future__ import annotations

import re
_HEX_RE = re.compile(r"\b([0-9a-fA-F]{8,40})\b")
from validation import check_file_validation
from largefiles import fetch_large_file
import os
from hashing import parse_md5_list
from common import resolve_local_file
# CLI-wide network policy.  Public helpers can override it explicitly, while
# every CLI mode inherits --offline (including large-file release fallback).
_OFFLINE = False


def set_offline(value: bool) -> None:
    """Forbid every network reach for the rest of the run."""
    global _OFFLINE
    _OFFLINE = value

def _detect_hash_type(h: str) -> str:
    n = len(h)
    if n == 40:
        return "sha1"
    if n == 32:
        return "md5"
    if n == 8:
        return "crc32"
    return "md5"

def parse_hash_input(raw: str) -> list[tuple[str, str]]:
    """Parse comma-separated hash string into (type, hash) tuples."""
    results: list[tuple[str, str]] = []
    for part in raw.split(","):
        part = part.strip().lower()
        if not part:
            continue
        m = _HEX_RE.search(part)
        if m:
            h = m.group(1)
            results.append((_detect_hash_type(h), h))
    return results

def parse_hash_file(path: str) -> list[tuple[str, str]]:
    """Parse hash file (one per line, comments with #, mixed formats)."""
    results: list[tuple[str, str]] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = _HEX_RE.search(line.lower())
            if m:
                h = m.group(1)
                results.append((_detect_hash_type(h), h))
    return results

def lookup_hashes(
    hashes: list[tuple[str, str]],
    db: dict,
    bios_dir: str,
    emulators_dir: str,
    platforms_dir: str,
) -> None:
    """Print diagnostic info for each hash."""
    files_db = db.get("files", {})
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    by_crc32 = db.get("indexes", {}).get("by_crc32", {})

    for hash_type, hash_val in hashes:
        sha1 = None
        if hash_type == "sha1" and hash_val in files_db:
            sha1 = hash_val
        elif hash_type == "md5":
            sha1 = by_md5.get(hash_val)
        elif hash_type == "crc32":
            sha1 = by_crc32.get(hash_val)

        if not sha1 or sha1 not in files_db:
            print(f"\n{hash_type.upper()}: {hash_val}")
            print("  NOT FOUND in database")
            continue

        entry = files_db[sha1]
        name = entry.get("name", "?")
        md5 = entry.get("md5", "?")
        paths = entry.get("paths") or []
        aliases = entry.get("aliases") or []

        print(f"\n{hash_type.upper()}: {hash_val}")
        print(f"  SHA1: {sha1}")
        print(f"  MD5:  {md5}")
        print(f"  Name: {name}")
        if paths:
            print(f"  Path: {paths[0]}")
        if aliases:
            print(f"  Aliases: {aliases}")

        # Check if file exists in repo (by path or by resolve_local_file)
        in_repo = False
        if paths:
            primary = os.path.join(bios_dir, paths[0])
            if os.path.exists(primary):
                in_repo = True
        if not in_repo:
            try:
                fe_check = {"name": name, "sha1": sha1, "md5": md5}
                local, status = resolve_file(fe_check, db, bios_dir, {})
                if local and status != "not_found":
                    in_repo = True
            except (KeyError, OSError):
                pass
        print(f"  In repo: {'YES' if in_repo else 'NO'}")

def _find_candidate_satisfying_both(
    file_entry: dict,
    db: dict,
    local_path: str,
    validation_index: dict,
    bios_dir: str,
) -> str | None:
    """Search for a repo file that satisfies both platform MD5 and emulator validation.

    When the current file passes platform verification but fails emulator checks,
    search all candidates with the same name for one that passes both.
    Returns a better path, or None if no upgrade found.
    """
    fname = file_entry.get("name", "")
    if not fname:
        return None
    entry = validation_index.get(fname)
    if not entry:
        return None

    md5_expected = file_entry.get("md5", "")
    md5_set = (
        {m.strip().lower() for m in md5_expected.split(",") if m.strip()}
        if md5_expected
        else set()
    )

    by_name = db.get("indexes", {}).get("by_name", {})
    files_db = db.get("files", {})

    for sha1 in by_name.get(fname, []):
        candidate = files_db.get(sha1, {})
        path = candidate.get("path", "")
        if (
            not path
            or not os.path.exists(path)
            or os.path.realpath(path) == os.path.realpath(local_path)
        ):
            continue
        # Must still satisfy platform MD5
        if md5_set and candidate.get("md5", "").lower() not in md5_set:
            continue
        # Check emulator validation
        reason = check_file_validation(path, fname, validation_index, bios_dir)
        if reason is None:
            return path
    return None

def resolve_file(
    file_entry: dict,
    db: dict,
    bios_dir: str,
    zip_contents: dict | None = None,
    dest_hint: str = "",
    data_dir_registry: dict | None = None,
    *,
    offline: bool | None = None,
) -> tuple[str | None, str]:
    """Resolve a BIOS file with storage tiers and release asset fallback.

    Wraps common.resolve_local_file() with pack-specific logic for
    storage tiers (external/user_provided), large file release assets,
    and MAME clone mapping (deduped ZIPs).
    """
    storage = file_entry.get("storage", "embedded")
    if storage == "user_provided":
        return None, "user_provided"
    if storage == "external":
        return None, "external"

    path, status = resolve_local_file(
        file_entry,
        db,
        zip_contents,
        dest_hint=dest_hint,
        data_dir_registry=data_dir_registry,
    )
    if path and status != "hash_mismatch":
        return path, status

    # Large files from GitHub release assets -tried when local file is
    # missing OR has a hash mismatch (wrong variant on disk)
    name = file_entry.get("name", "")
    sha1 = file_entry.get("sha1")
    first_sha1 = (sha1[0] if sha1 else "") if isinstance(sha1, list) else (sha1 or "")
    md5_list = parse_md5_list(file_entry.get("md5"))
    first_md5 = md5_list[0] if md5_list else ""
    cached = fetch_large_file(
        name,
        expected_sha1=first_sha1,
        expected_md5=first_md5,
        offline=_OFFLINE if offline is None else offline,
    )
    if cached:
        return cached, "release_asset"

    # Fall back to hash_mismatch local file if release asset unavailable
    if path:
        return path, status

    return None, "not_found"
