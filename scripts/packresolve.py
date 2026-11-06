"""Finding the bytes a pack entry names.

Resolution proper lives in common. This layer adds what only a build
needs: storage tiers, release assets for files too large to commit,
and the offline switch that forbids reaching for the network."""

from __future__ import annotations

import hashlib
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

from largefiles import fetch_large_file
from hashing import cut_md5_owner
from common import (
    declared_hash_verdict,
    resolution_is_hash_exact,
    resolve_local_file,
    sanitize_pack_path,
)
from validation import inner_rom_check
# CLI-wide network policy.  Public helpers can override it explicitly, while
# every CLI mode inherits --offline (including large-file release fallback).
_OFFLINE = False


def set_offline(value: bool) -> None:
    """Forbid every network reach for the rest of the run."""
    global _OFFLINE
    _OFFLINE = value


def scratch_dir() -> str:
    """The repository's tmp/, never the system /tmp (a 4 GB tmpfs on WSL)."""
    path = Path(__file__).resolve().parent.parent / "tmp"
    path.mkdir(exist_ok=True)
    return str(path)


def download_external(
    file_entry: dict, dest_path: str, offline: bool | None = None
) -> bool:
    """Download a `storage: external` file, verify its hash, write dest_path.

    The run's network policy applies: under --offline nothing is fetched and
    the entry stays missing, as verify reports it. The body is streamed to
    dest_path and hashed on the way, and removed when the hash disagrees.
    """
    url = file_entry.get("source_url")
    if not url:
        return False
    name = file_entry.get("name", url)
    declared = next(
        (
            (algo, str(file_entry[algo]).lower())
            for algo in ("sha256", "sha1", "md5")
            if file_entry.get(algo)
        ),
        None,
    )
    if declared is None:
        print(f"    WARNING: no hash for {name}, skipping unverifiable download")
        return False
    if _OFFLINE if offline is None else offline:
        print(f"    WARNING: {name} is external and the run is offline, not fetched")
        return False
    algo, expected = declared
    digest = hashlib.new(algo)
    Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "retrobios-pack-gen/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp, open(dest_path, "wb") as out:
            for chunk in iter(lambda: resp.read(1 << 20), b""):
                digest.update(chunk)
                out.write(chunk)
    except (urllib.error.URLError, OSError) as exc:
        print(f"    WARNING: Failed to download {url}: {exc}")
        Path(dest_path).unlink(missing_ok=True)
        return False
    if digest.hexdigest() != expected:
        print(f"    WARNING: {algo.upper()} mismatch for {name}")
        Path(dest_path).unlink(missing_ok=True)
        return False
    return True

def _values(raw: object) -> list[str]:
    """A hash field's values: one, a list, or a comma-separated string."""
    items = raw if isinstance(raw, list) else [raw] if raw else []
    return [
        value.strip().lower().removeprefix("0x")
        for item in items
        for value in str(item).split(",")
        if value.strip()
    ]


def _declared_hashes(file_entry: dict) -> dict[str, list[str]]:
    return {
        field: _values(file_entry.get(field))
        for field in ("sha1", "md5", "sha256", "crc32")
    }


def _verified_asset(
    name: str, declared: dict[str, list[str]], file_entry: dict, offline: bool
) -> str | None:
    """The release asset of that name, if it is a copy the entry accepts.

    The store is asked once per accepted sha1 (or md5), since it keeps one
    revision under a name. What it returns is held against every hash the
    entry declares, sha256 and crc32 included.
    """
    attempts = (
        [(sha1, "") for sha1 in declared["sha1"]]
        or [("", md5) for md5 in declared["md5"]]
        or [("", "")]
    )
    for sha1, md5 in attempts:
        cached = fetch_large_file(
            name, expected_sha1=sha1, expected_md5=md5, offline=offline,
        )
        if not cached:
            continue
        verdict = declared_hash_verdict(
            cached,
            has_strong_hash=any(declared.values()),
            sha1_candidates=set(declared["sha1"]),
            sha256_candidates=set(declared["sha256"]),
            md5_list=declared["md5"],
            crc_candidates=set(declared["crc32"]),
            zipped_file=file_entry.get("zipped_file"),
            declared_size=file_entry.get("size"),
            file_entry=file_entry,
        )
        if verdict != "hash_mismatch":
            return cached
    return None


def run_is_offline(offline: bool | None = None) -> bool:
    """Whether this run fetches nothing: --offline, or RETROBIOS_OFFLINE."""
    return bool(
        (_OFFLINE if offline is None else offline)
        or os.environ.get("RETROBIOS_OFFLINE")
    )


_RECORDS_BY_PATH: list[tuple[dict, int, dict[str, dict]]] = []


def _records_by_path(db: dict) -> dict[str, dict]:
    """The database records by path, built once per database."""
    files = db.get("files", {})
    if _RECORDS_BY_PATH:
        cached, size, index = _RECORDS_BY_PATH[0]
        if cached is files and size == len(files):
            return index
    index = {record.get("path"): record for record in files.values()}
    _RECORDS_BY_PATH[:] = [(files, len(files), index)]
    return index


def pending_release_asset(
    file_entry: dict, db: dict, registered: list[str] | None = None,
) -> str | None:
    """The release asset an online build fetches for an entry, if one does.

    The registered path whose database record carries what the entry
    declares, read without a download: verify never fetches, and a release
    asset the cache lacks was reported missing while an online build packed
    it. ``registered`` is the .gitignore registry (load_registered_paths).
    """
    from largefiles import asset_candidates, asset_names, load_registered_paths

    name = file_entry.get("name", "")
    if not name or name.endswith("/") or file_entry.get("type") == "directory":
        return None
    declared = _declared_hashes(file_entry)
    if file_entry.get("unsourceable") and not any(declared.values()):
        return None
    if file_entry.get("zipped_file") and not any(declared.values()):
        return None
    if registered is None:
        registered = load_registered_paths()
    assets = set(asset_candidates(name, registered))
    if not assets:
        return None
    records = _records_by_path(db)
    declared_size = file_entry.get("size")
    for path, asset in sorted(asset_names(registered).items()):
        record = records.get(path)
        if asset not in assets or record is None:
            continue
        if isinstance(declared_size, int) and record.get("size") != declared_size:
            continue
        if all(
            not values or str(record.get(field, "")).lower() in values
            for field, values in declared.items()
        ):
            return path
    return None


# Digest length in hex digits -> kind. A 29-digit MD5 is a value cut short,
# looked up as the resolver looks one up (cut_md5_owner).
_HASH_KINDS = {8: "crc32", 29: "md5", 32: "md5", 40: "sha1", 64: "sha256"}
_HEX_DIGITS = re.compile(r"[0-9a-f]+")
_WORD = re.compile(r"[0-9A-Za-z]+")
ACCEPTED_HASHES = (
    "CRC32 (8 hex digits), MD5 (32, or the 29 Batocera writes), "
    "SHA-1 (40) or SHA-256 (64)"
)


def _detect_hash_type(h: str) -> str | None:
    """The digest a hex string is, by its length, or None."""
    return _HASH_KINDS.get(len(h))


def _hash_token(token: str) -> tuple[str, str] | None:
    """(kind, value) when a token is a whole digest of a known length."""
    value = token.strip().lower().removeprefix("*").removeprefix("0x")
    kind = _detect_hash_type(value)
    if kind and _HEX_DIGITS.fullmatch(value):
        return kind, value
    return None


def _refuse(rejected: list[str]) -> None:
    shown = ", ".join(rejected[:5]) + (", ..." if len(rejected) > 5 else "")
    raise ValueError(f"not a hash: {shown}. Accepted: {ACCEPTED_HASHES}")


def parse_hash_input(raw: str) -> list[tuple[str, str]]:
    """Parse a comma-separated hash string into (type, hash) tuples.

    A part that is no digest is refused rather than dropped: a 12-digit
    value was looked up as an MD5 and reported NOT FOUND, and a SHA-256
    vanished without a word.
    """
    results: list[tuple[str, str]] = []
    rejected: list[str] = []
    for part in raw.split(","):
        if not part.strip():
            continue
        parsed = _hash_token(part)
        if parsed:
            results.append(parsed)
        else:
            rejected.append(part.strip())
    if rejected:
        _refuse(rejected)
    return results


def parse_hash_file(path: str) -> list[tuple[str, str]]:
    """Parse a hash file: one hash per line, alone or beside a file name as
    md5sum writes it, ``#`` for comments. A line holding no digest is
    refused with its line number."""
    results: list[tuple[str, str]] = []
    rejected: list[str] = []
    with open(path) as f:
        for number, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parsed = next(
                (h for h in map(_hash_token, _WORD.findall(line)) if h), None
            )
            if parsed:
                results.append(parsed)
            else:
                rejected.append(f"line {number} ({line[:40]})")
    if rejected:
        _refuse(rejected)
    return results


def sha1_for_hash(hash_type: str, hash_val: str, db: dict) -> str | None:
    """The database key a looked-up hash names, or None."""
    files_db = db.get("files", {})
    indexes = db.get("indexes", {})
    if hash_type == "sha1":
        sha1 = hash_val
    elif hash_type == "crc32":
        sha1 = indexes.get("by_crc32", {}).get(hash_val)
    elif hash_type == "md5":
        by_md5 = indexes.get("by_md5", {})
        sha1 = by_md5.get(hash_val)
        if sha1 is None:
            owner = cut_md5_owner(hash_val, by_md5)
            sha1 = by_md5.get(owner) if owner else None
    else:
        sha1 = next(
            (k for k, e in files_db.items() if e.get("sha256") == hash_val), None
        )
    return sha1 if sha1 in files_db else None

def lookup_hashes(
    hashes: list[tuple[str, str]],
    db: dict,
    bios_dir: str,
    emulators_dir: str,
    platforms_dir: str,
) -> int:
    """Print diagnostic info for each hash and return how many were not found."""
    missing = 0
    files_db = db.get("files", {})

    for hash_type, hash_val in hashes:
        sha1 = sha1_for_hash(hash_type, hash_val, db)
        if not sha1:
            print(f"\n{hash_type.upper()}: {hash_val}")
            print("  NOT FOUND in database")
            missing += 1
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
    if missing:
        print(f"\n{missing} of {len(hashes)} hash(es) not in the database")
    return missing

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

    # Large files from GitHub release assets: tried when local file is
    # missing OR has a hash mismatch (wrong variant on disk)
    name = file_entry.get("name", "")
    if file_entry.get("type") == "directory" or name.endswith("/"):
        # A tree the collection does not hold is missing, as verify says,
        # since the asset store holds files, not trees.
        return (path, status) if path else (None, "not_found")
    declared = _declared_hashes(file_entry)
    if file_entry.get("unsourceable") and not any(declared.values()):
        # The asset store is addressed by file name: with no hash to check,
        # it would hand back the same-named file of another game, which is
        # exactly what the flag forbids.
        return (path, status) if path else (None, "not_found")
    cached = _verified_asset(
        name, declared, file_entry, _OFFLINE if offline is None else offline,
    )
    if cached:
        return cached, "release_asset"

    # Fall back to hash_mismatch local file if release asset unavailable
    if path:
        return path, status

    return None, "not_found"


def apply_override(
    override: str | None, local_path: str | None, status: str
) -> tuple[str | None, str]:
    """The file a pack serves at a destination once its slot is settled.

    An entry the platform stores outside the collection, or a release asset
    fetched for its declared hash, keeps its own answer.
    """
    if override and status not in ("external", "release_asset"):
        return override, "slot_arbitrated"
    return local_path, status


def resolve_declaration(
    file_entry: dict,
    db: dict,
    bios_dir: str,
    zip_contents: dict | None,
    data_dir_registry: dict | None,
    override: str | None,
    *,
    offline: bool | None = None,
) -> tuple[str | None, str]:
    """The file a platform pack serves for one of the platform's declarations.

    Read by the builder, the install manifest, verify and the region pass.
    verify resolved with common.resolve_local_file and put the slot override
    first: without the release-asset tier a gitignored file absent from bios/
    read as missing there while the pack shipped the cached asset.
    """
    return apply_override(override, *resolve_file(
        file_entry,
        db,
        bios_dir,
        zip_contents,
        data_dir_registry=data_dir_registry,
        offline=offline,
    ))


def preferred_entries(
    pack_systems: dict,
    db: dict,
    bios_dir: str,
    base_dest: str,
    required_only: bool,
    zip_contents: dict | None,
    offline: bool | None,
) -> dict[str, int]:
    """Which declaration wins when several claim the same destination.

    A platform can declare one destination in more than one system, bare
    in one and hash-constrained in another. First-come dedup would let
    the bare entry pack whatever answers to the name, so a constrained
    sibling that resolves by content claims the destination instead.
    The choice is about the baseline and reads no data directory, for the
    pack, the manifest and verify alike: verify alone passed the registry
    and could crown a declaration only a data/ cache satisfies.
    """
    preferred_entries: dict[str, int] = {}
    dest_entries: dict[str, list[dict]] = {}
    for sys_id, system in sorted(pack_systems.items()):
        for file_entry in system.get("files", []):
            if required_only and file_entry.get("required") is False:
                continue
            dest = sanitize_pack_path(
                file_entry.get("destination", file_entry.get("name", ""))
            )
            if not dest:
                continue
            full = f"{base_dest}/{dest}" if base_dest else dest
            dest_entries.setdefault(full, []).append(file_entry)
    for full, entries in dest_entries.items():
        if len(entries) < 2:
            continue
        constrained = [
            fe
            for fe in entries
            if fe.get("md5") or fe.get("sha1") or fe.get("zipped_file")
        ]
        if not constrained:
            continue
        resolved = [
            (fe, *resolve_file(
                fe,
                db,
                bios_dir,
                zip_contents,
                offline=offline,
            ))
            for fe in constrained
        ]
        members = [fe for fe in entries if fe.get("zipped_file")]
        if members:
            # One archive declared once per ROM it must hold: the archive
            # to ship is the one the most declarations accept, not the first
            # that answers one of them (adam_fdc.zip: a one-member MAME set
            # answered first, the eight-member set sat beside it).
            def accepted(path: str | None) -> int:
                if not path or not path.endswith(".zip"):
                    return -1
                return sum(inner_rom_check(fe, path) == "ok" for fe in members)

            fe, path, _st = max(resolved, key=lambda item: accepted(item[1]))
            if accepted(path) > 0:
                preferred_entries[full] = id(fe)
                continue
        best = None
        for fe, _lp, _st in resolved:
            if _lp and _st == "md5_exact":
                best = fe
                break
            if best is None and _lp and resolution_is_hash_exact(_st):
                best = fe
        if best is not None:
            preferred_entries[full] = id(best)

    return preferred_entries
