"""Finding the bytes a pack entry names.

Resolution proper lives in resolve.localfile. This layer adds what only a build
needs: storage tiers, release assets for files too large to commit,
and the offline switch that forbids reaching for the network."""

from __future__ import annotations

import contextlib
import http.client
import os
import urllib.error
from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from core import upstream
from model.database import record_at, record_for_hash, sha1_at
from model.largefiles import asset_candidates, asset_names, fetch_large_file
from core.hashing import declared_hash_lists, file_digest
from resolve.content import declared_hash_verdict, record_answers_declaration
from resolve.localfile import resolution_is_hash_exact, resolve_local_file
from core.paths import REPO_ROOT, declared_destination
from core.ziptools import is_archive_path, readable_zip_member_crcs
from resolve.validation import inner_rom_check
# CLI-wide network policy.  Public helpers can override it explicitly, while
# every CLI mode inherits --offline (including large-file release fallback).
OFFLINE = False


def set_offline(value: bool) -> None:
    """Forbid every network reach for the rest of the run."""
    global OFFLINE
    OFFLINE = value


@contextlib.contextmanager
def offline() -> Iterator[None]:
    """The run offline for the length of a block, the previous policy restored after."""
    was_offline = OFFLINE
    set_offline(True)
    try:
        yield
    finally:
        set_offline(was_offline)


def scratch_dir() -> str:
    """The repository's tmp/, never the system /tmp (a 4 GB tmpfs on WSL)."""
    path = REPO_ROOT / "tmp"
    path.mkdir(exist_ok=True)
    return str(path)


class ExternalOutcome(Enum):
    """How a `storage: external` download ended."""

    FETCHED = "fetched"
    NO_URL = "no_url"
    NO_HASH = "no_hash"
    OFFLINE = "offline"
    NETWORK_ERROR = "network_error"
    MISMATCH = "mismatch"


@dataclass(frozen=True)
class ExternalFetch:
    """The end of one external download, with what the caller reports.

    ``detail`` is the URL and error for NETWORK_ERROR and the hash field for
    MISMATCH."""

    outcome: ExternalOutcome
    detail: str = ""

    @property
    def fetched(self) -> bool:
        return self.outcome is ExternalOutcome.FETCHED

    @property
    def reason(self) -> str:
        """Why the file is not in the pack, empty once it is."""
        return {
            ExternalOutcome.FETCHED: "",
            ExternalOutcome.NO_URL: "external file without a source_url",
            ExternalOutcome.NO_HASH: "external file without a hash, download unverifiable",
            ExternalOutcome.OFFLINE: "external file not fetched, the run is offline",
            ExternalOutcome.NETWORK_ERROR: f"external download failed: {self.detail}",
            ExternalOutcome.MISMATCH: f"external download fails its declared {self.detail}",
        }[self.outcome]


def download_external(
    file_entry: dict, dest_path: str, offline: bool | None = None
) -> ExternalFetch:
    """Download a `storage: external` file, verify its hash, write dest_path.

    The run's network policy applies: under --offline nothing is fetched and
    the entry stays missing, as verify reports it. core.upstream.download
    streams the body to a scratch beside dest_path, retried on a transient
    failure, and dest_path is written only once the scratch hashes to the
    declared value. Nothing is printed: the caller reports the outcome.
    """
    url = file_entry.get("source_url")
    if not url:
        return ExternalFetch(ExternalOutcome.NO_URL)
    # The strongest field declared, every value it accepts: a stringified
    # list or a comma-joined field matched no digest at all.
    declared = next(iter(declared_hash_lists(file_entry, ("sha256", "sha1", "md5")).items()), None)
    if declared is None:
        return ExternalFetch(ExternalOutcome.NO_HASH)
    if run_is_offline(offline):
        return ExternalFetch(ExternalOutcome.OFFLINE)
    algo, expected = declared[0], set(declared[1])
    Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
    try:
        served = upstream.download(
            url, dest_path, timeout=120, user_agent="retrobios-pack-gen/1.0",
            accept=lambda scratch: file_digest(Path(scratch), algo) in expected,
        )
    except (urllib.error.URLError, OSError, http.client.HTTPException,
            upstream.UpstreamError, ValueError) as exc:
        return ExternalFetch(ExternalOutcome.NETWORK_ERROR, f"{url}: {exc}")
    if served is None:
        return ExternalFetch(ExternalOutcome.MISMATCH, algo.upper())
    return ExternalFetch(ExternalOutcome.FETCHED)


def _fetched_asset(path: str, sha1: str, file_entry: dict, offline: bool) -> str | None:
    """The release asset of a registered path, downloaded if allowed and
    held to the record's sha1, then to every hash the entry declares."""
    declared = declared_hash_lists(file_entry)
    cached = fetch_large_file(path, expected_sha1=sha1, offline=offline)
    if not cached:
        return None
    verdict = declared_hash_verdict(
        cached,
        has_strong_hash=bool(declared),
        sha1_candidates=set(declared.get("sha1", [])),
        sha256_candidates=set(declared.get("sha256", [])),
        md5_list=declared.get("md5", []),
        crc_candidates=set(declared.get("crc32", [])),
        zipped_file=file_entry.get("zipped_file"),
        declared_size=file_entry.get("size"),
        file_entry=file_entry,
    )
    return None if verdict == "hash_mismatch" else cached


def run_is_offline(offline: bool | None = None) -> bool:
    """Whether this run fetches nothing: --offline, or RETROBIOS_OFFLINE."""
    return bool(
        (OFFLINE if offline is None else offline)
        or os.environ.get("RETROBIOS_OFFLINE")
    )


def release_asset_paths(
    file_entry: dict, db: dict, registered: list[str] | None = None,
) -> list[str]:
    """The registered paths whose release asset answers an entry, best first.

    Decided on the database record, without a download: the builder fetches
    the first that verifies (resolve_file), and verify, which never fetches,
    counts the first as packed. ``registered`` is the .gitignore registry
    (load_registered_paths).
    """
    name = file_entry.get("name", "")
    if not name or name.endswith("/") or file_entry.get("type") == "directory":
        # The asset store holds files, not trees.
        return []
    declared = declared_hash_lists(file_entry)
    if file_entry.get("unsourceable") and not declared:
        # The asset store is addressed by file name: with no hash to check,
        # it would hand back the same-named file of another game, which is
        # exactly what the flag forbids.
        return []
    if registered is None:
        # Looked up at call time, so a test's registry patch reaches it.
        from model.largefiles import load_registered_paths

        registered = load_registered_paths()
    by_asset: dict[str, str] = {}
    for path, asset in asset_names(registered).items():
        by_asset.setdefault(asset, path)
    paths: list[str] = []
    for asset in asset_candidates(name, registered):
        path = by_asset.get(asset)
        record = record_at(db, path)
        if path and record is not None and path not in paths and (
            record_answers_declaration(record, file_entry, declared)
        ):
            paths.append(path)
    return paths


def sha1_for_hash(hash_type: str, hash_val: str, db: dict) -> str | None:
    """The database key a looked-up hash names, or None."""
    return record_for_hash(db, hash_type, hash_val)


@dataclass(frozen=True)
class HashLookup:
    """What the database and the disk say about one looked-up hash.

    ``sha1`` is empty when the database holds no file under the hash."""

    kind: str
    value: str
    sha1: str = ""
    md5: str = ""
    name: str = ""
    path: str = ""
    in_repo: bool = False

    @property
    def found(self) -> bool:
        return bool(self.sha1)


def lookup_hashes(
    hashes: list[tuple[str, str]], db: dict, bios_dir: str,
) -> list[HashLookup]:
    """One record per hash: the file the database names, and whether the
    repository holds its bytes (at its path, wherever resolution finds them,
    or as a release asset). Nothing is downloaded to answer."""
    files_db = db.get("files", {})
    records: list[HashLookup] = []
    for hash_type, hash_val in hashes:
        sha1 = sha1_for_hash(hash_type, hash_val, db)
        if not sha1:
            records.append(HashLookup(hash_type, hash_val))
            continue
        entry = files_db[sha1]
        name = entry.get("name", "?")
        md5 = entry.get("md5", "?")
        path = entry.get("path", "")
        in_repo = bool(path) and os.path.exists(path)
        if not in_repo:
            fe_check = {"name": name, "sha1": sha1, "md5": md5}
            local, status = resolve_file(fe_check, db, bios_dir, {}, offline=True)
            in_repo = (bool(local) and status != "not_found") or bool(
                release_asset_paths(fe_check, db)
            )
        records.append(HashLookup(hash_type, hash_val, sha1, md5, name, path, in_repo))
    return records

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

    Wraps resolve_local_file() with pack-specific logic for
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
    for asset_path in release_asset_paths(file_entry, db):
        sha1 = sha1_at(db, asset_path) or ""
        cached = _fetched_asset(asset_path, sha1, file_entry, run_is_offline(offline))
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
    verify resolved with resolve_local_file and put the slot override
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


def _declarations_by_destination(
    pack_systems: dict, base_dest: str, required_only: bool,
) -> dict[str, list[dict]]:
    """The declarations of each full destination, in system order."""
    dest_entries: dict[str, list[dict]] = {}
    for _sys_id, system in sorted(pack_systems.items()):
        for file_entry in system.get("files", []):
            if required_only and file_entry.get("required") is False:
                continue
            dest = declared_destination(file_entry)
            if not dest:
                continue
            full = f"{base_dest}/{dest}" if base_dest else dest
            dest_entries.setdefault(full, []).append(file_entry)
    return dest_entries


def _archive_choice(
    resolved: list[tuple[dict, str | None, str]], members: list[dict],
) -> dict | None:
    """The declaration whose archive the most per-ROM declarations accept."""
    # One archive declared once per ROM it must hold: the archive
    # to ship is the one the most declarations accept, not the first
    # that answers one of them (adam_fdc.zip: a one-member MAME set
    # answered first, the eight-member set sat beside it).
    def accepted(path: str | None) -> int:
        if not path or not is_archive_path(path):
            return -1
        return sum(inner_rom_check(fe, path) == "ok" for fe in members)

    fe, path, _st = max(resolved, key=lambda item: accepted(item[1]))
    return fe if accepted(path) > 0 else None


def _covering_archive(candidates: list[tuple[dict, str]]) -> dict | None:
    """The archive holding every member each other candidate holds, and more.

    RetroDECK pins bios/cdibios.zip twice: the two-member MAME set for its
    mame component, the three-member set for the CD-i core. MAME reads the
    members, never the container, and its cdi driver needs all three, so
    the larger set serves both readers where the first one serves one.
    """
    sets: list[tuple[dict, frozenset[str]]] = []
    for fe, path in candidates:
        members = readable_zip_member_crcs(path)
        if members is None:
            return None
        sets.append((fe, members))
    for fe, members in sets:
        others = [m for other, m in sets if other is not fe]
        if all(members > m for m in others):
            return fe
    return None


def _hash_choice(resolved: list[tuple[dict, str | None, str]]) -> dict | None:
    """The declaration resolved by md5, else the first by any hash.

    Two md5 pins on one path are two files for one place: one stays red in
    the frontend's check whichever ships, so the archive covering the other
    ships, else the first.
    """
    by_md5 = [(fe, lp) for fe, lp, st in resolved if lp and st == "md5_exact"]
    if by_md5:
        if len({lp for _fe, lp in by_md5}) > 1:
            covering = _covering_archive(by_md5)
            if covering is not None:
                return covering
        return by_md5[0][0]
    return next(
        (fe for fe, lp, st in resolved if lp and resolution_is_hash_exact(st)), None)


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
    dest_entries = _declarations_by_destination(pack_systems, base_dest, required_only)
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
            chosen = _archive_choice(resolved, members)
            if chosen is not None:
                preferred_entries[full] = id(chosen)
                continue
        best = _hash_choice(resolved)
        if best is not None:
            preferred_entries[full] = id(best)

    return preferred_entries
