"""Checking a built pack the way the frontend would.

The builder and the verifier have to reach the same verdict on the
same file, so both read the native mode from one place: a pack and a
coverage report that disagree describe different collections."""

from __future__ import annotations

from pathlib import Path
from model.dbpaths import collection_root

from core.artifacts import build_timestamp
from packs.archive import is_pack_note
from core.ziptools import build_zip_contents_index, zip_members
from core.hashing import (
    compute_hashes, md5sum, stream_hashes,
)
import io
import os
from core.paths import BIOS_DIR
import zipfile
from collections.abc import Callable


def _members_are_held(data: bytes, by_md5: dict, held_inside: dict) -> bool:
    """Whether every member of an archive is a dump the collection holds."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = [i for i in archive.infolist() if not i.is_dir()]
            if not members:
                return False
            for info in members:
                with archive.open(info) as stream:
                    digest = md5sum(stream)
                if digest not in by_md5 and digest not in held_inside:
                    return False
    except (zipfile.BadZipFile, OSError):
        return False
    return True


def _once(build: Callable[[], dict]) -> Callable[[], dict]:
    """A value built on first use and kept."""
    built: list[dict] = []

    def get() -> dict:
        if not built:
            built.append(build())
        return built[0]

    return get


def _settle_untracked(
    status: str,
    name: str,
    zf: zipfile.ZipFile,
    by_md5: dict,
    held_inside: Callable[[], dict],
    errors: list[str],
    file_name: str,
) -> tuple[str, str]:
    """Status of a member no hash recognised, and the name to record.

    An archive the builder assembled (a MAME clone set) passes when every
    member is a dump the collection holds, loose or inside a romset. Bytes
    nothing recognises were written wrong or come from a source that no
    longer matches: counted and passed, they went unseen.
    """
    if status != "untracked":
        return status, file_name
    if name.endswith(".zip") and _members_are_held(zf.read(name), by_md5, held_inside()):
        return "verified_members", os.path.basename(name)
    errors.append(f"{name}: content matches no collected file")
    return "untracked", file_name


def same_members(pack: zipfile.ZipFile, name: str, source: str) -> bool:
    """Whether a ZIP inside the pack holds the members of a ZIP on disk.

    A rebuilt archive (TorrentZip) differs byte for byte and is the same
    set when every member and its CRC agree. The two checks that ask it
    each carried their own copy.
    """
    try:
        held = {member.name: member.crc32 for member in zip_members(source)}
        with zipfile.ZipFile(io.BytesIO(pack.read(name))) as packed:
            return held == {
                info.filename: format(info.CRC, "08x")
                for info in packed.infolist() if not info.is_dir()
            }
    except (zipfile.BadZipFile, OSError):
        return False


def _data_indexes(data_registry: dict | None) -> tuple[dict[str, list[str]], dict[str, str]]:
    """The cached data directory files by name and by relative path."""
    _data_index: dict[str, list[str]] = {}
    _data_path_index: dict[str, str] = {}
    if data_registry:
        for _de in data_registry.values():
            cache = _de.get("local_cache", "")
            if not cache or not os.path.isdir(cache):
                continue
            for _r, _d, _fns in os.walk(cache):
                for _fn in _fns:
                    _fp = os.path.join(_r, _fn)
                    _rel = os.path.relpath(_fp, cache)
                    _data_path_index[_rel] = _fp
                    _data_index.setdefault(_fn, []).append(_fp)
    return _data_index, _data_path_index


def _member_digests(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> tuple[str, str, int]:
    """(sha1, md5, size) of a pack member."""
    with zf.open(info) as f:
        digests = stream_hashes(f, frozenset({"sha1", "md5"}))
    return digests["sha1"], digests["md5"], info.file_size


def _rebuilt_from(zf: zipfile.ZipFile, name: str, by_name: dict, files_db: dict) -> str | None:
    """The name of a held archive a rebuilt ZIP carries the members of."""
    _bn = os.path.basename(name)
    for _src_sha1 in by_name.get(_bn, []):
        if _src_sha1 not in files_db:
            continue
        _src_path = files_db[_src_sha1]["path"]
        if not os.path.exists(_src_path):
            continue
        if same_members(zf, name, _src_path):
            return _bn
    return None


def _cached_as(
    zf: zipfile.ZipFile,
    name: str,
    size: int,
    sha1: str,
    data_indexes: tuple[dict[str, list[str]], dict[str, str]],
) -> str | None:
    """The name of the data directory file a member is, or None."""
    _data_index, _data_path_index = data_indexes
    _bn = os.path.basename(name)
    _pr = name
    for _known_prefix in ("system/", "bios/", "BIOS/", "Firmware/"):
        if name.startswith(_known_prefix):
            _pr = name[len(_known_prefix):]
            break
    _cands = []
    if _pr in _data_path_index:
        _cands.append(_data_path_index[_pr])
    for _dp in _data_index.get(_bn, []):
        if _dp not in _cands:
            _cands.append(_dp)
    for _dp in _cands:
        if not os.path.exists(_dp):
            continue
        # The content, not the size: a member written corrupt
        # keeps its length, and a same-sized homonym from another
        # cache is another file.
        if os.path.getsize(_dp) == size and compute_hashes(_dp, frozenset({"sha1"}))["sha1"] == sha1:
            return _bn
        if (
            name.endswith(".zip") and _dp.endswith(".zip")
            and same_members(zf, name, _dp)
        ):
            return _bn
    return None


def verify_pack(
    zip_path: str, db: dict, data_registry: dict | None = None
) -> tuple[bool, dict]:
    """Verify a generated pack ZIP by re-hashing every file inside.

    Checks against database.json, data directory caches, and verifies
    rebuilt ZIP content by comparing inner CRC32s against source.
    Returns (all_ok, manifest_dict).
    """
    files_db = db.get("files", {})  # SHA1 -> file_info
    by_md5 = db.get("indexes", {}).get("by_md5", {})  # MD5 -> SHA1
    # Built on the first archive no hash recognises, once per pack: the
    # index opens every archive of the collection.
    held_inside = _once(lambda: build_zip_contents_index(db, collection_root(Path(BIOS_DIR))))
    by_name = db.get("indexes", {}).get("by_name", {})  # name -> [SHA1]

    # Data directory file index
    data_indexes = _data_indexes(data_registry)

    manifest: dict = {
        "schema_version": 1,
        "version": 1,
        "generator": "retrobios generate_pack.py",
        "generated": build_timestamp(db),
        "files": [],
    }
    errors: list[str] = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir() or is_pack_note(info.filename):
                continue
            name = info.filename
            sha1, md5, size = _member_digests(zf, info)

            # Look up in database: files_db keyed by SHA1
            db_entry = files_db.get(sha1)
            status = "verified"
            file_name = ""
            if db_entry:
                file_name = db_entry.get("name", "")
            else:
                # Try MD5 -> SHA1 lookup
                ref_sha1 = by_md5.get(md5)
                db_entry = files_db.get(ref_sha1) if ref_sha1 else None
                if db_entry:
                    file_name = db_entry.get("name", "")
                    status = "verified_md5"
                else:
                    status = "untracked"

            # Rebuilt ZIP: verify inner ROM CRC32s match source
            if status == "untracked" and name.endswith(".zip"):
                rebuilt = _rebuilt_from(zf, name, by_name, files_db)
                if rebuilt:
                    status = "verified_rebuild"
                    file_name = rebuilt

            # Data directory: check against cached files
            if status == "untracked" and data_indexes[0]:
                cached = _cached_as(zf, name, size, sha1, data_indexes)
                if cached:
                    status = "verified_data"
                    file_name = cached

            status, file_name = _settle_untracked(
                status, name, zf, by_md5, held_inside, errors, file_name
            )

            manifest["files"].append(
                {
                    "path": name,
                    "sha1": sha1,
                    "md5": md5,
                    "size": size,
                    "status": status,
                    "name": file_name,
                }
            )

            # Corruption check: SHA1 in DB but doesn't match what we computed
            # This should never happen (we looked up by SHA1), but catches
            # edge cases where by_md5 resolved to a different SHA1
            if db_entry and status == "verified_md5":
                expected_sha1 = db_entry.get("sha1", "")
                if expected_sha1 and expected_sha1.lower() != sha1.lower():
                    errors.append(
                        f"{name}: SHA1 mismatch (expected {expected_sha1}, got {sha1})"
                    )

    verified = sum(1 for f in manifest["files"] if f["status"].startswith("verified"))
    untracked = sum(1 for f in manifest["files"] if f["status"] == "untracked")
    total = len(manifest["files"])
    manifest["summary"] = {
        "total_files": total,
        "verified": verified,
        "untracked": untracked,
        "errors": len(errors),
    }
    manifest["errors"] = errors

    all_ok = len(errors) == 0
    return all_ok, manifest
