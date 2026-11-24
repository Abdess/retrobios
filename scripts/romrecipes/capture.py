"""Capture: a recipe record for every archive the database lists."""

from __future__ import annotations

import hashlib
import zipfile
from collections import defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from core.hashing import parse_hash_list
from core.torrentzip import has_torrentzip_comment, write_torrentzip, zlib_ng_version
from model.dbpaths import on_disk
from romrecipes.ledger import database_archives, load_ledger, write_ledger
from romrecipes.members import member_sha1, member_opener
from romrecipes.pins import container_entries
from romrecipes.romsets import collect_recipes, load_dat_recipes


# --- capture ----------------------------------------------------------------


class HashSink:
    """A write target that hashes what it receives, and keeps it if asked."""

    def __init__(self, handle: BinaryIO | None = None) -> None:
        self.handle = handle
        self.sha1 = hashlib.sha1()
        self.md5 = hashlib.md5()
        self.size = 0

    def write(self, data: bytes) -> int:
        self.sha1.update(data)
        self.md5.update(data)
        self.size += len(data)
        if self.handle is not None:
            self.handle.write(data)
        return len(data)


def _file_infos(path: Path) -> tuple[list[zipfile.ZipInfo], list[str], bool]:
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        torrentzip = has_torrentzip_comment(archive.comment)
    files = [info for info in infos if not info.is_dir()]
    directories = [info.filename for info in infos if info.is_dir()]
    return files, directories, torrentzip


def read_archive(path: Path, sha1: str) -> dict:
    """Members, directories and rebuild class of the archive at *path*.

    A TorrentZip archive is rebuilt from its own members: equal bytes make
    the recipe ``exact``. A mismatch is rebuilt once more before it is
    believed, because this host sometimes computes wrongly under load. Any
    other archive is ``canonical`` and only its members are read.
    """
    files, directories, torrentzip = _file_infos(path)
    rebuild = "canonical"
    by_name: dict[str, str] = {}
    if torrentzip:
        for _attempt in range(2):
            sink = HashSink()
            written = write_torrentzip(
                sink, [(info.filename, member_opener(path, info.filename)) for info in files]
            )
            by_name = {member.name: member.sha1 for member in written}
            if sink.sha1.hexdigest() == sha1:
                rebuild = "exact"
                break
    else:
        by_name = {info.filename: member_sha1(path, info.filename) for info in files}
    record: dict = {
        "rebuild": rebuild,
        "members": [
            {
                "name": info.filename,
                "size": info.file_size,
                "crc32": f"{info.CRC:08x}",
                "sha1": by_name[info.filename],
            }
            for info in files
        ],
    }
    if directories:
        record["directories"] = directories
    return record


def _read_job(job: tuple[str, str, Path]) -> tuple[str, dict | str]:
    path, sha1, root = job
    try:
        return path, read_archive(on_disk(root, path), sha1)
    except (OSError, zipfile.BadZipFile, UnicodeEncodeError) as exc:
        return path, f"{type(exc).__name__}: {exc}"


def container_pins(platforms_dir: str, emulators_dir: str) -> dict[str, set[str]]:
    """Container hash -> who pins it: ``platform:<name>`` or ``profile:<name>``."""
    from model.profiles import load_emulator_profiles

    pins: dict[str, set[str]] = defaultdict(set)
    for platform, entry in container_entries(platforms_dir):
        for key in ("md5", "sha1", "alt_md5"):
            for value in parse_hash_list(entry.get(key)):
                pins[value].add(f"platform:{platform}")
    for name, profile in load_emulator_profiles(emulators_dir, skip_aliases=False).items():
        for entry in profile.get("files", []) or []:
            for key in ("md5", "sha1", "sha256"):
                for value in parse_hash_list(entry.get(key)):
                    pins[value].add(f"profile:{name}")
    return dict(pins)


MemberList = tuple[tuple[str, str], ...]


def recipe_index(emulators_dir: str, recipes_dir: str) -> dict[MemberList, set[str]]:
    """Sorted (name, crc32) -> labels of the recipes with exactly those members.

    Matching on the member list, not the archive name, credits a DAT that
    knows the set under another name (``aga.zip`` is MAME's ``isa_aga``).
    """
    from model.profiles import load_emulator_profiles

    index: dict[MemberList, set[str]] = defaultdict(set)
    profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)
    for per_label in collect_recipes(profiles).values():
        for label, recipe in per_label.items():
            index[tuple(sorted(recipe))].add(f"profile:{label}")
    for per_label in load_dat_recipes(recipes_dir).values():
        for label, recipe in per_label.items():
            index[tuple(sorted(recipe))].add(label)
    return dict(index)


def member_key(members: Iterable[dict]) -> MemberList:
    return tuple(sorted((m["name"], m["crc32"]) for m in members))


def capture(
    db: dict,
    previous: dict[str, dict],
    index: dict[MemberList, set[str]],
    pins: dict[str, set[str]],
    root: Path,
    workers: int = 4,
    log: Callable[[str], None] = print,
) -> tuple[dict[str, dict], dict[str, str]]:
    """A record for every archive in *db*, read under *root*, and those that could not be read.

    A previous record whose sha1 still names the file is kept as read: the
    container bytes fix the members. Sources and pins are recomputed every
    time, since profiles, snapshots and platform lists move.
    """
    if zlib_ng_version():
        raise ZlibNgError(zlib_ng_version())
    archives = database_archives(db)
    reused: dict[str, dict] = {}
    jobs: list[tuple[str, str, Path]] = []
    for path, entry in sorted(archives.items()):
        old = previous.get(path)
        if old and old.get("sha1") == entry["sha1"] and old.get("members"):
            reused[path] = old
        else:
            jobs.append((path, entry["sha1"], root))
    read: dict[str, dict] = {}
    failed: dict[str, str] = {}
    if jobs:
        log(f"  reading {len(jobs)} archives ({len(reused)} unchanged)")
        with ProcessPoolExecutor(max_workers=workers) as pool:
            for path, result in pool.map(_read_job, jobs, chunksize=4):
                if isinstance(result, str):
                    failed[path] = result
                else:
                    read[path] = result
    records: dict[str, dict] = {}
    for path, entry in sorted(archives.items()):
        body = reused.get(path) or read.get(path)
        if body is None:
            continue
        record = {
            "path": path,
            "sha1": entry["sha1"],
            "md5": entry["md5"],
            "size": entry["size"],
            "rebuild": body["rebuild"],
            "members": body["members"],
        }
        if body.get("directories"):
            record["directories"] = body["directories"]
        record["sources"] = sorted(index.get(member_key(body["members"]), set())) + [
            "collection"
        ]
        pinned = set()
        for value in (entry["md5"], entry["sha1"], entry.get("sha256", "")):
            pinned |= pins.get(str(value).lower(), set())
        if pinned:
            record["bytes_pinned"] = True
            record["pins"] = sorted(pinned)
        records[path] = record
    return records, failed


class ZlibNgError(RuntimeError):
    def __init__(self, version: str | None) -> None:
        super().__init__(
            f"this Python deflates with zlib-ng {version}: TorrentZip bytes are "
            "stock zlib's level-9 output, so an exact rebuild cannot be proven "
            "or claimed here. Run under a Python linked against stock zlib."
        )


@dataclass
class CaptureRun:
    """The records a capture wrote, the archives it could not read, and whether the file changed."""

    records: dict[str, dict]
    failed: dict[str, str]
    changed: bool

    def counts(self) -> dict[str, int]:
        """Records by rebuild class, those agreeing with another recipe, those pinned as bytes."""
        by_class: dict[str, int] = defaultdict(int)
        for record in self.records.values():
            by_class[record["rebuild"]] += 1
        return {
            "exact": by_class["exact"],
            "canonical": by_class["canonical"],
            "agreed": sum(1 for record in self.records.values() if len(record["sources"]) > 1),
            "pinned": sum(1 for record in self.records.values() if record.get("bytes_pinned")),
        }


def capture_ledger(
    archives: Path,
    db: dict,
    root: Path,
    emulators_dir: str,
    dat_recipes: str,
    platforms_dir: str,
) -> CaptureRun:
    """Capture every archive of *db* under *root* against the ledger at *archives*, written back."""
    records, failed = capture(
        db,
        load_ledger(archives),
        recipe_index(emulators_dir, dat_recipes),
        container_pins(platforms_dir, emulators_dir),
        root,
    )
    return CaptureRun(records, failed, write_ledger(records, archives))
