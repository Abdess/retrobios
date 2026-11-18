"""Capture: a recipe record for every archive the database lists."""

from __future__ import annotations

import hashlib
import zipfile
from collections import defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import BinaryIO

from core.torrentzip import write_torrentzip, zlib_ng_version
from recipes.ledger import database_archives
from recipes.members import _member_sha1, _opener


_TORRENTZIP_COMMENT = b"TORRENTZIPPED-"


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
        torrentzip = archive.comment.startswith(_TORRENTZIP_COMMENT)
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
                sink, [(info.filename, _opener(path, info.filename)) for info in files]
            )
            by_name = {member.name: member.sha1 for member in written}
            if sink.sha1.hexdigest() == sha1:
                rebuild = "exact"
                break
    else:
        by_name = {info.filename: _member_sha1(path, info.filename) for info in files}
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


def _read_job(job: tuple[str, str]) -> tuple[str, dict | str]:
    path, sha1 = job
    try:
        return path, read_archive(Path(path), sha1)
    except (OSError, zipfile.BadZipFile, UnicodeEncodeError) as exc:
        return path, f"{type(exc).__name__}: {exc}"


def _hash_values(value: object) -> set[str]:
    raw = value if isinstance(value, list) else str(value or "").split(",")
    return {str(item).strip().lower() for item in raw if str(item).strip()}


def container_pins(platforms_dir: str, emulators_dir: str) -> dict[str, set[str]]:
    """Container hash -> who pins it: ``platform:<name>`` or ``profile:<name>``.

    A ``zipped_file`` entry pins a ROM inside the archive, and a Recalbox
    archive md5 is the composite of its members (``zip_digest: composite``,
    Bios.cpp:64-68): neither pins the container bytes.
    """
    from model.registry import list_registered_platforms
    from model.profiles import load_emulator_profiles
    from model.platforms import load_platform_config

    pins: dict[str, set[str]] = defaultdict(set)
    for platform in list_registered_platforms(platforms_dir):
        config = load_platform_config(platform, platforms_dir)
        for system in config.get("systems", {}).values():
            for entry in system.get("files", []) or []:
                if entry.get("zipped_file") or entry.get("zip_digest") == "composite":
                    continue
                for key in ("md5", "sha1", "alt_md5"):
                    for value in _hash_values(entry.get(key)):
                        pins[value].add(f"platform:{platform}")
    for name, profile in load_emulator_profiles(emulators_dir, skip_aliases=False).items():
        for entry in profile.get("files", []) or []:
            for key in ("md5", "sha1", "sha256"):
                for value in _hash_values(entry.get(key)):
                    pins[value].add(f"profile:{name}")
    return dict(pins)


MemberList = tuple[tuple[str, str], ...]


def recipe_index(emulators_dir: str, recipes_dir: str) -> dict[MemberList, set[str]]:
    """Sorted (name, crc32) -> labels of the recipes with exactly those members.

    Matching on the member list, not the archive name, credits a DAT that
    knows the set under another name (``aga.zip`` is MAME's ``isa_aga``).
    """
    from model.profiles import load_emulator_profiles
    from recipes.romsets import collect_recipes, load_dat_recipes

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
    workers: int = 4,
    log: Callable[[str], None] = print,
) -> tuple[dict[str, dict], dict[str, str]]:
    """A record for every archive in *db*, and the archives that could not be read.

    A previous record whose sha1 still names the file is kept as read: the
    container bytes fix the members. Sources and pins are recomputed every
    time, since profiles, snapshots and platform lists move.
    """
    if zlib_ng_version():
        raise ZlibNgError(zlib_ng_version())
    archives = database_archives(db)
    reused: dict[str, dict] = {}
    jobs: list[tuple[str, str]] = []
    for path, entry in sorted(archives.items()):
        old = previous.get(path)
        if old and old.get("sha1") == entry["sha1"] and old.get("members"):
            reused[path] = old
        else:
            jobs.append((path, entry["sha1"]))
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
