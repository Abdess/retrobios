"""A recipe for every archive the collection holds, and the build that uses it.

The collection must be able to regenerate each archive it serves from the
ROMs it holds plus a committed recipe, without any copy of that archive
from elsewhere. ``recipes/archives.json`` is that recipe list: one record
per archive in ``database.json``, keyed by its path.

A record names the members in archive order, each with its size, crc32 and
sha1, and the container's sha1, md5 and size. ``rebuild`` says what the
build reproduces:

``exact``
    The archive is TorrentZip and ``build_torrentzip()`` over its members
    gives its bytes. Proven at capture by rebuilding it.
``canonical``
    Same members, other container bytes: the archive was written by another
    tool. The build writes the TorrentZip form and checks members only.

``sources`` lists the recipes that agree on the member list: profile
``contents:`` blocks and the MAME and FBNeo DAT snapshots under
``recipes/``, then ``collection``, the archive itself. A DAT is provenance,
never the only source. ``bytes_pinned`` marks an archive whose container
hash a platform or a profile pins, with each pin named.

The build reads each member by sha1: a loose file first, then a member of
another archive, then the archive's own copy, and verifies what it wrote
before moving it into place.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sys
import zipfile
from collections import defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

sys.path.insert(0, str(Path(__file__).resolve().parent))

from torrentzip import write_torrentzip, zlib_ng_version  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
ARCHIVES_FILE = REPO_ROOT / "recipes" / "archives.json"
# The writer contract: build_torrentzip's layout over stock zlib. A change to
# the layout is a new builder name and a new proof of every record.
BUILDER = "torrentzip-1"
_ARCHIVE_PATH = re.compile(r"\.zip(\.[0-9a-f]{8})?$", re.IGNORECASE)
_TORRENTZIP_COMMENT = b"TORRENTZIPPED-"


def is_archive_path(path: str) -> bool:
    """A ZIP by its name: ``x.zip`` or a ``.variants/`` copy ``x.zip.1a2b3c4d``."""
    return bool(_ARCHIVE_PATH.search(path))


def database_archives(db: dict) -> dict[str, dict]:
    """Path -> database entry, for every archive the database lists."""
    return {
        entry["path"]: entry
        for entry in (db.get("files") or {}).values()
        if is_archive_path(entry.get("path", ""))
    }


# --- the ledger file --------------------------------------------------------


def load_ledger(path: Path = ARCHIVES_FILE) -> dict[str, dict]:
    """Path -> record, from ``recipes/archives.json``, empty when absent."""
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    return {record["path"]: record for record in data.get("archives", [])}


def ledger_text(records: dict[str, dict]) -> str:
    """One record per line, so a diff names the archive that changed."""
    lines = [
        json.dumps(records[path], ensure_ascii=False, separators=(",", ":"))
        for path in sorted(records)
    ]
    body = ",\n".join(f"  {line}" for line in lines)
    return f'{{"builder": "{BUILDER}", "archives": [\n{body}\n]}}\n'


def write_ledger(records: dict[str, dict], path: Path = ARCHIVES_FILE) -> bool:
    from artifacts import write_if_changed  # noqa: PLC0415

    path.parent.mkdir(parents=True, exist_ok=True)
    return write_if_changed(str(path), ledger_text(records))


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


class _Member(io.RawIOBase):
    """One member of a ZIP, open for reading, closing the archive with it."""

    def __init__(self, archive: Path, name: str) -> None:
        super().__init__()
        self._zip = zipfile.ZipFile(archive)
        self._stream = self._zip.open(name)

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def close(self) -> None:
        if not self.closed:
            self._stream.close()
            self._zip.close()
        super().close()


def _opener(source: Path, member: str | None) -> Callable[[], BinaryIO]:
    if member is None:
        return lambda: source.open("rb")
    return lambda: _Member(source, member)


def _file_infos(path: Path) -> tuple[list[zipfile.ZipInfo], list[str], bool]:
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        torrentzip = archive.comment.startswith(_TORRENTZIP_COMMENT)
    files = [info for info in infos if not info.is_dir()]
    directories = [info.filename for info in infos if info.is_dir()]
    return files, directories, torrentzip


def _member_sha1(path: Path, name: str) -> str:
    digest = hashlib.sha1()
    with _Member(path, name) as stream:
        while chunk := stream.read(16 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


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
    from common import (  # noqa: PLC0415
        list_registered_platforms,
        load_emulator_profiles,
        load_platform_config,
    )

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
    from common import load_emulator_profiles  # noqa: PLC0415
    from romset_recipes import collect_recipes, load_dat_recipes  # noqa: PLC0415

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


# --- build ------------------------------------------------------------------


@dataclass
class Source:
    path: Path
    member: str | None  # None for a loose file


@dataclass
class AtomIndex:
    """Where each member sha1 can be read in the collection."""

    loose: dict[str, Path] = field(default_factory=dict)
    inside: dict[str, list[tuple[Path, str]]] = field(default_factory=dict)

    @classmethod
    def from_collection(cls, ledger: dict[str, dict], db: dict, root: Path) -> AtomIndex:
        index = cls()
        for entry in (db.get("files") or {}).values():
            path = root / entry.get("path", "")
            if not is_archive_path(entry.get("path", "")) and path.is_file():
                index.loose.setdefault(entry["sha1"], path)
        for archive, record in sorted(ledger.items()):
            path = root / archive
            if not path.is_file():
                continue
            for member in record.get("members", []):
                index.inside.setdefault(member["sha1"], []).append((path, member["name"]))
        return index

    def find(self, sha1: str, own: Path) -> Source | None:
        """A loose copy first, then another archive, then the archive itself."""
        if sha1 in self.loose:
            return Source(self.loose[sha1], None)
        holders = self.inside.get(sha1, [])
        for path, member in holders:
            if path != own:
                return Source(path, member)
        for path, member in holders:
            return Source(path, member)
        return None

    def held(self, sha1: str) -> bool:
        return sha1 in self.loose or sha1 in self.inside


@dataclass
class BuildResult:
    path: str
    status: str  # exact, canonical, impossible, failed
    output: str = ""
    detail: str = ""
    missing: list[dict] = field(default_factory=list)
    own_members: int = 0


def _members_match(built: Path, members: list[dict]) -> str:
    """Empty when *built* holds exactly *members*, else what differs."""
    expected = sorted((m["name"], m["size"], m["crc32"], m["sha1"]) for m in members)
    with zipfile.ZipFile(built) as archive:
        names = [info.filename for info in archive.infolist() if not info.is_dir()]
        sizes = {info.filename: info.file_size for info in archive.infolist()}
        crcs = {info.filename: f"{info.CRC:08x}" for info in archive.infolist()}
    held = sorted(
        (name, sizes[name], crcs[name], _member_sha1(built, name)) for name in names
    )
    if held == expected:
        return ""
    missing = sorted(set(expected) - set(held))
    extra = sorted(set(held) - set(expected))
    return f"members differ: expected {missing[:3]}, built {extra[:3]}"


def _file_sha1(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as handle:
        while chunk := handle.read(16 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def destination(record_path: str, output_dir: Path) -> Path:
    """Where a build lands: the archive's path below ``bios/``, under *output_dir*."""
    parts = Path(record_path).parts
    relative = Path(*parts[1:]) if parts and parts[0] == "bios" else Path(record_path)
    return output_dir / relative


def build_archive(
    record: dict,
    atoms: AtomIndex,
    output_dir: Path,
    root: Path = REPO_ROOT,
    attempts: int = 2,
) -> BuildResult:
    """Build *record* from held members into *output_dir*, verified.

    The bytes are written to a scratch file beside the destination and read
    back from disk: an exact recipe must give its recorded sha1, a canonical
    one its members. A mismatch is built once more, then refused: nothing
    wrong is ever moved to the destination. Under zlib-ng an exact recipe is
    checked by its members only and never reported exact.
    """
    path = record["path"]
    own = root / path
    sources: list[tuple[str, Source]] = []
    missing: list[dict] = []
    for member in record["members"]:
        source = atoms.find(member["sha1"], own)
        if source is None:
            missing.append(member)
        else:
            sources.append((member["name"], source))
    if missing:
        return BuildResult(path, "impossible", missing=missing)
    own_members = sum(1 for _name, source in sources if source.path == own)
    ng = zlib_ng_version()
    exact = record["rebuild"] == "exact" and not ng
    target = destination(path, output_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    scratch = target.with_name(f".{target.name}.{os.getpid()}.part")
    detail = ""
    try:
        for _attempt in range(attempts):
            with scratch.open("wb") as handle:
                write_torrentzip(
                    handle,
                    [(name, _opener(source.path, source.member)) for name, source in sources],
                )
            if exact:
                written = _file_sha1(scratch)
                detail = "" if written == record["sha1"] else (
                    f"sha1 {written} is not the recorded {record['sha1']}"
                )
            else:
                detail = _members_match(scratch, record["members"])
            if not detail:
                os.replace(scratch, target)
                status = "exact" if exact else "canonical"
                note = (
                    f"zlib-ng {ng}: exact bytes not claimed, members verified"
                    if ng and record["rebuild"] == "exact" else ""
                )
                return BuildResult(path, status, str(target), note, own_members=own_members)
    finally:
        if scratch.exists():
            scratch.unlink()
    return BuildResult(path, "failed", detail=detail, own_members=own_members)


def select(ledger: dict[str, dict], wanted: str, root: Path = REPO_ROOT) -> list[dict]:
    """Records named by a path (relative or absolute) or by a file name."""
    candidate = Path(wanted)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve().relative_to(root.resolve())
        except ValueError:
            return []
    key = candidate.as_posix()
    if key in ledger:
        return [ledger[key]]
    return [record for path, record in sorted(ledger.items()) if Path(path).name == wanted]


def missing_members(ledger: dict[str, dict], db: dict) -> list[dict]:
    """Members held nowhere: neither as a loose file nor inside any archive.

    Read from the committed data alone, so it holds without the files: a
    member is held when database.json has its sha1 as a file, or when the
    recipe of an archive database.json lists carries it.
    """
    archives = database_archives(db)
    loose = {
        sha1 for sha1, entry in (db.get("files") or {}).items()
        if not is_archive_path(entry.get("path", ""))
    }
    inside = {
        member["sha1"]
        for path, record in ledger.items() if path in archives
        for member in record.get("members", [])
    }
    return [
        {"archive": path, "member": member["name"], "sha1": member["sha1"]}
        for path, record in sorted(ledger.items())
        for member in record.get("members", [])
        if member["sha1"] not in loose and member["sha1"] not in inside
    ]
