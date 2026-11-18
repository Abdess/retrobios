"""Destinations a platform declares twice and resolves to two different files."""

from __future__ import annotations

import os
import zlib
from dataclasses import dataclass, field

from core.hashing import compute_hashes, parse_md5_list
from core.ziptools import check_inside_zip
from resolve.localfile import resolve_local_file, variant_base_name
from resolve.packfiles import records_by_path, preferred_entries


def comparable_destination(destination: str, fold: bool = True) -> str:
    """Comparable form of a destination, since layers write it differently.

    Case is folded only where the platform's filesystem folds it: on Linux
    RetroDECK ships bios/DISK.ROM and bios/disk.rom side by side.
    """
    cleaned = destination.strip().strip("/").replace("\\", "/")
    return cleaned.casefold() if fold else cleaned


@dataclass
class Collision:
    """One destination a platform fills with two different files."""

    destination: str
    resolved: list[str]
    # Each declaration with the file it resolved to, in the platform's order.
    declarations: list[tuple[dict, str | None]] = field(default_factory=list)
    # The system of each declaration, in the same order.
    systems: list[str] = field(default_factory=list)
    # The file the pack ships at the destination, as the builder decides it.
    shipped: str | None = None


def find_collisions(
    config: dict,
    db: dict,
    zip_contents: dict | None = None,
    data_dir_registry: dict | None = None,
) -> list[Collision]:
    """Destinations a platform declares twice and resolves two ways.

    One path holds one file, so whichever declaration the builder reaches
    first decides in silence. Declaring an archive several times to name its
    inner ROMs is the documented zipped_file pattern and resolves to one
    archive. Two declarations landing on two files name two files for one
    path. RetroDECK aims a PC-88 disk subsystem ROM and a
    CoCo disk ROM at one bios/disk.rom.
    """
    fold = bool(config.get("case_insensitive_fs", False))
    systems = config.get("systems") or {}
    # The builder lets a hash-constrained declaration that resolves by
    # content take the path, else the first it reaches walking the systems
    # sorted: the same choice says which file ships.
    preferred = set(
        preferred_entries(systems, db, "bios", "", False, zip_contents, True).values()
    )
    by_dest: dict[str, list[tuple[str, dict]]] = {}
    for sys_id, system in systems.items():
        for entry in system.get("files") or []:
            if not isinstance(entry, dict):
                continue
            dest = entry.get("destination") or entry.get("name") or ""
            if dest:
                by_dest.setdefault(comparable_destination(dest, fold), []).append((sys_id, entry))

    collisions = []
    for key, claims in sorted(by_dest.items()):
        if len(claims) < 2:
            continue
        entries = [entry for _sys_id, entry in claims]
        resolved = []
        declarations = []
        for entry in entries:
            local, _ = resolve_local_file(
                entry,
                db,
                zip_contents,
                dest_hint=entry.get("destination", ""),
                data_dir_registry=data_dir_registry,
            )
            declarations.append((entry, local))
            if local and local not in resolved:
                resolved.append(local)
        if len(resolved) > 1 and not _same_file_family(resolved):
            # A file every declaration accepts settles the path: RetroDECK
            # declares ATARIOSB.ROM twice, the second with an md5 list that
            # also names the first one's file.
            if any(accepted_by_all(path, entries, db) for path in resolved):
                continue
            reached = sorted(
                (sys_id, local)
                for (sys_id, _entry), (_e, local) in zip(claims, declarations) if local
            )
            shipped = next(
                (local for entry, local in declarations if local and id(entry) in preferred),
                reached[0][1],
            )
            collisions.append(
                Collision(
                    destination=key,
                    resolved=resolved,
                    declarations=declarations,
                    systems=[sys_id for sys_id, _entry in claims],
                    shipped=shipped,
                )
            )
    return collisions


def lists_hashes(entry: dict) -> bool:
    """Whether a declaration says anything about content at all."""
    return any(
        _declared_hashes(entry, field_name)
        for field_name in ("md5", "sha1", "sha256", "crc32")
    )


def _declared_hashes(entry: dict, field_name: str) -> set[str]:
    """Hashes an entry accepts for one field, declared as a string or a list."""
    value = entry.get(field_name)
    values = value if isinstance(value, list) else [value]
    # Recalbox writes its md5 list comma separated, and profiles do the
    # same for sha256 (mesence names four BS-X dumps in one string).
    return {
        part.strip().lower()
        for v in values
        if v
        for part in str(v).split(",")
        if part.strip()
    }


def _record_at(path: str, db: dict) -> dict | None:
    """The database record stored at path, from an index built once per db.

    A scan of db['files'] on every call was O(calls x 19 000 files) on the
    path verify --all and slots.py both take. The index is the pack
    resolver's, so one run holds one copy of it.
    """
    return records_by_path(db).get(path)


def content_sha1(path: str, db: dict) -> str | None:
    """The sha1 of the file at path, from the database or read from disk.

    A data directory cache is not in the database, so its files are hashed.
    """
    record = _record_at(path, db)
    if record is not None:
        return record.get("sha1")
    if not os.path.isfile(path):
        return None
    return compute_hashes(path, frozenset({"sha1"}))["sha1"]


def accepted_by_all(path: str, entries: list[dict], db: dict) -> bool:
    """Whether every declaration's own hashes accept the file at path."""
    record = _record_at(path, db)
    if record is None:
        return False
    for entry in entries:
        if entry.get("zipped_file"):
            declared = parse_md5_list(entry.get("md5"))
            if declared and not any(
                check_inside_zip(path, entry["zipped_file"], m) == "ok" for m in declared
            ):
                return False
            continue
        for field_name in ("md5", "sha1", "sha256", "crc32"):
            declared = _declared_hashes(entry, field_name)
            if declared and str(record.get(field_name, "")).lower() not in declared:
                if field_name == "crc32" and _headerless_crc32(path, record, entry) in declared:
                    continue
                return False
    return True


COPIER_HEADER = 512


def _headerless_crc32(path: str, record: dict, entry: dict) -> str | None:
    """The crc32 of a file past its 512-byte copier header, when the entry
    declares both the file's size and the size without the header.

    Geargrafx drops the header when the file is 512 bytes over the expected
    size and computes the crc32 on the rest (src/media.cpp:754-773). The
    profile lists both sizes. EmuELEC's headered syscard3.pce (crc32
    64f78e3c) is the 6d9a73ef image the profile names.
    """
    sizes = entry.get("size")
    declared = sizes if isinstance(sizes, list) else [sizes]
    size = record.get("size")
    if not isinstance(size, int) or not {size, size - COPIER_HEADER} <= set(declared):
        return None
    try:
        with open(path, "rb") as f:
            f.seek(COPIER_HEADER)
            return f"{zlib.crc32(f.read()):08x}"
    except OSError:
        return None


def _same_file_family(paths: list[str]) -> bool:
    """Whether the paths are one file and its own pinned variants.

    A platform list built on an older romset pins bytes the primary no longer
    carries, which the repository keeps side by side under .variants. That is
    the documented multi-version case, not two machines fighting for a path.
    """
    canonical = set()
    for path in paths:
        if "/.variants/" in path:
            directory, _, name = path.rpartition("/")
            directory = directory[: -len("/.variants")]
            name = variant_base_name(name)
            path = f"{directory}/{name}"
        canonical.add(path.casefold())
    return len(canonical) == 1
