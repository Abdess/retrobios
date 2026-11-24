"""The lookup a resolution runs on: the database indexes, record matching and the variant copies of a name."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from core.hashing import cut_md5_owner, parse_hash_list
from resolve.content import adler32_fits, content_fits, name_match_size_ok


_VARIANT_SUFFIX = re.compile(r"\.[0-9a-f]{8}$")


def variant_base_name(name: str) -> str:
    """The name a .variants/ copy stands in for: naomi2.zip.da79eca4 -> naomi2.zip.

    Only an eight-hex-digit suffix is a variant tag. A variant stored under
    its plain name (.variants/aes.zip) already is that name.
    """
    return _VARIANT_SUFFIX.sub("", name)


Resolution = tuple[str, str]


@dataclass(frozen=True)
class _Lookup:
    """One entry as resolve_local_file reads it: its names and declared hashes."""

    file_entry: dict
    db: dict
    dest_hint: str
    name: str
    zipped_file: str | None
    names_to_try: list[str]
    own_names: list[str]
    md5_list: list[str]
    sha1_candidates: list[str]
    sha256_candidates: list[str]
    crc_candidates: dict[str, None]
    declared_size: Any
    files_db: dict
    by_name: dict
    by_path_suffix: dict
    composite_only: bool

    @property
    def has_strong_hash(self) -> bool:
        return bool(
            self.sha1_candidates or self.sha256_candidates or self.md5_list or self.crc_candidates
        )


def _lookup_names(name: str, aliases: list, dest_hint: str) -> tuple[list[str], list[str]]:
    """The names an entry answers to, and the part of them that is its own."""
    names_to_try = [name] + [a for a in aliases if a != name]

    # When name contains a path separator (e.g. "res/tilemap.bin"), also
    # try the basename since by_name indexes filenames without directories
    if "/" in name:
        name_base = name.rsplit("/", 1)[-1]
        if name_base and name_base not in names_to_try:
            names_to_try.append(name_base)

    # When dest_hint contains a path, also try its basename as a name
    # (handles emulator profiles where name: is descriptive and path: is
    # the actual filename, e.g. name: "MDA font ROM", path: "mda.rom")
    own_names = list(names_to_try)
    if dest_hint:
        hint_base = dest_hint.rsplit("/", 1)[-1] if "/" in dest_hint else dest_hint
        if hint_base and hint_base not in names_to_try:
            names_to_try.append(hint_base)
    return names_to_try, own_names


def _lookup(
    file_entry: dict, db: dict, dest_hint: str, md5_list: list[str], *, composite_only: bool
) -> _Lookup:
    """Read the names and every declared hash of an entry once."""
    sha1 = file_entry.get("sha1")
    name = file_entry.get("name", "")
    names_to_try, own_names = _lookup_names(name, file_entry.get("aliases", []), dest_hint)
    sha1_candidates = [
        str(value).strip().lower()
        for value in (sha1 if isinstance(sha1, list) else [sha1] if sha1 else [])
        if str(value).strip()
    ]
    sha256_raw = file_entry.get("sha256")
    sha256_values = sha256_raw if isinstance(sha256_raw, list) else [sha256_raw]
    sha256_candidates = [
        candidate.strip().lower()
        for value in sha256_values
        if value
        for candidate in str(value).split(",")
        if len(candidate.strip()) == 64
    ]
    # One value, a list, or a comma-separated string, like the other hashes.
    crc_values = file_entry.get("crc32") or []
    # Kept in the order declared, which is the order a lookup tries them.
    crc_candidates = dict.fromkeys(
        candidate.strip().lower().removeprefix("0x")
        for value in (crc_values if isinstance(crc_values, list) else [crc_values])
        for candidate in str(value).split(",")
        if candidate.strip()
    )
    indexes = db.get("indexes", {})
    return _Lookup(
        file_entry=file_entry,
        db=db,
        dest_hint=dest_hint,
        name=name,
        zipped_file=file_entry.get("zipped_file"),
        names_to_try=names_to_try,
        own_names=own_names,
        md5_list=md5_list,
        sha1_candidates=sha1_candidates,
        sha256_candidates=sha256_candidates,
        crc_candidates=crc_candidates,
        declared_size=file_entry.get("size"),
        files_db=db.get("files", {}),
        by_name=indexes.get("by_name", {}),
        by_path_suffix=indexes.get("by_path_suffix", {}),
        composite_only=composite_only,
    )


def _record_match_status(q: _Lookup, match_sha1: str) -> str | None:
    """Return hash evidence when a DB record satisfies every declaration."""
    entry = q.files_db.get(match_sha1)
    if not entry:
        return None
    statuses: list[str] = []
    if q.sha1_candidates:
        if match_sha1.lower() not in q.sha1_candidates:
            return None
        statuses.append("sha1_exact")
    if q.sha256_candidates:
        if str(entry.get("sha256", "")).lower() not in q.sha256_candidates:
            return None
        statuses.append("sha256_exact")
    # With zipped_file the MD5 identifies the member, not the container.
    if q.md5_list and not q.zipped_file:
        actual_md5 = str(entry.get("md5", "")).lower()
        if actual_md5 not in q.md5_list:
            return None
        statuses.append("md5_exact")
    if q.crc_candidates:
        if str(entry.get("crc32", "")).lower() not in q.crc_candidates:
            return None
        if q.declared_size is not None:
            allowed_sizes = (
                q.declared_size if isinstance(q.declared_size, list) else [q.declared_size]
            )
            if entry.get("size") not in allowed_sizes:
                return None
        statuses.append("crc32_exact")
    return statuses[0] if statuses else None


def held_record_for(file_entry: dict, db: dict) -> str | None:
    """The sha1 of a record every declared hash agrees with, from the database.

    The resolver's hash steps without the disk check, for a caller asking
    whether the collection holds the content: sha1, sha256, md5 (a cut one
    standing for the held md5 it starts), then crc32 only without a stronger
    hash, bounded by the declared size.
    """
    indexes = db.get("indexes", {})
    by_md5 = indexes.get("by_md5", {})
    md5_list = [
        (cut_md5_owner(value, by_md5) or value) if len(value) < 32 else value
        for value in parse_hash_list(file_entry.get("md5"))
    ]
    q = _lookup(
        file_entry, db, "", md5_list,
        composite_only=file_entry.get("zip_digest") == "composite",
    )
    candidates = [
        *q.sha1_candidates,
        *(indexes.get("by_sha256", {}).get(v) for v in q.sha256_candidates),
    ]
    if not (q.zipped_file or q.composite_only):
        candidates += [by_md5.get(v) for v in md5_list]
    if not (q.sha1_candidates or q.sha256_candidates or q.md5_list or q.zipped_file):
        candidates += [indexes.get("by_crc32", {}).get(v) for v in q.crc_candidates]
    return next(
        (c for c in candidates if c and c in q.files_db and _record_match_status(q, c)),
        None,
    )


def variant_copies(
    file_entry: dict, db: dict, primary: str, dest_hint: str = ""
) -> list[str]:
    """The .variants/ copies that stand in for the primary an entry resolved to.

    A primary's alternates are filed in its own directory's .variants/ under
    its file name or one the entry answers to: the same name under another
    system (the PC-98 font.rom beside QUASI88's PC-88 one) is another file.
    A copy passes the shape the entry's code checks and, when the entry
    declares hashes, agrees with every one of them, as the resolver requires.
    """
    q = _lookup(
        file_entry, db, _entry_hint(file_entry, dest_hint), [
            (cut_md5_owner(value, db.get("indexes", {}).get("by_md5", {})) or value)
            if len(value) < 32 else value
            for value in parse_hash_list(file_entry.get("md5"))
        ],
        composite_only=file_entry.get("zip_digest") == "composite",
    )
    primary = os.path.normpath(primary)
    folder = os.path.dirname(primary)
    # A primary that is itself a .variants/ copy shares that directory.
    home = folder if os.path.basename(folder) == ".variants" else os.path.join(folder, ".variants")
    primary_name = variant_base_name(os.path.basename(primary))
    names = [primary_name, *(n for n in q.names_to_try if n != primary_name)]
    hashed = bool(
        q.sha1_candidates or q.sha256_candidates or q.crc_candidates
        or (q.md5_list and not q.zipped_file)
    )
    out: list[str] = []
    for name in names:
        for match_sha1 in q.by_name.get(name, ()):
            path = q.files_db.get(match_sha1, {}).get("path", "")
            if (
                os.path.dirname(os.path.normpath(path)) == home
                and os.path.normpath(path) != primary
                and variant_base_name(os.path.basename(path)) in names
                and (not hashed or _record_match_status(q, match_sha1))
                and _name_size_ok(q, match_sha1)
                and os.path.exists(path)
                and path not in out
            ):
                out.append(path)
    return out


def _name_size_ok(q: _Lookup, match_sha1: str) -> bool:
    """Whether a record found by name has the shape the entry's code checks."""
    record = q.files_db.get(match_sha1, {})
    return name_match_size_ok(q.file_entry, record.get("size")) and adler32_fits(
        q.file_entry, record.get("path", ""), q.db
    ) and content_fits(q.file_entry, record.get("path", ""))


def _entry_hint(file_entry: dict, dest_hint: str) -> str:
    """The destination tail the collection indexes the entry under."""
    # A platform that hands each core a system directory of its own (MinUI's
    # Bios/<TAG>/) writes that folder in front of the core's path. The tail
    # the collection indexes is the core's path alone.
    system_dir = file_entry.get("system_dir")
    if system_dir and dest_hint.startswith(f"{system_dir}/"):
        dest_hint = dest_hint[len(system_dir) + 1:]
    return dest_hint
