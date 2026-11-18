"""Archive members an emulator reads, and the copies of an archive that hold them."""

from __future__ import annotations

import sys
from collections import Counter
from collections.abc import Callable

from core.ziptools import zip_member_crcs, zip_member_names


# id(files) -> (files, len(files), {archive: entries with a crc32}). Callers
# ask once per entry of the same profile: scanning the list each time walked
# 38 million entries in one verify --all over mame.yml. The list is held so
# its id is not reused, a list that changed length is indexed again, and the
# members are read from the entries at each call. Short lists are scanned
# directly: a fresh default [] per call would only fill the cache.
_ARCHIVE_INDEX_MIN = 64
_archive_index: dict[int, tuple[list[dict], int, dict[str | None, list[dict]]]] = {}


def _member(f: dict) -> dict:
    member = {"crc32": str(f["crc32"]).lower(), "required": bool(f.get("required", True))}
    if f.get("group"):
        # One of the members sharing it is enough (alternatives.py).
        member["group"] = f["group"]
    return member


def _required_met(members: list[dict], held: Callable[[dict], bool]) -> tuple[int, bool]:
    """How many requirements an archive meets, and whether it meets all.

    A required member is one requirement, and so is a required set of
    alternatives, met when one of its members is held: Odin reads the
    first of three Hikaru boot ROMs it finds in hikaru.zip.
    """
    from model.alternatives import groups_of

    met = 0
    complete = True
    sets: dict[str, bool] = {}
    for m in members:
        if not m["required"]:
            continue
        names = groups_of(m)
        if names:
            for name in names:
                sets[name] = sets.get(name, False) or held(m)
            continue
        if held(m):
            met += 1
        else:
            complete = False
    met += sum(sets.values())
    return met, complete and all(sets.values())


def archive_members(archive: str, files: list[dict]) -> list[dict]:
    """The members a profile reads inside *archive*, with what it requires."""
    if len(files) < _ARCHIVE_INDEX_MIN:
        return [_member(f) for f in files if f.get("archive") == archive and f.get("crc32")]
    cached = _archive_index.get(id(files))
    if cached is None or cached[0] is not files or cached[1] != len(files):
        index: dict[str | None, list[dict]] = {}
        for f in files:
            if f.get("crc32"):
                index.setdefault(f.get("archive"), []).append(f)
        cached = _archive_index[id(files)] = (files, len(files), index)
    return [_member(f) for f in cached[2].get(archive, ())]


def archive_entry(archive: str, files: list[dict]) -> dict:
    """The entry a profile's archive resolves through.

    Its own declaration when it has one (it carries the container's hashes),
    and the members it reads inside, so a copy of the name that lacks a ROM
    the core requires is not taken for the archive.
    """
    own = next(
        (f for f in files if f.get("name") == archive and not f.get("archive")),
        {"name": archive},
    )
    members = archive_members(archive, files)
    return {**own, "members": members} if members else own


def archive_is_optional(entry: dict, archive: str, files: list[dict]) -> bool:
    """Optional as a whole: its own entry and every member it carries.

    A --required-only pack leaves it out, and the report of that pack too.
    geolith's _Required pack held neocd.zip and irrmaze.zip all the same.
    """
    return entry.get("required") is False and all(
        member.get("required") is False
        for member in files
        if member.get("archive") == archive
    )


def holds_required_members(path: str, members: list[dict]) -> bool:
    """Whether an archive holds every member a profile requires inside it."""
    crcs = zip_member_crcs(path)
    names = zip_member_names(path)
    return _required_met(members, lambda m: _member_held(m, crcs, names))[1]


def contents_members(file_entry: dict) -> list[dict]:
    """The members an archive entry's ``contents:`` lists, as ranking keys.

    A member is its crc32 where the profile declares one, its name where the
    code opens it by name alone: Flycast reads epr-21329.ic27 in
    hod2bios.zip by filename, and a copy without it has no Japan BIOS.
    A crc32 two members share also keeps the name: fpr23905.ic36 and
    fpr23905c.ic36 both have crc32 ffffffff in segadimm.zip, so the crc
    alone cannot tell a copy holding one from a copy holding both.
    """
    listed = [m for m in file_entry.get("contents") or [] if m.get("crc32") or m.get("name")]
    seen = Counter(str(m["crc32"]).lower() for m in listed if m.get("crc32"))
    members = []
    for m in listed:
        if not m.get("crc32"):
            members.append({"name": str(m["name"]), "required": True})
            continue
        crc = str(m["crc32"]).lower()
        member = {"crc32": crc, "required": True}
        if seen[crc] > 1 and m.get("name"):
            member["name"] = str(m["name"])
        members.append(member)
    return members


def _member_held(member: dict, crcs: frozenset[str], names: frozenset[str]) -> bool:
    named = member.get("name", "").rsplit("/", 1)[-1].casefold() in names
    if member.get("crc32"):
        return member["crc32"] in crcs and ("name" not in member or named)
    return named


def _holding_members(paths: list[str], members: list[dict]) -> list[str]:
    """The same-named archives holding the most required members, then the most members.

    FBNeo reads neocd.bin and 000-lo.lo inside neocdz.zip. The primary copy,
    a set without 000-lo.lo, won on the name while a variant held both.
    """
    def held(path: str) -> tuple[int, int]:
        crcs = zip_member_crcs(path)
        names = zip_member_names(path)
        found = {id(m) for m in members if _member_held(m, crcs, names)}
        return _required_met(members, lambda m: id(m) in found)[0], len(found)

    scores = {path: held(path) for path in paths}
    best = max(scores.values(), default=(0, 0))
    if best == (0, 0):
        # Not one declared member in any copy: the name is all that matches,
        # and galgames.zip holding only an assembler listing is not the set.
        return []
    return [path for path in paths if scores[path] == best]


def _covering_archives(paths: list[str]) -> list[str]:
    """Same-named archives, those holding every ROM each other copy holds.

    Without a declared layout, a primary that is a superset of the other
    primaries misses nothing any of them holds. Two copies that each hold a
    ROM the other lacks are different revisions, and nothing here can
    choose: the order is kept. Index order alone used to decide, and
    deleting an unrelated duplicate flipped which copy a core received.
    """
    # A variant is served only when no primary is, so the primaries are
    # the copies this choice is between. A copy in an emulator's own tree
    # (bios/Other/<emulator>/) is that emulator's file, not a revision of
    # the set: an entry no profile owns is not decided by it.
    pool = [
        path for path in paths
        if "/.variants/" not in path and not path.startswith("bios/Other/")
    ] or [path for path in paths if "/.variants/" not in path] or paths
    crcs = {path: zip_member_crcs(path) for path in pool}
    covering = [
        path for path in pool
        if crcs[path] and all(crcs[other] <= crcs[path] for other in pool)
    ]
    return covering + [path for path in paths if path not in covering]


_unreadable_archives: set[str] = set()


def _warn_unreadable_archive(path: str, exc: Exception) -> None:
    """Say once that an archive on disk cannot be read.

    Skipped in silence, a truncated ZIP came out as not_found or
    hash_mismatch, which reads as a missing dump instead of a broken one.
    """
    if path not in _unreadable_archives:
        _unreadable_archives.add(path)
        print(f"warning: unreadable archive {path}: {exc}", file=sys.stderr)
