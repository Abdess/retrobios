"""Destinations a platform's own list declares twice, for two files.

One path holds one file, so on an install one of the two checks always
fails. RetroDECK declares bios/disk.rom for the PC-88 core and for XRoar,
with two md5 that name two different ROMs. slots.find_collisions finds
these. The export keeps both entries and names, beside each declaration,
the emulators whose profile reads the file it declares.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from resolve.archives import contents_members, holds_required_members
from resolve.standalone import platform_layouts, standalone_set
from resolve.cores import resolve_platform_cores
from core.hashing import declared_hash_lists, lists_hashes
from model.declarations import declared_components
from model.profiles import lists_files
from resolve.collisions import accepted_by_all, find_collisions
from resolve.content import size_fits
from resolve.validation import opens_by_name, outside_gap_scope


def _names(entry: dict) -> set[str]:
    """The file names a profile entry is opened under."""
    names = {entry.get("name"), *(entry.get("aliases") or [])}
    for key in ("path", "standalone_path"):
        if entry.get(key):
            names.add(str(entry[key]).rsplit("/", 1)[-1])
    return {str(n).casefold() for n in names if n}


def _size_fits(entry: dict, local: str) -> bool:
    """Whether the file's size is one the entry states, or none is stated."""
    try:
        size = os.path.getsize(local)
    except OSError:
        return False
    return size_fits(entry, size)


def _reads(entry: dict, by_name: bool, local: str, db: dict) -> bool:
    """Whether a profile entry describes the file at local.

    An archive is read by its members, a dump by its hashes. A name the code
    opens with no hash to check is read by any copy of a size it accepts. A
    name that is only a label (a core identifying files by content) reads
    nothing by name.
    """
    if entry.get("contents"):
        return holds_required_members(local, contents_members(entry))
    if lists_hashes(entry):
        return accepted_by_all(local, [entry], db)
    return by_name and _size_fits(entry, local)


def doubled_destinations(
    scraped: dict | None,
    profiles: dict[str, dict],
    db: dict,
    zip_contents: dict | None = None,
    data_registry: dict | None = None,
) -> list[dict]:
    """Each destination the platform declares twice for two files.

    Every declaration is listed with its system, component, hashes and the
    file it resolves to, and the emulators the platform runs whose profile
    reads that file there, with the profile's source_ref. Nothing is
    removed from the platform's file.
    """
    if not scraped:
        return []
    collisions = find_collisions(scraped, db, zip_contents, data_registry)
    if not collisions:
        return []
    standalone = standalone_set(scraped, profiles)
    named: dict[str, list[tuple[str, dict, dict, bool]]] = {}
    for key in sorted(resolve_platform_cores(scraped, profiles)):
        profile = profiles[key]
        if not lists_files(profile):
            continue
        for layout, is_standalone in platform_layouts(key, profile, standalone):
            for entry in layout.get("files") or []:
                if not isinstance(entry, dict) or outside_gap_scope(entry, is_standalone):
                    continue
                by_name = opens_by_name(entry, layout, is_standalone)
                for name in _names(entry):
                    named.setdefault(name, []).append((key, layout, entry, by_name))

    doubled = []
    for collision in collisions:
        base = collision.destination.rsplit("/", 1)[-1].casefold()
        declarations = []
        for entry, local in collision.declarations:
            readers: list[dict] = []
            for key, layout, profile_entry, by_name in named.get(base, []):
                if not local or not _reads(profile_entry, by_name, local, db):
                    continue
                reader = {
                    "emulator": layout.get("emulator") or key,
                    "profile": key,
                    "entry": profile_entry.get("name", ""),
                    "source_ref": profile_entry.get("source_ref", ""),
                }
                if reader not in readers:
                    readers.append(reader)
            declarations.append({
                "system": entry.get("native_system") or "",
                "component": ", ".join(declared_components(entry.get("component"))),
                "name": entry.get("name", ""),
                "hashes": declared_hash_lists(entry),
                "file": local,
                "readers": readers,
            })
        doubled.append({
            "destination": collision.destination,
            "declarations": declarations,
        })
    return doubled
