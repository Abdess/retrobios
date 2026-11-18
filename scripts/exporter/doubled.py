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
from resolve.reconcile import HASH_FIELDS, _hash_values
from slots import _accepted_by_all, _lists_hashes, find_collisions
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
    declared = entry.get("size")
    sizes = declared if isinstance(declared, list) else [declared]
    sizes = [s for s in sizes if isinstance(s, int)]
    if sizes and size not in sizes:
        return False
    if isinstance(entry.get("min_size"), int) and size < entry["min_size"]:
        return False
    return not (isinstance(entry.get("max_size"), int) and size > entry["max_size"])


def _reads(entry: dict, by_name: bool, local: str, db: dict) -> bool:
    """Whether a profile entry describes the file at local.

    An archive is read by its members, a dump by its hashes. A name the code
    opens with no hash to check is read by any copy of a size it accepts. A
    name that is only a label (a core identifying files by content) reads
    nothing by name.
    """
    if entry.get("contents"):
        return holds_required_members(local, contents_members(entry))
    if _lists_hashes(entry):
        return _accepted_by_all(local, [entry], db)
    return by_name and _size_fits(entry, local)


def _hashes(entry: dict) -> dict[str, list[str]]:
    found = {f: _hash_values(entry, f) for f in HASH_FIELDS}
    return {f: values for f, values in found.items() if values}


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
    standalone = standalone_set(scraped)
    named: dict[str, list[tuple[str, dict, dict, bool]]] = {}
    for key in sorted(resolve_platform_cores(scraped, profiles)):
        profile = profiles[key]
        if profile.get("type") in ("launcher", "alias"):
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
                "component": entry.get("component") or "",
                "name": entry.get("name", ""),
                "hashes": _hashes(entry),
                "file": local,
                "readers": readers,
            })
        doubled.append({
            "destination": collision.destination,
            "declarations": declarations,
        })
    return doubled
