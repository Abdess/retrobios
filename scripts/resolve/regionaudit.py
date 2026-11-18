"""Profile region: values against the regions a dump catalogue gives the same file.

Advisory only: the emulator source decides what a region: value should be,
and a catalogue that disagrees is a second opinion, never a correction."""

from __future__ import annotations

import collections
import re

from model import region
from model.region import NOINTRO
from resolve.localfile import resolve_local_file


_PAREN = re.compile(r"\(([^)]+)\)")


def tokens_from_name(name: str) -> set[str]:
    """Extract geography slugs from a No-Intro style DAT entry name."""
    found: set[str] = set()
    for group in _PAREN.findall(name):
        for part in (p.strip() for p in group.split(",")):
            slug = NOINTRO.get(part)
            if slug:
                found.add(slug)
    return found


def catalog_regions(db: dict) -> dict[str, tuple[set[str], str]]:
    """Map SHA1 to (geography slugs, source label) from No-Intro provenance."""
    out: dict[str, tuple[set[str], str]] = {}
    for sha1, record in db["files"].items():
        entry = (record.get("provenance") or {}).get("no-intro")
        if not entry:
            continue
        name = entry.get("name", "")
        found = tokens_from_name(name)
        if found:
            out[sha1] = (found, name)
    return out


def resolve_sha1(file_entry: dict, db: dict, by_path: dict | None = None) -> str | None:
    """The repo SHA1 a profile entry resolves to, by the pack's own resolver.

    A private resolver read sha1, then md5, then a lone name: entries that
    identify their file by path (Dolphin's three IPL.bin), by crc32
    (geargrafx) or by sha256 (mednafen) were never checked at all.
    """
    if by_path is None:
        by_path = {entry.get("path", ""): sha1 for sha1, entry in db["files"].items()}
    path, status = resolve_local_file(
        file_entry, db, dest_hint=file_entry.get("path") or ""
    )
    if not path or status in ("not_found", "hash_mismatch"):
        return None
    return by_path.get(path)


def build_report(profiles: dict, db: dict) -> dict:
    """Compare every declared region: against the No-Intro catalogue."""
    catalog = catalog_regions(db)
    agree = 0
    unchecked = 0
    conflicts: list[dict] = []
    vocabulary: collections.Counter = collections.Counter()
    for slugs, _name in catalog.values():
        vocabulary.update(slugs)

    by_path = {entry.get("path", ""): sha1 for sha1, entry in db["files"].items()}
    for emu_name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias"):
            continue
        for f in profile.get("files") or []:
            if not isinstance(f, dict) or not f.get("region"):
                continue
            declared = region.normalize_declared(f["region"])
            sha1 = resolve_sha1(dict(f, source_profile=emu_name), db, by_path)
            if not sha1 or sha1 not in catalog:
                unchecked += 1
                continue
            found, name = catalog[sha1]
            if region.WORLD in declared or any(
                region.comparable(d, c) for d in declared for c in found
            ):
                agree += 1
                continue
            conflicts.append(
                {
                    "emulator": emu_name,
                    "file": f.get("name", ""),
                    "profile": sorted(declared),
                    "catalog": sorted(found),
                    "dat_name": name,
                }
            )
    return {
        "agree": agree,
        "disagree": len(conflicts),
        "unchecked": unchecked,
        "catalog_files": len(catalog),
        "repo_files": len(db["files"]),
        "vocabulary": dict(vocabulary.most_common()),
        "conflicts": conflicts,
    }
