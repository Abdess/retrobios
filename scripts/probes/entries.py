"""Profile entries as the probes read them: systems, destination, regions, category."""

from __future__ import annotations

import hashlib

from model import measurements as mr


def profile_digest(profile: dict) -> str:
    """What a check depends on in a profile: its entries, evidence left out,
    so the campaign's own evidence never makes it run again."""
    entries = [{k: v for k, v in entry.items() if k != "evidence"}
               for entry in profile.get("files") or []]
    body = {"files": entries, "cores": profile.get("cores"), "type": profile.get("type"),
            "systems": profile.get("systems")}
    return hashlib.sha1(mr.canonical(body)).hexdigest()


def entry_systems(entry: dict, profile: dict) -> list[str]:
    if entry.get("systems"):
        return list(entry["systems"])
    if entry.get("system"):
        return [entry["system"]]
    return list(profile.get("systems") or [])


def entry_dest(entry: dict) -> str:
    """Where the core reads the entry, relative to its system directory."""
    path = entry.get("path")
    if isinstance(path, str) and path and not path.endswith("/"):
        return path
    return entry["name"]


def region_matches(entry: dict, region: str | None) -> bool:
    regions = entry.get("region")
    if not regions or not region:
        return True
    if isinstance(regions, str):
        regions = [regions]
    return region in regions or "world" in regions


def regions_of(entry: dict) -> list[str]:
    regions = entry.get("region") or []
    return [regions] if isinstance(regions, str) else list(regions)


def is_bios(entry: dict) -> bool:
    return entry.get("category", "bios") == "bios" and entry.get("type") != "directory"
