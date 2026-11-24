"""Profile entries as the probes read them: systems, destination, regions, category."""

from __future__ import annotations

import hashlib
from pathlib import Path

from model import measurements as mr
from probes.host import working_directory


def profile_digest(profile: dict) -> str:
    """What a check depends on in a profile: its entries, evidence left out,
    so the campaign's own evidence never makes it run again."""
    entries = [{k: v for k, v in entry.items() if k != "evidence"}
               for entry in profile.get("files") or []]
    body = {"files": entries, "cores": profile.get("cores"), "type": profile.get("type"),
            "systems": profile.get("systems")}
    return hashlib.sha1(mr.canonical(body)).hexdigest()


def held_file(entry: dict, db: dict, root: Path) -> Path | None:
    """The collection's copy of an entry in the checkout at root, by its
    declared hashes or its name."""
    from resolve.localfile import resolve_local_file

    hint = entry.get("path") if isinstance(entry.get("path"), str) else ""
    # The database names files relative to the checkout it describes.
    with working_directory(root):
        path, status = resolve_local_file(entry, db, dest_hint=hint or "")
    if not path or status in ("not_found", "hash_mismatch"):
        return None
    local = Path(path)
    local = local if local.is_absolute() else root / local
    return local if local.is_file() else None


def held_variants(entry: dict, db: dict, root: Path, primary: Path) -> list[Path]:
    """The .variants/ copies standing in for the primary held_file chose, in
    the checkout at root."""
    from resolve.lookup import variant_copies

    hint = entry.get("path") if isinstance(entry.get("path"), str) else ""
    stored = primary.relative_to(root) if primary.is_relative_to(root) else primary
    with working_directory(root):
        paths = variant_copies(entry, db, str(stored), dest_hint=hint or "")
    return [path if path.is_absolute() else root / path for path in map(Path, paths)]


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
