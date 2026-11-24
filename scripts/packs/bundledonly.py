"""Collected files that only an emulator's own install provides."""

from __future__ import annotations

import json
from pathlib import Path

from core.hashing import compute_hashes
from model.platforms import load_platform_config
from model.registry import list_registered_platforms
from packs.consumers import FileConsumers
from resolve.directories import expand_directory_entries
from resolve.entryscope import installed_everywhere


def _entries(profile: dict, db: dict) -> list[dict]:
    files = [f for f in profile.get("files") or [] if isinstance(f, dict)]
    return expand_directory_entries(files, db, False) + [
        f for f in expand_directory_entries(files, db, True) if f not in files
    ]


def shipped_by_manifests(install_dir: Path) -> set[str]:
    """Every sha1 an install manifest places, alternatives included."""
    shipped: set[str] = set()
    for path in sorted(install_dir.glob("*.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        for entry in manifest.get("files") or []:
            shipped.add(str(entry.get("sha1") or ""))
            shipped.update(str(a.get("sha1") or "") for a in entry.get("alternatives") or [])
    return shipped - {""}


def bundled_only(db: dict, profiles: dict, platforms_dir: str, install_dir: Path) -> list[dict]:
    """Collected files a bundled entry resolves to and nothing else needs."""
    consumers = FileConsumers(db)
    needed: set[str] = set(shipped_by_manifests(install_dir))
    for name in list_registered_platforms(platforms_dir):
        config = load_platform_config(name, platforms_dir)
        for system in config.get("systems", {}).values():
            for entry in system.get("files", []):
                sha1 = consumers.sha1_of(entry, entry.get("destination", ""))
                if sha1:
                    needed.add(sha1)
    bundled: dict[str, set[str]] = {}
    for emulator, profile in profiles.items():
        if profile.get("type") == "alias":
            continue
        for entry in _entries(profile, db):
            sha1 = consumers.sha1_of(entry, entry.get("path") or "", owner=emulator)
            if not sha1:
                continue
            # A platform whose package leaves the file out (not_bundled_on:
            # AmberELEC's amiberry 7.1.1 has no AROS ROMs) brings it from
            # the collection.
            if installed_everywhere(entry):
                bundled.setdefault(sha1, set()).add(emulator)
            else:
                needed.add(sha1)
    files = db.get("files", {})
    rows = [
        {"sha1": sha1, "path": files[sha1]["path"], "size": files[sha1].get("size", 0),
         "emulators": sorted(emulators)}
        for sha1, emulators in sorted(bundled.items(), key=lambda kv: files[kv[0]]["path"])
        if sha1 not in needed and sha1 in files
    ]
    return rows + other_copies(rows, Path(db.get("bios_dir") or "bios"))


def other_copies(rows: list[dict], bios_dir: Path) -> list[dict]:
    """The same bytes under other paths of the collection.

    The database keeps one path per sha1, and the trees kept whole
    (NODEDUP: splitwolf's sprite directories, c64-emu's machine folders)
    hold the same file several times. Listing only the indexed path took
    five passes to empty splitwolf. A file is hashed only when its size is
    one a listed file has.
    """
    by_size: dict[int, dict[str, dict]] = {}
    for row in rows:
        by_size.setdefault(int(row["size"]), {})[row["sha1"]] = row
    listed = {row["path"] for row in rows}
    found = []
    for path in sorted(bios_dir.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.as_posix() in listed:
            continue
        same_size = by_size.get(path.stat().st_size)
        if not same_size:
            continue
        sha1 = compute_hashes(path, frozenset({"sha1"}))["sha1"]
        if sha1 in same_size:
            found.append({**same_size[sha1], "path": path.as_posix()})
    return found
