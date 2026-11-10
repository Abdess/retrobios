#!/usr/bin/env python3
"""Collected files that only an emulator's own install provides.

A file installed with the emulator is already on the user's machine, and the
packs leave it out. A copy in bios/ that nothing else asks for is then dead
weight: no platform declares it, no profile entry of any build needs it from
the collection, and no install manifest ships it. This lists those copies, so
they can be removed, and fails under --strict while one remains.

Usage:
    python scripts/bundled_only.py
    python scripts/bundled_only.py --strict
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from common import (
    compute_hashes,
    expand_directory_entries,
    list_registered_platforms,
    load_database,
    load_emulator_profiles,
    load_platform_config,
)
from cross_reference import FileConsumers


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
            if entry.get("bundled") and not entry.get("not_bundled_on"):
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


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    parser.add_argument("--db", default="database.json", help="database to read (default: %(default)s)")
    parser.add_argument("--emulators-dir", default="emulators", help="profiles (default: %(default)s)")
    parser.add_argument("--platforms-dir", default="platforms", help="platform lists (default: %(default)s)")
    parser.add_argument("--install-dir", default="install", type=Path,
                        help="install manifests, whose files are shipped (default: %(default)s)")
    parser.add_argument("--json", action="store_true", help="print the list as JSON")
    parser.add_argument("--strict", action="store_true", help="exit 1 while a file is listed")
    args = parser.parse_args()
    from common import work_from_repo_root  # noqa: PLC0415

    work_from_repo_root(args, parser, ["db", "emulators_dir", "platforms_dir", "install_dir"])

    rows = bundled_only(
        load_database(args.db), load_emulator_profiles(args.emulators_dir),
        args.platforms_dir, args.install_dir,
    )
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for row in rows:
            print(f"{row['path']}  ({', '.join(row['emulators'])})")
        total = sum(row["size"] for row in rows)
        print(f"{len(rows)} collected files only an emulator install provides, "
              f"{total / 1024**2:.1f} MB")
    return 1 if args.strict and rows else 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
