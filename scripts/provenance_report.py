#!/usr/bin/env python3
"""Report dump-catalog coverage of the collection.

Reads provenance/*.json snapshots and database.json, then reports per
source how many catalog entries the collection holds and which are
missing. Missing entries are acquisition targets: catalog-verified
dumps the collection does not have yet.

Usage:
    python scripts/provenance_report.py
    python scripts/provenance_report.py --missing
    python scripts/provenance_report.py --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(__file__))
from common import DEFAULT_PROVENANCE_DIR, load_database, load_provenance_snapshots


def archive_members(db: dict) -> dict[tuple[str, int], list[tuple[str, str]]]:
    """(crc32, size) of every member of the collection's ZIPs -> (zip, member).

    Read from the central directories alone: a romset member is a dump the
    collection already holds, and listing it as an acquisition target sent
    searches after astrocdw.zip's bioswhit.bin and the Gamate BIOS.
    """
    members: dict[tuple[str, int], list[tuple[str, str]]] = {}
    for entry in db.get("files", {}).values():
        path = entry.get("path", "")
        if not path.endswith(".zip") or not os.path.exists(path):
            continue
        try:
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    key = (f"{info.CRC:08x}", info.file_size)
                    members.setdefault(key, []).append((path, info.filename))
        except (zipfile.BadZipFile, OSError) as exc:
            print(f"  WARNING: {path}: {exc}", file=sys.stderr)
    return members


def _held_in_archive(entry: dict, members: dict) -> bool:
    """Whether a catalog entry is a member of one of the collection's ZIPs.

    crc32 and size only nominate candidates; a declared sha1 must match the
    member's bytes.
    """
    crc = str(entry.get("crc32") or "").lower()
    size = entry.get("size")
    if not crc or size is None:
        return False
    candidates = members.get((crc.zfill(8), int(size)), [])
    sha1 = str(entry.get("sha1") or "").lower()
    if not sha1:
        return bool(candidates)
    for path, name in candidates:
        try:
            with zipfile.ZipFile(path) as archive:
                if hashlib.sha1(archive.read(name)).hexdigest() == sha1:
                    return True
        except (zipfile.BadZipFile, OSError, KeyError) as exc:
            print(f"  WARNING: {path}:{name}: {exc}", file=sys.stderr)
    return False


def build_report(db: dict, snapshots: dict, members: dict | None = None) -> dict:
    """Compare each snapshot against the collection.

    A DAT counts as covered when the collection holds at least one of
    its entries. Missing entries from covered DATs are acquisition
    targets; missing entries from DATs the collection does not cover at
    all are out of scope and only counted. No-Intro tags every non-game
    dump "[BIOS]", including digital title distribution, so without this
    split the target list is swamped by content the project never ships.
    """
    by_sha1 = db.get("files", {})
    members = members or {}
    by_md5_size = {
        (entry.get("md5", ""), entry.get("size", 0)) for entry in by_sha1.values()
    }

    report = {}
    for source, snapshot in sorted(snapshots.items()):
        matched = 0
        covered_dats = set()
        unmatched = []
        for entry in snapshot["entries"]:
            if (
                entry.get("sha1") in by_sha1
                or (entry.get("md5"), entry.get("size")) in by_md5_size
                or _held_in_archive(entry, members)
            ):
                matched += 1
                covered_dats.add(entry.get("dat", ""))
            else:
                unmatched.append(entry)
        missing = [e for e in unmatched if e.get("dat", "") in covered_dats]
        out_of_scope = len(unmatched) - len(missing)
        report[source] = {
            "imported_at": snapshot.get("imported_at", ""),
            "dats": snapshot.get("dats", {}),
            "total": len(snapshot["entries"]),
            "matched": matched,
            "covered_dats": sorted(covered_dats),
            "missing": missing,
            "out_of_scope": out_of_scope,
        }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Dump-catalog coverage report")
    parser.add_argument("--db", default="database.json", help="Database path")
    parser.add_argument(
        "--provenance-dir",
        default=DEFAULT_PROVENANCE_DIR,
        help="Directory with dump-catalog snapshots",
    )
    parser.add_argument("--missing", action="store_true", help="List missing entries")
    parser.add_argument("--json", action="store_true", help="Full report as JSON")
    args = parser.parse_args()

    db = load_database(args.db)
    snapshots = load_provenance_snapshots(args.provenance_dir)
    if not snapshots:
        print(f"No provenance snapshots in {args.provenance_dir}/")
        return 0

    report = build_report(db, snapshots, archive_members(db))

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    for source, data in report.items():
        in_scope = data["matched"] + len(data["missing"])
        pct = 100 * data["matched"] / in_scope if in_scope else 0
        print(
            f"  {source} ({data['imported_at']}): "
            f"{data['matched']}/{in_scope} in collection ({pct:.0f}%) "
            f"across {len(data['covered_dats'])} covered DATs"
        )
        if data["out_of_scope"]:
            print(
                f"    {data['out_of_scope']} entries in DATs the collection "
                f"does not cover, not counted as targets"
            )
        if args.missing:
            for entry in data["missing"]:
                label = entry.get("description") or entry["name"]
                print(f"    MISSING {entry['name']} ({label}) sha1={entry.get('sha1')}")

    total_missing = sum(len(d["missing"]) for d in report.values())
    if total_missing:
        print(f"  {total_missing} catalog entries missing from collection")
    return 0


if __name__ == "__main__":
    sys.exit(main())
