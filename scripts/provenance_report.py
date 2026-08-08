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
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import DEFAULT_PROVENANCE_DIR, load_database, load_provenance_snapshots


def build_report(db: dict, snapshots: dict) -> dict:
    """Compare each snapshot against the collection.

    A DAT counts as covered when the collection holds at least one of
    its entries. Missing entries from covered DATs are acquisition
    targets; missing entries from DATs the collection does not cover at
    all are out of scope and only counted. No-Intro tags every non-game
    dump "[BIOS]", including digital title distribution, so without this
    split the target list is swamped by content the project never ships.
    """
    by_sha1 = db.get("files", {})
    by_md5_size = {
        (entry.get("md5", ""), entry.get("size", 0)) for entry in by_sha1.values()
    }

    report = {}
    for source, snapshot in sorted(snapshots.items()):
        matched = 0
        covered_dats = set()
        unmatched = []
        for entry in snapshot["entries"]:
            if entry.get("sha1") in by_sha1 or (
                entry.get("md5"),
                entry.get("size"),
            ) in by_md5_size:
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

    report = build_report(db, snapshots)

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
