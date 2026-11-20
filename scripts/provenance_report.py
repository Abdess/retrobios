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

A missing dump that is a file an emulator profile reads and the collection
lacks is named with that profile: by hash when the profile declares one, by
name and size when it declares a size and no hash.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from core.cli import add_repo_inputs
from model.dumpcatalog import DEFAULT_PROVENANCE_DIR, load_provenance_snapshots
from model.database import load_database
from model.profiles import load_emulator_profiles
from core.artifacts import write_if_changed
from acquire.provenance import (
    archive_members,
    build_report,
    distinct_missing,
    dump_identity,
    profile_needs,
)


def _print_missing(entry: dict, derived: dict[str, dict]) -> None:
    """One missing dump, with what derives it, reads it and holds it."""
    label = entry.get("description") or entry["name"]
    source = derived.get(entry.get("sha1", ""))
    if source:
        print(f"    DERIVABLE {entry['name']} ({label}): {source['transform']} "
              f"of {' + '.join(source['from'])}")
    else:
        print(f"    MISSING {entry['name']} ({label}) sha1={entry.get('sha1')}")
    for need in entry.get("needed_by", []):
        print(f"      needed by {need['emulator']} as {need['name']} "
              f"({'required' if need['required'] else 'optional'}, "
              f"matched by {need['by']})")
    for hit in entry.get("romsets", []):
        versions = hit["dats"][0] if len(hit["dats"]) == 1 else (
            f"{hit['dats'][0]} to {hit['dats'][-1]}"
        )
        print(f"      in {hit['source']} {hit['archive']} as "
              f"{hit['member']} ({versions})")


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Dump-catalog coverage report")
    add_repo_inputs(parser, "db")
    parser.add_argument(
        "--provenance-dir",
        default=DEFAULT_PROVENANCE_DIR,
        help="Directory with dump-catalog snapshots",
    )
    parser.add_argument("--missing", action="store_true", help="List missing entries")
    parser.add_argument(
        "--derive",
        action="store_true",
        help="Find missing entries a held dump contains (halves, word splits, "
        "byte swaps, concatenations). Reads the collection, about 35 s",
    )
    parser.add_argument("--json", action="store_true", help="Full report as JSON")
    parser.add_argument(
        "--emulators-dir", default="emulators",
        help="profiles whose unheld files a missing dump answers (default: %(default)s)",
    )
    parser.add_argument(
        "--write-derivable",
        metavar="PATH",
        help="With --derive, record the derivable entries for the site "
        "(the pipeline writes derivable.json)",
    )
    args = parser.parse_args()
    from model.cliargs import work_from_repo_root

    work_from_repo_root(args, parser, ["db", "provenance_dir", "emulators_dir", "write_derivable"])
    if args.write_derivable and not args.derive:
        parser.error("--write-derivable records what --derive finds: pass both")

    db = load_database(args.db)
    snapshots = load_provenance_snapshots(args.provenance_dir)
    if not snapshots:
        print(f"No provenance snapshots in {args.provenance_dir}/")
        return 0

    needs = profile_needs(load_emulator_profiles(args.emulators_dir), db)
    report = build_report(db, snapshots, archive_members(db), needs=needs)
    derived: dict[str, dict] = {}
    if args.derive:
        from acquire.derivations import derivable

        derived = derivable((e for d in report.values() for e in d["missing"]), db)
        for data in report.values():
            data["derivable"] = {
                e["sha1"]: derived[e["sha1"]] for e in data["missing"]
                if e.get("sha1") in derived
            }
        if args.write_derivable:
            # The site cannot spend 80 s reading the collection on every
            # build: the pipeline records what this pass found, and the
            # Wanted page stops asking for dumps the collection can produce.
            write_if_changed(
                args.write_derivable,
                json.dumps(dict(sorted(derived.items())), indent=2, sort_keys=True) + "\n",
            )

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
            # A dump an emulator reads comes first: it fills a hole in a pack.
            for entry in sorted(data["missing"], key=lambda e: not e.get("needed_by")):
                _print_missing(entry, derived)

    total_missing = distinct_missing(report)
    if total_missing:
        line = f"  {total_missing} catalogued dumps missing from collection"
        if args.derive:
            line += f", {len(derived)} of them derivable from held dumps"
        print(line)
        needed = {
            dump_identity(e)
            for data in report.values() for e in data["missing"] if e.get("needed_by")
        }
        if needed:
            print(f"  {len(needed)} of them a profile reads and the collection lacks"
                  + ("" if args.missing else " (--missing names them)"))
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
