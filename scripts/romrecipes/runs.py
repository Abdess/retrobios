"""The --capture and --build runs of romset_recipes.py: their checks, output and exit codes."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from core.torrentzip import zlib_ng_version
from romrecipes.build import AtomIndex, BuildTally, build_records, build_targets
from romrecipes.capture import ZlibNgError, capture_ledger
from romrecipes.collection import collection_root
from romrecipes.ledger import load_ledger
from romrecipes.text import print_build_result, print_build_totals, print_capture


def run_capture(args: argparse.Namespace, db: dict) -> int:
    """Write recipes/archives.json for every archive the database lists."""
    try:
        run = capture_ledger(
            Path(args.archives), db, collection_root(Path(args.bios_dir)),
            args.emulators_dir, args.dat_recipes, args.platforms_dir,
        )
    except ZlibNgError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print_capture(run, args.archives)
    return 1 if run.failed else 0


def run_build(args: argparse.Namespace, db: dict) -> int:
    """Build one archive, or all of them, from the members the collection holds."""
    if not args.output_dir:
        print("ERROR: --build and --build-all need --output-dir", file=sys.stderr)
        return 2
    ledger = load_ledger(Path(args.archives))
    root = collection_root(Path(args.bios_dir))
    records = build_targets(ledger, None if args.build_all else args.build, root)
    if not records and not args.build_all:
        print(f"ERROR: no archive recipe named {args.build}", file=sys.stderr)
        return 2
    ng = zlib_ng_version()
    if ng:
        print(
            f"  zlib-ng {ng} in use: TorrentZip bytes are stock zlib's output, so no "
            "build is claimed exact here; exact recipes are checked by their members"
        )
    atoms = AtomIndex.from_collection(ledger, db, root)
    tally = BuildTally()
    for result in build_records(records, atoms, Path(args.output_dir), root, args.discard):
        tally.add(result)
        print_build_result(result)
    print_build_totals(tally, len(records))
    if tally.counts["failed"]:
        print("ERROR: a build did not match its recipe and was not kept", file=sys.stderr)
        return 1
    return 1 if tally.counts["impossible"] else 0
