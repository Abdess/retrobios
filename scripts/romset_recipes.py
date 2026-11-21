#!/usr/bin/env python3
"""Identify and reconstruct arcade romset archives from their recipes.

A profile's ``contents:`` block is a recipe: the member names and CRC32s one
emulator version expects inside an archive. TorrentZip makes archive bytes a
function of that recipe alone, so a recipe plus the ROM bytes reproduces the
archive exactly.

Two questions follow, and this module answers both:

``--identify``
    Which version does an archive the collection holds correspond to? The
    recipe that rebuilds it byte for byte names it.

``--missing``
    A platform pins a container MD5 the collection does not have. If some
    recipe plus ROMs already present reproduces that MD5, the archive is
    constructible rather than absent.

Reconstruction is only possible when the pinned archive is itself TorrentZip.
An archive whose bytes carry metadata unrelated to its contents cannot be
derived from ROMs by anyone, and is reported as such rather than guessed at.

Every archive the collection holds also has a recipe of its own in
``recipes/archives.json`` (scripts/romrecipes/):

``--capture``
    Write a record for every archive in database.json: members in order with
    size, crc32 and sha1, container sha1, md5 and size, and whether the
    TorrentZip build reproduces the bytes (``exact``) or only the members
    (``canonical``). Archives already recorded under the same sha1 are not
    read again.

``--build NAME --output-dir DIR``
    Build an archive from the members the collection holds, loose or inside
    another archive, and verify it before moving it into place.

``--build-all --output-dir DIR``
    The same for every recorded archive, with one line per archive: exact,
    canonical, or impossible with the member nothing holds.
"""


from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.cli import add_repo_inputs, require_directory
from core.torrentzip import zlib_ng_version
from model.database import load_database
from romrecipes.build import AtomIndex, BuildTally, build_records, build_targets
from romrecipes.capture import ZlibNgError, capture_ledger
from romrecipes.ledger import ARCHIVES_FILE, load_ledger
from romrecipes.survey import survey, survey_modes
from romrecipes.text import print_build_result, print_build_totals, print_capture, print_survey


def run_capture(args: argparse.Namespace, db: dict) -> int:
    """Write recipes/archives.json for every archive the database lists."""
    try:
        run = capture_ledger(
            Path(args.archives), db, args.emulators_dir, args.dat_recipes, args.platforms_dir,
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
    records = build_targets(ledger, None if args.build_all else args.build)
    if not records and not args.build_all:
        print(f"ERROR: no archive recipe named {args.build}", file=sys.stderr)
        return 2
    ng = zlib_ng_version()
    if ng:
        print(
            f"  zlib-ng {ng} in use: TorrentZip bytes are stock zlib's output, so no "
            "build is claimed exact here; exact recipes are checked by their members"
        )
    root = Path(args.bios_dir).resolve().parent
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=__doc__.replace("``", ""),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--identify", action="store_true", help="label local archives")
    parser.add_argument(
        "--missing", action="store_true", help="attempt pinned archives we lack"
    )
    parser.add_argument(
        "--write", action="store_true",
        help="write reconstructions to .variants/ (implies --missing)",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    add_repo_inputs(parser, "bios", "platforms", "emulators", "db")
    parser.add_argument(
        "--dat-recipes",
        default="recipes",
        help="recipe snapshot file, or a directory of them",
    )
    parser.add_argument(
        "--archives", default=str(ARCHIVES_FILE),
        help="archive recipe file (default: recipes/archives.json)",
    )
    parser.add_argument(
        "--capture", action="store_true",
        help="write a recipe for every archive in the database",
    )
    build = parser.add_mutually_exclusive_group()
    build.add_argument("--build", metavar="ARCHIVE", help="build one archive, by path or name")
    build.add_argument("--build-all", action="store_true", help="build every recorded archive")
    parser.add_argument("--output-dir", help="where --build and --build-all write")
    parser.add_argument(
        "--discard", action="store_true",
        help="delete each build once verified: a full proof without the disk space",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    require_directory(args.bios_dir)
    if (args.output_dir or args.discard) and not (args.build or args.build_all):
        parser.error("--output-dir and --discard need --build or --build-all")
    if args.capture and (args.build or args.build_all):
        parser.error("--capture runs alone")

    db = load_database(args.db)
    if args.capture:
        return run_capture(args, db)
    if args.build or args.build_all:
        return run_build(args, db)
    args.identify, args.missing = survey_modes(args.identify, args.missing, args.write)
    result = survey(
        Path(args.bios_dir), args.emulators_dir, args.dat_recipes, args.platforms_dir, db,
        identify=args.identify, missing=args.missing, write=args.write,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    print_survey(result)
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
