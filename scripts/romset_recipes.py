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
``recipes/archives.json`` (scripts/recipes/):

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
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.cli import require_directory
from core.torrentzip import zlib_ng_version
from model.database import load_database
from model.profiles import load_emulator_profiles
from recipes.build import AtomIndex, build_archive, select
from recipes.capture import ZlibNgError, capture, container_pins, recipe_index
from recipes.identify import identify_report, missing_report, write_reconstructions
from recipes.ledger import ARCHIVES_FILE, load_ledger, write_ledger
from recipes.pool import AtomPool, DIGEST_CACHE
from recipes.romsets import collect_recipes, load_dat_recipes, merge_recipes


def print_missing(gap: dict) -> None:
    """The pinned archives the collection lacks, each one named."""
    print(
        f"\nPinned archives not held: "
        f"{len(gap['constructible'])} buildable, "
        f"{len(gap['unreproducible'])} not reproducible, "
        f"{len(gap['no_recipe'])} without a recipe"
    )
    for record in gap["constructible"]:
        print(
            f"  BUILDABLE: {record['archive']} md5={record['md5'][:8]} "
            f"via {record['recipe']} ({record['size']} bytes)"
        )
    # The acquisition targets: an archive pinned under several md5s is
    # one line, the platforms' own bundles rather than romsets.
    by_archive: dict[str, list[str]] = defaultdict(list)
    for record in gap["unreproducible"]:
        by_archive[record["archive"]].append(record["md5"][:8])
    for archive, md5s in sorted(by_archive.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f"  NOT REPRODUCIBLE: {archive} ({len(md5s)} pinned: {', '.join(sorted(md5s))})")
    for record in gap["no_recipe"]:
        print(f"  NO RECIPE: {record['archive']} md5={record['md5'][:8]}")


def run_capture(args: argparse.Namespace, db: dict) -> int:
    """Write recipes/archives.json for every archive the database lists."""
    try:
        records, failed = capture(
            db,
            load_ledger(Path(args.archives)),
            recipe_index(args.emulators_dir, args.dat_recipes),
            container_pins(args.platforms_dir, args.emulators_dir),
        )
    except ZlibNgError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    for path, reason in sorted(failed.items()):
        print(f"  UNREADABLE: {path}: {reason}", file=sys.stderr)
    changed = write_ledger(records, Path(args.archives))
    by_class: dict[str, int] = defaultdict(int)
    for record in records.values():
        by_class[record["rebuild"]] += 1
    agreed = sum(1 for record in records.values() if len(record["sources"]) > 1)
    pinned = sum(1 for record in records.values() if record.get("bytes_pinned"))
    print(
        f"{len(records)} archive recipes: {by_class['exact']} exact, "
        f"{by_class['canonical']} canonical; {agreed} agree with a profile or DAT "
        f"recipe, {pinned} pinned as bytes"
    )
    print(f"{'Wrote' if changed else 'Unchanged'} {args.archives}")
    return 1 if failed else 0


def run_build(args: argparse.Namespace, db: dict) -> int:
    """Build one archive, or all of them, from the members the collection holds."""
    if not args.output_dir:
        print("ERROR: --build and --build-all need --output-dir", file=sys.stderr)
        return 2
    ledger = load_ledger(Path(args.archives))
    if args.build_all:
        records = [ledger[path] for path in sorted(ledger)]
    else:
        records = select(ledger, args.build)
        if not records:
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
    counts: dict[str, int] = defaultdict(int)
    own: list[tuple[str, int]] = []
    for record in records:
        result = build_archive(record, atoms, Path(args.output_dir), root)
        counts[result.status] += 1
        if result.own_members:
            own.append((result.path, result.own_members))
        if result.status == "impossible":
            for member in result.missing:
                print(
                    f"  IMPOSSIBLE: {result.path}: missing {member['name']} "
                    f"({member['sha1']})"
                )
        elif result.status == "failed":
            print(f"  FAILED: {result.path}: {result.detail}")
        else:
            note = f" ({result.detail})" if result.detail else ""
            print(f"  {result.status.upper()}: {result.path}{note}")
            if args.discard:
                Path(result.output).unlink()
    print(
        f"\n{len(records)} archives: {counts['exact']} rebuilt exact, "
        f"{counts['canonical']} canonical, {counts['impossible']} impossible, "
        f"{counts['failed']} failed"
    )
    print(
        f"  {len(own)} of them read {sum(n for _p, n in own)} members from their "
        "own archive, held nowhere else in the collection"
    )
    if counts["failed"]:
        print("ERROR: a build did not match its recipe and was not kept", file=sys.stderr)
        return 1
    return 1 if counts["impossible"] else 0


def _resolve_modes(args: argparse.Namespace) -> None:
    """Which reports run: both by default, and --missing whenever --write.

    The reconstructions --write saves are those of the missing pins: with
    --identify alone beside it, nothing ran them, nothing was written, and
    the run exited 0.
    """
    if args.write:
        args.missing = True
    if not args.identify and not args.missing:
        args.identify = args.missing = True


def print_identification(ident: dict) -> None:
    """Which recipe reproduces each local archive, counted by recipe."""
    print(
        f"\nIdentification: {len(ident['identified'])} archives reproduced "
        f"by a recipe, {len(ident['unidentified'])} unidentified"
    )
    print(
        "  The label is the oldest version producing these bytes: a recipe "
        "unchanged since 0.177 is counted there, not at its own version."
    )
    by_recipe: dict[str, int] = defaultdict(int)
    for record in ident["identified"]:
        by_recipe[record["recipe"]] += 1
    for label, count in sorted(by_recipe.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {label}: {count}")
    for record in ident["unidentified"][:10]:
        print(f"  UNIDENTIFIED: {record['path']}")


def main() -> int:
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
    parser.add_argument(
        "--bios-dir", default="bios",
        help="BIOS collection directory (default: %(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default="platforms",
        help="platform YAML directory (default: %(default)s)",
    )
    parser.add_argument(
        "--emulators-dir", default="emulators",
        help="emulator profile directory (default: %(default)s)",
    )
    parser.add_argument(
        "--db", default="database.json",
        help="database file to read (default: %(default)s)",
    )
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
    _resolve_modes(args)
    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    profile_recipes = collect_recipes(profiles)
    dat_recipes = load_dat_recipes(args.dat_recipes)
    recipes = merge_recipes(profile_recipes, dat_recipes)
    pool = AtomPool(Path(args.bios_dir), DIGEST_CACHE, db)

    result: dict = {
        "recipes": sum(len(v) for v in recipes.values()),
        "profile_recipes": sum(len(v) for v in profile_recipes.values()),
        "dat_recipes": sum(len(v) for v in dat_recipes.values()),
        "archives_with_recipes": len(recipes),
        "atoms": len(pool),
    }
    if pool.unreadable:
        result["unreadable_archives"] = pool.unreadable
    if args.identify:
        result["identify"] = identify_report(recipes, pool, db)
    if args.missing:
        result["missing"] = missing_report(recipes, pool, db, args.platforms_dir)
        if args.write:
            result["written"] = write_reconstructions(
                result["missing"]["constructible"], recipes, pool,
                Path(args.bios_dir), db,
            )

    pool.save_digests()

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    print(
        f"{result['archives_with_recipes']} archives described by "
        f"{result['recipes']} recipes "
        f"({result['profile_recipes']} from profiles, {result['dat_recipes']} from DATs), "
        f"{result['atoms']} ROM atoms available"
    )
    if not result["dat_recipes"]:
        print(
            "  No DAT recipe: import one with "
            "`python -m scripts.scraper.romset_dat_importer --source mame --fetch mame0289`"
        )
    for problem in result.get("unreadable_archives", []):
        print(f"  UNREADABLE: {problem}")

    if args.identify:
        print_identification(result["identify"])

    if args.missing:
        print_missing(result["missing"])
        for path in result.get("written", []):
            print(f"  WROTE: {path}")

    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
