"""One database.json build: scan bios/, join aliases and provenance, write the record."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from collection.aliases import UnreadableSource, add_declared_aliases
from collection.declared import declarations
from collection.hashcache import CACHE_FILE, load_cache, save_cache
from collection.indexes import database_indexes
from collection.record import database_record, record_retired, write_database
from collection.releaseassets import preserve_large_file_entries
from collection.scan import scan_bios_dir
from model import retired
from model.dumpcatalog import annotate_provenance, load_provenance_snapshots


def generate(args: argparse.Namespace) -> int:
    """Scan bios/ and write the database, 1 when a declared source cannot be read."""
    bios_dir = Path(args.bios_dir)

    # A forced run rehashes every file but keeps the previous digests to
    # check the new ones against.
    cache = load_cache(CACHE_FILE)

    print(f"Scanning {bios_dir}/ ...")
    files, aliases, new_cache = scan_bios_dir(bios_dir, cache, args.force)

    if not files:
        print("Warning: No BIOS files found", file=sys.stderr)

    # Preserve entries for large files stored as release assets (.gitignore)
    preserved = preserve_large_file_entries(files, args.output)
    if preserved:
        print(f"  Preserved {preserved} large file entries from existing database")

    shadowed: list[tuple[str, set[str], list[str]]] = []
    try:
        add_declared_aliases(files, aliases, shadowed)
    except UnreadableSource as exc:
        for source in exc.sources:
            print(f"Error: cannot read {source}", file=sys.stderr)
        print(f"Error: {args.output} not written", file=sys.stderr)
        return 1

    snapshots = load_provenance_snapshots(args.provenance_dir)
    provenance_counts = annotate_provenance(files, snapshots)

    indexes = database_indexes(
        files, aliases, shadowed, declarations(Path("platforms"), Path("emulators"))
    )
    database = database_record(files, indexes, args.bios_dir)
    total_size = database["total_size"]

    output = Path(args.output)
    left = record_retired(output, database)
    if left:
        print(f"  Left the collection: {left} files, recorded in "
              f"{retired.retired_path(output)}")

    written = write_database(args.output, database)

    save_cache(CACHE_FILE, new_cache)

    alias_count = sum(len(v) for v in aliases.values())
    name_count = len(indexes["by_name"])
    status = "Generated" if written else "Unchanged"
    print(f"{status} {args.output}: {len(files)} files, {total_size:,} bytes total")
    print(f"  Name index: {name_count} names ({alias_count} aliases)")
    if provenance_counts:
        matched = sum(1 for e in files.values() if "provenance" in e)
        per_source = ", ".join(
            f"{source} {count}" for source, count in sorted(provenance_counts.items())
        )
        print(f"  Provenance: {matched} files catalog-matched ({per_source})")
    return 0

