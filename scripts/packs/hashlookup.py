"""The --from-md5 lookup report, printed for a person."""

from __future__ import annotations

from resolve.packfiles import HashLookup


def print_hash_lookup(records: list[HashLookup]) -> int:
    """Print each looked-up hash and return how many the database lacks."""
    for record in records:
        print(f"\n{record.kind.upper()}: {record.value}")
        if not record.found:
            print("  NOT FOUND in database")
            continue
        print(f"  SHA1: {record.sha1}")
        print(f"  MD5:  {record.md5}")
        print(f"  Name: {record.name}")
        if record.path:
            print(f"  Path: {record.path}")
        print(f"  In repo: {'YES' if record.in_repo else 'NO'}")
    missing = sum(not record.found for record in records)
    if missing:
        print(f"\n{missing} of {len(records)} hash(es) not in the database")
    return missing
