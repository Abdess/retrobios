#!/usr/bin/env python3
"""Files that left the collection, and the file that took their place.

A file's content address (files/?sha1=, #sha1-<12> on its card) is
published, and a published address never stops answering. When a rebuild
of database.json drops a sha1, the file it named is recorded here: its
name, its last path, its hashes, the day it left and the sha1 the
collection now holds at that path, or under that name in that folder.
The site's lookup reads the record and answers with it.

The record is append-only, written by generate_db.py beside the database.
A sha1 that comes back leaves it. `--backfill` rebuilds it from the
history of database.json since content addresses were published.

Usage:
    python scripts/retired_files.py --backfill
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from common import run_cli, write_if_changed  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
RETIRED_FILE = REPO_ROOT / "retired.json"
# The commit that published content addresses: 0d586ef6b, 2026-10-19.
FIRST_ADDRESSED = "0d586ef6b"
KEPT_FIELDS = ("name", "path", "size", "md5", "crc32", "sha256")


def retired_path(database: str | Path) -> Path:
    """The record kept beside a database file."""
    return Path(database).with_name("retired.json")


def _successor(entry: dict, by_path: dict[str, str],
               by_name: dict[str, list[tuple[str, str]]]) -> str | None:
    """The sha1 the new database holds at the entry's path, else under its
    name in the same folder, else the one file of that name: a2diskiing.zip
    was rebuilt from its recipe and filed under Apple II the same day."""
    path = str(entry.get("path", ""))
    if path in by_path:
        return by_path[path]
    named = by_name.get(str(entry.get("name", "")), [])
    folder = path.rsplit("/", 1)[0]
    beside = [sha1 for sha1, other in named if other.rsplit("/", 1)[0] == folder]
    for found in (beside, [sha1 for sha1, _other in named]):
        if len(found) == 1:
            return found[0]
    return None


def retired_between(old: dict, new: dict, day: str) -> dict[str, dict]:
    """sha1 -> record, for each file of *old* that *new* no longer holds."""
    old_files = old.get("files") or {}
    new_files = new.get("files") or {}
    by_path = {str(e.get("path", "")): sha1 for sha1, e in new_files.items()}
    by_name: dict[str, list[tuple[str, str]]] = {}
    for sha1, e in new_files.items():
        by_name.setdefault(str(e.get("name", "")), []).append((sha1, str(e.get("path", ""))))
    records = {}
    for sha1 in sorted(set(old_files) - set(new_files)):
        entry = old_files[sha1]
        record = {key: entry[key] for key in KEPT_FIELDS if entry.get(key) not in (None, "")}
        record["left"] = day
        successor = _successor(entry, by_path, by_name)
        if successor:
            record["successor"] = successor
        records[sha1] = record
    return records


def merge(record: dict[str, dict], left: dict[str, dict], new: dict) -> dict[str, dict]:
    """The record with *left* added, first departure kept, and every sha1
    the new database holds again taken out."""
    held = set(new.get("files") or {})
    merged = {sha1: entry for sha1, entry in record.items() if sha1 not in held}
    for sha1, entry in left.items():
        merged.setdefault(sha1, entry)
    return dict(sorted(merged.items()))


def load(path: Path) -> dict[str, dict]:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8")).get("files") or {}


def dump(records: dict[str, dict]) -> str:
    return json.dumps({"schema_version": 1, "files": records}, indent=1, sort_keys=True) + "\n"


def update(path: Path, old: dict, new: dict, day: str) -> int:
    """Records what *new* dropped from *old*. Returns how many left now."""
    left = retired_between(old, new, day)
    record = load(path)
    merged = merge(record, left, new)
    if merged != record:
        write_if_changed(str(path), dump(merged))
    return len(set(left) - set(record))


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True,
                          check=True).stdout


def backfill() -> dict[str, dict]:
    """Every sha1 that left database.json in the commits since content
    addresses were published, with the day of the commit that dropped it."""
    revisions = [line.split() for line in _git(
        "log", "--reverse", "--format=%H %cs", f"{FIRST_ADDRESSED}^..HEAD", "--", "database.json",
    ).splitlines() if line.strip()]
    records: dict[str, dict] = {}
    previous: dict | None = None
    for commit, day in revisions:
        current = json.loads(_git("show", f"{commit}:database.json"))
        if previous is not None:
            records = merge(records, retired_between(previous, current, day), current)
        previous = current
    return records


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n\n")[0])
    parser.add_argument("--backfill", action="store_true",
                        help="rebuild the record from the history of database.json")
    parser.add_argument("--output", default=str(RETIRED_FILE),
                        help="the record to write (default: retired.json)")
    args = parser.parse_args()
    if not args.backfill:
        parser.print_help()
        return 2
    records = backfill()
    current = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
    records = merge(records, {}, current)
    write_if_changed(args.output, dump(records))
    print(f"{len(records)} files left the collection since {FIRST_ADDRESSED}")
    return 0


if __name__ == "__main__":
    run_cli(main)
