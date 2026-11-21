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

The command (`--backfill`) is scripts/retired_files.py.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.artifacts import write_if_changed
from core.paths import REPO_ROOT
from model.database import sha1_at


RETIRED_FILE = REPO_ROOT / "retired.json"
# The commit that published content addresses: 0d586ef6b, 2026-10-19.
FIRST_ADDRESSED = "0d586ef6b"
KEPT_FIELDS = ("name", "path", "size", "md5", "crc32", "sha256")


def retired_path(database: str | Path) -> Path:
    """The record kept beside a database file."""
    return Path(database).with_name("retired.json")


def _successor(entry: dict, new: dict,
               by_name: dict[str, list[tuple[str, str]]]) -> str | None:
    """The sha1 the new database holds at the entry's path, else under its
    name in the same folder, else the one file of that name: a2diskiing.zip
    was rebuilt from its recipe and filed under Apple II the same day."""
    path = str(entry.get("path", ""))
    held = sha1_at(new, path)
    if held:
        return held
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
    by_name: dict[str, list[tuple[str, str]]] = {}
    for sha1, e in new_files.items():
        by_name.setdefault(str(e.get("name", "")), []).append((sha1, str(e.get("path", ""))))
    records = {}
    for sha1 in sorted(set(old_files) - set(new_files)):
        entry = old_files[sha1]
        record = {key: entry[key] for key in KEPT_FIELDS if entry.get(key) not in (None, "")}
        record["left"] = day
        successor = _successor(entry, new, by_name)
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
