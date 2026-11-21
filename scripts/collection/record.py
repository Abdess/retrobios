"""The database.json record: its fields, the sha1s a rebuild retires, and its write."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from core.artifacts import write_if_changed
from model import retired


def database_record(files: dict, indexes: dict, bios_dir: str) -> dict:
    """The database over the scanned files, stamped with the time of the build."""
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_files": len(files),
        "total_size": sum(entry["size"] for entry in files.values()),
        # The tree these paths belong to: dedup writes _mame_clones.json
        # beside it, and the resolver reads the map there, not at the repo root.
        "bios_dir": os.path.normpath(bios_dir),
        "files": files,
        "indexes": indexes,
    }


def record_retired(output: Path, database: dict) -> int:
    """Record beside the database the sha1s the rebuild drops from the one at output.

    A sha1 the rebuild drops keeps its published address: the record
    beside the database says when it left and what holds its place.
    """
    if not output.is_file():
        return 0
    previous = json.loads(output.read_text(encoding="utf-8"))
    return retired.update(
        retired.retired_path(output), previous, database,
        database["generated_at"][:10],
    )


def write_database(output: str, database: dict) -> bool:
    """Write the database unless only its timestamp moved, and say whether it was."""
    return write_if_changed(output, json.dumps(database, indent=2))
