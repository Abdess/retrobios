"""A recipe for every archive the collection holds, and the build that uses it.

The collection must be able to regenerate each archive it serves from the
ROMs it holds plus a committed recipe, without any copy of that archive
from elsewhere. ``recipes/archives.json`` is that recipe list: one record
per archive in ``database.json``, keyed by its path.

A record names the members in archive order, each with its size, crc32 and
sha1, and the container's sha1, md5 and size. ``rebuild`` says what the
build reproduces:

``exact``
    The archive is TorrentZip and ``build_torrentzip()`` over its members
    gives its bytes. Proven at capture by rebuilding it.
``canonical``
    Same members, other container bytes: the archive was written by another
    tool. The build writes the TorrentZip form and checks members only.

``sources`` lists the recipes that agree on the member list: profile
``contents:`` blocks and the MAME and FBNeo DAT snapshots under
``recipes/``, then ``collection``, the archive itself. A DAT is provenance,
never the only source. ``bytes_pinned`` marks an archive whose container
hash a platform or a profile pins, with each pin named.

The build reads each member by sha1: a loose file first, then a member of
another archive, then the archive's own copy, and verifies what it wrote
before moving it into place.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from core.paths import REPO_ROOT


ARCHIVES_FILE = REPO_ROOT / "recipes" / "archives.json"
# The writer contract: build_torrentzip's layout over stock zlib. A change to
# the layout is a new builder name and a new proof of every record.
BUILDER = "torrentzip-1"
_ARCHIVE_PATH = re.compile(r"\.zip(\.[0-9a-f]{8})?$", re.IGNORECASE)


def is_archive_path(path: str) -> bool:
    """A ZIP by its name: ``x.zip`` or a ``.variants/`` copy ``x.zip.1a2b3c4d``."""
    return bool(_ARCHIVE_PATH.search(path))


def database_archives(db: dict) -> dict[str, dict]:
    """Path -> database entry, for every archive the database lists."""
    return {
        entry["path"]: entry
        for entry in (db.get("files") or {}).values()
        if is_archive_path(entry.get("path", ""))
    }


# --- the ledger file --------------------------------------------------------


def load_ledger(path: Path = ARCHIVES_FILE) -> dict[str, dict]:
    """Path -> record, from ``recipes/archives.json``, empty when absent."""
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    return {record["path"]: record for record in data.get("archives", [])}


def rebuild_counts(path: Path = ARCHIVES_FILE) -> dict[str, int]:
    """How many recipes rebuild ``exact`` and ``canonical``, and ``total``:
    the figures the README and the site print."""
    records = load_ledger(path).values()
    return {
        "total": len(records),
        **{kind: sum(1 for r in records if r.get("rebuild") == kind)
           for kind in ("exact", "canonical")},
    }


def ledger_text(records: dict[str, dict]) -> str:
    """One record per line, so a diff names the archive that changed."""
    lines = [
        json.dumps(records[path], ensure_ascii=False, separators=(",", ":"))
        for path in sorted(records)
    ]
    body = ",\n".join(f"  {line}" for line in lines)
    return f'{{"builder": "{BUILDER}", "archives": [\n{body}\n]}}\n'


def write_ledger(records: dict[str, dict], path: Path = ARCHIVES_FILE) -> bool:
    from core.artifacts import write_if_changed

    path.parent.mkdir(parents=True, exist_ok=True)
    return write_if_changed(str(path), ledger_text(records))


def missing_members(ledger: dict[str, dict], db: dict) -> list[dict]:
    """Members held nowhere: neither as a loose file nor inside any archive.

    Read from the committed data alone, so it holds without the files: a
    member is held when database.json has its sha1 as a file, or when the
    recipe of an archive database.json lists carries it.
    """
    archives = database_archives(db)
    loose = {
        sha1 for sha1, entry in (db.get("files") or {}).items()
        if not is_archive_path(entry.get("path", ""))
    }
    inside = {
        member["sha1"]
        for path, record in ledger.items() if path in archives
        for member in record.get("members", [])
    }
    return [
        {"archive": path, "member": member["name"], "sha1": member["sha1"]}
        for path, record in sorted(ledger.items())
        for member in record.get("members", [])
        if member["sha1"] not in loose and member["sha1"] not in inside
    ]
