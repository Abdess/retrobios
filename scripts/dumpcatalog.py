"""Dump catalogues joined onto the collection.

Redump, No-Intro and TOSEC annotate what the repo holds. They are an
opinion on provenance, never an authority: the emulator source is."""

from __future__ import annotations

import json
import os
from pathlib import Path

from artifacts import write_if_changed


DEFAULT_PROVENANCE_DIR = "provenance"

def load_provenance_snapshots(provenance_dir: str = DEFAULT_PROVENANCE_DIR) -> dict:
    """Load dump-catalog snapshots from provenance/*.json.

    Returns {source_name: snapshot} where snapshot holds the normalized
    entries written by the redump scraper or the pack importer. Missing
    directory means no snapshots: returns an empty dict.
    """
    snapshots = {}
    prov_path = Path(provenance_dir)
    if not prov_path.is_dir():
        return snapshots
    for path in sorted(prov_path.glob("*.json")):
        with open(path) as f:
            snapshot = json.load(f)
        source = snapshot.get("source")
        if source and snapshot.get("entries"):
            snapshots[source] = snapshot
    return snapshots

def build_provenance_index(snapshots: dict) -> dict:
    """Index snapshot entries by sha1 and by (md5, size) per source.

    First entry wins on hash collisions within a source; entries are
    pre-sorted at snapshot write time so the outcome is deterministic.
    """
    index = {}
    for source, snapshot in snapshots.items():
        by_sha1 = {}
        by_md5_size = {}
        for entry in snapshot["entries"]:
            sha1 = entry.get("sha1", "")
            md5 = entry.get("md5", "")
            if sha1 and sha1 not in by_sha1:
                by_sha1[sha1] = entry
            if md5 and entry.get("size"):
                key = (md5, entry["size"])
                if key not in by_md5_size:
                    by_md5_size[key] = entry
        index[source] = {"by_sha1": by_sha1, "by_md5_size": by_md5_size}
    return index

def annotate_provenance(files: dict, snapshots: dict) -> dict[str, int]:
    """Attach a provenance field to database file entries.

    Matches by SHA1 first, then MD5 + size. Returns per-source match
    counts. Files without any catalog match keep no provenance field.
    """
    index = build_provenance_index(snapshots)
    counts = dict.fromkeys(index, 0)
    for sha1, entry in files.items():
        matches = {}
        for source in sorted(index):
            src_index = index[source]
            hit = src_index["by_sha1"].get(sha1) or src_index["by_md5_size"].get(
                (entry.get("md5", ""), entry.get("size", 0))
            )
            if hit:
                matches[source] = {
                    "dat": hit.get("dat", ""),
                    "name": hit.get("name", ""),
                    "description": hit.get("description", ""),
                }
                counts[source] += 1
        if matches:
            entry["provenance"] = matches
        else:
            entry.pop("provenance", None)
    return counts

def write_provenance_snapshot(
    path: str, source: str, imported_at: str, dats: dict, entries: list[dict]
) -> bool:
    """Write a normalized provenance snapshot, sorted for determinism."""
    snapshot = {
        "source": source,
        "imported_at": imported_at,
        "dats": dict(sorted(dats.items())),
        "entries": sorted(entries, key=lambda e: (e["dat"], e["name"])),
    }
    return write_if_changed(path, json.dumps(snapshot, indent=2) + "\n")
