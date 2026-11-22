"""The lines auto_fetch prints for each search, and its exit code for --sha1."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from acquire.fetch import FetchRecord, FetchRun, LookupRecord, fetch_summary, lookup_sha1
from acquire.placement import ACQUIRE_DIR
from core.paths import EMULATORS_DIR, PLATFORMS_DIR

# The step number and wording of each source that served a platform's file.
FOUND_IN = {
    "branch": "[2] Found in branch",
    "public_repo": "[3] Found in public repo",
    "software_heritage": "[3b] Found in Software Heritage",
    "archive_org": "[4] Found on archive.org",
}
# The name of each source that served a --sha1 lookup.
SHA1_FOUND_IN = {"software_heritage": "Software Heritage", "archive_org_sha1": "archive.org"}


def fetch_lines(record: FetchRecord) -> list[str]:
    """What a platform run prints once one file's search is over."""
    if record.outcome == "held":
        return [f"    [1] Found in database at: {record.held_at}"]
    if record.outcome == "unverifiable":
        return ["    [-] Cannot be verified from the network: declares no "
                "cryptographic hash. Not searched, nothing written"]
    if record.outcome == "dry_run":
        return ["    [DRY RUN] Would search branches, repos, Software Heritage, archive.org"]
    if record.outcome == "incomplete":
        return [f"    [5] Search incomplete, {len(record.unanswered)} source(s) did not "
                f"answer (first: {record.unanswered[0]})"]
    if record.outcome == "not_found":
        return ["    [5] Not found, open for contributions"]
    lines = []
    placed = record.placed
    assert placed is not None and record.source is not None
    if placed.kept_out:
        label = str(record.entry.get("system") or "") or os.path.basename(record.entry["name"])
        lines.append(f"    No single bios/ folder for {label}"
                     + (f" ({', '.join(placed.folders)})" if placed.folders else "")
                     + ": kept out of bios/")
    lines.append(f"    {FOUND_IN[record.source]}, saved to: {placed.path}")
    return lines


def report_fetch(
    missing: list[dict],
    db: dict,
    bios_dir: str,
    dry_run: bool = False,
    platforms_dir: str = PLATFORMS_DIR,
    emulators_dir: str = EMULATORS_DIR,
    acquire_dir: Path = ACQUIRE_DIR,
) -> dict:
    """Search every missing file, printing each search as it runs."""
    run = FetchRun(db, bios_dir, dry_run, platforms_dir, emulators_dir, acquire_dir)
    records = []
    for entry in missing:
        print(f"\n  Searching: {entry['name']} ({entry['system']})")
        record = run.fetch(entry)
        for line in fetch_lines(record):
            print(line)
        records.append(record)
    return {**fetch_summary(records), "records": records}


def lookup_line(record: LookupRecord) -> str:
    """What --sha1 prints for one lookup."""
    if record.outcome == "malformed":
        return f"  {record.raw}: not a sha1"
    if record.outcome == "held":
        return f"  {record.sha1}: already held at {record.held_at}"
    if record.outcome == "dry_run":
        return f"  {record.sha1}: would ask Software Heritage and archive.org"
    if record.outcome == "not_found":
        note = (f", {len(record.unanswered)} source(s) did not answer"
                if record.unanswered else "")
        return f"  {record.sha1}: not found{note}"
    assert record.source is not None
    return (f"  {record.sha1}: found in {SHA1_FOUND_IN[record.source]}, "
            f"{record.size} bytes, saved to {record.path}")


def report_lookups(sha1s: list[str], db: dict, dry_run: bool = False,
                   acquire_dir: Path = ACQUIRE_DIR) -> int:
    """Look up each --sha1, printing each answer: 0 when every one was found, 1 otherwise."""
    missing = 0
    for raw in sha1s:
        record = lookup_sha1(raw, db, dry_run, acquire_dir)
        malformed = record.outcome == "malformed"
        print(lookup_line(record), file=sys.stderr if malformed else sys.stdout)
        missing += malformed or record.outcome == "not_found"
    return 1 if missing else 0
