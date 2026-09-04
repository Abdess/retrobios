#!/usr/bin/env python3
"""Find profiles that declare no files whose source now asks for a directory.

A profile with an empty `files:` list asserts that the emulator loads nothing
from disk. That assertion ages: a core that embedded everything can grow a
path, and nothing in the repository notices, because there is no file to go
missing and no ref to drift. virtualjaguar carried "No external BIOS files are
required or loaded by this core" while its source had grown eleven filenames
read from the system directory.

The signal is the request for a directory to read from. A libretro core asks
the frontend with RETRO_ENVIRONMENT_GET_SYSTEM_DIRECTORY; other shapes ask the
environment or build a path from a home directory. Finding one in a file the
profile itself cites does not prove a file is loaded, and this reports rather
than concludes: it names the profiles worth a reading, so the other hundred and
fifty need none.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import upstream
from profile_sync import collect_citations, select_views, split_source_ref
from safeparse import yaml_load

# Ways a program asks for somewhere to read from.
SIGNALS = (
    "RETRO_ENVIRONMENT_GET_SYSTEM_DIRECTORY",
    "GET_SYSTEM_DIRECTORY",
    "system_directory",
    "get_system_directory",
)

SOURCE_SUFFIX = (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".m", ".mm")


def cited_paths(document: dict) -> list[str]:
    """Source paths the profile points at, in document order, deduplicated."""
    seen: list[str] = []
    for citation in collect_citations(document):
        for part in split_source_ref(citation.ref):
            path = part.path
            if path.endswith(SOURCE_SUFFIX) and path not in seen:
                seen.append(path)
    return seen


def audit(name: str, emulators_dir: str, cache_dir: str, offline: bool):
    """Signals found in the sources a fileless profile cites."""
    with open(os.path.join(emulators_dir, f"{name}.yml"), encoding="utf-8") as handle:
        document = yaml_load(handle) or {}
    if document.get("files"):
        return None
    if str(document.get("exclusion_note") or "").strip():
        # Someone read this one and wrote down why nothing is declared. The
        # check exists to find the profiles nobody has answered yet; an
        # answer that goes stale shows up as a drifting ref instead.
        return None
    if document.get("data_directories"):
        # The load is declared, as a directory rather than a file. dinothawr
        # reads system_dir/dinothawr/ and says so there; that is coverage, not
        # an assertion waiting to age.
        return None
    views = select_views(document, cache_dir, offline)
    if not views:
        return []
    hits: list[tuple[str, str]] = []
    for path in cited_paths(document)[:40]:
        for view in views:
            lines = upstream.fetch_file(view.repo, view.pin, path, cache_dir, offline)
            if lines is None:
                continue
            for signal in SIGNALS:
                if any(signal in line for line in lines):
                    hits.append((path, signal))
                    break
            break
    return hits


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("emulators", nargs="+")
    parser.add_argument("--emulators-dir", default="emulators")
    parser.add_argument("--cache-dir", default=".cache")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()

    flagged = 0
    for name in args.emulators:
        try:
            hits = audit(name, args.emulators_dir, args.cache_dir, args.offline)
        except upstream.UpstreamError as exc:
            print(f"{name}: unreachable, {exc}", file=sys.stderr)
            continue
        if hits is None or not hits:
            continue
        flagged += 1
        print(f"{name}: declares no files, yet its source asks for a directory")
        for path, signal in hits:
            print(f"    {path}: {signal}")
    raise SystemExit(1 if flagged else 0)


if __name__ == "__main__":
    main()
