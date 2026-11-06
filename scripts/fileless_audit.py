#!/usr/bin/env python3
"""Find profiles that declare no files whose source now asks for a directory.

A profile with an empty `files:` list asserts that the emulator loads nothing
from disk. That assertion ages: a core that embedded everything can grow a
path, and nothing in the repository notices, because there is no file to go
missing and no ref to drift. virtualjaguar carried "No external BIOS files are
required or loaded by this core" while its source had grown eleven filenames
read from the system directory.

The signal is the request for a directory to read from. A libretro core asks
the frontend with RETRO_ENVIRONMENT_GET_SYSTEM_DIRECTORY. Other shapes ask the
environment or build a path from a home directory. Finding one in a file the
profile itself cites does not prove a file is loaded, and this reports rather
than concludes: it names the profiles worth a reading, so the other hundred and
fifty need none.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

import upstream
from common import require_directory, suggest_names
from profile_sync import collect_citations, ref_role, select_views, split_source_ref
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
            path = ref_role(part.path)[1]
            if path.endswith(SOURCE_SUFFIX) and path not in seen:
                seen.append(path)
    return seen


def audit(
    name: str, emulators_dir: str, cache_dir: str, offline: bool
) -> list[tuple[str, str]] | None:
    """Signals found in the sources a fileless profile cites."""
    with open(os.path.join(emulators_dir, f"{name}.yml"), encoding="utf-8") as handle:
        document = yaml_load(handle) or {}
    if document.get("files"):
        return None
    if document.get("type") == "alias":
        # The same binary under another name: its files are its target's.
        return None
    if str(document.get("exclusion_note") or "").strip():
        # Someone read this one and wrote down why nothing is declared. The
        # check exists to find the profiles nobody has answered yet, and an
        # answer that goes stale shows up as a drifting ref instead.
        return None
    if document.get("data_directories"):
        # The load is declared, as a directory rather than a file. dinothawr
        # reads system_dir/dinothawr/ and says so there. That is coverage, not
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


def _settled_before_reading(document: dict) -> bool:
    """A profile answered without its sources: files, an exclusion note, or
    a declared data directory (see audit)."""
    return bool(
        document.get("files")
        or document.get("type") == "alias"
        or str(document.get("exclusion_note") or "").strip()
        or document.get("data_directories")
    )


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    parser.add_argument("emulators", nargs="*", help="profiles to read")
    parser.add_argument(
        "--all", action="store_true",
        help="every profile that declares no files and has no answer yet",
    )
    parser.add_argument(
        "--emulators-dir", default="emulators",
        help="emulator profile directory (default: %(default)s)",
    )
    parser.add_argument(
        "--cache-dir", default=".cache",
        help="download cache directory (default: %(default)s)",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="read only what the cache holds, no network access",
    )
    args = parser.parse_args()
    if args.all == bool(args.emulators):
        parser.error("name profiles or pass --all, not both")
    require_directory(args.emulators_dir, "--emulators-dir")

    known = sorted(path.stem for path in Path(args.emulators_dir).glob("*.yml"))
    unknown = [name for name in args.emulators if name not in known]
    if unknown:
        raise SystemExit(
            "ERROR: unknown profile " + ", ".join(unknown) + ". "
            + suggest_names(unknown, known, "python scripts/verify.py --list-emulators")
        )
    names = args.emulators
    if args.all:
        names = []
        for name in known:
            with open(Path(args.emulators_dir) / f"{name}.yml", encoding="utf-8") as handle:
                if not _settled_before_reading(yaml_load(handle) or {}):
                    names.append(name)

    flagged = unreachable = 0
    for name in names:
        try:
            hits = audit(name, args.emulators_dir, args.cache_dir, args.offline)
        except upstream.UpstreamError as exc:
            print(f"{name}: unreachable, {exc}", file=sys.stderr)
            unreachable += 1
            continue
        if hits is None or not hits:
            continue
        flagged += 1
        print(f"{name}: declares no files, yet its source asks for a directory")
        for path, signal in hits:
            print(f"    {path}: {signal}")
    print(
        f"{len(names)} profile(s) read, {flagged} to read again"
        + (f", {unreachable} unreachable" if unreachable else ""),
        file=sys.stderr,
    )
    # An unreachable source is not a clean one.
    raise SystemExit(1 if flagged or unreachable else 0)


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
