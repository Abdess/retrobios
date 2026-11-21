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

sys.path.insert(0, os.path.dirname(__file__))

from core import upstream
from core.cli import add_repo_inputs, require_directory
from model.profiles import ProfileSelectionError, load_emulator_profiles, resolve_profile_name
from profiling.fileless import audit, unanswered_profiles


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    parser.add_argument("emulators", nargs="*", help="profiles to read")
    parser.add_argument(
        "--all", action="store_true",
        help="every profile that declares no files and has no answer yet",
    )
    add_repo_inputs(parser, "emulators")
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

    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False) if args.emulators else {}
    try:
        names = [
            resolve_profile_name(name, profiles, "python scripts/verify.py --list-emulators")
            for name in args.emulators
        ]
    except ProfileSelectionError as exc:
        raise SystemExit(f"ERROR: {exc}") from None
    if args.all:
        names = unanswered_profiles(args.emulators_dir)

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
    from core.cli import run_cli

    run_cli(main)
