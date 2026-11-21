#!/usr/bin/env python3
"""Check that each MAME romset ref names the line declaring its own set.

profile_sync follows content: a ref that drifted still anchors wherever the
cited text went, which is what drift detection is for. It cannot say whether
the line a MAME ref points at declares the set the entry is named after, and
that is the only thing such a ref means. Asking the stronger question found
nineteen stale refs in one driver file where profile_sync had flagged five.

The set name is argument 1 of the machine macro, after the year. Matching the
name anywhere on the line would also match every clone that names this set as
its parent, which is most of a driver file. Comments are stripped first: a
declaration can sit behind one, as `/* Naomi */ GAME( 1998, naomi, ...)` does.

A set no machine macro declares is not an error. Device ROMs take the
shortname of their DEFINE_DEVICE_TYPE and some archives are bare ROM_START
blocks. A ref there cites something this check cannot judge, and says so.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from core import upstream
from core.cli import add_repo_inputs, require_directory
from profiling.mamerefs import audit, rewrite


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    parser.add_argument("emulators", nargs="+", help="MAME-family profiles to audit")
    add_repo_inputs(parser, "emulators")
    parser.add_argument(
        "--cache-dir", default=upstream.CACHE_DIR,
        help="download cache directory (default: %(default)s)",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="read only what the cache holds, no network access",
    )
    parser.add_argument(
        "--write", action="store_true",
        help="rewrite the refs the audit can settle",
    )
    args = parser.parse_args()
    require_directory(args.emulators_dir, "--emulators-dir")

    total = 0
    for name in args.emulators:
        try:
            findings, agreed, unjudged = audit(
                name, args.emulators_dir, args.cache_dir, args.offline
            )
        except upstream.UpstreamError as exc:
            print(f"{name}: unreachable, {exc}", file=sys.stderr)
            continue
        total += len(findings)
        print(
            f"{name}: {agreed} agree, {len(findings)} point elsewhere, "
            f"{unjudged} not judgeable"
        )
        for finding in findings:
            print(
                f"    {finding.set_name:16} {finding.path}"
                f":{finding.cited} -> {finding.declared}"
            )
        if args.write and findings:
            print(f"    written: {rewrite(name, args.emulators_dir, findings)}")
    raise SystemExit(1 if total and not args.write else 0)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
