"""--verify-version and --set-version over a selection: core_version against the code."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from profiling import versionbasis
from profiling.bump import write_version
from profiling.worktree import refuse_dirty_tree
from profiling.yamledit import YamlWriteError


def format_reading(name: str, reading: versionbasis.Reading) -> str:
    """One reading as a line: its status, the version said, and where it was read."""
    mode = f"[{reading.mode}] " if reading.mode else ""
    kind = f"{reading.kind} " if reading.kind else ""
    if reading.status == versionbasis.DRIFT:
        said = f"declared {reading.declared}, code {reading.read}"
    elif reading.status == versionbasis.MATCH:
        said = str(reading.read)
    else:
        said = f"declared {reading.declared}"
    return f"{name}: {mode}{reading.status} {said} ({kind}{reading.where})"


def run_versions(args: argparse.Namespace, profiles: dict, selected: dict) -> None:
    """--verify-version and --set-version over ``selected``: core_version against the code."""
    if args.set_version and not args.dry_run and not args.force:
        refuse_dirty_tree(args.emulators_dir, list(selected))
    counts: Counter = Counter()
    rows = []
    failed = False
    for name, profile in selected.items():
        readings = versionbasis.check(
            profile, args.cache_dir, args.offline, profiles, recompute=args.set_version
        )
        for reading in readings:
            counts[reading.status] += 1
            rows.append({"profile": name, **asdict(reading)})
            if not args.as_json and (not args.changed_only or reading.status != versionbasis.MATCH):
                print(format_reading(name, reading))
        if args.set_version:
            path = Path(args.emulators_dir) / f"{name}.yml"
            if args.dry_run:
                continue
            try:
                if write_version(path, readings):
                    print(f"{name}: core_version written")
            except YamlWriteError as exc:
                print(f"{name}: write refused: {exc}", file=sys.stderr)
                failed = True
        elif any(r.status in versionbasis.FAILING for r in readings):
            failed = True
    if args.as_json:
        print(json.dumps(rows, indent=2))
    else:
        print(", ".join(f"{count} {status}" for status, count in sorted(counts.items())),
              file=sys.stderr)
    if failed:
        raise SystemExit(1)
