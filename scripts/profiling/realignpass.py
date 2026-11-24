"""--realign-prose over a selection of profiles."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from core import forgehttp
from profiling.realign import realign_prose
from profiling.sourcepaths import record_write, refresh_source_paths
from profiling.yamledit import YamlWriteError


def run_realign(args: argparse.Namespace, selected: dict) -> None:
    """--realign-prose over the selected profiles, exit 1 when one failed."""
    failed: set[str] = set()
    written: set[str] = set()
    for name in selected:
        profile_path = Path(args.emulators_dir) / f"{name}.yml"
        if not profile_path.is_file():
            continue
        try:
            with record_write(profile_path, name, written):
                for line in realign_prose(
                    profile_path, args.cache_dir, args.offline, args.dry_run
                ):
                    print(f"{name}: {line}")
        except forgehttp.UpstreamError as exc:
            print(f"{name}: {exc}", file=sys.stderr)
            failed.add(name)
        except YamlWriteError as exc:
            print(f"{name}: write refused: {exc}", file=sys.stderr)
            failed.add(name)
    refresh_source_paths(args, written)
    if failed:
        raise SystemExit(1)
