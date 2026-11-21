#!/usr/bin/env python3
"""Refresh cached data directories from upstream repositories.

Reads platforms/_data_dirs.yml, compares cached commit SHAs against
remote, and re-downloads stale entries.

Usage:
    python scripts/refresh_data_dirs.py --dry-run
    python scripts/refresh_data_dirs.py --key dolphin-sys
    python scripts/refresh_data_dirs.py --force
"""

from __future__ import annotations

import argparse
import logging
import os
from core.cli import suggest_names
from model.cliargs import platform_arg, require_platform

from model.registry import data_dir_registry_at
from packs.datadirs import DEFAULT_REGISTRY, log, refresh_all, refresh_entry


def summarize(outcomes: dict[str, bool | None], dry_run: bool) -> str:
    """One closing line: how many entries changed, were current, failed."""
    refreshed = sum(1 for o in outcomes.values() if o is True)
    current = sum(1 for o in outcomes.values() if o is False)
    failed = sum(1 for o in outcomes.values() if o is None)
    verb = "would refresh" if dry_run else "refreshed"
    line = f"{len(outcomes)} entries: {refreshed} {verb}, {current} up to date"
    return f"{line}, {failed} failed" if failed else line


def main() -> None:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Refresh cached data directories from upstream"
    )
    parser.add_argument("--key", help="Refresh only this entry")
    parser.add_argument(
        "--force", action="store_true", help="Re-download even if up to date"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview without downloading"
    )
    parser.add_argument(
        "--platform", "-p", type=platform_arg, help="Only refresh entries for this platform"
    )
    parser.add_argument(
        "--registry", default=DEFAULT_REGISTRY, help="Path to _data_dirs.yml"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
    )

    if args.platform:
        # The registry sits in the platforms directory it serves.
        require_platform(args.platform, os.path.dirname(args.registry) or ".")
    registry = data_dir_registry_at(args.registry, required=True)

    if args.key:
        if args.key not in registry:
            log.error("unknown key: %s. %s", args.key, suggest_names([args.key], list(registry), "--dry-run"))
            raise SystemExit(1)
        allowed = registry[args.key].get("for_platforms")
        if args.platform and allowed and args.platform not in allowed:
            # The platform restriction applied only without --key: dolphin-sys
            # was refreshed for RomM, which never reads it.
            log.error(
                "%s does not serve %s (for_platforms: %s)",
                args.key, args.platform, ", ".join(allowed),
            )
            raise SystemExit(2)
        outcomes = {
            args.key: refresh_entry(
                args.key, registry[args.key], force=args.force, dry_run=args.dry_run
            )
        }
    else:
        outcomes = refresh_all(
            registry, force=args.force, dry_run=args.dry_run, platform=args.platform
        )

    log.info(summarize(outcomes, args.dry_run))
    failed = sorted(key for key, outcome in outcomes.items() if outcome is None)
    if failed:
        log.error("refresh failed: %s", ", ".join(failed))
        raise SystemExit(1)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
