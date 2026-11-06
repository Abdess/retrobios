#!/usr/bin/env python3
"""List the registered platforms.

Respects the `status` field in _registry.yml:
- active: listed by default
- archived: listed with --include-archived only

Usage:
    python scripts/list_platforms.py                # active platforms
    python scripts/list_platforms.py --include-archived  # archived ones too
    python scripts/list_platforms.py >> "$GITHUB_OUTPUT"
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import list_registered_platforms

PLATFORMS_DIR = "platforms"


def list_platforms(include_archived: bool = False) -> list[str]:
    """List platform config files, filtering by status from _registry.yml."""
    return list_registered_platforms(PLATFORMS_DIR, include_archived=include_archived)


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="List available platforms")
    # The name verify, generate_pack, slots and pipeline use. --all is the
    # older spelling, still read so existing commands keep working.
    parser.add_argument(
        "--include-archived", "--all", dest="include_archived", action="store_true",
        help="include archived platforms",
    )
    args = parser.parse_args()

    platforms = list_platforms(include_archived=args.include_archived)

    if not platforms:
        print("No platform configs found", file=sys.stderr)
        sys.exit(1)

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"platforms={json.dumps(platforms)}\n")
    else:
        print(json.dumps(platforms))


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
