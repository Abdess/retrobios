#!/usr/bin/env python3
"""List available platforms for CI matrix strategy.

Respects the `status` field in _registry.yml:
- active: included in CI releases and automated scraping
- archived: excluded from CI, user can generate manually

Usage:
    python scripts/list_platforms.py                # Active platforms (for CI)
    python scripts/list_platforms.py --all           # All platforms including archived
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


def main():
    parser = argparse.ArgumentParser(description="List available platforms")
    parser.add_argument("--all", action="store_true", help="Include archived platforms")
    args = parser.parse_args()

    platforms = list_platforms(include_archived=args.all)

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
    main()
