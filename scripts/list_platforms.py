#!/usr/bin/env python3
"""List the platforms registered in _registry.yml.

Usage:
    python scripts/list_platforms.py
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


def list_platforms() -> list[str]:
    """Every registered platform."""
    return list_registered_platforms(PLATFORMS_DIR)


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="List available platforms")
    args = parser.parse_args()
    from common import work_from_repo_root  # noqa: PLC0415

    work_from_repo_root(args, parser, [])

    platforms = list_platforms()

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
