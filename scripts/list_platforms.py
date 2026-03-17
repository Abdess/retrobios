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

import json
import os
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

PLATFORMS_DIR = "platforms"


def _load_registry(platforms_dir: str = PLATFORMS_DIR) -> dict:
    """Load _registry.yml if available."""
    registry_path = Path(platforms_dir) / "_registry.yml"
    if yaml and registry_path.exists():
        with open(registry_path) as f:
            return yaml.safe_load(f) or {}
    return {}


def list_platforms(include_archived: bool = False) -> list[str]:
    """List platform config files, filtering by status from _registry.yml."""
    platforms_dir = Path(PLATFORMS_DIR)
    if not platforms_dir.is_dir():
        return []

    registry = _load_registry(str(platforms_dir))
    registry_platforms = registry.get("platforms", {})

    platforms = []
    for f in sorted(platforms_dir.glob("*.yml")):
        if f.name.startswith("_"):
            continue
        name = f.stem
        status = registry_platforms.get(name, {}).get("status", "active")
        if status == "archived" and not include_archived:
            continue
        platforms.append(name)

    return platforms


def main():
    include_all = "--all" in sys.argv

    platforms = list_platforms(include_archived=include_all)

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
