#!/usr/bin/env python3
"""Scan bios/ directory and generate multi-indexed database.json.

Usage:
    python scripts/generate_db.py [--force] [--bios-dir DIR] [--output FILE]

Supports incremental mode via .cache/db_cache.json beside the scanned
tree (mtime-based).
Use --force to rehash all files.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from core.cli import add_repo_inputs, require_directory
from model.dumpcatalog import DEFAULT_PROVENANCE_DIR
from core.artifacts import repository_output_lock
from model.safeparse import require_yaml
from collection.run import generate

# Platform and profile aliases are read from YAML: without pyyaml the
# database lost every one of them and the run still exited 0.
yaml = require_yaml()

DEFAULT_OUTPUT = "database.json"


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Generate multi-indexed BIOS database")
    parser.add_argument("--force", action="store_true", help="Force rehash all files")
    add_repo_inputs(parser, "bios", "platforms", "emulators")
    parser.add_argument(
        "--output", "-o", default=DEFAULT_OUTPUT, help="Output JSON file"
    )
    parser.add_argument(
        "--provenance-dir",
        default=DEFAULT_PROVENANCE_DIR,
        help="Directory with dump-catalog snapshots",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Restore release assets from the local cache only, never download",
    )
    args = parser.parse_args()
    require_directory(args.bios_dir)
    require_directory(args.platforms_dir, "--platforms-dir")
    require_directory(args.emulators_dir, "--emulators-dir")
    with repository_output_lock(args.output):
        return generate(args)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
