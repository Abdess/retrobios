#!/usr/bin/env python3
"""Generate slim README.md from database.json and platform configs.

Detailed documentation lives on the site (abdess.github.io/retrobios/).
This script produces a concise landing page with download links and coverage.

Usage:
    python scripts/generate_readme.py [--db database.json] [--platforms-dir platforms/]
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from core.cli import add_repo_inputs
from model.database import load_database
from core.artifacts import repository_output_lock
from sitegen.readme import README_PATH, load_readme_inputs, render_readme, write_readme


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Generate slim README.md")
    add_repo_inputs(parser, "db", "platforms")
    args = parser.parse_args()

    import contextlib

    from model.registry import load_data_dir_registry
    from packs.datadirs import hold_data_dirs

    db = load_database(args.db)

    # Coverage resolves against data/: a refresh swapping a tree mid-read
    # published counts taken from half of it.
    with repository_output_lock(str(README_PATH)), contextlib.ExitStack() as held:
        hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))
        inputs = load_readme_inputs(db, args.platforms_dir, args.db)
        write_readme(render_readme(inputs))


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
