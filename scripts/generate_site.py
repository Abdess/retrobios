#!/usr/bin/env python3
"""Generate the site from database.json, platform configs, and emulator profiles.

The pages, navigation and data files are written into the Astro Starlight
project in website/, which builds the site.

Reads the same data sources as verify.py and generate_pack.py to produce
a complete documentation site. Zero manual content.

Usage:
    python scripts/generate_site.py
    python scripts/generate_site.py --db database.json --platforms-dir platforms
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from core.cli import require_directory
from core.artifacts import ArtifactLockBusy, artifact_lock

from sitegen.build import _generate
from sitegen.config import STARLIGHT_CONTENT, STARLIGHT_DIR
from sitegen.parts import PUBLISHED_PARTS_FILE


# Main


def main() -> None:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Generate the documentation site from project data"
    )
    parser.add_argument(
        "--db", default="database.json",
        help="database file to read (default: %(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default="platforms",
        help="platform YAML directory (default: %(default)s)",
    )
    parser.add_argument(
        "--emulators-dir", default="emulators",
        help="emulator profile directory (default: %(default)s)",
    )
    parser.add_argument(
        "--site-dir", default=STARLIGHT_DIR,
        help="the Astro Starlight project the site is written into (default: %(default)s)",
    )
    parser.add_argument(
        "--docs-dir", default=None,
        help="directory the pages are written to (default: the project's "
             "content collection, src/content/docs)",
    )
    args = parser.parse_args()
    if args.docs_dir is None:
        args.docs_dir = str(Path(args.site_dir) / STARLIGHT_CONTENT)
    # Before any write: the public assets and the bootstraps went out first,
    # and a mistyped folder stopped the run only after them.
    require_directory(args.emulators_dir, "--emulators-dir")
    require_directory(args.platforms_dir, "--platforms-dir")
    try:
        # Two runs over one docs/ delete each other's pages and scratch
        # files in the sweep, so the second is refused instead.
        import contextlib

        from model.registry import load_data_dir_registry
        from core.artifacts import repository_output_lock
        from packs.datadirs import hold_data_dirs

        # The coverage pages resolve against data/, held while they are read.
        # Whatever --docs-dir says, website/src/data and wiki/ are written.
        with artifact_lock(args.docs_dir), \
                repository_output_lock(str(PUBLISHED_PARTS_FILE)), \
                contextlib.ExitStack() as held:
            hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))
            _generate(args)
    except ArtifactLockBusy as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
