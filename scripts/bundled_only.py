#!/usr/bin/env python3
"""Collected files that only an emulator's own install provides.

A file installed with the emulator is already on the user's machine, and the
packs leave it out. A copy in bios/ that nothing else asks for is then dead
weight: no platform declares it, no profile entry of any build needs it from
the collection, and no install manifest ships it. This lists those copies, so
they can be removed, and fails under --strict while one remains.

Usage:
    python scripts/bundled_only.py
    python scripts/bundled_only.py --strict
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from core.cli import add_repo_inputs
from core.sizes import size_text
from model.database import load_database
from model.profiles import load_emulator_profiles
from packs.bundledonly import bundled_only


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    add_repo_inputs(parser, "db", "emulators", "platforms")
    parser.add_argument("--install-dir", default="install", type=Path,
                        help="install manifests, whose files are shipped (default: %(default)s)")
    parser.add_argument("--json", action="store_true", help="print the list as JSON")
    parser.add_argument("--strict", action="store_true", help="exit 1 while a file is listed")
    args = parser.parse_args()
    from model.cliargs import work_from_repo_root

    work_from_repo_root(args, parser, ["db", "emulators_dir", "platforms_dir", "install_dir"])

    rows = bundled_only(
        load_database(args.db), load_emulator_profiles(args.emulators_dir),
        args.platforms_dir, args.install_dir,
    )
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for row in rows:
            print(f"{row['path']}  ({', '.join(row['emulators'])})")
        total = sum(row["size"] for row in rows)
        print(f"{len(rows)} collected files only an emulator install provides, "
              f"{size_text(total)}")
    return 1 if args.strict and rows else 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
