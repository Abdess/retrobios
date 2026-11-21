"""Cross-check profile region: values against dump-catalog provenance.

Advisory only. The emulator source decides what a region: value should be. This
reports where an independent catalogue disagrees, so a hand-written value gets a
second opinion before it is trusted.

Read the limits printed in the header before acting on anything here.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.cli import add_repo_inputs
from model.database import load_database
from model.profiles import load_emulator_profiles
from resolve.regionaudit import build_report, print_report


def main() -> int:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Cross-check profile region: values against No-Intro provenance"
    )
    add_repo_inputs(parser, "db", "emulators")
    parser.add_argument("--json", action="store_true", help="Machine-readable output")
    args = parser.parse_args()
    from model.cliargs import work_from_repo_root

    work_from_repo_root(args, parser, ["db", "emulators_dir"])

    db = load_database(args.db)
    profiles = load_emulator_profiles(args.emulators_dir)
    report = build_report(profiles, db)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_report(report)
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
