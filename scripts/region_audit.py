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
from resolve.regionaudit import build_report


LIMITS = """Limits, read before trusting any line below.

  TOSEC's country field is the country of ORIGIN, not the regional variant
  (TOSEC Naming Convention v4, p.12). A Korean MSX ROM published by Microsoft
  US is tagged (US). TOSEC names are therefore NOT read here.

  Redump DATs carry no region at all: it exists in the redump.org database but
  is never exported, so a Redump entry contributes nothing.

  Only No-Intro filename tokens are usable, and only for the fraction of repo
  files that carry one. Everything else is silent, not clean.

  The emulator source decides. A disagreement is a prompt to reread the code,
  never a correction to apply on its own.
"""


def print_report(report: dict) -> None:
    print(LIMITS)
    print(
        f"repo files: {report['repo_files']}   "
        f"with a usable No-Intro region token: {report['catalog_files']}"
    )
    print(
        f"declared region: values -> agree {report['agree']}, "
        f"disagree {report['disagree']}, no catalogue entry {report['unchecked']}"
    )
    if report["vocabulary"]:
        print("\ncatalogue vocabulary present in this collection:")
        for slug, count in report["vocabulary"].items():
            print(f"  {count:5d}  {slug}")
    if not report["conflicts"]:
        print("\nNo disagreement.")
        return
    print("\nDISAGREEMENTS (reread the emulator source, do not apply blindly):\n")
    for c in report["conflicts"]:
        print(f"  {c['emulator']}: {c['file']}")
        print(f"    profile:   {c['profile']}")
        print(f"    catalogue: {c['catalog']}  ({c['dat_name']})")


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
