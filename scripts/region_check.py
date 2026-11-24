#!/usr/bin/env python3
"""Region checks: which regional BIOS a core reads for a game, and whether
the game boots without it.

For a system whose profile marks its BIOS entries with `region:`, each test
game of a region (campaign/content.yml) runs through core_probe four
times, each a record in measurements/<emulator>.jsonl:

  full    every regional BIOS the profile declares
  own     only the entries whose `region:` holds the game's region
  others  only the entries of the other regions
  pack    the files of `generate_pack.py --emulator E --region R`, at
          the place the pack puts them

The outcome reads the records: the file the core opened in the full run
(from strace) settles the `region:` claim, the verdicts of `own` and
`others` say whether the BIOS is locked to the region, and `pack` says
whether the pack filtered for the region boots the region's game.

  run     the four runs for each region game of one core and system
  report  the outcome of every region record already in measurements/

A maintainer starts a run. Nothing here runs on a timer.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# The probe tools do not import core/cli.py, which states the 3.9 floor for the
# other scripts. Under 3.8 they stopped on a str.removesuffix AttributeError.
if sys.version_info < (3, 9):
    sys.exit(
        f"{Path(sys.argv[0]).name} needs Python 3.9 or newer, "
        f"this is {sys.version.split()[0]}"
    )

sys.path.insert(0, str(Path(__file__).resolve().parent))

from probes.regioncheck import VARIANTS, collect, run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    go = sub.add_parser("run", allow_abbrev=False, help="the four runs of each region game, recorded")
    go.add_argument("--emulator", required=True, help="the profile, e.g. beetle_psx")
    go.add_argument("--system", required=True, help="the system, e.g. sony-playstation")
    go.add_argument("--core-name", help="buildbot core name, e.g. mednafen_psx (downloads the nightly)")
    go.add_argument("--core", help="a core .so to use instead of the nightly")
    go.add_argument("--core-artifact", help="where --core was downloaded from")
    go.add_argument("--content-dir",
                    help="where romfetch keeps the test games (default: .cache/test-content)")
    go.add_argument("--variants", nargs="*", choices=VARIANTS, help="a subset of the four runs")
    go.add_argument("--timeout", type=int, default=900, help="seconds per run")
    go.add_argument("--max-load-wait", type=int, default=1800,
                    help="seconds a run waits for a busy host to settle before it is given up (default 1800)")
    sub.add_parser("report", allow_abbrev=False, help="the outcomes the records hold, as JSON")
    args = parser.parse_args(argv)
    if args.command == "run":
        if not (args.core or args.core_name):
            parser.error("run needs --core-name or --core")
        return run(args)
    print(json.dumps(collect(), indent=2))
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
