#!/usr/bin/env python3
"""Write install/launchers/index.json: the handheld launchers as files for a card.

    python scripts/generate_launcher_index.py           rewrite the list
    python scripts/generate_launcher_index.py --check   exit 1 when it is stale

install.py --add-app reads this list from the ref its file lists come from,
and puts on a handheld's card the launcher of its system, each file checked
against the size and SHA-256 recorded here. The files are the members of the
archives scripts/build_port.py builds, from the same sources: muOS gets its
application archive, rebuilt by the installer from the members and checked
against the hash recorded for it, the others the archive's files at their
place on the card. Where each system's files go is install.py's APP_PLACES.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from core.artifacts import write_text_atomic
from installer_build.launcherindex import OUTPUT, build_index, render


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true",
                        help="exit 1 when the list differs from the launchers, writing nothing")
    parser.add_argument("--output", type=Path, default=OUTPUT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        text = render(build_index())
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    current = args.output.read_text(encoding="utf-8") if args.output.is_file() else None
    if current == text:
        return 0
    if args.check:
        print(f"{args.output} differs from the launchers in ports/: run "
              "python scripts/generate_launcher_index.py", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_text_atomic(str(args.output), text)
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
