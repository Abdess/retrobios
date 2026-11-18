#!/usr/bin/env python3
"""Rewrite the marked tables of wiki/installer.md from install.py.

    python scripts/generate_installer_doc.py           rewrite the tables
    python scripts/generate_installer_doc.py --check   exit 1 when one is stale

Each table sits between `<!-- generated: NAME -->` and
`<!-- /generated: NAME -->`. What install.py knows is written from it: the
options and their arguments from its parser, the event kinds and their keys
from EVENT_KEYS, the exit codes from its sys.exit calls, the RETROBIOS_PAD
values and each route's keys from TUI_ROUTES, the handheld launchers from
sitehandheld.LAUNCHERS. The prose cells (what an option
does, when an event comes) are kept as written, matched by their row. A row
install.py gains has no prose yet: the generator names it and writes nothing,
and the row is added by hand inside the markers, its first cell holding the
option, kind, code or value alone.

The run samples (a dry run, a first install, a later check, the reasons a
file is refused, a run copying from an old card) are printed by install.py
itself, run in its own process against the committed install/<platform>.json
served on the loopback, from a home and a card made under tmp/ and shown as
/home/me and /userdata. The reasons and the copy are read from a four-file
list laid out in that home (SMALL_LIST), whose files are written there. Only
the transport and the machine are stood in for, see _child. Each is dated by
the `generated` field of its list, so a rendering is the same from one day
to the next.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from core.artifacts import write_text_atomic

from installer_build.installerdoc import MissingProse, PAGE, SampleFailed, render


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true",
                        help="exit 1 when a table differs from install.py, writing nothing")
    parser.add_argument("--page", type=Path, default=PAGE, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    current = args.page.read_text(encoding="utf-8")
    try:
        text = render(current)
    except MissingProse as exc:
        print(f"{args.page}: {exc}. Add the row inside its markers, then run "
              "python scripts/generate_installer_doc.py", file=sys.stderr)
        return 1
    except SampleFailed as exc:
        print(f"{args.page}: {exc}", file=sys.stderr)
        return 1
    if text == current:
        return 0
    if args.check:
        print(f"{args.page} differs from install.py and install/*.json: run "
              "python scripts/generate_installer_doc.py", file=sys.stderr)
        return 1
    write_text_atomic(str(args.page), text)
    print(f"Wrote {args.page}")
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
