#!/usr/bin/env python3
"""Write schemas/install-events.schema.json from install.py's EVENT_KEYS.

    python scripts/generate_event_schema.py           rewrite the schema
    python scripts/generate_event_schema.py --check   exit 1 when it is stale
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from core.artifacts import write_text_atomic
from installer_build.eventschema import OUTPUT, build_schema, render


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true",
                        help="exit 1 when the file differs from EVENT_KEYS, writing nothing")
    parser.add_argument("--output", type=Path, default=OUTPUT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    text = render(build_schema())
    current = args.output.read_text(encoding="utf-8") if args.output.is_file() else None
    if current == text:
        return 0
    if args.check:
        print(f"{args.output} differs from EVENT_KEYS: run "
              "python scripts/generate_event_schema.py", file=sys.stderr)
        return 1
    write_text_atomic(str(args.output), text)
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
