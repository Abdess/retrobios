#!/usr/bin/env python3
"""Validate source and generated RetroBIOS data contracts."""

from __future__ import annotations

import argparse
import sys
from importlib import import_module

try:
    import_module("jsonschema")
except ImportError:
    # Tests import this module and skip on the ImportError, the command
    # names the install pipeline.py names for the same step.
    if __name__ != "__main__":
        raise
    sys.exit('Error: jsonschema required (pip install "jsonschema[format-nongpl]")')

from schemas.run import validate


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__)
    parser.add_argument(
        "--source-only",
        action="store_true",
        help="validate emulator/platform YAML only",
    )
    args = parser.parse_args()

    run = validate(args.source_only)
    for skipped in run.skipped:
        print(f"note: {skipped}", file=sys.stderr)
    if run.errors:
        for error in run.errors:
            print(f"ERROR {error}")
        print(f"{len(run.errors)} schema or semantic error(s)")
        return 1
    if run.skipped:
        print("Every schema and semantic invariant checked is valid: "
              + ", ".join(run.skipped) + ".")
        return 0
    print("All RetroBIOS schemas and semantic invariants are valid.")
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
