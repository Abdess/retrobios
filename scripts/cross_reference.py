#!/usr/bin/env python3
"""Cross-reference emulator profiles against platform configs.

Identifies BIOS files that emulators need but platforms don't declare,
providing gap analysis for extended coverage.

Usage:
    python scripts/cross_reference.py
    python scripts/cross_reference.py --emulator dolphin
    python scripts/cross_reference.py --json
    python scripts/cross_reference.py --platform retroarch --target switch
    python scripts/cross_reference.py --all --target switch
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from core.cli import add_repo_inputs
from model.cliargs import platform_arg
from model.safeparse import require_yaml

from packs.crossrefreport import run_gap_report

yaml = require_yaml()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Emulator vs platform gap analysis")
    add_repo_inputs(parser, "emulators", "platforms", "db")
    parser.add_argument("--emulator", "-e", help="Analyze single emulator")
    parser.add_argument(
        "--platform", "-p", type=platform_arg, help="Restrict analysis to one platform's cores"
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Analyze the emulators every platform runs (the default without --platform)",
    )
    parser.add_argument(
        "--target", "-t",
        help="Hardware target (e.g., switch, rpi4): with --platform, the cores built "
        "for it there, otherwise the cores each platform with the target builds for it",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--list-emulators", action="store_true", help="List available emulators"
    )
    return parser


def main() -> None:
    parser = build_parser()
    run_gap_report(parser.parse_args(), parser)


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
