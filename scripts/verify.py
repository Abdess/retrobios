#!/usr/bin/env python3
"""Platform-native BIOS verification engine.

Replicates the exact verification logic of each platform:
- RetroArch/Lakka/RetroPie: file existence only (core_info.c path_is_valid)
- Batocera: MD5 + checkInsideZip, no required distinction (batocera-systems:1062-1091)
- Recalbox: MD5 + mandatory/hashMatchMandatory, 3-color severity (Bios.cpp:109-130)
- RetroBat: same as Batocera
- EmuDeck: MD5 whitelist per system
- RetroDECK: MD5 per file via component manifests
- RomM: size + any hash, no ZIP inspection (firmware.py verify_file_hashes)
- ROCKNIX: MD5 + checkInsideZip with altmd5 (rocknix-systems checkBios)
- MiSTer FPGA: MD5 of the file at its destination, no ZIP inspection
- BizHawk: SHA1 firmware hash verification

Cross-references emulator profiles to detect undeclared files used by available cores.

Usage:
    python scripts/verify.py --all
    python scripts/verify.py --platform batocera
    python scripts/verify.py --all --json
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys


sys.path.insert(0, os.path.dirname(__file__))
from core.cli import add_emulator_selection, add_repo_inputs
from model.cliargs import platform_arg
from model.safeparse import require_yaml

from packs.verifyrun import run_verify

yaml = require_yaml()


def main() -> None:
    parser = build_parser()
    with contextlib.ExitStack() as held:
        run_verify(held, parser, parser.parse_args())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Platform-native BIOS verification")
    parser.add_argument("--platform", "-p", type=platform_arg, help="Platform name")
    parser.add_argument(
        "--all", action="store_true", help="Verify every registered platform"
    )
    add_emulator_selection(parser)
    parser.add_argument(
        "--list-platforms", action="store_true", help="List available platforms"
    )
    parser.add_argument("--target", "-t", help="Hardware target (e.g., switch, rpi4)")
    parser.add_argument(
        "--region", help="Region priority list, best first (e.g. us,eu,jp)"
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="List available targets for the platform",
    )
    parser.add_argument(
        "--no-game-data", action="store_true",
        help="Report on the pack built with --no-game-data: game data left "
        "out and named, firmware only",
    )
    parser.add_argument(
        "--required-only", action="store_true",
        help="Report on the pack built with --required-only: files the code "
        "runs without are left out",
    )
    add_repo_inputs(parser, "db", "platforms", "emulators")
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show emulator ground truth details",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--offline", action="store_true",
        help="Report as an offline build packs: a release asset the cache "
        "lacks is missing. Without it, it counts as fetched at build time",
    )
    parser.add_argument(
        "--destinations", metavar="FILE",
        help="With --platform or --all, also write the paths each pack holds "
        "according to this report to FILE (JSON), for comparison with the archive",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 on a required file missing: where the frontend checks "
        "hashes for a platform, without HLE for --emulator and --system. A file "
        "present with an unconfirmed hash is a warning, not a failure",
    )
    return parser


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
