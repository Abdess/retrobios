#!/usr/bin/env python3
"""Generate platform-specific BIOS ZIP packs.

Usage:
    python scripts/generate_pack.py --platform retroarch [--output-dir dist/]
    python scripts/generate_pack.py --all [--output-dir dist/]

Reads platform YAML config + database.json -> creates ZIP with correct
file layout for each platform. Handles inheritance, shared groups, variants,
and 3-tier storage (embedded/external/user_provided).
"""

from __future__ import annotations

import sys

# The README's first command. Under 3.8 it stopped on a SyntaxError that read
# like a damaged file. The build needs 3.9, as pipeline.py says.
if sys.version_info < (3, 9):
    sys.exit(f"generate_pack.py needs Python 3.9 or newer, this is {sys.version.split()[0]}")

import argparse
import contextlib
import os

sys.path.insert(0, os.path.dirname(__file__))
from core.artifacts import ArtifactLockBusy
from core.cli import add_emulator_selection, add_repo_inputs
from model.cliargs import platform_arg
from packs.archive import DamagedArchiveError
from packs import packmodes

DEFAULT_OUTPUT_DIR = "dist"


def main() -> None:
    with contextlib.ExitStack() as held:
        try:
            args = packmodes.run_pack_command(build_parser(), held)
        except (DamagedArchiveError, ArtifactLockBusy) as exc:
            # Emulator, system and hash modes have no per-platform loop to
            # report a damaged archive: the run stops with the file to
            # restore. A busy output directory refuses the run.
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(1)
    # A refresh refused by a quota left the PPSSPP pack with 2 files, exit 0:
    # a run written without a tree it carries is not complete.
    if args.uncached_trees:
        written = "manifests" if args.manifest else "packs"
        print(
            f"ERROR: {written} written without data directories that are not cached: "
            f"{', '.join(sorted(args.uncached_trees))} (run refresh_data_dirs.py)",
            file=sys.stderr,
        )
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    """The command line of generate_pack.py."""
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Generate platform BIOS ZIP packs")
    parser.add_argument(
        "--platform", "-p", type=platform_arg,
        help="Platform name (e.g., retroarch)",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Generate the release packs (release_pack in the registry), or with"
        " --manifest the install manifests of every platform",
    )
    add_emulator_selection(parser)
    add_repo_inputs(parser, "platforms", "db", "bios")
    parser.add_argument(
        "--output-dir", "-o", default=DEFAULT_OUTPUT_DIR,
        help="directory the packs and manifests go to (default: %(default)s)",
    )
    add_repo_inputs(parser, "emulators")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="No network at all: data directories and release assets come "
        "from the cache only, so a gitignored file never fetched is missing "
        "(--no-refresh-data keeps the trees as cached and still fetches assets)",
    )
    parser.add_argument(
        "--refresh-data",
        action="store_true",
        help="Force re-download all data directories",
    )
    parser.add_argument(
        "--no-refresh-data",
        action="store_true",
        help="Pack the data directories as cached, still fetching release assets",
    )
    # install.py's name. --list stays for the scripts that already type it.
    parser.add_argument(
        "--list-platforms", "--list", dest="list", action="store_true",
        help="List available platforms",
    )
    parser.add_argument(
        "--required-only",
        action="store_true",
        help="Only include required files, skip optional",
    )
    parser.add_argument(
        "--no-game-data",
        action="store_true",
        help="Leave out game data (the platform's entries a core reads as a "
        "game's files, and the cores' game data files): firmware only",
    )
    parser.add_argument(
        "--source",
        choices=["platform", "truth", "full"],
        default=None,
        help="File source: platform (YAML only), truth (emulator profiles), full "
             "(both, the default)",
    )
    parser.add_argument(
        "--all-variants",
        action="store_true",
        help="Generate all 6 source x required combinations",
    )
    parser.add_argument(
        "--split", action="store_true", help="Generate one ZIP per system/manufacturer"
    )
    parser.add_argument(
        "--group-by",
        choices=["system", "manufacturer"],
        default=None,
        help="Grouping for --split (default: system)",
    )
    parser.add_argument("--target", "-t", help="Hardware target (e.g., switch, rpi4)")
    parser.add_argument(
        "--region",
        help="Region priority list, best first (e.g. us,eu,jp)",
    )
    parser.add_argument(
        "--one-per-slot",
        action="store_true",
        help="Keep one BIOS per system and region where the core declares an order",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="List available targets for the platform",
    )
    parser.add_argument(
        "--from-md5",
        help="Hash(es) to look up or pack, comma-separated: CRC32, MD5, SHA-1 or SHA-256",
    )
    parser.add_argument(
        "--from-md5-file",
        help="File with hashes, one per line, alone or beside a file name as md5sum writes it",
    )
    parser.add_argument(
        "--manifest",
        action="store_true",
        help="Output JSON manifests instead of ZIP packs",
    )
    parser.add_argument(
        "--manifest-targets",
        action="store_true",
        help="Convert target YAMLs to installer JSON",
    )
    parser.add_argument(
        "--verify-packs",
        action="store_true",
        help="Extract and verify pack integrity (path + hash)",
    )
    return parser


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
