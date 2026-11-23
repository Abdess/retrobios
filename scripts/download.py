#!/usr/bin/env python3
"""Download BIOS packs from GitHub Releases.

Cross-platform tool (Linux/macOS/Windows) using only Python stdlib.

A pack over the release asset limit is published in several files, so a
platform is a group of assets rather than a single one. The parts are each
a ZIP (`.part1of2.zip`), checked and extracted one after the other. Releases
up to v2026.09.04 carry byte ranges of one archive instead (`.zip.001`,
`.zip.002`), which are joined first.

Usage:
    python scripts/download.py --list                    # List platforms
    python scripts/download.py retroarch ~/path/         # Download pack
    python scripts/download.py --info retroarch          # Show pack info
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import shutil
import sys
import urllib.error
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from core.paths import REPO_ROOT
from core.upstream import UpstreamError
from core.ziptools import safe_extract_zip
from model.releaserecord import RECORD, load_record
from release.downloaderror import DownloadError
from release.latest import DEFAULT_API, checked_url, get_latest_release
from release.packfetch import fetch_checksums, fetch_pack, make_staging
from release.packgroups import find_pack, list_platforms
from release.packinfo import exit_without_pack, show_info
from release.progressbar import ProgressBar

FETCH_ERRORS = (
    urllib.error.URLError, OSError, http.client.HTTPException, UpstreamError,
    json.JSONDecodeError,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Download BIOS packs from GitHub Releases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --list                       List available platforms
  %(prog)s retroarch ~/RetroArch/system  Download RetroArch pack
  %(prog)s --info retroarch              Show pack info

To check files already in place, use: python install.py --check
        """,
    )
    parser.add_argument("platform", nargs="?", help="Platform name")
    parser.add_argument("dest", nargs="?", help="Destination directory")
    parser.add_argument("--list", action="store_true", help="List available platforms")
    parser.add_argument("--info", action="store_true", help="Show platform info")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        api = checked_url(os.environ.get("RETROBIOS_API", DEFAULT_API), "RETROBIOS_API")

        if args.list:
            try:
                platforms = list_platforms(get_latest_release(api))
            except FETCH_ERRORS as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
            if platforms:
                print("Available platforms:")
                for p in platforms:
                    print(f"  - {p}")
            else:
                print("No platform packs found in latest release")
            return

        if not args.platform:
            parser.error("Platform name required (use --list to see options)")

        try:
            release = get_latest_release(api)
        except FETCH_ERRORS as e:
            print(f"Error fetching release info: {e}", file=sys.stderr)
            sys.exit(1)

        record = load_record(REPO_ROOT / RECORD)
        if args.info:
            show_info(args.platform, release, record)
            return

        if not args.dest:
            parser.error("Destination directory required")

        pack = find_pack(release, args.platform, record)
        if not pack:
            exit_without_pack(args.platform, release)

        dest = Path(os.path.expanduser(args.dest))
        dest.mkdir(parents=True, exist_ok=True)

        staging = make_staging(dest)
        try:
            archives = fetch_pack(
                pack, staging, fetch_checksums(release), print, ProgressBar()
            )
            print(f"Extracting to {dest}/...")
            for archive in archives:
                safe_extract_zip(str(archive), str(dest))
        finally:
            shutil.rmtree(staging, ignore_errors=True)
    except DownloadError as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
    print("Done!")


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
