#!/usr/bin/env python3
"""Compare a dated release with release.json and the checksum list.

Run on the draft before publishing it, and on the published release at any
time. Every pack asset release.json names must be on the release at the sha256
SHA256SUMS.txt lists for it, the parts of a pack must add up to the download
size the README prints, and nothing else may be attached. The record holds
one pack for each platform the registry marks release_pack, and no other
pack. The installer, the file lists and the handheld launchers are not
release files: a package pins the first two from the tag, and the site
serves the launchers built from its own commit (sitegen/handheld.py), so a
reader of the release page sees the packs and nothing to puzzle over. An upload that
failed in the loop, or a part re-uploaded from an older build, otherwise
publishes a release that `sha256sum --check` rejects for every user.

Usage:
    python scripts/check_release.py                        # the tag release.json records
    python scripts/check_release.py --tag v2026.10.10 --sums dist/SHA256SUMS.txt
    python scripts/check_release.py --json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from model.registry import list_release_pack_platforms
from core.cli import require_directory
from model.releaserecord import RECORD, load_record
from release.check import (
    SIGNATURE,
    SUMS,
    _sha256,
    compare_release,
    fetch_assets,
    fetch_sums,
    parse_sums,
)


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n")[0])
    parser.add_argument(
        "--record", default=str(RECORD),
        help="release record (release.json)",
    )
    parser.add_argument(
        "--tag",
        help="release to check (default: the tag the record names)",
    )
    parser.add_argument(
        "--sums", metavar="FILE",
        help=f"local {SUMS} the packs were listed in. Its copy and signature on "
        f"the release must be these files (default: the list attached to the release)",
    )
    parser.add_argument(
        "--platforms-dir", default="platforms",
        help="registry whose release_pack platforms each need a pack (default: %(default)s)",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()
    require_directory(args.platforms_dir, "--platforms-dir")

    record = load_record(args.record)
    tag = args.tag or record.get("tag")
    if not tag:
        print(f"ERROR: {args.record} names no tag, pass --tag", file=sys.stderr)
        return 2
    try:
        assets, draft = fetch_assets(tag)
        if args.sums:
            sums_path = Path(args.sums)
            sums_text = sums_path.read_text(encoding="utf-8")
            local_files = {SUMS: _sha256(sums_path)}
            signature = sums_path.with_name(SIGNATURE)
            if signature.is_file():
                local_files[SIGNATURE] = _sha256(signature)
        else:
            sums_text = fetch_sums(tag)
            local_files = {}
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: cannot read release {tag}: {exc.stderr.strip() or exc}", file=sys.stderr)
        return 2
    except (FileNotFoundError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    try:
        sums = parse_sums(sums_text)
    except ValueError as exc:
        print(f"ERROR: {SUMS}: {exc}", file=sys.stderr)
        return 2

    released = set(list_release_pack_platforms(args.platforms_dir))
    findings = compare_release(record, sums, assets, tag, local_files, released)
    if args.json:
        print(json.dumps(
            {"tag": tag, "draft": draft, "assets": len(assets),
             "findings": [vars(f) for f in findings]},
            indent=2,
        ))
    else:
        state = "draft" if draft else "published"
        print(f"{tag} ({state}): {len(assets)} assets, {len(sums)} listed in {SUMS}")
        for finding in findings:
            print(f"  {finding.kind.upper():<10} {finding.name}: {finding.detail}")
        if not findings:
            print("  every asset is the recorded file at its listed sha256")
    return 1 if findings else 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
