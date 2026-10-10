#!/usr/bin/env python3
"""Record what the packs of a release hold.

The README and the site print, beside each download link, how many files a
pack holds and what they weigh once extracted. Those figures have to be the
ones of the release the link serves. Read from the install manifests they
described what main would build today, and drifted from the published pack
with every commit made since the release.

The record is written from the archives themselves when a release is cut,
committed with it, and read by the generators.

Usage:
    python scripts/release_record.py dist/ --tag v2026.10.04
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path

import split_pack
from common import ArtifactLockBusy, artifact_lock, write_text_atomic

RECORD = "release.json"


def _match_key(value: str) -> str:
    """Letters and digits only: the platform is `misterfpga`, the pack MiSTer_FPGA."""
    return re.sub(r"[^a-z0-9]", "", value.lower())


class UnfinishedSplit(Exception):
    """A pack lies beside its own parts: a split is running or was killed."""


def build_record(dist: Path, tag: str) -> dict:
    """Read every pack of a directory, parts counted once across them.

    Read under the shared artifact lock, so a split that is reading its parts
    back cannot be recorded half done. A pack still beside its parts after
    that is a split that never finished: summed, it doubled the download size
    and named an asset that is never published.
    """
    with artifact_lock(str(dist), exclusive=False):
        return _read_record(Path(dist), tag)


def _read_record(dist: Path, tag: str) -> dict:
    assets: dict[str, list[Path]] = {}
    for path in sorted(dist.glob("*_BIOS_Pack*.zip")):
        assets.setdefault(split_pack.pack_of(path.name), []).append(path)
    for name, paths in sorted(assets.items()):
        whole = [p for p in paths if not split_pack.is_part(p.name)]
        if whole and len(paths) > len(whole):
            raise UnfinishedSplit(
                f"{whole[0].name} lies beside its parts: the split did not finish"
            )

    packs = {}
    for name, paths in sorted(assets.items()):
        members: dict[str, int] = {}
        for path in paths:
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    members[info.filename] = info.file_size
        packs[name] = {
            "files": len(members),
            "extracted_size": sum(members.values()),
            "download_size": sum(path.stat().st_size for path in paths),
            "assets": [path.name for path in paths],
        }
    return {"tag": tag, "packs": packs}


def load_record(path: str | Path = RECORD) -> dict:
    """The committed record, empty when no release has written one."""
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}


def pack_for(platform: str, record: dict) -> dict | None:
    """The pack of the release that serves a platform, if it has one."""
    needle = _match_key(platform)
    if not needle:
        return None
    for name, pack in sorted(record.get("packs", {}).items()):
        if needle in _match_key(name):
            return pack
    return None


def manifest_mismatches(record: dict, install_dir: str | Path) -> list[str]:
    """Packs whose archive does not hold what their install manifest expects."""
    found = []
    for manifest_path in sorted(Path(install_dir).glob("*.json")):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = manifest.get("pack_files")
        if expected is None:
            continue
        for name, pack in sorted(record.get("packs", {}).items()):
            if _match_key(manifest_path.stem) not in _match_key(name):
                continue
            if pack["files"] != expected:
                found.append(
                    f"{name} holds {pack['files']} files, "
                    f"install/{manifest_path.name} expects {expected}"
                )
            break
    return found


def _size(count: int) -> str:
    if count >= 1024**3:
        return f"{count / 1024**3:.1f} GB"
    return f"{count / 1024**2:.0f} MB"


def main() -> int:
    parser = argparse.ArgumentParser(description="Record what a release's packs hold")
    parser.add_argument("dist", type=Path, help="directory of the packs to publish")
    parser.add_argument("--tag", required=True, help="release tag, e.g. v2026.10.04")
    parser.add_argument("--install-dir", default="install", type=Path)
    parser.add_argument("--output", default=RECORD, type=Path)
    args = parser.parse_args()

    try:
        record = build_record(args.dist, args.tag)
    except (UnfinishedSplit, ArtifactLockBusy) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if not record["packs"]:
        print(f"Error: no pack in {args.dist}", file=sys.stderr)
        return 1
    for name, pack in record["packs"].items():
        print(
            f"{name:<44} download {_size(pack['download_size']):>8}"
            f"   extracted {_size(pack['extracted_size']):>8}"
            f"   {pack['files']:,} files   {len(pack['assets'])} asset(s)"
        )
    mismatches = manifest_mismatches(record, args.install_dir)
    for line in mismatches:
        print(f"Error: {line}", file=sys.stderr)
    if mismatches:
        return 1
    write_text_atomic(str(args.output), json.dumps(record, indent=2) + "\n")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
