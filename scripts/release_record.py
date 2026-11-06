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
import sys
import zipfile
from pathlib import Path

import split_pack
from common import (
    ArtifactLockBusy,
    artifact_lock,
    list_release_pack_platforms,
    write_text_atomic,
)

RECORD = "release.json"
# The record's format, which release.schema.json pins: a reader holding the
# file alone can tell which shape it reads.
SCHEMA_VERSION = 1
# Each registered platform has a page at get/<platform>/ on the site: the
# current pack's files, or the command when no release publishes one. The
# address outlives every release, so a link written elsewhere keeps working.
GET_DIR = "get"


class UnfinishedSplitError(Exception):
    """A pack lies beside its own parts: a split is running or was killed."""


class NotAReleasePackError(Exception):
    """A pack in the directory is not the full pack of a registered platform."""


def release_owners(platforms_dir: str = "platforms") -> dict[str, list[str]]:
    """Full pack file name to the platforms it serves, as the builder names it.

    Rebuilt from the name builder, never matched by substring: matched by
    substring, RetroArch_v1.22.2_AndroidArm64V8A_BIOS_Pack.zip sorts before
    the full pack and was taken for the RetroArch pack. Only the platforms
    marked release_pack own a release pack.
    """
    import generate_pack

    platforms = list_release_pack_platforms(platforms_dir)
    owners: dict[str, list[str]] = {}
    for platform, names in generate_pack._expected_pack_names(
        platforms, platforms_dir, None, None
    ).items():
        for name in names:
            owners.setdefault(name, []).append(platform)
    return {name: sorted(serves) for name, serves in owners.items()}


def build_record(
    dist: Path,
    tag: str,
    platforms_dir: str = "platforms",
    owners: dict[str, list[str]] | None = None,
) -> dict:
    """Read every pack of a directory, parts counted once across them.

    Read under the shared artifact lock, so a split that is reading its parts
    back cannot be recorded half done. A pack still beside its parts after
    that is a split that never finished: summed, it doubled the download size
    and named an asset that is never published. Each pack carries the
    platforms it serves, so a reader finds a platform's pack by that list
    after a later version or grouping has renamed the pack main would build.
    """
    if owners is None:
        owners = release_owners(platforms_dir)
    with artifact_lock(str(dist), exclusive=False):
        return _read_record(Path(dist), tag, owners)


def _read_record(dist: Path, tag: str, owners: dict[str, list[str]]) -> dict:
    assets: dict[str, list[Path]] = {}
    for path in sorted(dist.glob("*_BIOS_Pack*.zip")):
        assets.setdefault(split_pack.pack_of(path.name), []).append(path)
    for paths in assets.values():
        whole = [p for p in paths if not split_pack.is_part(p.name)]
        if whole and len(paths) > len(whole):
            raise UnfinishedSplitError(
                f"{whole[0].name} lies beside its parts: the split did not finish"
            )
    foreign = sorted(name for name in assets if name not in owners)
    if foreign:
        raise NotAReleasePackError(
            f"not the full pack of a registered platform: {', '.join(foreign)}"
            " (a narrowed or older build left in the directory)"
        )

    packs = {}
    for name, paths in sorted(assets.items()):
        members: dict[str, int] = {}
        for path in paths:
            with zipfile.ZipFile(path) as archive:
                # A part's marker names its siblings and is not pack content:
                # the manifest's pack_files is counted before any split.
                for info in archive.infolist():
                    if not split_pack.is_marker(info.filename):
                        members[info.filename] = info.file_size
        packs[name] = {
            "files": len(members),
            "extracted_size": sum(members.values()),
            "download_size": sum(path.stat().st_size for path in paths),
            "assets": [path.name for path in paths],
            "platforms": owners[name],
        }
    return {"schema_version": SCHEMA_VERSION, "tag": tag, "packs": packs}


def load_record(path: str | Path = RECORD) -> dict:
    """The committed record, empty when no release has written one."""
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}


def get_page(platform: str, site: str = "") -> str:
    """The permanent download address of a platform, under *site*."""
    return f"{site}{GET_DIR}/{platform}/"


def advertised(record: dict, platforms_dir: str = "platforms") -> dict:
    """The record as the download tables show it: release_pack platforms only.

    A release cut before a platform lost its release_pack still holds that
    platform's pack. The tables follow the registry, so a platform left out
    is offered the command, and a pack two platforms shared names the one
    still released.
    """
    if not record:
        return {}
    released = set(list_release_pack_platforms(platforms_dir))
    packs = {}
    for name, pack in record.get("packs", {}).items():
        serves = [p for p in pack.get("platforms", ()) if p in released]
        if serves:
            packs[name] = {**pack, "platforms": serves}
    return {**record, "packs": packs}


def load_advertised(path: str | Path = RECORD, platforms_dir: str = "platforms") -> dict:
    """The committed record, reduced to the platforms a release publishes."""
    return advertised(load_record(path), platforms_dir)


def pack_name_for(platform: str, record: dict) -> str | None:
    """Name of the release pack that serves a platform, if it has one."""
    for name, pack in sorted(record.get("packs", {}).items()):
        if platform in pack.get("platforms", ()):
            return name
    return None


def pack_for(platform: str, record: dict) -> dict | None:
    """The pack of the release that serves a platform, if it has one."""
    name = pack_name_for(platform, record)
    return record["packs"][name] if name else None


def manifest_mismatches(record: dict, install_dir: str | Path) -> list[str]:
    """Packs whose archive does not hold what their install manifest expects."""
    found = []
    for manifest_path in sorted(Path(install_dir).glob("*.json")):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = manifest.get("pack_files")
        name = pack_name_for(manifest_path.stem, record)
        if expected is None or name is None:
            continue
        pack = record["packs"][name]
        if pack["files"] != expected:
            found.append(
                f"{name} holds {pack['files']} files, "
                f"install/{manifest_path.name} expects {expected}"
            )
    return found


def _size(count: int) -> str:
    if count >= 1024**3:
        return f"{count / 1024**3:.1f} GB"
    return f"{count / 1024**2:.0f} MB"


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Record what a release's packs hold")
    parser.add_argument("dist", type=Path, help="directory of the packs to publish")
    parser.add_argument("--tag", required=True, help="release tag, e.g. v2026.10.04")
    parser.add_argument(
        "--install-dir", default="install", type=Path,
        help="manifests the archives are compared with (default: %(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default="platforms",
        help="registry the pack names are rebuilt from (default: %(default)s)",
    )
    parser.add_argument(
        "--output", default=RECORD, type=Path,
        help="record to write (default: %(default)s)",
    )
    args = parser.parse_args()

    try:
        record = build_record(args.dist, args.tag, args.platforms_dir)
    except (UnfinishedSplitError, NotAReleasePackError, ArtifactLockBusy) as exc:
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
    from common import run_cli

    run_cli(main)
