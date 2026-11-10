#!/usr/bin/env python3
"""Compare a dated release with release.json and the checksum list.

Run on the draft before publishing it, and on the published release at any
time. Every pack asset release.json names must be on the release at the sha256
SHA256SUMS.txt lists for it, as must each handheld launcher (RetroBIOS.zip
and the others build_port.py writes) the list names, the parts of a pack must add up to the download
size the README prints, and nothing else may be attached. The record holds
one pack for each platform the registry marks release_pack, and no other
pack. The installer and the file lists are not release files: a package pins
them from the tag, so a reader of the release page sees the packs and nothing
to puzzle over. An upload that
failed in the loop, or a part re-uploaded from an older build, otherwise
publishes a release that `sha256sum --check` rejects for every user.

Usage:
    python scripts/check_release.py                        # the tag release.json records
    python scripts/check_release.py --tag v2026.10.10 --sums dist/SHA256SUMS.txt
    python scripts/check_release.py --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from build_port import ARCHIVES
from check_release_assets import digests_of
from common import list_release_pack_platforms, require_directory
from largefiles import LARGE_FILES_REPO
from release_record import RECORD, load_record

SUMS = "SHA256SUMS.txt"
SIGNATURE = SUMS + ".sig"
@dataclass(frozen=True)
class Asset:
    size: int
    sha256: str | None


@dataclass(frozen=True)
class Finding:
    kind: str
    name: str
    detail: str


def parse_sums(text: str) -> dict[str, str]:
    """`sha256sum` output: digest, then a space and a mode character."""
    sums: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        digest, _, name = line.partition(" ")
        if len(digest) != 64 or not name:
            raise ValueError(f"not a sha256sum line: {line!r}")
        sums[name.lstrip(" *")] = digest.lower()
    return sums


def compare_release(
    record: dict,
    sums: dict[str, str],
    assets: dict[str, Asset],
    tag: str,
    local_files: dict[str, str] | None = None,
    released: set[str] | None = None,
) -> list[Finding]:
    """Every way the release can differ from what was built.

    *local_files* maps a file kept beside the packs (the checksum list, its
    signature) to its local sha256: the copy on the release must be that one.
    *released* names the platforms the registry marks release_pack: each one
    has a recorded pack, and no recorded pack serves only other platforms.
    """
    findings: list[Finding] = []
    if record.get("tag") != tag:
        findings.append(Finding("tag", tag, f"release.json records {record.get('tag')}"))
    if released is not None:
        packs = record.get("packs", {})
        served = {p for pack in packs.values() for p in pack.get("platforms", ())}
        for platform in sorted(released - served):
            findings.append(Finding(
                "no-pack", platform, "release_pack: true, no pack in release.json"
            ))
        for pack_name, pack in sorted(packs.items()):
            if not set(pack.get("platforms", ())) & released:
                findings.append(Finding(
                    "not-released", pack_name,
                    "serves no platform marked release_pack in platforms/_registry.yml",
                ))

    recorded = {
        name: pack_name
        for pack_name, pack in record.get("packs", {}).items()
        for name in pack.get("assets", [])
    }
    expected = set(recorded) | set(sums) | {SUMS} | set(local_files or ())
    allowed = expected | {SIGNATURE}

    for name in sorted(expected - set(assets)):
        findings.append(Finding("missing", name, "not attached to the release"))
    for name in sorted(set(assets) - allowed):
        findings.append(Finding("extra", name, "attached but neither recorded nor listed"))
    for name in sorted(set(recorded) - set(sums)):
        findings.append(Finding("unlisted", name, f"absent from {SUMS}"))
    # The handheld launchers are release files but no packs: release.json
    # records packs, and the checksum list alone vouches for the launchers.
    for name in sorted(set(sums) - set(recorded) - set(ARCHIVES)):
        findings.append(Finding("unrecorded", name, f"listed in {SUMS}, absent from release.json"))

    wanted = {**sums, **(local_files or {})}
    for name, digest in sorted(wanted.items()):
        asset = assets.get(name)
        if asset is None:
            continue
        if asset.sha256 is None:
            findings.append(Finding("unverified", name, "the release gives no sha256"))
        elif asset.sha256 != digest:
            findings.append(Finding(
                "content", name, f"release sha256 {asset.sha256[:12]} != {digest[:12]}"
            ))

    for pack_name, pack in sorted(record.get("packs", {}).items()):
        parts = [assets[name].size for name in pack.get("assets", []) if name in assets]
        if len(parts) == len(pack.get("assets", [])) and sum(parts) != pack.get("download_size"):
            findings.append(Finding(
                "size", pack_name,
                f"assets total {sum(parts)} bytes, release.json says {pack.get('download_size')}",
            ))
    return findings


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_assets(tag: str) -> tuple[dict[str, Asset], bool]:
    """Name, size and sha256 of every asset of *tag*, and whether it is a draft."""
    result = subprocess.run(
        ["gh", "release", "view", tag, "-R", LARGE_FILES_REPO, "--json", "assets,isDraft"],
        capture_output=True, text=True, check=True,
    )
    data = json.loads(result.stdout)
    digests = digests_of(data["assets"])
    return (
        {a["name"]: Asset(a["size"], digests.get(a["name"])) for a in data["assets"]},
        bool(data.get("isDraft")),
    )


def fetch_sums(tag: str) -> str:
    """The checksum list as attached to *tag*."""
    result = subprocess.run(
        ["gh", "release", "download", tag, "-R", LARGE_FILES_REPO,
         "--pattern", SUMS, "--output", "-"],
        capture_output=True, text=True, check=True,
    )
    return result.stdout


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
    from common import run_cli

    run_cli(main)
