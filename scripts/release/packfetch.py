"""A platform pack downloaded into a staging directory, joined and checked."""

from __future__ import annotations

import shutil
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING

from core.hashing import compute_hashes, parse_sha256sums
from core.upstream import open_retrying
from release.latest import checked_url
from release.transfer import download_file

if TYPE_CHECKING:
    from release.packgroups import Pack

CHECKSUMS_ASSET = "SHA256SUMS.txt"
STAGING_PREFIX = ".retrobios-download-"
MAX_CHECKSUMS_BYTES = 1 << 20
CHUNK = 1 << 20


def fetch_checksums(release: dict) -> dict[str, str]:
    """Read the published SHA-256 of each pack, keyed by archive name."""
    for asset in release.get("assets", []):
        if asset["name"] != CHECKSUMS_ASSET:
            continue
        url = checked_url(asset["browser_download_url"], "asset URL")
        req = urllib.request.Request(
            url, headers={"User-Agent": "retrobios-downloader/1.0"}
        )
        body = open_retrying(
            req, lambda resp: resp.read(MAX_CHECKSUMS_BYTES), 60
        ).decode("utf-8", "replace")
        # A file that is not sha256sum output refuses the download: read
        # leniently, a `*name` line matched nothing and the pack went
        # unchecked.
        try:
            return parse_sha256sums(body)
        except ValueError as exc:
            raise SystemExit(f"ERROR: {CHECKSUMS_ASSET}: {exc}") from exc
    return {}


def join_volumes(parts: list[Path], dest: Path) -> None:
    """Concatenate split volumes into one archive, streaming."""
    with open(dest, "wb") as out:
        for part in parts:
            with open(part, "rb") as src:
                shutil.copyfileobj(src, out, CHUNK)


def make_staging(dest: Path) -> Path:
    """Return a staging directory of this run's own, on the destination volume.

    A pack is gigabytes and that is the filesystem the user picked for them:
    the system temp directory is a RAM disk on the appliances these packs
    target. The name is unique per run because two downloads into one BIOS
    folder used to share a fixed path, so whichever finished first removed the
    other's archive mid-transfer and the second died on the missing file with
    nothing installed.
    """
    return Path(tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=dest))


def _check(archive: Path, checksums: dict[str, str]) -> None:
    """Compare a downloaded file with its published SHA-256, when there is one."""
    expected = checksums.get(archive.name)
    if not expected:
        print(f"No checksum published for {archive.name}, skipping.")
        return
    print(f"Checking {archive.name}...")
    actual = compute_hashes(str(archive))["sha256"].lower()
    if actual != expected:
        archive.unlink()
        print(
            f"Error: checksum mismatch for {archive.name}\n"
            f"  expected {expected}\n  got      {actual}\n"
            "Download the parts again: a truncated part gives this.",
            file=sys.stderr,
        )
        sys.exit(1)


def fetch_pack(pack: Pack, staging: Path, checksums: dict[str, str]) -> list[Path]:
    """Download a pack and return the archives to extract, each one checked."""
    if len(pack.parts) != pack.expected_parts:
        print(
            f"Error: the release lists {len(pack.parts)} of "
            f"{pack.expected_parts} parts of {pack.name}.",
            file=sys.stderr,
        )
        sys.exit(1)
    staging.mkdir(parents=True, exist_ok=True)
    volumes = []
    for index, part in enumerate(pack.parts, start=1):
        label = f"part {index}/{len(pack.parts)} " if len(pack.parts) > 1 else ""
        target = staging / part["name"]
        print(f"Downloading {part['name']} ({part.get('size', 0):,} bytes)...")
        download_file(part["browser_download_url"], target, part.get("size", 0), label)
        volumes.append(target)

    if pack.joined:
        archive = staging / pack.name
        print(f"Joining {len(volumes)} parts into {pack.name}...")
        join_volumes(volumes, archive)
        for volume in volumes:
            volume.unlink()
        volumes = [archive]

    if not checksums:
        print(f"No {CHECKSUMS_ASSET} in the release, skipping the checksum.")
        return volumes
    for archive in volumes:
        _check(archive, checksums)
    return volumes
