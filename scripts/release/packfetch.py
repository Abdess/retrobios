"""A platform pack downloaded into a staging directory, joined and checked."""

from __future__ import annotations

import shutil
import tempfile
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from core.hashing import compute_hashes, parse_sha256sums
from core.upstream import open_retrying
from release.downloaderror import DownloadError
from release.latest import checked_url
from release.transfer import TRANSFER_ERRORS, download_file

if TYPE_CHECKING:
    from collections.abc import Callable

    from release.packgroups import Pack

CHECKSUMS_ASSET = "SHA256SUMS.txt"
STAGING_PREFIX = ".retrobios-download-"
MAX_CHECKSUMS_BYTES = 1 << 20
CHUNK = 1 << 20


class Meter(Protocol):
    """What draws a part's progress: the command's own presentation."""

    def start(self, label: str) -> None: ...

    def update(self, done: int, total: int) -> None: ...

    def finish(self) -> None: ...


def fetch_checksums(release: dict) -> dict[str, str]:
    """Read the published SHA-256 of each pack, keyed by archive name."""
    for asset in release.get("assets", []):
        if asset["name"] != CHECKSUMS_ASSET:
            continue
        url = checked_url(asset["browser_download_url"], "asset URL")
        req = urllib.request.Request(
            url, headers={"User-Agent": "retrobios-downloader/1.0"}
        )
        try:
            raw = open_retrying(req, lambda resp: resp.read(MAX_CHECKSUMS_BYTES), 60)
        except TRANSFER_ERRORS as exc:
            raise DownloadError(f"Error: reading {CHECKSUMS_ASSET} failed: {exc}") from exc
        body = raw.decode("utf-8", "replace")
        # A file that is not sha256sum output refuses the download: read
        # leniently, a `*name` line matched nothing and the pack went
        # unchecked.
        try:
            return parse_sha256sums(body)
        except ValueError as exc:
            raise DownloadError(f"ERROR: {CHECKSUMS_ASSET}: {exc}") from exc
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


def _check(archive: Path, checksums: dict[str, str], say: Callable[[str], None]) -> None:
    """Compare a downloaded file with its published SHA-256, when there is one."""
    expected = checksums.get(archive.name)
    if not expected:
        say(f"No checksum published for {archive.name}, skipping.")
        return
    say(f"Checking {archive.name}...")
    actual = compute_hashes(str(archive))["sha256"].lower()
    if actual != expected:
        archive.unlink()
        raise DownloadError(
            f"Error: checksum mismatch for {archive.name}\n"
            f"  expected {expected}\n  got      {actual}\n"
            "Download the parts again: a truncated part gives this."
        )


def _download_part(part: dict, target: Path, label: str, meter: Meter | None) -> None:
    """Download one part, its progress drawn by *meter* when there is one."""
    url, size = part["browser_download_url"], part.get("size", 0)
    if meter is None:
        download_file(url, target, size)
        return
    meter.start(label)
    try:
        download_file(url, target, size, meter.update)
    finally:
        meter.finish()


def fetch_pack(
    pack: Pack,
    staging: Path,
    checksums: dict[str, str],
    say: Callable[[str], None],
    meter: Meter | None = None,
) -> list[Path]:
    """Download a pack and return the archives to extract, each one checked.

    Each progress line goes to *say*, each part's byte count to *meter*, and
    a failure raises DownloadError.
    """
    if len(pack.parts) != pack.expected_parts:
        raise DownloadError(
            f"Error: the release lists {len(pack.parts)} of "
            f"{pack.expected_parts} parts of {pack.name}."
        )
    staging.mkdir(parents=True, exist_ok=True)
    volumes = []
    for index, part in enumerate(pack.parts, start=1):
        label = f"part {index}/{len(pack.parts)} " if len(pack.parts) > 1 else ""
        target = staging / part["name"]
        say(f"Downloading {part['name']} ({part.get('size', 0):,} bytes)...")
        _download_part(part, target, label, meter)
        volumes.append(target)

    if pack.joined:
        archive = staging / pack.name
        say(f"Joining {len(volumes)} parts into {pack.name}...")
        join_volumes(volumes, archive)
        for volume in volumes:
            volume.unlink()
        volumes = [archive]

    if not checksums:
        say(f"No {CHECKSUMS_ASSET} in the release, skipping the checksum.")
        return volumes
    for archive in volumes:
        _check(archive, checksums, say)
    return volumes
