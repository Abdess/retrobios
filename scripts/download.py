#!/usr/bin/env python3
"""Download BIOS packs from GitHub Releases.

Cross-platform tool (Linux/macOS/Windows) using only Python stdlib.

A pack over 2 GB is published as numbered volumes (`.zip.001`, `.zip.002`),
so a platform is a group of assets rather than a single one.

Usage:
    python scripts/download.py --list                    # List platforms
    python scripts/download.py retroarch ~/path/         # Download pack
    python scripts/download.py --info retroarch          # Show pack info
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import compute_hashes, safe_extract_zip

DEFAULT_API = "https://api.github.com"
REPO = "Abdess/retrobios"
PACK_SUFFIX = "_BIOS_Pack.zip"
CHECKSUMS_ASSET = "SHA256SUMS.txt"
STAGING_DIR = ".retrobios-download"
MAX_CHECKSUMS_BYTES = 1 << 20
CHUNK = 1 << 20

_VOLUME_RE = re.compile(rf"^(?P<base>.+{re.escape(PACK_SUFFIX)})\.(?P<index>\d+)$")
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _checked_url(value: str, label: str) -> str:
    """Refuse a URL that is neither HTTPS nor loopback.

    This endpoint names the assets and, through them, the bytes that land in
    the BIOS directory, so it is the trust anchor of the whole download.
    Plain HTTP to loopback stays allowed: it is how this is tested end to end.
    """
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme == "https":
        return value.rstrip("/")
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "http" and host in _LOOPBACK_HOSTS:
        return value.rstrip("/")
    print(f"Error: {label} must use HTTPS, got {value!r}", file=sys.stderr)
    sys.exit(1)


API = _checked_url(os.environ.get("RETROBIOS_API", DEFAULT_API), "RETROBIOS_API")


@dataclass(frozen=True)
class Pack:
    """A platform pack: one asset, or the volumes it was split into."""

    name: str
    platform: str
    parts: tuple[dict, ...]
    size: int


def get_latest_release() -> dict:
    """Fetch latest release info from GitHub API."""
    url = f"{API}/repos/{REPO}/releases/latest"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "retrobios-downloader/1.0",
            "Accept": "application/vnd.github.v3+json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print("No releases found. The repository may not have any releases yet.")
            sys.exit(1)
        raise


def group_packs(release: dict) -> list[Pack]:
    """Group release assets into packs, volumes folded into their archive."""
    groups: dict[str, list[tuple[int, dict]]] = {}
    for asset in release.get("assets", []):
        name = asset["name"]
        volume = _VOLUME_RE.match(name)
        if volume:
            groups.setdefault(volume["base"], []).append((int(volume["index"]), asset))
        elif name.endswith(PACK_SUFFIX):
            groups.setdefault(name, []).append((0, asset))

    packs = []
    for base, volumes in sorted(groups.items()):
        parts = tuple(asset for _, asset in sorted(volumes, key=lambda v: v[0]))
        packs.append(
            Pack(
                name=base,
                platform=base[: -len(PACK_SUFFIX)].replace("_", " "),
                parts=parts,
                size=sum(part.get("size", 0) for part in parts),
            )
        )
    return packs


def list_platforms(release: dict) -> list[str]:
    """List available platform packs from release assets."""
    return sorted(pack.platform for pack in group_packs(release))


def _match_key(value: str) -> str:
    """Letters and digits only: the platform is `misterfpga`, the asset MiSTer_FPGA."""
    return re.sub(r"[^a-z0-9]", "", value.lower())


def find_pack(release: dict, platform: str) -> Pack | None:
    """Find the pack for a platform name."""
    needle = _match_key(platform)
    if not needle:
        return None
    for pack in group_packs(release):
        if needle in _match_key(pack.name):
            return pack
    return None


def fetch_checksums(release: dict) -> dict[str, str]:
    """Read the published SHA-256 of each pack, keyed by archive name."""
    for asset in release.get("assets", []):
        if asset["name"] != CHECKSUMS_ASSET:
            continue
        url = _checked_url(asset["browser_download_url"], "asset URL")
        req = urllib.request.Request(
            url, headers={"User-Agent": "retrobios-downloader/1.0"}
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read(MAX_CHECKSUMS_BYTES).decode("utf-8", "replace")
        sums = {}
        for line in body.splitlines():
            digest, _, name = line.strip().partition("  ")
            if digest and name:
                sums[name] = digest.lower()
        return sums
    return {}


def download_file(url: str, dest: Path, expected_size: int = 0, label: str = ""):
    """Download a file with progress indication."""
    url = _checked_url(url, "asset URL")
    req = urllib.request.Request(
        url, headers={"User-Agent": "retrobios-downloader/1.0"}
    )

    with urllib.request.urlopen(req, timeout=300) as resp:
        total = int(resp.headers.get("Content-Length", expected_size))
        downloaded = 0

        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)

                if total > 0:
                    pct = downloaded * 100 // total
                    bar = "=" * (pct // 2) + " " * (50 - pct // 2)
                    print(
                        f"\r  {label}[{bar}] {pct}% ({downloaded:,}/{total:,})",
                        end="",
                        flush=True,
                    )

    print()
    if expected_size and downloaded != expected_size:
        raise ValueError(f"downloaded {downloaded} bytes; expected {expected_size}")


def join_volumes(parts: list[Path], dest: Path) -> None:
    """Concatenate split volumes into one archive, streaming."""
    with open(dest, "wb") as out:
        for part in parts:
            with open(part, "rb") as src:
                shutil.copyfileobj(src, out, CHUNK)


def fetch_pack(pack: Pack, staging: Path, checksums: dict[str, str]) -> Path:
    """Download every volume of a pack and return the assembled archive."""
    staging.mkdir(parents=True, exist_ok=True)
    volumes = []
    for index, part in enumerate(pack.parts, start=1):
        label = f"part {index}/{len(pack.parts)} " if len(pack.parts) > 1 else ""
        target = staging / part["name"]
        print(f"Downloading {part['name']} ({part.get('size', 0):,} bytes)...")
        download_file(part["browser_download_url"], target, part.get("size", 0), label)
        volumes.append(target)

    archive = staging / pack.name
    if volumes != [archive]:
        if len(volumes) > 1:
            print(f"Joining {len(volumes)} parts into {pack.name}...")
            join_volumes(volumes, archive)
            for volume in volumes:
                volume.unlink()
        else:
            volumes[0].replace(archive)

    expected = checksums.get(pack.name)
    if expected:
        print("Checking the archive...")
        actual = compute_hashes(str(archive))["sha256"].lower()
        if actual != expected:
            archive.unlink()
            print(
                f"Error: checksum mismatch for {pack.name}\n"
                f"  expected {expected}\n  got      {actual}\n"
                "Download the parts again; a truncated part gives this.",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        print(f"No {CHECKSUMS_ASSET} in the release, skipping the checksum.")
    return archive


def show_info(platform: str, release: dict):
    """Show pack information for a platform."""
    pack = find_pack(release, platform)
    if not pack:
        print(f"Platform '{platform}' not found in release")
        return

    print(f"  Platform: {pack.platform}")
    print(f"  File: {pack.name}")
    print(f"  Parts: {len(pack.parts)} part{'s' if len(pack.parts) > 1 else ''}")
    print(f"  Size: {pack.size:,} bytes ({pack.size / (1024 * 1024):.1f} MB)")
    for part in pack.parts:
        print(f"    {part['name']} ({part.get('size', 0):,} bytes)")


def main():
    parser = argparse.ArgumentParser(
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
    args = parser.parse_args()

    if args.list:
        try:
            release = get_latest_release()
            platforms = list_platforms(release)
            if platforms:
                print("Available platforms:")
                for p in platforms:
                    print(f"  - {p}")
            else:
                print("No platform packs found in latest release")
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            OSError,
            json.JSONDecodeError,
        ) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return

    if not args.platform:
        parser.error("Platform name required (use --list to see options)")

    try:
        release = get_latest_release()
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        print(f"Error fetching release info: {e}", file=sys.stderr)
        sys.exit(1)

    if args.info:
        show_info(args.platform, release)
        return

    if not args.dest:
        parser.error("Destination directory required")

    pack = find_pack(release, args.platform)
    if not pack:
        print(f"Platform '{args.platform}' not found in release.")
        print("Available:", ", ".join(list_platforms(release)))
        sys.exit(1)

    dest = Path(os.path.expanduser(args.dest))
    dest.mkdir(parents=True, exist_ok=True)

    # Staged inside the destination: a pack is gigabytes, and that is the
    # filesystem the user picked for them. The system temp directory is a RAM
    # disk on the appliances these packs target.
    staging = dest / STAGING_DIR
    try:
        archive = fetch_pack(pack, staging, fetch_checksums(release))
        print(f"Extracting to {dest}/...")
        safe_extract_zip(str(archive), str(dest))
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    print("Done!")


if __name__ == "__main__":
    main()
