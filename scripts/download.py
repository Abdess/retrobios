#!/usr/bin/env python3
"""Download BIOS packs from GitHub Releases.

Cross-platform tool (Linux/macOS/Windows) using only Python stdlib.

Usage:
    python scripts/download.py --list                    # List platforms
    python scripts/download.py retroarch ~/path/         # Download pack
    python scripts/download.py --verify retroarch ~/path # Verify local files
    python scripts/download.py --info retroarch          # Show coverage info
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request
import urllib.error
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import safe_extract_zip

GITHUB_API = "https://api.github.com"
REPO = "Abdess/retroarch_system"


def get_latest_release() -> dict:
    """Fetch latest release info from GitHub API."""
    url = f"{GITHUB_API}/repos/{REPO}/releases/latest"
    req = urllib.request.Request(url, headers={
        "User-Agent": "retrobios-downloader/1.0",
        "Accept": "application/vnd.github.v3+json",
    })

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print("No releases found. The repository may not have any releases yet.")
            sys.exit(1)
        raise


def list_platforms(release: dict) -> list[str]:
    """List available platform packs from release assets."""
    platforms = []
    for asset in release.get("assets", []):
        name = asset["name"]
        if name.endswith("_BIOS_Pack.zip"):
            platform = name.replace("_BIOS_Pack.zip", "").replace("_", " ")
            platforms.append(platform)
    return sorted(platforms)


def find_asset(release: dict, platform: str) -> dict | None:
    """Find the release asset for a specific platform."""
    normalized = platform.lower().replace(" ", "_").replace("-", "_")

    for asset in release.get("assets", []):
        asset_name = asset["name"].lower().replace(" ", "_").replace("-", "_")
        if normalized in asset_name and asset_name.endswith("_bios_pack.zip"):
            return asset

    return None


def download_file(url: str, dest: str, expected_size: int = 0):
    """Download a file with progress indication."""
    req = urllib.request.Request(url, headers={"User-Agent": "retrobios-downloader/1.0"})

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
                    print(f"\r  [{bar}] {pct}% ({downloaded:,}/{total:,})", end="", flush=True)

    print()


def extract_pack(zip_path: str, dest_dir: str):
    """Extract a BIOS pack ZIP to destination."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        members = zf.namelist()
        print(f"  Extracting {len(members)} files to {dest_dir}/")
    safe_extract_zip(zip_path, dest_dir)


def verify_files(platform: str, dest_dir: str, release: dict):
    """Verify local files against database.json from release."""
    db_asset = None
    for asset in release.get("assets", []):
        if asset["name"] == "database.json":
            db_asset = asset
            break

    if not db_asset:
        print("No database.json found in release assets. Cannot verify.")
        return

    import tempfile
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp.close()

    try:
        download_file(db_asset["browser_download_url"], tmp.name, db_asset.get("size", 0))
        with open(tmp.name) as f:
            db = json.load(f)
    finally:
        os.unlink(tmp.name)

    dest = Path(dest_dir)
    verified = 0
    missing = 0
    mismatched = 0

    for sha1, entry in db.get("files", {}).items():
        name = entry["name"]
        found = False
        for local_file in dest.rglob(name):
            if local_file.is_file():
                h = hashlib.sha1()
                with open(local_file, "rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        h.update(chunk)

                if h.hexdigest() == sha1:
                    verified += 1
                    found = True
                    break
                else:
                    mismatched += 1
                    print(f"  MISMATCH: {name} (expected {sha1[:12]}..., got {h.hexdigest()[:12]}...)")
                    found = True
                    break

        if not found:
            missing += 1

    total = verified + missing + mismatched
    print(f"\n  Verified: {verified}/{total}")
    if missing:
        print(f"  Missing: {missing}")
    if mismatched:
        print(f"  Mismatched: {mismatched}")


def show_info(platform: str, release: dict):
    """Show coverage information for a platform."""
    asset = find_asset(release, platform)
    if not asset:
        print(f"Platform '{platform}' not found in release")
        return

    print(f"  Platform: {platform}")
    print(f"  File: {asset['name']}")
    print(f"  Size: {asset['size']:,} bytes ({asset['size'] / (1024*1024):.1f} MB)")
    print(f"  Downloads: {asset.get('download_count', 'N/A')}")
    print(f"  Updated: {asset.get('updated_at', 'N/A')}")


def main():
    parser = argparse.ArgumentParser(
        description="Download BIOS packs from GitHub Releases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --list                       List available platforms
  %(prog)s retroarch ~/RetroArch/system  Download RetroArch pack
  %(prog)s --verify retroarch ~/path     Verify local files
  %(prog)s --info retroarch              Show pack info
        """,
    )
    parser.add_argument("platform", nargs="?", help="Platform name")
    parser.add_argument("dest", nargs="?", help="Destination directory")
    parser.add_argument("--list", action="store_true", help="List available platforms")
    parser.add_argument("--verify", action="store_true", help="Verify existing files")
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
        except Exception as e:
            print(f"Error: {e}")
        return

    if not args.platform:
        parser.error("Platform name required (use --list to see options)")

    try:
        release = get_latest_release()
    except Exception as e:
        print(f"Error fetching release info: {e}")
        sys.exit(1)

    if args.info:
        show_info(args.platform, release)
        return

    if args.verify:
        if not args.dest:
            parser.error("Destination directory required for --verify")
        verify_files(args.platform, args.dest, release)
        return

    if not args.dest:
        parser.error("Destination directory required")

    asset = find_asset(release, args.platform)
    if not asset:
        print(f"Platform '{args.platform}' not found in release.")
        print("Available:", ", ".join(list_platforms(release)))
        sys.exit(1)

    import tempfile
    zip_path = os.path.join(tempfile.gettempdir(), asset["name"])

    print(f"Downloading {asset['name']} ({asset['size']:,} bytes)...")
    download_file(asset["browser_download_url"], zip_path, asset["size"])

    dest = os.path.expanduser(args.dest)
    os.makedirs(dest, exist_ok=True)

    print(f"Extracting to {dest}/...")
    extract_pack(zip_path, dest)

    os.unlink(zip_path)
    print("Done!")


if __name__ == "__main__":
    main()
