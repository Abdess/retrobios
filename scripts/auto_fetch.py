#!/usr/bin/env python3
"""Auto-fetch missing BIOS files from multiple sources.

Pipeline:
1. Cross-reference database.json (already exists under different name/path?)
2. Scan old branches (git show origin/branch:path)
3. Search public BIOS repos on GitHub
4. Search archive.org collections
5. Create GitHub Issue for community help

Usage:
    python scripts/auto_fetch.py --platform retroarch [--dry-run]
    python scripts/auto_fetch.py --all [--dry-run]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import list_registered_platforms, load_database, load_platform_config

try:
    import yaml
except ImportError:
    print("Error: PyYAML required (pip install pyyaml)", file=sys.stderr)
    sys.exit(1)

DEFAULT_DB = "database.json"
DEFAULT_PLATFORMS_DIR = "platforms"
DEFAULT_BIOS_DIR = "bios"

MAX_DOWNLOAD = 100 * 1024 * 1024  # 100MB per file

LEGACY_BRANCHES = ["libretro", "RetroArch", "RetroPie", "Recalbox", "batocera", "Other"]

PUBLIC_REPOS = [
    # archtaurus/RetroPieBIOS - most complete verified collection
    "https://raw.githubusercontent.com/archtaurus/RetroPieBIOS/master/BIOS/{name}",
    "https://raw.githubusercontent.com/archtaurus/RetroPieBIOS/master/BIOS/pcsx2/bios/{name}",
    "https://raw.githubusercontent.com/archtaurus/RetroPieBIOS/master/BIOS/ep128emu/roms/{name}",
    "https://raw.githubusercontent.com/archtaurus/RetroPieBIOS/master/BIOS/fuse/{name}",
    # prefetchnta/retroarch-bios - alternative verified collection
    "https://raw.githubusercontent.com/prefetchnta/retroarch-bios/main/system/{name}",
    "https://raw.githubusercontent.com/prefetchnta/retroarch-bios/main/system/pcsx2/bios/{name}",
    # BatoceraPLUS - Batocera-specific
    "https://raw.githubusercontent.com/BatoceraPLUS/Batocera.PLUS-bios/main/{name}",
]

ARCHIVE_ORG_COLLECTIONS = [
    "RetroarchSystemFiles",
    "retroarch_bios",
    "retroarch-ultimate-bios-pack_20250824",
    "system_20240621",
    "full-pack-bios-batocera-39",
]


def find_missing(config: dict, db: dict) -> list[dict]:
    """Find BIOS files required by platform but not in database."""
    missing = []

    for sys_id, system in config.get("systems", {}).items():
        for file_entry in system.get("files", []):
            storage = file_entry.get("storage", "embedded")
            if storage != "embedded":
                continue

            sha1 = file_entry.get("sha1")
            md5 = file_entry.get("md5")
            name = file_entry.get("name", "")

            found = False
            if sha1 and sha1 in db.get("files", {}):
                found = True
            elif md5:
                by_md5 = db.get("indexes", {}).get("by_md5", {})
                md5_list = [m.strip() for m in md5.split(",") if m.strip()]
                found = any(m in by_md5 for m in md5_list)

            if not found:
                missing.append({
                    "name": name,
                    "system": sys_id,
                    "sha1": sha1,
                    "md5": md5,
                    "size": file_entry.get("size"),
                    "destination": file_entry.get("destination", name),
                })

    return missing


def verify_content(data: bytes, expected: dict) -> bool:
    """Verify downloaded content matches expected hashes."""
    if expected.get("sha1"):
        actual = hashlib.sha1(data).hexdigest()
        return actual == expected["sha1"]
    if expected.get("md5"):
        actual = hashlib.md5(data).hexdigest()
        return actual == expected["md5"]
    return False


def _read_limited(resp, limit: int = MAX_DOWNLOAD) -> bytes | None:
    """Read response up to limit bytes. Returns None if exceeded."""
    data = resp.read(limit + 1)
    if len(data) > limit:
        return None
    return data


def step1_crossref_db(entry: dict, db: dict) -> str | None:
    """Check if file exists under different name/path in database."""
    sha1 = entry.get("sha1")
    md5 = entry.get("md5")

    if sha1 and sha1 in db.get("files", {}):
        return db["files"][sha1]["path"]

    if md5:
        sha1_match = db.get("indexes", {}).get("by_md5", {}).get(md5)
        if sha1_match and sha1_match in db["files"]:
            return db["files"][sha1_match]["path"]

    return None


def step2_scan_branches(entry: dict) -> bytes | None:
    """Search old git branches for the file by hash."""
    name = entry["name"]

    for branch in LEGACY_BRANCHES:
        ref = f"origin/{branch}"
        try:
            subprocess.run(
                ["git", "rev-parse", "--verify", ref],
                capture_output=True, check=True,
            )
        except subprocess.CalledProcessError:
            continue

        result = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", ref],
            capture_output=True, text=True,
        )

        for filepath in result.stdout.strip().split("\n"):
            if os.path.basename(filepath) == name:
                try:
                    blob = subprocess.run(
                        ["git", "show", f"{ref}:{filepath}"],
                        capture_output=True, check=True,
                    )
                    if verify_content(blob.stdout, entry):
                        return blob.stdout
                except subprocess.CalledProcessError:
                    continue

    return None


def step3_search_public_repos(entry: dict) -> bytes | None:
    """Search public GitHub BIOS repos."""
    name = entry["name"]
    destination = entry.get("destination", name)

    for url_template in PUBLIC_REPOS:
        url = url_template.format(name=name)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "retrobios-fetch/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = _read_limited(resp)
                if data is None:
                    continue
                if verify_content(data, entry):
                    return data
        except (urllib.error.URLError, urllib.error.HTTPError):
            continue

        if "/" in destination:
            url = url_template.format(name=destination)
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "retrobios-fetch/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = _read_limited(resp)
                    if data is None:
                        continue
                    if verify_content(data, entry):
                        return data
            except (urllib.error.URLError, urllib.error.HTTPError):
                continue

    return None


def step4_search_archive_org(entry: dict) -> bytes | None:
    """Search archive.org firmware collections by direct download."""
    name = entry["name"]

    for collection_id in ARCHIVE_ORG_COLLECTIONS:
        for path in [name, f"system/{name}", f"bios/{name}"]:
            url = f"https://archive.org/download/{collection_id}/{path}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "retrobios-fetch/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = _read_limited(resp)
                    if data is None:
                        continue
                    if verify_content(data, entry):
                        return data
            except (urllib.error.URLError, urllib.error.HTTPError):
                continue

    sha1 = entry.get("sha1", "")
    if not sha1:
        return None

    search_url = (
        f"https://archive.org/advancedsearch.php?"
        f"q=sha1:{sha1}&output=json&rows=1"
    )

    try:
        req = urllib.request.Request(search_url, headers={"User-Agent": "retrobios-fetch/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            docs = result.get("response", {}).get("docs", [])
            if docs:
                identifier = docs[0].get("identifier")
                if identifier:
                    dl_url = f"https://archive.org/download/{identifier}/{name}"
                    try:
                        req2 = urllib.request.Request(dl_url, headers={"User-Agent": "retrobios-fetch/1.0"})
                        with urllib.request.urlopen(req2, timeout=30) as resp2:
                            data = _read_limited(resp2)
                            if data is not None and verify_content(data, entry):
                                return data
                    except (urllib.error.URLError, urllib.error.HTTPError):
                        pass
    except (urllib.error.URLError, json.JSONDecodeError):
        pass

    return None


def place_file(data: bytes, entry: dict, bios_dir: str, db: dict) -> str:
    """Place a fetched BIOS file in the correct location."""
    name = os.path.basename(entry["name"])
    system = entry["system"]

    dest_dir = Path(bios_dir)

    for manufacturer_dir in dest_dir.iterdir():
        if not manufacturer_dir.is_dir():
            continue
        for console_dir in manufacturer_dir.iterdir():
            if not console_dir.is_dir():
                continue
            dir_path = f"{manufacturer_dir.name}/{console_dir.name}".lower()
            if any(part in dir_path for part in system.split("-") if len(part) > 2):
                dest = console_dir / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                with open(dest, "wb") as f:
                    f.write(data)
                return str(dest)

    dest = dest_dir / "Unknown" / system / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as f:
        f.write(data)
    return str(dest)


def fetch_missing(
    missing: list[dict],
    db: dict,
    bios_dir: str,
    dry_run: bool = False,
) -> dict:
    """Run the 5-step auto-fetch pipeline for missing files."""
    stats = {"found": 0, "not_found": 0, "errors": 0}
    still_missing = []

    for entry in missing:
        name = entry["name"]
        print(f"\n  Searching: {name} ({entry['system']})")

        existing = step1_crossref_db(entry, db)
        if existing:
            print(f"    [1] Found in database at: {existing}")
            stats["found"] += 1
            continue

        if dry_run:
            print(f"    [DRY RUN] Would search branches, repos, archive.org")
            still_missing.append(entry)
            stats["not_found"] += 1
            continue

        data = step2_scan_branches(entry)
        if data:
            path = place_file(data, entry, bios_dir, db)
            print(f"    [2] Found in branch, saved to: {path}")
            stats["found"] += 1
            continue

        data = step3_search_public_repos(entry)
        if data:
            path = place_file(data, entry, bios_dir, db)
            print(f"    [3] Found in public repo, saved to: {path}")
            stats["found"] += 1
            continue

        data = step4_search_archive_org(entry)
        if data:
            path = place_file(data, entry, bios_dir, db)
            print(f"    [4] Found on archive.org, saved to: {path}")
            stats["found"] += 1
            continue

        print(f"    [5] Not found - needs community contribution")
        still_missing.append(entry)
        stats["not_found"] += 1

    return {"stats": stats, "still_missing": still_missing}


def generate_issue_body(missing: list[dict], platform: str) -> str:
    """Generate a GitHub Issue body for missing BIOS files."""
    lines = [
        f"## Missing BIOS Files for {platform}",
        "",
        "The following BIOS files are required but not available in the repository.",
        "If you have any of these files, please submit a Pull Request!",
        "",
        "| File | System | SHA1 | MD5 |",
        "|------|--------|------|-----|",
    ]

    for entry in missing:
        sha1 = entry.get("sha1") or "N/A"
        md5 = entry.get("md5") or "N/A"
        lines.append(f"| `{entry['name']}` | {entry['system']} | `{sha1[:12]}...` | `{md5[:12]}...` |")

    lines.extend([
        "",
        "### How to Contribute",
        "",
        "1. Fork this repository",
        "2. Add the BIOS file to `bios/Manufacturer/Console/`",
        "3. Create a Pull Request - checksums are verified automatically",
    ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Auto-fetch missing BIOS files")
    parser.add_argument("--platform", "-p", help="Platform to check")
    parser.add_argument("--all", action="store_true", help="Check all platforms")
    parser.add_argument("--dry-run", action="store_true", help="Don't download, just report")
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--platforms-dir", default=DEFAULT_PLATFORMS_DIR)
    parser.add_argument("--bios-dir", default=DEFAULT_BIOS_DIR)
    parser.add_argument("--create-issues", action="store_true", help="Output GitHub Issue bodies")
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f"Error: {args.db} not found. Run generate_db.py first.", file=sys.stderr)
        sys.exit(1)

    db = load_database(args.db)

    if args.all:
        platforms = list_registered_platforms(
            args.platforms_dir, include_archived=True,
        )
    elif args.platform:
        platforms = [args.platform]
    else:
        parser.error("Specify --platform or --all")
        return

    all_still_missing = {}

    for platform in sorted(platforms):
        print(f"\n{'='*60}")
        print(f"Platform: {platform}")
        print(f"{'='*60}")

        try:
            config = load_platform_config(platform, args.platforms_dir)
        except FileNotFoundError:
            print(f"  Config not found, skipping")
            continue

        missing = find_missing(config, db)
        if not missing:
            print(f"  All BIOS files present!")
            continue

        print(f"  {len(missing)} missing files")
        result = fetch_missing(missing, db, args.bios_dir, args.dry_run)

        if result["still_missing"]:
            all_still_missing[platform] = result["still_missing"]

        stats = result["stats"]
        print(f"\n  Results: {stats['found']} found, {stats['not_found']} not found")

    if args.create_issues and all_still_missing:
        print(f"\n{'='*60}")
        print("GitHub Issue Bodies")
        print(f"{'='*60}")
        for platform, missing in all_still_missing.items():
            print(f"\n--- Issue for {platform} ---\n")
            print(generate_issue_body(missing, platform))


if __name__ == "__main__":
    main()
