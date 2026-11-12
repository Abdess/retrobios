#!/usr/bin/env python3
"""Auto-fetch missing BIOS files from multiple sources.

Pipeline:
1. Cross-reference database.json (already exists under different name/path?)
2. Scan old branches (git show origin/branch:path)
3. Search public BIOS repos on GitHub
4. Search archive.org collections
5. Print an issue body for the files still missing (--create-issues).
   It posts nothing.

Usage:
    python scripts/auto_fetch.py --platform retroarch [--dry-run]
    python scripts/auto_fetch.py --all [--dry-run]
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (
    platform_arg,
    require_directory,
    list_registered_platforms,
    load_database,
    load_platform_config,
    require_platform,
    require_yaml,
)

yaml = require_yaml()

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

# Software Heritage archives the source of every public forge, deleted
# repositories and rewritten histories included, and finds a file by its
# hash: a ROM once committed anywhere answers here even when no forge still
# serves it. Anonymous use allows 120 requests an hour.
SOFTWARE_HERITAGE = "https://archive.softwareheritage.org/api/1/content"

ARCHIVE_ORG_COLLECTIONS = [
    "RetroarchSystemFiles",
    "retroarch_bios",
    "retroarch-ultimate-bios-pack_20250824",
    "system_20240621",
    "full-pack-bios-batocera-39",
]


def find_missing(config: dict, db: dict) -> list[dict]:
    """Files the platform's own check or its cores' code would not find.

    Read from verify, the platform's native check: a hash or name lookup
    of our own called pc6001.zip and fmtowns.zip missing on Batocera, which
    checks them inside the zip and holds them, and saw none of the files
    the cores need that no platform lists.
    """
    from nativemode import reads_file_contents  # noqa: PLC0415
    from verify import Status, verify_platform  # noqa: PLC0415

    result = verify_platform(config, db)
    hashed = reads_file_contents(config.get("verification_mode", "existence"))
    wanted = {
        (d.get("system", ""), d.get("name", ""))
        for d in result["details"]
        if d["status"] == Status.MISSING or (hashed and d["status"] == Status.UNTESTED)
    }
    missing: list[dict] = []
    for sys_id, system in config.get("systems", {}).items():
        for file_entry in system.get("files", []):
            name = file_entry.get("name", "")
            if (sys_id, name) not in wanted:
                continue
            if file_entry.get("storage", "embedded") != "embedded":
                continue
            missing.append({
                "name": name,
                "system": sys_id,
                "sha1": file_entry.get("sha1"),
                "md5": file_entry.get("md5"),
                "sha256": file_entry.get("sha256"),
                "crc32": file_entry.get("crc32"),
                "size": file_entry.get("size"),
                "destination": file_entry.get("destination", name),
            })
    for u in result["undeclared_files"]:
        # A file installed with its emulator is not an acquisition target:
        # verify leaves it out of the missing count, and bundled_only.py
        # --strict refuses a copy that only bundled entries reach.
        if u.get("in_repo") or not u.get("required") or u.get("bundled"):
            continue
        missing.append({
            "name": u["name"],
            "system": u.get("system") or "",
            "sha1": u.get("sha1"),
            "md5": u.get("md5"),
            "sha256": u.get("sha256"),
            "crc32": u.get("crc32"),
            "size": u.get("size"),
            "destination": u.get("path") or u["name"],
            "emulator": u.get("emulator", ""),
        })
    return missing


def _accepted(entry: dict, field: str) -> set[str]:
    """Every value an entry accepts for a hash field.

    A profile lists several revisions as a YAML list (daedalusx64's
    n64.psh), a platform as a comma-separated string. Read as one value,
    the list stopped the run with an unhashable-type error.
    """
    value = entry.get(field)
    values = value if isinstance(value, list) else str(value or "").split(",")
    return {str(v).strip().lower() for v in values if str(v).strip()}


def _crc32s(entry: dict) -> set[str]:
    return {value.removeprefix("0x").zfill(8) for value in _accepted(entry, "crc32")}


def _size(entry: dict) -> int | None:
    try:
        return int(entry["size"]) if entry.get("size") is not None else None
    except (TypeError, ValueError):
        return None


CRYPTO_HASHES = (
    ("sha256", hashlib.sha256),
    ("sha1", hashlib.sha1),
    ("md5", hashlib.md5),
)


def verifiable(entry: dict) -> bool:
    """Whether a network download can be proved to be this file.

    Only a cryptographic hash proves it. A crc32 and a size can be met by
    crafted bytes, so they identify a file the database already holds
    (step 1) and never accept one a remote source serves.
    """
    return any(_accepted(entry, field) for field, _digest in CRYPTO_HASHES)


def verify_content(data: bytes, expected: dict) -> bool:
    """Whether downloaded bytes match every cryptographic hash declared.

    Each declared field must hold the bytes' digest among its accepted
    values. An entry declaring none is refused.
    """
    declared = [
        (accepted, digest)
        for field, digest in CRYPTO_HASHES
        for accepted in [_accepted(expected, field)]
        if accepted
    ]
    return bool(declared) and all(
        digest(data).hexdigest() in accepted for accepted, digest in declared
    )


def _read_limited(
    resp: http.client.HTTPResponse, limit: int = MAX_DOWNLOAD
) -> bytes | None:
    """Read response up to limit bytes. Returns None if exceeded."""
    data = resp.read(limit + 1)
    if len(data) > limit:
        return None
    return data


def step1_crossref_db(entry: dict, db: dict) -> str | None:
    """Check if file exists under different name/path in database."""
    files = db.get("files", {})
    for sha1 in sorted(_accepted(entry, "sha1")):
        if sha1 in files:
            return files[sha1]["path"]
    indexes = db.get("indexes", {})
    for field, index in (("sha256", "by_sha256"), ("md5", "by_md5")):
        by_hash = indexes.get(index, {})
        for value in sorted(_accepted(entry, field)):
            sha1_match = by_hash.get(value)
            if sha1_match and sha1_match in files:
                return files[sha1_match]["path"]
    size = _size(entry)
    if size is not None:
        by_crc32 = indexes.get("by_crc32", {})
        for crc in sorted(_crc32s(entry)):
            sha1_match = by_crc32.get(crc)
            if sha1_match in files and files[sha1_match].get("size") == size:
                return files[sha1_match]["path"]
    return None


def step2_scan_branches(entry: dict) -> bytes | None:
    """Search old git branches for the file by hash."""
    name = entry["name"]

    for branch in LEGACY_BRANCHES:
        ref = f"origin/{branch}"
        try:
            subprocess.run(
                ["git", "rev-parse", "--verify", ref],
                capture_output=True,
                check=True,
            )
        except subprocess.CalledProcessError:
            continue

        result = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", ref],
            capture_output=True,
            text=True,
        )

        for filepath in result.stdout.strip().split("\n"):
            if os.path.basename(filepath) == name:
                try:
                    blob = subprocess.run(
                        ["git", "show", f"{ref}:{filepath}"],
                        capture_output=True,
                        check=True,
                    )
                    if verify_content(blob.stdout, entry):
                        return blob.stdout
                except subprocess.CalledProcessError:
                    continue

    return None


# Sources that did not answer during the current file's search. A 404 is an
# answer, the file is not there. Anything else leaves the question open: an
# offline run used to report every file as needing a community contribution.
_UNANSWERED: list[str] = []


def _unanswered(url: str, exc: Exception) -> None:
    if isinstance(exc, urllib.error.HTTPError) and exc.code == 404:
        return
    _UNANSWERED.append(f"{url}: {exc}")


def step3_search_public_repos(entry: dict) -> bytes | None:
    """Search public GitHub BIOS repos."""
    name = entry["name"]
    destination = entry.get("destination", name)

    for url_template in PUBLIC_REPOS:
        url = url_template.format(name=name)
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "retrobios-fetch/1.0"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = _read_limited(resp)
                if data is None:
                    continue
                if verify_content(data, entry):
                    return data
        except urllib.error.URLError as exc:
            _unanswered(url, exc)
            continue

        if "/" in destination:
            url = url_template.format(name=destination)
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "retrobios-fetch/1.0"}
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = _read_limited(resp)
                    if data is None:
                        continue
                    if verify_content(data, entry):
                        return data
            except urllib.error.URLError as exc:
                _unanswered(url, exc)
                continue

    return None


def step3b_software_heritage(entry: dict) -> bytes | None:
    """Ask Software Heritage for the file by each accepted sha1, then
    sha256: its archive answers by content, whatever the file was named."""
    for field in ("sha1", "sha256"):
        for value in sorted(_accepted(entry, field)):
            url = f"{SOFTWARE_HERITAGE}/{field}:{value}/raw/"
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "retrobios-fetch/1.0"}
                )
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = _read_limited(resp)
            except urllib.error.URLError as exc:
                _unanswered(url, exc)
                continue
            if data is not None and verify_content(data, entry):
                return data
    return None


def step4_search_archive_org(entry: dict) -> bytes | None:
    """Search archive.org firmware collections by direct download."""
    name = entry["name"]

    for collection_id in ARCHIVE_ORG_COLLECTIONS:
        for path in [name, f"system/{name}", f"bios/{name}"]:
            url = f"https://archive.org/download/{collection_id}/{path}"
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "retrobios-fetch/1.0"}
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = _read_limited(resp)
                    if data is None:
                        continue
                    if verify_content(data, entry):
                        return data
            except urllib.error.URLError as exc:
                _unanswered(url, exc)
                continue

    sha1s = sorted(_accepted(entry, "sha1"))
    if not sha1s:
        return None
    # Each accepted revision is a query of its own: archive.org matches one.
    sha1 = " OR ".join(f"sha1:{value}" for value in sha1s)

    search_url = (
        "https://archive.org/advancedsearch.php?q="
        f"{urllib.parse.quote(sha1)}&output=json&rows=1"
    )

    try:
        req = urllib.request.Request(
            search_url, headers={"User-Agent": "retrobios-fetch/1.0"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            docs = result.get("response", {}).get("docs", [])
            if docs:
                identifier = docs[0].get("identifier")
                if identifier:
                    dl_url = f"https://archive.org/download/{identifier}/{name}"
                    try:
                        req2 = urllib.request.Request(
                            dl_url, headers={"User-Agent": "retrobios-fetch/1.0"}
                        )
                        with urllib.request.urlopen(req2, timeout=30) as resp2:
                            data = _read_limited(resp2)
                            if data is not None and verify_content(data, entry):
                                return data
                    except urllib.error.URLError as exc:
                        _unanswered(dl_url, exc)
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        _unanswered(search_url, exc)

    return None


def place_file(data: bytes, entry: dict, bios_dir: str, db: dict) -> str:
    """Place a fetched BIOS file in the correct location."""
    name = os.path.basename(entry["name"])
    system = entry["system"]

    dest_dir = Path(bios_dir)

    # Every part of the slug, not any: matching "nintendo" alone filed the
    # N64's n64.psh under the first Nintendo folder walked, the SNES one.
    parts = [part for part in system.lower().split("-") if len(part) > 1]
    matches = sorted(
        (len(f"{manufacturer_dir.name}/{console_dir.name}"), str(console_dir), console_dir)
        for manufacturer_dir in dest_dir.iterdir() if manufacturer_dir.is_dir()
        for console_dir in manufacturer_dir.iterdir() if console_dir.is_dir()
        and all(
            part in f"{manufacturer_dir.name}/{console_dir.name}".lower()
            for part in parts
        )
    )
    folder = matches[0][2] if matches else dest_dir / "Unknown" / system
    dest = folder / name
    if dest.exists() and dest.read_bytes() != data:
        # Another revision under the same name: the collection keeps it
        # beside, never in place of, the file already there.
        dest = folder / ".variants" / f"{name}.{hashlib.sha1(data).hexdigest()[:8]}"
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
    stats = {"found": 0, "not_found": 0, "errors": 0, "unverifiable": 0}
    still_missing = []

    for entry in missing:
        name = entry["name"]
        _UNANSWERED.clear()
        print(f"\n  Searching: {name} ({entry['system']})")

        existing = step1_crossref_db(entry, db)
        if existing:
            print(f"    [1] Found in database at: {existing}")
            stats["found"] += 1
            continue

        if not verifiable(entry):
            # Searched, a file of that name could only ever be refused.
            print("    [-] Cannot be verified from the network: declares no "
                  "cryptographic hash. Not searched, nothing written")
            still_missing.append(entry)
            stats["unverifiable"] += 1
            continue

        if dry_run:
            print("    [DRY RUN] Would search branches, repos, Software Heritage, archive.org")
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

        data = step3b_software_heritage(entry)
        if data:
            path = place_file(data, entry, bios_dir, db)
            print(f"    [3b] Found in Software Heritage, saved to: {path}")
            stats["found"] += 1
            continue

        data = step4_search_archive_org(entry)
        if data:
            path = place_file(data, entry, bios_dir, db)
            print(f"    [4] Found on archive.org, saved to: {path}")
            stats["found"] += 1
            continue

        if _UNANSWERED:
            # Not looked for everywhere: no issue asks the community for it.
            print(
                f"    [5] Search incomplete, {len(_UNANSWERED)} source(s) did not "
                f"answer (first: {_UNANSWERED[0]})"
            )
            stats["errors"] += 1
            continue
        print("    [5] Not found, open for contributions")
        still_missing.append(entry)
        stats["not_found"] += 1

    return {"stats": stats, "still_missing": still_missing}


ACQUIRE_DIR = Path("tmp") / "acquire"


def lookup_sha1s(sha1s: list[str], db: dict, dry_run: bool = False) -> int:
    """--sha1: each file looked for by its hash alone, without a platform.
    Found bytes are verified, then saved as tmp/acquire/<sha1>, never into
    bios/: placing a file is a decision the collection makes. 0 when every
    one was found, 1 otherwise."""
    missing = 0
    for raw in sha1s:
        sha1 = raw.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{40}", sha1):
            print(f"  {raw}: not a sha1", file=sys.stderr)
            missing += 1
            continue
        entry = {"name": sha1, "sha1": sha1, "system": ""}
        _UNANSWERED.clear()
        held = step1_crossref_db(entry, db)
        if held:
            print(f"  {sha1}: already held at {held}")
            continue
        if dry_run:
            print(f"  {sha1}: would ask Software Heritage and archive.org")
            continue
        data = step3b_software_heritage(entry)
        where = "Software Heritage"
        if data is None:
            data, where = _archive_org_by_sha1(sha1), "archive.org"
        if data is None:
            note = f", {len(_UNANSWERED)} source(s) did not answer" if _UNANSWERED else ""
            print(f"  {sha1}: not found{note}")
            missing += 1
            continue
        ACQUIRE_DIR.mkdir(parents=True, exist_ok=True)
        out = ACQUIRE_DIR / sha1
        out.write_bytes(data)
        print(f"  {sha1}: found in {where}, {len(data)} bytes, saved to {out}")
    return 1 if missing else 0


def _archive_org_by_sha1(sha1: str) -> bytes | None:
    """The first archive.org file whose metadata names sha1, read and checked."""
    search = ("https://archive.org/advancedsearch.php?q="
              f"{urllib.parse.quote(f'sha1:{sha1}')}&fl[]=identifier&output=json&rows=5")
    try:
        with urllib.request.urlopen(urllib.request.Request(
                search, headers={"User-Agent": "retrobios-fetch/1.0"}), timeout=30) as resp:
            docs = json.loads(resp.read()).get("response", {}).get("docs", [])
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        _unanswered(search, exc)
        return None
    for doc in docs:
        identifier = doc.get("identifier")
        meta = f"https://archive.org/metadata/{identifier}/files"
        try:
            with urllib.request.urlopen(urllib.request.Request(
                    meta, headers={"User-Agent": "retrobios-fetch/1.0"}), timeout=30) as resp:
                files = json.loads(resp.read()).get("result", [])
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            _unanswered(meta, exc)
            continue
        for item in files:
            if str(item.get("sha1", "")).lower() != sha1:
                continue
            url = (f"https://archive.org/download/{identifier}/"
                   f"{urllib.parse.quote(item['name'])}")
            try:
                with urllib.request.urlopen(urllib.request.Request(
                        url, headers={"User-Agent": "retrobios-fetch/1.0"}), timeout=60) as resp:
                    data = _read_limited(resp)
            except urllib.error.URLError as exc:
                _unanswered(url, exc)
                continue
            if data is not None and hashlib.sha1(data).hexdigest() == sha1:
                return data
    return None


CONTRIBUTING_URL = "https://github.com/Abdess/retrobios/blob/main/CONTRIBUTING.md"


def generate_issue_body(missing: list[dict], platform: str) -> str:
    """An issue body for the files a platform still needs.

    The hashes are written in full: a contributor matches a file against
    them, and a 12-character prefix confirms nothing.
    """
    lines = [
        f"## Files {platform} still needs",
        "",
        "| File | System | SHA1 | MD5 |",
        "|------|--------|------|-----|",
    ]
    for entry in missing:
        sha1 = ", ".join(f"`{h}`" for h in sorted(_accepted(entry, "sha1"))) or "none declared"
        md5 = ", ".join(f"`{h}`" for h in sorted(_accepted(entry, "md5"))) or "none declared"
        lines.append(f"| `{entry['name']}` | {entry['system']} | {sha1} | {md5} |")
    lines += [
        "",
        "A file with one of these hashes can be added through the upload link in"
        f" [CONTRIBUTING.md]({CONTRIBUTING_URL}). CI checks it on arrival.",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Auto-fetch missing BIOS files")
    parser.add_argument("--platform", "-p", type=platform_arg, help="Platform to check")
    parser.add_argument("--all", action="store_true", help="Check all platforms")
    parser.add_argument(
        "--dry-run", action="store_true", help="Don't download, just report"
    )
    parser.add_argument(
        "--db", default=DEFAULT_DB,
        help="database file to read (default: %(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default=DEFAULT_PLATFORMS_DIR,
        help="platform YAML directory (default: %(default)s)",
    )
    parser.add_argument(
        "--bios-dir", default=DEFAULT_BIOS_DIR,
        help="BIOS collection directory (default: %(default)s)",
    )
    parser.add_argument(
        "--create-issues", action="store_true", help="Output GitHub Issue bodies"
    )
    parser.add_argument(
        "--sha1", action="append", metavar="SHA1",
        help="look for one file by its sha1 in the database, Software Heritage and "
             "archive.org, and save what is found under tmp/acquire/ (repeatable)",
    )
    args = parser.parse_args()
    require_directory(args.bios_dir)
    if args.sha1:
        if args.platform or args.all or args.create_issues:
            parser.error("--sha1 looks for files by hash alone: it takes no "
                         "--platform, --all or --create-issues")
        db = load_database(args.db) if os.path.exists(args.db) else {"files": {}}
        sys.exit(lookup_sha1s(args.sha1, db, args.dry_run))

    if not os.path.exists(args.db):
        print(f"Error: {args.db} not found. Run generate_db.py first.", file=sys.stderr)
        sys.exit(1)

    db = load_database(args.db)

    if args.all:
        platforms = list_registered_platforms(
            args.platforms_dir,
        )
    elif args.platform:
        require_platform(args.platform, args.platforms_dir)
        platforms = [args.platform]
    else:
        parser.error("Specify --platform or --all")
        return

    all_still_missing = {}

    for platform in sorted(platforms):
        print(f"\n{'=' * 60}")
        print(f"Platform: {platform}")
        print(f"{'=' * 60}")

        try:
            config = load_platform_config(platform, args.platforms_dir)
        except FileNotFoundError:
            print("  Config not found, skipping")
            continue

        missing = find_missing(config, db)
        if not missing:
            print("  All BIOS files present!")
            continue

        print(f"  {len(missing)} missing files")
        result = fetch_missing(missing, db, args.bios_dir, args.dry_run)

        if result["still_missing"]:
            all_still_missing[config.get("platform") or platform] = result["still_missing"]

        stats = result["stats"]
        print(
            f"\n  Results: {stats['found']} found, {stats['not_found']} not found, "
            f"{stats['errors']} not fully searched, "
            f"{stats['unverifiable']} without a cryptographic hash"
        )

    if args.create_issues and all_still_missing:
        print(f"\n{'=' * 60}")
        print("GitHub Issue Bodies")
        print(f"{'=' * 60}")
        for platform, missing in all_still_missing.items():
            print(f"\n--- Issue for {platform} ---\n")
            print(generate_issue_body(missing, platform))


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
