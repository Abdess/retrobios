#!/usr/bin/env python3
"""Platform-aware BIOS verification engine.

Replicates the exact verification logic of each platform:
- RetroArch/Lakka/RetroPie: file existence only (path_is_valid)
- Batocera: MD5 hash verification + zippedFile content check (checkBios/checkInsideZip)

Usage:
    python scripts/verify.py --platform batocera
    python scripts/verify.py --all
    python scripts/verify.py --platform retroarch --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import zipfile
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Error: PyYAML required (pip install pyyaml)", file=sys.stderr)
    sys.exit(1)

sys.path.insert(0, os.path.dirname(__file__))
from common import load_platform_config, md5sum

DEFAULT_DB = "database.json"
DEFAULT_PLATFORMS_DIR = "platforms"


class Status:
    OK = "ok"            # Verified - hash matches (or existence for existence-only platforms)
    UNTESTED = "untested" # File present but hash mismatch (Batocera term)
    MISSING = "missing"   # File not found at all


def check_inside_zip(container: str, file_name: str, expected_md5: str) -> str:
    """Check a ROM inside a ZIP - replicates Batocera's checkInsideZip().

    Returns Status.OK, Status.UNTESTED, or "not_in_zip".
    """
    try:
        with zipfile.ZipFile(container) as archive:
            # casefold() for case-insensitive ZIP lookup, matching Batocera's checkInsideZip()
            for fname in archive.namelist():
                if fname.casefold() == file_name.casefold():
                    if expected_md5 == "":
                        return Status.OK

                    with archive.open(fname) as entry:
                        h = hashlib.md5()
                        while True:
                            block = entry.read(65536)
                            if not block:
                                break
                            h.update(block)

                    if h.hexdigest() == expected_md5:
                        return Status.OK
                    else:
                        return Status.UNTESTED

            return "not_in_zip"
    except Exception:
        return "error"


def resolve_to_local_path(file_entry: dict, db: dict) -> str | None:
    """Find the local file path for a BIOS entry using database.json.

    Tries: SHA1 -> MD5 -> name index. Returns the first existing path found.
    """
    sha1 = file_entry.get("sha1")
    md5 = file_entry.get("md5")
    name = file_entry.get("name", "")
    files_db = db.get("files", {})
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    by_name = db.get("indexes", {}).get("by_name", {})

    if sha1 and sha1 in files_db:
        path = files_db[sha1]["path"]
        if os.path.exists(path):
            return path

    if md5 and md5 in by_md5:
        sha1_match = by_md5[md5]
        if sha1_match in files_db:
            path = files_db[sha1_match]["path"]
            if os.path.exists(path):
                return path

    # Truncated MD5 (batocera-systems bug: 29 chars instead of 32)
    if md5 and len(md5) < 32:
        for db_md5, db_sha1 in by_md5.items():
            if db_md5.startswith(md5) and db_sha1 in files_db:
                path = files_db[db_sha1]["path"]
                if os.path.exists(path):
                    return path

    if name in by_name:
        for match_sha1 in by_name[name]:
            if match_sha1 in files_db:
                path = files_db[match_sha1]["path"]
                if os.path.exists(path):
                    return path

    return None


def verify_entry_existence(file_entry: dict, local_path: str | None) -> dict:
    """RetroArch verification: file exists = OK."""
    name = file_entry.get("name", "")
    if local_path:
        return {"name": name, "status": Status.OK, "path": local_path}
    return {"name": name, "status": Status.MISSING}


def verify_entry_md5(file_entry: dict, local_path: str | None) -> dict:
    """MD5 verification - supports single MD5 (Batocera) and multi-MD5 (Recalbox)."""
    name = file_entry.get("name", "")
    expected_md5 = file_entry.get("md5", "")
    zipped_file = file_entry.get("zipped_file")

    # Recalbox uses comma-separated MD5 lists
    if expected_md5 and "," in expected_md5:
        md5_list = [m.strip() for m in expected_md5.split(",") if m.strip()]
    else:
        md5_list = [expected_md5] if expected_md5 else []

    if not local_path:
        return {"name": name, "status": Status.MISSING, "expected_md5": expected_md5}

    if zipped_file:
        for md5_candidate in md5_list or [""]:
            result = check_inside_zip(local_path, zipped_file, md5_candidate)
            if result == Status.OK:
                return {"name": name, "status": Status.OK, "path": local_path}
        return {
            "name": name, "status": Status.UNTESTED, "path": local_path,
            "reason": f"{zipped_file} MD5 mismatch inside ZIP",
        }

    if not md5_list:
        return {"name": name, "status": Status.OK, "path": local_path}

    actual_md5 = md5sum(local_path)

    # Case-insensitive - Recalbox uses uppercase MD5s
    actual_lower = actual_md5.lower()
    for expected in md5_list:
        if actual_lower == expected.lower():
            return {"name": name, "status": Status.OK, "path": local_path}
        if len(expected) < 32 and actual_lower.startswith(expected.lower()):
            return {"name": name, "status": Status.OK, "path": local_path}

    return {
        "name": name, "status": Status.UNTESTED, "path": local_path,
        "expected_md5": md5_list[0] if md5_list else "", "actual_md5": actual_md5,
    }


def verify_platform(config: dict, db: dict) -> dict:
    """Verify all BIOS files for a platform using its verification_mode.

    Returns:
        {
            "platform": str,
            "verification_mode": str,
            "total": int,
            "ok": int,
            "untested": int,
            "missing": int,
            "details": [{"name", "status", ...}, ...]
        }
    """
    mode = config.get("verification_mode", "existence")
    platform = config.get("platform", "unknown")

    verify_fn = verify_entry_existence if mode == "existence" else verify_entry_md5

    results = []
    for sys_id, system in config.get("systems", {}).items():
        for file_entry in system.get("files", []):
            local_path = resolve_to_local_path(file_entry, db)
            result = verify_fn(file_entry, local_path)
            result["system"] = sys_id
            results.append(result)

    ok = sum(1 for r in results if r["status"] == Status.OK)
    untested = sum(1 for r in results if r["status"] == Status.UNTESTED)
    missing = sum(1 for r in results if r["status"] == Status.MISSING)

    return {
        "platform": platform,
        "verification_mode": mode,
        "total": len(results),
        "ok": ok,
        "untested": untested,
        "missing": missing,
        "details": results,
    }



def main():
    parser = argparse.ArgumentParser(description="Verify BIOS coverage per platform")
    parser.add_argument("--platform", "-p", help="Platform name")
    parser.add_argument("--all", action="store_true", help="Verify all platforms")
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--platforms-dir", default=DEFAULT_PLATFORMS_DIR)
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    with open(args.db) as f:
        db = json.load(f)

    if args.all:
        platforms = [p.stem for p in Path(args.platforms_dir).glob("*.yml") if not p.name.startswith("_")]
    elif args.platform:
        platforms = [args.platform]
    else:
        parser.error("Specify --platform or --all")
        return

    all_results = {}
    for platform in sorted(platforms):
        config = load_platform_config(platform, args.platforms_dir)
        result = verify_platform(config, db)
        all_results[platform] = result

        if not args.json:
            mode = result["verification_mode"]
            if mode == "existence":
                print(f"{result['platform']}: {result['ok']}/{result['total']} present, "
                      f"{result['missing']} missing [verification: {mode}]")
            else:
                print(f"{result['platform']}: {result['ok']}/{result['total']} verified, "
                      f"{result['untested']} untested, {result['missing']} missing [verification: {mode}]")

                for d in result["details"]:
                    if d["status"] == Status.UNTESTED:
                        reason = d.get("reason", "")
                        if not reason and "expected_md5" in d:
                            reason = f"expected={d['expected_md5'][:16]}... got={d['actual_md5'][:16]}..."
                        print(f"  UNTESTED: {d['system']}/{d['name']} - {reason}")

                for d in result["details"]:
                    if d["status"] == Status.MISSING:
                        print(f"  MISSING: {d['system']}/{d['name']}")

    if args.json:
        for r in all_results.values():
            r["details"] = [d for d in r["details"] if d["status"] != Status.OK]
        print(json.dumps(all_results, indent=2))


if __name__ == "__main__":
    main()
