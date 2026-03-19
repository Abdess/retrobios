#!/usr/bin/env python3
"""Platform-native BIOS verification engine.

Replicates the exact verification logic of each platform:
- RetroArch/Lakka/RetroPie: file existence only (core_info.c path_is_valid)
- Batocera: MD5 + checkInsideZip, no required distinction (batocera-systems:1062-1091)
- Recalbox: MD5 + mandatory/hashMatchMandatory, 3-color severity (Bios.cpp:109-130)
- RetroBat: same as Batocera
- EmuDeck: MD5 whitelist per system

Cross-references emulator profiles to detect undeclared files used by available cores.

Usage:
    python scripts/verify.py --all
    python scripts/verify.py --platform batocera
    python scripts/verify.py --all --include-archived
    python scripts/verify.py --all --json
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
from common import (
    build_zip_contents_index, check_inside_zip, group_identical_platforms,
    load_emulator_profiles, load_platform_config, md5sum, md5_composite,
    resolve_local_file,
)

DEFAULT_DB = "database.json"
DEFAULT_PLATFORMS_DIR = "platforms"
DEFAULT_EMULATORS_DIR = "emulators"


# ---------------------------------------------------------------------------
# Status model — aligned with Batocera BiosStatus (batocera-systems:967-969)
# ---------------------------------------------------------------------------

class Status:
    OK = "ok"
    UNTESTED = "untested"   # file present, hash not confirmed
    MISSING = "missing"


# Severity for per-file required/optional distinction
class Severity:
    CRITICAL = "critical"   # required file missing or bad hash (Recalbox RED)
    WARNING = "warning"     # optional missing or hash mismatch (Recalbox YELLOW)
    INFO = "info"           # optional missing on existence-only platform
    OK = "ok"               # file verified


# ---------------------------------------------------------------------------
# Verification functions
# ---------------------------------------------------------------------------

def verify_entry_existence(file_entry: dict, local_path: str | None) -> dict:
    """RetroArch verification: path_is_valid() — file exists = OK."""
    name = file_entry.get("name", "")
    required = file_entry.get("required", True)
    if local_path:
        return {"name": name, "status": Status.OK, "required": required}
    return {"name": name, "status": Status.MISSING, "required": required}


def verify_entry_md5(
    file_entry: dict,
    local_path: str | None,
    resolve_status: str = "",
) -> dict:
    """MD5 verification — Batocera md5sum + Recalbox multi-hash + Md5Composite."""
    name = file_entry.get("name", "")
    expected_md5 = file_entry.get("md5", "")
    zipped_file = file_entry.get("zipped_file")
    required = file_entry.get("required", True)
    base = {"name": name, "required": required}

    if expected_md5 and "," in expected_md5:
        md5_list = [m.strip() for m in expected_md5.split(",") if m.strip()]
    else:
        md5_list = [expected_md5] if expected_md5 else []

    if not local_path:
        return {**base, "status": Status.MISSING}

    if zipped_file:
        found_in_zip = False
        had_error = False
        for md5_candidate in md5_list or [""]:
            result = check_inside_zip(local_path, zipped_file, md5_candidate)
            if result == Status.OK:
                return {**base, "status": Status.OK, "path": local_path}
            if result == "error":
                had_error = True
            elif result != "not_in_zip":
                found_in_zip = True
        if had_error and not found_in_zip:
            return {**base, "status": Status.UNTESTED, "path": local_path,
                    "reason": f"{local_path} read error"}
        if not found_in_zip:
            return {**base, "status": Status.UNTESTED, "path": local_path,
                    "reason": f"{zipped_file} not found inside ZIP"}
        return {**base, "status": Status.UNTESTED, "path": local_path,
                "reason": f"{zipped_file} MD5 mismatch inside ZIP"}

    if not md5_list:
        return {**base, "status": Status.OK, "path": local_path}

    if resolve_status == "md5_exact":
        return {**base, "status": Status.OK, "path": local_path}

    actual_md5 = md5sum(local_path)
    actual_lower = actual_md5.lower()
    for expected in md5_list:
        if actual_lower == expected.lower():
            return {**base, "status": Status.OK, "path": local_path}
        if len(expected) < 32 and actual_lower.startswith(expected.lower()):
            return {**base, "status": Status.OK, "path": local_path}

    if ".zip" in os.path.basename(local_path):
        try:
            composite = md5_composite(local_path)
            for expected in md5_list:
                if composite.lower() == expected.lower():
                    return {**base, "status": Status.OK, "path": local_path}
        except (zipfile.BadZipFile, OSError):
            pass

    return {**base, "status": Status.UNTESTED, "path": local_path,
            "reason": f"expected {md5_list[0][:12]}… got {actual_md5[:12]}…"}


# ---------------------------------------------------------------------------
# Severity mapping per platform
# ---------------------------------------------------------------------------

def compute_severity(status: str, required: bool, mode: str) -> str:
    """Map (status, required, verification_mode) → severity.

    Based on native platform behavior:
    - RetroArch (existence): required+missing = warning, optional+missing = info
    - Batocera (md5): no required distinction — all equal (batocera-systems has no mandatory field)
    - Recalbox (md5): mandatory+missing = critical, optional+missing = warning (Bios.cpp:109-130)
    """
    if status == Status.OK:
        return Severity.OK

    if mode == "existence":
        if status == Status.MISSING:
            return Severity.WARNING if required else Severity.INFO
        return Severity.OK

    # md5 mode (Batocera, Recalbox, RetroBat, EmuDeck)
    if status == Status.MISSING:
        return Severity.CRITICAL if required else Severity.WARNING
    if status == Status.UNTESTED:
        return Severity.WARNING if required else Severity.WARNING
    return Severity.OK


# ---------------------------------------------------------------------------
# ZIP content index
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Cross-reference: undeclared files used by cores
# ---------------------------------------------------------------------------

def find_undeclared_files(
    config: dict,
    emulators_dir: str,
    db: dict,
) -> list[dict]:
    """Find files needed by cores but not declared in platform config."""
    # Collect all filenames declared by this platform
    declared_names: set[str] = set()
    platform_systems: set[str] = set()
    for sys_id, system in config.get("systems", {}).items():
        platform_systems.add(sys_id)
        for fe in system.get("files", []):
            name = fe.get("name", "")
            if name:
                declared_names.add(name)

    # Collect data_directory refs
    declared_dd: set[str] = set()
    for sys_id, system in config.get("systems", {}).items():
        for dd in system.get("data_directories", []):
            ref = dd.get("ref", "")
            if ref:
                declared_dd.add(ref)

    by_name = db.get("indexes", {}).get("by_name", {})
    profiles = load_emulator_profiles(emulators_dir)

    undeclared = []
    seen = set()
    for emu_name, profile in sorted(profiles.items()):
        emu_systems = set(profile.get("systems", []))
        # Only check emulators whose systems overlap with this platform
        if not emu_systems & platform_systems:
            continue

        # Skip if emulator's data_directories cover the files
        emu_dd = {dd.get("ref", "") for dd in profile.get("data_directories", [])}
        covered_by_dd = bool(emu_dd & declared_dd)

        for f in profile.get("files", []):
            fname = f.get("name", "")
            if not fname or fname in seen:
                continue
            # Skip standalone-only files for libretro platforms
            if f.get("mode") == "standalone":
                continue
            if fname in declared_names:
                continue
            if covered_by_dd:
                continue

            in_repo = fname in by_name or fname.rsplit("/", 1)[-1] in by_name
            seen.add(fname)
            undeclared.append({
                "emulator": profile.get("emulator", emu_name),
                "name": fname,
                "required": f.get("required", False),
                "in_repo": in_repo,
                "note": f.get("note", ""),
            })

    return undeclared


# ---------------------------------------------------------------------------
# Platform verification
# ---------------------------------------------------------------------------

def verify_platform(config: dict, db: dict, emulators_dir: str = DEFAULT_EMULATORS_DIR) -> dict:
    """Verify all BIOS files for a platform, including cross-reference gaps."""
    mode = config.get("verification_mode", "existence")
    platform = config.get("platform", "unknown")

    has_zipped = any(
        fe.get("zipped_file")
        for sys in config.get("systems", {}).values()
        for fe in sys.get("files", [])
    )
    zip_contents = build_zip_contents_index(db) if has_zipped else {}

    # Per-entry results
    details = []
    # Per-destination aggregation
    file_status: dict[str, str] = {}
    file_required: dict[str, bool] = {}
    file_severity: dict[str, str] = {}

    for sys_id, system in config.get("systems", {}).items():
        for file_entry in system.get("files", []):
            local_path, resolve_status = resolve_local_file(
                file_entry, db, zip_contents,
            )
            if mode == "existence":
                result = verify_entry_existence(file_entry, local_path)
            else:
                result = verify_entry_md5(file_entry, local_path, resolve_status)
            result["system"] = sys_id
            details.append(result)

            # Aggregate by destination
            dest = file_entry.get("destination", file_entry.get("name", ""))
            if not dest:
                dest = f"{sys_id}/{file_entry.get('name', '')}"
            required = file_entry.get("required", True)
            cur = result["status"]
            prev = file_status.get(dest)
            sev_order = {Status.OK: 0, Status.UNTESTED: 1, Status.MISSING: 2}
            if prev is None or sev_order.get(cur, 0) > sev_order.get(prev, 0):
                file_status[dest] = cur
                file_required[dest] = required
            sev = compute_severity(cur, required, mode)
            prev_sev = file_severity.get(dest)
            sev_prio = {Severity.OK: 0, Severity.INFO: 1, Severity.WARNING: 2, Severity.CRITICAL: 3}
            if prev_sev is None or sev_prio.get(sev, 0) > sev_prio.get(prev_sev, 0):
                file_severity[dest] = sev

    # Count by severity
    counts = {Severity.OK: 0, Severity.INFO: 0, Severity.WARNING: 0, Severity.CRITICAL: 0}
    for s in file_severity.values():
        counts[s] = counts.get(s, 0) + 1

    # Cross-reference undeclared files
    undeclared = find_undeclared_files(config, emulators_dir, db)

    return {
        "platform": platform,
        "verification_mode": mode,
        "total_files": len(file_status),
        "severity_counts": counts,
        "undeclared_files": undeclared,
        "details": details,
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_platform_result(result: dict, group: list[str]) -> None:
    mode = result["verification_mode"]
    total = result["total_files"]
    c = result["severity_counts"]
    label = " / ".join(group)
    ok_count = c[Severity.OK]
    problems = total - ok_count

    # Summary line — platform-native terminology
    if mode == "existence":
        if problems:
            missing = c.get(Severity.WARNING, 0) + c.get(Severity.CRITICAL, 0)
            optional_missing = c.get(Severity.INFO, 0)
            parts = [f"{ok_count}/{total} present"]
            if missing:
                parts.append(f"{missing} missing")
            if optional_missing:
                parts.append(f"{optional_missing} optional missing")
        else:
            parts = [f"{ok_count}/{total} present"]
    else:
        untested = c.get(Severity.WARNING, 0)
        missing = c.get(Severity.CRITICAL, 0)
        parts = [f"{ok_count}/{total} OK"]
        if untested:
            parts.append(f"{untested} untested")
        if missing:
            parts.append(f"{missing} missing")
    print(f"{label}: {', '.join(parts)} [{mode}]")

    # Detail non-OK entries with required/optional
    seen_details = set()
    for d in result["details"]:
        if d["status"] == Status.UNTESTED:
            key = f"{d['system']}/{d['name']}"
            if key in seen_details:
                continue
            seen_details.add(key)
            req = "required" if d.get("required", True) else "optional"
            reason = d.get("reason", "")
            print(f"  UNTESTED ({req}): {key} — {reason}")
    for d in result["details"]:
        if d["status"] == Status.MISSING:
            key = f"{d['system']}/{d['name']}"
            if key in seen_details:
                continue
            seen_details.add(key)
            req = "required" if d.get("required", True) else "optional"
            print(f"  MISSING ({req}): {key}")

    # Cross-reference: undeclared files used by cores
    undeclared = result.get("undeclared_files", [])
    if undeclared:
        req_not_in_repo = [u for u in undeclared if u["required"] and not u["in_repo"]]
        req_in_repo = [u for u in undeclared if u["required"] and u["in_repo"]]
        opt_count = len(undeclared) - len(req_not_in_repo) - len(req_in_repo)

        summary_parts = []
        if req_not_in_repo:
            summary_parts.append(f"{len(req_not_in_repo)} required NOT in repo")
        if req_in_repo:
            summary_parts.append(f"{len(req_in_repo)} required in repo")
        summary_parts.append(f"{opt_count} optional")
        print(f"  Core gaps: {len(undeclared)} undeclared ({', '.join(summary_parts)})")

        # Show only critical gaps (required + not in repo)
        for u in req_not_in_repo:
            print(f"    {u['emulator']} → {u['name']} (required, NOT in repo)")
        # Show required in repo (actionable)
        for u in req_in_repo[:10]:
            print(f"    {u['emulator']} → {u['name']} (required, in repo)")
        if len(req_in_repo) > 10:
            print(f"    ... and {len(req_in_repo) - 10} more required in repo")


def main():
    parser = argparse.ArgumentParser(description="Platform-native BIOS verification")
    parser.add_argument("--platform", "-p", help="Platform name")
    parser.add_argument("--all", action="store_true", help="Verify all active platforms")
    parser.add_argument("--include-archived", action="store_true")
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--platforms-dir", default=DEFAULT_PLATFORMS_DIR)
    parser.add_argument("--emulators-dir", default=DEFAULT_EMULATORS_DIR)
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    with open(args.db) as f:
        db = json.load(f)

    if args.all:
        from list_platforms import list_platforms as _list_platforms
        platforms = _list_platforms(include_archived=args.include_archived)
    elif args.platform:
        platforms = [args.platform]
    else:
        parser.error("Specify --platform or --all")
        return

    # Group identical platforms (same function as generate_pack)
    groups = group_identical_platforms(platforms, args.platforms_dir)
    all_results = {}
    group_results: list[tuple[dict, list[str]]] = []
    for group_platforms, representative in groups:
        config = load_platform_config(representative, args.platforms_dir)
        result = verify_platform(config, db, args.emulators_dir)
        names = [load_platform_config(p, args.platforms_dir).get("platform", p) for p in group_platforms]
        group_results.append((result, names))
        for p in group_platforms:
            all_results[p] = result

    if not args.json:
        for result, group in group_results:
            print_platform_result(result, group)
            print()

    if args.json:
        for r in all_results.values():
            r["details"] = [d for d in r["details"] if d["status"] != Status.OK]
        print(json.dumps(all_results, indent=2))


if __name__ == "__main__":
    main()
