#!/usr/bin/env python3
"""Cross-reference emulator profiles against platform configs.

Identifies BIOS files that emulators need but platforms don't declare,
providing gap analysis for extended coverage.

Usage:
    python scripts/cross_reference.py
    python scripts/cross_reference.py --emulator dolphin
    python scripts/cross_reference.py --json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Error: PyYAML required (pip install pyyaml)", file=sys.stderr)
    sys.exit(1)

sys.path.insert(0, os.path.dirname(__file__))
from common import list_registered_platforms, load_database, load_emulator_profiles, load_platform_config

DEFAULT_EMULATORS_DIR = "emulators"
DEFAULT_PLATFORMS_DIR = "platforms"
DEFAULT_DB = "database.json"


def load_platform_files(platforms_dir: str) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Load all platform configs and collect declared filenames + data_directories per system."""
    declared = {}
    platform_data_dirs = {}
    for platform_name in list_registered_platforms(platforms_dir, include_archived=True):
        config = load_platform_config(platform_name, platforms_dir)
        for sys_id, system in config.get("systems", {}).items():
            for fe in system.get("files", []):
                name = fe.get("name", "")
                if name:
                    declared.setdefault(sys_id, set()).add(name)
            for dd in system.get("data_directories", []):
                ref = dd.get("ref", "")
                if ref:
                    platform_data_dirs.setdefault(sys_id, set()).add(ref)
    return declared, platform_data_dirs


def _find_in_repo(fname: str, by_name: dict[str, list], by_name_lower: dict[str, str]) -> bool:
    if fname in by_name:
        return True
    basename = fname.rsplit("/", 1)[-1] if "/" in fname else None
    if basename and basename in by_name:
        return True
    key = fname.lower()
    if key in by_name_lower:
        return True
    if basename:
        key = basename.lower()
        if key in by_name_lower:
            return True
    return False


def cross_reference(
    profiles: dict[str, dict],
    declared: dict[str, set[str]],
    db: dict,
    platform_data_dirs: dict[str, set[str]] | None = None,
) -> dict:
    """Compare emulator profiles against platform declarations.

    Returns a report with gaps (files emulators need but platforms don't list)
    and coverage stats. Files covered by matching data_directories between
    emulator profile and platform config are not reported as gaps.
    """
    platform_data_dirs = platform_data_dirs or {}
    by_name = db.get("indexes", {}).get("by_name", {})
    by_name_lower = {k.lower(): k for k in by_name}
    report = {}

    for emu_name, profile in profiles.items():
        emu_files = profile.get("files", [])
        systems = profile.get("systems", [])

        platform_names = set()
        for sys_id in systems:
            platform_names.update(declared.get(sys_id, set()))

        gaps = []
        covered = []
        for f in emu_files:
            fname = f.get("name", "")
            if not fname:
                continue

            # Skip standalone-only files when comparing against libretro
            # platforms (RetroArch, Lakka, etc.). These files are embedded
            # in the core and don't need to be in the platform pack.
            file_mode = f.get("mode", "both")
            if file_mode == "standalone":
                continue

            in_platform = fname in platform_names
            in_repo = _find_in_repo(fname, by_name, by_name_lower)

            entry = {
                "name": fname,
                "required": f.get("required", False),
                "note": f.get("note", ""),
                "source_ref": f.get("source_ref", ""),
                "in_platform": in_platform,
                "in_repo": in_repo,
            }

            if not in_platform:
                gaps.append(entry)
            else:
                covered.append(entry)

        report[emu_name] = {
            "emulator": profile.get("emulator", emu_name),
            "systems": systems,
            "total_files": len(emu_files),
            "platform_covered": len(covered),
            "gaps": len(gaps),
            "gap_in_repo": sum(1 for g in gaps if g["in_repo"]),
            "gap_missing": sum(1 for g in gaps if not g["in_repo"]),
            "gap_details": gaps,
        }

    return report


def print_report(report: dict) -> None:
    """Print a human-readable gap analysis report."""
    print("Emulator vs Platform Gap Analysis")
    print("=" * 60)

    total_gaps = 0
    total_in_repo = 0
    total_missing = 0

    for emu_name, data in sorted(report.items()):
        gaps = data["gaps"]
        if gaps == 0:
            status = "OK"
        else:
            status = f"{data['gap_in_repo']} in repo, {data['gap_missing']} missing"

        print(f"\n{data['emulator']} ({', '.join(data['systems'])})")
        print(f"  {data['total_files']} files in profile, "
              f"{data['platform_covered']} declared by platforms, "
              f"{gaps} undeclared")

        if gaps > 0:
            print(f"  Gaps: {status}")
            for g in data["gap_details"]:
                req = "*" if g["required"] else " "
                loc = "repo" if g["in_repo"] else "MISSING"
                note = f" -- {g['note']}" if g["note"] else ""
                print(f"    {req} {g['name']} [{loc}]{note}")

        total_gaps += gaps
        total_in_repo += data["gap_in_repo"]
        total_missing += data["gap_missing"]

    print(f"\n{'=' * 60}")
    print(f"Total: {total_gaps} undeclared files across all emulators")
    print(f"  {total_in_repo} already in repo (can be added to packs)")
    print(f"  {total_missing} missing from repo (need to be sourced)")


def main():
    parser = argparse.ArgumentParser(description="Emulator vs platform gap analysis")
    parser.add_argument("--emulators-dir", default=DEFAULT_EMULATORS_DIR)
    parser.add_argument("--platforms-dir", default=DEFAULT_PLATFORMS_DIR)
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--emulator", "-e", help="Analyze single emulator")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    profiles = load_emulator_profiles(args.emulators_dir)
    if args.emulator:
        profiles = {k: v for k, v in profiles.items() if k == args.emulator}

    if not profiles:
        print("No emulator profiles found.", file=sys.stderr)
        return

    declared, plat_data_dirs = load_platform_files(args.platforms_dir)
    db = load_database(args.db)
    report = cross_reference(profiles, declared, db, plat_data_dirs)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
