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

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    list_registered_platforms,
    load_database,
    load_emulator_profiles,
    load_platform_config,
    require_yaml,
)

yaml = require_yaml()

DEFAULT_EMULATORS_DIR = "emulators"
DEFAULT_PLATFORMS_DIR = "platforms"
DEFAULT_DB = "database.json"


def load_platform_files(
    platforms_dir: str,
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Load all platform configs and collect declared filenames + data_directories per system."""
    declared = {}
    platform_data_dirs = {}
    for platform_name in list_registered_platforms(
        platforms_dir, include_archived=True
    ):
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


def _build_supplemental_index(
    data_root: str = "data", bios_root: str = "bios"
) -> set[str]:
    """Build a set of filenames and directory names in data/ and inside bios/ ZIPs."""
    names: set[str] = set()
    root_path = Path(data_root)
    if root_path.is_dir():
        for fpath in root_path.rglob("*"):
            if fpath.name.startswith("."):
                continue
            names.add(fpath.name)
            names.add(fpath.name.lower())
            if fpath.is_dir():
                # Also index relative path from data/subdir/ for directory entries
                parts = fpath.relative_to(root_path).parts
                if len(parts) > 1:
                    rel = "/".join(parts[1:])
                    names.add(rel)
                    names.add(rel + "/")
                    names.add(rel.lower())
                    names.add(rel.lower() + "/")
    bios_path = Path(bios_root)
    if bios_path.is_dir():
        # Index directory names for directory-type entries (e.g., "nestopia/samples/moepro/")
        for dpath in bios_path.rglob("*"):
            if dpath.is_dir() and not dpath.name.startswith("."):
                names.add(dpath.name)
                names.add(dpath.name.lower())
                names.add(dpath.name + "/")
                names.add(dpath.name.lower() + "/")
        import zipfile

        for zpath in bios_path.rglob("*.zip"):
            try:
                with zipfile.ZipFile(zpath) as zf:
                    for member in zf.namelist():
                        if not member.endswith("/"):
                            basename = (
                                member.rsplit("/", 1)[-1] if "/" in member else member
                            )
                            names.add(basename)
                            names.add(basename.lower())
            except (zipfile.BadZipFile, OSError):
                pass
    return names


def _resolve_source(
    fname: str,
    by_name: dict[str, list],
    by_name_lower: dict[str, str],
    data_names: set[str] | None = None,
    by_path_suffix: dict | None = None,
) -> str | None:
    """Return the source category for a file, or None if not found.

    Returns ``"bios"`` (in database.json / bios/), ``"data"`` (in data/),
    or ``None`` (not available anywhere).
    """
    # bios/ via database.json by_name
    if fname in by_name:
        return "bios"
    stripped = fname.rstrip("/")
    basename = stripped.rsplit("/", 1)[-1] if "/" in stripped else None
    if basename and basename in by_name:
        return "bios"
    key = fname.lower()
    if key in by_name_lower:
        return "bios"
    if basename:
        if basename.lower() in by_name_lower:
            return "bios"
    # bios/ via by_path_suffix (regional variants)
    if by_path_suffix and fname in by_path_suffix:
        return "bios"
    # data/ supplemental index
    if data_names:
        if fname in data_names or key in data_names:
            return "data"
        if basename and (basename in data_names or basename.lower() in data_names):
            return "data"
    return None


def cross_reference(
    profiles: dict[str, dict],
    declared: dict[str, set[str]],
    db: dict,
    platform_data_dirs: dict[str, set[str]] | None = None,
    data_names: set[str] | None = None,
    all_declared: set[str] | None = None,
) -> dict:
    """Compare emulator profiles against platform declarations.

    Returns a report with gaps (files emulators need but platforms don't list)
    and coverage stats.  Each gap entry carries a ``source`` field indicating
    where the file is available: ``"bios"`` (bios/ via database.json),
    ``"data"`` (data/ directory), ``"large_file"`` (GitHub release asset),
    or ``"missing"`` (not available anywhere).

    The boolean ``in_repo`` is derived: ``source != "missing"``.

    When *all_declared* is provided (flat set of every filename declared by
    any platform for any system), it is used for the ``in_platform`` check
    instead of the per-system lookup.  This is appropriate for the global
    gap analysis page where "undeclared" means "no platform declares it at all".
    """
    platform_data_dirs = platform_data_dirs or {}
    by_name = db.get("indexes", {}).get("by_name", {})
    by_name_lower = {k.lower(): k for k in by_name}
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    by_path_suffix = db.get("indexes", {}).get("by_path_suffix", {})
    db_files = db.get("files", {})
    report = {}

    for emu_name, profile in profiles.items():
        emu_files = profile.get("files", [])
        systems = profile.get("systems", [])

        if all_declared is not None:
            platform_names = all_declared
        else:
            platform_names = set()
            for sys_id in systems:
                platform_names.update(declared.get(sys_id, set()))

        gaps = []
        covered = []
        for f in emu_files:
            fname = f.get("name", "")
            if not fname:
                continue

            # Skip pattern placeholders (e.g., <bios>.bin, <user-selected>.bin)
            if "<" in fname or ">" in fname:
                continue

            # Skip UI-imported files with explicit path: null (not resolvable by pack)
            if "path" in f and f["path"] is None:
                continue

            # Skip standalone-only files
            file_mode = f.get("mode", "both")
            if file_mode == "standalone":
                continue

            # --- resolve source provenance ---
            storage = f.get("storage", "")
            if storage in ("release", "large_file"):
                source = "large_file"
            else:
                source = _resolve_source(
                    fname, by_name, by_name_lower, data_names, by_path_suffix
                )
                if source is None:
                    path_field = f.get("path", "")
                    if path_field and path_field != fname:
                        source = _resolve_source(
                            path_field, by_name, by_name_lower,
                            data_names, by_path_suffix,
                        )
                # Try MD5 hash match
                if source is None:
                    md5_raw = f.get("md5", "")
                    if md5_raw:
                        for md5_val in md5_raw.split(","):
                            md5_val = md5_val.strip().lower()
                            if md5_val and by_md5.get(md5_val):
                                source = "bios"
                                break
                # Try SHA1 hash match
                if source is None:
                    sha1 = f.get("sha1", "")
                    if sha1 and sha1 in db_files:
                        source = "bios"
                if source is None:
                    source = "missing"

            in_repo = source != "missing"
            in_platform = fname in platform_names

            entry = {
                "name": fname,
                "required": f.get("required", False),
                "note": f.get("note", ""),
                "source_ref": f.get("source_ref", ""),
                "in_platform": in_platform,
                "in_repo": in_repo,
                "source": source,
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
            "gap_missing": sum(1 for g in gaps if g["source"] == "missing"),
            "gap_bios": sum(1 for g in gaps if g["source"] == "bios"),
            "gap_data": sum(1 for g in gaps if g["source"] == "data"),
            "gap_large_file": sum(1 for g in gaps if g["source"] == "large_file"),
            "gap_details": gaps,
        }

    return report


def print_report(report: dict) -> None:
    """Print a human-readable gap analysis report."""
    print("Emulator vs Platform Gap Analysis")
    print("=" * 60)

    total_gaps = 0
    totals: dict[str, int] = {"bios": 0, "data": 0, "large_file": 0, "missing": 0}

    for emu_name, data in sorted(report.items()):
        gaps = data["gaps"]
        if gaps == 0:
            continue

        parts = []
        for key in ("bios", "data", "large_file", "missing"):
            count = data.get(f"gap_{key}", 0)
            if count:
                parts.append(f"{count} {key}")
        status = ", ".join(parts) if parts else "OK"

        print(f"\n{data['emulator']} ({', '.join(data['systems'])})")
        print(
            f"  {data['total_files']} files in profile, "
            f"{data['platform_covered']} declared by platforms, "
            f"{gaps} undeclared"
        )
        print(f"  Gaps: {status}")

        for g in data["gap_details"]:
            req = "*" if g["required"] else " "
            src = g.get("source", "missing").upper()
            note = f" -- {g['note']}" if g["note"] else ""
            print(f"    {req} {g['name']} [{src}]{note}")

        total_gaps += gaps
        for key in totals:
            totals[key] += data.get(f"gap_{key}", 0)

    print(f"\n{'=' * 60}")
    print(f"Total: {total_gaps} undeclared files across all emulators")
    available = totals["bios"] + totals["data"] + totals["large_file"]
    print(f"  {available} available (bios: {totals['bios']}, data: {totals['data']}, "
          f"large_file: {totals['large_file']})")
    print(f"  {totals['missing']} missing (need to be sourced)")


def main():
    parser = argparse.ArgumentParser(description="Emulator vs platform gap analysis")
    parser.add_argument("--emulators-dir", default=DEFAULT_EMULATORS_DIR)
    parser.add_argument("--platforms-dir", default=DEFAULT_PLATFORMS_DIR)
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--emulator", "-e", help="Analyze single emulator")
    parser.add_argument(
        "--platform", "-p", help="Platform name (required for --target)"
    )
    parser.add_argument("--target", "-t", help="Hardware target (e.g., switch, rpi4)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    profiles = load_emulator_profiles(args.emulators_dir)
    if args.emulator:
        profiles = {k: v for k, v in profiles.items() if k == args.emulator}

    if args.target:
        if not args.platform:
            parser.error("--target requires --platform")
        from common import load_target_config, resolve_platform_cores

        target_cores = load_target_config(
            args.platform, args.target, args.platforms_dir
        )
        config = load_platform_config(args.platform, args.platforms_dir)
        relevant = resolve_platform_cores(config, profiles, target_cores=target_cores)
        profiles = {k: v for k, v in profiles.items() if k in relevant}

    if not profiles:
        print("No emulator profiles found.", file=sys.stderr)
        return

    declared, plat_data_dirs = load_platform_files(args.platforms_dir)
    db = load_database(args.db)
    data_names = _build_supplemental_index()
    report = cross_reference(profiles, declared, db, plat_data_dirs, data_names)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
