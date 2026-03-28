#!/usr/bin/env python3
"""Platform-native BIOS verification engine.

Replicates the exact verification logic of each platform:
- RetroArch/Lakka/RetroPie: file existence only (core_info.c path_is_valid)
- Batocera: MD5 + checkInsideZip, no required distinction (batocera-systems:1062-1091)
- Recalbox: MD5 + mandatory/hashMatchMandatory, 3-color severity (Bios.cpp:109-130)
- RetroBat: same as Batocera
- EmuDeck: MD5 whitelist per system
- BizHawk: SHA1 firmware hash verification

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
    _build_validation_index, _parse_validation, build_ground_truth,
    build_zip_contents_index, check_file_validation,
    check_inside_zip, compute_hashes, filter_files_by_mode,
    filter_systems_by_target, group_identical_platforms, list_emulator_profiles,
    list_system_ids, load_data_dir_registry, load_emulator_profiles,
    load_platform_config, md5sum, md5_composite, resolve_local_file,
    resolve_platform_cores,
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

_STATUS_ORDER = {Status.OK: 0, Status.UNTESTED: 1, Status.MISSING: 2}
_SEVERITY_ORDER = {Severity.OK: 0, Severity.INFO: 1, Severity.WARNING: 2, Severity.CRITICAL: 3}


# ---------------------------------------------------------------------------
# Verification functions
# ---------------------------------------------------------------------------

def verify_entry_existence(
    file_entry: dict, local_path: str | None,
    validation_index: dict[str, dict] | None = None,
) -> dict:
    """RetroArch verification: path_is_valid() — file exists = OK."""
    name = file_entry.get("name", "")
    required = file_entry.get("required", True)
    if not local_path:
        return {"name": name, "status": Status.MISSING, "required": required}
    result = {"name": name, "status": Status.OK, "required": required}
    if validation_index:
        reason = check_file_validation(local_path, name, validation_index)
        if reason:
            ventry = validation_index.get(name, {})
            emus = ", ".join(ventry.get("emulators", []))
            result["discrepancy"] = f"file present (OK) but {emus} says {reason}"
    return result


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
        md5_list = [m.strip().lower() for m in expected_md5.split(",") if m.strip()]
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


def verify_entry_sha1(
    file_entry: dict,
    local_path: str | None,
) -> dict:
    """SHA1 verification — BizHawk firmware hash check."""
    name = file_entry.get("name", "")
    expected_sha1 = file_entry.get("sha1", "")
    required = file_entry.get("required", True)
    base = {"name": name, "required": required}

    if not local_path:
        return {**base, "status": Status.MISSING}

    if not expected_sha1:
        return {**base, "status": Status.OK, "path": local_path}

    hashes = compute_hashes(local_path)
    actual_sha1 = hashes["sha1"].lower()
    if actual_sha1 == expected_sha1.lower():
        return {**base, "status": Status.OK, "path": local_path}

    return {**base, "status": Status.UNTESTED, "path": local_path,
            "reason": f"expected {expected_sha1[:12]}… got {actual_sha1[:12]}…"}


# ---------------------------------------------------------------------------
# Severity mapping per platform
# ---------------------------------------------------------------------------

def compute_severity(
    status: str, required: bool, mode: str, hle_fallback: bool = False,
) -> str:
    """Map (status, required, verification_mode, hle_fallback) → severity.

    Based on native platform behavior + emulator HLE capability:
    - RetroArch (existence): required+missing = warning, optional+missing = info
    - Batocera/Recalbox/RetroBat/EmuDeck (md5): hash-based verification
    - BizHawk (sha1): same severity rules as md5
    - hle_fallback: core works without this file via HLE → always INFO when missing
    """
    if status == Status.OK:
        return Severity.OK

    # HLE fallback: core works without this file regardless of platform requirement
    if hle_fallback and status == Status.MISSING:
        return Severity.INFO

    if mode == "existence":
        if status == Status.MISSING:
            return Severity.WARNING if required else Severity.INFO
        return Severity.OK

    # md5 mode (Batocera, Recalbox, RetroBat, EmuDeck)
    if status == Status.MISSING:
        return Severity.CRITICAL if required else Severity.WARNING
    if status == Status.UNTESTED:
        return Severity.WARNING
    return Severity.OK


# ---------------------------------------------------------------------------
# ZIP content index
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Cross-reference: undeclared files used by cores
# ---------------------------------------------------------------------------


def _build_expected(file_entry: dict, checks: list[str]) -> dict:
    """Extract expected validation values from an emulator profile file entry."""
    expected: dict = {}
    if not checks:
        return expected
    if "size" in checks:
        for key in ("size", "min_size", "max_size"):
            if file_entry.get(key) is not None:
                expected[key] = file_entry[key]
    for hash_type in ("crc32", "md5", "sha1", "sha256"):
        if hash_type in checks and file_entry.get(hash_type):
            expected[hash_type] = file_entry[hash_type]
    adler_val = file_entry.get("known_hash_adler32") or file_entry.get("adler32")
    if adler_val:
        expected["adler32"] = adler_val
    return expected

def _name_in_index(name: str, by_name: dict, by_path_suffix: dict | None = None,
                    data_names: set[str] | None = None) -> bool:
    """Check if a name is resolvable in the database indexes or data directories."""
    if name in by_name:
        return True
    basename = name.rsplit("/", 1)[-1]
    if basename != name and basename in by_name:
        return True
    if by_path_suffix and name in by_path_suffix:
        return True
    if data_names:
        if name in data_names or name.lower() in data_names:
            return True
        if basename != name and (basename in data_names or basename.lower() in data_names):
            return True
    return False


def find_undeclared_files(
    config: dict,
    emulators_dir: str,
    db: dict,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
    data_names: set[str] | None = None,
) -> list[dict]:
    """Find files needed by cores but not declared in platform config."""
    # Collect all filenames declared by this platform
    declared_names: set[str] = set()
    for sys_id, system in config.get("systems", {}).items():
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
    by_path_suffix = db.get("indexes", {}).get("by_path_suffix", {})
    profiles = emu_profiles if emu_profiles is not None else load_emulator_profiles(emulators_dir)

    relevant = resolve_platform_cores(config, profiles, target_cores=target_cores)
    standalone_set = set(str(c) for c in config.get("standalone_cores", []))
    undeclared = []
    seen_files: set[str] = set()
    # Track archives: archive_name -> {in_repo, emulator, files: [...], ...}
    archive_entries: dict[str, dict] = {}

    for emu_name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias"):
            continue
        if emu_name not in relevant:
            continue

        # Check if this profile is standalone: match profile name or any cores: alias
        is_standalone = emu_name in standalone_set or bool(
            standalone_set & {str(c) for c in profile.get("cores", [])}
        )

        for f in profile.get("files", []):
            fname = f.get("name", "")
            if not fname or fname in seen_files:
                continue
            # Skip pattern placeholders (e.g., <user-selected>.bin)
            if "<" in fname or ">" in fname or "*" in fname:
                continue
            # Mode filtering: skip files incompatible with platform's usage
            file_mode = f.get("mode")
            if file_mode == "standalone" and not is_standalone:
                continue
            if file_mode == "libretro" and is_standalone:
                continue

            archive = f.get("archive")

            # Skip files declared by the platform (by name or archive)
            if fname in declared_names:
                seen_files.add(fname)
                continue
            if archive and archive in declared_names:
                seen_files.add(fname)
                continue

            seen_files.add(fname)

            # Archived files are grouped by archive
            if archive:
                if archive not in archive_entries:
                    in_repo = _name_in_index(archive, by_name, by_path_suffix, data_names)
                    archive_entries[archive] = {
                        "emulator": profile.get("emulator", emu_name),
                        "name": archive,
                        "archive": archive,
                        "path": archive,
                        "required": False,
                        "hle_fallback": False,
                        "category": f.get("category", "bios"),
                        "in_repo": in_repo,
                        "note": "",
                        "checks": [],
                        "source_ref": None,
                        "expected": {},
                        "archive_file_count": 0,
                        "archive_required_count": 0,
                    }
                entry = archive_entries[archive]
                entry["archive_file_count"] += 1
                if f.get("required", False):
                    entry["archive_required_count"] += 1
                    entry["required"] = True
                continue

            # Determine destination path based on mode
            if is_standalone:
                dest = f.get("standalone_path") or f.get("path") or fname
            else:
                dest = f.get("path") or fname

            # Resolution: try name, then path basename, then path_suffix
            in_repo = _name_in_index(fname, by_name, by_path_suffix, data_names)
            if not in_repo and dest != fname:
                path_base = dest.rsplit("/", 1)[-1]
                in_repo = _name_in_index(path_base, by_name, by_path_suffix, data_names)

            checks = _parse_validation(f.get("validation"))
            undeclared.append({
                "emulator": profile.get("emulator", emu_name),
                "name": fname,
                "path": dest,
                "required": f.get("required", False),
                "hle_fallback": f.get("hle_fallback", False),
                "category": f.get("category", "bios"),
                "in_repo": in_repo,
                "note": f.get("note", ""),
                "checks": sorted(checks) if checks else [],
                "source_ref": f.get("source_ref"),
                "expected": _build_expected(f, checks),
            })

    # Append grouped archive entries
    for entry in sorted(archive_entries.values(), key=lambda e: e["name"]):
        undeclared.append(entry)

    return undeclared


def find_exclusion_notes(
    config: dict, emulators_dir: str, emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
) -> list[dict]:
    """Document why certain emulator files are intentionally excluded.

    Reports:
    - Launchers (BIOS managed by standalone emulator)
    - Standalone-only files (not needed in libretro mode)
    - Frozen snapshots with files: [] (code doesn't load .info firmware)
    - Files covered by data_directories
    """
    profiles = emu_profiles if emu_profiles is not None else load_emulator_profiles(emulators_dir)
    platform_systems = set()
    for sys_id in config.get("systems", {}):
        platform_systems.add(sys_id)

    relevant = resolve_platform_cores(config, profiles, target_cores=target_cores)
    notes = []
    for emu_name, profile in sorted(profiles.items()):
        emu_systems = set(profile.get("systems", []))
        # Match by core resolution OR system intersection (documents all potential emulators)
        if emu_name not in relevant and not (emu_systems & platform_systems):
            continue

        emu_display = profile.get("emulator", emu_name)

        # Launcher excluded entirely
        if profile.get("type") == "launcher":
            notes.append({
                "emulator": emu_display, "reason": "launcher",
                "detail": profile.get("exclusion_note", "BIOS managed by standalone emulator"),
            })
            continue

        # Profile-level exclusion note (frozen snapshots, etc.)
        exclusion_note = profile.get("exclusion_note")
        if exclusion_note:
            notes.append({
                "emulator": emu_display, "reason": "exclusion_note",
                "detail": exclusion_note,
            })
            continue

        # Count standalone-only files — but only report as excluded if the
        # platform does NOT use this emulator in standalone mode
        standalone_set = set(str(c) for c in config.get("standalone_cores", []))
        is_standalone = emu_name in standalone_set or bool(
            standalone_set & {str(c) for c in profile.get("cores", [])}
        )
        if not is_standalone:
            standalone_files = [f for f in profile.get("files", []) if f.get("mode") == "standalone"]
            if standalone_files:
                names = [f["name"] for f in standalone_files[:3]]
                more = f" +{len(standalone_files)-3}" if len(standalone_files) > 3 else ""
                notes.append({
                    "emulator": emu_display, "reason": "standalone_only",
                    "detail": f"{len(standalone_files)} files for standalone mode only ({', '.join(names)}{more})",
                })

    return notes


# ---------------------------------------------------------------------------
# Platform verification
# ---------------------------------------------------------------------------

def _find_best_variant(
    file_entry: dict, db: dict, current_path: str,
    validation_index: dict,
) -> str | None:
    """Search for a repo file that passes both platform MD5 and emulator validation."""
    fname = file_entry.get("name", "")
    if not fname or fname not in validation_index:
        return None

    md5_expected = file_entry.get("md5", "")
    md5_set = {m.strip().lower() for m in md5_expected.split(",") if m.strip()} if md5_expected else set()

    by_name = db.get("indexes", {}).get("by_name", {})
    files_db = db.get("files", {})

    for sha1 in by_name.get(fname, []):
        candidate = files_db.get(sha1, {})
        path = candidate.get("path", "")
        if not path or not os.path.exists(path) or os.path.realpath(path) == os.path.realpath(current_path):
            continue
        if md5_set and candidate.get("md5", "").lower() not in md5_set:
            continue
        reason = check_file_validation(path, fname, validation_index)
        if reason is None:
            return path
    return None


def verify_platform(
    config: dict, db: dict,
    emulators_dir: str = DEFAULT_EMULATORS_DIR,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
) -> dict:
    """Verify all BIOS files for a platform, including cross-reference gaps."""
    mode = config.get("verification_mode", "existence")
    platform = config.get("platform", "unknown")

    has_zipped = any(
        fe.get("zipped_file")
        for sys in config.get("systems", {}).values()
        for fe in sys.get("files", [])
    )
    zip_contents = build_zip_contents_index(db) if has_zipped else {}

    # Build HLE + validation indexes from emulator profiles
    profiles = emu_profiles if emu_profiles is not None else load_emulator_profiles(emulators_dir)
    hle_index: dict[str, bool] = {}
    for profile in profiles.values():
        for f in profile.get("files", []):
            if f.get("hle_fallback"):
                hle_index[f.get("name", "")] = True
    validation_index = _build_validation_index(profiles)

    # Filter systems by target
    plat_cores = resolve_platform_cores(config, profiles) if target_cores else None
    verify_systems = filter_systems_by_target(
        config.get("systems", {}), profiles, target_cores,
        platform_cores=plat_cores,
    )

    # Per-entry results
    details = []
    # Per-destination aggregation
    file_status: dict[str, str] = {}
    file_required: dict[str, bool] = {}
    file_severity: dict[str, str] = {}

    for sys_id, system in verify_systems.items():
        for file_entry in system.get("files", []):
            local_path, resolve_status = resolve_local_file(
                file_entry, db, zip_contents,
            )
            if mode == "existence":
                result = verify_entry_existence(
                    file_entry, local_path, validation_index,
                )
            elif mode == "sha1":
                result = verify_entry_sha1(file_entry, local_path)
            else:
                result = verify_entry_md5(file_entry, local_path, resolve_status)
                # Emulator-level validation: informational for platform packs.
                # Platform verification (MD5) is the authority. Emulator
                # mismatches are reported as discrepancies, not failures.
                if result["status"] == Status.OK and local_path and validation_index:
                    fname = file_entry.get("name", "")
                    reason = check_file_validation(local_path, fname, validation_index)
                    if reason:
                        better = _find_best_variant(
                            file_entry, db, local_path, validation_index,
                        )
                        if not better:
                            ventry = validation_index.get(fname, {})
                            emus = ", ".join(ventry.get("emulators", []))
                            result["discrepancy"] = f"{platform} says OK but {emus} says {reason}"
            result["system"] = sys_id
            result["hle_fallback"] = hle_index.get(file_entry.get("name", ""), False)
            result["ground_truth"] = build_ground_truth(
                file_entry.get("name", ""), validation_index,
            )
            details.append(result)

            # Aggregate by destination
            dest = file_entry.get("destination", file_entry.get("name", ""))
            if not dest:
                dest = f"{sys_id}/{file_entry.get('name', '')}"
            required = file_entry.get("required", True)
            cur = result["status"]
            prev = file_status.get(dest)
            if prev is None or _STATUS_ORDER.get(cur, 0) > _STATUS_ORDER.get(prev, 0):
                file_status[dest] = cur
                file_required[dest] = required
            hle = hle_index.get(file_entry.get("name", ""), False)
            sev = compute_severity(cur, required, mode, hle)
            prev_sev = file_severity.get(dest)
            if prev_sev is None or _SEVERITY_ORDER.get(sev, 0) > _SEVERITY_ORDER.get(prev_sev, 0):
                file_severity[dest] = sev

    # Count by severity
    counts = {Severity.OK: 0, Severity.INFO: 0, Severity.WARNING: 0, Severity.CRITICAL: 0}
    for s in file_severity.values():
        counts[s] = counts.get(s, 0) + 1

    # Count by file status (ok/untested/missing)
    status_counts: dict[str, int] = {}
    for s in file_status.values():
        status_counts[s] = status_counts.get(s, 0) + 1

    # Cross-reference undeclared files
    from cross_reference import _build_supplemental_index
    data_names = _build_supplemental_index()
    undeclared = find_undeclared_files(config, emulators_dir, db, emu_profiles,
                                       target_cores=target_cores, data_names=data_names)
    exclusions = find_exclusion_notes(config, emulators_dir, emu_profiles, target_cores=target_cores)

    # Ground truth coverage
    gt_filenames = set(validation_index)
    dest_to_name: dict[str, str] = {}
    for sys_id, system in verify_systems.items():
        for fe in system.get("files", []):
            dest = fe.get("destination", fe.get("name", ""))
            if not dest:
                dest = f"{sys_id}/{fe.get('name', '')}"
            dest_to_name.setdefault(dest, fe.get("name", ""))
    with_validation = sum(
        1 for dest in file_status if dest_to_name.get(dest, "") in gt_filenames
    )
    total = len(file_status)

    return {
        "platform": platform,
        "verification_mode": mode,
        "total_files": total,
        "severity_counts": counts,
        "status_counts": status_counts,
        "undeclared_files": undeclared,
        "exclusion_notes": exclusions,
        "details": details,
        "ground_truth_coverage": {
            "with_validation": with_validation,
            "platform_only": total - with_validation,
            "total": total,
        },
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _format_ground_truth_aggregate(ground_truth: list[dict]) -> str:
    """Format ground truth as a single aggregated line.

    Example: beetle_psx [md5], pcsx_rearmed [existence]
    """
    parts = []
    for gt in ground_truth:
        checks_label = "+".join(gt["checks"]) if gt["checks"] else "existence"
        parts.append(f"{gt['emulator']} [{checks_label}]")
    return ", ".join(parts)


def _format_ground_truth_verbose(ground_truth: list[dict]) -> list[str]:
    """Format ground truth as one line per core with expected values and source ref.

    Example: handy validates size=512,crc32=0d973c9d [rom.h:48-49]
    """
    lines = []
    for gt in ground_truth:
        checks_label = "+".join(gt["checks"]) if gt["checks"] else "existence"
        expected = gt.get("expected", {})
        if expected:
            vals = ",".join(f"{k}={v}" for k, v in sorted(expected.items()))
            part = f"{gt['emulator']} validates {vals}"
        else:
            part = f"{gt['emulator']} validates {checks_label}"
        if gt.get("source_ref"):
            part += f" [{gt['source_ref']}]"
        lines.append(part)
    return lines


def print_platform_result(result: dict, group: list[str], verbose: bool = False) -> None:
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
        sc = result.get("status_counts", {})
        untested = sc.get(Status.UNTESTED, 0)
        missing = sc.get(Status.MISSING, 0)
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
            hle = ", HLE available" if d.get("hle_fallback") else ""
            reason = d.get("reason", "")
            print(f"  UNTESTED ({req}{hle}): {key} — {reason}")
            gt = d.get("ground_truth", [])
            if gt:
                if verbose:
                    for line in _format_ground_truth_verbose(gt):
                        print(f"    {line}")
                else:
                    print(f"    {_format_ground_truth_aggregate(gt)}")
    for d in result["details"]:
        if d["status"] == Status.MISSING:
            key = f"{d['system']}/{d['name']}"
            if key in seen_details:
                continue
            seen_details.add(key)
            req = "required" if d.get("required", True) else "optional"
            hle = ", HLE available" if d.get("hle_fallback") else ""
            print(f"  MISSING ({req}{hle}): {key}")
            gt = d.get("ground_truth", [])
            if gt:
                if verbose:
                    for line in _format_ground_truth_verbose(gt):
                        print(f"    {line}")
                else:
                    print(f"    {_format_ground_truth_aggregate(gt)}")
    for d in result["details"]:
        disc = d.get("discrepancy")
        if disc:
            key = f"{d['system']}/{d['name']}"
            if key in seen_details:
                continue
            seen_details.add(key)
            print(f"  DISCREPANCY: {key} — {disc}")
            gt = d.get("ground_truth", [])
            if gt:
                if verbose:
                    for line in _format_ground_truth_verbose(gt):
                        print(f"    {line}")
                else:
                    print(f"    {_format_ground_truth_aggregate(gt)}")

    if verbose:
        for d in result["details"]:
            if d["status"] == Status.OK:
                key = f"{d['system']}/{d['name']}"
                if key in seen_details:
                    continue
                seen_details.add(key)
                gt = d.get("ground_truth", [])
                if gt:
                    req = "required" if d.get("required", True) else "optional"
                    print(f"  OK ({req}): {key}")
                    for line in _format_ground_truth_verbose(gt):
                        print(f"    {line}")

    # Cross-reference: undeclared files used by cores
    undeclared = result.get("undeclared_files", [])
    if undeclared:
        bios_files = [u for u in undeclared if u.get("category", "bios") == "bios"]
        game_data = [u for u in undeclared if u.get("category", "bios") == "game_data"]

        req_not_in_repo = [u for u in bios_files if u["required"] and not u["in_repo"] and not u.get("hle_fallback")]
        req_hle_not_in_repo = [u for u in bios_files if u["required"] and not u["in_repo"] and u.get("hle_fallback")]
        req_in_repo = [u for u in bios_files if u["required"] and u["in_repo"]]
        opt_in_repo = [u for u in bios_files if not u["required"] and u["in_repo"]]
        opt_not_in_repo = [u for u in bios_files if not u["required"] and not u["in_repo"]]

        # Core coverage: files from emulator profiles not declared by the platform
        core_in_pack = len(req_in_repo) + len(opt_in_repo)
        core_missing_req = len(req_not_in_repo) + len(req_hle_not_in_repo)
        core_missing_opt = len(opt_not_in_repo)
        core_total = len(bios_files)

        print(f"  Core files: {core_in_pack} in pack, {core_missing_req} required missing, {core_missing_opt} optional missing")

        # Required NOT in repo = critical
        if req_not_in_repo:
            for u in req_not_in_repo:
                arc_count = u.get("archive_file_count")
                if arc_count:
                    label = f"{u['name']} ({arc_count} file{'s' if arc_count != 1 else ''})"
                else:
                    label = u["name"]
                print(f"    MISSING (required): {u['emulator']} needs {label}")
                checks = u.get("checks", [])
                if checks:
                    if verbose:
                        expected = u.get("expected", {})
                        if expected:
                            vals = ",".join(f"{k}={v}" for k, v in sorted(expected.items()))
                            ref_part = f" [{u['source_ref']}]" if u.get("source_ref") else ""
                            print(f"      validates {vals}{ref_part}")
                        else:
                            checks_label = "+".join(checks)
                            ref_part = f" [{u['source_ref']}]" if u.get("source_ref") else ""
                            print(f"      validates {checks_label}{ref_part}")
                    else:
                        checks_label = "+".join(checks)
                        print(f"      [{checks_label}]")
        if req_hle_not_in_repo:
            for u in req_hle_not_in_repo:
                arc_count = u.get("archive_file_count")
                if arc_count:
                    label = f"{u['name']} ({arc_count} file{'s' if arc_count != 1 else ''})"
                else:
                    label = u["name"]
                print(f"    MISSING (required, HLE fallback): {u['emulator']} needs {label}")
                checks = u.get("checks", [])
                if checks:
                    if verbose:
                        expected = u.get("expected", {})
                        if expected:
                            vals = ",".join(f"{k}={v}" for k, v in sorted(expected.items()))
                            ref_part = f" [{u['source_ref']}]" if u.get("source_ref") else ""
                            print(f"      validates {vals}{ref_part}")
                        else:
                            checks_label = "+".join(checks)
                            ref_part = f" [{u['source_ref']}]" if u.get("source_ref") else ""
                            print(f"      validates {checks_label}{ref_part}")
                    else:
                        checks_label = "+".join(checks)
                        print(f"      [{checks_label}]")

        if game_data:
            gd_missing = [u for u in game_data if not u["in_repo"]]
            gd_present = [u for u in game_data if u["in_repo"]]
            if gd_missing or gd_present:
                print(f"  Game data: {len(gd_present)} in pack, {len(gd_missing)} missing")

    # No external files (explain why certain emulator files are NOT included)
    exclusions = result.get("exclusion_notes", [])
    if exclusions:
        print(f"  No external files ({len(exclusions)}):")
        for ex in exclusions:
            print(f"    {ex['emulator']} — {ex['detail']} [{ex['reason']}]")

    # Ground truth coverage footer
    gt_cov = result.get("ground_truth_coverage")
    if gt_cov and gt_cov["total"] > 0:
        pct = gt_cov["with_validation"] * 100 // gt_cov["total"]
        print(f"  Ground truth: {gt_cov['with_validation']}/{gt_cov['total']} files have emulator validation ({pct}%)")
        if gt_cov["platform_only"]:
            print(f"    {gt_cov['platform_only']} platform-only (no emulator profile)")


# ---------------------------------------------------------------------------
# Emulator/system mode verification
# ---------------------------------------------------------------------------

def _effective_validation_label(details: list[dict], validation_index: dict) -> str:
    """Determine the bracket label for the report.

    Returns the union of all check types used, e.g. [crc32+existence+size].
    """
    all_checks: set[str] = set()
    has_files = False
    for d in details:
        fname = d.get("name", "")
        if d.get("note"):
            continue  # skip informational entries (empty profiles)
        has_files = True
        entry = validation_index.get(fname)
        if entry:
            all_checks.update(entry["checks"])
        else:
            all_checks.add("existence")
    if not has_files:
        return "existence"
    return "+".join(sorted(all_checks))


def verify_emulator(
    profile_names: list[str],
    emulators_dir: str,
    db: dict,
    standalone: bool = False,
) -> dict:
    """Verify files for specific emulator profiles."""
    profiles = load_emulator_profiles(emulators_dir)
    zip_contents = build_zip_contents_index(db)

    # Also load aliases for redirect messages
    all_profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)

    # Resolve profile names, reject alias/launcher
    selected: list[tuple[str, dict]] = []
    for name in profile_names:
        if name not in all_profiles:
            available = sorted(k for k, v in all_profiles.items()
                               if v.get("type") not in ("alias", "test"))
            print(f"Error: emulator '{name}' not found", file=sys.stderr)
            print(f"Available: {', '.join(available[:10])}...", file=sys.stderr)
            sys.exit(1)
        p = all_profiles[name]
        if p.get("type") == "alias":
            alias_of = p.get("alias_of", "?")
            print(f"Error: {name} is an alias of {alias_of} — use --emulator {alias_of}",
                  file=sys.stderr)
            sys.exit(1)
        if p.get("type") == "launcher":
            print(f"Error: {name} is a launcher — use the emulator it launches",
                  file=sys.stderr)
            sys.exit(1)
        # Check standalone capability
        ptype = p.get("type", "libretro")
        if standalone and "standalone" not in ptype:
            print(f"Error: {name} ({ptype}) does not support --standalone",
                  file=sys.stderr)
            sys.exit(1)
        selected.append((name, p))

    # Build validation index from selected profiles only
    selected_profiles = {n: p for n, p in selected}
    validation_index = _build_validation_index(selected_profiles)
    data_registry = load_data_dir_registry(
        os.path.join(os.path.dirname(__file__), "..", "platforms")
    )

    details = []
    file_status: dict[str, str] = {}
    file_severity: dict[str, str] = {}
    dest_to_name: dict[str, str] = {}
    data_dir_notices: list[str] = []

    for emu_name, profile in selected:
        files = filter_files_by_mode(profile.get("files", []), standalone)

        # Check data directories (only notice if not cached)
        for dd in profile.get("data_directories", []):
            ref = dd.get("ref", "")
            if not ref:
                continue
            if data_registry and ref in data_registry:
                cache_path = data_registry[ref].get("local_cache", "")
                if cache_path and os.path.isdir(cache_path):
                    continue  # cached, no notice needed
            data_dir_notices.append(ref)

        if not files:
            details.append({
                "name": f"({emu_name})", "status": Status.OK,
                "required": False, "system": "",
                "note": f"No files needed for {profile.get('emulator', emu_name)}",
                "ground_truth": [],
            })
            continue

        # Verify archives as units (e.g., neogeo.zip, aes.zip)
        seen_archives: set[str] = set()
        for file_entry in files:
            archive = file_entry.get("archive")
            if archive and archive not in seen_archives:
                seen_archives.add(archive)
                archive_entry = {"name": archive}
                local_path, _ = resolve_local_file(archive_entry, db, zip_contents)
                required = any(
                    f.get("archive") == archive and f.get("required", True)
                    for f in files
                )
                if local_path:
                    result = {"name": archive, "status": Status.OK,
                              "required": required, "path": local_path}
                else:
                    result = {"name": archive, "status": Status.MISSING,
                              "required": required}
                result["system"] = file_entry.get("system", "")
                result["hle_fallback"] = False
                result["ground_truth"] = build_ground_truth(archive, validation_index)
                details.append(result)
                dest = archive
                dest_to_name[dest] = archive
                cur = result["status"]
                prev = file_status.get(dest)
                if prev is None or _STATUS_ORDER.get(cur, 0) > _STATUS_ORDER.get(prev, 0):
                    file_status[dest] = cur
                sev = compute_severity(cur, required, "existence", False)
                prev_sev = file_severity.get(dest)
                if prev_sev is None or _SEVERITY_ORDER.get(sev, 0) > _SEVERITY_ORDER.get(prev_sev, 0):
                    file_severity[dest] = sev

        for file_entry in files:
            # Skip archived files (verified as archive units above)
            if file_entry.get("archive"):
                continue

            dest_hint = file_entry.get("path", "")
            local_path, resolve_status = resolve_local_file(
                file_entry, db, zip_contents, dest_hint=dest_hint,
            )
            name = file_entry.get("name", "")
            required = file_entry.get("required", True)
            hle = file_entry.get("hle_fallback", False)

            if not local_path:
                result = {"name": name, "status": Status.MISSING, "required": required}
            else:
                # Apply emulator validation
                reason = check_file_validation(local_path, name, validation_index)
                if reason:
                    result = {"name": name, "status": Status.UNTESTED,
                              "required": required, "path": local_path,
                              "reason": reason}
                else:
                    result = {"name": name, "status": Status.OK,
                              "required": required, "path": local_path}

            result["system"] = file_entry.get("system", "")
            result["hle_fallback"] = hle
            result["ground_truth"] = build_ground_truth(name, validation_index)
            details.append(result)

            # Aggregate by destination (path if available, else name)
            dest = file_entry.get("path", "") or name
            dest_to_name[dest] = name
            cur = result["status"]
            prev = file_status.get(dest)
            if prev is None or _STATUS_ORDER.get(cur, 0) > _STATUS_ORDER.get(prev, 0):
                file_status[dest] = cur
            sev = compute_severity(cur, required, "existence", hle)
            prev_sev = file_severity.get(dest)
            if prev_sev is None or _SEVERITY_ORDER.get(sev, 0) > _SEVERITY_ORDER.get(prev_sev, 0):
                file_severity[dest] = sev

    counts = {Severity.OK: 0, Severity.INFO: 0, Severity.WARNING: 0, Severity.CRITICAL: 0}
    for s in file_severity.values():
        counts[s] = counts.get(s, 0) + 1
    status_counts: dict[str, int] = {}
    for s in file_status.values():
        status_counts[s] = status_counts.get(s, 0) + 1

    label = _effective_validation_label(details, validation_index)

    gt_filenames = set(validation_index)
    total = len(file_status)
    with_validation = sum(
        1 for dest in file_status if dest_to_name.get(dest, "") in gt_filenames
    )

    return {
        "emulators": [n for n, _ in selected],
        "verification_mode": label,
        "total_files": total,
        "severity_counts": counts,
        "status_counts": status_counts,
        "details": details,
        "data_dir_notices": sorted(set(data_dir_notices)),
        "ground_truth_coverage": {
            "with_validation": with_validation,
            "platform_only": total - with_validation,
            "total": total,
        },
    }


def verify_system(
    system_ids: list[str],
    emulators_dir: str,
    db: dict,
    standalone: bool = False,
) -> dict:
    """Verify files for all emulators supporting given system IDs."""
    profiles = load_emulator_profiles(emulators_dir)
    matching = []
    for name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias", "test"):
            continue
        emu_systems = set(profile.get("systems", []))
        if emu_systems & set(system_ids):
            ptype = profile.get("type", "libretro")
            if standalone and "standalone" not in ptype:
                continue  # skip non-standalone in standalone mode
            matching.append(name)

    if not matching:
        all_systems: set[str] = set()
        for p in profiles.values():
            all_systems.update(p.get("systems", []))
        if standalone:
            print(f"No standalone emulators found for system(s): {', '.join(system_ids)}",
                  file=sys.stderr)
        else:
            print(f"No emulators found for system(s): {', '.join(system_ids)}",
                  file=sys.stderr)
        print(f"Available systems: {', '.join(sorted(all_systems)[:20])}...",
              file=sys.stderr)
        sys.exit(1)

    return verify_emulator(matching, emulators_dir, db, standalone)


def print_emulator_result(result: dict, verbose: bool = False) -> None:
    """Print verification result for emulator/system mode."""
    label = " + ".join(result["emulators"])
    mode = result["verification_mode"]
    total = result["total_files"]
    c = result["severity_counts"]
    ok_count = c[Severity.OK]

    sc = result.get("status_counts", {})
    untested = sc.get(Status.UNTESTED, 0)
    missing = sc.get(Status.MISSING, 0)
    parts = [f"{ok_count}/{total} OK"]
    if untested:
        parts.append(f"{untested} untested")
    if missing:
        parts.append(f"{missing} missing")
    print(f"{label}: {', '.join(parts)} [{mode}]")

    seen = set()
    for d in result["details"]:
        if d["status"] == Status.UNTESTED:
            if d["name"] in seen:
                continue
            seen.add(d["name"])
            req = "required" if d.get("required", True) else "optional"
            hle = ", HLE available" if d.get("hle_fallback") else ""
            reason = d.get("reason", "")
            print(f"  UNTESTED ({req}{hle}): {d['name']} — {reason}")
            gt = d.get("ground_truth", [])
            if gt:
                if verbose:
                    for line in _format_ground_truth_verbose(gt):
                        print(f"    {line}")
                else:
                    print(f"    {_format_ground_truth_aggregate(gt)}")
    for d in result["details"]:
        if d["status"] == Status.MISSING:
            if d["name"] in seen:
                continue
            seen.add(d["name"])
            req = "required" if d.get("required", True) else "optional"
            hle = ", HLE available" if d.get("hle_fallback") else ""
            print(f"  MISSING ({req}{hle}): {d['name']}")
            gt = d.get("ground_truth", [])
            if gt:
                if verbose:
                    for line in _format_ground_truth_verbose(gt):
                        print(f"    {line}")
                else:
                    print(f"    {_format_ground_truth_aggregate(gt)}")
    for d in result["details"]:
        if d.get("note"):
            print(f"  {d['note']}")

    if verbose:
        for d in result["details"]:
            if d["status"] == Status.OK:
                if d["name"] in seen:
                    continue
                seen.add(d["name"])
                gt = d.get("ground_truth", [])
                if gt:
                    req = "required" if d.get("required", True) else "optional"
                    print(f"  OK ({req}): {d['name']}")
                    for line in _format_ground_truth_verbose(gt):
                        print(f"    {line}")

    for ref in result.get("data_dir_notices", []):
        print(f"  Note: data directory '{ref}' required but not included (use refresh_data_dirs.py)")

    # Ground truth coverage footer
    gt_cov = result.get("ground_truth_coverage")
    if gt_cov and gt_cov["total"] > 0:
        pct = gt_cov["with_validation"] * 100 // gt_cov["total"]
        print(f"  Ground truth: {gt_cov['with_validation']}/{gt_cov['total']} files have emulator validation ({pct}%)")
        if gt_cov["platform_only"]:
            print(f"    {gt_cov['platform_only']} platform-only (no emulator profile)")


def main():
    parser = argparse.ArgumentParser(description="Platform-native BIOS verification")
    parser.add_argument("--platform", "-p", help="Platform name")
    parser.add_argument("--all", action="store_true", help="Verify all active platforms")
    parser.add_argument("--emulator", "-e", help="Emulator profile name(s), comma-separated")
    parser.add_argument("--system", "-s", help="System ID(s), comma-separated")
    parser.add_argument("--standalone", action="store_true", help="Use standalone mode")
    parser.add_argument("--list-emulators", action="store_true", help="List available emulators")
    parser.add_argument("--list-systems", action="store_true", help="List available systems")
    parser.add_argument("--include-archived", action="store_true")
    parser.add_argument("--target", "-t", help="Hardware target (e.g., switch, rpi4)")
    parser.add_argument("--list-targets", action="store_true", help="List available targets for the platform")
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--platforms-dir", default=DEFAULT_PLATFORMS_DIR)
    parser.add_argument("--emulators-dir", default=DEFAULT_EMULATORS_DIR)
    parser.add_argument("--verbose", "-v", action="store_true", help="Show emulator ground truth details")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.list_emulators:
        list_emulator_profiles(args.emulators_dir)
        return
    if args.list_systems:
        list_system_ids(args.emulators_dir)
        return

    if args.list_targets:
        if not args.platform:
            parser.error("--list-targets requires --platform")
        from common import list_available_targets
        targets = list_available_targets(args.platform, args.platforms_dir)
        if not targets:
            print(f"No targets configured for platform '{args.platform}'")
            return
        for t in targets:
            aliases = f" (aliases: {', '.join(t['aliases'])})" if t['aliases'] else ""
            print(f"  {t['name']:30s} {t['architecture']:10s} {t['core_count']:>4d} cores{aliases}")
        return

    # Mutual exclusion
    modes = sum(1 for x in (args.platform, args.all, args.emulator, args.system) if x)
    if modes == 0:
        parser.error("Specify --platform, --all, --emulator, or --system")
    if modes > 1:
        parser.error("--platform, --all, --emulator, and --system are mutually exclusive")
    if args.standalone and not (args.emulator or args.system):
        parser.error("--standalone requires --emulator or --system")
    if args.target and not (args.platform or args.all):
        parser.error("--target requires --platform or --all")
    if args.target and (args.emulator or args.system):
        parser.error("--target is incompatible with --emulator and --system")

    with open(args.db) as f:
        db = json.load(f)

    # Emulator mode
    if args.emulator:
        names = [n.strip() for n in args.emulator.split(",") if n.strip()]
        result = verify_emulator(names, args.emulators_dir, db, args.standalone)
        if args.json:
            result["details"] = [d for d in result["details"] if d["status"] != Status.OK]
            print(json.dumps(result, indent=2))
        else:
            print_emulator_result(result, verbose=args.verbose)
        return

    # System mode
    if args.system:
        system_ids = [s.strip() for s in args.system.split(",") if s.strip()]
        result = verify_system(system_ids, args.emulators_dir, db, args.standalone)
        if args.json:
            result["details"] = [d for d in result["details"] if d["status"] != Status.OK]
            print(json.dumps(result, indent=2))
        else:
            print_emulator_result(result, verbose=args.verbose)
        return

    # Platform mode (existing)
    if args.all:
        from list_platforms import list_platforms as _list_platforms
        platforms = _list_platforms(include_archived=args.include_archived)
    elif args.platform:
        platforms = [args.platform]
    else:
        parser.error("Specify --platform or --all")
        return

    # Load emulator profiles once for cross-reference (not per-platform)
    emu_profiles = load_emulator_profiles(args.emulators_dir)

    target_cores_cache: dict[str, set[str] | None] = {}
    if args.target:
        from common import load_target_config
        skip = []
        for p in platforms:
            try:
                target_cores_cache[p] = load_target_config(p, args.target, args.platforms_dir)
            except FileNotFoundError:
                if args.all:
                    target_cores_cache[p] = None
                else:
                    print(f"ERROR: No target config for platform '{p}'", file=sys.stderr)
                    sys.exit(1)
            except ValueError as e:
                if args.all:
                    print(f"INFO: Skipping {p}: {e}")
                    skip.append(p)
                else:
                    print(f"ERROR: {e}", file=sys.stderr)
                    sys.exit(1)
        platforms = [p for p in platforms if p not in skip]

    # Group identical platforms (same function as generate_pack)
    groups = group_identical_platforms(platforms, args.platforms_dir,
                                      target_cores_cache if args.target else None)
    all_results = {}
    group_results: list[tuple[dict, list[str]]] = []
    for group_platforms, representative in groups:
        config = load_platform_config(representative, args.platforms_dir)
        tc = target_cores_cache.get(representative) if args.target else None
        result = verify_platform(config, db, args.emulators_dir, emu_profiles, target_cores=tc)
        names = [load_platform_config(p, args.platforms_dir).get("platform", p) for p in group_platforms]
        group_results.append((result, names))
        for p in group_platforms:
            all_results[p] = result

    if not args.json:
        for result, group in group_results:
            print_platform_result(result, group, verbose=args.verbose)
            print()

    if args.json:
        for r in all_results.values():
            r["details"] = [d for d in r["details"] if d["status"] != Status.OK]
        print(json.dumps(all_results, indent=2))


if __name__ == "__main__":
    main()
