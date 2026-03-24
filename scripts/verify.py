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
    build_zip_contents_index, check_inside_zip, compute_hashes,
    group_identical_platforms, load_data_dir_registry,
    load_emulator_profiles, load_platform_config,
    md5sum, md5_composite, resolve_local_file, resolve_platform_cores,
)
from crypto_verify import check_crypto_validation

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
# Emulator-level validation (size, crc32 checks from emulator profiles)
# ---------------------------------------------------------------------------

def _parse_validation(validation: list | dict | None) -> list[str]:
    """Extract the validation check list from a file's validation field.

    Handles both simple list and divergent (core/upstream) dict forms.
    For dicts, uses the ``core`` key since RetroArch users run the core.
    """
    if validation is None:
        return []
    if isinstance(validation, list):
        return validation
    if isinstance(validation, dict):
        return validation.get("core", [])
    return []


# Validation types that require console-specific cryptographic keys.
# verify.py cannot reproduce these — size checks still apply if combined.
_CRYPTO_CHECKS = frozenset({"signature", "crypto"})

# All reproducible validation types.
_HASH_CHECKS = frozenset({"crc32", "md5", "sha1", "adler32"})


def _build_validation_index(profiles: dict) -> dict[str, dict]:
    """Build per-filename validation rules from emulator profiles.

    Returns {filename: {"checks": [str], "size": int|None, "min_size": int|None,
    "max_size": int|None, "crc32": str|None, "md5": str|None, "sha1": str|None,
    "adler32": str|None, "crypto_only": [str]}}.

    ``crypto_only`` lists validation types we cannot reproduce (signature, crypto)
    so callers can report them as non-verifiable rather than silently skipping.

    When multiple emulators reference the same file, merges checks (union).
    Raises ValueError if two profiles declare conflicting values.
    """
    index: dict[str, dict] = {}
    sources: dict[str, dict[str, str]] = {}
    for emu_name, profile in profiles.items():
        if profile.get("type") in ("launcher", "alias"):
            continue
        for f in profile.get("files", []):
            fname = f.get("name", "")
            if not fname:
                continue
            checks = _parse_validation(f.get("validation"))
            if not checks:
                continue
            if fname not in index:
                index[fname] = {
                    "checks": set(), "sizes": set(),
                    "min_size": None, "max_size": None,
                    "crc32": set(), "md5": set(), "sha1": set(), "sha256": set(),
                    "adler32": set(), "crypto_only": set(),
                }
                sources[fname] = {}
            index[fname]["checks"].update(checks)
            # Track non-reproducible crypto checks
            index[fname]["crypto_only"].update(
                c for c in checks if c in _CRYPTO_CHECKS
            )
            # Size checks
            if "size" in checks:
                if f.get("size") is not None:
                    index[fname]["sizes"].add(f["size"])
                if f.get("min_size") is not None:
                    cur = index[fname]["min_size"]
                    index[fname]["min_size"] = min(cur, f["min_size"]) if cur is not None else f["min_size"]
                if f.get("max_size") is not None:
                    cur = index[fname]["max_size"]
                    index[fname]["max_size"] = max(cur, f["max_size"]) if cur is not None else f["max_size"]
            # Hash checks — collect all accepted hashes as sets (multiple valid
            # versions of the same file, e.g. MT-32 ROM versions)
            if "crc32" in checks and f.get("crc32"):
                norm = f["crc32"].lower()
                if norm.startswith("0x"):
                    norm = norm[2:]
                index[fname]["crc32"].add(norm)
            for hash_type in ("md5", "sha1", "sha256"):
                if hash_type in checks and f.get(hash_type):
                    index[fname][hash_type].add(f[hash_type].lower())
            # Adler32 — stored as known_hash_adler32 field (not in validation: list
            # for Dolphin, but support it in both forms for future profiles)
            adler_val = f.get("known_hash_adler32") or f.get("adler32")
            if adler_val:
                norm = adler_val.lower()
                if norm.startswith("0x"):
                    norm = norm[2:]
                index[fname]["adler32"].add(norm)
    # Convert sets to sorted tuples/lists for determinism
    for v in index.values():
        v["checks"] = sorted(v["checks"])
        v["crypto_only"] = sorted(v["crypto_only"])
        # Keep hash sets as frozensets for O(1) lookup in check_file_validation
    return index


def check_file_validation(
    local_path: str, filename: str, validation_index: dict[str, dict],
    bios_dir: str = "bios",
) -> str | None:
    """Check emulator-level validation on a resolved file.

    Supports: size (exact/min/max), crc32, md5, sha1, adler32,
    signature (RSA-2048 PKCS1v15 SHA256), crypto (AES-128-CBC + SHA256).

    Returns None if all checks pass or no validation applies.
    Returns a reason string if a check fails.
    """
    entry = validation_index.get(filename)
    if not entry:
        return None
    checks = entry["checks"]

    # Size checks — sizes is a set of accepted values
    if "size" in checks:
        actual_size = os.path.getsize(local_path)
        if entry["sizes"] and actual_size not in entry["sizes"]:
            expected = ",".join(str(s) for s in sorted(entry["sizes"]))
            return f"size mismatch: got {actual_size}, accepted [{expected}]"
        if entry["min_size"] is not None and actual_size < entry["min_size"]:
            return f"size too small: min {entry['min_size']}, got {actual_size}"
        if entry["max_size"] is not None and actual_size > entry["max_size"]:
            return f"size too large: max {entry['max_size']}, got {actual_size}"

    # Hash checks — compute once, reuse for all hash types.
    # Each hash field is a set of accepted values (multiple valid ROM versions).
    need_hashes = (
        any(h in checks and entry.get(h) for h in ("crc32", "md5", "sha1", "sha256"))
        or entry.get("adler32")
    )
    if need_hashes:
        hashes = compute_hashes(local_path)
        if "crc32" in checks and entry["crc32"]:
            if hashes["crc32"].lower() not in entry["crc32"]:
                expected = ",".join(sorted(entry["crc32"]))
                return f"crc32 mismatch: got {hashes['crc32']}, accepted [{expected}]"
        if "md5" in checks and entry["md5"]:
            if hashes["md5"].lower() not in entry["md5"]:
                expected = ",".join(sorted(entry["md5"]))
                return f"md5 mismatch: got {hashes['md5']}, accepted [{expected}]"
        if "sha1" in checks and entry["sha1"]:
            if hashes["sha1"].lower() not in entry["sha1"]:
                expected = ",".join(sorted(entry["sha1"]))
                return f"sha1 mismatch: got {hashes['sha1']}, accepted [{expected}]"
        if "sha256" in checks and entry["sha256"]:
            if hashes["sha256"].lower() not in entry["sha256"]:
                expected = ",".join(sorted(entry["sha256"]))
                return f"sha256 mismatch: got {hashes['sha256']}, accepted [{expected}]"
        if entry["adler32"]:
            if hashes["adler32"].lower() not in entry["adler32"]:
                expected = ",".join(sorted(entry["adler32"]))
                return f"adler32 mismatch: got 0x{hashes['adler32']}, accepted [{expected}]"

    # Signature/crypto checks (3DS RSA, AES)
    if entry["crypto_only"]:
        crypto_reason = check_crypto_validation(local_path, filename, bios_dir)
        if crypto_reason:
            return crypto_reason

    return None


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
    if validation_index:
        reason = check_file_validation(local_path, name, validation_index)
        if reason:
            return {"name": name, "status": Status.UNTESTED, "required": required,
                    "path": local_path, "reason": reason}
    return {"name": name, "status": Status.OK, "required": required}


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

def compute_severity(
    status: str, required: bool, mode: str, hle_fallback: bool = False,
) -> str:
    """Map (status, required, verification_mode, hle_fallback) → severity.

    Based on native platform behavior + emulator HLE capability:
    - RetroArch (existence): required+missing = warning, optional+missing = info
    - Batocera (md5): no required distinction (batocera-systems has no mandatory field)
    - Recalbox (md5): mandatory+missing = critical, optional+missing = warning
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

def find_undeclared_files(
    config: dict,
    emulators_dir: str,
    db: dict,
    emu_profiles: dict | None = None,
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
    profiles = emu_profiles if emu_profiles is not None else load_emulator_profiles(emulators_dir)

    relevant = resolve_platform_cores(config, profiles)
    undeclared = []
    seen = set()
    for emu_name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias"):
            continue
        if emu_name not in relevant:
            continue

        for f in profile.get("files", []):
            fname = f.get("name", "")
            if not fname or fname in seen:
                continue
            # Skip standalone-only files for libretro platforms
            if f.get("mode") == "standalone":
                continue
            if fname in declared_names:
                continue

            in_repo = fname in by_name or fname.rsplit("/", 1)[-1] in by_name
            seen.add(fname)
            undeclared.append({
                "emulator": profile.get("emulator", emu_name),
                "name": fname,
                "required": f.get("required", False),
                "hle_fallback": f.get("hle_fallback", False),
                "category": f.get("category", "bios"),
                "in_repo": in_repo,
                "note": f.get("note", ""),
            })

    return undeclared


def find_exclusion_notes(
    config: dict, emulators_dir: str, emu_profiles: dict | None = None,
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

    relevant = resolve_platform_cores(config, profiles)
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

        # Count standalone-only files
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

def verify_platform(
    config: dict, db: dict,
    emulators_dir: str = DEFAULT_EMULATORS_DIR,
    emu_profiles: dict | None = None,
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
                result = verify_entry_existence(
                    file_entry, local_path, validation_index,
                )
            else:
                result = verify_entry_md5(file_entry, local_path, resolve_status)
                # Apply emulator-level validation on top of MD5 check
                if result["status"] == Status.OK and local_path and validation_index:
                    fname = file_entry.get("name", "")
                    reason = check_file_validation(local_path, fname, validation_index)
                    if reason:
                        result["status"] = Status.UNTESTED
                        result["reason"] = reason
            result["system"] = sys_id
            result["hle_fallback"] = hle_index.get(file_entry.get("name", ""), False)
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
    undeclared = find_undeclared_files(config, emulators_dir, db, emu_profiles)
    exclusions = find_exclusion_notes(config, emulators_dir, emu_profiles)

    return {
        "platform": platform,
        "verification_mode": mode,
        "total_files": len(file_status),
        "severity_counts": counts,
        "status_counts": status_counts,
        "undeclared_files": undeclared,
        "exclusion_notes": exclusions,
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
    for d in result["details"]:
        if d["status"] == Status.MISSING:
            key = f"{d['system']}/{d['name']}"
            if key in seen_details:
                continue
            seen_details.add(key)
            req = "required" if d.get("required", True) else "optional"
            hle = ", HLE available" if d.get("hle_fallback") else ""
            print(f"  MISSING ({req}{hle}): {key}")

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

        summary_parts = []
        if req_not_in_repo:
            summary_parts.append(f"{len(req_not_in_repo)} required NOT in repo")
        if req_hle_not_in_repo:
            summary_parts.append(f"{len(req_hle_not_in_repo)} required with HLE NOT in repo")
        if req_in_repo:
            summary_parts.append(f"{len(req_in_repo)} required in repo")
        if opt_in_repo:
            summary_parts.append(f"{len(opt_in_repo)} optional in repo")
        if opt_not_in_repo:
            summary_parts.append(f"{len(opt_not_in_repo)} optional NOT in repo")
        if game_data:
            gd_missing = [u for u in game_data if not u["in_repo"]]
            gd_present = [u for u in game_data if u["in_repo"]]
            if gd_missing:
                summary_parts.append(f"{len(gd_missing)} game_data NOT in repo")
            if gd_present:
                summary_parts.append(f"{len(gd_present)} game_data in repo")
        print(f"  Core gaps: {len(undeclared)} undeclared ({', '.join(summary_parts)})")

        # Show critical gaps (required bios + no HLE + not in repo)
        for u in req_not_in_repo:
            print(f"    {u['emulator']} → {u['name']} (required, NOT in repo)")
        # Show required with HLE (core works but not ideal)
        for u in req_hle_not_in_repo:
            print(f"    {u['emulator']} → {u['name']} (required, HLE available, NOT in repo)")
        # Show required in repo (actionable)
        for u in req_in_repo[:10]:
            print(f"    {u['emulator']} → {u['name']} (required, in repo)")
        if len(req_in_repo) > 10:
            print(f"    ... and {len(req_in_repo) - 10} more required in repo")

    # Intentional exclusions (explain why certain emulator files are NOT included)
    exclusions = result.get("exclusion_notes", [])
    if exclusions:
        print(f"  Intentional exclusions ({len(exclusions)}):")
        for ex in exclusions:
            print(f"    {ex['emulator']} — {ex['detail']} [{ex['reason']}]")


# ---------------------------------------------------------------------------
# Emulator/system mode verification
# ---------------------------------------------------------------------------

def _filter_files_by_mode(files: list[dict], standalone: bool) -> list[dict]:
    """Filter file entries by libretro/standalone mode."""
    result = []
    for f in files:
        fmode = f.get("mode", "")
        if standalone and fmode == "libretro":
            continue
        if not standalone and fmode == "standalone":
            continue
        result.append(f)
    return result


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
    data_dir_notices: list[str] = []

    for emu_name, profile in selected:
        files = _filter_files_by_mode(profile.get("files", []), standalone)

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
                details.append(result)
                dest = archive
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
            details.append(result)

            # Aggregate by destination (path if available, else name)
            dest = file_entry.get("path", "") or name
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

    return {
        "emulators": [n for n, _ in selected],
        "verification_mode": label,
        "total_files": len(file_status),
        "severity_counts": counts,
        "status_counts": status_counts,
        "details": details,
        "data_dir_notices": sorted(set(data_dir_notices)),
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


def print_emulator_result(result: dict) -> None:
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
    for d in result["details"]:
        if d["status"] == Status.MISSING:
            if d["name"] in seen:
                continue
            seen.add(d["name"])
            req = "required" if d.get("required", True) else "optional"
            hle = ", HLE available" if d.get("hle_fallback") else ""
            print(f"  MISSING ({req}{hle}): {d['name']}")
    for d in result["details"]:
        if d.get("note"):
            print(f"  {d['note']}")

    for ref in result.get("data_dir_notices", []):
        print(f"  Note: data directory '{ref}' required but not included (use refresh_data_dirs.py)")


def _list_emulators(emulators_dir: str) -> None:
    """Print available emulator profiles."""
    profiles = load_emulator_profiles(emulators_dir)
    for name in sorted(profiles):
        p = profiles[name]
        if p.get("type") in ("alias", "test"):
            continue
        display = p.get("emulator", name)
        ptype = p.get("type", "libretro")
        systems = ", ".join(p.get("systems", [])[:3])
        more = "..." if len(p.get("systems", [])) > 3 else ""
        print(f"  {name:30s} {display:40s} [{ptype}] {systems}{more}")


def _list_systems(emulators_dir: str) -> None:
    """Print available system IDs with emulator count."""
    profiles = load_emulator_profiles(emulators_dir)
    system_emus: dict[str, list[str]] = {}
    for name, p in profiles.items():
        if p.get("type") in ("alias", "test", "launcher"):
            continue
        for sys_id in p.get("systems", []):
            system_emus.setdefault(sys_id, []).append(name)
    for sys_id in sorted(system_emus):
        count = len(system_emus[sys_id])
        print(f"  {sys_id:35s} ({count} emulator{'s' if count > 1 else ''})")


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
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--platforms-dir", default=DEFAULT_PLATFORMS_DIR)
    parser.add_argument("--emulators-dir", default=DEFAULT_EMULATORS_DIR)
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.list_emulators:
        _list_emulators(args.emulators_dir)
        return
    if args.list_systems:
        _list_systems(args.emulators_dir)
        return

    # Mutual exclusion
    modes = sum(1 for x in (args.platform, args.all, args.emulator, args.system) if x)
    if modes == 0:
        parser.error("Specify --platform, --all, --emulator, or --system")
    if modes > 1:
        parser.error("--platform, --all, --emulator, and --system are mutually exclusive")
    if args.standalone and not (args.emulator or args.system):
        parser.error("--standalone requires --emulator or --system")

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
            print_emulator_result(result)
        return

    # System mode
    if args.system:
        system_ids = [s.strip() for s in args.system.split(",") if s.strip()]
        result = verify_system(system_ids, args.emulators_dir, db, args.standalone)
        if args.json:
            result["details"] = [d for d in result["details"] if d["status"] != Status.OK]
            print(json.dumps(result, indent=2))
        else:
            print_emulator_result(result)
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

    # Group identical platforms (same function as generate_pack)
    groups = group_identical_platforms(platforms, args.platforms_dir)
    all_results = {}
    group_results: list[tuple[dict, list[str]]] = []
    for group_platforms, representative in groups:
        config = load_platform_config(representative, args.platforms_dir)
        result = verify_platform(config, db, args.emulators_dir, emu_profiles)
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
