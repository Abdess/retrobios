#!/usr/bin/env python3
"""Generate platform-specific BIOS ZIP packs.

Usage:
    python scripts/generate_pack.py --platform retroarch [--output-dir dist/]
    python scripts/generate_pack.py --all [--output-dir dist/]

Reads platform YAML config + database.json -> creates ZIP with correct
file layout for each platform. Handles inheritance, shared groups, variants,
and 3-tier storage (embedded/external/user_provided).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import urllib.request
import urllib.error
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    MANUFACTURER_PREFIXES,
    _build_validation_index, build_zip_contents_index, check_file_validation,
    check_inside_zip, compute_hashes, fetch_large_file, filter_files_by_mode,
    group_identical_platforms, list_emulator_profiles, list_platform_system_ids,
    list_registered_platforms,
    filter_systems_by_target, list_system_ids, load_database,
    load_data_dir_registry, load_emulator_profiles, load_platform_config,
    md5_composite, resolve_local_file,
)
from deterministic_zip import rebuild_zip_deterministic

try:
    import yaml
except ImportError:
    print("Error: PyYAML required (pip install pyyaml)", file=sys.stderr)
    sys.exit(1)

DEFAULT_PLATFORMS_DIR = "platforms"
DEFAULT_DB_FILE = "database.json"
DEFAULT_OUTPUT_DIR = "dist"
DEFAULT_BIOS_DIR = "bios"
MAX_ENTRY_SIZE = 512 * 1024 * 1024  # 512MB


def _find_candidate_satisfying_both(
    file_entry: dict,
    db: dict,
    local_path: str,
    validation_index: dict,
    bios_dir: str,
) -> str | None:
    """Search for a repo file that satisfies both platform MD5 and emulator validation.

    When the current file passes platform verification but fails emulator checks,
    search all candidates with the same name for one that passes both.
    Returns a better path, or None if no upgrade found.
    """
    fname = file_entry.get("name", "")
    if not fname:
        return None
    entry = validation_index.get(fname)
    if not entry:
        return None

    md5_expected = file_entry.get("md5", "")
    md5_set = {m.strip().lower() for m in md5_expected.split(",") if m.strip()} if md5_expected else set()

    by_name = db.get("indexes", {}).get("by_name", {})
    files_db = db.get("files", {})

    for sha1 in by_name.get(fname, []):
        candidate = files_db.get(sha1, {})
        path = candidate.get("path", "")
        if not path or not os.path.exists(path) or os.path.realpath(path) == os.path.realpath(local_path):
            continue
        # Must still satisfy platform MD5
        if md5_set and candidate.get("md5", "").lower() not in md5_set:
            continue
        # Check emulator validation
        reason = check_file_validation(path, fname, validation_index, bios_dir)
        if reason is None:
            return path
    return None


def _sanitize_path(raw: str) -> str:
    """Strip path traversal components from a relative path."""
    raw = raw.replace("\\", "/")
    parts = [p for p in raw.split("/") if p and p not in ("..", ".")]
    return "/".join(parts)


def resolve_file(file_entry: dict, db: dict, bios_dir: str,
                  zip_contents: dict | None = None,
                  dest_hint: str = "") -> tuple[str | None, str]:
    """Resolve a BIOS file with storage tiers and release asset fallback.

    Wraps common.resolve_local_file() with pack-specific logic for
    storage tiers (external/user_provided), large file release assets,
    and MAME clone mapping (deduped ZIPs).
    """
    storage = file_entry.get("storage", "embedded")
    if storage == "user_provided":
        return None, "user_provided"
    if storage == "external":
        return None, "external"

    path, status = resolve_local_file(file_entry, db, zip_contents,
                                      dest_hint=dest_hint)
    if path and status != "hash_mismatch":
        return path, status

    # Large files from GitHub release assets — tried when local file is
    # missing OR has a hash mismatch (wrong variant on disk)
    name = file_entry.get("name", "")
    sha1 = file_entry.get("sha1")
    md5_raw = file_entry.get("md5", "")
    md5_list = [m.strip().lower() for m in md5_raw.split(",") if m.strip()] if md5_raw else []
    first_md5 = md5_list[0] if md5_list else ""
    cached = fetch_large_file(name, expected_sha1=sha1 or "", expected_md5=first_md5)
    if cached:
        return cached, "release_asset"

    # Fall back to hash_mismatch local file if release asset unavailable
    if path:
        return path, status

    return None, "not_found"



def download_external(file_entry: dict, dest_path: str) -> bool:
    """Download an external BIOS file, verify hash, save to dest_path."""
    url = file_entry.get("source_url")
    if not url:
        return False

    sha256 = file_entry.get("sha256")
    sha1 = file_entry.get("sha1")
    md5 = file_entry.get("md5")

    if not (sha256 or sha1 or md5):
        print(f"    WARNING: no hash for {file_entry['name']}, skipping unverifiable download")
        return False

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "retrobios-pack-gen/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
    except urllib.error.URLError as e:
        print(f"    WARNING: Failed to download {url}: {e}")
        return False

    if sha256:
        actual = hashlib.sha256(data).hexdigest()
        if actual != sha256:
            print(f"    WARNING: SHA256 mismatch for {file_entry['name']}")
            return False
    elif sha1:
        actual = hashlib.sha1(data).hexdigest()
        if actual != sha1:
            print(f"    WARNING: SHA1 mismatch for {file_entry['name']}")
            return False
    elif md5:
        actual = hashlib.md5(data).hexdigest()
        if actual != md5:
            print(f"    WARNING: MD5 mismatch for {file_entry['name']}")
            return False

    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    with open(dest_path, "wb") as f:
        f.write(data)
    return True


def _collect_emulator_extras(
    config: dict,
    emulators_dir: str,
    db: dict,
    seen: set,
    base_dest: str,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
) -> list[dict]:
    """Collect core requirement files from emulator profiles not in the platform pack.

    Uses the same system-overlap matching as verify.py cross-reference:
    - Matches emulators by shared system IDs with the platform
    - Filters mode: standalone, type: launcher, type: alias
    - Respects data_directories coverage
    - Only returns files that exist in the repo (packable)

    Works for ANY platform (RetroArch, Batocera, Recalbox, etc.)
    """
    from verify import find_undeclared_files

    undeclared = find_undeclared_files(config, emulators_dir, db, emu_profiles, target_cores=target_cores)
    extras = []
    for u in undeclared:
        if not u["in_repo"]:
            continue
        name = u["name"]
        dest = u.get("path") or name
        full_dest = f"{base_dest}/{dest}" if base_dest else dest
        if full_dest in seen:
            continue
        extras.append({
            "name": name,
            "destination": dest,
            "required": u.get("required", False),
            "hle_fallback": u.get("hle_fallback", False),
            "source_emulator": u.get("emulator", ""),
        })
    return extras


def generate_pack(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    include_extras: bool = False,
    emulators_dir: str = "emulators",
    zip_contents: dict | None = None,
    data_registry: dict | None = None,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
    required_only: bool = False,
    system_filter: list[str] | None = None,
) -> str | None:
    """Generate a ZIP pack for a platform.

    Returns the path to the generated ZIP, or None on failure.
    """
    config = load_platform_config(platform_name, platforms_dir)
    if zip_contents is None:
        zip_contents = {}

    verification_mode = config.get("verification_mode", "existence")
    platform_display = config.get("platform", platform_name)
    base_dest = config.get("base_destination", "")

    version = config.get("version", config.get("dat_version", ""))
    version_tag = f"_{version.replace(' ', '')}" if version else ""
    req_tag = "_Required" if required_only else ""

    sys_tag = ""
    if system_filter:
        display_parts = []
        for sid in system_filter:
            s = sid.lower().replace("_", "-")
            for prefix in MANUFACTURER_PREFIXES:
                if s.startswith(prefix):
                    s = s[len(prefix):]
                    break
            parts = s.split("-")
            display_parts.append("_".join(p.title() for p in parts if p))
        sys_tag = "_" + "_".join(display_parts)

    zip_name = f"{platform_display.replace(' ', '_')}{version_tag}{req_tag}_BIOS_Pack{sys_tag}.zip"
    zip_path = os.path.join(output_dir, zip_name)
    os.makedirs(output_dir, exist_ok=True)

    # Case-insensitive dedup only for platforms targeting Windows/macOS.
    # Linux-only platforms (Batocera, Recalbox, RetroDECK, Lakka, RomM)
    # are case-sensitive and may have distinct files like DISK.ROM vs disk.rom.
    case_insensitive = config.get("case_insensitive_fs", False)

    total_files = 0
    missing_files = []
    user_provided = []
    seen_destinations: set[str] = set()
    seen_lower: set[str] = set()  # only used when case_insensitive=True
    # Per-file status: worst status wins (missing > untested > ok)
    file_status: dict[str, str] = {}
    file_reasons: dict[str, str] = {}

    # Build emulator-level validation index (same as verify.py)
    validation_index = {}
    if emu_profiles:
        validation_index = _build_validation_index(emu_profiles)

    # Filter systems by target if specified
    from common import resolve_platform_cores
    plat_cores = resolve_platform_cores(config, emu_profiles or {}) if target_cores else None
    pack_systems = filter_systems_by_target(
        config.get("systems", {}),
        emu_profiles or {},
        target_cores,
        platform_cores=plat_cores,
    )

    if system_filter:
        from common import _norm_system_id
        norm_filter = {_norm_system_id(s) for s in system_filter}
        filtered = {sid: sys_data for sid, sys_data in pack_systems.items()
                    if sid in system_filter or _norm_system_id(sid) in norm_filter}
        if not filtered:
            available = sorted(pack_systems.keys())[:10]
            print(f"  WARNING: no systems matched filter {system_filter} "
                  f"(available: {', '.join(available)})")
            return None
        pack_systems = filtered

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for sys_id, system in sorted(pack_systems.items()):
            for file_entry in system.get("files", []):
                if required_only and file_entry.get("required") is False:
                    continue
                dest = _sanitize_path(file_entry.get("destination", file_entry["name"]))
                if not dest:
                    # EmuDeck-style entries (system:md5 whitelist, no filename).
                    fkey = f"{sys_id}/{file_entry.get('name', '')}"
                    md5 = file_entry.get("md5", "")
                    if md5 and md5 in db.get("indexes", {}).get("by_md5", {}):
                        file_status.setdefault(fkey, "ok")
                    else:
                        file_status[fkey] = "missing"
                    continue
                if base_dest:
                    full_dest = f"{base_dest}/{dest}"
                else:
                    full_dest = dest

                dedup_key = full_dest
                already_packed = dedup_key in seen_destinations or (case_insensitive and dedup_key.lower() in seen_lower)

                storage = file_entry.get("storage", "embedded")

                if storage == "user_provided":
                    if already_packed:
                        continue
                    seen_destinations.add(dedup_key)
                    if case_insensitive:
                        seen_lower.add(dedup_key.lower())
                    file_status.setdefault(dedup_key, "ok")
                    instructions = file_entry.get("instructions", "Please provide this file manually.")
                    instr_name = f"INSTRUCTIONS_{file_entry['name']}.txt"
                    instr_path = f"{base_dest}/{instr_name}" if base_dest else instr_name
                    zf.writestr(instr_path, f"File needed: {file_entry['name']}\n\n{instructions}\n")
                    user_provided.append(file_entry["name"])
                    total_files += 1
                    continue

                local_path, status = resolve_file(file_entry, db, bios_dir, zip_contents)

                if status == "external":
                    file_ext = os.path.splitext(file_entry["name"])[1] or ""
                    with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp:
                        tmp_path = tmp.name

                    try:
                        if download_external(file_entry, tmp_path):
                            extract = file_entry.get("extract", False)
                            if extract and tmp_path.endswith(".zip"):
                                _extract_zip_to_archive(tmp_path, full_dest, zf)
                            else:
                                zf.write(tmp_path, full_dest)
                            seen_destinations.add(dedup_key)
                            if case_insensitive:
                                seen_lower.add(dedup_key.lower())
                            file_status.setdefault(dedup_key, "ok")
                            total_files += 1
                        else:
                            missing_files.append(file_entry["name"])
                            file_status[dedup_key] = "missing"
                    finally:
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)
                    continue

                if status == "not_found":
                    if not already_packed:
                        missing_files.append(file_entry["name"])
                        file_status[dedup_key] = "missing"
                    continue

                if status == "hash_mismatch" and verification_mode != "existence":
                    zf_name = file_entry.get("zipped_file")
                    if zf_name and local_path:
                        inner_md5_raw = file_entry.get("md5", "")
                        inner_md5_list = (
                            [m.strip() for m in inner_md5_raw.split(",") if m.strip()]
                            if inner_md5_raw else [""]
                        )
                        zip_ok = False
                        last_result = "not_in_zip"
                        for md5_candidate in inner_md5_list:
                            last_result = check_inside_zip(local_path, zf_name, md5_candidate)
                            if last_result == "ok":
                                zip_ok = True
                                break
                        if zip_ok:
                            file_status.setdefault(dedup_key, "ok")
                        elif last_result == "not_in_zip":
                            file_status[dedup_key] = "untested"
                            file_reasons[dedup_key] = f"{zf_name} not found inside ZIP"
                        elif last_result == "error":
                            file_status[dedup_key] = "untested"
                            file_reasons[dedup_key] = "cannot read ZIP"
                        else:
                            file_status[dedup_key] = "untested"
                            file_reasons[dedup_key] = f"{zf_name} MD5 mismatch inside ZIP"
                    else:
                        file_status[dedup_key] = "untested"
                        file_reasons[dedup_key] = "hash mismatch"
                else:
                    file_status.setdefault(dedup_key, "ok")

                # Emulator-level validation: informational only for platform packs.
                # Platform verification (existence/md5) is the authority for pack status.
                # Emulator checks are supplementary — logged but don't downgrade.
                # When a discrepancy is found, try to find a file satisfying both.
                if (file_status.get(dedup_key) == "ok"
                        and local_path and validation_index):
                    fname = file_entry.get("name", "")
                    reason = check_file_validation(local_path, fname, validation_index,
                                                   bios_dir)
                    if reason:
                        better = _find_candidate_satisfying_both(
                            file_entry, db, local_path, validation_index, bios_dir,
                        )
                        if better:
                            local_path = better
                        else:
                            ventry = validation_index.get(fname, {})
                            emus = ", ".join(ventry.get("emulators", []))
                            file_reasons.setdefault(
                                dedup_key,
                                f"{platform_display} says OK but {emus} says {reason}",
                            )

                if already_packed:
                    continue
                seen_destinations.add(dedup_key)
                if case_insensitive:
                    seen_lower.add(dedup_key.lower())

                extract = file_entry.get("extract", False)
                if extract and local_path.endswith(".zip"):
                    _extract_zip_to_archive(local_path, full_dest, zf)
                elif local_path.endswith(".zip"):
                    _normalize_zip_for_pack(local_path, full_dest, zf)
                else:
                    zf.write(local_path, full_dest)
                total_files += 1

        # Core requirements: files platform's cores need but YAML doesn't declare
        if emu_profiles is None:
            emu_profiles = load_emulator_profiles(emulators_dir)
        core_files = _collect_emulator_extras(
            config, emulators_dir, db,
            seen_destinations, base_dest, emu_profiles, target_cores=target_cores,
        )
        core_count = 0
        for fe in core_files:
            if required_only and fe.get("required") is False:
                continue
            dest = _sanitize_path(fe.get("destination", fe["name"]))
            if not dest:
                continue
            # Core extras use flat filenames; prepend base_destination or
            # default to the platform's most common BIOS path prefix
            if base_dest:
                full_dest = f"{base_dest}/{dest}"
            elif "/" not in dest:
                # Bare filename with empty base_destination — infer bios/ prefix
                # to match platform conventions (RetroDECK: ~/retrodeck/bios/)
                full_dest = f"bios/{dest}"
            else:
                full_dest = dest
            if full_dest in seen_destinations:
                continue
            # Skip case-insensitive duplicates (Windows/macOS FS safety)
            if full_dest.lower() in seen_lower and case_insensitive:
                continue

            local_path, status = resolve_file(fe, db, bios_dir, zip_contents)
            if status in ("not_found", "external", "user_provided"):
                continue

            if local_path.endswith(".zip"):
                _normalize_zip_for_pack(local_path, full_dest, zf)
            else:
                zf.write(local_path, full_dest)
            seen_destinations.add(full_dest)
            if case_insensitive:
                seen_lower.add(full_dest.lower())
            core_count += 1
            total_files += 1

        # Data directories from _data_dirs.yml
        for sys_id, system in sorted(pack_systems.items()):
            for dd in system.get("data_directories", []):
                ref_key = dd.get("ref", "")
                if not ref_key or not data_registry or ref_key not in data_registry:
                    continue
                entry = data_registry[ref_key]
                allowed = entry.get("for_platforms")
                if allowed and platform_name not in allowed:
                    continue
                local_path = entry.get("local_cache", "")
                if not local_path or not os.path.isdir(local_path):
                    print(f"  WARNING: data directory '{ref_key}' not cached at {local_path} — run refresh_data_dirs.py")
                    continue
                dd_dest = dd.get("destination", "")
                if base_dest and dd_dest:
                    dd_prefix = f"{base_dest}/{dd_dest}"
                elif base_dest:
                    dd_prefix = base_dest
                else:
                    dd_prefix = dd_dest
                for root, _dirs, filenames in os.walk(local_path):
                    for fname in filenames:
                        src = os.path.join(root, fname)
                        rel = os.path.relpath(src, local_path)
                        full = f"{dd_prefix}/{rel}"
                        if full in seen_destinations or full.lower() in seen_lower and case_insensitive:
                            continue
                        seen_destinations.add(full)
                        if case_insensitive:
                            seen_lower.add(full.lower())
                        zf.write(src, full)
                        total_files += 1

    files_ok = sum(1 for s in file_status.values() if s == "ok")
    files_untested = sum(1 for s in file_status.values() if s == "untested")
    files_miss = sum(1 for s in file_status.values() if s == "missing")
    total_checked = len(file_status)

    parts = [f"{files_ok}/{total_checked} files OK"]
    if files_untested:
        parts.append(f"{files_untested} untested")
    if files_miss:
        parts.append(f"{files_miss} missing")
    baseline = total_files - core_count
    print(f"  {zip_path}: {total_files} files packed ({baseline} baseline + {core_count} from cores), {', '.join(parts)} [{verification_mode}]")

    for key, reason in sorted(file_reasons.items()):
        status = file_status.get(key, "")
        label = "UNTESTED" if status == "untested" else "DISCREPANCY"
        print(f"  {label}: {key} — {reason}")
    for name in missing_files:
        print(f"  MISSING: {name}")
    return zip_path


def _extract_zip_to_archive(source_zip: str, dest_prefix: str, target_zf: zipfile.ZipFile):
    """Extract contents of a source ZIP into target ZIP under dest_prefix."""
    with zipfile.ZipFile(source_zip, "r") as src:
        for info in src.infolist():
            if info.is_dir():
                continue
            clean_name = _sanitize_path(info.filename)
            if not clean_name:
                continue
            data = src.read(info.filename)
            target_path = f"{dest_prefix}/{clean_name}" if dest_prefix else clean_name
            target_zf.writestr(target_path, data)


def _normalize_zip_for_pack(source_zip: str, dest_path: str, target_zf: zipfile.ZipFile):
    """Add a MAME BIOS ZIP to the pack as a deterministic rebuild.

    Instead of copying the original ZIP (with non-deterministic metadata),
    extracts the ROM atoms, rebuilds the ZIP deterministically, and writes
    the normalized version into the pack.

    This ensures:
    - Same ROMs → same ZIP hash in every pack build
    - No dependency on how the user built their MAME ROM set
    - Bit-identical ZIPs across platforms and build times
    """
    import tempfile as _tmp
    tmp_fd, tmp_path = _tmp.mkstemp(suffix=".zip", dir="tmp")
    os.close(tmp_fd)
    try:
        rebuild_zip_deterministic(source_zip, tmp_path)
        target_zf.write(tmp_path, dest_path)
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Emulator/system mode pack generation
# ---------------------------------------------------------------------------

def _resolve_destination(file_entry: dict, pack_structure: dict | None,
                         standalone: bool) -> str:
    """Resolve the ZIP destination path for a file entry."""
    # 1. standalone_path override
    if standalone and file_entry.get("standalone_path"):
        rel = file_entry["standalone_path"]
    # 2. path field
    elif file_entry.get("path"):
        rel = file_entry["path"]
    # 3. name fallback
    else:
        rel = file_entry.get("name", "")

    rel = _sanitize_path(rel)

    # Prepend pack_structure prefix
    if pack_structure:
        mode_key = "standalone" if standalone else "libretro"
        prefix = pack_structure.get(mode_key, "")
        if prefix:
            rel = f"{prefix}/{rel}"

    return rel


def generate_emulator_pack(
    profile_names: list[str],
    emulators_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    standalone: bool = False,
    zip_contents: dict | None = None,
    required_only: bool = False,
) -> str | None:
    """Generate a ZIP pack for specific emulator profiles."""
    all_profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)
    if zip_contents is None:
        zip_contents = build_zip_contents_index(db)

    # Resolve and validate profile names
    selected: list[tuple[str, dict]] = []
    for name in profile_names:
        if name not in all_profiles:
            available = sorted(k for k, v in all_profiles.items()
                               if v.get("type") not in ("alias", "test"))
            print(f"Error: emulator '{name}' not found", file=sys.stderr)
            print(f"Available: {', '.join(available[:10])}...", file=sys.stderr)
            return None
        p = all_profiles[name]
        if p.get("type") == "alias":
            alias_of = p.get("alias_of", "?")
            print(f"Error: {name} is an alias of {alias_of} — use --emulator {alias_of}",
                  file=sys.stderr)
            return None
        if p.get("type") == "launcher":
            print(f"Error: {name} is a launcher — use the emulator it launches",
                  file=sys.stderr)
            return None
        ptype = p.get("type", "libretro")
        if standalone and "standalone" not in ptype:
            print(f"Error: {name} ({ptype}) does not support --standalone",
                  file=sys.stderr)
            return None
        selected.append((name, p))

    # ZIP naming
    display_names = [p.get("emulator", n).replace(" ", "") for n, p in selected]
    zip_name = "_".join(display_names) + "_BIOS_Pack.zip"
    zip_path = os.path.join(output_dir, zip_name)
    os.makedirs(output_dir, exist_ok=True)

    total_files = 0
    missing_files = []
    seen_destinations: set[str] = set()
    seen_lower: set[str] = set()
    seen_hashes: set[str] = set()  # SHA1 dedup for same file, different path
    data_dir_notices: list[str] = []
    data_registry = load_data_dir_registry(
        os.path.join(os.path.dirname(__file__), "..", "platforms")
    )

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for emu_name, profile in sorted(selected):
            pack_structure = profile.get("pack_structure")
            files = filter_files_by_mode(profile.get("files", []), standalone)
            for dd in profile.get("data_directories", []):
                ref_key = dd.get("ref", "")
                if not ref_key or not data_registry or ref_key not in data_registry:
                    if ref_key:
                        data_dir_notices.append(ref_key)
                    continue
                entry = data_registry[ref_key]
                local_cache = entry.get("local_cache", "")
                if not local_cache or not os.path.isdir(local_cache):
                    data_dir_notices.append(ref_key)
                    continue
                dd_dest = dd.get("destination", "")
                if pack_structure:
                    mode_key = "standalone" if standalone else "libretro"
                    prefix = pack_structure.get(mode_key, "")
                    if prefix:
                        dd_dest = f"{prefix}/{dd_dest}" if dd_dest else prefix
                for root, _dirs, filenames in os.walk(local_cache):
                    for fname in filenames:
                        src = os.path.join(root, fname)
                        rel = os.path.relpath(src, local_cache)
                        full = f"{dd_dest}/{rel}" if dd_dest else rel
                        if full.lower() in seen_lower:
                            continue
                        seen_destinations.add(full)
                        seen_lower.add(full.lower())
                        zf.write(src, full)
                        total_files += 1

            if not files:
                print(f"  No files needed for {profile.get('emulator', emu_name)}")
                continue

            # Collect archives as atomic units
            archives: set[str] = set()
            for fe in files:
                archive = fe.get("archive")
                if archive:
                    archives.add(archive)

            # Pack archives as units
            for archive_name in sorted(archives):
                archive_dest = _sanitize_path(archive_name)
                if pack_structure:
                    mode_key = "standalone" if standalone else "libretro"
                    prefix = pack_structure.get(mode_key, "")
                    if prefix:
                        archive_dest = f"{prefix}/{archive_dest}"

                if archive_dest.lower() in seen_lower:
                    continue

                archive_entry = {"name": archive_name}
                local_path, status = resolve_file(archive_entry, db, bios_dir, zip_contents)
                if local_path and status not in ("not_found",):
                    if local_path.endswith(".zip"):
                        _normalize_zip_for_pack(local_path, archive_dest, zf)
                    else:
                        zf.write(local_path, archive_dest)
                    seen_destinations.add(archive_dest)
                    seen_lower.add(archive_dest.lower())
                    total_files += 1
                else:
                    missing_files.append(archive_name)

            # Pack individual files (skip archived ones)
            for fe in files:
                if required_only and fe.get("required") is False:
                    continue
                if fe.get("archive"):
                    continue

                dest = _resolve_destination(fe, pack_structure, standalone)
                if not dest:
                    continue

                if dest.lower() in seen_lower:
                    continue

                storage = fe.get("storage", "embedded")
                if storage == "user_provided":
                    seen_destinations.add(dest)
                    seen_lower.add(dest.lower())
                    instr = fe.get("instructions", "Please provide this file manually.")
                    instr_name = f"INSTRUCTIONS_{fe['name']}.txt"
                    zf.writestr(instr_name, f"File needed: {fe['name']}\n\n{instr}\n")
                    total_files += 1
                    continue

                dest_hint = fe.get("path", "")
                local_path, status = resolve_file(fe, db, bios_dir, zip_contents,
                                                  dest_hint=dest_hint)

                if status == "external":
                    file_ext = os.path.splitext(fe["name"])[1] or ""
                    with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp:
                        tmp_path = tmp.name
                    try:
                        if download_external(fe, tmp_path):
                            zf.write(tmp_path, dest)
                            seen_destinations.add(dest)
                            seen_lower.add(dest.lower())
                            total_files += 1
                        else:
                            missing_files.append(fe["name"])
                    finally:
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)
                    continue

                if status in ("not_found", "user_provided"):
                    missing_files.append(fe["name"])
                    continue

                # SHA1 dedup: skip if same physical file AND same destination
                # (but allow same file to be packed under different destinations,
                # e.g., IPL.bin in GC/USA/ and GC/EUR/ from same source)
                if local_path:
                    real = os.path.realpath(local_path)
                    dedup_key_hash = f"{real}:{dest}"
                    if dedup_key_hash in seen_hashes:
                        continue
                    seen_hashes.add(dedup_key_hash)

                if local_path.endswith(".zip"):
                    _normalize_zip_for_pack(local_path, dest, zf)
                else:
                    zf.write(local_path, dest)
                seen_destinations.add(dest)
                seen_lower.add(dest.lower())
                total_files += 1

    # Remove empty ZIP (no files packed and no missing = nothing to ship)
    if total_files == 0 and not missing_files:
        os.unlink(zip_path)

    # Report
    label = " + ".join(p.get("emulator", n) for n, p in selected)
    missing_count = len(missing_files)
    ok_count = total_files
    parts = [f"{ok_count} files packed"]
    if missing_count:
        parts.append(f"{missing_count} missing")
    print(f"  {zip_path}: {', '.join(parts)}")
    for name in missing_files:
        print(f"  MISSING: {name}")
    for ref in sorted(set(data_dir_notices)):
        print(f"  Note: data directory '{ref}' required but not included (use refresh_data_dirs.py)")

    return zip_path if total_files > 0 or missing_files else None


def generate_system_pack(
    system_ids: list[str],
    emulators_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    standalone: bool = False,
    zip_contents: dict | None = None,
    required_only: bool = False,
) -> str | None:
    """Generate a ZIP pack for all emulators supporting given system IDs."""
    profiles = load_emulator_profiles(emulators_dir)
    matching = []
    for name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias", "test"):
            continue
        emu_systems = set(profile.get("systems", []))
        if emu_systems & set(system_ids):
            ptype = profile.get("type", "libretro")
            if standalone and "standalone" not in ptype:
                continue
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
        return None

    # Use system-based ZIP name
    sys_display = "_".join(
        "_".join(w.title() for w in sid.split("-")) for sid in system_ids
    )
    result = generate_emulator_pack(
        matching, emulators_dir, db, bios_dir, output_dir,
        standalone, zip_contents, required_only=required_only,
    )
    if result:
        # Rename to system-based name
        new_name = f"{sys_display}_BIOS_Pack.zip"
        new_path = os.path.join(output_dir, new_name)
        if new_path != result:
            os.rename(result, new_path)
            result = new_path
    return result


def list_platforms(platforms_dir: str) -> list[str]:
    """List available platform names from registry."""
    return list_registered_platforms(platforms_dir, include_archived=True)


def _system_display_name(system_id: str) -> str:
    """Convert system ID to display name for ZIP naming."""
    s = system_id.lower().replace("_", "-")
    for prefix in MANUFACTURER_PREFIXES:
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    parts = s.split("-")
    return "_".join(p.title() for p in parts if p)


def _group_systems_by_manufacturer(
    systems: dict[str, dict],
    db: dict,
    bios_dir: str,
) -> dict[str, list[str]]:
    """Group system IDs by manufacturer for --split --group-by manufacturer."""
    from common import derive_manufacturer
    groups: dict[str, list[str]] = {}
    for sid, sys_data in systems.items():
        mfr = derive_manufacturer(sid, sys_data)
        groups.setdefault(mfr, []).append(sid)
    return groups


def generate_split_packs(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    group_by: str = "system",
    emulators_dir: str = "emulators",
    zip_contents: dict | None = None,
    data_registry: dict | None = None,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
    required_only: bool = False,
) -> list[str]:
    """Generate split packs (one ZIP per system or manufacturer)."""
    config = load_platform_config(platform_name, platforms_dir)
    platform_display = config.get("platform", platform_name)
    split_dir = os.path.join(output_dir, f"{platform_display.replace(' ', '_')}_Split")
    os.makedirs(split_dir, exist_ok=True)

    systems = config.get("systems", {})

    if group_by == "manufacturer":
        groups = _group_systems_by_manufacturer(systems, db, bios_dir)
    else:
        groups = {_system_display_name(sid): [sid] for sid in systems}

    results = []
    for group_name, group_system_ids in sorted(groups.items()):
        zip_path = generate_pack(
            platform_name, platforms_dir, db, bios_dir, split_dir,
            emulators_dir=emulators_dir, zip_contents=zip_contents,
            data_registry=data_registry, emu_profiles=emu_profiles,
            target_cores=target_cores, required_only=required_only,
            system_filter=group_system_ids,
        )
        if zip_path:
            version = config.get("version", config.get("dat_version", ""))
            ver_tag = f"_{version.replace(' ', '')}" if version else ""
            req_tag = "_Required" if required_only else ""
            new_name = f"{platform_display.replace(' ', '_')}{ver_tag}{req_tag}_{group_name}_BIOS_Pack.zip"
            new_path = os.path.join(split_dir, new_name)
            if new_path != zip_path:
                os.rename(zip_path, new_path)
                zip_path = new_path
            results.append(zip_path)

    return results


def main():
    parser = argparse.ArgumentParser(description="Generate platform BIOS ZIP packs")
    parser.add_argument("--platform", "-p", help="Platform name (e.g., retroarch)")
    parser.add_argument("--all", action="store_true", help="Generate packs for all active platforms")
    parser.add_argument("--emulator", "-e", help="Emulator profile name(s), comma-separated")
    parser.add_argument("--system", "-s", help="System ID(s), comma-separated")
    parser.add_argument("--standalone", action="store_true", help="Use standalone mode")
    parser.add_argument("--list-emulators", action="store_true", help="List available emulators")
    parser.add_argument("--list-systems", action="store_true", help="List available systems")
    parser.add_argument("--include-archived", action="store_true", help="Include archived platforms")
    parser.add_argument("--platforms-dir", default=DEFAULT_PLATFORMS_DIR)
    parser.add_argument("--db", default=DEFAULT_DB_FILE, help="Path to database.json")
    parser.add_argument("--bios-dir", default=DEFAULT_BIOS_DIR)
    parser.add_argument("--output-dir", "-o", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--include-extras", action="store_true",
                        help="(no-op) Core requirements are always included")
    parser.add_argument("--emulators-dir", default="emulators")
    parser.add_argument("--offline", action="store_true",
                        help="Skip data directory freshness check, use cache only")
    parser.add_argument("--refresh-data", action="store_true",
                        help="Force re-download all data directories")
    parser.add_argument("--list", action="store_true", help="List available platforms")
    parser.add_argument("--required-only", action="store_true",
                        help="Only include required files, skip optional")
    parser.add_argument("--split", action="store_true",
                        help="Generate one ZIP per system/manufacturer")
    parser.add_argument("--group-by", choices=["system", "manufacturer"],
                        default="system",
                        help="Grouping for --split (default: system)")
    parser.add_argument("--target", "-t", help="Hardware target (e.g., switch, rpi4)")
    parser.add_argument("--list-targets", action="store_true", help="List available targets for the platform")
    args = parser.parse_args()

    if args.list:
        platforms = list_platforms(args.platforms_dir)
        for p in platforms:
            print(p)
        return
    if args.list_emulators:
        list_emulator_profiles(args.emulators_dir)
        return
    if args.list_systems:
        if args.platform:
            list_platform_system_ids(args.platform, args.platforms_dir)
        else:
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

    # Mode validation
    has_platform = bool(args.platform)
    has_all = args.all
    has_emulator = bool(args.emulator)
    has_system = bool(args.system)

    # --platform/--all and --system can combine (system filters within platform)
    # --emulator is exclusive with everything else
    if has_emulator and (has_platform or has_all or has_system):
        parser.error("--emulator is mutually exclusive with --platform, --all, and --system")
    if has_platform and has_all:
        parser.error("--platform and --all are mutually exclusive")
    if not (has_platform or has_all or has_emulator or has_system):
        parser.error("Specify --platform, --all, --emulator, or --system")
    if args.standalone and not (has_emulator or (has_system and not has_platform and not has_all)):
        parser.error("--standalone requires --emulator or --system (without --platform)")
    if args.split and not (has_platform or has_all):
        parser.error("--split requires --platform or --all")
    if args.split and has_emulator:
        parser.error("--split is incompatible with --emulator")
    if args.group_by != "system" and not args.split:
        parser.error("--group-by requires --split")
    if args.target and not (has_platform or has_all):
        parser.error("--target requires --platform or --all")
    if args.target and has_emulator:
        parser.error("--target is incompatible with --emulator")

    db = load_database(args.db)
    zip_contents = build_zip_contents_index(db)

    # Emulator mode
    if args.emulator:
        names = [n.strip() for n in args.emulator.split(",") if n.strip()]
        result = generate_emulator_pack(
            names, args.emulators_dir, db, args.bios_dir, args.output_dir,
            args.standalone, zip_contents, required_only=args.required_only,
        )
        if not result:
            sys.exit(1)
        return

    # System mode (standalone, without platform context)
    if has_system and not has_platform and not has_all:
        system_ids = [s.strip() for s in args.system.split(",") if s.strip()]
        result = generate_system_pack(
            system_ids, args.emulators_dir, db, args.bios_dir, args.output_dir,
            args.standalone, zip_contents, required_only=args.required_only,
        )
        if not result:
            sys.exit(1)
        return

    system_filter = None
    if args.system:
        system_filter = [s.strip() for s in args.system.split(",") if s.strip()]

    # Platform mode (existing)
    if args.all:
        platforms = list_registered_platforms(
            args.platforms_dir, include_archived=args.include_archived,
        )
    elif args.platform:
        platforms = [args.platform]
    else:
        parser.error("Specify --platform or --all")
        return

    data_registry = load_data_dir_registry(args.platforms_dir)
    if data_registry and not args.offline:
        from refresh_data_dirs import refresh_all, load_registry
        registry = load_registry(os.path.join(args.platforms_dir, "_data_dirs.yml"))
        results = refresh_all(registry, force=args.refresh_data)
        updated = sum(1 for v in results.values() if v)
        if updated:
            print(f"Refreshed {updated} data director{'ies' if updated > 1 else 'y'}")

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

    groups = group_identical_platforms(platforms, args.platforms_dir,
                                      target_cores_cache if args.target else None)

    for group_platforms, representative in groups:
        variants = [p for p in group_platforms if p != representative]
        if variants:
            all_names = [load_platform_config(p, args.platforms_dir).get("platform", p) for p in group_platforms]
            label = " / ".join(all_names)
            print(f"\nGenerating pack for {label}...")
        else:
            print(f"\nGenerating pack for {representative}...")

        try:
            tc = target_cores_cache.get(representative) if args.target else None
            if args.split:
                zip_paths = generate_split_packs(
                    representative, args.platforms_dir, db, args.bios_dir,
                    args.output_dir, group_by=args.group_by,
                    emulators_dir=args.emulators_dir, zip_contents=zip_contents,
                    data_registry=data_registry, emu_profiles=emu_profiles,
                    target_cores=tc, required_only=args.required_only,
                )
                print(f"  Split into {len(zip_paths)} packs")
            else:
                zip_path = generate_pack(
                    representative, args.platforms_dir, db, args.bios_dir, args.output_dir,
                    include_extras=args.include_extras, emulators_dir=args.emulators_dir,
                    zip_contents=zip_contents, data_registry=data_registry,
                    emu_profiles=emu_profiles, target_cores=tc,
                    required_only=args.required_only,
                    system_filter=system_filter,
                )
            if not args.split and zip_path and variants:
                rep_cfg = load_platform_config(representative, args.platforms_dir)
                ver = rep_cfg.get("version", rep_cfg.get("dat_version", ""))
                ver_tag = f"_{ver.replace(' ', '')}" if ver else ""
                all_names = [load_platform_config(p, args.platforms_dir).get("platform", p) for p in group_platforms]
                combined = "_".join(n.replace(" ", "") for n in all_names) + f"{ver_tag}_BIOS_Pack.zip"
                new_path = os.path.join(os.path.dirname(zip_path), combined)
                if new_path != zip_path:
                    os.rename(zip_path, new_path)
                    print(f"  Renamed -> {os.path.basename(new_path)}")
        except (FileNotFoundError, OSError, yaml.YAMLError) as e:
            print(f"  ERROR: {e}")

    # Post-generation: verify all packs + inject manifests + SHA256SUMS
    if not args.list_emulators and not args.list_systems:
        print("\nVerifying packs and generating manifests...")
        all_ok = verify_and_finalize_packs(args.output_dir, db)
        if not all_ok:
            print("WARNING: some packs have verification errors")
            sys.exit(1)


# ---------------------------------------------------------------------------
# Post-generation pack verification + manifest + SHA256SUMS
# ---------------------------------------------------------------------------

def verify_pack(zip_path: str, db: dict) -> tuple[bool, dict]:
    """Verify a generated pack ZIP by re-hashing every file inside.

    Opens the ZIP, computes SHA1 for each file, and checks against
    database.json. Returns (all_ok, manifest_dict).

    The manifest contains per-file metadata for self-documentation.
    """
    files_db = db.get("files", {})  # SHA1 -> file_info
    by_md5 = db.get("indexes", {}).get("by_md5", {})  # MD5 -> SHA1
    manifest = {
        "version": 1,
        "generator": "retrobios generate_pack.py",
        "generated": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": [],
    }
    errors = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename
            if name.startswith("INSTRUCTIONS_") or name == "manifest.json":
                continue
            with zf.open(info) as f:
                sha1_h = hashlib.sha1()
                md5_h = hashlib.md5()
                size = 0
                for chunk in iter(lambda: f.read(65536), b""):
                    sha1_h.update(chunk)
                    md5_h.update(chunk)
                    size += len(chunk)
            sha1 = sha1_h.hexdigest()
            md5 = md5_h.hexdigest()

            # Look up in database: files_db keyed by SHA1
            db_entry = files_db.get(sha1)
            status = "verified"
            file_name = ""
            if db_entry:
                file_name = db_entry.get("name", "")
            else:
                # Try MD5 -> SHA1 lookup
                ref_sha1 = by_md5.get(md5)
                if ref_sha1:
                    db_entry = files_db.get(ref_sha1)
                    if db_entry:
                        file_name = db_entry.get("name", "")
                        status = "verified_md5"
                    else:
                        status = "untracked"
                else:
                    status = "untracked"

            manifest["files"].append({
                "path": name,
                "sha1": sha1,
                "md5": md5,
                "size": size,
                "status": status,
                "name": file_name,
            })

            # Corruption check: SHA1 in DB but doesn't match what we computed
            # This should never happen (we looked up by SHA1), but catches
            # edge cases where by_md5 resolved to a different SHA1
            if db_entry and status == "verified_md5":
                expected_sha1 = db_entry.get("sha1", "")
                if expected_sha1 and expected_sha1.lower() != sha1.lower():
                    errors.append(f"{name}: SHA1 mismatch (expected {expected_sha1}, got {sha1})")

    verified = sum(1 for f in manifest["files"] if f["status"] == "verified")
    untracked = sum(1 for f in manifest["files"] if f["status"] == "untracked")
    total = len(manifest["files"])
    manifest["summary"] = {
        "total_files": total,
        "verified": verified,
        "untracked": untracked,
        "errors": len(errors),
    }
    manifest["errors"] = errors

    all_ok = len(errors) == 0
    return all_ok, manifest


def inject_manifest(zip_path: str, manifest: dict) -> None:
    """Inject manifest.json into an existing ZIP pack."""
    manifest_json = json.dumps(manifest, indent=2, ensure_ascii=False)

    # Check if manifest already exists
    with zipfile.ZipFile(zip_path, "r") as zf:
        has_manifest = "manifest.json" in zf.namelist()

    if not has_manifest:
        # Fast path: append directly
        with zipfile.ZipFile(zip_path, "a") as zf:
            zf.writestr("manifest.json", manifest_json)
    else:
        # Rebuild to replace existing manifest
        import tempfile as _tempfile
        tmp_fd, tmp_path = _tempfile.mkstemp(suffix=".zip", dir=os.path.dirname(zip_path))
        os.close(tmp_fd)
        try:
            with zipfile.ZipFile(zip_path, "r") as src, \
                 zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as dst:
                for item in src.infolist():
                    if item.filename == "manifest.json":
                        continue
                    dst.writestr(item, src.read(item.filename))
                dst.writestr("manifest.json", manifest_json)
            os.replace(tmp_path, zip_path)
        except (OSError, zipfile.BadZipFile):
            os.unlink(tmp_path)
            raise


def generate_sha256sums(output_dir: str) -> str | None:
    """Generate SHA256SUMS.txt for all ZIP files in output_dir."""
    sums_path = os.path.join(output_dir, "SHA256SUMS.txt")
    entries = []
    for name in sorted(os.listdir(output_dir)):
        if not name.endswith(".zip"):
            continue
        path = os.path.join(output_dir, name)
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        entries.append(f"{sha256.hexdigest()}  {name}")
    if not entries:
        return None
    with open(sums_path, "w") as f:
        f.write("\n".join(entries) + "\n")
    print(f"\n{sums_path}: {len(entries)} pack checksums")
    return sums_path


def verify_pack_against_platform(
    zip_path: str, platform_name: str, platforms_dir: str,
    db: dict | None = None, emulators_dir: str = "emulators",
    emu_profiles: dict | None = None,
) -> tuple[bool, int, int, list[str]]:
    """Verify a pack ZIP against its platform config and core requirements.

    Checks:
    1. Every baseline file declared by the platform exists in the ZIP
       at the correct destination path
    2. Every in-repo core extra file (from emulator profiles) is present
    3. No duplicate entries
    4. No path anomalies (double slash, absolute, traversal)
    5. No unexpected zero-byte BIOS files

    Returns (all_ok, checked, present, errors).
    """
    from collections import Counter
    from verify import find_undeclared_files

    config = load_platform_config(platform_name, platforms_dir)
    base_dest = config.get("base_destination", "")
    errors: list[str] = []
    checked = 0
    present = 0

    if emu_profiles is None:
        emu_profiles = load_emulator_profiles(emulators_dir)

    with zipfile.ZipFile(zip_path, "r") as zf:
        zip_set = set(zf.namelist())
        zip_lower = {n.lower(): n for n in zip_set}

        # Structural checks
        dupes = sum(1 for c in Counter(zf.namelist()).values() if c > 1)
        if dupes:
            errors.append(f"{dupes} duplicate entries")
        for n in zip_set:
            if "//" in n:
                errors.append(f"double slash: {n}")
            if n.startswith("/"):
                errors.append(f"absolute path: {n}")
            if ".." in n:
                errors.append(f"path traversal: {n}")

        # Zero-byte check (exclude Dolphin GraphicMods markers)
        for info in zf.infolist():
            if info.file_size == 0 and not info.is_dir():
                if "GraphicMods" not in info.filename and info.filename != "manifest.json":
                    errors.append(f"zero-byte: {info.filename}")

        # 1. Baseline file presence
        baseline_checked = 0
        baseline_present = 0
        for sys_id, system in config.get("systems", {}).items():
            for fe in system.get("files", []):
                dest = fe.get("destination", fe.get("name", ""))
                if not dest:
                    continue
                expected = f"{base_dest}/{dest}" if base_dest else dest
                baseline_checked += 1

                if expected in zip_set or expected.lower() in zip_lower:
                    baseline_present += 1
                else:
                    errors.append(f"baseline missing: {expected}")

        # 2. Core extras presence (files from emulator profiles, in repo)
        core_checked = 0
        core_present = 0
        if db is not None:
            undeclared = find_undeclared_files(config, emulators_dir, db, emu_profiles)
            for u in undeclared:
                if not u["in_repo"]:
                    continue
                dest = u.get("path") or u["name"]
                if base_dest:
                    full = f"{base_dest}/{dest}"
                elif "/" not in dest:
                    full = f"bios/{dest}"
                else:
                    full = dest
                core_checked += 1

                if full in zip_set or full.lower() in zip_lower:
                    core_present += 1
                # Not an error if missing — some get deduped or filtered

        checked = baseline_checked + core_checked
        present = baseline_present + core_present

    return (len(errors) == 0, checked, present, errors,
            baseline_checked, baseline_present, core_checked, core_present)


def verify_and_finalize_packs(output_dir: str, db: dict,
                               platforms_dir: str = "platforms") -> bool:
    """Verify all packs, inject manifests, generate SHA256SUMS.

    Two-stage verification:
    1. Hash check against database.json (integrity)
    2. Extract + verify against platform config (conformance)

    Returns True if all packs pass verification.
    """
    all_ok = True

    # Map ZIP names to platform names
    pack_to_platform: dict[str, list[str]] = {}
    for name in sorted(os.listdir(output_dir)):
        if not name.endswith(".zip"):
            continue
        for pname in list_registered_platforms(platforms_dir):
            cfg = load_platform_config(pname, platforms_dir)
            display = cfg.get("platform", pname).replace(" ", "_")
            if display in name or display.replace("_", "") in name.replace("_", ""):
                pack_to_platform.setdefault(name, []).append(pname)

    for name in sorted(os.listdir(output_dir)):
        if not name.endswith(".zip"):
            continue
        zip_path = os.path.join(output_dir, name)

        # Stage 1: database integrity
        ok, manifest = verify_pack(zip_path, db)
        summary = manifest["summary"]
        status = "OK" if ok else "ERRORS"
        print(f"  verify {name}: {summary['verified']}/{summary['total_files']} verified, "
              f"{summary['untracked']} untracked, {summary['errors']} errors [{status}]")
        if not ok:
            for err in manifest["errors"]:
                print(f"    ERROR: {err}")
            all_ok = False
        inject_manifest(zip_path, manifest)

        # Stage 2: platform conformance (extract + verify)
        platforms = pack_to_platform.get(name, [])
        for pname in platforms:
            (p_ok, total, matched, p_errors,
             bl_checked, bl_present, core_checked, core_present) = \
                verify_pack_against_platform(
                    zip_path, pname, platforms_dir, db=db,
                )
            status = "OK" if p_ok else "FAILED"
            print(f"  platform {pname}: {bl_present}/{bl_checked} baseline, "
                  f"{core_present}/{core_checked} cores, {status}")
            if not p_ok:
                for err in p_errors:
                    print(f"    {err}")
                all_ok = False

    generate_sha256sums(output_dir)
    return all_ok


if __name__ == "__main__":
    main()
