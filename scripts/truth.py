"""Platform truth generation and diffing.

Generates ground-truth YAML from emulator profiles for gap analysis,
and diffs truth against scraped platform data to find divergences.
"""

from __future__ import annotations

import sys

from common import _norm_system_id, resolve_platform_cores
from validation import filter_files_by_mode


def _determine_core_mode(
    emu_name: str, profile: dict,
    cores_config: str | list | None,
    standalone_set: set[str] | None,
) -> str:
    """Determine effective mode (libretro/standalone) for a resolved core."""
    if cores_config == "all_libretro":
        return "libretro"
    if standalone_set is not None:
        profile_names = {emu_name} | {str(c) for c in profile.get("cores", [])}
        if profile_names & standalone_set:
            return "standalone"
        return "libretro"
    ptype = profile.get("type", "libretro")
    if "standalone" in ptype and "libretro" in ptype:
        return "both"
    if "standalone" in ptype:
        return "standalone"
    return "libretro"


def _enrich_hashes(entry: dict, db: dict) -> None:
    """Fill missing hash fields from the database."""
    sha1 = entry.get("sha1", "")
    md5 = entry.get("md5", "")

    # Hashes can be lists (multi-hash) — use first string value
    if isinstance(sha1, list):
        sha1 = sha1[0] if sha1 else ""
    if isinstance(md5, list):
        md5 = md5[0] if md5 else ""

    record = None
    if sha1 and isinstance(sha1, str) and db.get("files"):
        record = db["files"].get(sha1)
    if record is None and md5:
        by_md5 = db.get("by_md5", {})
        md5_str = md5 if isinstance(md5, str) else md5[0] if md5 else ""
        ref_sha1 = by_md5.get(md5_str.lower()) if md5_str else None
        if ref_sha1 and db.get("files"):
            record = db["files"].get(ref_sha1)
    if record is None:
        return

    for field in ("sha1", "md5", "sha256", "crc32"):
        if not entry.get(field) and record.get(field):
            entry[field] = record[field]


def _merge_file_into_system(
    system: dict, file_entry: dict, emu_name: str, db: dict | None,
) -> None:
    """Merge a file entry into a system's file list, deduplicating by name."""
    files = system.setdefault("files", [])
    name_lower = file_entry["name"].lower()

    existing = None
    for f in files:
        if f["name"].lower() == name_lower:
            existing = f
            break

    if existing is not None:
        existing["_cores"] = existing.get("_cores", set()) | {emu_name}
        sr = file_entry.get("source_ref")
        if sr is not None:
            sr_key = str(sr) if not isinstance(sr, str) else sr
            existing["_source_refs"] = existing.get("_source_refs", set()) | {sr_key}
        else:
            existing.setdefault("_source_refs", set())
        if file_entry.get("required") and not existing.get("required"):
            existing["required"] = True
        for h in ("sha1", "md5", "sha256", "crc32"):
            theirs = file_entry.get(h, "")
            ours = existing.get(h, "")
            if theirs and ours and theirs.lower() != ours.lower():
                print(
                    f"WARNING: hash conflict for {file_entry['name']} "
                    f"({h}: {ours} vs {theirs}, core {emu_name})",
                    file=sys.stderr,
                )
            elif theirs and not ours:
                existing[h] = theirs
        return

    entry: dict = {"name": file_entry["name"]}
    if file_entry.get("required") is not None:
        entry["required"] = file_entry["required"]
    for field in ("sha1", "md5", "sha256", "crc32", "size", "path",
                  "description", "hle_fallback", "category", "note",
                  "validation", "min_size", "max_size", "aliases"):
        val = file_entry.get(field)
        if val is not None:
            entry[field] = val
    entry["_cores"] = {emu_name}
    sr = file_entry.get("source_ref")
    if sr is not None:
        sr_key = str(sr) if not isinstance(sr, str) else sr
        entry["_source_refs"] = {sr_key}
    else:
        entry["_source_refs"] = set()

    if db:
        _enrich_hashes(entry, db)

    files.append(entry)


def generate_platform_truth(
    platform_name: str,
    config: dict,
    registry_entry: dict,
    profiles: dict[str, dict],
    db: dict | None = None,
    target_cores: set[str] | None = None,
) -> dict:
    """Generate ground-truth system data for a platform from emulator profiles.

    Args:
        platform_name: platform identifier
        config: loaded platform config (via load_platform_config), has cores,
                systems, standalone_cores with inheritance resolved
        registry_entry: registry metadata for hash_type, verification_mode, etc.
        profiles: all loaded emulator profiles
        db: optional database for hash enrichment
        target_cores: optional hardware target core filter

    Returns a dict with platform metadata, systems, and per-file details
    including which cores reference each file.
    """
    cores_config = config.get("cores")

    # Resolve standalone set for mode determination
    standalone_set: set[str] | None = None
    standalone_cores = config.get("standalone_cores")
    if isinstance(standalone_cores, list):
        standalone_set = {str(c) for c in standalone_cores}

    resolved = resolve_platform_cores(config, profiles, target_cores)

    # Build mapping: profile system ID -> platform system ID
    # Three strategies, tried in order:
    # 1. File-based: if the scraped platform already has this file, use its system
    # 2. Exact match: profile system ID == platform system ID
    # 3. Normalized match: strip manufacturer prefix + separators
    platform_sys_ids = set(config.get("systems", {}).keys())

    # File->platform_system reverse index from scraped config
    file_to_plat_sys: dict[str, str] = {}
    for psid, sys_data in config.get("systems", {}).items():
        for fe in sys_data.get("files", []):
            fname = fe.get("name", "").lower()
            if fname:
                file_to_plat_sys[fname] = psid
            for alias in fe.get("aliases", []):
                file_to_plat_sys[alias.lower()] = psid

    # Normalized ID -> platform system ID
    norm_to_platform: dict[str, str] = {}
    for psid in platform_sys_ids:
        norm_to_platform[_norm_system_id(psid)] = psid

    def _map_sys_id(profile_sid: str, file_name: str = "") -> str:
        """Map a profile system ID to the platform's system ID."""
        # 1. File-based lookup (handles composites and name mismatches)
        if file_name:
            plat_sys = file_to_plat_sys.get(file_name.lower())
            if plat_sys:
                return plat_sys
        # 2. Exact match
        if profile_sid in platform_sys_ids:
            return profile_sid
        # 3. Normalized match
        normed = _norm_system_id(profile_sid)
        return norm_to_platform.get(normed, profile_sid)

    systems: dict[str, dict] = {}
    cores_profiled: set[str] = set()
    cores_unprofiled: set[str] = set()
    # Track which cores contribute to each system
    system_cores: dict[str, dict[str, set[str]]] = {}

    for emu_name in sorted(resolved):
        profile = profiles.get(emu_name)
        if not profile:
            cores_unprofiled.add(emu_name)
            continue
        cores_profiled.add(emu_name)

        mode = _determine_core_mode(emu_name, profile, cores_config, standalone_set)
        raw_files = profile.get("files", [])
        if mode == "both":
            filtered = raw_files
        else:
            filtered = filter_files_by_mode(raw_files, standalone=(mode == "standalone"))

        for fe in filtered:
            profile_sid = fe.get("system", "")
            if not profile_sid:
                sys_ids = profile.get("systems", [])
                profile_sid = sys_ids[0] if sys_ids else "unknown"
            sys_id = _map_sys_id(profile_sid, fe.get("name", ""))
            system = systems.setdefault(sys_id, {})
            _merge_file_into_system(system, fe, emu_name, db)
            # Track core contribution per system
            sys_cov = system_cores.setdefault(sys_id, {
                "profiled": set(), "unprofiled": set(),
            })
            sys_cov["profiled"].add(emu_name)

    # Ensure all systems of resolved cores have entries (even with 0 files).
    # This documents that the system is covered -the core was analyzed and
    # needs no external files for this system.
    for emu_name in cores_profiled:
        profile = profiles[emu_name]
        for prof_sid in profile.get("systems", []):
            sys_id = _map_sys_id(prof_sid)
            systems.setdefault(sys_id, {})
            sys_cov = system_cores.setdefault(sys_id, {
                "profiled": set(), "unprofiled": set(),
            })
            sys_cov["profiled"].add(emu_name)

    # Track unprofiled cores per system based on profile system lists
    for emu_name in cores_unprofiled:
        for sys_id in systems:
            sys_cov = system_cores.setdefault(sys_id, {
                "profiled": set(), "unprofiled": set(),
            })
            sys_cov["unprofiled"].add(emu_name)

    # Convert sets to sorted lists for serialization
    for sys_id, sys_data in systems.items():
        for fe in sys_data.get("files", []):
            fe["_cores"] = sorted(fe.get("_cores", set()))
            fe["_source_refs"] = sorted(fe.get("_source_refs", set()))
        # Add per-system coverage
        cov = system_cores.get(sys_id, {})
        sys_data["_coverage"] = {
            "cores_profiled": sorted(cov.get("profiled", set())),
            "cores_unprofiled": sorted(cov.get("unprofiled", set())),
        }

    return {
        "platform": platform_name,
        "generated": True,
        "systems": systems,
        "_coverage": {
            "cores_resolved": len(resolved),
            "cores_profiled": len(cores_profiled),
            "cores_unprofiled": sorted(cores_unprofiled),
        },
    }


# Platform truth diffing

def _diff_system(truth_sys: dict, scraped_sys: dict) -> dict:
    """Compare files between truth and scraped for a single system."""
    # Build truth index: name.lower() -> entry, alias.lower() -> entry
    truth_index: dict[str, dict] = {}
    for fe in truth_sys.get("files", []):
        truth_index[fe["name"].lower()] = fe
        for alias in fe.get("aliases", []):
            truth_index[alias.lower()] = fe

    # Build scraped index: name.lower() -> entry
    scraped_index: dict[str, dict] = {}
    for fe in scraped_sys.get("files", []):
        scraped_index[fe["name"].lower()] = fe

    missing: list[dict] = []
    hash_mismatch: list[dict] = []
    required_mismatch: list[dict] = []
    extra_phantom: list[dict] = []
    extra_unprofiled: list[dict] = []

    matched_truth_names: set[str] = set()

    # Compare scraped files against truth
    for s_key, s_entry in scraped_index.items():
        t_entry = truth_index.get(s_key)
        if t_entry is None:
            continue
        matched_truth_names.add(t_entry["name"].lower())

        # Hash comparison
        for h in ("sha1", "md5", "crc32"):
            t_hash = t_entry.get(h, "")
            s_hash = s_entry.get(h, "")
            if not t_hash or not s_hash:
                continue
            # Normalize to list for multi-hash support
            t_list = t_hash if isinstance(t_hash, list) else [t_hash]
            s_list = s_hash if isinstance(s_hash, list) else [s_hash]
            t_set = {v.lower() for v in t_list}
            s_set = {v.lower() for v in s_list}
            if not t_set & s_set:
                hash_mismatch.append({
                    "name": s_entry["name"],
                    "hash_type": h,
                    f"truth_{h}": t_hash,
                    f"scraped_{h}": s_hash,
                    "truth_cores": list(t_entry.get("_cores", [])),
                })
                break

        # Required mismatch
        t_req = t_entry.get("required")
        s_req = s_entry.get("required")
        if t_req is not None and s_req is not None and t_req != s_req:
            required_mismatch.append({
                "name": s_entry["name"],
                "truth_required": t_req,
                "scraped_required": s_req,
            })

    # Truth files not matched -> missing
    for fe in truth_sys.get("files", []):
        if fe["name"].lower() not in matched_truth_names:
            missing.append({
                "name": fe["name"],
                "cores": list(fe.get("_cores", [])),
                "source_refs": list(fe.get("_source_refs", [])),
            })

    # Scraped files not in truth -> extra
    coverage = truth_sys.get("_coverage", {})
    has_unprofiled = bool(coverage.get("cores_unprofiled"))
    for s_key, s_entry in scraped_index.items():
        if s_key not in truth_index:
            entry = {"name": s_entry["name"]}
            if has_unprofiled:
                extra_unprofiled.append(entry)
            else:
                extra_phantom.append(entry)

    result: dict = {}
    if missing:
        result["missing"] = missing
    if hash_mismatch:
        result["hash_mismatch"] = hash_mismatch
    if required_mismatch:
        result["required_mismatch"] = required_mismatch
    if extra_phantom:
        result["extra_phantom"] = extra_phantom
    if extra_unprofiled:
        result["extra_unprofiled"] = extra_unprofiled
    return result


def _has_divergences(sys_div: dict) -> bool:
    """Check if a system divergence dict contains any actual divergences."""
    return bool(sys_div)


def _update_summary(summary: dict, sys_div: dict) -> None:
    """Update summary counters from a system divergence dict."""
    summary["total_missing"] += len(sys_div.get("missing", []))
    summary["total_extra_phantom"] += len(sys_div.get("extra_phantom", []))
    summary["total_extra_unprofiled"] += len(sys_div.get("extra_unprofiled", []))
    summary["total_hash_mismatch"] += len(sys_div.get("hash_mismatch", []))
    summary["total_required_mismatch"] += len(sys_div.get("required_mismatch", []))


def diff_platform_truth(truth: dict, scraped: dict) -> dict:
    """Compare truth YAML against scraped YAML, returning divergences.

    System IDs are matched using normalized forms (via _norm_system_id) to
    handle naming differences between emulator profiles and scraped platforms
    (e.g. 'sega-game-gear' vs 'sega-gamegear').
    """
    truth_systems = truth.get("systems", {})
    scraped_systems = scraped.get("systems", {})

    summary = {
        "systems_compared": 0,
        "systems_fully_covered": 0,
        "systems_partially_covered": 0,
        "systems_uncovered": 0,
        "total_missing": 0,
        "total_extra_phantom": 0,
        "total_extra_unprofiled": 0,
        "total_hash_mismatch": 0,
        "total_required_mismatch": 0,
    }

    divergences: dict[str, dict] = {}
    uncovered_systems: list[str] = []

    # Build normalized-ID lookup for truth systems
    norm_to_truth: dict[str, str] = {}
    for sid in truth_systems:
        norm_to_truth[_norm_system_id(sid)] = sid

    # Match scraped systems to truth via normalized IDs
    matched_truth: set[str] = set()

    for s_sid in sorted(scraped_systems):
        norm = _norm_system_id(s_sid)
        t_sid = norm_to_truth.get(norm)

        if t_sid is None:
            # Also try exact match (in case normalization is lossy)
            if s_sid in truth_systems:
                t_sid = s_sid
            else:
                uncovered_systems.append(s_sid)
                summary["systems_uncovered"] += 1
                continue

        matched_truth.add(t_sid)
        summary["systems_compared"] += 1
        sys_div = _diff_system(truth_systems[t_sid], scraped_systems[s_sid])

        if _has_divergences(sys_div):
            divergences[s_sid] = sys_div
            _update_summary(summary, sys_div)
            summary["systems_partially_covered"] += 1
        else:
            summary["systems_fully_covered"] += 1

    # Truth systems not matched by any scraped system -all files missing
    for t_sid in sorted(truth_systems):
        if t_sid in matched_truth:
            continue
        summary["systems_compared"] += 1
        sys_div = _diff_system(truth_systems[t_sid], {"files": []})
        if _has_divergences(sys_div):
            divergences[t_sid] = sys_div
            _update_summary(summary, sys_div)
            summary["systems_partially_covered"] += 1
        else:
            summary["systems_fully_covered"] += 1

    result: dict = {"summary": summary}
    if divergences:
        result["divergences"] = divergences
    if uncovered_systems:
        result["uncovered_systems"] = uncovered_systems
    return result
