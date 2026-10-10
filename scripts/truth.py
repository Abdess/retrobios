"""Platform truth generation and diffing.

Generates ground-truth YAML from emulator profiles for gap analysis,
and diffs truth against scraped platform data to find divergences.
"""

from __future__ import annotations

import sys

from common import _norm_system_id, resolve_platform_cores, runs_standalone
from validation import filter_files_by_mode, read_from_system_dir


def _serialize_source_ref(sr: object) -> str:
    """Convert a source_ref value to a clean string for serialization."""
    if isinstance(sr, str):
        return sr
    if isinstance(sr, dict):
        parts = [f"{k}: {v}" for k, v in sr.items()]
        return "; ".join(parts)
    return str(sr)


def _enrich_hashes(entry: dict, db: dict) -> None:
    """Fill missing sibling hashes from the database, ground-truth preserving.

    The profile's hashes come from the emulator source code (ground truth).
    Any hash of a given file set of bytes is a projection of that same
    ground truth. sha1, md5 and crc32 all identify the same bytes. If the
    profile has ONE ground-truth hash, the DB can supply its siblings.

    Lookup order (all are hash-anchored, never name-based):
      1. SHA1 direct
      2. MD5 -> SHA1 via indexes.by_md5
      3. CRC32 -> SHA1 via indexes.by_crc32 (weaker 32-bit anchor,
         requires size match when profile has size)

    Name-based enrichment is NEVER used: a name alone has no ground-truth
    anchor, the file in bios/ may not match what the source code expects.

    Multi-hash entries (lists of accepted variants) are left untouched to
    preserve variant information.
    """
    # Skip multi-hash entries. They express ground truth as "any of these N
    # variants", enriching with a single sibling would lose that information.
    for h in ("sha1", "md5", "crc32"):
        if isinstance(entry.get(h), list):
            return

    files_db = db.get("files", {})
    indexes = db.get("indexes", {})

    record = None

    # Anchor 1: SHA1 (strongest)
    sha1 = entry.get("sha1")
    if sha1 and isinstance(sha1, str):
        record = files_db.get(sha1)

    # Anchor 2: MD5 (strong)
    if record is None:
        md5 = entry.get("md5")
        if md5 and isinstance(md5, str):
            by_md5 = indexes.get("by_md5", {})
            ref = by_md5.get(md5.lower())
            if ref:
                ref_sha1 = ref if isinstance(ref, str) else (ref[0] if ref else None)
                if ref_sha1:
                    record = files_db.get(ref_sha1)

    # Anchor 3: CRC32 (32-bit, collisions theoretically possible).
    # Require size match when profile has a size to guard against collisions.
    if record is None:
        crc = entry.get("crc32")
        if crc and isinstance(crc, str):
            by_crc32 = indexes.get("by_crc32", {})
            ref = by_crc32.get(crc.lower())
            if ref:
                ref_sha1 = ref if isinstance(ref, str) else (ref[0] if ref else None)
                if ref_sha1:
                    candidate = files_db.get(ref_sha1)
                    if candidate is not None:
                        profile_size = entry.get("size")
                        if not profile_size or candidate.get("size") == profile_size:
                            record = candidate

    if record is None:
        return

    # Copy sibling hashes and size from the anchored record.
    # These are projections of the same ground-truth bytes.
    for field in ("sha1", "md5", "sha256", "crc32"):
        if not entry.get(field) and record.get(field):
            entry[field] = record[field]
    if not entry.get("size") and record.get("size"):
        entry["size"] = record["size"]


_FILLED_FIELDS = (
    "size",
    "min_size",
    "max_size",
    "path",
    "validation",
    "description",
    "category",
    "hle_fallback",
    "note",
    "aliases",
    "contents",
    "region",
)
_COPIED_FIELDS = (
    "sha1",
    "md5",
    "sha256",
    "crc32",
    "size",
    "path",
    "description",
    "hle_fallback",
    "category",
    "note",
    "validation",
    "min_size",
    "max_size",
    "aliases",
    "contents",
    "priority",
    "region",
)
_HASH_FIELDS = ("sha1", "md5", "sha256", "crc32")


def _merge_file_into_system(
    system: dict,
    file_entry: dict,
    emu_name: str,
    db: dict | None,
) -> None:
    """Merge a file entry into a system's file list, deduplicating by name.

    A name is one file across cores, whatever path each core gives it. A
    core that declares the same name under two paths declares two files:
    Dolphin's three IPL.bin differ only by GC/USA, GC/EUR, GC/JAP. Under
    one path or none, its declarations are revisions of one file.
    """
    files = system.setdefault("files", [])
    existing = _same_file(files, file_entry, emu_name)
    if existing is None:
        files.append(_new_truth_entry(file_entry, emu_name, db))
    else:
        _fold_into(existing, file_entry, emu_name)


def _same_file(files: list[dict], file_entry: dict, emu_name: str) -> dict | None:
    """The entry already standing for this file, if any."""
    name_lower = file_entry["name"].lower()
    path = str(file_entry.get("path") or "").casefold()

    def other_path(f: dict) -> str:
        return str(f.get("path") or "").casefold()

    same_name = [f for f in files if f["name"].lower() == name_lower]
    return (
        next((f for f in same_name if path and other_path(f) == path), None)
        # Another core's file of the same name is the same file unless their
        # contents disagree: beebem's 16 KB BBC BIOS.rom and np2kai's PC-98
        # bios.rom merged, and the export wrote the BBC md5 over Recalbox's.
        or next(
            (f for f in same_name
             if emu_name not in f.get("_cores", ()) and not _contents_disagree(f, file_entry)),
            None,
        )
        # Revisions accepted under one name and no path fill one slot.
        or next((f for f in same_name if not path or not other_path(f)), None)
    )


def _declared(entry: dict, field: str) -> set[str]:
    """The values an entry declares for a hash field, one or a list."""
    value = entry.get(field)
    values = value if isinstance(value, list) else [value]
    return {str(v).lower() for v in values if v}


def _contents_disagree(a: dict, b: dict) -> bool:
    """A hash both declare without a value in common, or two declared sizes."""
    for field in ("sha1", "md5", "sha256", "crc32"):
        ours, theirs = _declared(a, field), _declared(b, field)
        if ours and theirs and not ours & theirs:
            return True
    size_a, size_b = a.get("size"), b.get("size")
    return isinstance(size_a, int) and isinstance(size_b, int) and size_a != size_b


def _fold_into(existing: dict, file_entry: dict, emu_name: str) -> None:
    """Add one core's declaration to the entry that already stands for it."""
    existing["_cores"] = existing.get("_cores", set()) | {emu_name}
    sr = file_entry.get("source_ref")
    if sr is not None:
        sr_key = _serialize_source_ref(sr)
        existing["_source_refs"] = existing.get("_source_refs", set()) | {sr_key}
    else:
        existing.setdefault("_source_refs", set())
    if file_entry.get("required"):
        existing["required"] = True
        # Which cores need it: `required` above is the union, true when
        # any core needs it, and a package of one core must not read it.
        existing["_required_by"] = existing.get("_required_by", set()) | {emu_name}
    _merge_hashes(existing, file_entry, emu_name)
    # Merge non-hash data fields if existing lacks them.
    # A core that creates an entry without size/path/validation may be
    # enriched by a sibling core that has those fields.
    for field in _FILLED_FIELDS:
        if file_entry.get(field) is not None and existing.get(field) is None:
            existing[field] = file_entry[field]
    _merge_priority(existing, file_entry.get("priority"))


def _merge_hashes(existing: dict, file_entry: dict, emu_name: str) -> None:
    for h in _HASH_FIELDS:
        theirs = file_entry.get(h, "")
        ours = existing.get(h, "")
        if not theirs:
            continue
        if not ours:
            existing[h] = theirs
            continue
        # Normalize to sets for multi-hash comparison
        t_list = theirs if isinstance(theirs, list) else [theirs]
        o_list = ours if isinstance(ours, list) else [ours]
        if not {str(v).lower() for v in t_list} & {str(v).lower() for v in o_list}:
            print(
                f"WARNING: hash conflict for {file_entry['name']} "
                f"({h}: {ours} vs {theirs}, core {emu_name})",
                file=sys.stderr,
            )


def _merge_priority(existing: dict, theirs: int | None) -> None:
    """Search order is a fact of the code, so it travels with the entry.

    The best rank any core gives it is kept and the disagreement is recorded
    beside it, the way slot.py already does: the rank says how early to read
    the file, the conflict says the order cannot decide which single file to
    keep.
    """
    if theirs is None:
        return
    ours = existing.get("priority")
    if ours is None:
        existing["priority"] = theirs
        return
    if ours != theirs:
        existing["priority_conflict"] = True
    existing["priority"] = min(ours, theirs)


def _new_truth_entry(file_entry: dict, emu_name: str, db: dict | None) -> dict:
    entry: dict = {"name": file_entry["name"]}
    if file_entry.get("required") is not None:
        entry["required"] = file_entry["required"]
    for field in _COPIED_FIELDS:
        val = file_entry.get(field)
        if val is not None:
            entry[field] = val
    # Strip empty string hashes (profile says "" when hash is unknown)
    for h in _HASH_FIELDS:
        if entry.get(h) == "":
            del entry[h]
    # Normalize CRC32: strip 0x prefix, lowercase
    crc = entry.get("crc32")
    if isinstance(crc, str):
        entry["crc32"] = crc.removeprefix("0x").lower()
    entry["_cores"] = {emu_name}
    entry["_required_by"] = {emu_name} if file_entry.get("required") else set()
    sr = file_entry.get("source_ref")
    entry["_source_refs"] = {_serialize_source_ref(sr)} if sr is not None else set()
    if db:
        _enrich_hashes(entry, db)
    return entry


def _has_exploitable_data(entry: dict) -> bool:
    """Check if an entry has any data beyond its name that can drive verification.

    Applied AFTER merging all cores so entries benefit from enrichment by
    sibling cores before being judged empty.
    """
    return bool(
        any(entry.get(h) for h in ("sha1", "md5", "sha256", "crc32"))
        or entry.get("path")
        or entry.get("size")
        or entry.get("min_size")
        or entry.get("max_size")
        or entry.get("validation")
        or entry.get("contents")
    )


def _system_dir_files(profile: dict, standalone: bool) -> list[dict]:
    """Entries of the build the platform runs, read from the system directory."""
    return list(
        filter(
            read_from_system_dir,
            filter_files_by_mode(profile.get("files", []), standalone=standalone),
        )
    )


def _archives_not_members(files: list[dict]) -> list[dict]:
    """A profile's entries with the members of each archive folded into it.

    fbneo declares bubsys.zip as the ROMs it holds, each carrying
    `archive: bubsys.zip`. The platform reads the archive, never a member:
    as loose files the members were added to RetroArch's System.dat, and
    the 480-byte boot.bin was filed under the Dreamcast by its bare name.
    The archive stands in their place with the members as its contents,
    the shape a profile that declares the archive itself already has.
    """
    out: list[dict] = []
    archives: dict[tuple[str, str], dict] = {}
    for fe in files:
        archive = fe.get("archive")
        if not archive:
            out.append(fe)
            continue
        key = (archive, fe.get("system", ""))
        entry = archives.get(key)
        if entry is None:
            entry = {"name": archive, "category": "bios_zip", "contents": []}
            if fe.get("system"):
                entry["system"] = fe["system"]
            if fe.get("source_ref") is not None:
                entry["source_ref"] = fe["source_ref"]
            archives[key] = entry
            out.append(entry)
        if fe.get("required"):
            entry["required"] = True
        entry["contents"].append({
            field: fe[field]
            for field in ("name", "size", "crc32", "sha1", "md5")
            if fe.get(field) is not None
        })
    return out


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
    # The layout rule verify and the pack builder apply: truth guessed its
    # own from the profile type where the platform names no standalone
    # emulator, and kept files the pack never carries.
    standalone_set = {str(c) for c in config.get("standalone_cores") or []}

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

        filtered = _archives_not_members(_system_dir_files(
            profile, runs_standalone(emu_name, profile, standalone_set)
        ))

        for fe in filtered:
            profile_sid = fe.get("system", "")
            if not profile_sid:
                sys_ids = profile.get("systems", [])
                profile_sid = sys_ids[0] if sys_ids else "unknown"
            sys_id = _map_sys_id(profile_sid, fe.get("name", ""))
            system = systems.setdefault(sys_id, {})
            _merge_file_into_system(system, fe, emu_name, db)
            # Track core contribution per system
            sys_cov = system_cores.setdefault(
                sys_id,
                {
                    "profiled": set(),
                    "unprofiled": set(),
                },
            )
            sys_cov["profiled"].add(emu_name)

    # Ensure all systems of resolved cores have entries (even with 0 files).
    # This documents that the system is covered -the core was analyzed and
    # needs no external files for this system.
    for emu_name in cores_profiled:
        profile = profiles[emu_name]
        for prof_sid in profile.get("systems", []):
            sys_id = _map_sys_id(prof_sid)
            systems.setdefault(sys_id, {})
            sys_cov = system_cores.setdefault(
                sys_id,
                {
                    "profiled": set(),
                    "unprofiled": set(),
                },
            )
            sys_cov["profiled"].add(emu_name)

    # Track unprofiled cores per system based on profile system lists
    for emu_name in cores_unprofiled:
        for sys_id in systems:
            sys_cov = system_cores.setdefault(
                sys_id,
                {
                    "profiled": set(),
                    "unprofiled": set(),
                },
            )
            sys_cov["unprofiled"].add(emu_name)

    # Drop files with no exploitable data AFTER all cores have contributed.
    # A file declared by one core without hash/size/path may be enriched by
    # another core that has the same entry with data, so the filter must run
    # once at the end, not per-core at creation time.
    for sys_data in systems.values():
        files_list = sys_data.get("files", [])
        if files_list:
            sys_data["files"] = [fe for fe in files_list if _has_exploitable_data(fe)]

    # Convert sets to sorted lists for serialization
    for sys_id, sys_data in systems.items():
        for fe in sys_data.get("files", []):
            fe["_cores"] = sorted(fe.get("_cores", set()))
            fe["_required_by"] = sorted(fe.get("_required_by", set()))
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


def _match_renames(
    unmatched_truth: list[dict], unmatched_scraped: dict
) -> tuple[set[int], set]:
    """Pair files a platform renamed with the truth entry they came from.

    A platform is free to call a file whatever it likes -- Batocera ships
    the same ROM as ROM1 -- so a name that matches nothing is not yet a
    gap. When an unmatched file on either side carries the same hash, it
    is one file under two names, and counting it as both missing and extra
    would report a gap that does not exist.

    Returns the positions in unmatched_truth and the scraped keys that pair
    up: a name does not identify a truth entry, two can share it.
    """
    # Hash-based fallback: detect platform renames (e.g. Batocera ROM → ROM1)
    # If an unmatched scraped file shares a hash with an unmatched truth file,
    # it's the same file under a different name: a platform rename, not a gap.
    rename_matched_truth: set[int] = set()
    rename_matched_scraped: set = set()

    if unmatched_truth and unmatched_scraped:
        # Build hash → truth file index for unmatched truth files
        truth_hash_index: dict[str, int] = {}
        for position, fe in enumerate(unmatched_truth):
            for h in ("sha1", "md5", "crc32"):
                val = fe.get(h)
                if val and isinstance(val, str):
                    truth_hash_index[val.lower()] = position

        for s_key, s_entry in unmatched_scraped.items():
            for h in ("sha1", "md5", "crc32"):
                s_val = s_entry.get(h)
                if not s_val or not isinstance(s_val, str):
                    continue
                position = truth_hash_index.get(s_val.lower())
                if position is not None:
                    # Rename detected. Count as matched
                    rename_matched_truth.add(position)
                    rename_matched_scraped.add(s_key)
                    break

    return rename_matched_truth, rename_matched_scraped


def _hash_set(entry: dict) -> set[str]:
    values: set[str] = set()
    for h in ("sha1", "md5", "crc32"):
        value = entry.get(h) or []
        values.update(str(v).lower() for v in (value if isinstance(value, list) else [value]))
    return values


def _path_tail(value: object) -> str:
    return str(value or "").replace("\\", "/").casefold()


def _pair_rank(truth_entry: dict, scraped_entry: dict) -> tuple[bool, bool, bool, bool]:
    """How well a same-named truth entry describes a scraped one.

    Exact path suffix, then same directory, then primary name over alias,
    then a shared hash.
    """
    destination = _path_tail(scraped_entry.get("destination"))
    t_path = _path_tail(truth_entry.get("path"))
    return (
        bool(t_path) and destination.endswith(t_path),
        "/" in t_path and t_path.rsplit("/", 1)[0] == destination.rpartition("/")[0],
        truth_entry["name"].lower() == scraped_entry["name"].lower(),
        bool(_hash_set(scraped_entry) & _hash_set(truth_entry)),
    )


def _hash_mismatch(t_entry: dict, s_entry: dict) -> dict | None:
    """The first hash both sides declare without a value in common."""
    for h in ("sha1", "md5", "crc32"):
        t_hash = t_entry.get(h, "")
        s_hash = s_entry.get(h, "")
        if not t_hash or not s_hash:
            continue
        # Normalize to list for multi-hash support
        t_list = t_hash if isinstance(t_hash, list) else [t_hash]
        s_list = s_hash if isinstance(s_hash, list) else [s_hash]
        if not {v.lower() for v in t_list} & {v.lower() for v in s_list}:
            return {
                "name": s_entry["name"],
                "hash_type": h,
                f"truth_{h}": t_hash,
                f"scraped_{h}": s_hash,
                "truth_cores": list(t_entry.get("_cores", [])),
            }
    return None


def _diff_system(truth_sys: dict, scraped_sys: dict) -> dict:
    """Compare files between truth and scraped for a single system.

    A name can stand for several files of one system (Dolphin's IPL.bin
    under GC/USA, GC/EUR and GC/JAP), so each scraped entry is paired with
    the same-named truth entry at its destination first, and an entry
    never answers for two.
    """
    truth_files = truth_sys.get("files", [])
    truth_index: dict[str, list[int]] = {}
    for position, fe in enumerate(truth_files):
        for key in [fe["name"], *fe.get("aliases", [])]:
            truth_index.setdefault(key.lower(), []).append(position)

    scraped_files = scraped_sys.get("files", [])

    missing: list[dict] = []
    hash_mismatch: list[dict] = []
    required_mismatch: list[dict] = []
    extra_phantom: list[dict] = []
    extra_unprofiled: list[dict] = []

    matched: set[int] = set()
    unmatched_scraped: dict[int, dict] = {}
    for s_position, s_entry in enumerate(scraped_files):
        candidates = [
            p for p in truth_index.get(s_entry["name"].lower(), []) if p not in matched
        ]
        if not candidates:
            if s_entry["name"].lower() not in truth_index:
                unmatched_scraped[s_position] = s_entry
            continue
        # The first best candidate wins, as max() keeps the first maximum.
        ranked = [(_pair_rank(truth_files[p], s_entry), p) for p in candidates]
        t_position = max(ranked, key=lambda pair: pair[0])[1]
        matched.add(t_position)
        t_entry = truth_files[t_position]

        mismatch = _hash_mismatch(t_entry, s_entry)
        if mismatch:
            hash_mismatch.append(mismatch)
        t_req = t_entry.get("required")
        s_req = s_entry.get("required")
        if t_req is not None and s_req is not None and t_req != s_req:
            required_mismatch.append(
                {
                    "name": s_entry["name"],
                    "truth_required": t_req,
                    "scraped_required": s_req,
                }
            )

    # Collect unmatched files from both sides
    unmatched_truth = [
        fe for position, fe in enumerate(truth_files) if position not in matched
    ]

    rename_matched_truth, rename_matched_scraped = _match_renames(
        unmatched_truth, unmatched_scraped
    )

    # Truth files not matched (by name, alias, or hash) -> missing
    for position, fe in enumerate(unmatched_truth):
        if position not in rename_matched_truth:
            missing.append(
                {
                    "name": fe["name"],
                    "cores": list(fe.get("_cores", [])),
                    "source_refs": list(fe.get("_source_refs", [])),
                }
            )

    # Scraped files not in truth -> extra
    coverage = truth_sys.get("_coverage", {})
    has_unprofiled = bool(coverage.get("cores_unprofiled"))
    # An archive declared once per ROM it holds (zipped_file) is still one
    # file.
    seen_extra: set[tuple[str, str]] = set()
    for s_key, s_entry in unmatched_scraped.items():
        key = (s_entry["name"].lower(), _path_tail(s_entry.get("destination")))
        if s_key in rename_matched_scraped or key in seen_extra:
            continue
        seen_extra.add(key)
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
