"""The divergences between a platform's own declarations and its generated truth."""

from __future__ import annotations

from model.systems import norm_system_id


# Platform truth diffing


def _path_tail(value: object) -> str:
    return str(value or "").replace("\\", "/").casefold()


def _hash_mismatch(t_entry: dict, s_entry: dict) -> dict | None:
    """The first hash field the export would correct, by the export's rule.

    contradicted_hashes is the one decision: a hash the code does not check
    contradicts nothing (checked_hashes), and a platform md5 that is a
    composite of a zip's members is no container md5 (comparable).
    """
    from resolve.nativemodel import contradicted_hashes

    fields = contradicted_hashes(t_entry, s_entry)
    if not fields:
        return None
    h = fields[0]
    return {
        "name": s_entry["name"],
        "hash_type": h,
        f"truth_{h}": t_entry.get(h, ""),
        f"scraped_{h}": s_entry.get(h, ""),
        "truth_cores": list(t_entry.get("_cores", [])),
    }


def _diff_system(truth_sys: dict, scraped_sys: dict) -> dict:
    """Compare files between truth and scraped for a single system.

    Entries are paired by pair_entries, the rule export_native applies. Two
    rules had diverged, and diff_truth flagged a hash the export did not
    correct while the export corrected hashes the diff never named. An entry
    never answers for two.
    """
    from resolve.nativemodel import is_placeholder, is_label
    from resolve.reconcile import pair_entries, platform_declares

    truth_files = [
        fe for fe in truth_sys.get("files", [])
        if fe.get("name") and not fe["name"].startswith("_")
        and not is_placeholder(fe["name"])
    ]
    scraped_files = scraped_sys.get("files", [])

    missing: list[dict] = []
    hash_mismatch: list[dict] = []
    required_mismatch: list[dict] = []
    extra_phantom: list[dict] = []
    extra_unprofiled: list[dict] = []

    pairs = pair_entries(truth_files, scraped_files)
    claimed = set(pairs.values())
    for t_index, t_entry in enumerate(truth_files):
        s_position = pairs.get(t_index)
        if s_position is None:
            if (not is_label(t_entry) and not t_entry.get("bundled")
                    and not platform_declares(t_entry, scraped_files)):
                missing.append(
                    {
                        "name": t_entry["name"],
                        "destination": t_entry.get("path") or t_entry["name"],
                        "cores": list(t_entry.get("_cores", [])),
                        "source_refs": list(t_entry.get("_source_refs", [])),
                    }
                )
            continue
        s_entry = scraped_files[s_position]
        mismatch = _hash_mismatch(t_entry, s_entry)
        if mismatch:
            mismatch["destination"] = s_entry.get("destination") or s_entry["name"]
            hash_mismatch.append(mismatch)
        t_req = t_entry.get("required")
        s_req = s_entry.get("required")
        if t_entry.get("one_of_required") and not t_req:
            # Needed as one of a set: no value of its own to compare.
            t_req = None
        if t_req is not None and s_req is not None and t_req != s_req:
            required_mismatch.append(
                {
                    "name": s_entry["name"],
                    "destination": s_entry.get("destination") or s_entry["name"],
                    "truth_required": t_req,
                    "scraped_required": s_req,
                }
            )

    # A scraped entry no truth entry describes, by path, name or hash.
    unmatched_scraped = {
        position: s_entry
        for position, s_entry in enumerate(scraped_files)
        if position not in claimed
        and not any(platform_declares(t, [s_entry]) for t in truth_files)
    }

    # Scraped files not in truth -> extra
    coverage = truth_sys.get("_coverage", {})
    has_unprofiled = bool(coverage.get("cores_unprofiled"))
    # An archive declared once per ROM it holds (zipped_file) is still one
    # file.
    seen_extra: set[tuple[str, str]] = set()
    for s_entry in unmatched_scraped.values():
        key = (s_entry["name"].lower(), _path_tail(s_entry.get("destination")))
        if key in seen_extra:
            continue
        seen_extra.add(key)
        # The destination tells apart two declarations of one name: the
        # report listed six `hiscore.dat` to add beside one to drop.
        entry = {
            "name": s_entry["name"],
            "destination": s_entry.get("destination") or s_entry["name"],
        }
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

    System IDs are matched using normalized forms (via norm_system_id) to
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
        norm_to_truth[norm_system_id(sid)] = sid

    # Match scraped systems to truth via normalized IDs
    matched_truth: set[str] = set()

    for s_sid in sorted(scraped_systems):
        norm = norm_system_id(s_sid)
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

    # Truth systems not matched by any scraped system: all files missing
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
