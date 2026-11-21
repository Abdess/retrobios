"""Verify results printed for a person, per platform and per emulator."""

from __future__ import annotations

from collections import Counter

from core.text import count_text
from packs.shares import core_shares
from packs.verdicts import Severity, Status
from resolve.categories import BIOS
from resolve.nativemode import reads_file_contents


# Output


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

    Example: handy validates crc32=0d973c9d,size=512 [lynx/rom.h:48-49]
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


def _print_ground_truth(gt: list[dict], verbose: bool) -> None:
    """Print ground truth lines for a file entry."""
    if not gt:
        return
    if verbose:
        for line in _format_ground_truth_verbose(gt):
            print(f"    {line}")
    else:
        print(f"    {_format_ground_truth_aggregate(gt)}")


def discrepancy_keys(details: list[dict]) -> set[str]:
    """The DISCREPANCY lines _print_detail_entries prints for these details.

    A file already reported MISSING or UNTESTED on its own ground is not
    printed again as a discrepancy, and is not counted as one either.
    """
    shown = {
        f"{d['system']}/{d['name']}"
        for d in details
        if d["status"] == Status.MISSING
        or (d["status"] == Status.UNTESTED and not d.get("discrepancy"))
    }
    return {
        key
        for d in details
        if d.get("discrepancy")
        and (key := f"{d['system']}/{d['name']}") not in shown
    }


# A platform entry that is not firmware, as the report names it.
NOT_FIRMWARE = {
    "game_data": "game data",
    "unread": "no core the platform runs opens it",
}


def category_evidence_text(evidence: dict) -> str:
    """One line saying what establishes a missing entry's category."""
    if evidence.get("read_by"):
        groups: dict[bool, list[str]] = {True: [], False: []}
        for reader in evidence["read_by"]:
            refs = [
                f"{e['name']} at {e['source_ref']}" if e.get("source_ref") else e["name"]
                for e in reader.get("entries", [])
            ]
            groups[bool(reader.get("runs_system"))].append(
                f"{reader['emulator']} ({', '.join(refs)})" if refs
                else f"{reader['emulator']} (by {reader['proof']})"
            )
        if not groups[True]:
            return "read by " + ", ".join(groups[False])
        text = "read by " + ", ".join(groups[True])
        if groups[False]:
            text += ", also named by " + ", ".join(groups[False])
        return text
    examined = evidence.get("cores_examined") or []
    cores = f"cores examined: {', '.join(examined)}" if examined else "no core examined"
    if evidence.get("unsettled"):
        return f"no reader found, not settled: {evidence['unsettled']} ({cores})"
    return f"no reader found ({cores})"


def _print_category_evidence(detail: dict) -> None:
    evidence = detail.get("category_evidence")
    if evidence:
        print(f"      {category_evidence_text(evidence)}")


def _print_detail_entries(details: list[dict], seen: set[str], verbose: bool) -> None:
    """Print UNTESTED, MISSING, and DISCREPANCY entries from verification details."""
    _print_untested_details(details, seen, verbose)
    _print_missing_details(details, seen, verbose)
    _print_discrepancy_details(details, seen, verbose)
    if verbose:
        _print_ok_details(details, seen)


def _print_untested_details(details: list[dict], seen: set[str], verbose: bool) -> None:
    for d in details:
        if d["status"] != Status.UNTESTED:
            continue
        if d.get("discrepancy"):
            # Reported below with the ground for it: a declaration
            # unmet at a path another declaration holds.
            continue
        key = f"{d['system']}/{d['name']}"
        if key in seen:
            continue
        seen.add(key)
        req = "required" if d.get("required", True) else "optional"
        hle = ", HLE available" if d.get("hle_fallback") else ""
        reason = d.get("reason", "")
        print(f"  UNTESTED ({req}{hle}): {key}: {reason}")
        _print_ground_truth(d.get("ground_truth", []), verbose)


def _print_missing_details(details: list[dict], seen: set[str], verbose: bool) -> None:
    for d in details:
        if d["status"] != Status.MISSING:
            continue
        key = f"{d['system']}/{d['name']}"
        if key in seen:
            continue
        label = NOT_FIRMWARE.get(d.get("category", BIOS))
        if label:
            # Counted on their own line, named on request.
            if verbose:
                seen.add(key)
                print(f"  MISSING ({label}): {key}")
                _print_category_evidence(d)
            continue
        seen.add(key)
        req = "required" if d.get("required", True) else "optional"
        hle = ", HLE available" if d.get("hle_fallback") else ""
        print(f"  MISSING ({req}{hle}): {key}")
        if verbose:
            _print_category_evidence(d)
        _print_ground_truth(d.get("ground_truth", []), verbose)


def _print_discrepancy_details(details: list[dict], seen: set[str], verbose: bool) -> None:
    for d in details:
        disc = d.get("discrepancy")
        if disc:
            key = f"{d['system']}/{d['name']}"
            if key in seen:
                continue
            seen.add(key)
            print(f"  DISCREPANCY: {key}: {disc}")
            _print_ground_truth(d.get("ground_truth", []), verbose)


def _print_ok_details(details: list[dict], seen: set[str]) -> None:
    for d in details:
        if d["status"] != Status.OK:
            continue
        key = f"{d['system']}/{d['name']}"
        if key in seen:
            continue
        seen.add(key)
        gt = d.get("ground_truth", [])
        if gt:
            req = "required" if d.get("required", True) else "optional"
            print(f"  OK ({req}): {key}")
            for line in _format_ground_truth_verbose(gt):
                print(f"    {line}")


def _print_undeclared_entry(
    u: dict, prefix: str, verbose: bool, repeated: frozenset[str] = frozenset()
) -> None:
    """Print a single undeclared file entry with its validation checks.

    A name in ``repeated`` is read at more than one path, and the line names
    the path: two identical lines told no one there were two slots to fill.
    """
    name = u["path"] if u["name"] in repeated and u.get("path") else u["name"]
    arc_count = u.get("archive_file_count")
    if arc_count:
        name_label = f"{name} ({count_text(arc_count, 'file')})"
    else:
        name_label = name
    if u.get("alternatives") and not u.get("in_repo"):
        name_label += f" (or {', '.join(u['alternatives'])})"
    print(f"    {prefix}: {u['emulator']} needs {name_label}")
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
            # A bare "[size]" under the entry said nothing to a reader.
            print(f"      validates {'+'.join(checks)}")


def _repeated_names(entries: list[dict]) -> frozenset[str]:
    """Names more than one of ``entries`` carries."""
    counts = Counter(u["name"] for u in entries)
    return frozenset(name for name, count in counts.items() if count > 1)


def _omission_reasons(entries: list[dict]) -> str:
    """Each reason a held file was left out, with its count when several.

    Printing the first entry's reason for the whole count named one cause
    for 412 RomM files when 20 carried it.
    """
    counts = Counter(u.get("omitted", "not placed") for u in entries)
    if len(counts) == 1:
        return next(iter(counts))
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return ", ".join(f"{count} {reason}" for reason, count in ranked)


def _print_undeclared_section(result: dict, verbose: bool) -> None:
    """Print cross-reference section for undeclared files used by cores."""
    undeclared = result.get("undeclared_files", [])
    # The pack's core copies can come from no gap entry: recalbox
    # --system nec-pc-engine packs six root syscard copies for geargrafx
    # with an empty gap report, and returning here hid them.
    packed = result.get("packed_extras")
    if not undeclared and not (packed and any(packed.values())):
        return

    shares = core_shares(result)
    bundled, unplaced, game_data = shares.bundled, shares.unplaced, shares.game_data
    req_not_in_repo = shares.required_missing
    req_hle_not_in_repo = shares.hle_missing
    opt_not_in_repo = shares.optional_missing
    core_in_pack, gd_packed = shares.in_pack, shares.game_data_packed
    core_missing_req = len(req_not_in_repo) + len(req_hle_not_in_repo)
    core_missing_opt = len(opt_not_in_repo)

    # Required gaps are always named below, the optional ones on request.
    listed = "" if verbose or not core_missing_opt else " (--verbose lists them)"
    print(
        f"  Core files: {core_in_pack} in pack, {core_missing_req} required missing, "
        f"{core_missing_opt} optional missing{listed}"
    )
    # The missing files follow the line that counts them: printed after the
    # held-but-not-packed line, they read as files installed with their emulator.
    repeated = _repeated_names(req_not_in_repo + req_hle_not_in_repo + opt_not_in_repo)
    for u in req_not_in_repo:
        _print_undeclared_entry(u, "MISSING (required)", verbose, repeated)
    for u in req_hle_not_in_repo:
        _print_undeclared_entry(u, "MISSING (required, HLE fallback)", verbose, repeated)
    if verbose:
        for u in opt_not_in_repo:
            _print_undeclared_entry(u, "MISSING (optional)", verbose, repeated)
    if bundled:
        # The required firmware is named, as a missing one would be. The
        # rest (shaders, runtime libraries, engine data) on request.
        shown = bundled if verbose else [
            u for u in bundled
            if u["required"] and u.get("category", "bios") != "game_data"
        ]
        named = sorted({u["name"] for u in shown})
        # The required firmware alone read as the whole count: 14 names
        # for 154 entries, nothing saying the rest existed.
        hidden = len({u["name"] for u in bundled}) - len(named)
        more = f"{hidden} more, " if named else ""
        items = named + ([f"{more}--verbose lists them"] if hidden else [])
        print(
            f"  Bundled with their emulator, not collected: {len(bundled)}"
            + (f" ({', '.join(items)})" if items else "")
        )
    if unplaced:
        print(f"  Core files held but not packed: {len(unplaced)} "
              f"({_omission_reasons(unplaced)})")

    if game_data or (packed and packed.get("game_data")):
        gd_missing = shares.game_data_missing
        gd_unplaced = shares.game_data_unplaced
        if gd_missing or gd_packed or gd_unplaced:
            listed = "" if verbose or not gd_missing else " (--verbose lists them)"
            print(f"  Game data: {gd_packed} in pack, {len(gd_missing)} missing{listed}")
        if verbose:
            repeated = _repeated_names(gd_missing)
            for u in gd_missing:
                _print_undeclared_entry(u, "MISSING (game data)", verbose, repeated)
        if gd_unplaced:
            print(
                f"  Game data held but not packed: {len(gd_unplaced)} "
                f"({_omission_reasons(gd_unplaced)})"
            )


def _print_launcher_unproven(result: dict, verbose: bool) -> None:
    """Launcher records resting on a config file the code does not prove."""
    rows = result.get("launcher_unproven") or []
    if not rows:
        return
    listed = "" if verbose else " (--verbose lists them)"
    print(f"  Launcher records unproven: {len(rows)}{listed}")
    if not verbose:
        return
    for row in rows:
        print(f"    [{row['index']}] {row['emulator']} {row['kind']}: {row['passes_to']}")
        for link in row["missing"]:
            print(f"      missing {link}")


def _print_launcher_reads(result: dict, verbose: bool) -> None:
    """Names the platform's launch code reads that the collection lacks."""
    every = result.get("launcher_reads_not_held") or []
    rows = [r for r in every if not r.get("unsourceable")]
    unsourceable = [r for r in every if r.get("unsourceable")]
    listed = "" if verbose else " (--verbose lists them)"
    if rows:
        print(f"  Launcher reads, not held: {len(rows)}{listed}")
    if unsourceable:
        print(f"  Launcher reads, unsourceable: {len(unsourceable)}{listed}")
    if not verbose:
        return
    for row in unsourceable:
        print(f"    {row['name']} [{', '.join(row['emulators'])}]: {row['unsourceable']}")
    for row in rows:
        kinds = ", ".join(sorted({r["kind"] for r in row["readers"]}))
        casing = f", held as {row['held_as']}" if row.get("held_as") else ""
        print(f"    {row['name']} [{', '.join(row['emulators'])}, {kinds}{casing}]")
        for reader in row["readers"]:
            print(f"      {reader['emulator']}: {reader['source_ref']}")


def _platform_summary_parts(result: dict) -> list[str]:
    """The counts of a platform's first report line, in its mode's terms."""
    mode = result["verification_mode"]
    total = result["total_files"]
    c = result["severity_counts"]
    ok_count = c[Severity.OK]
    problems = total - ok_count

    if not reads_file_contents(mode):
        parts = [f"{ok_count}/{total} present"]
        if problems:
            missing = c.get(Severity.WARNING, 0) + c.get(Severity.CRITICAL, 0)
            optional_missing = c.get(Severity.INFO, 0)
            if missing:
                parts.append(f"{missing} missing")
            if optional_missing:
                parts.append(f"{optional_missing} optional missing")
        return parts
    sc = result.get("status_counts", {})
    untested = sc.get(Status.UNTESTED, 0)
    missing = sc.get(Status.MISSING, 0)
    parts = [f"{ok_count}/{total} OK"]
    if untested:
        parts.append(f"{untested} untested")
    if missing:
        parts.append(f"{missing} missing")
    return parts


def _print_release_assets(details: list[dict]) -> None:
    fetched = sorted({d["name"] for d in details if d.get("release_asset")})
    if fetched:
        # Counted present: an online build downloads them. --offline counts
        # them missing, as an offline build leaves them out.
        shown = ", ".join(fetched[:10]) + (f" (+{len(fetched) - 10})" if len(fetched) > 10 else "")
        print(f"  Release assets fetched when the pack is built ({len(fetched)}): {shown}")


def _print_platform_notices(result: dict, verbose: bool) -> None:
    """What the counts leave unsaid: uncached trees, cuts, region and category gaps."""
    uncached = result.get("data_dir_notices") or []
    if uncached and result.get("status_counts", {}).get(Status.MISSING):
        shown = ", ".join(uncached[:10]) + (f" (+{len(uncached) - 10})" if len(uncached) > 10 else "")
        print(
            f"  Data directories not cached ({len(uncached)}), their files count missing "
            f"until refresh_data_dirs.py runs (an online pack build refreshes them): {shown}"
        )
    for line in result.get("left_out") or []:
        print(f"  {line}")
    fallbacks = result.get("region_fallbacks") or []
    if fallbacks:
        from packs.readme import group_label

        print(f"  No BIOS for the requested regions, all kept ({len(fallbacks)}): "
              + ", ".join(group_label(g) for g in fallbacks))

    not_firmware = result.get("missing_not_firmware") or {}
    if not_firmware:
        counts = ", ".join(
            f"{len(dests)} {NOT_FIRMWARE[category]}"
            for category, dests in not_firmware.items()
        )
        listed = "" if verbose else " (--verbose lists them)"
        print(f"  Missing, not firmware: {counts}{listed}")


def _print_platform_coverage(result: dict, verbose: bool) -> None:
    # The same notes come back for every platform running these cores and
    # filled 985 of the 1114 lines of verify --all: counted, listed on ask.
    exclusions = result.get("exclusion_notes", [])
    if exclusions and verbose:
        print(f"  No external files ({len(exclusions)}):")
        for ex in exclusions:
            print(f"    {ex['emulator']}: {ex['detail']} [{ex['reason']}]")
    elif exclusions:
        print(f"  No external files: {len(exclusions)} cores (--verbose lists them)")

    gt_cov = result.get("ground_truth_coverage")
    if gt_cov and not gt_cov.get("applicable", True):
        # MiSTer declares no core by design: its BiosDB is the answer, and
        # the site shows "-" for it rather than a 0% gap.
        print("  Ground truth: not applicable, the platform runs no profiled core")
    elif gt_cov and gt_cov["total"] > 0:
        # Rounded, as the site rounds: truncated, RetroArch read 20% here
        # and 21% there for one measure.
        pct = round(gt_cov["with_validation"] * 100 / gt_cov["total"])
        print(
            f"  Ground truth: {gt_cov['with_validation']}/{gt_cov['total']} files have emulator validation ({pct}%)"
        )
        no_profile = gt_cov["total"] - gt_cov.get("with_profile", gt_cov["with_validation"])
        if no_profile:
            print(f"    {no_profile} platform-only (no emulator profile)")


def print_platform_result(
    result: dict, group: list[str], verbose: bool = False
) -> None:
    mode = result["verification_mode"]
    label = " / ".join(group)
    if result.get("systems"):
        label += f" ({', '.join(result['systems'])})"
    parts = _platform_summary_parts(result)
    print(f"{label}: {', '.join(parts)} [{mode}]")
    _print_release_assets(result["details"])
    _print_platform_notices(result, verbose)

    seen_details: set[str] = set()
    _print_detail_entries(result["details"], seen_details, verbose)
    _print_undeclared_section(result, verbose)
    _print_launcher_reads(result, verbose)
    _print_launcher_unproven(result, verbose)
    _print_platform_coverage(result, verbose)


def _emulator_summary_parts(result: dict) -> list[str]:
    total = result["total_files"]
    ok_count = result["severity_counts"][Severity.OK]
    sc = result.get("status_counts", {})
    untested = sc.get(Status.UNTESTED, 0)
    missing = sc.get(Status.MISSING, 0)
    # Counted by slot, as missing is: xash3d's thirteen unsourceable
    # pak0.pak and liblist.gam were three names and ten "missing".
    missing_slots: dict[str, bool] = {}
    for d in result["details"]:
        if d["status"] == Status.MISSING:
            slot = d.get("destination") or d["name"]
            missing_slots[slot] = missing_slots.get(slot, True) and "unsourceable" in d
    unsourceable = sum(missing_slots.values())
    parts = [f"{ok_count}/{total} OK"]
    if untested:
        parts.append(f"{untested} untested")
    if missing - unsourceable > 0:
        parts.append(f"{missing - unsourceable} missing")
    if unsourceable:
        parts.append(f"{unsourceable} unsourceable")
    return parts


def _print_emulator_ground_truth(gt: list[dict], verbose: bool) -> None:
    if gt:
        if verbose:
            for line in _format_ground_truth_verbose(gt):
                print(f"    {line}")
        else:
            print(f"    {_format_ground_truth_aggregate(gt)}")


def _print_emulator_problems(details: list[dict], seen: set[str], verbose: bool) -> None:
    """The UNTESTED, MISSING and UNSOURCEABLE lines of an emulator report."""
    for d in details:
        if d["status"] == Status.UNTESTED:
            if d["name"] in seen:
                continue
            seen.add(d["name"])
            req = "required" if d.get("required", True) else "optional"
            hle = ", HLE available" if d.get("hle_fallback") else ""
            reason = d.get("reason", "")
            print(f"  UNTESTED ({req}{hle}): {d['name']}: {reason}")
            _print_emulator_ground_truth(d.get("ground_truth", []), verbose)
    for d in details:
        if d["status"] == Status.MISSING and "unsourceable" not in d:
            if d["name"] in seen:
                continue
            seen.add(d["name"])
            req = "required" if d.get("required", True) else "optional"
            hle = ", HLE available" if d.get("hle_fallback") else ""
            others = d.get("alternatives")
            either = f" (or {', '.join(others)})" if others else ""
            print(f"  MISSING ({req}{hle}): {d['name']}{either}")
            _print_emulator_ground_truth(d.get("ground_truth", []), verbose)
    for d in details:
        if d["status"] == Status.MISSING and "unsourceable" in d:
            if d["name"] in seen:
                continue
            seen.add(d["name"])
            why = d.get("unsourceable") or "documented as unobtainable"
            print(f"  UNSOURCEABLE: {d['name']}: {why}")


def _print_emulator_ok(details: list[dict], seen: set[str]) -> None:
    for d in details:
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


def print_emulator_result(result: dict, verbose: bool = False) -> None:
    """Print verification result for emulator/system mode."""
    label = " + ".join(result["emulators"])
    mode = result["verification_mode"]
    parts = _emulator_summary_parts(result)
    print(f"{label}: {', '.join(parts)} [{mode}]")
    fetched = sorted({d["name"] for d in result["details"] if d.get("release_asset")})
    if fetched:
        shown = ", ".join(fetched[:10]) + (f" (+{len(fetched) - 10})" if len(fetched) > 10 else "")
        print(f"  Release assets fetched when the pack is built ({len(fetched)}): {shown}")

    seen: set[str] = set()
    _print_emulator_problems(result["details"], seen, verbose)

    for d in result["details"]:
        if d.get("note"):
            print(f"  {d['note']}")

    if verbose:
        _print_emulator_ok(result["details"], seen)

    for ref in result.get("data_dir_notices", []):
        print(
            f"  Note: data directory '{ref}' required but not included (use refresh_data_dirs.py)"
        )

    gt_cov = result.get("ground_truth_coverage")
    if gt_cov and gt_cov["total"] > 0:
        pct = round(gt_cov["with_validation"] * 100 / gt_cov["total"])
        print(
            f"  Ground truth: {gt_cov['with_validation']}/{gt_cov['total']} files have emulator validation ({pct}%)"
        )
        if gt_cov["platform_only"]:
            print(f"    {gt_cov['platform_only']} without declared validation")
