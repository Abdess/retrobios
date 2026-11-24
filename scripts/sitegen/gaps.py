"""The gap analysis page: what each platform misses, and why."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import TYPE_CHECKING

from core.hashing import declared_hash_lists
from core.text import series
from model.platforms import native_layer
from packs.crossref import whole_tree_gaps
from resolve.nativemode import check_label
from sitegen import markup, wanted as sitewanted
from sitegen.config import date_line
from sitegen.emulatorsindex import content_check_ceiling

if TYPE_CHECKING:
    from packs.supplemental import SupplementalIndex
from sitegen.gapproblems import render_problem_files
from sitegen.gapsources import (
    SourceListing,
    bundled_note,
    complement_intro,
    missing_files,
    not_collected_section,
    source_counted,
    source_row,
    source_table,
    undeclared_gaps,
)


@dataclass(frozen=True)
class PlatformRegistries:
    """The platform registry and the data directory registry of one run."""

    platforms: dict = dataclasses.field(default_factory=dict)
    data_dirs: dict = dataclasses.field(default_factory=dict)


def _declarations(cov: dict) -> dict[int, dict]:
    """Each verify detail of a platform, by id, with the declaration it
    scores (wanted.paired_declarations): AmberELEC declares
    hardwareconfig.xml under eighteen folders, and a match by name gave
    every missing one the first folder."""
    systems = (cov.get("config") or {}).get("systems") or {}
    by_system: dict[str, list[dict]] = {}
    for detail in cov.get("details", []):
        by_system.setdefault(detail.get("system", ""), []).append(detail)
    return {
        id(detail): entry
        for system, details in by_system.items()
        for detail, entry in sitewanted.paired_declarations(
            (systems.get(system) or {}).get("files") or [], details)
    }


def _platform_lists_sentence(
    total: int, verified: int, untested: int, missing: int,
    not_firmware: dict[str, int] | None = None,
) -> str:
    """The platforms' own lists in one sentence, every count said.

    Four tiles opened the page: "Verified (100%)" for 5,437 of 5,438 and
    "Missing 0", above a table of red cells, on the page about what is
    missing. The gaps are in the files the emulators load, and the sentence
    says so. The missing count then read as missing firmware, while every
    entry behind it was game data or a file no emulator opens: the split by
    category is said with it.
    """
    def _is(count: int) -> str:
        return "is" if count == 1 else "are"

    not_firmware = {k: v for k, v in (not_firmware or {}).items() if v}
    parts = [f"{verified:,} {_is(verified)} held and pass the platform's own check"]
    if untested:
        parts.append(f"{untested:,} {_is(untested)} held but not verified "
                     "(listed under Untested below)")
    parts.append(f"{missing:,} {_is(missing)} missing")
    listed = series(parts)
    split = ""
    if missing and not_firmware:
        labels = {"game_data": "game data",
                  "unread": "opened by none of the platform's emulators"}
        firmware = missing - sum(not_firmware.values())
        others = [
            f"{count:,} {'is' if count == 1 else 'are'} {labels.get(category, category)}"
            for category, count in sorted(not_firmware.items())
        ]
        others_text = series(others)
        head = (f"None of the missing is firmware: {others_text}" if not firmware
                else f"Of the missing, {firmware:,} {'is' if firmware == 1 else 'are'} "
                     f"firmware, {others_text}")
        split = f" {head}. Only missing firmware stops a console from starting."
    return (
        f"Of the {total:,} files on the platforms' own BIOS lists, {listed}.{split} "
        "The files the emulators load beyond those lists are counted per "
        "platform in the table below."
    )


def _ratio_cell(done: int, total: int, alarm: int = 0) -> str:
    """A held-over-needed cell: the numbers, a bar, and a badge only when
    required firmware is missing."""
    if not total:
        return "-"
    share = done / total * 100
    cell = (f'<span class="rb-bar" style="--v:{share:.1f}%" aria-hidden="true"><span></span></span>'
            f"{done:,}/{total:,}")
    if alarm:
        cell += f' <span class="rb-badge rb-badge-danger">{alarm:,} required missing</span>'
    return cell


@dataclass
class _VerifyTally:
    """Verify results aggregated across all platforms."""

    verified: int = 0
    untested: int = 0
    missing: int = 0
    files: int = 0
    not_firmware: dict[str, int] = dataclasses.field(default_factory=dict)
    problems: list[dict] = dataclasses.field(default_factory=list)
    settled: list[dict] = dataclasses.field(default_factory=list)


def _by_platform_name(coverages: dict) -> list[tuple[str, dict]]:
    """The coverages in the order of their display names."""
    return sorted(coverages.items(), key=lambda x: x[1]["platform"])


def _problem_record(pname: str, cov: dict, d: dict, entry: dict) -> dict:
    """A detail of a platform's verify result that is not ok, as the
    problem tables read it, with the declaration it scores: the place the
    list puts it, its name when the entry names no folder."""
    return {
        "platform": cov["platform"],
        "platform_key": pname,
        "name": d["name"],
        "status": d["status"],
        "required": d.get("required", True),
        "category": d.get("category", "bios"),
        "reason": d.get("reason", ""),
        "discrepancy": d.get("discrepancy", ""),
        "accepted": d.get("accepted") or {},
        "system": d.get("system", ""),
        # The untested table said "declared hash contradicted by the local
        # file" and named neither: the reader could not look for the dump
        # RetroDECK asks for, nor report the difference.
        "declared": declared_hash_lists(entry),
        "destination": str(entry.get("destination") or d.get("name", "")),
        "path": d.get("path") or "",
    }


def _verify_tally(coverages: dict) -> _VerifyTally:
    """Section 1: aggregate verify results across all platforms."""
    tally = _VerifyTally()
    for pname, cov in _by_platform_name(coverages):
        tally.verified += cov["verified"]
        tally.untested += cov["untested"]
        tally.missing += cov["missing"]
        tally.files += cov["total"]
        for category, count in (cov.get("missing_not_firmware") or {}).items():
            tally.not_firmware[category] = tally.not_firmware.get(category, 0) + count

        declarations = _declarations(cov)
        for d in cov["details"]:
            if d.get("settled_by") and d["status"] != "ok":
                # Its path holds another declaration's file: the headline,
                # counted by destination, rightly leaves it out, and listing
                # it under the same word made the page contradict itself.
                tally.settled.append({
                    "platform": cov["platform"], "name": d["name"],
                    "status": d["status"], "held_by": d["settled_by"],
                })
                continue
            if d["status"] != "ok" or d.get("discrepancy"):
                tally.problems.append(_problem_record(pname, cov, d, declarations.get(id(d), {})))
    return tally


def _pack_content_rows(coverages: dict) -> list[str]:
    """One row a platform: its list and its emulators' files, held over needed."""
    rows = []
    for pname, cov in _by_platform_name(coverages):
        display = cov["platform"]
        # A file held but not placed is needed and not in the pack, yet not
        # missing. One installed with its emulator is not needed from us.
        core_total = (
            cov["core_present"] + cov["core_missing"] + cov["core_unplaced"]
            + cov["core_unsourceable"]
        )
        rows.append(
            f"| [{display}](platforms/{pname}.md) "
            f"| {_ratio_cell(cov['present'], cov['total'], cov['required_missing'])} "
            f"| {_ratio_cell(cov['core_present'], core_total)} "
            f"| {check_label(cov['mode'], cov['config'].get('hash_rule'))} |"
        )
    return rows


def _corroboration_rows(coverages: dict) -> list[str]:
    """One row a platform: how much of its list the emulator code confirms."""
    rows = []
    for pname, cov in _by_platform_name(coverages):
        gt = cov["ground_truth"]
        if not gt.get("applicable", True):
            prof_cell = gt_cell = "-"
        elif gt["total"]:
            prof_pct = f"{gt.get('with_profile', 0) / gt['total'] * 100:.0f}%"
            prof_cell = f"{gt.get('with_profile', 0):,} ({prof_pct})"
            gt_pct = f"{gt['with_validation'] / gt['total'] * 100:.0f}%"
            gt_cell = f"{gt['with_validation']:,} ({gt_pct})"
        else:
            prof_cell = gt_cell = "0"
        rows.append(
            f"| [{cov['platform']}](platforms/{pname}.md) "
            f"| {gt['total']:,} | {prof_cell} | {gt_cell} |"
        )
    return rows


def _divergence_rows(
    coverages: dict, registries: PlatformRegistries, profiles: dict, db: dict,
) -> list[str]:
    """Section 1b: platform lists vs emulator source, one row a platform."""
    from resolve.platformdiff import diff_platform_truth
    from resolve.truth import generate_platform_truth

    div_rows = []
    for pname, cov in _by_platform_name(coverages):
        truth_data = generate_platform_truth(
            pname, cov["config"], registries.platforms.get(pname, {}), profiles, db,
            data_registry=registries.data_dirs,
        )
        s = diff_platform_truth(truth_data, native_layer(cov["config"]))["summary"]
        if s["systems_compared"] == 0:
            div_rows.append(
                f"| [{cov['platform']}](platforms/{pname}.md) | - | - | - | - |"
            )
        else:
            div_rows.append(
                f"| [{cov['platform']}](platforms/{pname}.md) "
                f"| {s['total_missing']} "
                f"| {s['total_extra_phantom'] + s['total_extra_unprofiled']} "
                f"| {s['total_hash_mismatch']} "
                f"| {s['total_required_mismatch']} |"
            )
    return div_rows


_PACK_CONTENTS_NOTE = (
    "Each fraction is what the pack has over what is needed, counting "
    "required and optional files alike since both ship. The first column "
    "is the BIOS list the platform publishes, counted by destination: a "
    "path the list declares twice is one file to place. A red badge marks "
    "a list that is short of required firmware. The second counts files its "
    "emulators load that this list never mentions, found by reading their "
    "source code, and it is often several times larger. What is short "
    "is named in the sections below. That second "
    "number is a floor, not a ceiling: an emulator that accepts any file "
    "handed to it names none in its code, so nothing there can be counted. "
    "Checked by is the test the platform runs on its own, replicated here "
    "from its source code "
    "([how each one works](wiki/verification-modes.md))."
)

_CORROBORATION_NOTE = (
    "Both columns count the files on the platform's own BIOS list, the "
    "same number as the first column of the table above. Documented in a "
    "profile means an emulator profile, written from source, describes the "
    "file. Content the code checks is stricter: the emulator verifies a "
    "size or hash for it, and this tool repeats that check. The gap "
    "between the two is "
    "not a defect, it is what the emulator code does: many emulators load "
    "a file without ever checking its content, and no amount of profiling "
    "can invent a check the code does not perform. A dash means no "
    "profiled emulator applies to the platform, whose own source is then "
    "the only authority."
)


def _divergence_section(div_rows: list[str]) -> list[str]:
    """The platform lists vs emulator source table, with its legend."""
    return [
        "## Platform lists vs emulator source",
        "",
        "Platform file lists are scraped as-is from each upstream project. "
        "Emulator profiles are read from source code. The two do not always "
        "agree, and this table counts the differences. Packs follow the "
        "platform contract, and these numbers show where that contract diverges "
        "from what the code loads.",
        "",
        "| Platform | Missing from list | Not read by profiles | Hash conflict | Required status |",
        "|----------|------------------:|--------:|--------------:|----------------:|",
        *div_rows,
        "",
        "- **Missing from list**: a profiled emulator loads the file, the platform list does not mention it",
        "- **Not read by profiles**: on the platform list, loaded by no emulator profiled so far (a profile may still be incomplete)",
        "- **Hash conflict**: the platform list and the emulator source expect different hashes",
        "- **Required status**: required/optional differs between list and code",
        "",
        "A dash means no profiled emulator overlaps the platform's systems, "
        "so there is nothing to compare: the platform's own source is the "
        "only authority for its files.",
        "",
        "The same comparison feeds the [updated platform files](exports.md): "
        "each platform's own file, patched with these differences and kept "
        "in its native format (System.dat, es_bios.xml, batocera-systems, ...).",
        "",
    ]


def generate_gap_analysis(
    profiles: dict,
    coverages: dict,
    db: dict,
    data_names: SupplementalIndex | None = None,
    registries: PlatformRegistries | None = None,
    gap_report: dict | None = None,
    listing: SourceListing | None = None,
    catalogued: dict | None = None,
) -> str:
    """Generate a unified gap analysis page.

    ``listing`` says where the files to source go (SourceListing).
    ``registries`` are the run's platform and data directory registries.

    ``catalogued`` is a provenance report built with the profiles' needs:
    a file the collection does not hold yet names the catalog or romset
    that lists it.

    Combines verification results (from packs/coverage.py) with source
    provenance (from cross_reference) into a single truth dashboard.

    Sections:
    1. Verification status, aggregated across all platforms
    2. Problem files: missing, untested, hash mismatch
    3. Core complement: emulator files not declared by any platform
    """
    listing = listing or SourceListing()
    tally = _verify_tally(coverages)

    lines = [
        "# What the packs do not hold",
        "",
        "What each pack still cannot give, and why. Most gaps are not "
        "firmware: a platform's list can also name game files, such as "
        "Diablo's `diabdat.mpq`, which comes from an owned copy of the game, or files "
        "no emulator of that platform opens. Those are counted apart. A missing "
        "firmware file means a console that does not start, and each one is "
        "named below with the platforms that list it.",
        "",
        "Each file here is a request: for a file under \"Files to source\", "
        "[adding it](contributing.md) fills the gap for "
        "every platform at once. Have some of these? [Drop them on the wanted "
        "page](wanted.md): it says which ones are wanted and where each goes.",
        "",
        " ".join([
            markup.button("Download gaps CSV", "downloads/gaps.csv"),
            markup.button("Open gaps API", "api/v1/gaps.json"),
            markup.button("All data exports", "data.md"),
        ]),
        "",
        _platform_lists_sentence(
            tally.files, tally.verified, tally.untested, tally.missing,
            tally.not_firmware,
        ),
        "",
    ]

    # ---- Verification per platform ----

    lines.extend([
        "## What each pack contains",
        "",
        "| Platform | On its BIOS list (destinations) | Files its emulators load | Checked by |",
        "|----------|-----------------:|-------------------------:|------------|",
        *_pack_content_rows(coverages),
        "",
        _PACK_CONTENTS_NOTE,
        "",
        "## How much of each list the emulator code confirms { #corroboration-against-emulator-source }",
        "",
        "| Platform | On its BIOS list | Documented in a profile | Content the code checks |",
        "|----------|-----------------:|------------------------:|------------------------:|",
        *_corroboration_rows(coverages),
        "",
        _CORROBORATION_NOTE,
        "",
        content_check_ceiling(profiles),
        "",
    ])

    lines.extend(_divergence_section(_divergence_rows(
        coverages, registries or PlatformRegistries(), profiles, db,
    )))

    lines.extend(render_problem_files(tally.problems, tally.settled, db, tally.missing))

    # ---- Section 3: Core complement (cross-reference provenance) ----

    if gap_report is None:
        gap_report = whole_tree_gaps(
            [cov["config"] for cov in coverages.values()], db, profiles, data_names)
    report_all = gap_report
    src_totals, total_undeclared, emulator_gaps = undeclared_gaps(report_all)

    if total_undeclared > 0:
        lines.extend(complement_intro(src_totals, total_undeclared, emulator_gaps,
                                       listing.moved))
        # List truly missing files with platform impact
        missing = missing_files(emulator_gaps)
        if missing.rows:
            counted = source_counted(missing)
            rows = [
                source_row(m, profiles, listing.placer)
                for m in sorted(missing.rows, key=lambda x: (not x["required"], x["name"]))
            ]
            lines.extend(["### Files to source", "", counted,
                          "[The wanted page](wanted.md) lists them, each with its upload button.", ""])
            lines.extend(source_table(counted, rows, listing.moved))
        lines.extend(bundled_note(missing.bundled))

    lines.extend(not_collected_section(report_all, profiles, catalogued, listing.moved))

    lines.extend(["", date_line()])
    return "\n".join(lines) + "\n"
