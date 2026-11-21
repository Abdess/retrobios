"""The gap analysis page: what each platform misses, and why."""

from __future__ import annotations

import dataclasses
import html
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from core.hashing import declared_hash_lists
from core.text import series
from model.database import sha1_at
from model.platforms import native_layer
from model.profiles import is_emulator
from resolve.cores import resolve_platform_cores
from resolve.nativemode import check_label
from sitegen import markup, wanted as sitewanted
from sitegen.cards import PROVENANCE_LABELS, fetch_url
from sitegen.config import date_line
from sitegen.crossref import gap_sources
from sitegen.dataexports import build_emulator_gap_report
from sitegen.emulatorsindex import content_check_ceiling
from sitegen.parts import list_pages
from sitegen.render import code_span, count_text, escape_tags
from sitegen.sources import source_ref_markdown

if TYPE_CHECKING:
    from packs.crossref import SupplementalIndex


# Contributing page


_ACCEPTED_RE = re.compile(r"\b(sha1|sha256|md5|crc32) mismatch: got \S+, accepted \[([^\]]*)\]")


def _held_accepted(discrepancy: str, db: dict | None) -> str:
    """Where the collection keeps a dump the emulator accepts, if it does.

    The table printed the hash the emulator wants and stopped there, while
    the collection held that exact dump for every one of the ten rows.
    """
    match = _ACCEPTED_RE.search(discrepancy or "")
    if not match or not db:
        return ""
    algo, accepted = match.group(1), match.group(2)
    indexes = db.get("indexes", {})
    for value in re.split(r"[\s,]+", accepted.lower()):
        if algo == "sha1":
            sha1 = value if value in db.get("files", {}) else None
        else:
            sha1 = indexes.get(f"by_{algo}", {}).get(value)
        path = db.get("files", {}).get(sha1 or "", {}).get("path")
        if path:
            return path
    return ""


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


def short_hash(value: str) -> str:
    """A hash in a table cell: its first 12 characters, the whole value in
    the title. Full MD5 and SHA1 values pushed the gaps tables past the
    column on every screen."""
    value = str(value)
    if len(value) <= 12:
        return code_span(value)
    return f'<code title="{html.escape(value)}">{html.escape(value[:12])}</code>'


def _hash_cell(hashes: dict[str, list[str]]) -> str:
    return "<br>".join(
        f"{algo} " + ", ".join(short_hash(v) for v in values) for algo, values in hashes.items()
    )


def _catalogued_needs(report: dict | None) -> dict[tuple[str, str], list[str]]:
    """(profile, file name casefolded) -> where a dump catalog or an
    imported romset lists that file, from a provenance report built with
    the profiles' needs."""
    return {
        need: [f"{escape_tags(where)} `{escape_tags(name)}`" for where, name in listed]
        for need, listed in sitewanted.catalog_listings(report, PROVENANCE_LABELS).items()
    }


def _reason_cell(text: str) -> str:
    """A reason in a gaps table, in the class that keeps its column readable."""
    return f'<span class="rb-reason">{text}</span>' if text else "-"


def _copy_cell(path: str, algos: list[str], db: dict | None) -> str:
    """The file a path holds, with its hashes in the algorithms declared."""
    if not path:
        return "-"
    sha1 = sha1_at(db or {}, path)
    record: dict = (db or {})["files"][sha1] | {"sha1": sha1} if sha1 else {}
    hashes = {algo: [str(record[algo]).lower()] for algo in algos if record.get(algo)}
    shown = f"[{code_span(path)}]({fetch_url(path)})"
    return f"{shown}<br>{_hash_cell(hashes)}" if hashes else shown


def _render_problem_files(
    platform_problems: list, settled: list | None = None, db: dict | None = None,
    missing_total: int | None = None,
) -> list[str]:
    """Files a platform declares that its own check then rejects.

    Split out of generate_gap_analysis, which reached complexity 56. This
    section is the one that stands alone: it reads platform_problems and
    nothing else, where the sections around it share gap_report and the
    resolved core list.
    """
    lines: list[str] = []
    # ---- Section 2: Problem files ----

    missing_files: dict[str, dict] = {}
    untested_files: dict[str, dict] = {}
    mismatch_files: dict[str, dict] = {}

    for p in platform_problems:
        fname = p["name"]
        if p["status"] == "missing":
            entry = missing_files.setdefault(fname, {
                "name": fname, "required": p["required"],
                "platforms": [], "reason": p["reason"], "categories": set(),
                "where": {},
            })
            entry["platforms"].append(p["platform"])
            # The platform's entry for the file, and the folder it expects.
            entry["where"].setdefault(
                (p["platform"], p.get("platform_key", ""), p.get("system", "")), set(),
            ).add(p.get("destination") or fname)
            entry["categories"].add(p.get("category", "bios"))
            if p["required"]:
                entry["required"] = True
        elif p["status"] == "untested":
            # Keyed by what is declared and what is held: two platforms
            # asking two dumps under one name are two rows.
            declared = p.get("declared") or {}
            key = f"{fname}\0{sorted(declared.items())}\0{p.get('path', '')}"
            entry = untested_files.setdefault(key, {
                "name": fname, "required": p["required"],
                "platforms": [], "reason": p["reason"],
                "declared": declared, "path": p.get("path", ""),
            })
            entry["platforms"].append(p["platform"])
        if p.get("discrepancy"):
            entry = mismatch_files.setdefault(fname, {
                "name": fname, "platforms": [],
                "discrepancy": p["discrepancy"],
            })
            entry["platforms"].append(p["platform"])

    total_problems = len(missing_files) + len(untested_files) + len(mismatch_files)
    # One row per name: the page opened on "48 are missing", counted by
    # destination, above a heading that said "10 files". Both are said.
    names = count_text(len(missing_files), "name")
    missing_said = (f"{missing_total:,} missing under {names}"
                    if missing_total is not None else f"{len(missing_files)} missing")

    if total_problems > 0:
        lines.extend([
            "## Problem files",
            "",
            f"{missing_said}, {len(untested_files)} untested, "
            f"{len(mismatch_files)} discrepancy.",
            "",
        ])

        if missing_files:
            lines.extend([
                f'### Missing <span class="rb-badge rb-badge-danger">'
                f"{count_text(len(missing_files), 'name')}</span>",
                "",
                "Required is the platform's own flag. Category says what the "
                "platform's emulators do with the file: `bios` is firmware they "
                "load, `game_data` comes from a copy of the game, `unread` is "
                "opened by none of them. Only a missing `bios` entry stops a "
                "console from starting. A name a list declares in several "
                "folders is one row. Each platform links to its entry, which "
                "names the cores examined, and is followed by where its list "
                "puts the file.",
                "",
                "| File | Category | Required | Platforms |",
                "|------|----------|----------|-----------|",
            ])
            for fname in sorted(missing_files):
                f = missing_files[fname]
                req = "yes" if f["required"] else "no"
                plats = "; ".join(
                    (f"[{display}](platforms/{key}.md#{system.replace(' ', '-')})"
                     if key and system else display)
                    + " " + ", ".join(code_span(dest) for dest in sorted(dests))
                    for (display, key, system), dests in sorted(f["where"].items())
                )
                cats = f["categories"]
                category = "bios" if "bios" in cats else ", ".join(sorted(cats))
                lines.append(f"| `{fname}` | {category} | {req} | {plats} |")
            lines.append("")

        if untested_files:
            lines.extend([
                f'### Untested <span class="rb-badge rb-badge-warning">'
                f"{count_text(len(untested_files), 'file')}</span>",
                "",
                "Present, but not the expected hash. Declared is what the platform "
                "asks for, the collection copy is what the path holds.",
                "",
                "| File | Platforms | Reason | Declared | Collection copy |",
                "|------|----------|--------|----------|-----------------|",
            ])
            for key in sorted(untested_files):
                f = untested_files[key]
                plats = ", ".join(sorted(set(f["platforms"])))
                declared = f["declared"]
                lines.append(
                    f"| {code_span(f['name'])} | {plats} | {_reason_cell(f['reason'])} "
                    f"| {_hash_cell(declared) or '-'} "
                    f"| {_copy_cell(f['path'], list(declared) or ['md5'], db)} |"
                )
            lines.append("")

        if mismatch_files:
            lines.extend([
                f'### Discrepancy <span class="rb-badge rb-badge-warning">'
                f"{count_text(len(mismatch_files), 'file')}</span>",
                "",
                "The platform's own check passes, but the emulator's size or "
                "hash check fails. Each row names the check that fails.",
                "",
                "| File | Platforms | Discrepancy | Accepted dump in the collection |",
                "|------|----------|-------------|-------------------|",
            ])
            for fname in sorted(mismatch_files):
                f = mismatch_files[fname]
                plats = ", ".join(sorted(set(f["platforms"])))
                held = _held_accepted(f["discrepancy"], db)
                cell = f"[{code_span(held)}]({fetch_url(held)})" if held else "-"
                lines.append(f"| `{fname}` | {plats} | {_reason_cell(f['discrepancy'])} | {cell} |")
            lines.append("")

    if settled:
        lines.extend([
            "### Other revisions of a held destination",
            "",
            "A platform can declare one path twice with different hashes. The "
            "path holds the file one declaration accepts, so it is counted once, "
            "as held. The other declaration cannot be met at the same time.",
            "",
            "| File | Platform | Status | Path held for system |",
            "|------|----------|--------|--------------|",
        ])
        lines.extend(
            f"| {code_span(p['name'])} | {escape_tags(p['platform'])} | {p['status']} "
            f"| {code_span(p['held_by'])} |"
            for p in sorted(settled, key=lambda row: (row["name"], row["platform"]))
        )
        lines.append("")

    return lines


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


# GitHub's upload page for a folder of bios/: a browser upload by someone
# without write access lands on a fork and opens a pull request.
UPLOAD_URL = f"{sitewanted.UPLOAD_ROOT}bios"
# Rows of Files to source on one page: 601 on one page made a phone page
# 274,509 px long.
FILES_TO_SOURCE_PART = 100
# The two other long tables, each on a page of its own. Emulator cards link
# the second.
PER_EMULATOR_STEM = "gaps-per-emulator"
NOT_COLLECTED_STEM = "gaps-not-collected"


def reading_platforms(emu_name: str, profile: dict, name: str,
                      configs: dict[str, dict]) -> set[str]:
    """Of the platforms running an emulator (name -> config), those whose
    build of it reads the entry: BlastEm's cdbios.bin is read by the
    standalone build only, and RetroBat hands that build other names."""
    from resolve.standalone import platform_layouts, standalone_set
    from resolve.validation import filter_files_by_mode, unread_on

    return {
        platform for platform, config in configs.items()
        if any(f.get("name") == name and not unread_on(f, platform)
               for view, standalone in platform_layouts(emu_name, profile, standalone_set(config))
               for f in filter_files_by_mode(view.get("files") or [], standalone))
    }


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


def _divergence_rows(coverages: dict, registry: dict | None, profiles: dict, db: dict) -> list[str]:
    """Section 1b: platform lists vs emulator source, one row a platform."""
    from resolve.truth import diff_platform_truth, generate_platform_truth

    div_rows = []
    for pname, cov in _by_platform_name(coverages):
        truth_data = generate_platform_truth(
            pname, cov["config"], (registry or {}).get(pname, {}), profiles, db
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


def _emulator_platforms(profiles: dict, coverages: dict) -> dict[str, set[str]]:
    """Each emulator with the platforms that run it."""
    emu_to_platforms: dict[str, set[str]] = {}
    unique_profiles = {
        k: v
        for k, v in profiles.items()
        if is_emulator(v)
    }
    for pname in coverages:
        config = coverages[pname]["config"]
        matched = resolve_platform_cores(config, unique_profiles)
        for emu_name in matched:
            emu_to_platforms.setdefault(emu_name, set()).add(pname)
    return emu_to_platforms


@dataclass
class _MissingFiles:
    """The files to find, one row each, and the entries they come from."""

    rows: list[dict] = dataclasses.field(default_factory=list)
    entries: int = 0
    bundled: set[tuple[str, str]] = dataclasses.field(default_factory=set)


def _missing_files(emulator_gaps: list[tuple[str, dict]]) -> _MissingFiles:
    """One row per file to find: a name two emulators share is one file
    only when both declare the same hash. Keyed by name alone, Fallout
    2's master.dat vanished behind Fallout 1's, and the three Sonic
    decompilations' Data.rsdk showed as one."""
    found = _MissingFiles()
    by_identity: dict[tuple[str, str], dict] = {}
    for emu_name, data in emulator_gaps:
        for g in data["gap_details"]:
            if g["source"] != "missing":
                continue
            if g.get("bundled"):
                # It arrives with the emulator's own package, which is
                # why the collection documents it and does not hold it:
                # asking readers to source it sent them after a file
                # every install already has.
                found.bundled.add((data["emulator"], g["name"]))
                continue
            found.entries += 1
            key = (g["name"], g.get("identity") or f"emulator:{emu_name}")
            row = by_identity.get(key)
            if row is None:
                row = by_identity[key] = {
                    "name": g["name"],
                    "path": g.get("path") or g["name"],
                    "identity": g.get("identity", ""),
                    "emulators": [data["emulator"]],
                    "emu_keys": [emu_name],
                    "required": g["required"],
                    "source_ref": g["source_ref"],
                }
                found.rows.append(row)
            elif emu_name not in row["emu_keys"]:
                row["emulators"].append(data["emulator"])
                row["emu_keys"].append(emu_name)
                row["required"] = row["required"] or g["required"]
    return found


@dataclass(frozen=True)
class SourceListing:
    """Where the list of files to source goes. With ``moved``, the list goes
    to pages of its own, keyed by stem: on the page it made 662 KB of HTML.
    ``placer`` gives each file to source the folder its upload goes to, the
    one validate_pr asks for. Without it the link opens bios/."""

    moved: dict[str, str] | None = None
    placer: sitewanted.Placer | None = None


def _source_row(m: dict, profiles: dict, coverages: dict,
                emu_to_platforms: dict[str, set[str]], placer: sitewanted.Placer | None) -> str:
    """The row of one file to source."""
    plats = sorted(set().union(
        *(reading_platforms(key, profiles[key], m["name"], {
            p: coverages[p]["config"] for p in emu_to_platforms.get(key, set())
        }) for key in m["emu_keys"])
    ))
    plat_badges = (
        " ".join(
            f'<span class="rb-badge rb-badge-info">{p}</span>'
            for p in plats
        )
        if plats
        else "-"
    )
    req = "yes" if m["required"] else "no"
    algorithm, _, value = m["identity"].partition(":")
    expected = f"{algorithm} {short_hash(value)}" if value else "-"
    destination = code_span(m["path"]) if m["path"] != m["name"] else "-"
    emulators = ", ".join(
        f"[{escape_tags(display)}](emulators/{key}.md)"
        for display, key in zip(m["emulators"], m["emu_keys"])
    )
    owner = profiles[m["emu_keys"][0]]
    declared = sitewanted.gap_entries(owner, m["name"], m["identity"], False)
    folder = placer.folder(declared[0]) if placer and declared else ""
    upload = sitewanted.upload_href(sitewanted.UPLOAD_ROOT, folder)
    return (
        f"| `{m['name']}` [Have it? Upload]({upload}) | {destination} | {expected} "
        f"| {emulators} | {req} | {plat_badges} | "
        f"{source_ref_markdown(owner, m['source_ref'])} |"
    )


def _source_counted(missing: _MissingFiles) -> str:
    """How many files there are to source, and the entries they come from."""
    req_src = [m for m in missing.rows if m["required"]]
    return (
        f"{count_text(len(missing.rows), 'file')}, {len(req_src)} required."
        + (
            f" They come from {count_text(missing.entries, 'entry', 'entries')}: a file "
            "declared with the same hash at several places is listed once."
            if missing.entries != len(missing.rows) else ""
        )
    )


def _source_table(counted: str, rows: list[str], moved: dict[str, str] | None) -> list[str]:
    """The table of files to source, on the page or on pages of its own."""
    head = [
        "| File | Destination | Expected | Emulator | Required | Affects platforms | Source ref |",
        "|------|-------------|----------|----------|----------|------------------|-----------|",
    ]
    if moved is None:
        return [*head, *rows, ""]
    where = list_pages(
        "gaps-files-to-source", "Files to source",
        f"{counted} Each is a file an emulator loads that no platform lists and "
        "the collection does not hold. Part of "
        "[What the packs do not hold](gaps.md#files-to-source).",
        head, [rows[i:i + FILES_TO_SOURCE_PART] for i in range(
            0, len(rows), FILES_TO_SOURCE_PART)], moved, budget=1,
        parent=("What the packs do not hold", "/gaps/"),
    )
    return [f"Listed on {where}.", ""]


def _bundled_note(bundled_rows: set[tuple[str, str]]) -> list[str]:
    """The files that arrive with their emulator, counted, not listed."""
    if not bundled_rows:
        return []
    emulators = sorted({emulator for emulator, _name in bundled_rows})
    return [
        f"{len(bundled_rows)} further files arrive with their emulator's own "
        f"package ({escape_tags(', '.join(emulators))}): documented in the profile, not "
        "collected, and not listed here.",
        "",
    ]


def _undeclared_gaps(report_all: dict) -> tuple[dict[str, int], int, list[tuple[str, dict]]]:
    """The files emulators load that no platform lists: counts by source,
    the total, and the emulators that have any."""
    src_totals: dict[str, int] = {
        "bios": 0, "data": 0, "large_file": 0, "bundled": 0, "missing": 0,
    }
    total_undeclared = 0
    emulator_gaps = []
    for emu_name, data in sorted(report_all.items()):
        if data["gaps"] == 0:
            continue
        total_undeclared += data["gaps"]
        for key, count in gap_sources(data).items():
            src_totals[key] += count
        emulator_gaps.append((emu_name, data))
    return src_totals, total_undeclared, emulator_gaps


def _complement_rows(emulator_gaps: list[tuple[str, dict]]) -> list[str]:
    """One row an emulator: its undeclared files by source."""
    rows = []
    for emu_name, data in sorted(emulator_gaps, key=lambda x: -x[1]["gaps"]):
        display = data["emulator"]
        sources = gap_sources(data)
        to_source = sources["missing"]
        missing_str = (
            f'<span class="rb-badge rb-badge-danger">{to_source}</span>'
            if to_source > 0
            else '<span class="rb-badge rb-badge-success">0</span>'
        )
        rows.append(
            f"| [{display}](emulators/{emu_name}.md) "
            f"| {data['gaps']} "
            f"| {sources['bios']} "
            f"| {sources['data']} "
            f"| {sources['large_file']} "
            f"| {sources['bundled']} "
            f"| {missing_str} |"
        )
    return rows


def _moved_table(stem: str, title: str, intro: str, head: list[str], rows: list[str], noun: str,
                 moved: dict[str, str] | None) -> list[str]:
    """A table on the gaps page, or on a page of its own with a line here.
    Two tables of 340 and 283 rows held most of the gaps page's 8,300
    elements: their first layout was a 200 ms task on a phone."""
    if moved is None:
        return [*head, *rows, ""]
    where = list_pages(stem, title, intro, head, [rows], moved, budget=1,
                       parent=("What the packs do not hold", "/gaps/"))
    return [f"{count_text(len(rows), noun)}, listed on {where}.", ""]


def _complement_intro(src_totals: dict[str, int], total_undeclared: int,
                      emulator_gaps: list[tuple[str, dict]],
                      moved: dict[str, str] | None = None) -> list[str]:
    """Section 3 up to its per-emulator table: what the emulators load
    that no platform lists, and where those files come from."""
    total_available = (
        src_totals["bios"] + src_totals["data"] + src_totals["large_file"]
    )
    pct_available = (
        f"{total_available / total_undeclared * 100:.0f}%"
        if total_undeclared
        else "0%"
    )
    return [
        "## Files emulators load that no platform lists { #core-complement }",
        "",
        f"Files loaded by emulators but not declared by any platform. "
        f"{total_undeclared:,} files across {count_text(len(emulator_gaps), 'emulator')}, "
        f"{total_available:,} available ({pct_available}), "
        f"{src_totals['bundled']:,} installed with their emulator, "
        f"{src_totals['missing']:,} to source.",
        "",
        "This counts every profiled emulator, including those no platform "
        "ships yet, so it reaches past what the first table above counts: "
        "it covers only the emulators each platform actually ships. "
        "Whatever is not in the collection is an acquisition target, named "
        "per emulator below.",
        "",
        "### Where the files come from",
        "",
        "| Source | Count | Description |",
        "|--------|------:|-------------|",
        f"| bios/ | {src_totals['bios']} | In repository (database.json) |",
        f"| data/ | {src_totals['data']} | Data directories (buildbot, GitHub) |",
        f"| release | {src_totals['large_file']} "
        "| GitHub release assets (large files) |",
        f"| bundled | {src_totals['bundled']} "
        "| Installed with the emulator's own package, not collected |",
        f"| missing | {src_totals['missing']} | Not available, needs sourcing |",
        "",
        "### Per emulator",
        "",
        *_moved_table(
            PER_EMULATOR_STEM, "Files emulators load, per emulator",
            f"For each of {count_text(len(emulator_gaps), 'emulator')}, the files it loads "
            "that no platform lists, counted by where they come from. Part of "
            "[What the packs do not hold](gaps.md#per-emulator).",
            ["| Emulator | Undeclared | bios | data | release | Bundled | Missing |",
             "|----------|----------:|-----:|-----:|--------:|--------:|--------:|"],
            _complement_rows(emulator_gaps), "emulator", moved),
    ]


def _not_collected_section(report_all: dict, profiles: dict, catalogued: dict | None,
                           moved: dict[str, str] | None = None) -> list[str]:
    """Section 4: files the collection does not hold yet (unsourceable)."""
    all_unsourceable: list[dict] = [
        {
            "name": u["name"],
            "emulator": data["emulator"],
            "emu_key": emu_name,
            "reason": u["reason"],
            "source_ref": u.get("source_ref", ""),
        }
        for emu_name, data in sorted(report_all.items())
        for u in data.get("unsourceable", [])
    ]
    if not all_unsourceable:
        return []
    listed = _catalogued_needs(catalogued)
    # The old heading's address still leads here.
    lines = [
        '<span id="acknowledged-gaps"></span>',
        "",
        "## Not collected yet",
        "",
        f"{len(all_unsourceable)} files the collection does not hold. A file "
        "with the same name is never served in their place. Each is still "
        "wanted, and the last column names a catalog or romset that lists it.",
        "",
    ]
    rows = []
    for u in sorted(all_unsourceable, key=lambda x: x["name"]):
        where = listed.get((u["emu_key"], str(u["name"]).casefold()), [])
        rows.append(
            f"| `{u['name']}` | {u['emulator']} | {_reason_cell(u['reason'])} "
            f"| {source_ref_markdown(profiles[u['emu_key']], u['source_ref'])} "
            f"| {', '.join(where) or '-'} |"
        )
    lines.extend(_moved_table(
        NOT_COLLECTED_STEM, "Files not collected yet",
        f"{count_text(len(rows), 'file')} the collection does not hold, each with the "
        "emulator that loads it, why it is not collected and the catalog or romset "
        "that lists it. Part of [What the packs do not hold](gaps.md#not-collected-yet).",
        ["| File | Emulator | Reason | Source ref | Listed in |",
         "|------|----------|--------|-----------|-----------|"],
        rows, "file", moved))
    return lines


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
    registry: dict | None = None,
    gap_report: dict | None = None,
    listing: SourceListing | None = None,
    catalogued: dict | None = None,
) -> str:
    """Generate a unified gap analysis page.

    ``listing`` says where the files to source go (SourceListing).

    ``catalogued`` is a provenance report built with the profiles' needs:
    a file the collection does not hold yet names the catalog or romset
    that lists it.

    Combines verification results (from coverages/verify.py) with source
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

    lines.extend(_divergence_section(_divergence_rows(coverages, registry, profiles, db)))

    lines.extend(_render_problem_files(tally.problems, tally.settled, db, tally.missing))

    # ---- Section 3: Core complement (cross-reference provenance) ----

    if gap_report is None:
        gap_report = build_emulator_gap_report(profiles, coverages, db, data_names)
    report_all = gap_report
    src_totals, total_undeclared, emulator_gaps = _undeclared_gaps(report_all)

    if total_undeclared > 0:
        lines.extend(_complement_intro(src_totals, total_undeclared, emulator_gaps,
                                       listing.moved))
        # List truly missing files with platform impact
        emu_to_platforms = _emulator_platforms(profiles, coverages)
        missing = _missing_files(emulator_gaps)
        if missing.rows:
            counted = _source_counted(missing)
            rows = [
                _source_row(m, profiles, coverages, emu_to_platforms, listing.placer)
                for m in sorted(missing.rows, key=lambda x: (not x["required"], x["name"]))
            ]
            lines.extend(["### Files to source", "", counted,
                          "[The wanted page](wanted.md) lists them, each with its upload button.", ""])
            lines.extend(_source_table(counted, rows, listing.moved))
        lines.extend(_bundled_note(missing.bundled))

    lines.extend(_not_collected_section(report_all, profiles, catalogued, listing.moved))

    lines.extend(["", date_line()])
    return "\n".join(lines) + "\n"
