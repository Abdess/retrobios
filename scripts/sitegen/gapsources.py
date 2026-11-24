"""The gaps page's core complement: the files to source and those not collected yet."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from packs.crossref import gap_source_counts
from resolve.sendable import sendable
from sitegen import wanted as sitewanted
from sitegen.cards import PROVENANCE_LABELS
from sitegen.gapproblems import reason_cell, short_hash
from sitegen.parts import list_pages
from sitegen.render import code_span, count_text, escape_tags
from sitegen.sources import source_ref_markdown


def catalog_listings(report: dict | None, labels: dict[str, str]) -> dict[tuple[str, str], list[tuple[str, str]]]:
    """(profile, file name casefolded) -> (catalog or romset, the name it
    lists the file under), from a provenance report built with the
    profiles' needs: the "Listed in" column of the gaps page."""
    out: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for source, data in sorted((report or {}).items()):
        label = labels.get(source, source)
        for entry in data.get("missing", []):
            where = [(label, str(entry.get("name", "")))]
            where += [(str(hit["source"]), str(hit["archive"])) for hit in entry.get("romsets", [])]
            for need in entry.get("needed_by", []):
                held = out.setdefault((need["emulator"], str(need["name"]).casefold()), [])
                held += [w for w in where if w not in held]
    return out


def _catalogued_needs(report: dict | None) -> dict[tuple[str, str], list[str]]:
    """(profile, file name casefolded) -> where a dump catalog or an
    imported romset lists that file, from a provenance report built with
    the profiles' needs."""
    return {
        need: [f"{escape_tags(where)} `{escape_tags(name)}`" for where, name in listed]
        for need, listed in catalog_listings(report, PROVENANCE_LABELS).items()
    }


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


@dataclass
class _MissingFiles:
    """The files to find, one row each, and the entries they come from."""

    rows: list[dict] = dataclasses.field(default_factory=list)
    entries: int = 0
    bundled: set[tuple[str, str]] = dataclasses.field(default_factory=set)


def missing_files(emulator_gaps: list[tuple[str, dict]]) -> _MissingFiles:
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
                    "profile_path": g.get("profile_path", ""),
                    "emulators": [data["emulator"]],
                    "emu_keys": [emu_name],
                    "required": g["required"],
                    "source_ref": g["source_ref"],
                    "platforms": set(g.get("platforms") or ()),
                }
                found.rows.append(row)
            elif emu_name not in row["emu_keys"]:
                row["emulators"].append(data["emulator"])
                row["emu_keys"].append(emu_name)
                row["required"] = row["required"] or g["required"]
            row["platforms"].update(g.get("platforms") or ())
    return found


@dataclass(frozen=True)
class SourceListing:
    """Where the list of files to source goes. With ``moved``, the list goes
    to pages of its own, keyed by stem: on the page it made 662 KB of HTML.
    ``placer`` gives each file to source the folder its upload goes to, the
    one validate_pr asks for. Without it the link opens bios/."""

    moved: dict[str, str] | None = None
    placer: sitewanted.Placer | None = None


def source_row(m: dict, profiles: dict, placer: sitewanted.Placer | None) -> str:
    """The row of one file to source, with the platforms the gap report
    found needing it."""
    plats = sorted(m["platforms"])
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
    declared = sitewanted.gap_entries(owner, m, False)
    folder = placer.folder(declared[0]) if placer and declared else ""
    upload = sitewanted.upload_href(sitewanted.UPLOAD_ROOT, folder)
    return (
        f"| `{m['name']}` [Have it? Upload]({upload}) | {destination} | {expected} "
        f"| {emulators} | {req} | {plat_badges} | "
        f"{source_ref_markdown(owner, m['source_ref'])} |"
    )


def source_counted(missing: _MissingFiles) -> str:
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


def source_table(counted: str, rows: list[str], moved: dict[str, str] | None) -> list[str]:
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


def bundled_note(bundled_rows: set[tuple[str, str]]) -> list[str]:
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


def undeclared_gaps(report_all: dict) -> tuple[dict[str, int], int, list[tuple[str, dict]]]:
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
        for key, count in gap_source_counts(data).items():
            src_totals[key] += count
        emulator_gaps.append((emu_name, data))
    return src_totals, total_undeclared, emulator_gaps


def _complement_rows(emulator_gaps: list[tuple[str, dict]]) -> list[str]:
    """One row an emulator: its undeclared files by source."""
    rows = []
    for emu_name, data in sorted(emulator_gaps, key=lambda x: -x[1]["gaps"]):
        display = data["emulator"]
        sources = gap_source_counts(data)
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


def complement_intro(src_totals: dict[str, int], total_undeclared: int,
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


def not_collected_section(report_all: dict, profiles: dict, catalogued: dict | None,
                           moved: dict[str, str] | None = None) -> list[str]:
    """Section 4: files the collection does not hold yet (unsourceable)."""
    all_unsourceable: list[dict] = [
        {
            "name": u["name"],
            "emulator": data["emulator"],
            "emu_key": emu_name,
            "reason": u["reason"],
            "source_ref": u.get("source_ref", ""),
            # The wanted page's own rule, on the entries behind the row.
            "wanted": any(sendable(entry, str(u["reason"])) for entry in sitewanted.gap_entries(
                profiles.get(emu_name) or {}, u, True)),
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
        "with the same name is never served in their place. The [wanted "
        f"page](wanted.md) asks for the {sum(u['wanted'] for u in all_unsourceable)} "
        "marked wanted. No one can send the others: a name the code builds, a "
        "file no copy of which can be shared, game data, or a file the emulator "
        "installs itself. \"Listed in\" names a catalog or romset that lists a file.",
        "",
    ]
    rows = []
    for u in sorted(all_unsourceable, key=lambda x: x["name"]):
        where = listed.get((u["emu_key"], str(u["name"]).casefold()), [])
        rows.append(
            f"| `{u['name']}` | {u['emulator']} | {reason_cell(u['reason'])} "
            f"| {source_ref_markdown(profiles[u['emu_key']], u['source_ref'])} "
            f"| {', '.join(where) or '-'} | {'yes' if u['wanted'] else 'no'} |"
        )
    lines.extend(_moved_table(
        NOT_COLLECTED_STEM, "Files not collected yet",
        f"{count_text(len(rows), 'file')} the collection does not hold, each with the "
        "emulator that loads it, why it is not collected, the catalog or romset "
        "that lists it and whether the [wanted page](wanted.md) asks for it. Part of "
        "[What the packs do not hold](gaps.md#not-collected-yet).",
        ["| File | Emulator | Reason | Source ref | Listed in | Wanted |",
         "|------|----------|--------|-----------|-----------|--------|"],
        rows, "file", moved))
    return lines
