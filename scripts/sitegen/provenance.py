"""The provenance page, and the wanted lists it leads to."""

from __future__ import annotations

import html
import json
from datetime import datetime

from model.composition import compute_composition, count_catalog_matched
from provenance_report import distinct_missing
from sitegen import entries as siteentries, markup
from sitegen.cards import _PROVENANCE_LABELS, _ROMSET_SOURCES
from sitegen.config import _date_line
from sitegen.parts import _list_pages
from sitegen.render import _count, _escape_tags, _slugify_anchor


_PROVENANCE_HOMES = {
    "redump": "http://redump.org/",
    "no-intro": "https://no-intro.org/",
    "tosec": "https://www.tosecdev.org/",
}


def _prov_title(data: dict) -> str:
    """Tooltip text for a provenance badge."""
    parts = [data.get("dat", ""), data.get("description", "")]
    return ": ".join(p for p in parts if p).replace('"', "&quot;")


def load_derivable(path: str = "derivable.json") -> dict[str, dict]:
    """Missing sha1 -> how the collection produces it, as the pipeline found.

    Empty when the pipeline has not recorded it: the page then lists every
    missing dump, as it did before the record existed.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return {}


def _date_in_words(stamp: str) -> str:
    """`2026-08-07T...` as `<time datetime="2026-08-07">7 August 2026</time>`."""
    try:
        day = datetime.strptime(str(stamp)[:10], "%Y-%m-%d")
    except ValueError:
        return _escape_tags(str(stamp))
    return f'<time datetime="{day:%Y-%m-%d}">{day.day} {day:%B %Y}</time>'


def generate_provenance_page(
    db: dict, report: dict, derivable: dict[str, dict] | None = None,
    moved: dict[str, str] | None = None,
) -> str:
    """Page explaining the verified dump badges and listing catalog gaps.

    With ``moved``, each catalog's wanted list goes to a page of its own,
    keyed by stem: the three lists made a 694 KB page."""
    matched_files = count_catalog_matched(db)
    total_files = compute_composition(db)["systems"]["files"]
    # When each catalog was read: a 76-day-old snapshot showed no age.
    as_of = ", ".join(
        f"{_PROVENANCE_LABELS.get(source, source)} {_date_in_words(data['imported_at'])}"
        for source, data in report.items() if data.get("imported_at")
    )

    lines = [
        "# Dump provenance",
        "",
        *([f'<p class="rb-timestamp" data-pagefind-ignore>Catalogs as of: {as_of}.</p>', ""]
          if as_of else []),
        "Provenance says whether a file is, byte for byte, a dump that Redump, "
        "No-Intro or TOSEC catalogues. It says where a dump is known from, "
        "not whether an emulator accepts it: that is the emulator's code, read "
        "in its profile. Example: `scph5501.bin` is Redump's `ps-30a.bin`.",
        "",
        f"**{matched_files:,}** of {total_files:,} system files match an entry "
        "in a dump-preservation catalog. Those files carry a "
        '<span class="rb-badge rb-badge-success">catalog</span> badge and the '
        "catalog entry's own name on the [system pages](systems/index.md), "
        'orange (<span class="rb-badge rb-badge-warning">TOSEC</span>) where '
        "TOSEC flags the dump as bad, overdumped, hacked, cracked or fixed. "
        "Arcade ROM sets and engine data "
        "sit outside what those catalogs index, so they are excluded from the "
        "ratio rather than counted as failures.",
        "",
        "## What the badge means",
        "",
        "The badge says the file is byte-identical to a dump catalogued by "
        "No-Intro, Redump, or TOSEC. Matching is done on SHA1, falling back to "
        "MD5 plus size for older catalog entries that predate SHA1. Filenames "
        "are never used: the same dump is `fdsbios.nes` here, "
        "`[BIOS] Family Computer Disk System (Japan) (En) (Rev 1).bin` at "
        "No-Intro, and "
        "`Nintendo Famicom Disk System BIOS (198x)(Nintendo)(JP)(en).bin` at "
        "TOSEC.",
        "",
        "## What it does not mean",
        "",
        "A file without a badge is not inferior and works exactly the same. "
        "Emulator behaviour is decided by [verification]"
        "(wiki/verification-modes.md), which reads the emulator source code, "
        "not by catalog membership. Plenty of files this project ships are "
        "outside any catalog by nature: composites a core assembles for itself "
        "(the MiSTer X68000 `boot.rom` is `cgrom.dat` joined to `iplrom.dat`), "
        "modern console firmware updates, game data such as Diablo's `diabdat.mpq`, and "
        "arcade sets tracked by MAME driver source instead.",
        "",
        "When the two views disagree, this project follows the code, because "
        "that is what decides whether the emulator boots. The reasoning is in "
        "the [technical questions](wiki/technical-faq.md#are-these-files-verified-against-original-"
        "hardware-dumps).",
        "",
        "## Coverage",
        "",
        "| Catalog | In collection | Covered DATs | Snapshot |",
        "|---------|--------------|-------------|----------|",
    ]

    for source, data in report.items():
        label = _PROVENANCE_LABELS.get(source, source)
        home = _PROVENANCE_HOMES.get(source, "")
        in_scope = data["matched"] + len(data["missing"])
        pct = 100 * data["matched"] / in_scope if in_scope else 0
        name = f"[{label}]({home})" if home else label
        lines.append(
            f"| {name} | {data['matched']:,}/{in_scope:,} ({pct:.0f}%) | "
            f"{len(data['covered_dats'])} | {_date_in_words(data['imported_at'])} |"
        )

    lines.extend(
        [
            "",
            "Coverage counts only DATs the collection already reaches: a DAT "
            "counts as covered once at least one of its entries is held. "
            "No-Intro tags every non-game dump `[BIOS]`, including digital "
            "title distribution such as the Wii U and 3DS CDN catalogues, "
            "which this project does not ship.",
            "",
        ]
    )

    out_of_scope = {s: d["out_of_scope"] for s, d in report.items() if d["out_of_scope"]}
    if out_of_scope:
        detail = ", ".join(
            f"{_PROVENANCE_LABELS.get(s, s)} {c:,}" for s, c in sorted(out_of_scope.items())
        )
        lines.extend(
            [
                f"Entries in DATs the collection does not cover at all are "
                f"excluded from those numbers ({detail}).",
                "",
            ]
        )

    derivable = derivable or {}
    derived_entries, derived_by_source = _split_derivable(report, derivable)
    total_missing = distinct_missing(report)
    # The three counts below added up to more than the total above it.
    listed = sum(len(data["missing"]) for data in report.values())
    overlap = (
        f" A dump two catalogs describe is listed under each, so the lists "
        f"hold {listed:,} rows."
        if listed != total_missing else ""
    )
    lines.extend(
        [
            "## Wanted: catalogued dumps this project does not have",
            "",
            f"The tables below list **{total_missing:,}** dumps a catalog "
            f"describes and the collection lacks.{overlap} Nothing here ships in any "
            "pack: it is an acquisition list, published with hashes so anyone "
            "can check a personal collection against it. A contribution "
            "matching one of these hashes is welcome: see "
            "[Contributing](contributing.md).",
            "",
            markup.button("Download the list (CSV)", "downloads/provenance-wanted.csv"),
            "",
        ]
    )

    for source, data in report.items():
        if data["missing"]:
            lines.extend(_wanted_section(source, data, derived_by_source.get(source, 0), moved))

    lines.extend(_derivable_section(derived_entries, derivable))

    lines.extend(["", _date_line()])
    return "\n".join(lines) + "\n"


def _split_derivable(report: dict, derivable: dict[str, dict]) -> tuple[dict[str, dict], dict[str, int]]:
    """Take out of each catalog's missing dumps those the collection already
    produces, by sha1, with how many each catalog lost.

    A dump the collection already produces (the odd bytes of a Kickstart,
    the halves of a character ROM) is no acquisition target: the page asked
    the public for 79 of them."""
    derived_entries: dict[str, dict] = {}
    derived_by_source: dict[str, int] = {}
    for source, data in report.items():
        kept = []
        for entry in data["missing"]:
            sha1 = (entry.get("sha1") or "").lower()
            if sha1 in derivable:
                derived_entries.setdefault(sha1, entry)
                derived_by_source[source] = derived_by_source.get(source, 0) + 1
            else:
                kept.append(entry)
        data["missing"] = kept
    return derived_entries, derived_by_source


def _wanted_dat_table(entries: list) -> list[str]:
    """One DAT's missing dumps as a table."""
    table = ["| Name | Description | SHA1 |", "|------|-------------|------|"]
    for entry in sorted(entries, key=lambda e: e["name"]):
        sha1 = entry.get("sha1") or "-"
        # A pipe in catalog text would split the markdown table row
        name = entry["name"].replace("|", "-")
        desc = (entry.get("description") or "").replace("|", "-")
        # Where an emulator's romset already carries the dump.
        for hit in entry.get("romsets", []):
            desc += (
                f" Ships in {_ROMSET_SOURCES.get(hit['source'], hit['source'])} "
                f"`{hit['archive']}` as `{hit['member']}`."
            )
        table.append(f"| `{name}` | {desc} | `{sha1}` |")
    return table


def _wanted_section(source: str, data: dict, derived: int, moved: dict[str, str] | None) -> list[str]:
    """A catalog's missing dumps, by DAT, or a line naming the page they went to."""
    label = _PROVENANCE_LABELS.get(source, source)
    by_dat: dict[str, list] = {}
    for entry in data["missing"]:
        for dat in entry.get("dats") or [entry.get("dat", "")]:
            by_dat.setdefault(dat, []).append(entry)
    lines = [f"### {label}", ""]
    if moved is not None:
        where = _list_pages(
            f"provenance-{_slugify_anchor(source)}", f"Wanted from {label}",
            f"Dumps {label} catalogues and the collection lacks. Part of "
            f"[Dump provenance](provenance.md#{_slugify_anchor(label)}).",
            [], [_wanted_list(source, label, data, by_dat, derived)],
            moved, parent=("Dump provenance", "/provenance/"),
        )
        lines.extend([
            f"{_count(len(data['missing']), 'dump')} in {_count(len(by_dat), 'DAT')}: "
            f"listed on {where}.", "",
        ])
        return lines
    for dat in sorted(by_dat):
        entries = by_dat[dat]
        lines.extend(markup.details("note", f"{dat} ({len(entries)})", _wanted_dat_table(entries)))
    return lines


def _derivable_section(derived_entries: dict[str, dict], derivable: dict[str, dict]) -> list[str]:
    """The catalogued dumps the collection produces from a file it holds."""
    if not derived_entries:
        return []
    lines = [
        "## Derivable: dumps the collection already produces",
        "",
        f"**{len(derived_entries):,}** catalogued dumps are not held as "
        "files but come out of one that is: a byte or word split, a "
        "half, a swap, or two chips joined. They are not wanted.",
        "",
        "| Name | Comes from | How | SHA1 |",
        "|------|------------|-----|------|",
    ]
    for sha1, entry in sorted(derived_entries.items(), key=lambda kv: kv[1]["name"]):
        how = derivable[sha1]
        sources = " + ".join(f"`{path}`" for path in how.get("from", []))
        name = entry["name"].replace("|", "-")
        lines.append(f"| `{name}` | {sources} | {how.get('transform', '')} | `{sha1}` |")
    lines.append("")
    return lines


def _wanted_list(source: str, label: str, data: dict, by_dat: dict[str, list],
                 derived: int) -> list[str]:
    """A catalog's wanted page: the counts, then every missing dump in one
    table folded under a filter box.

    The page was one closed block per DAT, 46 for TOSEC: a name was found
    by opening each in turn. The box filters the whole list by name, DAT,
    description or SHA1, and says how many rows it keeps.
    """
    missing = data["missing"]
    held = data["matched"]
    reached = held + len(missing) + derived
    dats = _count(len(data["covered_dats"]), "DAT")
    lines = [
        f"Held: **{held:,}** of {reached:,}, in the {dats} the collection reaches. "
        f"Wanted: **{len(missing):,}**, from {_count(len(by_dat), 'DAT')}.",
        "",
    ]
    if derived:
        verb = "is" if derived == 1 else "are"
        lines.extend([
            f"{derived:,} more {verb} [derivable]"
            "(provenance.md#derivable-dumps-the-collection-already-produces).", ""])
    if data.get("out_of_scope"):
        lines.extend([f"{data['out_of_scope']:,} more sit in DATs the collection does not reach.", ""])
    counts = ["| DAT | Wanted |", "|-----|--------|",
              *(f"| {dat.replace('|', '-')} | {len(entries):,} |"
                for dat, entries in sorted(by_dat.items()))]
    lines.extend(markup.details("note", f"Wanted by DAT ({len(by_dat):,})", counts))
    rows = []
    for entry in sorted(missing, key=lambda e: (e["name"], e.get("sha1") or "")):
        desc = markup.inline_html(entry.get("description") or "")
        for hit in entry.get("romsets", []):
            desc += markup.inline_html(
                f" Ships in {_ROMSET_SOURCES.get(hit['source'], hit['source'])} "
                f"`{hit['archive']}` as `{hit['member']}`.")
        in_dats = ", ".join(html.escape(d) for d in (entry.get("dats") or [entry.get("dat", "")]))
        sha1 = html.escape(entry.get("sha1") or "-")
        # The search reads the name alone. The DAT names are searched once, in
        # the count table above, and the site search holds no hashes. With the
        # descriptions indexed too, the TOSEC list matched "2" 556 times
        # (years, versions) and put the PlayStation page ahead of the
        # PlayStation 2 one for "playstation 2 bios". The name and the hash
        # sit in their cells as text: a catalog name is words, and in code
        # each word wore its own box on a narrow column.
        skip = markup.search_exclude()
        rows.append("<tr>"
                    f"<td>{html.escape(entry['name'], quote=False)}</td>"
                    f"<td {skip}>{in_dats}</td><td {skip}>{desc or '-'}</td>"
                    f'<td class="rb-hash" {skip}>{sha1}</td></tr>')
    heads = ["Name", "DAT", "Description", "SHA1"]
    lines.extend([
        siteentries.filter_box(f"rb-wanted-filter-{_slugify_anchor(source)}",
                               "dumps", heads, len(rows)),
        '<details class="rb-details rb-details-note">',
        f"<summary>All {_count(len(rows), 'wanted dump')}</summary>",
        '<table class="rb-wanted" data-rb-stack="true">',
        "<thead><tr>" + "".join(f'<th scope="col">{h}</th>' for h in heads) + "</tr></thead>",
        "<tbody>", *rows, "</tbody>", "</table>", "</details>", "",
    ])
    return lines
