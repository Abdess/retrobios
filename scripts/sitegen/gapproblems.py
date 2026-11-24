"""The gaps page's problem files: what a platform declares and its own check rejects."""

from __future__ import annotations

import html

from model.database import declared_records, sha1_at
from sitegen.cards import fetch_url
from sitegen.render import code_span, count_text, escape_tags


# Contributing page


def _held_accepted(accepted: dict[str, list[str]], db: dict | None) -> str:
    """Where the collection keeps a dump the emulator accepts, if it does.

    The table printed the hash the emulator wants and stopped there, while
    the collection held that exact dump for every one of the ten rows.
    ``accepted`` is the verify detail's field, the values by algorithm.
    """
    if not accepted or not db:
        return ""
    files = db.get("files", {})
    return next((path for named in declared_records(db, accepted).values()
                 for sha1 in named if (path := files[sha1].get("path"))), "")


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


def reason_cell(text: str) -> str:
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


def render_problem_files(
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
                "accepted": p.get("accepted") or {},
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
                    f"| {code_span(f['name'])} | {plats} | {reason_cell(f['reason'])} "
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
                held = _held_accepted(f["accepted"], db)
                cell = f"[{code_span(held)}]({fetch_url(held)})" if held else "-"
                lines.append(f"| `{fname}` | {plats} | {reason_cell(f['discrepancy'])} | {cell} |")
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
