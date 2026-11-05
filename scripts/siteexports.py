"""The site page that publishes each platform's corrected BIOS file.

export_native.py writes the platform's own file, corrected, under
exports/<platform>/ and what it changed beside it as exports/<platform>.json.
This page reads those reports: the reader finds a platform, the file its
maintainers keep, the corrected copy, and every change named.
"""

from __future__ import annotations

import json
from pathlib import Path

import sitemarkup as markup

EXPORTS_DIR = "exports"
REPO_BLOB = "https://github.com/Abdess/retrobios/blob/main"
REPO_TREE = "https://github.com/Abdess/retrobios/tree/main"
REPO_RAW = "https://raw.githubusercontent.com/Abdess/retrobios/main"
# Where the site publishes each report, beside the API (generate_site).
API_EXPORTS = "api/v1/exports"

# Report key, then how a line of it reads on the page.
CHANGE_KINDS = (
    ("hashes_corrected", "Hashes updated to the emulator source"),
    ("hashes_filled", "Hashes added where the original lists none"),
    ("sizes_corrected", "Sizes updated to the emulator source"),
    ("sizes_removed", "Sizes no longer stated"),
    ("hashes_cleared", "Hashes no longer listed"),
    ("withheld", "Changes not applied"),
)


# Report key, then the kind each line of `changes` carries.
CHANGE_RECORDS = {
    "hashes_corrected": "hash_corrected",
    "hashes_filled": "hash_filled",
    "sizes_corrected": "size_corrected",
    "sizes_removed": "size_removed",
    "hashes_cleared": "hash_cleared",
}


def _value(value: object) -> str:
    """One value in code, or a list the checker reads as any of its values."""
    if isinstance(value, list):
        return " or ".join(f"`{v}`" for v in value) if value else "`[]`"
    return f"`{value}`"


def describe_change(change: dict) -> str:
    """One change in words, with the value before and after it."""
    label = f"`{change['system']}/{change['name']}` {change['field']}"
    kind, old, new = change["kind"], change["old"], change["new"]
    if kind in ("hash_corrected", "size_corrected"):
        return f"{label} {_value(old)} becomes {_value(new)}"
    if kind == "hash_filled":
        return f"{label} {_value(new)} added"
    if kind == "requirement_corrected":
        return f"`{change['system']}/{change['name']}` becomes {'required' if new else 'optional'}"
    return f"{label} {_value(old)} no longer listed"


def change_items(report: dict, key: str) -> list[str]:
    """The lines a kind of change shows. A report written before values
    were recorded names the entries only."""
    kind = CHANGE_RECORDS.get(key)
    changes = report.get("changes")
    if kind and changes is not None:
        return [describe_change(c) for c in changes if c["kind"] == kind]
    items = report.get(key) or []
    return [str(i) if key == "withheld" else f"`{i}`" for i in items]


def requirement_lines(report: dict) -> list[str]:
    """Each required flag aligned with the code, and what it is now."""
    items = [
        describe_change(c) for c in report.get("changes") or []
        if c["kind"] == "requirement_corrected"
    ]
    if not items:
        return []
    return _lookup_only(markup.details(
        "note", f"Required flags aligned with the code ({len(items)})",
        [f"- {item}" for item in items]))


def _lookup_only(block: list[str]) -> list[str]:
    """A list of entries changed, out of the site search: 129 "md5" in them
    put this page above the one that explains MD5 checks."""
    return ["", markup.block_open("section", markup.search_exclude()), "", *block, "", "</section>", ""]


def _plural(count: int, noun: str, plural: str = "") -> str:
    return f"{count:,} {noun if count == 1 else plural or noun + 's'}"


def change_text(report: dict) -> str:
    """What the updated file changes, from the report's numbers.

    The command line prints its own terse summary. The page states each
    kind of change once, in plain terms, and leaves out what did not
    happen. RetroPie's unit is a package, so its own sentence is kept.
    """
    counts = report.get("counts")
    if not counts:
        return report["summary"]
    parts = [f"{_plural(counts['kept'], 'entry', 'entries')} kept"]
    extra = [
        (counts["added"], "file", "files", "added"),
        (len(report.get("hashes_corrected") or []), "hash", "hashes", "updated"),
        (report.get("requirements_corrected") or 0, "required flag", "required flags",
         "aligned with the code"),
        (len(report.get("hashes_filled") or []), "hash", "hashes", "added"),
        (len(report.get("sizes_corrected") or []), "size", "sizes", "updated"),
    ]
    parts += [f"{_plural(n, one, many)} {verb}" for n, one, many, verb in extra if n]
    return ", ".join(parts)


# Beyond this many entries a reason's list folds away.
LONG_LIST = 10


def candidate_lines(candidates: list[dict]) -> list[str]:
    """The entries no emulator the platform runs is known to open.

    Each stays in the updated file. The count comes first, then the entries
    grouped by reason, a long group in a block the reader opens.
    """
    if not candidates:
        return []
    open_question = sum(c.get("verdict") == "undetermined" for c in candidates)
    count = _plural(len(candidates), "entry", "entries")
    sentence = (
        f"{count} of the original {'is' if len(candidates) == 1 else 'are'} not "
        "named, by name, path or hash, in the profile of any emulator this "
        "platform runs. "
        f"{'It stays' if len(candidates) == 1 else 'They stay'} in the updated file"
    )
    if open_question:
        sentence += (
            f", and {open_question} of them may still be read by an emulator "
            "this project has not profiled in full"
        )
    lines = [sentence + ".", ""]
    groups: dict[str, list[dict]] = {}
    for candidate in candidates:
        groups.setdefault(candidate.get("reason", ""), []).append(candidate)
    for reason, entries in groups.items():
        title = (reason[:1].upper() + reason[1:]).replace('"', "'")
        items = [f"`{c['system']}` `{c['destination']}`" for c in entries]
        if len(entries) > LONG_LIST:
            lines.extend(_lookup_only(markup.details(
                "note", f"{title} ({len(entries)})", [f"- {item}" for item in items])))
        else:
            lines.extend([f"{title}:", "", *[f"- {item}" for item in items], ""])
    return lines


def _declaration(declaration: dict) -> str:
    """One declaration of a doubled destination: who declares it, its hash,
    and the emulators that read the file it names."""
    where = f"`{declaration['system']}`"
    if declaration.get("component"):
        where += f" (`{declaration['component']}`)"
    parts = [where] + [
        f"{field} {_value(values[0] if len(values) == 1 else values)}"
        for field, values in (declaration.get("hashes") or {}).items()
    ]
    readers = declaration.get("readers") or []
    read = (
        "read by " + ", ".join(
            r["emulator"] + (f" (`{r['source_ref']}`)" if r.get("source_ref") else "")
            for r in readers
        )
        if readers else "no emulator this platform runs is known to read this file"
    )
    return " ".join(parts) + f": {read}"


def doubled_lines(doubled: list[dict]) -> list[str]:
    """The destinations the original declares twice, for two files.

    One path holds one file, so one of the two checks fails on every
    install. Both entries stay in the updated file.
    """
    if not doubled:
        return []
    count = _plural(len(doubled), "destination")
    lines = [
        f"{count} of the original {'is' if len(doubled) == 1 else 'are'} declared "
        "twice, for two different files. One path holds one file, so one of the "
        "two checks fails on every install. Both entries stay in the updated file.",
        "",
    ]
    for item in doubled:
        lines.append(f"- `{item['destination']}`")
        lines.extend(f"  - {_declaration(d)}" for d in item["declarations"])
    lines.append("")
    return lines


def load_export_reports(directory: str = EXPORTS_DIR) -> list[dict]:
    """Every platform report the export wrote, by platform name."""
    root = Path(directory)
    if not root.is_dir():
        return []
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(root.glob("*.json"))
    ]


def _display(platform: str, names: dict[str, str]) -> str:
    return names.get(platform) or platform


def _corrected_link(report: dict) -> str:
    platform, files = report["platform"], report["files"]
    if len(files) == 1:
        path = f"{EXPORTS_DIR}/{platform}/{files[0]}"
        return f"[`{Path(files[0]).name}`]({REPO_BLOB}/{path})"
    return f"[{len(files)} files]({REPO_TREE}/{EXPORTS_DIR}/{platform})"


def _original_link(report: dict) -> str:
    originals = report.get("originals") or {}
    if len(originals) == 1:
        (name, url), = originals.items()
        return f"[`{Path(name).name}`]({url})"
    return f"{len(originals)} files"


def generate_exports_page(reports: list[dict], names: dict[str, str]) -> str:
    """The page, names mapping each platform key to the name it displays."""
    lines = [
        "# Updated platform files",
        "",
        "Each platform keeps its own list of the BIOS files it checks: "
        "libretro's `System.dat`, Batocera's `batocera-systems`, Recalbox's "
        "`es_bios.xml` and so on. This project reads the emulators' source "
        "code file by file, and offers each platform its own file with those "
        "findings applied: a hash is updated where the emulator source states "
        "another, and files the platform's emulators read are added. An entry "
        "that no emulator the platform runs is known to open stays in the "
        "file and is listed as a removal candidate, with the reason, on the "
        "platform's section. It would leave the file only once the code of "
        "every emulator that platform runs for the system is shown not to "
        "read it. Where a value of an entry is "
        "dropped, the platform's section lists it. Code the file carries is "
        "patched in place. With the original files on hand, the tests run "
        "the updated Batocera and ROCKNIX scripts (`--createReadme`), parse "
        "`checkBIOS.sh` and the RetroPie scriptmodules with `bash -n`, and "
        "check that every Recalbox entry carries the attributes the "
        "`es_bios.xsd` Recalbox publishes requires.",
        "",
        "Each file starts from the revision of the original that this project "
        "last read, so it compares cleanly with it, and every change can be "
        "taken or left on its own. Each value comes from an emulator profile, "
        "whose page cites where it was read. If a change does not fit a platform, an "
        "issue on the [repository](https://github.com/Abdess/retrobios/issues) "
        "is welcome: this project's profile is revised, and every platform's "
        "file follows.",
        "",
        "A file is added only when the format can carry it. A platform that "
        "checks an md5 needs one, so a file whose emulator source states no "
        "md5 is not added, and neither is a file under a system the "
        "platform's checker does not read. Those are counted on each "
        "platform's section.",
        "",
    ]
    if not reports:
        lines.extend([
            "No updated file has been published yet. They are written by "
            "`python scripts/export_native.py --all --fetch`.",
            "",
        ])
        return "\n".join(lines)

    lines.extend([
        "| Platform | Original file | Updated file | Changes |",
        "|----------|------------|----------------|--------------|",
    ])
    for report in reports:
        platform = report["platform"]
        lines.append(
            f"| [{_display(platform, names)}](#{platform}) | "
            f"{_original_link(report)} | {_corrected_link(report)} | "
            f"{change_text(report)} |"
        )
    lines.append("")

    for report in reports:
        platform = report["platform"]
        lines.extend([f"## {_display(platform, names)} {{ #{platform} }}", ""])
        text = change_text(report)
        lines.extend([text[:1].upper() + text[1:] + ".", ""])
        counts = report.get("counts") or {}
        if counts.get("not_added"):
            lines.extend([
                f"{_plural(counts['not_added'], 'other file')} the emulators read "
                f"{'is' if counts['not_added'] == 1 else 'are'} not added, for the "
                "reasons above.",
                "",
            ])
        if counts.get("not_kept"):
            lines.extend([
                f"{_plural(counts['not_kept'], 'entry', 'entries')} of the original "
                "cannot be written in this format and should be checked by hand.",
                "",
            ])
        lines.extend(candidate_lines(report.get("removal_candidates") or []))
        lines.extend(doubled_lines(report.get("doubled") or []))
        if report.get("invalid"):
            lines.extend(markup.aside(
                "warning", "The updated file does not pass the platform's own checks",
                [f"- {issue}" for issue in report["invalid"]]))

        originals = report.get("originals") or {}
        files = report["files"]
        raw = [f"{REPO_RAW}/{EXPORTS_DIR}/{platform}/{name}" for name in files]
        # Every change as JSON, the report the page is written from.
        changes = markup.button("Every change (JSON)", f"{API_EXPORTS}/{platform}.json")
        if len(files) == 1:
            lines.extend([
                markup.button("Download the updated file", raw[0], primary=True) + " "
                + markup.button("See it on GitHub", f"{REPO_BLOB}/{EXPORTS_DIR}/{platform}/{files[0]}")
                + " " + changes,
                "",
            ])
        else:
            lines.extend([
                markup.button(f"Browse the {len(files)} updated files",
                              f"{REPO_TREE}/{EXPORTS_DIR}/{platform}", primary=True)
                + " " + changes,
                "",
            ])
        if len(originals) > 1:
            lines.extend(markup.details(
                "note", f"The {len(originals)} original files it is based on",
                [f"- [`{name}`]({url})" for name, url in sorted(originals.items())]))
        elif originals:
            (name, url), = originals.items()
            lines.extend([f"Based on [`{name}`]({url}).", ""])

        lines.extend(requirement_lines(report))
        for key, title in CHANGE_KINDS:
            items = change_items(report, key)
            if not items:
                continue
            lines.extend(_lookup_only(markup.details(
                "note", f"{title} ({len(items)})", [f"- {item}" for item in items])))
    return "\n".join(lines)
