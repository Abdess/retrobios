"""The gap report printed for a person: profile gaps, then the launcher rows."""

from __future__ import annotations

from core.text import count_text
from packs.crossref import SET_ASIDE, gap_source_counts

# How each reason an entry is left out of the comparison reads.
SET_ASIDE_LABELS = {
    "other_versions": "other versions of a slot",
    "not_read": "not read on this platform",
    "outside_scope": "outside the pack",
    "launcher": "filled by the platform's launcher",
}


def profile_breakdown(data: dict) -> str:
    """Where each entry of a profile went, adding up to its file count.

    The heading said 261 files, 7 declared and 238 undeclared, and the 16
    others were nowhere: the versions a slot accepts, the entries the
    platform never opens and the ones no pack carries.
    """
    # A report built without the per-entry tally (a fixture, a saved --json
    # of an earlier run) falls back to its row counts.
    parts = [f"{data.get('declared_files', data['platform_covered'])} declared by platforms",
             f"{data.get('undeclared_files', data['gaps'])} undeclared"]
    unsourceable = data.get("unsourceable_files", len(data.get("unsourceable") or []))
    if unsourceable:
        parts.append(f"{unsourceable} unsourceable")
    aside = data.get("set_aside") or {}
    detail = [f"{aside[key]} {SET_ASIDE_LABELS[key]}" for key in SET_ASIDE if aside.get(key)]
    if detail:
        parts.append(f"{sum(aside.values())} set aside ({', '.join(detail)})")
    return ", ".join(parts)


def print_launcher_unproven(rows: list[dict]) -> None:
    """The launcher records resting on a config file the code does not prove.

    Neither a pack, a manifest nor a severity reads them: each is listed
    with the links it lacks.
    """
    if not rows:
        return
    platforms = sorted({r["platform"] for r in rows})
    print(f"\nLauncher records unproven: {len(rows)} across {count_text(len(platforms), 'platform')}")
    for platform in platforms:
        print(f"\n{platform}")
        for row in (r for r in rows if r["platform"] == platform):
            print(f"    [{row['index']}] {row['emulator']} {row['kind']}: {row['passes_to']}")
            for link in row["missing"]:
                print(f"        missing {link}")


def print_launcher_reads(rows: list[dict]) -> None:
    """The launcher reads gap category, after the profile gaps.

    A name its reader declares unsourceable is listed apart, with the
    reason: it is no file left to find.
    """
    unsourceable = [r for r in rows if r.get("unsourceable")]
    rows = [r for r in rows if not r.get("unsourceable")]
    platforms = sorted({r["platform"] for r in rows})
    print(f"\nLauncher reads, not held: {count_text(len(rows), 'name')} "
          f"across {count_text(len(platforms), 'platform')}")
    for platform in platforms:
        print(f"\n{platform}")
        for row in (r for r in rows if r["platform"] == platform):
            first = row["readers"][0]
            more = f" (+{count_text(len(row['readers']) - 1, 'record')})" if len(row["readers"]) > 1 else ""
            casing = f", held as {row['held_as']}" if row.get("held_as") else ""
            print(
                f"    {row['name']} [{', '.join(row['emulators'])}, {first['kind']}, "
                f"{first['source_ref']}]{more}{casing}"
            )
    if not unsourceable:
        return
    platforms = sorted({r["platform"] for r in unsourceable})
    print(
        f"\nLauncher reads, unsourceable: {count_text(len(unsourceable), 'name')} "
        f"across {count_text(len(platforms), 'platform')}"
    )
    for row in unsourceable:
        print(
            f"    {row['platform']}: {row['name']} [{', '.join(row['emulators'])}, "
            f"{row['readers'][0]['source_ref']}]: {row['unsourceable']}"
        )


def print_report(
    report: dict, scope: str = "all emulators", show_clean: bool = False
) -> None:
    """Print a human-readable gap analysis report.

    `scope` names what the totals cover: under --platform, the emulators
    that platform runs, not all of them. `show_clean` lists an emulator with
    nothing undeclared too: asked about by name, it was the whole answer and
    the report used to leave it out.
    """
    print("Emulator vs Platform Gap Analysis")
    print("=" * 60)
    print("* marks a file the emulator requires")

    total_gaps = 0
    totals: dict[str, int] = {"bios": 0, "data": 0, "large_file": 0, "missing": 0}
    # A runtime component bundled with its emulator is left out of the
    # collection by design, as verify and the gaps page say: not a file to find.
    bundled = 0

    for _emu_name, data in sorted(report.items()):
        gaps = data["gaps"]
        if gaps == 0 and not show_clean:
            continue

        # Counted once, for the heading and the total alike.
        counts = gap_source_counts(data)
        emulator_bundled = counts["bundled"]
        parts = [f"{count} {key}" for key, count in counts.items() if count]
        status = ", ".join(parts) if parts else "OK"

        systems = ", ".join(data["systems"])
        print(f"\n{data['emulator']}" + (f" ({systems})" if systems else ""))
        print(f"  {data['total_files']} files in profile: {profile_breakdown(data)}")
        print(f"  Gaps: {status}")

        for g in data["gap_details"]:
            req = "*" if g["required"] else " "
            src = g.get("source", "missing").upper()
            if g.get("bundled"):
                src = "BUNDLED"
            # One line per file: a note spanning lines fell to column 0
            # between entries and read as an emulator heading.
            note = f": {' '.join(str(g['note']).split())}" if g["note"] else ""
            archive_info = ""
            if g.get("archive"):
                fc = g.get("archive_file_count", 0)
                rc = g.get("archive_required_count", 0)
                archive_info = f" ({fc} files, {rc} required)"
            if g.get("alternatives") and not g.get("in_repo"):
                archive_info += f" (or {', '.join(g['alternatives'])})"
            print(f"    {req} {g['name']} [{src}]{archive_info}{note}")

        total_gaps += gaps
        for key in totals:
            totals[key] += counts[key]
        bundled += emulator_bundled

    print(f"\n{'=' * 60}")
    print(f"Total: {total_gaps} undeclared files across {scope}")
    available = totals["bios"] + totals["data"] + totals["large_file"]
    print(f"  {available} available (bios: {totals['bios']}, data: {totals['data']}, "
          f"large_file: {totals['large_file']})")
    print(f"  {totals['missing']} missing (need to be sourced)")
    if bundled:
        print(f"  {bundled} bundled with their emulator, not packed")
