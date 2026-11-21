"""The gap report printed for a person: profile gaps, then the launcher rows."""

from __future__ import annotations

from core.text import count_text
from packs.crossref import profile_breakdown


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

        # Counted once, for the heading and the total alike: a file installed
        # with its emulator is neither one to source nor one the pack brings,
        # held or not (validation.deliverable leaves it out of every pack).
        bundled_gaps = [g for g in data["gap_details"] if g.get("bundled")]
        emulator_bundled = len(bundled_gaps)
        counts = {key: data.get(f"gap_{key}", 0) for key in totals}
        for g in bundled_gaps:
            counts[g.get("source", "missing")] -= 1
        counts["bundled"] = emulator_bundled
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
