"""The truth diff of one platform rendered for a terminal or as markdown."""

from __future__ import annotations


def _where(entry: dict) -> str:
    """Where a diffed entry sits: one name can be declared at several paths."""
    return entry.get("destination") or entry["name"]


_TOTAL_LABELS = (
    ("total_missing", "missing"),
    ("total_extra_phantom", "unpaired"),
    ("total_extra_unprofiled", "unprofiled"),
    ("total_hash_mismatch", "hash"),
    ("total_required_mismatch", "required"),
)

_DIVERGENCE_LABELS = (
    ("missing", "MISSING"),
    ("extra_phantom", "UNPAIRED"),
    ("extra_unprofiled", "UNPROF"),
    ("hash_mismatch", "HASH"),
    ("required_mismatch", "REQ"),
)


def _terminal_divergence(sys_id: str, div: dict) -> list[str]:
    labels = [f"{label}:{len(div[key])}" for key, label in _DIVERGENCE_LABELS if div.get(key)]
    lines = [f"  {sys_id}: {' '.join(labels)}"]
    lines.extend(
        f"    + {_where(m)}  [{', '.join(m.get('cores', []))}]"
        for m in div.get("missing", [])
    )
    lines.extend(
        f"    ~ {_where(h)}  {h['hash_type']}: "
        f"{h['truth_' + h['hash_type']]} != {h['scraped_' + h['hash_type']]}"
        for h in div.get("hash_mismatch", [])
    )
    lines.extend(
        f"    - {_where(p)}  (no profile entry of this system matches it)"
        for p in div.get("extra_phantom", [])
    )
    lines.extend(
        f"    ? {_where(u)}  (unprofiled cores)"
        for u in div.get("extra_unprofiled", [])
    )
    lines.extend(
        f"    ! {_where(r)}  required: {r['truth_required']} != {r['scraped_required']}"
        for r in div.get("required_mismatch", [])
    )
    return lines


def format_terminal(report: dict) -> str:
    """The report as terminal lines: totals, then each divergent system."""
    lines: list[str] = []
    platform = report.get("platform", "unknown")
    s = report["summary"]

    lines.append(f"=== {platform} ===")
    lines.append(
        f"  {s['systems_compared']} systems compared: "
        f"{s['systems_fully_covered']} full, "
        f"{s['systems_partially_covered']} partial, "
        f"{s['systems_uncovered']} uncovered"
    )

    totals = [f"{s[key]} {label}" for key, label in _TOTAL_LABELS if s[key]]
    if totals:
        lines.append(f"  divergences: {', '.join(totals)}")
    else:
        lines.append("  no divergences")

    for sys_id, div in sorted(report.get("divergences", {}).items()):
        lines.extend(_terminal_divergence(sys_id, div))

    uncovered = report.get("uncovered_systems", [])
    if uncovered:
        lines.append(f"  uncovered ({len(uncovered)}): {', '.join(uncovered)}")

    return "\n".join(lines)


def _markdown_divergence(sys_id: str, div: dict) -> list[str]:
    lines = [f"## {sys_id}", ""]
    for m in div.get("missing", []):
        refs = ""
        if m.get("source_refs"):
            refs = " " + " ".join(f"`{r}`" for r in m["source_refs"])
        lines.append(f"- **Add** `{_where(m)}`{refs}")
    lines.extend(
        f"- **Fix hash** `{_where(h)}` {h['hash_type']}: "
        f"`{h['truth_' + h['hash_type']]}` != `{h['scraped_' + h['hash_type']]}`"
        for h in div.get("hash_mismatch", [])
    )
    # Evidence, not a request: an entry leaves a platform's file only on
    # proof (export_native's removal_candidates). A core can read a
    # file its profile does not pair with this declaration.
    lines.extend(
        f"- **Unpaired** `{_where(p)}`: no profile entry of this system matches it "
        "by path, name or hash"
        for p in div.get("extra_phantom", [])
    )
    lines.extend(
        f"- **Unpaired** `{_where(u)}`: some cores of this platform "
        "have no profile yet"
        for u in div.get("extra_unprofiled", [])
    )
    lines.extend(
        f"- **Fix required** `{_where(r)}`: truth={r['truth_required']}, scraped={r['scraped_required']}"
        for r in div.get("required_mismatch", [])
    )
    lines.append("")
    return lines


def format_markdown(report: dict) -> str:
    """The report as a markdown page, one section per divergent system."""
    lines: list[str] = []
    platform = report.get("platform", "unknown")
    s = report["summary"]

    lines.append(f"# {platform}")
    lines.append("")
    lines.append(
        f"**{s['systems_compared']}** systems compared | "
        f"**{s['systems_fully_covered']}** full | "
        f"**{s['systems_partially_covered']}** partial | "
        f"**{s['systems_uncovered']}** uncovered"
    )
    lines.append(
        f"**{s['total_missing']}** missing | "
        f"**{s['total_extra_phantom']}** unpaired | "
        f"**{s['total_extra_unprofiled']}** unprofiled | "
        f"**{s['total_hash_mismatch']}** hash | "
        f"**{s['total_required_mismatch']}** required"
    )
    lines.append("")

    for sys_id, div in sorted(report.get("divergences", {}).items()):
        lines.extend(_markdown_divergence(sys_id, div))

    uncovered = report.get("uncovered_systems", [])
    if uncovered:
        lines.append("## Uncovered systems")
        lines.append("")
        lines.extend(f"- {u}" for u in uncovered)
        lines.append("")

    return "\n".join(lines)
