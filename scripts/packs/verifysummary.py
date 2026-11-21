"""The closing lines of a verify run over several platforms."""

from __future__ import annotations

from core.text import count_text
from packs.report import NOT_FIRMWARE, core_required_missing, discrepancy_keys, split_undeclared
from packs.verdicts import Severity


def overall_summary(group_results: list[tuple[dict, list[str]]]) -> str:
    """The closing lines of a multi-platform run, worst severity first.

    Each count names the platforms carrying it, and the core files a core
    cannot run without are counted too: a reader of the summary alone used
    to conclude nothing required was missing, and could not tell where the
    one warning was without reading the whole output.
    """
    platforms = sum(len(group) for _, group in group_results)

    def where(counts: dict[str, int]) -> str:
        named = [f"{name} {count}" for name, count in counts.items() if count]
        return f" ({', '.join(named)})" if named else ""

    def on(groups: tuple[str, ...]) -> str:
        """The platforms a file is missing on, by the shorter side."""
        if len(group_results) < 2 or len(groups) * 2 <= len(group_results):
            return ", ".join(groups)
        others = [" / ".join(g) for _, g in group_results if " / ".join(g) not in groups]
        return "every platform" + (f" but {', '.join(others)}" if others else "")

    parts = []
    for severity, label in ((Severity.CRITICAL, "critical"), (Severity.WARNING, "warning"),
                            (Severity.INFO, "info")):
        counts = {
            " / ".join(group): r["severity_counts"].get(severity, 0)
            for r, group in group_results
        }
        parts.append(f"{sum(counts.values())} {label}{where(counts)}")
    # Shipped files whose bytes contradict a declaration or a core's own
    # check: the body printed 19 of them under a last line that read clean.
    counts = {
        " / ".join(group): len(discrepancy_keys(r.get("details", [])))
        for r, group in group_results
    }
    total = sum(counts.values())
    parts.append(f"{count_text(total, 'discrepancy', 'discrepancies')}{where(counts)}")
    lines = [f"{count_text(platforms, 'platform')}: {', '.join(parts)}"]

    # Grouped by file, not by platform: sfiii2a.zip missing everywhere was
    # counted and printed once per platform, 24 files for 10 distinct ones.
    holders: dict[str, list[str]] = {}
    for r, group in group_results:
        for name in sorted({
            u["name"] for u in core_required_missing(split_undeclared(
                r.get("undeclared_files", []))[1])
        }):
            holders.setdefault(name, []).append(" / ".join(group))
    if holders:
        by_platforms: dict[tuple[str, ...], list[str]] = {}
        for name, groups in sorted(holders.items()):
            by_platforms.setdefault(tuple(groups), []).append(name)
        detail = "; ".join(
            f"{', '.join(names)} ({on(groups)})"
            for groups, names in sorted(by_platforms.items(),
                                        key=lambda item: (-len(item[0]), item[1]))
        )
        lines.append(f"{len(holders)} core file(s) a core cannot run without are "
                     f"missing: {detail}")
    for category, label in NOT_FIRMWARE.items():
        counts = {
            " / ".join(group): len((r.get("missing_not_firmware") or {}).get(category, []))
            for r, group in group_results
        }
        total = sum(counts.values())
        if total:
            lines.append(f"{total} platform entries missing, not firmware, {label}{where(counts)}")
    return "\n".join(lines)
