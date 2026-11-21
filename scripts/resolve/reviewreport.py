"""A review's results as JSON rows, a pull request comment, or terminal lines."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from resolve.review import ValidationResult

# The terminal's word for each check status; any other status is "info".
MARKERS = {"PASS": "ok", "FAIL": "fail", "WARN": "warn"}


def json_rows(results: list[ValidationResult]) -> list[dict]:
    """One JSON object per file reviewed."""
    return [
        {
            "file": r.filepath,
            "passed": r.passed,
            # A file that failed, unread or refused, is not a new one.
            "outcome": r.outcome or ("new" if r.passed else "failed"),
            "destination": r.destination,
            "sha1": r.sha1,
            "md5": r.md5,
            "size": r.size,
            "checks": [{"status": s, "message": m} for s, m in r.checks],
        }
        for r in results
    ]


def markdown_report(results: list[ValidationResult]) -> str:
    """The report posted as a pull request comment."""
    lines = ["## BIOS Validation Report", ""]
    held = sum(r.outcome == "held" for r in results)
    unknown = sum(r.outcome == "unknown" for r in results)
    review = ", ".join(part for part in (
        f"{held} already held" if held else "",
        f"{unknown} not recognised" if unknown else "",
    ) if part)
    status = ("some checks failed" if not all(r.passed for r in results)
              else f"no check failed, to review: {review}" if review
              else "all checks passed")
    lines.append(f"**Status**: {status}")
    lines.append("")

    for r in results:
        lines.append(r.to_markdown())
        lines.append("")

    return "\n".join(lines)


def text_lines(results: list[ValidationResult]) -> list[str]:
    """The terminal report, each file headed by a blank line."""
    lines: list[str] = []
    for r in results:
        lines.extend(("", f"[{r.status}] {r.filepath}"))
        if r.sha1:
            lines.append(f"  SHA1: {r.sha1}")
            lines.append(f"  MD5:  {r.md5}")
            lines.append(f"  Size: {r.size:,}")
        lines.extend(f"  [{MARKERS.get(s, 'info')}] {m}" for s, m in r.checks)
    return lines
