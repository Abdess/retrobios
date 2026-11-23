"""A review's results as JSON rows, a pull request comment, or terminal lines."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from resolve.review import ValidationResult

# Each check status as the pull request comment and the terminal word it.
# Any other status is an informational note.
WORDS = {"PASS": ("Pass", "ok"), "FAIL": ("Fail", "fail"), "WARN": ("Warning", "warn")}
INFO = ("Info", "info")


def _was_read(r: ValidationResult) -> bool:
    """A path refused before it was read has no size or digest to show:
    empty fields read as an empty file contributed."""
    return bool(r.sha1)


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
        lines.append(file_markdown(r))
        lines.append("")

    return "\n".join(lines)


def file_markdown(r: ValidationResult) -> str:
    """One file's block of the pull request comment."""
    lines = [f"### {r.status} `{r.filename}`", "", f"- **Path**: `{r.filepath}`"]
    if _was_read(r):
        lines.append(f"- **Size**: {r.size:,} bytes")
        lines.append(f"- **SHA1**: `{r.sha1}`")
        lines.append(f"- **MD5**: `{r.md5}`")
        lines.append(f"- **CRC32**: `{r.crc32}`")
    lines.append("")
    lines.extend(f"- {WORDS.get(s, INFO)[0]}: {m}" for s, m in r.checks)
    return "\n".join(lines)


def text_lines(results: list[ValidationResult]) -> list[str]:
    """The terminal report, each file headed by a blank line."""
    lines: list[str] = []
    for r in results:
        lines.extend(("", f"[{r.status}] {r.filepath}"))
        if _was_read(r):
            lines.append(f"  SHA1: {r.sha1}")
            lines.append(f"  MD5:  {r.md5}")
            lines.append(f"  Size: {r.size:,}")
        lines.extend(f"  [{WORDS.get(s, INFO)[1]}] {m}" for s, m in r.checks)
    return lines
