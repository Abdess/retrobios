"""The current state of each campaign finding: its latest line, and the statuses still open."""

from __future__ import annotations

from pathlib import Path

from model import measurements as mr

OPEN_STATUSES = ("open", "flagged")


def latest_findings(root: Path) -> dict[str, dict]:
    """Each finding key's latest line in the findings file: the last line written wins."""
    return {line["key"]: line for line in mr.read_campaign(root, mr.FINDINGS)}
