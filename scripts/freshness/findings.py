"""The finding a freshness check reports, its statuses and the areas it covers."""

from __future__ import annotations

from dataclasses import dataclass, field


SHOWN_ITEMS = 4  # items named in a diff summary before ", ..."
SHOWN_NAMES = 12  # core names named in an unresolved row before ", ..."
AREAS = (
    "platforms", "native", "targets", "romfolders", "coreinfo", "data", "catalogs", "ci", "profiles",
)
OK, STALE, UNKNOWN, ERROR, SKIPPED = "OK", "STALE", "UNKNOWN", "ERROR", "SKIPPED"
# Every status a finding may carry, in the order the summary counts them.
STATUSES = (STALE, UNKNOWN, ERROR, SKIPPED, OK)


@dataclass(frozen=True)
class Finding:
    area: str
    subject: str
    status: str
    local: str = ""
    remote: str = ""
    detail: str = ""
    # Every name a shortened detail stands for: --json carries them all, so
    # a script can act on the 50 cores a row names 12 of.
    items: list[str] = field(default_factory=list)
