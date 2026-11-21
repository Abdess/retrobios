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

# Subjects the refresh planner (freshness.stalecommands) picks a command by:
# the checks name their rows with these, so a rename reaches both sides.
NO_INTRO_GAMES = "no-intro games"
REDUMP_GAMES = "redump games"
MAME_RECIPES = "mame recipes"
FBNEO_RECIPES = "fbneo recipes"
INSTALLER_PIN = "install.py pin"
_UNPROFILED_CORES = " cores"


def unprofiled_cores_subject(platform: str) -> str:
    """The targets row listing the core names of a platform no profile claims."""
    return f"{platform}{_UNPROFILED_CORES}"


def is_unprofiled_cores(subject: str) -> bool:
    """Whether a targets row is the backlog of unprofiled names, not a target file."""
    return subject.endswith(_UNPROFILED_CORES)


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
