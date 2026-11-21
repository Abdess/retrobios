"""What kind of profile a profile is: an emulator, an alias, a launcher, a test core."""

from __future__ import annotations

# A launcher hands the game to another emulator and an alias is another
# profile's build under a second name: neither declares files of its own.
FILELESS_TYPES = frozenset({"launcher", "alias"})


def lists_files(profile: dict) -> bool:
    """Whether a profile declares the files its emulator reads."""
    return profile.get("type") not in FILELESS_TYPES


def is_emulator(profile: dict) -> bool:
    """Whether a profile counts as an emulator of its own, neither an alias
    nor a test core."""
    return profile.get("type") != "alias" and profile.get("role") != "test"


def reads_own_files(profile: dict) -> bool:
    """Whether a profile lists the files its emulator reads and is not a test core."""
    return lists_files(profile) and profile.get("role") != "test"
