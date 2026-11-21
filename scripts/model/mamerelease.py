"""MAME versions and the mamedev/mame release tags that name them."""

from __future__ import annotations


def mame_tag(version: str) -> str:
    """The mamedev/mame release tag of a version: 0.289 is mame0289."""
    return "mame" + version.replace(".", "").zfill(4)


def tag_version(tag: str) -> str | None:
    """The version a mamedev/mame release tag names, None for anything else.

    Release tags carry four digits or more (mame0121 is the first on GitHub).
    """
    raw = tag.removeprefix("mame")
    if raw.isdigit() and len(raw) >= 4:
        return f"{raw[0]}.{raw[1:]}"
    return None


def mame_version(tag: str) -> str:
    """The version a mamedev/mame release tag names: mame0289 is 0.289.

    Anything else (a branch, a commit) is returned without its prefix.
    """
    return tag_version(tag) or tag.removeprefix("mame")
