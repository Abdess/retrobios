"""The committed release record, release.json, as the README, the site and the release tools read it."""

from __future__ import annotations

import json
from pathlib import Path

from core.paths import PLATFORMS_DIR
from model.registry import list_release_pack_platforms


RECORD = "release.json"
# The record's format, which release.schema.json pins: a reader holding the
# file alone can tell which shape it reads.
SCHEMA_VERSION = 1
# Each registered platform has a page at get/<platform>/ on the site: the
# current pack's files, or the command when no release publishes one. The
# address outlives every release, so a link written elsewhere keeps working.
GET_DIR = "get"


def load_record(path: str | Path = RECORD) -> dict:
    """The committed record, empty when no release has written one."""
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}


def get_page(platform: str, site: str = "") -> str:
    """The permanent download address of a platform, under *site*."""
    return f"{site}{GET_DIR}/{platform}/"


def advertised(record: dict, platforms_dir: str = PLATFORMS_DIR) -> dict:
    """The record as the download tables show it: release_pack platforms only.

    A release cut before a platform lost its release_pack still holds that
    platform's pack. The tables follow the registry, so a platform left out
    is offered the command, and a pack two platforms shared names the one
    still released.
    """
    if not record:
        return {}
    released = set(list_release_pack_platforms(platforms_dir))
    packs = {}
    for name, pack in record.get("packs", {}).items():
        serves = [p for p in pack.get("platforms", ()) if p in released]
        if serves:
            packs[name] = {**pack, "platforms": serves}
    return {**record, "packs": packs}


def load_advertised(path: str | Path = RECORD, platforms_dir: str = PLATFORMS_DIR) -> dict:
    """The committed record, reduced to the platforms a release publishes."""
    return advertised(load_record(path), platforms_dir)


def pack_name_for(platform: str, record: dict) -> str | None:
    """Name of the release pack that serves a platform, if it has one."""
    for name, pack in sorted(record.get("packs", {}).items()):
        if platform in pack.get("platforms", ()):
            return name
    return None


def pack_for(platform: str, record: dict) -> dict | None:
    """The pack of the release that serves a platform, if it has one."""
    name = pack_name_for(platform, record)
    return record["packs"][name] if name else None
