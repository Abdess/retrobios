"""The release and version lines the pages state, and stats.json."""

from __future__ import annotations

import re
from datetime import datetime

from core.artifacts import build_timestamp
from model import releaserecord
from model import siteinputs
from model.composition import count_catalog_matched
from model.platforms import load_platform_config
from model.profiles import unique_emulator_profiles
from sitegen.config import RELEASE_URL, REPO_URL
from sitegen.install import display_name


def compute_stats(db: dict, coverages: dict, profiles: dict) -> dict:
    unique = unique_emulator_profiles(profiles)
    systems: set[str] = set()
    for p in unique.values():
        systems.update(p.get("systems", []))
    return {
        "schema_version": 1,
        "generated_at": build_timestamp(),
        "files": db.get("total_files", 0),
        "size_bytes": db.get("total_size", 0),
        "platforms": len(coverages),
        "emulators": len(unique),
        "systems": len(systems),
        "catalog_matched": count_catalog_matched(db),
        "source": REPO_URL,
        "downloads": RELEASE_URL,
    }


def _release_date(tag: str) -> str:
    """The date a release tag names (v2026.10.10), in words, or empty."""
    match = re.fullmatch(r"v(\d{4})\.(\d{2})\.(\d{2})", tag or "")
    if not match:
        return ""
    moment = datetime(int(match[1]), int(match[2]), int(match[3]))
    return f"{moment.day} {moment.strftime('%B %Y')}"


def _pack_version(pack_name: str, platforms: list[str]) -> str:
    """The platform version a pack was built for, from its name
    (Batocera_43.1_BIOS_Pack.zip is 43.1).

    Read past the platform part the builder writes, not at the last
    underscore: AmberELEC_prerelease-20261019_1835 read as 1835.
    """
    from packs.naming import platform_pack_prefix

    stem = pack_name.removesuffix(releaserecord.PACK_SUFFIX)
    prefix = platform_pack_prefix(
        platforms, platforms[0], str(siteinputs.current().platforms)
    ) + "_"
    return stem[len(prefix):] if stem.startswith(prefix) else ""


def _pack_platforms(platform_name: str, record: dict, pack_name: str) -> list[str]:
    """The platforms a release pack was built for, the one asked first."""
    listed = list(record.get("packs", {}).get(pack_name, {}).get("platforms") or [])
    return listed or [platform_name]


def release_line(platform_name: str, record: dict) -> list[str]:
    """Which release the buttons serve, with its checksums and signature, and
    the version gap when the page describes a newer platform than the pack."""
    tag = record.get("tag")
    pack_name = releaserecord.pack_name_for(platform_name, record)
    if not tag or not pack_name:
        return []
    base = f"{REPO_URL}/releases/download/{tag}"
    built = _release_date(tag)
    lines = [
        f"Pack {tag}{f', built {built}' if built else ''}. "
        f"[SHA256SUMS.txt]({base}/SHA256SUMS.txt) and its "
        f"[signature]({base}/SHA256SUMS.txt.sig).",
    ]
    config = load_platform_config(platform_name, str(siteinputs.current().platforms))
    page_version = str(config.get("version") or "")
    pack_version = _pack_version(
        pack_name, _pack_platforms(platform_name, record, pack_name)
    )
    if page_version and pack_version and page_version.lstrip("v") != pack_version.lstrip("v"):
        display = display_name(config, platform_name)
        lines.append(f"This pack was built for {display} {pack_version}. The command "
                     f"installs the files for {display} {page_version}.")
    return lines


def other_version(platform_name: str, prefix: str = "../") -> str:
    """What a reader on another version of the setup does with the pack.
    Our data says which list the pack was made from, not what an older list
    lacks. A bare `--check` was no command to run for someone holding a ZIP:
    the line links the setup page's commands that check."""
    target = f"{prefix}platforms/{platform_name}.md#how-to-check"
    return f"Other version? [Check the files]({target}) after copying."


def setup_version(platform_name: str, record: dict | None = None) -> str:
    """The setup and version whose BIOS list the pack was made from
    ("Batocera 43.1"): the version in the pack's name, else the version the
    platform YAML was read at. Empty when neither says, or when the
    platform has no YAML to read a version from."""
    try:
        config = load_platform_config(platform_name, str(siteinputs.current().platforms))
    except FileNotFoundError:
        return ""
    pack_name = releaserecord.pack_name_for(platform_name, record or {})
    version = (
        _pack_version(pack_name, _pack_platforms(platform_name, record or {}, pack_name))
        if pack_name else ""
    ) or str(config.get("version") or "")
    if not version:
        return ""
    return f"{display_name(config, platform_name)} {version.removeprefix('v')}"


def version_line(platform_name: str, record: dict, named: bool = False,
                 prefix: str = "../") -> str:
    """The version the pack fits, and what to do on another. *named* when
    the release line already named the pack's version."""
    made_from = setup_version(platform_name, record)
    other = other_version(platform_name, prefix)
    if named or not made_from:
        return other
    return f"Made for {made_from}. {other}"
