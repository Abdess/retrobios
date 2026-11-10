#!/usr/bin/env python3
"""Generate the site from database.json, platform configs, and emulator profiles.

The pages, navigation and data files are written into the Astro Starlight
project in website/, which builds the site.

Reads the same data sources as verify.py and generate_pack.py to produce
a complete documentation site. Zero manual content.

Usage:
    python scripts/generate_site.py
    python scripts/generate_site.py --db database.json --platforms-dir platforms
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import functools
import html
import io
import json
import os
import re
import shlex
import shutil
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

sys.path.insert(0, os.path.dirname(__file__))
from sitecollection import (  # noqa: E402
    _copy_places, _group_by_manufacturer, _profiles_in,
    _profiles_on_disk, _slug, collection_paths,
)
from common import (
    BUCKET_FOLDERS,
    names_manufacturer,
    upstream_profile_index,
    build_zip_contents_index,
    GAME_DATA_TOPS,
    compute_composition,
    count_catalog_matched,
    entry_system_ids,
    list_registered_platforms,
    list_release_pack_platforms,
    load_platform_registry,
    load_database,
    load_emulator_profiles,
    load_platform_config,
    load_provenance_snapshots,
    native_layer,
    require_directory,
    require_yaml,
    resolution_is_hash_exact,
    resolve_local_file,
    resolve_platform_cores,
    runs_standalone,
    unique_emulator_profiles,
    yaml_load,
)
from siterender import SECTION_LABELS, WIKI_SRC_DIR
from artifacts import ArtifactLockBusy, artifact_lock
from artifacts import json_text as _json_text
from cross_reference import FileConsumers, entry_target, held_copy
from nativemode import check_label, digest_algorithm, reads_file_contents


yaml = require_yaml()
from generate_readme import (
    compute_coverage,
    platform_coverages,
    NO_PACK,
    asset_links,
    contributing_text,
    demo_description,
    demo_facts,
    download_links,
    extract_notes,
    extract_targets,
    release_totals,
)
from provenance_report import build_report, distinct_missing, profile_needs
import sitemarkup as markup
import siteentries
import siteinputs
import retired_files
import siteagents
import sitestarlight
import sitesteps
from siteexports import generate_exports_page, load_export_reports
from siteguides import (
    ALSO_RUNS,
    DEVICE_GROUPS,
    GROUP_ANCHORS,
    GROUP_TILES,
    GUIDES,
    HANDHELD_GUIDE,
    Guide,
    HandheldGuide,
    HandheldSystem,
    FENCE_TITLES,
    INSTALL_BASE,
    INSTALL_PS1,
    INSTALL_SH,
    PACKAGE_COMMAND,
    TERMINALS,
    TRUST_ITEMS,
    detected_systems as _detected_systems,
    fence,
    folder_list,
    install_command,
    setup_count,
    platform_args,
    terminal_tabs,
    trust_box,
)
import archive_build
import release_record
import sitebootstrap
import sitemeasurements

# The Starlight project, and where its pages go inside it.
STARLIGHT_DIR = "website"
STARLIGHT_CONTENT = "src/content/docs"
SITE_NAME = "RetroBIOS"
REPO_URL = "https://github.com/Abdess/retrobios"
RELEASE_URL = f"{REPO_URL}/releases/latest"
# What LICENSE grants over the published data: its MIT terms name the
# metadata. The BIOS files themselves are under NOTICE, never this.
DATA_LICENSE = "MIT (LICENSE: scripts, tooling, schemas, documentation and metadata)"
SITE_URL = "https://abdess.github.io/retrobios/"
GENERATED_DIRS = ["platforms", "systems", "emulators", "wiki", "api", "downloads", "files",
                  release_record.GET_DIR]
# Generated directories of files served as they are, not pages.
PUBLIC_DIRS = ("api", "downloads")


def _content_check_ceiling(profiles: dict) -> str:
    """How far content checking can reach across every profiled entry."""
    hashed = sized = neither = 0
    for profile in unique_emulator_profiles(profiles).values():
        for f in profile.get("files", []) or []:
            if any(
                f.get(k)
                for k in ("md5", "sha1", "crc32", "sha256", "known_hash_adler32")
            ):
                hashed += 1
            elif any(f.get(k) for k in ("size", "min_size", "max_size")):
                sized += 1
            else:
                neither += 1
    total = hashed + sized + neither
    if not total:
        return ""
    return (
        f"Across every profiled entry, {hashed:,} of {total:,} "
        f"({hashed / total * 100:.0f}%) carry a hash the code checks, "
        f"{sized:,} ({sized / total * 100:.0f}%) only a size, and "
        f"{neither:,} ({neither / total * 100:.0f}%) neither. That last share "
        "is the ceiling of the method: where an emulator validates nothing, "
        "reading its source establishes which file it loads, never whether "
        "the content is the right dump. The provenance field answers that "
        "other question, for the files a dump catalog indexes."
    )


CLS_LABELS = {
    "official_port": "Official ports",
    "community_fork": "Community forks",
    "pure_libretro": "Pure libretro",
    "game_engine": "Game engines",
    "enhanced_fork": "Enhanced forks",
    "frozen_snapshot": "Frozen snapshots",
    "embedded_hle": "Embedded HLE",
    "launcher": "Launchers",
    "unclassified": "Unclassified",
    "other": "Other",
}

# The same classes said of one emulator: its page read "Classification:
# Official ports".
CLS_LABEL_ONE = {
    "official_port": "Official port",
    "community_fork": "Community fork",
    "pure_libretro": "Pure libretro",
    "game_engine": "Game engine",
    "enhanced_fork": "Enhanced fork",
    "frozen_snapshot": "Frozen snapshot",
    "embedded_hle": "Embedded HLE",
    "launcher": "Launcher",
    "unclassified": "Unclassified",
    "other": "Other",
}


def _copies_by_path(db: dict) -> dict[str, set[tuple[str, str, str]]]:
    """The copy places of each content, keyed by the path the database keeps."""
    files = db.get("files", {})
    return {
        str(files[sha1].get("path", "")): where
        for sha1, where in _copy_places(db).items()
    }


def _system_folder(
    files: list[dict],
    db: dict,
    name_consoles: dict[str, set[tuple[str, str]]],
    sys_id: str = "",
    copies: dict[str, set[tuple[str, str, str]]] | None = None,
) -> tuple[str, str] | None:
    """The bios/<manufacturer>/<console> folder a system's files live in.

    A content votes for every folder holding a copy under the name the system
    declares, not only the one deduplication kept: disksys.rom is kept as
    Arcade/FBNeo/fdsbios.nes and filed again under Nintendo/Famicom Disk
    System. A copy filed under another name, outside the manufacturer the id
    names, is another machine's file and votes only when no copy carries the
    declared name. An id that names its manufacturer (nintendo-fds) keeps the
    votes cast inside that manufacturer when there are any, and a maker's
    folder outranks the folders that file copies by emulator.
    """
    if copies is None:
        copies = _copies_by_path(db)
    votes: dict[tuple[str, str], int] = {}
    for fe in files:
        local, status = resolve_local_file(fe, db)
        if not local or not resolution_is_hash_exact(status):
            continue
        held = copies.get(local, set())
        if not held:
            parts = local.split("/")
            if len(parts) >= 4 and parts[0] == "bios":
                held = {(parts[1], parts[2], parts[-1])}
        declared = str(fe.get("name", "")).casefold()
        named = {
            (m, c) for m, c, base in held
            if base.casefold() == declared or names_manufacturer(sys_id, m)
        }
        for place in named or {(m, c) for m, c, _ in held}:
            votes[place] = votes.get(place, 0) + 1
    if votes:
        own = [place for place in votes if names_manufacturer(sys_id, place[0])]
        makers = [place for place in votes if place[0] not in BUCKET_FOLDERS]
        candidates = own or makers or list(votes)
        return max(sorted(candidates), key=lambda place: votes[place])
    for fe in files:
        places = name_consoles.get(fe.get("name", ""), set())
        if len(places) == 1:
            return next(iter(places))
    return None


def _folders_by_name(manufacturers: dict) -> dict[str, set[tuple[str, str]]]:
    """Normalized system name -> the console folders that spell it.

    nintendo-nes, nes and the NES folder normalize alike, as do
    sega-mastersystem and Sega/Master System.
    """
    from common import _norm_system_id

    index: dict[str, set[tuple[str, str]]] = {}
    for mfr, consoles in manufacturers.items():
        for console in consoles:
            spelled = console.lower().replace(" ", "-")
            for key in {
                _norm_system_id(f"{_slug(mfr)}-{spelled}"), _norm_system_id(spelled)
            }:
                index.setdefault(key, set()).add((mfr, console))
    return index


def _folder_named(sys_id: str, by_name: dict[str, set[tuple[str, str]]]) -> tuple[str, str] | None:
    from common import _norm_system_id

    places = by_name.get(_norm_system_id(sys_id), set())
    return next(iter(places)) if len(places) == 1 else None


def _system_pages_from_data(
    manufacturers: dict,
    coverages: dict,
    db: dict,
    profiles: dict | None = None,
) -> dict[str, tuple[str, str]]:
    """The system_id -> (manufacturer_slug, console_name) table.

    Uses platform file paths to trace system_id -> bios directory -> manufacturer page.
    """
    # Every console folder a filename sits in. A name in one folder only can
    # place a system, while a name in several says nothing (MiSTer's boot.rom lives
    # under a dozen consoles, and the last one written used to win).
    name_consoles: dict[str, set[tuple[str, str]]] = {}
    for mfr, consoles in manufacturers.items():
        for console, entries in consoles.items():
            for entry in entries:
                name_consoles.setdefault(entry["name"], set()).add((mfr, console))

    # Build normalized console name index for fuzzy matching
    console_norm: dict[str, tuple[str, str]] = {}
    for mfr, consoles in manufacturers.items():
        slug = mfr.lower().replace(" ", "-")
        mfr_norm = mfr.lower().replace(" ", "-")
        for console in consoles:
            norm = console.lower().replace(" ", "-")
            entry = (slug, console)
            console_norm[norm] = entry
            console_norm[f"{mfr_norm}-{norm}"] = entry
            # Short aliases: strip common manufacturer prefix words
            for prefix in (
                f"{mfr_norm}-",
                "nintendo-",
                "sega-",
                "sony-",
                "snk-",
                "nec-",
            ):
                if norm.startswith(prefix.replace(f"{mfr_norm}-", "")):
                    pass  # already covered by norm
                key = f"{prefix}{norm}"
                console_norm[key] = entry

    # Map system_id -> (manufacturer, console) via platform file entries
    copies = _copies_by_path(db)
    folders_by_name = _folders_by_name(manufacturers)
    pages: dict[str, tuple[str, str]] = {}
    for cov in coverages.values():
        config = cov["config"]
        for sys_id, system in config.get("systems", {}).items():
            if sys_id in pages:
                continue
            # Strategy 1: the one console folder the id spells (nintendo-nes,
            # NES). A copy of the disk system BIOS in the NES list does not
            # move the NES to the folder that copy sits in.
            # Strategy 2: the folder holding the files the system declares,
            # found by content, and most votes win. A bare name stands in only
            # where the collection files it in a single console.
            place = _folder_named(sys_id, folders_by_name) or _system_folder(
                system.get("files", []), db, name_consoles, sys_id, copies
            )
            if place is not None:
                mfr, console = place
                pages[sys_id] = (mfr.lower().replace(" ", "-"), console)
                continue
            # Strategy 3: fuzzy match system_id against console directory names
            if sys_id in console_norm:
                pages[sys_id] = console_norm[sys_id]
            else:
                # Try partial match: "nintendo-wii" matches "Wii" under "Nintendo"
                parts = sys_id.split("-")
                for i in range(len(parts)):
                    suffix = "-".join(parts[i:])
                    if suffix in console_norm:
                        pages[sys_id] = console_norm[suffix]
                        break

    # Systems only emulator profiles name (sega-naomi, commodore-pet): placed
    # by the files the profile files under them, as a platform's are. A
    # profile of one system files all of its entries there.
    for profile in (profiles or {}).values():
        systems = [str(sid) for sid in profile.get("systems") or []]
        for sys_id in systems:
            if sys_id in pages:
                continue
            files = [
                entry for entry in profile.get("files") or []
                if isinstance(entry, dict)
                and (entry.get("system") == sys_id or len(systems) == 1)
            ]
            place = _folder_named(sys_id, folders_by_name) or _system_folder(
                files, db, name_consoles, sys_id, copies
            )
            if place is not None:
                mfr, console = place
                pages[sys_id] = (mfr.lower().replace(" ", "-"), console)
            elif sys_id in console_norm:
                pages[sys_id] = console_norm[sys_id]
    return pages


def _timestamp() -> str:
    """The build time for data files (stats, API records), ISO 8601."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def data_as_of(moment: datetime | None = None) -> str:
    """The build date for a reader, in words, with the machine form beside it.
    A raw ISO stamp ("2026-10-22T22:43:08Z") closed the home page."""
    moment = moment or datetime.now(timezone.utc)
    return (f'<time datetime="{moment.strftime("%Y-%m-%dT%H:%M:%SZ")}">'
            f"Data as of {moment.day} {moment.strftime('%B %Y')}</time>")


def _date_line() -> str:
    """The date a page closes on, in the words of data_as_of(). The search
    does not read it: a query word such as the "2" of "playstation 2 bios"
    also matches the start of "2026", and every page closing on the date
    then held every word of the query."""
    return f'<div class="rb-timestamp" data-pagefind-ignore>{data_as_of()}.</div>'


# Home page


def _stat(value: str, label: str) -> list[str]:
    return [
        markup.block_open("div", 'class="rb-stat"'),
        f'<span class="rb-stat-value">{value}</span>',
        f'<span class="rb-stat-label">{label}</span>',
        "</div>",
        "",
    ]


def _group_members(coverages: dict, registry: dict, group: str) -> list[str]:
    """Registered platforms of a device group, by display name."""
    return sorted(
        (name for name in coverages if registry.get(name, {}).get("device_group") == group),
        key=lambda name: coverages[name]["platform"].casefold(),
    )


def _next_block(links: list[str]) -> list[str]:
    """Where to go from here, at the end of a page: a plain heading and a
    list. A tinted callout with a side stripe said the same as the pager."""
    return ["## Next steps", "", *(f"- {link}" for link in links), ""]


def _tiles(registry: dict, members: list[str], display: dict[str, str], prefix: str = "",
           group: str = "", eager: int = 0) -> list[str]:
    """The setup tiles of one device group: logo, name and the hardware it
    runs on, then the group's other tiles: a kind of device that runs one of
    the setups (Android handhelds, Linux handhelds)."""
    return markup.platform_tiles([
        *((display[name], f"{prefix}platforms/{name}.md",
           str(registry.get(name, {}).get("logo") or ""),
           GUIDES[name].runs_on or _runs_on(registry.get(name, {}), GUIDES[name]))
          for name in members),
        *((tile.name, f"{prefix}{tile.link}", tile.logo, tile.text)
          for tile in GROUP_TILES.get(group, ())),
    ], eager=eager)


def setup_picker(registry: dict, display: dict[str, str], prefix: str = "") -> list[str]:
    """Every setup as a tile, under the device group it belongs to. The
    setups alone in their group share one row: "MiSTer FPGA" above
    "MiSTer FPGA" said nothing. Only the first row of logos loads with the
    page: the 19 logos were most of the bytes of the home page."""
    lines: list[str] = []
    alone: list[str] = []
    for group, (label, _description) in DEVICE_GROUPS.items():
        members = _group_keys(registry, group, display)
        if len(members) == 1 and not GROUP_TILES.get(group):
            alone += members
        elif members:
            eager = 0 if lines else markup.FIRST_ROW_TILES
            lines += [f"**{label}**", "",
                      *_tiles(registry, members, display, prefix, group, eager)]
    if alone:
        eager = 0 if lines else markup.FIRST_ROW_TILES
        lines += ["**Other setups**", "", *_tiles(registry, alone, display, prefix, eager=eager)]
    return lines


def generate_home(
    db: dict,
    coverages: dict,
    profiles: dict,
    registry: dict | None = None,
    platforms_dir: str = "platforms",
) -> str:
    """The page someone lands on knowing nothing: what a BIOS file is,
    whether they need one, and the three steps to get the right ones.

    The figures about the collection, the cards to the deeper pages and the
    call for help sat below the steps and doubled the page: they are on the
    Explore index, one tab further. No date and no "next" box: the hero
    buttons say where to go."""
    registry = registry or load_platform_registry(platforms_dir)
    display = {key: load_platform_config(key, platforms_dir).get("platform", key)
               for key in registry}
    named = [n for n in ("RetroArch", "Batocera", "EmuDeck") if n in display.values()]
    others = setup_count() - len(named)
    works_with = ", ".join(named) + (f" and {others} more" if others else "")

    lines = [
        "# BIOS files for emulators",
        "",
        "Some consoles need a small program to start their games. It is called "
        "the **BIOS**. The emulator needs a copy of it. RetroBIOS puts the right copy "
        "in the right folder.",
        "",
        markup.button("Get the files", "which-pack.md", primary=True) + " "
        + markup.button("What is a BIOS?", "wiki/what-are-bios-files.md"),
        "",
        f"Free. No account. Works with {works_with}.",
        "",
        "- BIOS missing, even with the file there? "
        "[When a game does not start](wiki/troubleshooting.md)",
        "- Have a file? [Check it](files/index.md)",
        "",
        "## Is it needed? { #do-i-need-it }",
        "",
        "- **Yes**, if the emulator says a BIOS is missing.",
        "- **Yes** for PlayStation 2 and Neo Geo.",
        "- **Better with it** for Dreamcast: some games need it.",
        "- **Usually not** for NES, Super Nintendo, Mega Drive and Game Boy.",
        "",
        "Details: [Every console, one by one](systems/index.md)",
        "",
        "## Three steps",
        "",
        *markup.steps([
            "**Pick the device.** Its page gives one line to copy.",
            "**Paste it, press Enter.** Some setups have a ZIP.",
            "**Start a game.**",
        ]),
        *install_demo(),
        "## Pick the device { #pick-your-device }",
        "",
        *setup_picker(registry, display),
        "## Is it safe?",
        "",
        *(f"- {item}" for item in TRUST_ITEMS),
        "",
        "[How the command is checked](wiki/faq.md#is-piping-the-installer-into-a-shell-safe). "
        "Details: [Is it legal?](wiki/legal.md)",
        "",
    ]
    return "\n".join(lines) + "\n"


def generate_explore_index(db: dict, coverages: dict, profiles: dict) -> str:
    """The Explore tab opens here: where to look for one console, one
    emulator or one installer option, and the figures of the collection."""
    total_files = db.get("total_files", 0)
    total_size = db.get("total_size", 0)
    emulator_count = len(unique_emulator_profiles(profiles))
    lines = [
        "# Explore",
        "",
        "One console, one emulator, or one installer option: each has its page, "
        "with the files it needs and the code that reads them.",
        "",
        *markup.card_grid([
            ("Systems", ["What each console and computer needs, file by file.", "",
                         "[Browse the systems](systems/index.md)"]),
            ("Emulators", ["What each emulator reads, with the source code that reads it.", "",
                           "[Browse the emulators](emulators/index.md)"]),
            ("Installer options", [
                "Fewer files, one region, another folder, a check without download.", "",
                "[All installer options](wiki/installer.md)"]),
            ("How files are checked", [
                "Each setup checks its files its own way: by name, by MD5 or by SHA1.", "",
                "[How each platform checks files](wiki/verification-modes.md)"]),
            ("Data and API", ["Every file and hash as JSON, CSV and SQLite.", "",
                              "[Data and API](data.md)"]),
        ]),
        "## The collection",
        "",
        markup.block_open("div", 'class="rb-stats"'),
        "",
        *_stat(f"{total_files:,}", COLLECTION_FILES_LABEL),
        *_stat(str(setup_count()), "Setups supported"),
        *_stat(str(emulator_count), "Emulators documented"),
        *_stat(_fmt_size(total_size), "Size of the collection"),
        "</div>",
        "",
        composition_sentence(db),
        "",
        "## Help the project",
        "",
        "A file sent in, an emulator profile or a correction fills a gap for "
        "every setup at once. For contributors: [How to contribute](contributing.md).",
        "",
    ]
    return "\n".join(lines) + "\n"


def compute_stats(db: dict, coverages: dict, profiles: dict) -> dict:
    unique = unique_emulator_profiles(profiles)
    systems: set[str] = set()
    for p in unique.values():
        systems.update(p.get("systems", []))
    return {
        "schema_version": 1,
        "generated_at": _timestamp(),
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
    from generate_pack import platform_pack_prefix  # noqa: PLC0415

    stem = pack_name.removesuffix("_BIOS_Pack.zip")
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
    pack_name = release_record.pack_name_for(platform_name, record)
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
        display = config.get("platform", platform_name)
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
    pack_name = release_record.pack_name_for(platform_name, record or {})
    version = (
        _pack_version(pack_name, _pack_platforms(platform_name, record or {}, pack_name))
        if pack_name else ""
    ) or str(config.get("version") or "")
    if not version:
        return ""
    return f"{config.get('platform', platform_name)} {version.removeprefix('v')}"


def version_line(platform_name: str, record: dict, named: bool = False,
                 prefix: str = "../") -> str:
    """The version the pack fits, and what to do on another. *named* when
    the release line already named the pack's version."""
    made_from = setup_version(platform_name, record)
    other = other_version(platform_name, prefix)
    if named or not made_from:
        return other
    return f"Made for {made_from}. {other}"


# Why a setup has no ZIP, answered once on the FAQ.
NO_ZIP_FAQ = "wiki/faq.md#why-is-there-no-zip-for-my-setup"


def has_release_pack(platform_name: str) -> bool:
    """Whether a release publishes a ZIP for the platform (`release_pack`)."""
    return platform_name in _release_pack_platforms()


def no_zip_line(display: str) -> str:
    """The one line a setup without a release pack shows where the ZIP would be."""
    return f"No ZIP for {display}. The command installs every file and checks it."


def get_page_link(platform_name: str, prefix: str = "") -> str:
    """The platform's permanent download page, as a site link."""
    return f"{prefix}{release_record.GET_DIR}/{platform_name}.md"


def get_page_title(platform_name: str, display: str) -> str:
    """What a get/ page holds, by its name: the ZIP of a setup a release
    publishes one for, the files of any other. "Download KNULLI" read as
    the system's own download. A setup that is also an emulator (BizHawk)
    names it last: "BizHawk BIOS files" is the title of its emulator page."""
    kind = "BIOS pack" if has_release_pack(platform_name) else "BIOS files"
    if (siteinputs.current().emulators / f"{platform_name}.yml").is_file():
        return f"{kind} for {display}"
    return f"{display} {kind}"


def _unzip_into(platform_name: str, display: str, extract_to: str | None, parts: int) -> list[str]:
    """Where the ZIP is unzipped, on the get/ page. A folder the registry
    writes relative to the setup's own (`system/`, `bios/`) is named as the
    setup's, with the way to find it."""
    what = "them all" if parts > 1 else "it"
    if not _setup_relative(extract_to):
        return [f"- Unzip {what} into {_folder_words(display, extract_to)}.", ""]
    lead = GUIDES[platform_name].lead if platform_name in GUIDES else ""
    return [
        f"- Unzip {what} into {_folder_words(display, extract_to)}. "
        f"[Where is it?](../platforms/{platform_name}.md#where-the-files-go)",
        "",
        *([lead, ""] if lead else []),
    ]


def _setup_relative(extract_to: str | None) -> bool:
    """Whether the registry writes the folder relative to the setup's own
    (`system/`, `Firmware/`), not as a path the device reads."""
    return bool(extract_to) and not extract_to.startswith(("/", "~", "<"))


def _folder_words(display: str, extract_to: str | None) -> str:
    """The folder a pack or a copy goes into, in words: the device's path,
    or a folder of the setup named as the setup's."""
    if not extract_to:
        return "the BIOS folder"
    if _setup_relative(extract_to):
        return f"{display}'s `{extract_to.rstrip('/')}` folder"
    return f"`{extract_to}`"


def _pack_buttons(platform_name: str, label: str = "Pack", prefix: str = "../",
                  display: str | None = None) -> str:
    """The way to the platform's ZIP from its setup page: a button to its
    get/ page, the release it comes from, and the setup version its list
    was read at. "Does this pack fit my version?" is the first question a
    frontend user asks. A setup with no release pack gets the line that
    says so, and why."""
    if not has_release_pack(platform_name):
        display = display or load_platform_config(platform_name, str(siteinputs.current().platforms)).get(
            "platform", platform_name)
        return f"{no_zip_line(display)} [Why no ZIP?]({prefix}{NO_ZIP_FAQ})"
    record = release_record.load_advertised()
    buttons = download_links(
        platform_name,
        record,
        label,
        button=lambda text, url: markup.button(text, url, primary=True),
        page=get_page_link(platform_name, prefix),
    )
    released = release_line(platform_name, record)
    return "\n\n".join([buttons, *released,
                        version_line(platform_name, record, named=len(released) > 1,
                                     prefix=prefix)])


def generate_get_page(platform_name: str) -> str:
    """get/<platform>/: the address a link outside the site can keep.

    Every release deletes the previous tag, and with it each asset URL: six
    of the eight links a wiki had to our packs went dead. This page lists
    the files of the pack the current release holds, read from release.json,
    or the command when no release publishes one. The release process
    never touches it: committing release.json rebuilds it."""
    config = load_platform_config(platform_name, str(siteinputs.current().platforms))
    display = config.get("platform", platform_name)
    record = release_record.load_advertised()
    pack = release_record.pack_for(platform_name, record)
    released = has_release_pack(platform_name)
    title = get_page_title(platform_name, display)
    # The page changes with the release it lists: its tag is its date, the
    # one the sitemap gives (vYYYY.MM.DD).
    tag_date = re.fullmatch(r"v(\d{4})\.(\d{2})\.(\d{2})", str(record.get("tag", "")))
    if released and pack and tag_date:
        PAGE_DATA[f"{release_record.GET_DIR}/{platform_name}.md"] = {"dateModified": "-".join(tag_date.groups())}
    if released and pack and pack.get("assets"):
        description = (f"The BIOS pack for {display}: {_fmt_size(pack['download_size'])} to "
                       "download. The address stays the same and always gives the latest ZIP.")
    else:
        description = f"The BIOS files for {display}: one command installs and checks them."
    lines = [
        "---", "search: exclude", f"description: {json.dumps(description)}",
        *_parent_front_matter((display, f"/platforms/{platform_name}/")), "---", "",
        f"# {title}", "",
    ]
    if released and pack and pack.get("assets"):
        parts = len(pack["assets"])
        release = release_line(platform_name, record)
        extract_to = (load_platform_registry(str(siteinputs.current().platforms)).get(platform_name) or {}).get("extract_to")
        lines += [
            "This address stays the same. It always gives the latest ZIP.",
            "",
            asset_links(platform_name, record, REPO_URL, f"Download {display} Pack",
                        button=lambda text, url: markup.button(text, url, primary=True)),
            "",
            f"- {_fmt_size(pack['download_size'])} to download, "
            f"{_fmt_size(pack['extracted_size'])} once unzipped.",
            *(["- Both parts are needed." if parts == 2 else f"- All {parts} parts are needed."]
              if parts > 1 else []),
            *_unzip_into(platform_name, display, extract_to, parts),
            *(line for text in release for line in (text, "")),
            version_line(platform_name, record, named=len(release) > 1),
            "",
        ]
    elif released and record.get("tag"):
        lines += [
            f"No {display} ZIP yet. The next release has one. "
            "The command installs every file and checks it.",
            "",
            *_setup_routes(platform_name, display),
        ]
    elif released:
        lines += [
            "This address stays the same. It always gives the latest ZIP.",
            "",
            markup.button(f"Download {display} Pack", RELEASE_URL, primary=True),
            "",
        ]
    else:
        lines += [
            no_zip_line(display),
            "",
            *_setup_routes(platform_name, display),
            f"[Why no ZIP?](../{NO_ZIP_FAQ})",
            "",
        ]
    lines += _next_block([
        f"[{display}](../platforms/{platform_name}.md#install): the folder, "
        "and how to run the command on the device",
        "[All installer options](../wiki/installer.md)",
    ])
    return "\n".join(lines)


def generate_get_index() -> str:
    """get/: the permanent page of every setup, grouped as the home tiles
    are. A link trimmed to /get/ answered 404."""
    registry = load_platform_registry(str(siteinputs.current().platforms))
    lines = [
        "---", "search: exclude",
        'description: "The BIOS files of every setup, one page each. Each address stays the same."',
        "---", "",
        "# BIOS files by setup", "",
        "One page per setup. Its address stays the same, so it is the one to share.", "",
    ]
    for group, (label, _description) in DEVICE_GROUPS.items():
        names = [name for name, entry in registry.items() if entry.get("device_group") == group]
        if not names:
            continue
        lines += [f"## {label}", ""]
        for name in names:
            display = load_platform_config(name, str(siteinputs.current().platforms)).get("platform", name)
            lines.append(f"- [{get_page_title(name, display)}]({name}.md)")
        lines.append("")
    return "\n".join(lines)


# The home tile counts the whole collection. Labelled "Files" above a table
# of pack buttons, it read as what one pack contains.
COLLECTION_FILES_LABEL = "Files collected"


def composition_sentence(db: dict) -> str:
    comp = compute_composition(db)
    return (
        f"The collection holds {comp['systems']['files']:,} console and "
        f"computer system files, {comp['arcade']['files']:,} arcade ROM sets "
        f"(`Arcade/`), and {comp['game_data']['files']:,} game and engine "
        "data files (`Game Engines/`, `RPG Maker/`, `ScummVM/` and the game "
        "publishers' trees). No pack holds "
        "them all: each carries what its platform's emulators load."
    )


def generate_stats(stats: dict) -> str:
    return json.dumps(stats, indent=2) + "\n"


HASH_ALGORITHMS = ("sha1", "sha256", "md5", "crc32")


def _hash_values(value: object) -> list[str]:
    """Every accepted value of one hash field, lowercase.

    A field holds one value, a list of accepted revisions, or (Recalbox) a
    comma-joined string: an exact lookup missed all but the first form.
    """
    if value is None:
        return []
    items = value if isinstance(value, (list, tuple)) else str(value).split(",")
    return sorted({str(item).strip().lower() for item in items if str(item).strip()})


def _accepted_hash_rows(platform_files: list[dict], emulator_items: list[dict]) -> list[dict]:
    """One row per accepted hash value, for both layers, lookup-ready."""
    rows: list[dict] = []
    for row in platform_files:
        for algorithm in HASH_ALGORITHMS:
            for value in _hash_values(row.get(f"{algorithm}_raw", row.get(algorithm))):
                rows.append({
                    "layer": "platform", "owner": row["platform_id"],
                    "system": row["system"], "name": row["name"],
                    "path": row["destination"], "algorithm": algorithm, "value": value,
                })
    for item in emulator_items:
        for entry in item["profile"].get("files", []) or []:
            if not isinstance(entry, dict):
                continue
            for algorithm in HASH_ALGORITHMS:
                for value in _hash_values(entry.get(algorithm)):
                    rows.append({
                        "layer": "emulator", "owner": item["id"],
                        "system": _json_text(entry.get("system")),
                        "name": entry.get("name", ""), "path": entry.get("path", "") or "",
                        "algorithm": algorithm, "value": value,
                    })
            # Members of an archive: MAME and FBNeo hash the ROMs inside the
            # set, never the set. Left out, a loose nmk004.bin (crc32
            # 83b6f611) found no row while the site search found it.
            archive = entry.get("name", "")
            for member in entry.get("contents") or []:
                if not isinstance(member, dict) or not member.get("name"):
                    continue
                for algorithm in HASH_ALGORITHMS:
                    for value in _hash_values(member.get(algorithm)):
                        rows.append({
                            "layer": "emulator", "owner": item["id"],
                            "system": _json_text(entry.get("system")),
                            "name": str(member["name"]), "path": f"{archive}/{member['name']}",
                            "algorithm": algorithm, "value": value,
                        })
    rows.sort(key=lambda r: (r["layer"], r["owner"], r["name"], r["algorithm"], r["value"]))
    return rows


def _csv_document(fieldnames: list[str], rows: list[dict]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n"
    )
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_outcomes(
    coverage: dict, sha1_by_path: dict[str, str]
) -> Callable[[str, str], dict]:
    """For each declared entry, in declaration order: what verify found.

    Returns a function of (system, name) giving the next outcome for that
    pair: status, category, the collection path that answers the entry and
    that file's sha1. The CSV gave the declaration and nothing about it.
    """
    details: dict[tuple[str, str], list[dict]] = {}
    for detail in coverage.get("details") or []:
        details.setdefault((detail.get("system", ""), detail.get("name", "")), []).append(detail)
    taken: dict[tuple[str, str], int] = {}

    def outcome(system: str, name: str) -> dict:
        found = details.get((system, name)) or [{}]
        nth = taken.get((system, name), 0)
        taken[(system, name)] = nth + 1
        detail = found[min(nth, len(found) - 1)]
        path = str(detail.get("path") or "") if detail.get("status") != "missing" else ""
        return {
            "status": detail.get("status", ""),
            "category": detail.get("category", ""),
            "collection_path": path,
            "resolved_sha1": sha1_by_path.get(path, "") if path else "",
        }
    return outcome


def _sha1_by_path(db: dict | None) -> dict[str, str]:
    return {str(e.get("path", "")): sha1 for sha1, e in ((db or {}).get("files") or {}).items()}


@functools.lru_cache(maxsize=1)
def _contract_keys() -> frozenset[str]:
    """The top-level keys platform.schema.json allows in a platform's list."""
    schema = json.loads((_REPO_ROOT / "schemas" / "platform.schema.json").read_text(encoding="utf-8"))
    return frozenset(schema.get("properties") or {})


def _split_contract(config: dict) -> tuple[dict, dict]:
    """The list, valid against platform.schema.json, and the registry entry.

    load_platform_config merges the registry into the list: `install`,
    `logo`, `scraper` and `_key` made all 18 contracts fail the published
    schema. They stay published, beside the contract.
    """
    allowed = _contract_keys()
    contract = {key: value for key, value in config.items() if key in allowed}
    # platform_system and platform_cores are the resolver's copies of the key
    # each entry sits under and of that system's cores.
    if isinstance(contract.get("systems"), dict):
        contract["systems"] = {
            sys_id: {
                **system,
                "files": [
                    {
                        k: v
                        for k, v in f.items()
                        if k not in ("platform_system", "platform_cores")
                    }
                    for f in system["files"]
                ],
            }
            if isinstance(system, dict) and system.get("files")
            else system
            for sys_id, system in contract["systems"].items()
        }
    registry = {key: value for key, value in config.items()
                if key not in allowed and key != "_key"}
    # The merged config gives a child its parent's release_pack: Lakka and
    # RetroPie said true in the API while every page said they had no ZIP.
    # The registry's own entry decides, as it does for the pages.
    released = config.get("_key") in _release_pack_platforms()
    if released or "release_pack" in registry:
        registry["release_pack"] = released
    return contract, registry


def _release_pack_platforms() -> frozenset[str]:
    return _release_packs_in(str(siteinputs.current().platforms))


@functools.lru_cache(maxsize=None)
def _release_packs_in(platforms_dir: str) -> frozenset[str]:
    return frozenset(list_release_pack_platforms(platforms_dir))


# Per-entry fields a folder check needs beyond the hashes: an md5 is a ZIP
# member's when zipped_file is set, and a CSV without it judged 106 good
# Batocera files wrong.
ENTRY_EXPORT_FIELDS = (
    "zipped_file", "hash_match_mandatory", "mandatory_declared", "curated",
    "shared_group", "mirror_of", "zip_digest",
)


def _platform_export_rows(
    coverages: dict, db: dict | None = None,
) -> tuple[list[dict], list[dict]]:
    """Normalized platform summaries and one row per declared file."""
    items: list[dict] = []
    file_rows: list[dict] = []
    sha1_by_path = _sha1_by_path(db)
    for key, coverage in sorted(coverages.items()):
        config = coverage["config"]
        outcome = _verify_outcomes(coverage, sha1_by_path)
        contract, registry = _split_contract(config)
        items.append({
            "id": key,
            "name": coverage["platform"],
            "coverage": {
                field: coverage.get(field, 0)
                for field in (
                    "total", "present", "verified", "untested", "missing",
                    "core_present", "core_missing", "core_unsourceable",
                )
            },
            "contract": contract,
            "registry": registry,
        })
        for system_id, system in sorted(config.get("systems", {}).items()):
            for entry in system.get("files", []) or []:
                file_rows.append({
                    "platform_id": key,
                    "platform": coverage["platform"],
                    "system": system_id,
                    "name": entry.get("name", ""),
                    "destination": entry.get(
                        "destination", entry.get("dest", entry.get("name", ""))
                    ),
                    "required": bool(entry.get("required", True)),
                    "region": _json_text(entry.get("region")),
                    "selection_slot": _json_text(entry.get("selection_slot")),
                    "size": entry.get("size"),
                    "sha1": _json_text(entry.get("sha1")),
                    "sha256": _json_text(entry.get("sha256")),
                    "md5": _json_text(entry.get("md5")),
                    "crc32": _json_text(entry.get("crc32")),
                    **{field: _export_flag(entry.get(field)) for field in ENTRY_EXPORT_FIELDS},
                    **outcome(system_id, entry.get("name", "")),
                })
    return items, file_rows


def _export_flag(value: object) -> object:
    """A per-entry field as CSV and SQLite hold it: booleans stay booleans,
    an absent field is empty."""
    if value is None:
        return ""
    return value if isinstance(value, bool) else str(value)


def _emulator_export_items(profiles: dict) -> list[dict]:
    return [
        {"id": key, "profile": profile}
        for key, profile in sorted(profiles.items())
    ]


def build_emulator_gap_report(
    profiles: dict,
    coverages: dict,
    db: dict,
    data_names: set[str] | None = None,
) -> dict:
    """Files a core loads that no platform declares, per emulator profile.

    The gap analysis page and the published gaps export must not compute this
    twice and drift. Both read this one report.
    """
    from common import _norm_system_id, merged_platform_declarations
    from cross_reference import cross_reference as run_cross_reference

    # Enriched with alias resolution, with each declaration's size and slot:
    # a name alone settled DOSBox's 32 KiB SC-55 ROM1.BIN on Galaksija's.
    all_declared = merged_platform_declarations(
        [cov["config"] for cov in coverages.values()], db
    )
    declared: dict[str, set[str]] = {}
    for _name, cov in coverages.items():
        config = cov["config"]
        for sys_id, system in config.get("systems", {}).items():
            for fe in system.get("files", []):
                fname = fe.get("name", "")
                if fname:
                    declared.setdefault(_norm_system_id(sys_id), set()).add(fname)

    unique_profiles = {
        k: v
        for k, v in profiles.items()
        if v.get("type") != "alias" and v.get("role") != "test"
    }
    from common import merged_standalone_set, platform_declarations
    from validation import case_folded_slots

    # The command line passes these too: without them a RetroBat file named
    # 32X_G_BIOS.BIN read as missing for a core opening 32X_G_BIOS.bin.
    folded = frozenset().union(*(
        case_folded_slots(cov["config"], platform_declarations(cov["config"], db))
        for cov in coverages.values()
    ))
    return run_cross_reference(
        unique_profiles, declared, db,
        data_names=data_names, all_declared=all_declared,
        standalone_cores=merged_standalone_set(
            cov["config"] for cov in coverages.values()
        ),
        folded_slots=folded,
    )


def _gap_export_rows(
    coverages: dict, gap_report: dict | None = None, db: dict | None = None,
    profiles: dict | None = None,
) -> list[dict]:
    """Every gap the site reports, both layers, in one table.

    ``platform`` rows are anomalies against a platform's own BIOS list.
    ``emulator`` rows are files a profiled core loads that no platform
    declares, which is the larger number the gap analysis page leads with.
    A `layer` column keeps the two apart instead of publishing only one.
    """
    rows: list[dict] = []
    sha1_by_path = _sha1_by_path(db)
    for key, coverage in sorted(coverages.items()):
        for detail in coverage.get("details", []):
            if detail.get("status") == "ok" and not detail.get("discrepancy"):
                continue
            path = str(detail.get("path") or "") if detail.get("status") != "missing" else ""
            rows.append({
                "category": detail.get("category", "bios"),
                "collection_path": path,
                "resolved_sha1": sha1_by_path.get(path, "") if path else "",
                "layer": "platform",
                "platform_id": key,
                "platform": coverage["platform"],
                "emulator": "",
                "system": detail.get("system", ""),
                "name": detail.get("name", ""),
                "status": detail.get("status", ""),
                "required": bool(detail.get("required", True)),
                "in_repo": "",
                "reason": detail.get("reason", ""),
                "discrepancy": detail.get("discrepancy", ""),
                "destination": detail.get("destination", ""),
                "expected": "",
            })
    for emu_key, data in sorted((gap_report or {}).items()):
        systems = ";".join(str(s) for s in data.get("systems", []) or [])
        categories = _profile_categories((profiles or {}).get(emu_key) or {})
        for gap in data.get("gap_details", []) or []:
            rows.append({
                "category": categories.get(
                    (gap.get("name", ""), gap.get("path") or gap.get("name", "")), ""),
                "collection_path": "",
                "resolved_sha1": "",
                "layer": "emulator",
                "platform_id": "",
                "platform": "",
                "emulator": data.get("emulator", emu_key),
                "system": systems,
                "name": gap.get("name", ""),
                # A file the emulator's own package installs is not one to
                # find: its own status, as unsourceable has.
                "status": (
                    "bundled" if gap.get("bundled") and gap.get("source") == "missing"
                    else gap.get("source", "")
                ),
                "required": bool(gap.get("required", False)),
                "in_repo": bool(gap.get("in_repo", False)),
                "reason": gap.get("note", ""),
                "discrepancy": "",
                # What a contributor needs to supply the right revision and
                # put it in the right place: the gaps table gave neither.
                "destination": gap.get("path") or gap.get("name", ""),
                "expected": gap.get("identity", ""),
            })
        for entry in data.get("unsourceable", []) or []:
            rows.append({
                "category": categories.get(
                    (entry.get("name", ""), entry.get("path") or entry.get("name", "")), ""),
                "collection_path": "",
                "resolved_sha1": "",
                "layer": "emulator",
                "platform_id": "",
                "platform": "",
                "emulator": data.get("emulator", emu_key),
                "system": systems,
                "name": entry.get("name", ""),
                "status": "unsourceable",
                "required": bool(entry.get("required", False)),
                "in_repo": False,
                "reason": entry.get("reason", ""),
                "discrepancy": "",
                "destination": entry.get("path") or entry.get("name", ""),
                "expected": "",
            })
    # Two declarations that differ only in what the row does not carry are
    # one row: AmberELEC's hardwareconfig.xml was printed twice.
    unique: dict[tuple, dict] = {}
    for row in rows:
        unique.setdefault(tuple(sorted((k, str(v)) for k, v in row.items())), row)
    return list(unique.values())


def _profile_categories(profile: dict) -> dict[tuple[str, str], str]:
    """(name, path) -> the category a profile gives the entry, bios by default."""
    found: dict[tuple[str, str], str] = {}
    for entry in profile.get("files") or []:
        if isinstance(entry, dict) and entry.get("name"):
            name = str(entry["name"])
            found.setdefault((name, str(entry.get("path") or name)),
                             str(entry.get("category") or "bios"))
    return found


def _cross_reference_export_rows(coverages: dict, profiles: dict) -> list[dict]:
    from common import resolve_platform_cores

    unique = {
        key: value
        for key, value in profiles.items()
        if value.get("type") != "alias" and value.get("role") != "test"
    }
    rows: list[dict] = []
    for platform_id, coverage in sorted(coverages.items()):
        for profile_id in sorted(resolve_platform_cores(coverage["config"], unique)):
            profile = unique[profile_id]
            cores = profile.get("cores") or [profile_id]
            systems = profile.get("systems") or [""]
            for core in cores:
                for system in systems:
                    rows.append({
                        "platform_id": platform_id,
                        "platform": coverage["platform"],
                        "profile_id": profile_id,
                        "emulator": profile.get("emulator", profile_id),
                        "core": core,
                        "system": system,
                        "classification": profile.get("core_classification", ""),
                        "type": profile.get("type", ""),
                        "source": _json_text(profile.get("source")),
                        "upstream": _json_text(profile.get("upstream")),
                        "profiled_commit": _json_text(profile.get("source_commit", "")),
                        "file_count": len(profile.get("files", []) or []),
                    })
    return rows


def _write_sqlite_export(
    destination: Path,
    db: dict,
    platform_items: list[dict],
    platform_files: list[dict],
    emulator_items: list[dict],
    gap_rows: list[dict],
) -> None:
    """Build a queryable, deterministic snapshot without embedding binaries."""
    temp_dir = Path("tmp") / "site"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / f"retrobios-{os.getpid()}.sqlite"
    temp_path.unlink(missing_ok=True)
    destination.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(temp_path)
    try:
        connection.executescript("""
            PRAGMA journal_mode = OFF;
            PRAGMA synchronous = OFF;
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE files (
                sha1 TEXT PRIMARY KEY, path TEXT NOT NULL, name TEXT NOT NULL,
                size INTEGER NOT NULL, md5 TEXT NOT NULL, sha256 TEXT NOT NULL,
                crc32 TEXT NOT NULL, adler32 TEXT NOT NULL
            );
            CREATE TABLE file_provenance (
                sha1 TEXT NOT NULL, catalog TEXT NOT NULL, details_json TEXT NOT NULL,
                PRIMARY KEY (sha1, catalog),
                FOREIGN KEY (sha1) REFERENCES files(sha1)
            );
            CREATE TABLE platforms (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, total INTEGER NOT NULL,
                present INTEGER NOT NULL, verified INTEGER NOT NULL,
                missing INTEGER NOT NULL, contract_json TEXT NOT NULL
            );
            CREATE TABLE platform_files (
                platform_id TEXT NOT NULL, system TEXT NOT NULL, name TEXT NOT NULL,
                destination TEXT NOT NULL, required INTEGER NOT NULL,
                region TEXT, selection_slot TEXT, size INTEGER,
                sha1 TEXT, sha256 TEXT, md5 TEXT, crc32 TEXT,
                status TEXT, category TEXT, collection_path TEXT, resolved_sha1 TEXT,
                zipped_file TEXT, hash_match_mandatory INTEGER, mandatory_declared INTEGER,
                curated INTEGER, shared_group TEXT, mirror_of TEXT, zip_digest TEXT
            );
            CREATE TABLE emulators (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT,
                classification TEXT, source TEXT, upstream TEXT,
                source_commit TEXT, profile_json TEXT NOT NULL
            );
            CREATE TABLE emulator_systems (
                emulator_id TEXT NOT NULL, system TEXT NOT NULL,
                PRIMARY KEY (emulator_id, system)
            );
            CREATE TABLE emulator_files (
                emulator_id TEXT NOT NULL, system TEXT, name TEXT NOT NULL,
                path TEXT, required INTEGER NOT NULL, mode TEXT, region TEXT,
                size TEXT, sha1 TEXT, sha256 TEXT, md5 TEXT, crc32 TEXT,
                source_ref TEXT
            );
            CREATE TABLE gaps (
                layer TEXT NOT NULL, platform_id TEXT, platform TEXT,
                emulator TEXT, system TEXT, name TEXT NOT NULL,
                status TEXT NOT NULL, required INTEGER NOT NULL,
                in_repo TEXT, reason TEXT, discrepancy TEXT,
                destination TEXT, expected TEXT, category TEXT,
                collection_path TEXT, resolved_sha1 TEXT
            );
            CREATE TABLE accepted_hashes (
                layer TEXT NOT NULL, owner TEXT NOT NULL, system TEXT,
                name TEXT NOT NULL, path TEXT, algorithm TEXT NOT NULL,
                value TEXT NOT NULL
            );
            CREATE INDEX accepted_hashes_value_idx ON accepted_hashes(algorithm, value);
            CREATE INDEX files_name_idx ON files(name);
            CREATE INDEX files_md5_idx ON files(md5);
            CREATE INDEX files_sha256_idx ON files(sha256);
            CREATE INDEX platform_files_name_idx ON platform_files(name);
            CREATE INDEX emulator_files_name_idx ON emulator_files(name);
            CREATE INDEX gaps_status_idx ON gaps(layer, status);
        """)
        commit = _source_commit()
        metadata = {
            "schema_version": "1",
            "generated_at": str(db.get("generated_at") or _timestamp()),
            **({"commit": commit} if commit else {}),
            "source": REPO_URL,
            "scope": "metadata only, no BIOS or firmware payload bytes",
            "license": DATA_LICENSE,
        }
        connection.executemany(
            "INSERT INTO metadata(key, value) VALUES (?, ?)",
            sorted(metadata.items()),
        )
        for sha1, entry in sorted(db.get("files", {}).items()):
            connection.execute(
                "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    sha1, entry.get("path", ""), entry.get("name", ""),
                    entry.get("size", 0), entry.get("md5", ""),
                    entry.get("sha256", ""), entry.get("crc32", ""),
                    entry.get("adler32", ""),
                ),
            )
            for catalog, details in sorted((entry.get("provenance") or {}).items()):
                connection.execute(
                    "INSERT INTO file_provenance VALUES (?, ?, ?)",
                    (sha1, catalog, _json_text(details)),
                )
        for item in platform_items:
            coverage = item["coverage"]
            connection.execute(
                "INSERT INTO platforms VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    item["id"], item["name"], coverage.get("total", 0),
                    coverage.get("present", 0), coverage.get("verified", 0),
                    coverage.get("missing", 0), _json_text(item["contract"]),
                ),
            )
        connection.executemany(
            "INSERT INTO platform_files VALUES "
            "(:platform_id, :system, :name, :destination, :required, :region, "
            ":selection_slot, :size, :sha1, :sha256, :md5, :crc32, :status, :category, "
            ":collection_path, :resolved_sha1, :zipped_file, :hash_match_mandatory, "
            ":mandatory_declared, :curated, :shared_group, :mirror_of, :zip_digest)",
            platform_files,
        )
        for item in emulator_items:
            profile = item["profile"]
            connection.execute(
                "INSERT INTO emulators VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    item["id"], profile.get("emulator", item["id"]),
                    profile.get("type", ""),
                    profile.get("core_classification", ""),
                    _json_text(profile.get("source")),
                    _json_text(profile.get("upstream")),
                    # source_commit is a string or, when the builds live in
                    # separate repositories, an object keyed by build mode.
                    # SQLite cannot bind the object form.
                    _json_text(profile.get("source_commit", "")),
                    _json_text(profile),
                ),
            )
            for system in sorted(set(profile.get("systems", []) or [])):
                connection.execute(
                    "INSERT INTO emulator_systems VALUES (?, ?)",
                    (item["id"], system),
                )
            for entry in profile.get("files", []) or []:
                connection.execute(
                    "INSERT INTO emulator_files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        item["id"], _json_text(entry.get("system")),
                        entry.get("name", ""), entry.get("path", ""),
                        int(bool(entry.get("required", False))),
                        entry.get("mode", ""), _json_text(entry.get("region")),
                        _json_text(entry.get("size")), _json_text(entry.get("sha1")),
                        _json_text(entry.get("sha256")), _json_text(entry.get("md5")),
                        _json_text(entry.get("crc32")),
                        _json_text(entry.get("source_ref")),
                    ),
                )
        connection.executemany(
            "INSERT INTO accepted_hashes VALUES "
            "(:layer, :owner, :system, :name, :path, :algorithm, :value)",
            _accepted_hash_rows(platform_files, emulator_items),
        )
        connection.executemany(
            "INSERT INTO gaps VALUES "
            "(:layer, :platform_id, :platform, :emulator, :system, :name, "
            ":status, :required, :in_repo, :reason, :discrepancy, :destination, :expected, "
            ":category, :collection_path, :resolved_sha1)",
            gap_rows,
        )
        connection.commit()
        connection.execute("VACUUM")
    finally:
        connection.close()
    os.replace(temp_path, destination)


def write_single_item(
    path: Path, kind: str, item: dict, generated_at: str, commit: str = "",
) -> None:
    """One item in the envelope of its collection, for a page to link."""
    path.parent.mkdir(parents=True, exist_ok=True)
    write_if_changed(
        str(path),
        json.dumps(
            {"schema_version": 1, "generated_at": generated_at,
             **({"commit": commit} if commit else {}), "kind": kind,
             "count": 1, "items": [item]},
            indent=2, sort_keys=True, ensure_ascii=False, default=str,
        ) + "\n",
    )


def system_export_item(slug: str, manufacturer: str, consoles: dict[str, list]) -> dict:
    """A system page's files by console, with the hashes its cards show."""
    fields = ("name", "path", "size", "sha1", "md5", "sha256", "crc32")
    return {
        "id": slug,
        "name": manufacturer,
        "consoles": {
            console: [
                {field: entry[field] for field in fields if entry.get(field) is not None}
                for entry in sorted(entries, key=lambda e: (e.get("name", ""), e.get("sha1", "")))
            ]
            for console, entries in sorted(consoles.items())
        },
    }


@functools.lru_cache(maxsize=1)
def _source_commit() -> str:
    """The commit of the checkout the site is built from, empty outside one."""
    import subprocess

    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=_REPO_ROOT,
            capture_output=True, text=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"  no commit recorded in the exports: {error}", file=sys.stderr)
        return ""
    commit = result.stdout.strip()
    return commit if re.fullmatch(r"[0-9a-f]{40}", commit) else ""


# One row per dump a catalog describes and the collection lacks: the list
# the provenance page publishes under "Wanted".
WANTED_FIELDS = ("catalog", "dat", "name", "description", "size", "crc32", "md5", "sha1")


def _provenance_wanted_rows(db: dict) -> list[dict]:
    """The Wanted list of the provenance page, as rows. A dump the
    collection already produces (derivable.json) is not wanted."""
    derivable = load_derivable()
    rows: list[dict] = []
    for catalog, data in build_report(db, load_provenance_snapshots()).items():
        for entry in data["missing"]:
            if (entry.get("sha1") or "").lower() in derivable:
                continue
            for dat in entry.get("dats") or [entry.get("dat", "")]:
                rows.append({
                    "catalog": catalog, "dat": dat,
                    **{f: _json_text(entry.get(f)) for f in WANTED_FIELDS[2:]},
                })
    rows.sort(key=lambda r: (r["catalog"], r["dat"], r["name"], r["sha1"]))
    return rows


def generate_data_exports(
    docs: Path,
    db: dict,
    coverages: dict,
    profiles: dict,
    stats: dict,
    gap_report: dict | None = None,
    consumers: FileConsumers | None = None,
) -> list[dict]:
    """Create versioned static API, CSV and SQLite metadata snapshots."""
    api = docs / "api" / "v1"
    downloads = docs / "downloads"
    schemas_dest = api / "schemas"
    for directory in (api, downloads, schemas_dest):
        directory.mkdir(parents=True, exist_ok=True)

    generated_at = str(db.get("generated_at") or _timestamp())
    # The revision the data was read at: a tool comparing two downloads
    # could not tell which commit each came from.
    commit = _source_commit()
    stamp = {"commit": commit} if commit else {}
    platform_items, platform_files = _platform_export_rows(coverages, db)
    emulator_items = _emulator_export_items(profiles)
    gap_rows = _gap_export_rows(coverages, gap_report, db, profiles)
    cross_rows = _cross_reference_export_rows(coverages, profiles)

    members = data_directory_members()
    locations = file_location_items(db, profiles, members)
    wanted = _provenance_wanted_rows(db)
    envelopes = {
        "platforms.json": ("platforms", platform_items),
        "emulators.json": ("emulators", emulator_items),
        "gaps.json": ("verification-and-coverage-gaps", gap_rows),
        "file-locations.json": ("file-locations", locations),
    }
    write_lookup_shards(
        api, file_lookup_records(db, coverages, profiles, locations, members, consumers,
                                 retired_files.load(_REPO_ROOT / "retired.json"), wanted),
        generated_at, commit,
    )
    for filename, (kind, items) in envelopes.items():
        document = {
            "schema_version": 1,
            "generated_at": generated_at,
            **stamp,
            "kind": kind,
            "count": len(items),
            "items": items,
        }
        write_if_changed(
            str(api / filename),
            json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
    # One platform without the others, as api/v1/emulators/<id>.json is one
    # profile: platforms.json is 2.8 MB for twelve platforms.
    for item in platform_items:
        write_single_item(api / "platforms" / f"{item['id']}.json",
                          "platforms", item, generated_at, commit)
    write_if_changed(str(api / "stats.json"), generate_stats(stats))
    write_if_changed(
        str(api / "database.json"),
        json.dumps(db, ensure_ascii=False, indent=2) + "\n",
    )

    # Every schema the published files are written against, the manifests'
    # too: an integrator had the platform's list and not what the pack writes.
    for schema_path in sorted((_REPO_ROOT / "schemas").glob("*.schema.json")):
        shutil.copy2(schema_path, schemas_dest / schema_path.name)
        _record(schemas_dest / schema_path.name)

    manifest_assets = _publish_manifests(api)
    for filename, (kind, items) in {
        "systems.json": ("system-index", system_index_items(db, coverages, profiles)),
        "cores.json": ("core-index", core_index_items(profiles)),
    }.items():
        write_if_changed(str(api / filename), json.dumps({
            "schema_version": 1, "generated_at": generated_at, **stamp,
            "kind": kind, "count": len(items), "items": items,
        }, ensure_ascii=False, indent=2, sort_keys=True) + "\n")

    file_rows = []
    for sha1, entry in sorted(db.get("files", {}).items()):
        file_rows.append({
            "sha1": sha1,
            "path": entry.get("path", ""),
            "name": entry.get("name", ""),
            "size": entry.get("size", 0),
            "md5": entry.get("md5", ""),
            "sha256": entry.get("sha256", ""),
            "crc32": entry.get("crc32", ""),
            "adler32": entry.get("adler32", ""),
            "provenance_catalogs": ";".join(
                sorted((entry.get("provenance") or {}).keys())
            ),
        })
    write_if_changed(str(downloads / "retrobios.dat"), collection_dat(db, generated_at))
    platform_dats = _write_platform_dats(downloads / "dat", db, members, generated_at)
    write_if_changed(
        str(downloads / "files.csv"),
        _csv_document(
            [
                "sha1", "path", "name", "size", "md5", "sha256",
                "crc32", "adler32", "provenance_catalogs",
            ],
            file_rows,
        ),
    )
    write_if_changed(
        str(downloads / "platform-files.csv"),
        _csv_document(
            [
                "platform_id", "platform", "system", "name", "destination",
                "required", "region", "selection_slot", "size", "sha1",
                "sha256", "md5", "crc32", "status", "category",
                "collection_path", "resolved_sha1", *ENTRY_EXPORT_FIELDS,
            ],
            platform_files,
        ),
    )
    write_if_changed(
        str(downloads / "cross-reference.csv"),
        _csv_document(
            [
                "platform_id", "platform", "profile_id", "emulator", "core",
                "system", "classification", "type", "source", "upstream",
                "profiled_commit", "file_count",
            ],
            cross_rows,
        ),
    )
    write_if_changed(
        str(downloads / "gaps.csv"),
        _csv_document(
            [
                "layer", "platform_id", "platform", "emulator", "system",
                "name", "status", "required", "in_repo", "reason",
                "discrepancy", "destination", "expected", "category",
                "collection_path", "resolved_sha1",
            ],
            gap_rows,
        ),
    )
    write_if_changed(
        str(downloads / "accepted-hashes.csv"),
        _csv_document(
            ["layer", "owner", "system", "name", "path", "algorithm", "value"],
            _accepted_hash_rows(platform_files, emulator_items),
        ),
    )
    _write_sqlite_export(
        downloads / "retrobios.sqlite", db, platform_items, platform_files,
        emulator_items, gap_rows,
    )
    _record(downloads / "retrobios.sqlite")
    write_if_changed(
        str(downloads / "provenance-wanted.csv"),
        _csv_document(list(WANTED_FIELDS), wanted),
    )

    assets = [
        (api / "database.json", "Content database", "application/json", "schemas/database.schema.json"),
        (api / "platforms.json", "Platform contracts", "application/json", "schemas/site-api-envelope.schema.json"),
        (api / "emulators.json", "Emulator profiles", "application/json", "schemas/site-api-envelope.schema.json"),
        (api / "gaps.json", "Verification and coverage gaps", "application/json", "schemas/site-api-envelope.schema.json"),
        (api / "file-locations.json", "Where each file's card is, by SHA1", "application/json", "schemas/site-api-envelope.schema.json"),
        (api / "stats.json", "Project statistics", "application/json", "schemas/stats.schema.json"),
        (api / "systems.json", "System ids, their names and sections", "application/json",
         "schemas/site-api-envelope.schema.json"),
        (api / "cores.json", "Core names and the profile each one is", "application/json",
         "schemas/site-api-envelope.schema.json"),
        *manifest_assets,
        (downloads / "files.csv", "File hashes CSV", "text/csv", None),
        (downloads / "retrobios.dat", "Collection DAT (Logiqx XML, for clrmamepro and RomVault)",
         "application/xml", None),
        *((path, f"Setup DAT: {path.stem}", "application/xml", None) for path in platform_dats),
        (downloads / "platform-files.csv", "Platform declarations CSV", "text/csv", None),
        (downloads / "cross-reference.csv", "Cross-reference CSV", "text/csv", None),
        (downloads / "gaps.csv", "Verification and coverage gaps CSV", "text/csv", None),
        (downloads / "accepted-hashes.csv", "Accepted hashes, one row per value", "text/csv", None),
        (downloads / "provenance-wanted.csv", "Catalogued dumps the collection lacks", "text/csv", None),
        (downloads / "retrobios.sqlite", "SQLite snapshot", "application/vnd.sqlite3", None),
        *([(downloads / "measurements.sqlite", "Core probe measurements (SQLite)",
            "application/vnd.sqlite3", None)]
          if (downloads / "measurements.sqlite").is_file() else []),
    ]
    catalog_items: list[dict] = []
    published: list[dict] = []
    for path, title, media_type, schema in assets:
        relative = path.relative_to(docs).as_posix()
        item = {
            "title": title,
            "url": relative,
            "media_type": media_type,
            "bytes": path.stat().st_size,
            "sha256": _sha256_path(path),
        }
        if schema:
            item["schema"] = schema
        catalog_items.append(item)
        # In the catalog both references resolve against the catalog's own
        # URL, as RFC 3986 clients do: `url` was relative to the site root
        # and `schema` to api/v1/, so no single base resolved both.
        published.append({
            **item,
            "url": os.path.relpath(path, api).replace(os.sep, "/"),
        })
    catalog = {
        "schema_version": 1,
        "generated_at": generated_at,
        **stamp,
        "kind": "catalog",
        "license": DATA_LICENSE,
        "count": len(published),
        "items": published,
    }
    write_if_changed(
        str(api / "catalog.json"),
        json.dumps(catalog, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    # api/v1/ itself is a folder GitHub Pages answers with the 404 page: the
    # entry point is a document of its own, naming where to start.
    entry_points = [
        {"title": "Catalog", "url": "catalog.json",
         "description": "Each dataset, manifest, export and download with its size, "
                        "SHA256 and schema. The one-item documents of emulators/, "
                        "platforms/, systems/ and lookup/ are not listed."},
        {"title": "System ids", "url": "systems.json",
         "description": "Each system id with its name and the section holding its files."},
        {"title": "Core names", "url": "cores.json",
         "description": "Each core name and alias with the profile it designates."},
        {"title": "Schemas", "url": "schemas/site-api-envelope.schema.json",
         "description": "The envelope every JSON document of api/v1 shares."},
    ]
    write_if_changed(str(api / "index.json"), json.dumps({
        "schema_version": 1, "generated_at": generated_at, **stamp,
        "kind": "index", "license": DATA_LICENSE,
        "count": len(entry_points), "items": entry_points,
    }, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return catalog_items


def write_release_advertised(generated: Path) -> None:
    """The release record as the pages read it, for the file picker.

    The picker imported release.json whole and offered the ZIP of six setups
    the registry no longer releases, while their pages said "No ZIP". It
    reads this file instead: the platforms marked release_pack only.
    """
    generated.mkdir(parents=True, exist_ok=True)
    write_if_changed(
        str(generated / "release-advertised.json"),
        json.dumps(release_record.load_advertised(), ensure_ascii=False, indent=1,
                   sort_keys=True) + "\n",
    )


def _publish_manifests(api: Path) -> list[tuple]:
    """The install manifests and the release record, beside the API.

    The platform's list says what a setup checks. The manifest says what its
    pack installs: Batocera's list holds 353 files, its pack 14,508. The
    only copy was install/<platform>.json on the repository's main branch,
    which no page named. Copied byte for byte: the SHA256 the catalog gives
    is the repository file's.
    """
    folder = api / "manifests"
    folder.mkdir(parents=True, exist_ok=True)
    assets: list[tuple] = []
    for source in sorted((_REPO_ROOT / "install").glob("*.json")):
        target = folder / source.name
        shutil.copy2(source, target)
        _record(target)
        assets.append((target, f"Install manifest: {source.stem}", "application/json",
                       "schemas/install-manifest.schema.json"))
    # The target lists install.py --target reads: no catalog entry, and
    # api/v1/targets/ answered 404.
    targets = api / "targets"
    targets.mkdir(parents=True, exist_ok=True)
    for source in sorted((_REPO_ROOT / "install" / "targets").glob("*.json")):
        shutil.copy2(source, targets / source.name)
        _record(targets / source.name)
        assets.append((targets / source.name, f"Target list: {source.stem}",
                       "application/json", "schemas/target-manifest.schema.json"))
    # Every change each updated platform file carries, for a maintainer who
    # reviews them by script: the Exports page linked only the files.
    exports = api / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    for source in sorted((_REPO_ROOT / "exports").glob("*.json")):
        shutil.copy2(source, exports / source.name)
        _record(exports / source.name)
        assets.append((exports / source.name, f"Updated platform file, its changes: {source.stem}",
                       "application/json", None))
    release = _REPO_ROOT / "release.json"
    if release.is_file():
        shutil.copy2(release, api / "release.json")
        _record(api / "release.json")
        assets.append((api / "release.json", "Latest release: packs, sizes and assets",
                       "application/json", "schemas/release.schema.json"))
    return assets


def _site_path(markdown_target: str) -> str:
    """A page link as generators write it (systems/sony.md#psx) as a
    site-absolute path (/retrobios/systems/sony/#psx), which resolves the same
    from any document that holds it."""
    page, _, anchor = markdown_target.partition("#")
    base = urllib.parse.urlsplit(SITE_URL).path
    page = page.removesuffix(".md")
    page = "" if page == "index" else page.removesuffix("/index") + "/"
    return f"{base}{page}" + (f"#{anchor}" if anchor else "")


def system_index_items(db: dict, coverages: dict, profiles: dict) -> list[dict]:
    """Each system id the platforms and profiles write, reachable by that id.

    api/v1/systems/ is keyed by manufacturer and its consoles by display
    name: a frontend keying by system id (sony-playstation) had no way in.
    The url is the section system_section gives, the one every page links.
    An id with no section of its own (tyrian, scummvm) that holds files
    takes the card of its first file, else the page of the emulator naming
    it: 28 such ids sent their hashes to no page.
    """
    from siterender import card_page, system_ids, system_section

    sha1_by_path = _sha1_by_path(db)
    files = db.get("files") or {}
    by_md5 = (db.get("indexes") or {}).get("by_md5") or {}
    held: dict[str, set[str]] = {}
    for coverage in coverages.values():
        for detail in coverage.get("details") or []:
            path = str(detail.get("path") or "")
            sha1 = sha1_by_path.get(path) if detail.get("status") != "missing" else None
            if sha1:
                held.setdefault(str(detail.get("system", "")), set()).add(sha1)
    for profile in profiles.values():
        if profile.get("type") == "alias" or profile.get("role") == "test":
            continue
        own = [str(s) for s in profile.get("systems") or []]
        for entry in profile.get("files") or []:
            if not isinstance(entry, dict):
                continue
            ids = ([str(entry["system"])] if entry.get("system")
                   else [str(s) for s in entry.get("systems") or []] or
                   (own if len(own) == 1 else []))
            found = {v for v in _hash_values(entry.get("sha1")) if v in files}
            for md5 in _hash_values(entry.get("md5")):
                match = by_md5.get(md5)
                found.update([match] if isinstance(match, str) else match or [])
            for sys_id in ids:
                held.setdefault(sys_id, set()).update(found)
    manufacturers = {_slug(mfr): mfr for mfr in _group_by_manufacturer(db)}
    base = urllib.parse.urlsplit(SITE_URL).path
    items = []
    for sys_id in sorted(system_ids(profiles, [c["config"] for c in coverages.values()])):
        section = system_section(sys_id)
        try:
            name = system_name(sys_id)
        except KeyError:
            name = sys_id
        sha1s = sorted(held.get(sys_id, set()) & files.keys())
        manufacturer = manufacturers.get(section[0], "") if section else ""
        url = _site_path(console_href(*section)) if section else None
        if url is None and sha1s:
            manufacturer, url = _first_file_place(sys_id, sha1s, files, profiles, card_page)
        # The id's JSON document: api/v1/systems/ is keyed by the manufacturer
        # page, and sony-playstation.json answered 404.
        holder = section[0] if section else _slug(manufacturer) if manufacturer else ""
        api = f"{base}api/v1/systems/{holder}.json" if holder else None
        items.append({"id": sys_id, "name": name, "manufacturer": manufacturer,
                      "url": url, "api": api, "sha1": sha1s})
    return items


def _first_file_place(
    sys_id: str, sha1s: list[str], files: dict, profiles: dict,
    card_page: Callable[[str, str], str],
) -> tuple[str, str | None]:
    """(manufacturer, url) of the card of an id's first collection file,
    else of the page of the first emulator naming the id."""
    for sha1 in sha1s:
        parts = str(files[sha1].get("path", "")).split("/")
        if len(parts) >= 3 and parts[0] == "bios":
            page = card_page("/".join(parts), sha1)
            return parts[1], _site_path(f"systems/{page}.md#sha1-{sha1[:12]}")
    for key in sorted(profiles):
        profile = profiles[key]
        if profile.get("type") != "alias" and profile.get("role") != "test" and sys_id in (profile.get("systems") or []):
            return "", _site_path(f"emulators/{key}.md")
    return "", None


def core_index_items(profiles: dict) -> list[dict]:
    """Every name a core goes by, with the profile it designates.

    A frontend knows mednafen_psx_libretro, and api/v1/emulators/ had only
    beetle_psx.json: the reverse index resolve_platform_cores reads, aliases
    included, said once. A name two profiles claim (pcsx2) lists both, the
    one a platform list designates first.
    """
    from common import preferred_profile, upstream_profile_index

    published = {name for name, p in profiles.items() if p.get("type") != "alias" and p.get("role") != "test"}
    index = upstream_profile_index(profiles)
    for name, profile in profiles.items():
        target = str(profile.get("alias_of") or "")
        if profile.get("type") == "alias" and target in published:
            index.setdefault(name, set()).add(target)
    items = []
    for name in sorted(index):
        claimants = sorted(index[name] & published)
        preferred = preferred_profile({name: set(claimants)}, name)
        for profile in sorted(claimants, key=lambda p: (p != preferred, p)):
            items.append({"name": name, "profile": profile, "preferred": profile == preferred})
    return items


def _is_manifest(item: dict) -> bool:
    return item["url"].startswith("api/v1/manifests/")


def _is_target_list(item: dict) -> bool:
    return item["url"].startswith("api/v1/targets/")


def _is_setup_dat(item: dict) -> bool:
    return item["url"].startswith("downloads/dat/")


def _is_export_report(item: dict) -> bool:
    return item["url"].startswith("api/v1/exports/")


def _served_schemas() -> list[tuple[str, str]]:
    """(file name, title) of every schema api/v1/schemas/ serves, from the folder
    the export copies: the page linked 7 of 11."""
    return [
        (path.name, str(json.loads(path.read_text(encoding="utf-8")).get("title") or path.stem))
        for path in sorted((_REPO_ROOT / "schemas").glob("*.schema.json"))
    ]


# A URL template written in prose (https://.../<ref>/<repo_path>): escaped,
# the autolinker made a link of it, &lt;ref> on screen and a 404 behind it.
_URL_TEMPLATE = re.compile(r"(?<!`)https?://[^\s`]*<[^\s`]*?(?=[.,;]?(?:\s|$))")


def _schema_field_rows(schema: dict, keys: tuple[str, ...]) -> list[str]:
    """One table row per field, its description read from the schema, so the
    page and the published contract say the same thing. A URL template is
    written as code."""
    props = schema.get("properties") or {}
    rows = []
    for key in keys:
        text = str((props.get(key) or {}).get("description") or "")
        if text:
            # Python before 3.12 refuses a backslash inside an f-string expression.
            described = _escape_tags(_URL_TEMPLATE.sub(r"`\g<0>`", text))
            rows.append(f"| `{key}` | {described} |")
    return rows


def _other_fields(schema: dict, shown: tuple[str, ...]) -> list[str]:
    """The fields a short table leaves out, every one with its description."""
    rest = tuple(key for key in schema.get("properties") or {} if key not in shown)
    return ["| Field | Meaning |", "|-------|---------|", *_schema_field_rows(schema, rest)]


def _nested_fields(schema: dict, prefix: str = "") -> list[str]:
    """A table for every object below *schema*, at any depth, and one line
    per code where a field lists its codes' meanings (enumDescriptions).

    The top-level and `files` tables left 50 nested fields undescribed, all
    of `omitted_files` among them: a tool could not say why a file was not
    installed.
    """
    lines: list[str] = []
    for key, spec in (schema.get("properties") or {}).items():
        path = f"{prefix}{key}"
        codes = spec.get("enumDescriptions")
        if codes:
            lines.extend([f"Codes of `{path}`:", ""])
            lines.extend(f"- `{code}`: {text}" for code, text in zip(spec["enum"], codes))
            lines.append("")
        for label, child, child_path in (
            ("Each entry of", spec.get("items"), f"{path}[]"),
            ("Each value of", spec.get("additionalProperties"), f"{path}{{}}"),
            ("Fields of", spec, path),
        ):
            if not isinstance(child, dict) or not child.get("properties"):
                continue
            lines.extend([
                f"{label} `{path}`:", "",
                "| Field | Meaning |", "|-------|---------|",
                *_schema_field_rows(child, tuple(child["properties"])), "",
            ])
            lines.extend(_nested_fields(child, f"{child_path}."))
    return lines


# The manifest fields an integrator reads first, in the order they matter.
MANIFEST_TOP_FIELDS = ("platform", "version", "base_destination", "files",
                       "omitted_files", "pack_files", "core_names", "system_cores")
MANIFEST_FILE_FIELDS = ("dest", "sha1", "size", "repo_path", "release_asset", "cores",
                        "systems", "category", "alternatives")


def _short_sha256(item: dict, catalog: str) -> str:
    """A digest cell that fits its column: 12 characters linking the catalog
    that holds it, the whole value in the title. 64 characters pushed the
    table to 932 px in a 720 px column."""
    value = str(item["sha256"])
    return f'<a href="{catalog}"><code title="{value}">{value[:12]}</code></a>'


def _platforms_without_a_list(platforms_dir: Path | None = None) -> list[str]:
    """The names of the platforms whose registry says they keep no list."""
    platforms_dir = platforms_dir or siteinputs.current().platforms
    names = []
    for key, entry in sorted(load_platform_registry(str(platforms_dir)).items()):
        if entry.get("native_list") != "none":
            continue
        config = platforms_dir / str(entry.get("config") or f"{key}.yml")
        data = yaml_load(config.read_text(encoding="utf-8")) if config.is_file() else {}
        names.append(str((data or {}).get("platform") or key))
    return names


def _join_names(names: list[str]) -> str:
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + f" and {names[-1]}"


def generate_data_page(exports: list[dict], measurements_sqlite: Path | None = None) -> str:
    manifest_schema = json.loads(
        (_REPO_ROOT / "schemas" / "install-manifest.schema.json").read_text(encoding="utf-8"))
    snippet = (_REPO_ROOT / "scripts" / "check_platform_folder.py").read_text(encoding="utf-8")
    manifests = [item for item in exports if _is_manifest(item)]
    targets = [item for item in exports if _is_target_list(item)]
    no_list = _platforms_without_a_list()
    lines = [
        "---",
        "terms: manifest, schema, json schema, license, check a folder, "
        "check bios folder script, rate limit, api",
        "---",
        "",
        "# Data and API",
        "",
        "RetroBIOS publishes the same metadata used by its verifier, pack builder "
        "and website as versioned static files. No account or API key is required.",
        "",
        " ".join([
            markup.button("API catalog", "api/v1/catalog.json", primary=True),
            markup.button("SQLite snapshot", "downloads/retrobios.sqlite"),
            markup.button("Collection DAT", "downloads/retrobios.dat"),
        ]),
        "",
        f"**Licence:** the metadata is offered under the MIT terms of [LICENSE]({REPO_URL}/blob/main/LICENSE), "
        "which cover the scripts, tooling, schemas, documentation and metadata. "
        f"They never cover a BIOS or firmware file ([NOTICE]({REPO_URL}/blob/main/NOTICE)). "
        "`catalog.json` and the SQLite `metadata` table carry the same `license`.",
        "",
        "## Stable JSON endpoints",
        "",
        "Start at [`api/v1/index.json`](api/v1/index.json): it names the catalog, "
        "the two id indexes and the envelope schema.",
        "",
        "| Dataset | Endpoint | Schema | Size |",
        "|---------|----------|--------|-----:|",
    ]
    for item in exports:
        if (item["media_type"] != "application/json" or _is_manifest(item)
                or _is_target_list(item) or _is_export_report(item)):
            continue
        schema = (
            f"[JSON Schema](api/v1/{item['schema']})"
            if item.get("schema") else "-"
        )
        lines.append(
            f"| {item['title']} | [`{item['url']}`]({item['url']}) | "
            f"{schema} | {_fmt_size(item['bytes'])} |"
        )
    lines.extend([
        "",
        "Every envelope carries `schema_version`, `kind` and `commit`, the revision "
        "of this repository the data was read at. Breaking changes use a new "
        "URL prefix (`/api/v2/`), and fields may only be added compatibly within v1. "
        "Each schema's `$id` is the address it is served at.",
        "",
        "Schemas:",
        "",
        *(f"- [`{name}`](api/v1/schemas/{name}): {title}" for name, title in _served_schemas()),
        "",
        "`database.json`, `stats.json`, `release.json` and the manifests are not "
        "envelopes. Their revision is the `commit` of `catalog.json` that lists "
        "their SHA256.",
        "",
        "One emulator profile without the whole list: "
        "`api/v1/emulators/<id>.json`, the envelope of `emulators.json` holding "
        "that one item, its `profile` valid against "
        "[`emulator.schema.json`](api/v1/schemas/emulator.schema.json). Each "
        "emulator page links its own. `api/v1/platforms/<id>.json` holds one "
        "platform of `platforms.json`, its `contract` valid against "
        "[`platform.schema.json`](api/v1/schemas/platform.schema.json) and its "
        "`registry` the install and scraper settings beside the list. "
        "`api/v1/systems/<slug>.json` holds the files of one system page by console. "
        "Each platform and system page links its own.",
        "",
        "By id: [`systems.json`](api/v1/systems.json) gives each system id a platform "
        "or a profile writes (`sony-playstation`) with its name, its manufacturer, the "
        "`url` of the section holding its files, the `api` document of that section "
        "and the files' SHA1. "
        "[`cores.json`](api/v1/cores.json) gives each core name the buildbot or a "
        "platform uses (`mednafen_psx`) the profile it designates (`beetle_psx`), "
        "whose document is `api/v1/emulators/<profile>.json`. A name two profiles "
        "claim (`pcsx2`) has one item per profile, and `preferred: true` marks the "
        "one a platform list naming that core gets: the profile with that very id, "
        "else the first id in alphabetical order.",
        "",
        "One hash without the whole list: `api/v1/lookup/<xx>.json`, where `<xx>` "
        "is the first two characters of the hash in lowercase, holds every SHA1, "
        "MD5, CRC32 and SHA256 starting with them. Each record names its `layer` "
        "(the collection, a member of a collection archive, a file that left the "
        "collection, a data directory, a platform's list or an emulator profile), "
        "the file `name`, the `url` of the page that shows it and, "
        "when one is known, the `system_name` the site gives its system. "
        "[Find or check a file](files/index.md) reads it.",
        "",
        "`catalog.json` lists the datasets, manifests, exports and downloads. It "
        "does not list these one-item documents, which hold no SHA256 of their own.",
        "",
        "In a browser, the SHA1 of a file the reader picks finds its records when "
        "the collection holds that file. A list naming a file the collection lacks "
        "is filed under its MD5 or CRC32 alone, and Web Crypto has no MD5: "
        "that page computes MD5 and CRC32 in script and looks "
        "up all four.",
        "",
        "```js",
        "// The records of the file a reader picked, by its SHA1.",
        "async function lookUp(file) {",
        "  const digest = await crypto.subtle.digest(\"SHA-1\", await file.arrayBuffer());",
        "  const sha1 = [...new Uint8Array(digest)]",
        "    .map((byte) => byte.toString(16).padStart(2, \"0\"))",
        "    .join(\"\");",
        f"  const base = \"{SITE_URL}api/v1/lookup/\";",
        "  const response = await fetch(`${base}${sha1.slice(0, 2)}.json`);",
        "  if (!response.ok) return [];",
        "  const shard = await response.json();",
        "  // layer: collection, archive-member, retired, data-directory, platform, emulator.",
        "  return shard.items.filter((item) => item.value === sha1);",
        "}",
        "```",
        "",
        "Two kinds of `url`:",
        "",
        "- In `catalog.json` and `index.json`, a `url` is relative to the document "
        "holding it, as RFC 3986 resolves it.",
        "- In the lookup shards, `file-locations.json` and `systems.json`, a `url` "
        f"is site-absolute (`/retrobios/systems/sony/#...`). Prefix "
        f"`{SITE_URL.removesuffix(urllib.parse.urlsplit(SITE_URL).path)}` for a full address.",
        "",
        "## Platform manifests",
        "",
        "A platform's list is what the setup checks. Its manifest is what the pack "
        "installs: the list's files plus every file the setup's cores load. "
        "`api/v1/manifests/<platform>.json` is the file `install.py` reads, byte "
        "for byte, valid against "
        "[`install-manifest.schema.json`](api/v1/schemas/install-manifest.schema.json). "
        "[`api/v1/release.json`](api/v1/release.json) records the packs of the latest "
        "release and the files each one holds.",
        "",
        "Manifests: " + ", ".join(
            f"[{item['url'].rsplit('/', 1)[-1].removesuffix('.json')}]({item['url']})"
            for item in manifests) + "." if manifests else "",
        "",
        "`api/v1/targets/<platform>.json` gives each hardware target of a platform "
        "the cores it runs, valid against "
        "[`target-manifest.schema.json`](api/v1/schemas/target-manifest.schema.json). "
        "`install.py --target` reads the same file. Like the manifests, they are "
        "copied byte for byte and are not envelopes.",
        "",
        "Target lists: " + ", ".join(
            f"[{item['url'].rsplit('/', 1)[-1].removesuffix('.json')}]({item['url']})"
            for item in targets) + "." if targets else "",
        "",
        "`api/v1/exports/<platform>.json` lists every change of a setup's "
        "[updated file](exports.md), the report that page is written from, copied "
        "byte for byte like the manifests.",
        "",
        "| Field | Meaning |",
        "|-------|---------|",
        *_schema_field_rows(manifest_schema, MANIFEST_TOP_FIELDS),
        "",
        "Each entry of `files`:",
        "",
        "| Field | Meaning |",
        "|-------|---------|",
        *_schema_field_rows(manifest_schema["$defs"]["file"], MANIFEST_FILE_FIELDS),
        "",
        *markup.details("note", "All fields", [
            "The manifest:",
            "",
            *_other_fields(manifest_schema, MANIFEST_TOP_FIELDS),
            "",
            "Each entry of `files`:",
            "",
            *_other_fields(manifest_schema["$defs"]["file"], MANIFEST_FILE_FIELDS),
            "",
            *_nested_fields(manifest_schema),
            *_nested_fields(manifest_schema["$defs"]["file"], "files[]."),
        ]),
        "## Check a folder for one platform",
        "",
        "The job most tools come for: is this BIOS folder what the platform checks? "
        "Read `api/v1/platforms/<id>.json` and apply the platform's own rules:",
        "",
        "- `verification_mode: existence`: a file at its `destination` passes.",
        "- An entry with no hash in the mode's field is checked on presence too.",
        "- `zipped_file` set: the md5 is that of this member inside the ZIP, never "
        "the ZIP's. Member names compare casefolded. A ZIP declared once per member "
        "appears once per member: Batocera lists 692 entries for 353 destinations.",
        "- An md5 shorter than 32 characters (Batocera) compares by its prefix. "
        "Recalbox writes several accepted md5 in one field, comma separated.",
        "- `zip_digest: composite` (Recalbox): the md5 of a ZIP is that of its members "
        "read in name order, never the archive's.",
        "- An entry with no `destination` (EmuDeck) names no file: the system "
        "passes when any file in the BIOS folder has one of its md5.",
        "- `hash_rule: size_and_any_hash` (RomM) wants the size and any one hash. "
        "The script below does not apply it.",
        *([f"- {_join_names(no_list)} have no list of their own (`native_list: none`). "
           "An empty list does not mean nothing is needed."] if no_list else []),
        "",
        "```python",
        snippet.rstrip("\n"),
        "```",
        "",
        "The script is [`scripts/check_platform_folder.py`]"
        f"({REPO_URL}/blob/main/scripts/check_platform_folder.py). A test runs it "
        "against the verifier on a sample folder, so the two give the same answer. "
        "It exits 1 when a file is wrong or missing. For an unknown platform it "
        "prints the known ones, and it names a folder that does not exist.",
        "",
        "`install.py --check` answers another question by default: whether the folder "
        "holds what the pack installs, the manifest above. With `--declared-only`, or "
        "from the `declared` event, `install.py --check` answers it too.",
        "",
        "## Bulk downloads",
        "",
        "| Export | Format | Size | SHA256 |",
        "|--------|--------|-----:|--------|",
    ])
    for item in exports:
        if item["media_type"] == "application/json" or _is_setup_dat(item):
            continue
        lines.append(
            f"| [{item['title']}]({item['url']}) | `{item['media_type']}` | "
            f"{_fmt_size(item['bytes'])} | {_short_sha256(item, 'api/v1/catalog.json')} |"
        )
    lines.extend([
        "",
        "Each SHA256 is cut to 12 characters. Point at it for the whole value, or "
        "read it in [`catalog.json`](api/v1/catalog.json).",
        "",
        "The DAT is Logiqx XML, the format clrmamepro and RomVault read: one game "
        "per `bios/<Manufacturer>/<Console>/` folder of the collection, named "
        "`Manufacturer\\Console` so the tools look in that subfolder, each file a "
        "rom named by its path below that folder. It audits a copy of the "
        "collection's `bios/` tree, or rebuilds that layout from a reader's own dumps.",
        "",
        "A setup's DAT, `downloads/dat/<platform>.dat`, describes its BIOS folder "
        "once installed: one game named after the folder (`bios`, `system`), each "
        "file a rom named by its place below it, as its manifest lists it. It audits "
        "that folder with the same tools. Setup DATs: " + ", ".join(
            f"[{item['url'].rsplit('/', 1)[-1].removesuffix('.dat')}]({item['url']})"
            for item in exports if _is_setup_dat(item)) + ".",
        "",
        "The SQLite file contains indexed tables for content hashes, provenance "
        "catalog matches, platform declarations, emulator profiles and current "
        "gaps. It contains metadata only, never BIOS or firmware bytes.",
        "",
        "To find who accepts a hash, query `accepted_hashes` (or "
        "`accepted-hashes.csv`): one lowercase row per accepted value, per "
        "algorithm, for platform declarations and emulator profiles alike, "
        "indexed on `(algorithm, value)`. A ROM inside a MAME or FBNeo set "
        "has its own row, its `path` naming the archive and the member "
        "(`nmk004.zip/nmk004.bin`). The hash columns of `platform_files` "
        "and `emulator_files` keep each source's own form: a Recalbox md5 may "
        "list several revisions separated by commas, and an emulator field "
        "holding several accepted values is a JSON array.",
        "",
        "```sql",
        "SELECT layer, owner, name FROM accepted_hashes",
        "WHERE algorithm = 'md5' AND value = 'c87a52c277f7952b41c639fc7bf0a43b';",
        "```",
        "",
        "The gaps dataset carries both layers behind one `layer` column: "
        "`platform` rows are anomalies against a platform's own BIOS list, "
        "`emulator` rows are files a profiled core loads that no platform "
        "declares. The two answer different questions and are not comparable "
        "totals. Each row is listed once.",
        "",
        "`platform-files.csv` and the gaps add what the check found: `status` "
        "(`ok`, `untested`, `missing`), `category` (`bios`, `game_data`, "
        "`unread`), and for a held file `collection_path` and `resolved_sha1`, "
        "the collection file that answers the declaration. "
        "`provenance-wanted.csv` is the Wanted list of [Dump provenance]"
        "(provenance.md): each dump a catalog describes and the collection lacks.",
        "",
        "`platform-files.csv` and the `platform_files` table also carry the entry "
        "fields a check needs:",
        "",
        "- `zipped_file` set: the md5 is the md5 of that member inside the ZIP.",
        "- `zip_digest` is `composite` where the md5 of a ZIP covers its members.",
        "- `hash_match_mandatory` and `mandatory_declared` are Recalbox's flags.",
        "- `curated`, `shared_group` and `mirror_of` mark an entry the platform's "
        "own file does not carry.",
        "",
        *(sitemeasurements.data_page_section(measurements_sqlite)
          if measurements_sqlite and measurements_sqlite.is_file() else []),
        "## Hosting, rate limits and caching",
        "",
        "- Static files on GitHub Pages, read with a plain GET. No key, no account.",
        "- Any origin may read them (`Access-Control-Allow-Origin: *`), so a "
        "browser tool can call them directly.",
        "- Responses are cached for 10 minutes (`Cache-Control: max-age=600`). "
        "Send the `ETag` back in `If-None-Match` to skip an unchanged download.",
        "- GitHub may answer HTTP 429 to a client that sends too many requests, and "
        "a Pages site has a soft limit of 100 GB of traffic a month ([GitHub Pages "
        "limits](https://docs.github.com/en/pages/getting-started-with-github-pages/"
        "github-pages-limits)). Fetch the one shard or document a question needs.",
        "- The base is the project's address, "
        f"`{SITE_URL}api/v1/`. Compare `commit` to know whether two downloads differ.",
        "",
        "## Semantics and limits",
        "",
        "Treat four questions separately: content identity (hashes), presence in "
        "the collection, acceptance by a specific emulator, and catalog provenance. "
        "One does not imply the others. In particular, presence, a matching dump "
        "catalog, or emulator compatibility is not a statement about copyright, "
        "ownership, or redistribution rights.",
        "",
        f"The data can be newer than the [latest published pack]({RELEASE_URL}). "
        "A pack is published by hand, once every release check has passed.",
        "",
        "See the [data model](wiki/data-model.md), [verification modes]"
        "(wiki/verification-modes.md), and [methodology](wiki/architecture.md) "
        "before interpreting aggregate counts.",
        "",
    ])
    return "\n".join(lines)


def _page_title(markdown: str, path: Path) -> str:
    match = re.search(r"^#\s+(.+?)\s*$", markdown, flags=re.MULTILINE)
    if match:
        title = re.sub(r"<[^>]+>", "", match.group(1))
        return title.replace(f" - {SITE_NAME}", "").strip()
    return path.stem.replace("-", " ").title()


def _browser_title(relative: Path, title: str) -> str:
    """Return a concise, unique browser/search title for a generated page."""
    key = relative.as_posix()
    index_titles = {
        # Material appends " - RetroBIOS": the home title says what the site
        # is, instead of "RetroBIOS - RetroBIOS".
        "index.md": "BIOS and firmware packs for RetroArch, Batocera and more",
        "platforms/index.md": "Setups",
        "systems/index.md": "Systems",
        "emulators/index.md": "Emulators",
        "wiki/index.md": "Reference",
        "explore.md": "Explore",
    }
    if key in index_titles:
        return index_titles[key]
    # A console page is filed with the parts of its manufacturer's page, and
    # titled "Sega: Dreamcast". A part names its range of files.
    part = key in PART_PAGES and (
        not key.startswith("systems/") or ": " not in title
        or re.search(r", part \d+ of \d+$", title))
    if part:
        return title
    # The words a web search for a console or an emulator types: "dreamcast
    # bios", "duckstation bios". The h1 and the sidebar keep the name.
    if key.startswith("emulators/"):
        has_files = PAGE_DATA.get(key, {}).get("hasPart") and key not in NOTHING_TO_FETCH
        # Lexaloffle, QEMU and ScummVM name a system page too.
        own = " emulator" if f"systems/{relative.name}" in PAGE_DATA else ""
        return f"{title}{own} BIOS files" if has_files else f"{title} emulator"
    if key.startswith("systems/"):
        maker, _, console = title.partition(": ")
        return f"{console} BIOS files ({maker})" if console else f"{title} BIOS files"
    return title


_LINK_TEXT = r"(?:`[^`]*`|\[[^\]\[]*\]|[^\]\[])"


def _plain_markdown(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text)
    # Link text may hold brackets: a code span or a No-Intro name such as
    # `[BIOS] LaserActive PAC-N1 (Japan) (v1.02).bin` left the whole link,
    # anchor included, in the Pioneer page's meta description.
    text = re.sub(rf"!\[({_LINK_TEXT}*)\]\([^)]*\)", r"\1", text)
    text = re.sub(rf"\[({_LINK_TEXT}+)\]\([^)]*\)", r"\1", text)
    # Code spans keep their text whole: validate_schemas.py read
    # validateschemas.py once every underscore was taken for emphasis.
    pieces = re.split(r"(`[^`]*`)", text)
    text = "".join(
        piece.strip("`") if piece.startswith("`")
        else re.sub(r"(?<!\w)_+|_+(?!\w)", "", re.sub(r"[*~]", "", piece))
        for piece in pieces
    )
    return re.sub(r"\s+", " ", text).strip()


def _shorten(plain: str, limit: int = 157) -> str:
    """A description cut at a word, never inside one: six snippets ended
    in "op..." or "Fo..."."""
    if len(plain) <= limit:
        return plain
    cut = plain[: limit + 1].rsplit(" ", 1)[0] if " " in plain[:limit] else plain[:limit]
    return cut.rstrip(" ,;:-(.") + "..."


def _page_description(markdown: str, relative: Path, title: str) -> str:
    key = relative.as_posix()
    specific = {
        "index.md": "The BIOS files emulators need, for RetroArch, Batocera, EmuDeck and more: the folder they go in, one command that installs and checks them, and packs to download.",
        "data.md": "Versioned RetroBIOS JSON API, CSV exports, SQLite snapshot, schemas, checksums and data interpretation guidance.",
        "cross-reference.md": "Every emulator core each retrogaming platform runs, the systems it emulates and the upstream project it comes from.",
        "gaps.md": "Current RetroBIOS verification gaps, platform-to-emulator divergences, missing files and documented source limitations.",
        "exports.md": "Each platform's own BIOS list (System.dat, batocera-systems, es_bios.xml and the rest) with the hashes and files the emulator source code shows, offered to its maintainers.",
        sitemeasurements.EXPLORER_PAGE: "The records of emulator cores run headless on demand, each with its claim, verdict, the BIOS it ran, method, computer and full record, filterable, and as SQLite.",
        "provenance.md": "Hash-based comparison of RetroBIOS metadata with No-Intro, Redump and TOSEC catalog snapshots.",
        "explore.md": "Systems, emulators and installer options to explore, with the figures of the BIOS collection.",
        "which-pack.md": "Pick a device or setup and get its BIOS files: the folder they go in, one command that installs and checks them, or a ZIP pack to extract.",
        "contributing.md": "Add a BIOS file the collection lacks from the browser, checked on arrival, or add a platform or an emulator profile.",
    }
    if key in specific:
        return specific[key]
    # What a search engine shows is the page's own first sentence: 707 pages
    # shared five templates of level 3 words ("source-pinned", "provenance").
    browser = _browser_title(relative, title)
    held = re.search(r"\bThis part holds (.+?)\.(?: |$)", markdown, re.M)
    if key in PART_PAGES and held:
        return _shorten(f"{browser}. This part holds {_plain_markdown(held[1])}.", 155)
    lead = _lead(markdown)
    if key in PART_PAGES and re.search(r"\bpart \d+ of \d+", title):
        # The parts of one list open on the same sentence.
        first = _first_paragraph(lead) or _first_paragraph(markdown)
        return _shorten(f"{title}. {first}", 155)
    if key.startswith(f"{release_record.GET_DIR}/"):
        size = re.search(r"^- (.+ to download\b.*?)\.?$", markdown, re.M)
        if size:
            return _shorten(f"{title}: the BIOS pack of this setup, {_plain_markdown(size[1])}. "
                            "The address stays the same and always gives the latest ZIP.", 155)
        return _shorten(_first_paragraph(lead) or title, 155)
    if key.startswith("systems/") and relative.stem != "index":
        return _system_description(markdown, browser)
    if key.startswith("emulators/") and relative.stem != "index":
        return _emulator_description(markdown, key, title, _first_paragraph(lead))
    if key.startswith("platforms/") and relative.stem != "index":
        # The summary ends on a link to the platform's site, whose label
        # alone was left: "A system for handhelds. ROCKNIX website."
        summary = _first_paragraph(lead).removesuffix(f" {title} website.")
        return _shorten(f"The BIOS files for {title}, the folder they go in and the "
                        f"command that installs them. {summary}", 155)
    first = _first_paragraph(lead, minimum=35)
    questions = [_plain_markdown(re.sub(r"\s*\{[^}]*\}\s*$", "", heading))
                 for heading in re.findall(r"^## (.+\?)(?:[ \t]*\{[^}]*\})?[ \t]*$", markdown, re.M)]
    if not first and len(questions) >= 3:
        # A page of questions with no intro: its first paragraph is the
        # answer to one of them ("Run the command with --dry-run").
        return _shorten(f"{title}: {' '.join(questions)}", 155)
    first = first or _first_paragraph(markdown, minimum=35)
    if first:
        return _shorten(first, 155)
    return f"{title}: RetroBIOS source-traced retrogaming firmware reference."


def _lead(markdown: str) -> str:
    """The text a page opens with, before its first section, details
    block or ignored section (the install box, the profile table)."""
    return re.split(r"^(?:## |<details|<section)", markdown, maxsplit=1, flags=re.M)[0]


def _emulator_description(markdown: str, key: str, title: str, intro: str) -> str:
    """An emulator page by its intro sentence ("DuckStation emulates Sony
    PlayStation. It picks the BIOS for the game's region: ..."), or by
    its profile table when the profile names no system."""
    notes = re.search(r"<summary>Technical notes</summary>\s*\n\n(.+?)(?:\n\n|$)", markdown, re.S)
    if not intro and notes:
        # An initial is no sentence end: hcl's read "open-source port of E."
        sentence = re.split(r"(?<![\s(][A-Z]\.)(?<=\.)\s", _plain_markdown(notes[1]),
                            maxsplit=1)[0]
        intro = f"{title}: {sentence[:1].lower()}{sentence[1:]}"
    if not intro:
        row = {name: _plain_markdown(value) for name, value in re.findall(
            r"^\| (Type|Classification|Version) \| (.+?) \|$", markdown, re.M)}
        kind = row.get("Classification") or row.get("Type") or "emulator"
        # The cell goes on to say where the version is read: the intro
        # keeps the version alone.
        version = row.get("Version", "").split(", ")[0]
        known = f", version {version}" if version and version[0].isdigit() else ""
        intro = f"{title}: {kind.lower()}{known}."
    elif title not in intro:
        # "It reads 1 file": the profile names no system to open on.
        intro = f"{title}: {intro[:1].lower()}{intro[1:]}"
    if key in NOTHING_TO_FETCH:
        return _shorten(f"{intro} Every file it reads comes with the app.", 155)
    if PAGE_DATA.get(key, {}).get("hasPart"):
        return _shorten(_files_snippet(markdown, key, title, intro), 155)
    # An alias page sends the reader to the core whose files it shares.
    if "uses the same firmware as" in intro:
        return _shorten(intro, 155)
    needs = "It needs no BIOS or firmware file."
    if "\n## Data directories" in markdown:
        needs = "It needs no BIOS or firmware file, only the data folders listed."
    return _shorten(f"{intro} {needs}", 155)


def _files_snippet(markdown: str, key: str, title: str, intro: str) -> str:
    """The snippet of an emulator page with files to get.

    A search for "gba_bios.bin" or "scph5500.bin" landed on a page described
    as "It reads 4 files, none of them required": the names the reader typed
    were not in the result, and fewer than 1 in 70 clicked. The longest
    form that fits is kept: a snippet cut by "..." reads as unfinished.
    """
    if " any region." in intro:
        step = ("Download one from this page and put it in the folder it shows."
                if re.search(r"^1\. Download ", _lead(markdown), re.M)
                else "Where to get one and the folder it goes in.")
        head = f"{intro.split(' any region.')[0]} any region."
        forms = [f"{head} {step} Any file name works.", f"{head} {step}"]
        return next((form for form in forms if len(form) <= 155), intro)
    snippet = EMULATOR_SNIPPETS.get(key)
    if not snippet or not snippet[1] or "It reads " not in intro:
        return intro
    system, names, required, noun = snippet
    if required == 0:
        need = "none required"
    elif required == len(names):
        need = "all required" if len(names) > 1 else "required"
    else:
        need = f"{required:,} required"
    subject = f"{system} {noun} for {title}" if system else f"{title} {noun}"
    tails = ["Where each goes, its hashes and one command that installs them."
             if "Install this emulator's files" in markdown else "",
             "Where each goes and its hashes.", "Where each goes."]
    forms = []
    for count in range(min(len(names), 4), 0, -1):
        shown = (names if count == len(names)
                 else [*names[:count - 1], f"{len(names) - count + 1:,} more"])
        head = f"{subject}: {_said_as_list(shown)}, {need}."
        forms += [f"{head} {tail}" for tail in tails if tail] + [head]
    return next((form for form in forms if len(form) <= 155), intro)


# Lines a page opens with that say where it sits, not what it holds.
_PLACE_LINES = ("Part of ", "This part holds ", "On a card, ")


def _first_paragraph(markdown: str, minimum: int = 1) -> str:
    """The first paragraph of prose of a page body, as plain text: no
    heading, table, list, fence, admonition or HTML block, and none that
    only says where the page sits."""
    for paragraph in re.split(r"\n\s*\n", markdown):
        stripped = paragraph.strip()
        if (
            not stripped
            or stripped.startswith(("#", "|", "```", "???", ":::", "<", "- ", "* ", "import "))
        ):
            continue
        plain = _plain_markdown(stripped)
        if plain.startswith(_PLACE_LINES):
            continue
        # A paragraph that ends on a colon introduces what follows: alone,
        # it describes nothing ("One file needs no clone and no local setup:").
        if len(plain) >= minimum and not plain.endswith(":"):
            return plain
    return ""


# Section headings of a system page that are not a console.
_NOT_A_CONSOLE = {"Next steps", "Files", "Other files"}
_CARD_TITLE = re.compile(r'class="rb-file-title"[^>]*><code>([^<]+)</code>')


def _system_description(markdown: str, browser: str) -> str:
    """A system page by what it holds: a manufacturer page by its consoles,
    a console page by its "Start with" line, else by its first files."""
    consoles = [
        _plain_markdown(re.sub(r"\s*\{[^}]*\}\s*$", "", heading))
        for heading in re.findall(r"^## (.+?)[ \t]*$", markdown, re.M)
    ]
    consoles = [name for name in consoles if name and name not in _NOT_A_CONSOLE]
    if len(consoles) > 1:
        shown = consoles if len(consoles) <= 4 else consoles[:3] + [f"{len(consoles) - 3} more"]
        return _shorten(f"{browser} for {_said_as_list(shown)}, one card per file with its "
                        "hashes and the emulators that read it.", 155)
    start = re.search(r"^\*\*Start with\*\*(?P<line>.*)$(?P<list>(?:\n+- .*)*)", markdown, re.M)
    if start:
        # "Start with the files of your machine:" introduces one line per machine.
        machines = [_plain_markdown(item) for item in re.findall(r"^- (.+)$", start["list"], re.M)]
        text = _plain_markdown(start["line"]).lstrip(": ")
        said = "; ".join(machines) if machines and text.endswith(":") else text
        return _shorten(f"{browser}. Start with {said}", 155)
    names = list(dict.fromkeys(html.unescape(name) for name in _CARD_TITLE.findall(markdown)))
    if names:
        shown = names if len(names) <= 3 else names[:3] + [f"{len(names) - 3} more"]
        return _shorten(f"{browser}: {_said_as_list(shown)}, with their hashes and the "
                        "emulators that read them.", 155)
    return _shorten(f"{browser}, one card per file with its hashes and the emulators "
                    "that read it.", 155)


# Structured data a page generator knows beyond its text, by page path
# relative to docs/: read by decorate_markdown_pages.
PAGE_DATA: dict[str, dict] = {}
# Emulator pages whose every file comes with the app: no "BIOS files" in
# their title, and their description says so (DaedalusX64, ZEsarUX).
NOTHING_TO_FETCH: set[str] = set()
# The first system, the file names, the count of required names and the
# word for them ("BIOS" or "files") of each emulator page, for its snippet.
EMULATOR_SNIPPETS: dict[str, tuple[str, list[str], int, str]] = {}
# Pages that hold part of a page too long for one (a console of a split
# manufacturer, a run of an emulator's cards), by path relative to docs/:
# their H1 already says what they are.
PART_PAGES: set[str] = set()


SYSTEM_PARTS_IN_FULL = 250


def collection_dat(db: dict, generated_at: str) -> str:
    """The collection as a Logiqx DAT, the format clrmamepro and RomVault read.

    One game per bios/<Manufacturer>/<Console>/ folder, named
    Manufacturer\\Console, each file a rom named by its path below that
    folder, subfolders joined with a backslash as Logiqx DATs write them. An auditor checking a BIOS tree against the
    collection had JSON, CSV and SQLite, and a converter to write.
    """
    games: dict[str, list[dict]] = {}
    files = db.get("files", {})
    # Every copy, not the one path the database keeps: an audit of bios/
    # read the 2,502 others as unknown files, and a fix moved them away
    # from the engines that read them by path.
    for sha1, paths in collection_paths(db).items():
        for path in sorted(paths):
            parts = path.split("/")
            folder = parts[1:3] if len(parts) > 3 else parts[1:2]
            # A backslash is how a Logiqx set name writes a subfolder: named
            # "Sony - PlayStation", the set was looked for beside Sony/, and an
            # audit of a copy of bios/ found 330 sets missing.
            games.setdefault("\\".join(folder), []).append(
                {**files[sha1], "_rom": "\\".join(parts[1 + len(folder):])}
            )
    return _logiqx(SITE_NAME, f"{SITE_NAME} collection ({sum(map(len, games.values()))} files)",
                   games, generated_at)


def _write_platform_dats(folder: Path, db: dict, members: dict, generated_at: str) -> list[Path]:
    """downloads/dat/<platform>.dat for each install manifest."""
    folder.mkdir(parents=True, exist_ok=True)
    digests = _data_member_digests(members)
    written = []
    for source in sorted((_REPO_ROOT / "install").glob("*.json")):
        manifest = json.loads(source.read_text(encoding="utf-8"))
        path = folder / f"{source.stem}.dat"
        write_if_changed(str(path), platform_dat(manifest, db, digests, generated_at))
        written.append(path)
    return written


def platform_dat(manifest: dict, db: dict, member_digests: dict[str, dict[str, str]],
                 generated_at: str) -> str:
    """What one setup's BIOS folder holds once installed, as a Logiqx DAT.

    One game named after the folder (`bios`, `system`), each file a rom
    named by its place below it, as the install manifest writes it: the
    files of the setup's list and those its cores load, and the members of
    its data directories. A Batocera user auditing share/bios against the
    collection DAT met thousands of sets laid out by manufacturer.
    """
    files = db.get("files", {})
    roms: list[dict] = []
    for entry in manifest.get("files") or []:
        if entry.get("root") == "save":
            continue  # installed in the save directory, not this folder
        sha1 = str(entry.get("sha1", ""))
        roms.append({**files.get(sha1, {}), "sha1": sha1, "size": entry.get("size", 0),
                     "_rom": str(entry["dest"]).replace("/", "\\")})
    for tree in manifest.get("data_directories") or []:
        dest = str(tree.get("dest") or "").strip("/")
        for member, info in (tree.get("files") or {}).items():
            sha1 = str(info.get("sha1", ""))
            path = f"{dest}/{member}" if dest else member
            roms.append({**member_digests.get(sha1, {}), "sha1": sha1,
                         "size": info.get("size", 0), "_rom": path.replace("/", "\\")})
    folder = str(manifest.get("base_destination") or "bios").strip("/").rsplit("/", 1)[-1]
    name = f"{SITE_NAME} - {manifest.get('display_name') or manifest['platform']}"
    unique = list({rom["_rom"]: rom for rom in reversed(roms)}.values())
    return _logiqx(name, f"{name} ({len(unique)} files)", {folder: unique}, generated_at)


def _logiqx(name: str, description: str, games: dict[str, list[dict]], generated_at: str) -> str:
    """Games of roms as a Logiqx datafile, each rom's `_rom` its name."""
    import xml.etree.ElementTree as ET  # noqa: PLC0415

    root = ET.Element("datafile")
    header = ET.SubElement(root, "header")
    version = generated_at[:10].replace("-", "")
    for tag, text in (
        ("name", name),
        ("description", description),
        ("version", version),
        ("date", generated_at[:10]),
        ("author", SITE_NAME),
        ("homepage", SITE_URL),
        ("url", REPO_URL),
    ):
        ET.SubElement(header, tag).text = text
    for game_name in sorted(games):
        game = ET.SubElement(root, "game", name=game_name)
        ET.SubElement(game, "description").text = game_name
        for entry in sorted(games[game_name], key=lambda e: e["_rom"]):
            attributes = {"name": entry["_rom"], "size": str(entry.get("size", 0))}
            for attribute, field in (("crc", "crc32"), ("md5", "md5"), ("sha1", "sha1")):
                if entry.get(field):
                    attributes[attribute] = str(entry[field]).lower()
            ET.SubElement(game, "rom", attributes)
    ET.indent(root, space="\t")
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE datafile PUBLIC "-//Logiqx//DTD ROM Management Datafile//EN" '
        '"http://www.logiqx.com/Dats/datafile.dtd">\n'
        + ET.tostring(root, encoding="unicode") + "\n"
    )


def system_structured_data(slug: str, consoles: dict[str, list]) -> dict:
    """A system page's files for a machine: each card as a CreativeWork.

    The pages that hold a card per file published a bare TechArticle with
    no file, hash or provenance, while emulator pages listed theirs.
    """
    parts = []
    for _console, entries in sorted(consoles.items()):
        for entry in entries:
            sha1 = str(entry.get("sha1") or "")
            part: dict = {"@type": "CreativeWork", "name": str(entry.get("name", ""))}
            if sha1:
                part["url"] = urllib.parse.urljoin(SITE_URL, f"systems/{slug}/#sha1-{sha1[:12]}")
            identifiers = [
                f"{field}:{str(entry[field]).lower()}"
                for field in ("sha1", "md5", "crc32", "sha256") if entry.get(field)
            ]
            if identifiers:
                part["identifier"] = identifiers
            if entry.get("size"):
                part["contentSize"] = f"{entry['size']} B"
            citations = [
                f"{catalog}: {record.get('dat', '')} ({record.get('name', '')})"
                for catalog, record in sorted((entry.get("provenance") or {}).items())
                if isinstance(record, dict)
            ]
            if citations:
                part["citation"] = citations
            parts.append(part)
    if len(parts) > SYSTEM_PARTS_IN_FULL:
        # A page of cards carried up to 2.6 MB of JSON-LD (game-engines), a
        # quarter of its weight: past the cap a page lists its
        # catalogue-verified files and points at the full table.
        return {
            "hasPart": [part for part in parts if part.get("citation")],
            "isBasedOn": urllib.parse.urljoin(SITE_URL, "downloads/files.csv"),
        }
    return {"hasPart": parts} if parts else {}


def platform_structured_data(name: str, coverage: dict) -> dict:
    """A platform page's declarations for a machine reader.

    The page printed thousands of hashes while its JSON-LD named only the
    page: a crawler could not learn which md5 Batocera requires for a file.
    The software and its version are the subject, and each declared file, with
    the hashes the platform checks, is a part. Past SYSTEM_PARTS_IN_FULL the
    parts give way to the platform-files table, as system pages do.
    """
    config = coverage.get("config") or {}
    about: dict = {"@type": "SoftwareApplication", "name": str(coverage.get("platform", name))}
    if config.get("version"):
        about["softwareVersion"] = str(config["version"])
    if config.get("homepage"):
        about["url"] = str(config["homepage"])
    parts = []
    for system_id, system in sorted((config.get("systems") or {}).items()):
        for entry in system.get("files") or []:
            if not isinstance(entry, dict) or not entry.get("name"):
                continue
            part: dict = {
                "@type": "CreativeWork",
                "name": str(entry.get("destination") or entry["name"]),
                "url": urllib.parse.urljoin(SITE_URL, f"platforms/{name}/#{system_id}"),
            }
            identifiers = [
                f"{field}:{value}"
                for field in ("sha1", "md5", "crc32", "sha256")
                for value in _hash_values(entry.get(field))
            ]
            if identifiers:
                part["identifier"] = identifiers
            parts.append(part)
    data: dict = {"about": about}
    if len(parts) > SYSTEM_PARTS_IN_FULL:
        data["isBasedOn"] = urllib.parse.urljoin(SITE_URL, "downloads/platform-files.csv")
    elif parts:
        data["hasPart"] = parts
    return data


def dataset_structured_data(exports: list[dict], db: dict) -> dict:
    """The data page as a schema.org Dataset a harvester can index.

    It was a Dataset named "Data & API" with no download, licence, date or
    creator, so Google Dataset Search and open-data catalogues had nothing
    to list. The exports are metadata this project authors: MIT, as the
    LICENSE's scope says.
    """
    data: dict = {
        "name": f"{SITE_NAME} collection data",
        "license": "https://opensource.org/licenses/MIT",
        "creator": {"@type": "Organization", "name": SITE_NAME, "url": REPO_URL},
        "distribution": [
            {
                "@type": "DataDownload",
                "name": item["title"],
                "contentUrl": urllib.parse.urljoin(SITE_URL, item["url"]),
                "encodingFormat": item["media_type"],
                "contentSize": f"{item['bytes']} B",
                "sha256": item["sha256"],
            }
            for item in exports
        ],
    }
    generated = str(db.get("generated_at") or "")[:10]
    if generated:
        data["dateModified"] = generated
    return data


def emulator_file_anchors(files: list[dict]) -> list[str]:
    """The id of each file card on an emulator page, in profile order.

    An entry that declares a hash is addressed by it: its anchor depends on
    its own content, never on the entries beside it, and a second version
    added under the same path moves nothing. An entry without one keeps
    its plain anchor when its path is declared once, and otherwise takes
    its size, else, when even the size is shared, its description. The
    page and its JSON-LD both read this, so a structured part links to its
    card. The plain anchor of a hashed card stays reachable through
    emulator_file_aliases.
    """
    bases = [
        "file-" + (
            re.sub(
                r"[^a-z0-9]+", "-",
                str(f.get("path") or f.get("standalone_path") or f.get("name", "")).lower(),
            ).strip("-") or "entry"
        )
        for f in files
    ]
    repeated = {b for b in bases if bases.count(b) > 1}

    def _version_key(f: dict) -> str:
        digest = _first_hash_value(f)
        if digest:
            return digest[:8]
        return f"{f['size']}b" if f.get("size") else ""

    keys = [
        (b, _version_key(f)) if b in repeated or _first_hash_value(f) else (b, "")
        for f, b in zip(files, bases)
    ]
    used: dict[str, int] = {}
    anchors = []
    for f, (base, key) in zip(files, keys):
        anchor = f"{base}-{key}" if key else base
        if keys.count((base, key)) > 1 and f.get("description"):
            described = re.sub(r"[^a-z0-9]+", "-", str(f["description"]).lower()).strip("-")
            anchor = f"{anchor}-{described[:40].strip('-')}"
        used[anchor] = used.get(anchor, 0) + 1
        if used[anchor] > 1:
            anchor = f"{anchor}-{used[anchor]}"
        anchors.append(anchor)
    return anchors


def emulator_file_aliases(files: list[dict], anchors: list[str]) -> list[str]:
    """The plain file-<path> id each card also answers to, or "".

    A link cited as emulators/raze/#file-duke3d-grp must still land once the
    card is addressed by its hash: the first card of that path keeps the
    plain id, unless another card already is it.
    """
    taken = set(anchors)
    aliases = []
    for f, anchor in zip(files, anchors):
        base = "file-" + (
            re.sub(
                r"[^a-z0-9]+", "-",
                str(f.get("path") or f.get("standalone_path") or f.get("name", "")).lower(),
            ).strip("-") or "entry"
        )
        if base in taken or anchor == base:
            aliases.append("")
        else:
            taken.add(base)
            aliases.append(base)
    return aliases


# A commit id: hexadecimal with a letter and a digit, 7 to 40 long. A version
# that holds one (0.8.139-2-g25e1ee2fd5) names no release.
_COMMIT_ID = re.compile(
    r"(?<![0-9a-f])(?=[0-9a-f]*[a-f])(?=[0-9a-f]*[0-9])[0-9a-f]{7,40}(?![0-9a-f])", re.I)


def release_versions(profile: dict) -> dict[str, str]:
    """The `core_version` of a profile by build mode ("" when one covers
    every build), kept only where it names a release: a number and no
    commit id. A commit id of digits only reads as a number, so a run that
    starts one of the profile's own pins is one too (supermodel3's
    "0.3a-1481545-mm")."""
    pins = [str(value).casefold()
            for field in ("source_commit", "upstream_commit")
            for value in (profile[field].values() if isinstance(profile.get(field), dict)
                          else [profile.get(field)])
            if value]

    def names_a_commit(value: str) -> bool:
        return bool(_COMMIT_ID.search(value)) or any(
            pin.startswith(run) for run in re.findall(r"[0-9a-f]{7,40}", value.casefold())
            for pin in pins)

    stated = profile.get("core_version")
    pairs = stated.items() if isinstance(stated, dict) else [("", stated)]
    versions = {str(mode): str(value or "").strip() for mode, value in pairs}
    return {mode: value for mode, value in versions.items()
            if re.search(r"[0-9]", value) and not names_a_commit(value)}


def record_emulator_page(name: str, profile: dict) -> None:
    """What the title and the description of an emulator page read."""
    key = f"emulators/{name}.md"
    PAGE_DATA[key] = emulator_structured_data(profile)
    listed = [f for f in profile.get("files") or [] if isinstance(f, dict)]
    fetched = [f for f in listed if f.get("name") and not comes_with_app(f)]
    systems = profile.get("systems") or []
    first = systems[0] if systems else ""
    makers = [_system_page_map[sys_id][0] for sys_id in systems if sys_id in _system_page_map]
    if makers:
        sitestarlight.EMULATOR_CARDS[f"emulators/{name}"] = makers[0]
    else:
        sitestarlight.EMULATOR_CARDS.pop(f"emulators/{name}", None)
    # The first system's files first: "dreamcast bios" found Flycast's
    # page, whose required NAOMI archives came before dc_boot.bin.
    names: dict[str, str] = {}
    for f in sorted(fetched, key=lambda f: (f.get("system", first) != first,
                                            f.get("required") is not True)):
        base = Path(str(f["name"])).name
        names.setdefault(base.casefold(), base)
    firmware = [f for f in fetched if f.get("category", "bios") in ("bios", "bios_zip")]
    EMULATOR_SNIPPETS[key] = (
        # One console names an emulator of five systems, not BizHawk of 40.
        system_name(first) if 0 < len(systems) <= 5 else "",
        list(names.values()),
        len({Path(str(f["name"])).name.casefold() for f in fetched if f.get("required") is True}),
        _snippet_noun(names.values(), len(firmware), len(fetched)),
    )
    if listed and all(comes_with_app(f) for f in listed):
        NOTHING_TO_FETCH.add(key)
    else:
        NOTHING_TO_FETCH.discard(key)


def emulator_structured_data(profile: dict) -> dict:
    """What an emulator page states, for a reader of its JSON-LD.

    The block said only the page name: a crawler could not learn which files
    the core loads, their hashes, the source read or when.
    """
    data: dict = {}
    # Every repository the profile reads. The source repository carries the
    # release the profile describes, never a commit id: a pin is no version.
    # The upstream of a port is another code base and states none.
    versions = release_versions(profile)
    about = []
    seen: set[str] = set()
    for field in ("source", "upstream"):
        urls = profile.get(field)
        for mode, url in (urls.items() if isinstance(urls, dict) else [("", urls)]):
            if not url or not str(url).startswith("http") or str(url) in seen:
                continue
            seen.add(str(url))
            entry = {
                "@type": "SoftwareSourceCode",
                "name": str(profile.get("emulator", "")),
                "codeRepository": str(url),
            }
            version = (versions.get(mode) or versions.get("")) if field == "source" else None
            if version:
                entry["version"] = version
            about.append(entry)
    if about:
        data["about"] = about[0] if len(about) == 1 else about
    if profile.get("profiled_date"):
        data["dateModified"] = str(profile["profiled_date"])
    parts = []
    files = [f for f in profile.get("files") or [] if isinstance(f, dict)]
    for f, anchor in zip(files, emulator_file_anchors(files)):
        if not f.get("name"):
            continue
        # One identifier per accepted value: "sha256:a,b,c,d" matched no
        # exact search (mesence's BS-X.bin).
        identifiers = [
            f"{field}:{value}"
            for field in ("sha1", "sha256", "md5", "crc32")
            for value in _hash_values(f.get(field))
        ]
        part = {
            "@type": "CreativeWork",
            "name": str(f.get("path") or f["name"]),
            # The card's own anchor, as system and platform parts carry.
            "url": f"#{anchor}",
        }
        if identifiers:
            part["identifier"] = identifiers
        # An archive is identified by its members: MAME and FBNeo hash them,
        # never the ZIP, and 1 338 archive parts had no identifier at all.
        members = [
            {
                "@type": "CreativeWork",
                "name": str(member.get("name", "")),
                "identifier": [
                    f"{field}:{value}"
                    for field in ("sha1", "crc32")
                    for value in _hash_values(member.get(field))
                ],
            }
            for member in f.get("contents") or []
            if isinstance(member, dict) and member.get("name")
            and (member.get("sha1") or member.get("crc32"))
        ]
        if members:
            part["hasPart"] = members
        parts.append(part)
    if len(parts) > SYSTEM_PARTS_IN_FULL:
        # MAME's 1,564 entries and their members were 614 KB of JSON-LD: past
        # the cap the members are left to the profile's JSON.
        for part in parts:
            part.pop("hasPart", None)
    if parts:
        data["hasPart"] = parts
    return data


# Working notes kept under docs/ during development, never part of the site,
# and no generated page lives in a directory of these names.
LOCAL_NOTE_DIRS = ("plans", "specs")


# The funnel: who each page is written for, from someone who knows nothing
# (start) to someone adding to the project (contribute). The label sits above
# the title, and the search ranks the first two levels higher.
LEVELS = {
    "start": "Start here",
    "setup": "Setup guide",
    "explore": "Details",
    "reference": "Reference",
    "contribute": "For contributors",
}
# How much the site search weighs the words of a page (Pagefind's
# data-pagefind-weight, 1 by default). Each value was measured on the
# queries of website/tools/search_gate.py.
# - Start here pages answer a beginner's words first.
# - A system page holds the file cards themselves: a file name finds its
#   card before a guide that cites the name as an example.
# - A setup guide is found by its name (the page title weighs it).
# - A guide behind the first two levels (reference, options, contributing)
#   names everything a reader types, and ranks after the page that answers.
# - A launcher, an alias or a frozen copy answers a name after the emulator.
# - A part of a split page (a console's files, 5 of 9) holds cards, each found
#   by its own heading, and ranks after the page that answers the question.
SEARCH_WEIGHT = {"start": 10, "setup": 1.5, "reference": 0.5, "contribute": 0.5, "part": 0.5}
SYSTEM_PAGE_WEIGHT = 5
DEEP_GUIDE_WEIGHT = 0.5
SEARCH_DEMOTED: set[str] = set()
# A tool page a reader reaches by a task, not its name: "check my dump",
# "md5 check" found emulator pages and never the page that checks a file.
SEARCH_WEIGHT_OF_PAGE = {"files/index.md": 2}
DEMOTED_WEIGHT = 0.5


def search_weight(relative: Path, level: str) -> float | None:
    """The search weight of a page, None for the default. A part page
    states its own in its front matter: search_weight(path, "part")."""
    if level == "part":
        return SEARCH_WEIGHT["part"]
    if relative.as_posix() in SEARCH_WEIGHT_OF_PAGE:
        return SEARCH_WEIGHT_OF_PAGE[relative.as_posix()]
    if relative.as_posix() in SEARCH_DEMOTED:
        return DEMOTED_WEIGHT
    if relative.parts[0] == "systems":
        return SYSTEM_PAGE_WEIGHT
    if relative.parts[0] == "wiki" and level not in ("start", "setup"):
        return DEEP_GUIDE_WEIGHT
    return SEARCH_WEIGHT.get(level)


_REFERENCE_PAGES = {
    "gaps.md", "cross-reference.md", "provenance.md", "exports.md", "data.md",
    "files/index.md", "wiki/data-model.md", sitemeasurements.EXPLORER_PAGE,
}


def page_level(relative: Path) -> str:
    """The level of a generated page. A wiki page states its own."""
    path = relative.as_posix()
    if path in ("index.md", "which-pack.md"):
        return "start"
    if relative.parts[0] in ("platforms", release_record.GET_DIR):
        return "setup"
    if relative.parts[0] in ("systems", "emulators") or path == "explore.md":
        return "explore"
    if path in _REFERENCE_PAGES:
        return "reference"
    if path == "contributing.md":
        return "contribute"
    return ""


def level_label(level: str) -> str:
    """The visible label of a level, plain text for the theme to style."""
    return f'<span class="rb-level rb-level-{level}">{LEVELS[level]}</span>'


def _front_matter(markdown: str) -> dict:
    """The YAML front matter of a page, empty when it has none."""
    if not markdown.startswith("---\n"):
        return {}
    end = markdown.find("\n---\n", 4)
    if end == -1:
        return {}
    data = yaml.safe_load(markdown[4:end])
    return data if isinstance(data, dict) else {}


@functools.lru_cache(maxsize=None)
def _sha1_by_prefix(db_path: str) -> dict[str, str]:
    return {sha1[:12]: sha1 for sha1 in load_database(db_path)["files"]}


def _cards_elsewhere(markdown: str) -> str:
    """A start line links each file to its card. A console split over part
    pages keeps its cards on the parts, so a card this page does not hold
    is reached by its permanent link instead."""
    links = set(re.findall(r"\]\(#(sha1-[0-9a-f]{12})\)", markdown))
    away = {ident for ident in links if f'id="{ident}"' not in markdown}
    if not away:
        return markdown
    by_prefix = _sha1_by_prefix(str(siteinputs.current().db))
    for ident in away:
        full = by_prefix[ident.removeprefix("sha1-")]
        markdown = markdown.replace(f"](#{ident})", f"]({markup.site_href(f'files/?sha1={full}')})")
    return markdown


def decorate_markdown_pages(docs: Path) -> dict[str, str]:
    """Add per-page descriptions and machine-readable structured data.

    Under Starlight each page is written in its final form (front matter,
    site addresses, pinned heading ids) and the dates a page states are
    returned by address, for the sitemap.
    """
    lastmod: dict[str, str] = {}
    terms = sitestarlight.glossary_terms(_REPO_ROOT / WIKI_SRC_DIR / "glossary.md")
    # The console words of every system page, decorated or not: a console
    # another page's words cover gets a search field of its own.
    console_words: dict[str, set[str]] = {}
    for path in sorted((docs / "systems").glob("*.md*")):
        text = path.read_text(encoding="utf-8")
        words = sitestarlight.page_console_words(_front_matter(text), text)
        if words:
            console_words[path.relative_to(docs).with_suffix("").as_posix()] = words
    for path in sorted(docs.rglob("*.md")):
        relative = path.relative_to(docs)
        if any(part in LOCAL_NOTE_DIRS for part in relative.parts[:-1]):
            continue
        original = path.read_text(encoding="utf-8")
        authored = _front_matter(original)
        if "head" in authored:
            # Written in its final form by an earlier pass and rewritten by
            # nothing since: a second pass would find no title to read.
            continue
        markdown = _cards_elsewhere(prepare_page(original, relative))
        for image_id in unresolved_images(markdown):
            print(f"  WARNING: {relative}: no diagram named {image_id!r}", file=sys.stderr)
        stripped = _undecorated(markdown)
        if stripped is not markdown:
            markdown = stripped
        elif authored:
            # A wiki page states its own level: keep it, wrap the body.
            markdown = markdown[markdown.find("\n---\n", 4) + 5:].lstrip("\n")
        level = authored.get("level") or page_level(relative)

        title = _page_title(markdown, relative)
        browser_title = _browser_title(relative, title)
        description = str(authored.get("description") or _page_description(markdown, relative, title))
        if relative.name == "index.md":
            page_path = "" if len(relative.parts) == 1 else "/".join(relative.parts[:-1]) + "/"
        else:
            page_path = relative.with_suffix("").as_posix() + "/"
        # Encoded as mkdocs encodes the canonical link and the sitemap:
        # idtech4a++ named .../idtech4a++/ here and .../idtech4a%2B%2B/ there.
        canonical = urllib.parse.urljoin(SITE_URL, urllib.parse.quote(page_path))
        schema_type = "WebSite" if relative.as_posix() == "index.md" else "TechArticle"
        if relative.as_posix() == "data.md":
            schema_type = "Dataset"
        structured = {
            "@context": "https://schema.org",
            "@type": schema_type,
            "name": title,
            "description": description,
            "url": canonical,
            "isPartOf": {
                "@type": "WebSite",
                "name": SITE_NAME,
                "url": SITE_URL,
            },
            **PAGE_DATA.get(relative.as_posix(), {}),
        }
        if schema_type == "WebSite":
            # The home page is the site: named as the site, part of nothing.
            structured["name"] = SITE_NAME
            del structured["isPartOf"]
        target, text = sitestarlight.finalize_page(
            relative.as_posix(), markdown, level=level,
            weight=search_weight(relative, level),
            browser_title=browser_title,
            description=description, structured=structured, terms=terms,
            search=authored.get("search") != "exclude",
            logo=str(authored.get("logo") or ""),
            parent=authored.get("parent"),
            authored=authored,
            words_by_page=console_words,
        )
        write_decorated(docs / target, text)
        # One file per page: a page that gained or lost its components
        # changed extension, and the other one would claim its address.
        stem = relative.with_suffix("").as_posix()
        for suffix in (".md", ".mdx"):
            if f"{stem}{suffix}" != target:
                (docs / f"{stem}{suffix}").unlink(missing_ok=True)
        if structured.get("dateModified"):
            lastmod[sitestarlight.page_url(target)] = str(structured["dateModified"])
    return lastmod


# Platform pages


def generate_platform_index(coverages: dict, registry: dict | None = None) -> str:
    """The Setups tab: every platform by the device it runs on, and one
    line to the table that sets them side by side (setup_table), which is
    reference matter and sits with how each setup checks its files."""
    registry = registry or {}
    lines = [
        "# Setups",
        "",
        "Each setup's page gives the folder and the command.",
        "",
    ]
    for group, (label, _description) in DEVICE_GROUPS.items():
        members = _group_members(coverages, registry, group)
        if not members:
            continue
        # The group label names the devices, and each card carries its
        # setup's own sentence. The kinds of device that run a setup
        # follow, as on the home tiles.
        lines += [f"## {label}", ""]
        lines += markup.card_grid([
            *((f"[{coverages[name]['platform']}]({name}.md)", [GUIDES[name].summary])
              for name in members),
            *((f"[{tile.name}](../{tile.link})", [tile.text])
              for tile in GROUP_TILES.get(group, ())),
        ])
    lines += [
        f"Comparing setups? [Every setup side by side](../{SETUP_TABLE_LINK})",
        "",
    ]
    return "\n".join(lines) + "\n"


# Where the side-by-side table of setups is published: with how each setup
# checks its files, the column a reader compares.
SETUP_TABLE_PAGE = "wiki/verification-modes.md"
SETUP_TABLE_ANCHOR = "every-setup-at-a-glance"
SETUP_TABLE_LINK = f"{SETUP_TABLE_PAGE}#{SETUP_TABLE_ANCHOR}"


def setup_table(coverages: dict) -> list[str]:
    """Every setup side by side: the files on its own list, the files in its
    ZIP, and how it checks them. Written under the Reference level, on the
    page that explains each way of checking."""
    lines = [
        f"## Every setup at a glance {{ #{SETUP_TABLE_ANCHOR} }}",
        "",
        "| Setup | Files on its own list | Files in the ZIP | How it checks |",
        "|-------|------:|------:|---------------|",
    ]
    for name, cov in sorted(coverages.items(), key=lambda item: item[1]["platform"].casefold()):
        listed = f"{cov['total']:,}" if cov["total"] else "No list of its own"
        files, _size = release_totals(name, release_record.load_advertised())
        zipped = (f"{files:,}" if files
                  else "No ZIP yet" if has_release_pack(name) else "No ZIP")
        lines.append(
            f"| [{cov['platform']}](../platforms/{name}.md) | {listed} | {zipped} | "
            f"{check_label(cov['mode'], cov['config'].get('hash_rule'))} |"
        )
    lines += [
        "",
        "The ZIP adds the files its emulators load to the files on the setup's own list.",
        "",
    ]
    lines += ["No ZIP: the setup is served by the command alone. "
              f"[Why?](../{NO_ZIP_FAQ})", ""]
    return lines


def with_setup_table(page: str, coverages: dict) -> str:
    """The comparison table placed before the Next steps of its page, or at
    its end."""
    table = "\n".join(setup_table(coverages))
    marker = "\n## Next steps"
    if marker in page:
        head, tail = page.split(marker, 1)
        return f"{head.rstrip()}\n\n{table}{marker}{tail}"
    return f"{page.rstrip()}\n\n{table}"


# A platform's file lists are split by the share of a page they render to,
# in thousandths: their elements against validate_site's MAX_PAGE_ELEMENTS,
# their bytes against the 600,000 of test_site_built_gate, whichever is
# larger. Measured in Markdown characters, the lists split anew whenever
# their markup changed: rows written as tables moved 38 more systems to
# pages of their own.
PAGE_ELEMENTS = 10_000
PAGE_BYTES = 600_000
# A system whose list passes this share gets a page of its own.
PLATFORM_SECTION_BUDGET = 400
# A system's own page in runs of at most this share.
PLATFORM_PART_BUDGET = 700
# The share of a platform page's file lists, past which the largest
# systems move to pages of their own.
PLATFORM_REFERENCE_BUDGET = 600


# Every part page the site has published, with the page it belongs to:
# platforms/batocera-atari-st.md -> platforms/batocera.md#atari-st,
# gaps-files-to-source-7.md -> gaps.md. When a budget or a list changes, a
# part can fold back or the list shrink, and its address then redirects to
# that page instead of ending on the 404 page.
PUBLISHED_PARTS_FILE = (Path(__file__).resolve().parent.parent
                        / "website" / "src" / "data" / "published-parts.json")


def _published_parts() -> dict[str, str]:
    if not PUBLISHED_PARTS_FILE.is_file():
        return {}
    return json.loads(PUBLISHED_PARTS_FILE.read_text(encoding="utf-8"))


def _parent_page(link: str) -> str:
    """The page a `parent:` link names (/platforms/batocera/), under docs/."""
    path, _, fragment = link.partition("#")
    # Written with the site's base (/retrobios/emulators/x/) or without it.
    path = path.removeprefix(sitestarlight.BASE.rstrip("/"))
    stem = path.strip("/") or "index"
    return f"{stem}.md" + (f"#{fragment}" if fragment else "")


def record_parts(docs: Path, present: set[str], published: dict[str, str]) -> dict[str, str]:
    """``published`` with every page of this run that names its parent.

    Only platform parts were recorded: gaps-files-to-source-7 or
    mame-files-10, gone once their list shrank, ended on the 404 page. A
    part already recorded keeps its target, which may name a section.
    """
    found = dict(published)
    for rel in sorted(present):
        page = docs / rel
        if not page.is_file():
            page = page.with_suffix(".mdx")
        try:
            parent = _front_matter(page.read_text(encoding="utf-8")).get("parent")
        except OSError:
            continue
        if isinstance(parent, dict) and parent.get("link") and rel not in found:
            found[rel] = _parent_page(str(parent["link"]))
    return dict(sorted(found.items()))


# A list moved off a reference page (gaps, provenance) is cut in parts of
# at most this much Markdown: about 450 KB of HTML each.
LIST_PART_BUDGET = 300_000


def _characters(lines: list[str]) -> int:
    return sum(len(line) + 1 for line in lines)


def _blocks_in_runs(blocks: list[list[str]], budget: int,
                    weigh: Callable[[list[str]], int] = _characters) -> list[list[str]]:
    """Blocks (table rows, folded lists) in runs of at most ``budget``, by
    default in characters, a block never cut."""
    runs: list[list[str]] = [[]]
    size = 0
    for block in blocks:
        weight = weigh(block)
        if runs[-1] and size + weight > budget:
            runs.append([])
            size = 0
        runs[-1].extend(block)
        size += weight
    return runs


def _parent_front_matter(parent: tuple[str, str] | None) -> list[str]:
    """The `parent:` front matter of a part page: the page it belongs to,
    by label and site path, which the breadcrumb and sidebar read."""
    if parent is None:
        return []
    label, link = parent
    return ["parent:", f"  label: {json.dumps(label)}", f"  link: {json.dumps(link)}"]


def _list_pages(
    stem: str, title: str, intro: str, head: list[str], blocks: list[list[str]],
    moved: dict[str, str], budget: int = LIST_PART_BUDGET,
    parent: tuple[str, str] | None = None,
) -> str:
    """Pages of their own for a long list: ``head`` (a table header, say)
    opens each part, ``blocks`` are cut between parts. Returns where the list
    went, as the page it left says it. ``parent`` (label, site path) is the
    page the parts belong to, for the breadcrumb."""
    runs = _blocks_in_runs(blocks, budget)
    stems = [stem + (f"-{n}" if n > 1 else "") for n in range(1, len(runs) + 1)]
    for n, (here, run) in enumerate(zip(stems, runs), 1):
        part = f" (part {n} of {len(runs)})" if len(runs) > 1 else ""
        # The page description is the opening of the intro: parts sharing
        # one read as duplicates to search and to validate_site.
        opening = f"Part {n} of {len(runs)}. {intro}" if len(runs) > 1 else intro
        moved[here] = "\n".join([
            "---", "level: reference", *_parent_front_matter(parent), "---", "",
            f"# {title}{part}", "", opening, "",
            *([", ".join(f"[part {i}]({other}.md)" if other != here else f"part {i}"
                         for i, other in enumerate(stems, 1)), ""] if len(runs) > 1 else []),
            *head, *run, "", _date_line(),
        ]) + "\n"
    if len(stems) == 1:
        return f"[a page of their own]({stems[0]}.md)"
    return "pages of their own: " + ", ".join(
        f"[part {i}]({other}.md)" for i, other in enumerate(stems, 1))


def _collection_sha1_by_path() -> dict[str, str]:
    """The sha1 of each file the collection holds, by its path."""
    return _sha1_by_path_in(str(siteinputs.current().db))


@functools.lru_cache(maxsize=None)
def _sha1_by_path_in(db_path: str) -> dict[str, str]:
    with open(db_path, encoding="utf-8") as handle:
        files = json.load(handle).get("files", {})
    return {str(entry.get("path", "")): sha1 for sha1, entry in files.items()}


def _system_heading_link(sys_id: str, prefix: str = "") -> str:
    """A system's name, linked to its own console section when it has one.

    The id stays beside it in small text: it is what the platform's list
    writes. A system with no section of its own is named, never sent to the
    page a storage folder chose.
    """
    return f"{_system_named_link(sys_id, prefix)} <small>{_escape_tags(sys_id)}</small>"


def _system_named_link(sys_id: str, prefix: str = "") -> str:
    """A system's name, linked to the section system_section gives."""
    from siterender import system_section

    name = _escape_tags(system_name(sys_id))
    section = system_section(sys_id)
    if section is not None:
        slug, console = section
        name = f"[{name}]({console_href(slug, console, prefix)})"
    return name


def _emulator_named_link(key: str, prefix: str = "") -> str:
    """An emulator by the name its page carries, linked to that page. A
    profile with no page (an alias, a test) is named only."""
    profile = _profiles_on_disk().get(key, {})
    label = _escape_tags(str(profile.get("emulator") or key))
    if profile.get("type") == "alias" or profile.get("role") == "test":
        return label
    return f"[{label}]({prefix}emulators/{key}.md)"


def _served_line(f: dict, declared_sha1: str = "") -> str:
    """Which collection file answers the entry, from the resolver's result.

    "OK" with no path gave an expert nothing to check: Batocera's
    scph1001.bin is served by bios/Sony/PlayStation/scph1001_v20.bin.
    The copy's sha1 is named only when it is not one the row already
    declares (Recalbox joins several with commas).
    """
    path = str(f.get("path") or "")
    if f.get("status") == "missing":
        return "Not held"
    if not path:
        # A slot the pack fills from a release asset or leaves to the user.
        return ""
    sha1 = _collection_sha1_by_path().get(path, "")
    label = "Served by" if f.get("status") == "ok" else "Held, not the declared hash"
    parts = path.split("/")
    if not sha1 or len(parts) < 3 or parts[0] != "bios":
        return f"{label}: {_code(path)}"
    # The card of that copy: every hash, provenance and the download.
    page = urllib.parse.quote(card_page(path, sha1))
    link = f"{label}: [{_code(path)}](../systems/{page}.md#sha1-{sha1[:12]})"
    declared = {value.strip().lower() for value in declared_sha1.split(",")}
    return link if sha1 in declared else f"{link} (sha1 `{sha1[:8]}`)"


def _launcher_refs(config: dict) -> dict[str, list[str]]:
    """Entry name, casefolded -> each launcher record that opens it, rendered."""
    from launchers import _names as launcher_names
    from sitesources import launcher_ref_markdown, list_source

    # Every scraper reads its launchers in the repository and at the revision
    # of the list it scrapes, so `source` pins each source_ref.
    source = list_source(str(config.get("source") or ""))
    found: dict[str, list[str]] = {}
    for record in config.get("launchers") or []:
        if not isinstance(record, dict) or not record.get("source_ref"):
            continue
        text = (f"{_escape_tags(str(record.get('emulator', '')))} at "
                f"{launcher_ref_markdown(source, str(record['source_ref']))}")
        for name in launcher_names(record):
            names = found.setdefault(name.rsplit("/", 1)[-1].casefold(), [])
            if text not in names:
                names.append(text)
    return found


# The hash a row shows first, when the list does not say which it checks.
_ROW_HASHES = ("sha1", "md5", "sha256", "crc32")
# An untested entry whose reason is a hash the bytes do not match.
_OTHER_HASH = re.compile(r"hash|mismatch|expected|must match", re.IGNORECASE)
# A list this long gets a filter box above it, as a table of RECORD_ROWS
# rows does (website/src/plugins/rehype-stack-tables.mjs).
FILTER_ROWS = 20


def _status_chip(f: dict) -> str:
    """The row's status as a chip, its word and its colour saying the same. A
    declared hash the held copy does not have is "Other hash": the two differ,
    which says nothing of whose is right (a platform may pin its own bundle)."""
    status = f.get("status")
    if status == "ok":
        word, tone = "OK", "success"
    elif status == "missing":
        word, tone = "Missing", "danger"
    elif status == "untested":
        word = "Other hash" if _OTHER_HASH.search(str(f.get("reason") or "")) else "Untested"
        tone = "warning"
    else:
        word, tone = str(status), "muted"
    return f'<span class="rb-badge rb-badge-{tone}">{html.escape(word)}</span>'


def _copy_hash(algorithm: str, value: str | list) -> str:
    """A declared hash cut to SHORT_HASH characters on a button that copies
    it whole. A list of accepted values (Recalbox) copies its first. Outside
    a form a button submits nothing, so it carries no type."""
    from hashing import parse_hash_list  # noqa: PLC0415

    values = parse_hash_list(value)
    if not values:
        return ""
    first = html.escape(values[0])
    more = f" +{len(values) - 1}" if len(values) > 1 else ""
    return (f'<button class="rb-copy" data-copy="{first}" '
            f'aria-label="Copy {algorithm.upper()} {first[:SHORT_HASH]}{more}">'
            f'{first[:SHORT_HASH]}{more}</button>')


# Characters Markdown or MDX would read inside the raw HTML of a row: an
# MDX page parses the text of its HTML as Markdown, a .md page does not.
_INERT = str.maketrans({"*": "&#42;", "_": "&#95;", "`": "&#96;", "[": "&#91;", "]": "&#93;"})
_INLINE_MD = re.compile(
    r"\[(?P<label>(?:`[^`]*`|[^\]`])+)\]\((?P<url>[^)\s]+)\)"
    r"|`(?P<code>[^`]+)`"
    r"|\*\*(?P<bold>[^*]+)\*\*"
)


def _text_html(text: str) -> str:
    """Plain text as HTML that neither Markdown nor MDX rewrites."""
    return html.escape(html.unescape(text), quote=False).translate(_INERT)


def _inline_html(markdown: str) -> str:
    """The inline Markdown of a row's evidence (links, code, bold) as HTML.

    Code spans become plain text and a linked path loses its code element:
    one per reference and per reader was the bulk of the elements of a
    platform page, and the words say the same without them.
    """
    out: list[str] = []
    position = 0
    for match in _INLINE_MD.finditer(markdown):
        out.append(_text_html(markdown[position:match.start()]))
        if match["url"]:
            out.append(f'<a href="{html.escape(match["url"])}">'
                       f'{_text_html(match["label"].replace("`", ""))}</a>')
        elif match["code"]:
            out.append(_text_html(match["code"]))
        else:
            out.append(f"<strong>{_text_html(match['bold'])}</strong>")
        position = match.end()
    out.append(_text_html(markdown[position:]))
    return "".join(out)


def _row_path(fname: str, cfg_entry: dict) -> str:
    """Where the file goes, when its name alone does not say: three GameCube
    IPL.bin differ only by GC/USA, GC/EUR and GC/JAP. A destination that is
    the name says nothing, and one that ends with it shows its folder."""
    destination = str(cfg_entry.get("destination") or "")
    if destination.endswith("/" + fname):
        return destination[:len(destination) - len(fname)]
    return "" if destination == fname else destination


def _platform_file_row(f: dict, cfg_entry: dict, hash_type: str = "",
                       launched: list[str] | None = None) -> str:
    """One file of a platform's list as one row, written as HTML.

    The row is a details element whose summary holds the name, the folder
    when there is one and the status, followed by the short hash on its copy
    button: a button cannot sit in a summary, which is itself a control.
    The details hold every hash the platform declares, the size, the copy
    that serves it and its readers, across the width of the list.
    """
    fname = f["name"]
    hashes = {
        "sha1": cfg_entry.get("sha1", f.get("sha1", "")),
        "md5": cfg_entry.get("md5", f.get("expected_md5", "")),
        # The crc32 is what System.dat and clrmamepro print. RetroDECK
        # declares sha256 too (dsifirmware.bin).
        "crc32": str(cfg_entry.get("crc32") or ""),
        "sha256": str(cfg_entry.get("sha256") or ""),
    }
    size = cfg_entry.get("size", f.get("size", 0))
    shown = next((alg for alg in (hash_type, *_ROW_HASHES) if alg in hashes and hashes[alg]), "")

    facts: list[str] = []
    # One code element per value: Recalbox lists accepted md5s joined by
    # commas, and each is a value a reader compares a dump with.
    facts.extend(f"{alg.upper()}: {_hash_spans(hashes[alg])}"
                 for alg in ("sha1", "md5", "crc32", "sha256") if hashes[alg])
    # The size closes the hash lines: a line of its own was one more
    # element per row.
    if size and facts:
        facts[-1] += f" ({_fmt_size(size)})"
    elif size:
        facts.append(f"Size: {_fmt_size(size)}")
    if f.get("status") == "untested" and f.get("reason"):
        facts.append(_text_html(f"Not confirmed: {f['reason']}"))
    # Not every entry is firmware: the platform may list a game's data or a
    # file no core it runs opens.
    kind = {"game_data": "Game data, not firmware",
            "unread": "No core the platform runs opens it"}.get(f.get("category", ""))
    if kind:
        facts.append(kind)
    served = _served_line(f, str(hashes["sha1"] or ""))
    if served:
        facts.append(_inline_html(served))
    if f.get("category_evidence"):
        facts.append(_inline_html(_category_evidence_md(f["category_evidence"], launched)))

    path = _row_path(fname, cfg_entry)
    summary = (_text_html(fname) + (f"<code>{_text_html(path)}</code>" if path else "")
               + _status_chip(f))
    copy = _copy_hash(shown, hashes[shown]) if shown else ""
    return (f'<details class="rb-file"><summary>{summary}</summary>'
            f'{"<br>".join(facts)}</details>{copy}')


def _platform_file_list(rows: list[str], has_path: bool, anchor: str) -> list[str]:
    """A system's rows as one HTML block, with a filter box when long.

    The list drops its path column when no row has one, so a blank cell
    never reads as missing data.
    """
    lines: list[str] = []
    if len(rows) >= FILTER_ROWS:
        field = f"rb-files-filter-{anchor}"
        lines += [
            '<div class="rb-table-filter">'
            f'<label for="{field}">Filter files</label>'
            f'<input id="{field}" type="search" autocomplete="off" placeholder="File, path, status, hash...">'
            f'<span class="rb-table-filter-count" aria-live="polite">{len(rows):,} rows</span></div>',
            "",
        ]
    kind = "rb-files rb-files-path" if has_path else "rb-files"
    return [*lines, f'<div class="{kind}">', *rows, "</div>"]


# The elements a line puts on the page: its HTML tags, and the links and
# code spans of the Markdown before a list.
_ELEMENT = re.compile(r"<[a-zA-Z]|\]\(|`[^`]+`")


def _element_weight(lines: list[str]) -> int:
    """How many elements the lines render to."""
    return sum(len(_ELEMENT.findall(line)) for line in lines)


def _page_share(lines: list[str]) -> float:
    """The share of a page the lines render to, in thousandths: the rows
    are HTML already, so their length is their weight in bytes."""
    return max(_element_weight(lines) * 1000 / PAGE_ELEMENTS,
               _characters(lines) * 1000 / PAGE_BYTES)


def _render_platform_systems(
    by_system: dict, config_files: dict, emulator_files: dict,
    platform: tuple[str, str] | None = None, moved: dict[str, str] | None = None,
    config: dict | None = None,
) -> list[str]:
    """One collapsible block per system, listing every file it needs.

    Split out of generate_platform_page: the block is most of that
    function's branching, since each file renders a different set of
    hashes, sizes and provenance depending on what the platform declares.
    With ``platform`` (its key and name) and ``moved``, a list longer than
    PLATFORM_SECTION_BUDGET goes to a page of its own, written into
    ``moved`` by stem, and the system's heading stays with a link to it.
    """
    lines: list[str] = []
    # Per-system detail sections (collapsible for large platforms)
    use_collapsible = len(by_system) > 10
    by_system_declared = _declared_by_system(config_files)
    launched = _launcher_refs(config or {})

    sections: list[dict] = []
    for sys_id, files in sorted(by_system.items()):
        ok_count = sum(1 for f in files if f["status"] == "ok")
        total = len(files)

        sys_emus = _system_emulators(sys_id, emulator_files, by_system_declared.get(sys_id))
        anchor = sys_id.replace(" ", "-")
        head = [f"{ok_count}/{total} files verified"]
        if sys_emus:
            emu_links = ", ".join(_emulator_named_link(e, "../") for e in sorted(sys_emus))
            head[-1] += "\\"
            head.append(f"Emulators: {emu_links}")
        head.append("")

        # One row per file, the evidence in its details. The sort is stable,
        # so same-named entries keep the order verify reported them in,
        # which is the declaration order.
        rows: list[str] = []
        has_path = False
        seen_names: dict[str, int] = {}
        for f in sorted(files, key=lambda x: x["name"]):
            fname = f["name"]
            declared = config_files.get((sys_id, fname), [])
            nth = seen_names.get(fname, 0)
            seen_names[fname] = nth + 1
            cfg_entry = declared[nth] if nth < len(declared) else {}
            has_path = has_path or bool(_row_path(fname, cfg_entry))
            rows.append(_platform_file_row(
                f, cfg_entry, str((config or {}).get("hash_type") or ""),
                launched.get(fname.rsplit("/", 1)[-1].casefold())))
        body = head + _platform_file_list(rows, has_path, anchor)

        # Measured in the share of a page the list renders to.
        size = _page_share(body)
        if use_collapsible:
            status_tag = "OK" if ok_count == total else _count(total - ok_count, "issue")
            block = markup.details("note", f"{_count(total, 'file')} ({status_tag})", body)
            while block and not block[-1]:
                block.pop()
        else:
            block = body
        sections.append({"sys_id": sys_id, "anchor": anchor, "head": head, "rows": rows,
                         "has_path": has_path, "block": block,
                         "size": size, "total": total, "ok": ok_count})

    # A list longer than its budget goes to a page of its own, then the
    # largest lists until the page's reference fits PLATFORM_REFERENCE_BUDGET:
    # with each file's served copy and pinned readers, Batocera's 97 systems
    # rendered 785 KB of HTML on one page.
    own_page: set[str] = set()
    if moved is not None and platform:
        own_page = {sec["sys_id"] for sec in sections if sec["size"] > PLATFORM_SECTION_BUDGET}
        kept = sum(sec["size"] for sec in sections if sec["sys_id"] not in own_page)
        for sec in sorted(sections, key=lambda sec: -sec["size"]):
            if kept <= PLATFORM_REFERENCE_BUDGET:
                break
            if sec["sys_id"] not in own_page:
                own_page.add(sec["sys_id"])
                kept -= sec["size"]

    for sec in sections:
        sys_id, anchor = sec["sys_id"], sec["anchor"]
        total, ok_count = sec["total"], sec["ok"]
        # Every system is a heading with the same anchor in both layouts:
        # emulator cards link here, and the site search splits a page at its
        # headings. Folded into blocks under one heading, every hash pasted
        # in the search led to the systems overview of a 100-block page.
        lines.append(f"### {_system_heading_link(sys_id, '../')} {{ #{anchor} }}")
        lines.append("")
        if moved is not None and platform and sys_id in own_page:
            key, display = platform
            runs = [sec["head"] + _platform_file_list(run, sec["has_path"], anchor)
                    for run in _blocks_in_runs([[row] for row in sec["rows"]],
                                               PLATFORM_PART_BUDGET, _page_share)]
            stems = [f"{key}-{anchor}" + (f"-{n}" if n > 1 else "")
                     for n in range(1, len(runs) + 1)]
            for n, (stem, run) in enumerate(zip(stems, runs), 1):
                part = f" (part {n} of {len(runs)})" if len(runs) > 1 else ""
                # A console query landed here with no way to the console's
                # own page: the list says whose it is first, linked.
                moved[stem] = "\n".join([
                    "---", *_parent_front_matter((display, f"/platforms/{key}/")), "---", "",
                    f"# {display}: {system_name(sys_id)}{part}", "",
                    f"{display}'s list for {_system_named_link(sys_id, '../')}. "
                    f"Part of the [{display} page]({key}.md#{anchor}), whose other systems "
                    f"are listed there. Each file below is as {display} declares it, with "
                    "its status in the pack.",
                    *([""] + [", ".join(
                        f"[part {i}]({other}.md)" if other != stem else f"part {i}"
                        for i, other in enumerate(stems, 1))] if len(runs) > 1 else []),
                    "", "## Files", "", *markup.details("note", ROLE_LEGEND_TITLE, [ROLE_LEGEND]),
                    *search_excluded(run),
                    "", _date_line(),
                ]) + "\n"
            # The count and status a folded system shows in its summary,
            # linked to the page that lists the files.
            tag = "OK" if ok_count == total else _count(total - ok_count, "issue")
            count = f"{_count(total, 'file')} ({tag})"
            lines.extend([
                f"[{count}]({stems[0]}.md)" if len(stems) == 1 else f"{count}: " + ", ".join(
                    f"[part {i}]({stem}.md)" for i, stem in enumerate(stems, 1)),
                "",
            ])
            continue
        # The section's heading stays searchable, its file list with every
        # hash is the lookup's: retrodeck's arcade list was 495 KB of index.
        lines.extend(search_excluded(sec["block"]))

    return lines


# Platforms with an updated file published by export_native.py.
_EXPORTED: set[str] = set()


def _platform_data_links(name: str) -> str:
    """The platform's own data, machine-readable: the YAML transcribed from
    its upstream list, this page's JSON and the manifest the installer reads.

    An emulator page linked its YAML and JSON, a platform page nothing: a
    tool had to download all twelve platforms in platforms.json and filter.
    """
    links = [
        f"[YAML]({REPO_URL}/blob/main/platforms/{name}.yml)",
        f"[JSON](../api/v1/platforms/{name}.json)",
    ]
    if (_REPO_ROOT / "install" / f"{name}.json").is_file():
        # The site's own copy, byte for byte (_publish_manifests).
        links.append(f"[install manifest](../api/v1/manifests/{name}.json)")
        # The installed BIOS folder for clrmamepro and RomVault.
        links.append(f"[DAT](../downloads/dat/{name}.dat)")
    return ", ".join(links)


def _site_profiles() -> dict[str, dict]:
    """Every emulator profile, read once for the citations of a page."""
    return _profiles_in(str(siteinputs.current().emulators), skip_aliases=True)


# Whose code a source reference cites, in one word: a platform page names
# each role once in ROLE_LEGEND. Written after every reference, "(emulator
# code, libretro port)" ran through Batocera's 14,000 words.
ROLE_WORDS = {
    "libretro glue": "glue",
    "emulator code, libretro port": "port",
    "upstream emulator": "upstream",
    "this build": "build",
}
ROLE_LEGEND_TITLE = "Source reference words"
ROLE_LEGEND = (
    "In a file's details, a word before its source references says whose code they are. "
    "**glue** means libretro glue, **port** means emulator code in the libretro port, "
    "**upstream** means the upstream emulator and **build** means this build's own code."
)


def _refs_by_role(profile: dict, value: str | dict | None) -> str:
    """A source_ref's parts grouped by whose code they cite, each role named
    once by its ROLE_WORDS word: `glue a.c:1, b.c:2 and port c.c:3`."""
    from sitesources import source_ref_items

    texts = []
    for label, items in source_ref_items(profile, value):
        by_role: dict[str, list[str]] = {}
        for part, role in items:
            by_role.setdefault(role, []).append(part)
        text = " and ".join(
            (f"{ROLE_WORDS.get(role, role)} " if role else "") + ", ".join(parts)
            for role, parts in by_role.items())
        texts.append(f"**{label}:** {text}" if label else text)
    return ", ".join(texts)


def _category_evidence_md(evidence: dict, launched: list[str] | None = None) -> str:
    """What establishes an entry's category, as the page shows it.

    ``launched`` holds the platform's launcher records that open the entry,
    already rendered: "(by launcher)" alone named no record and no line.
    """
    if evidence.get("read_by"):
        groups: dict[bool, list[str]] = {True: [], False: []}
        bare: list[str] = []
        profiles = _site_profiles()
        for reader in evidence["read_by"]:
            # Pinned links, the repository named in words: the refs were
            # plain code with the role word ("source") left in front.
            profile = profiles.get(reader["emulator"], {})
            refs = [
                (f"`{e['name']}` at {_refs_by_role(profile, e['source_ref'])}"
                 if e.get("source_ref") else f"`{e['name']}`")
                + (" (by name)" if e.get("by") == "name" else "")
                for e in reader.get("entries", [])
            ]
            if reader["emulator"] == "launcher":
                name = "the platform's launcher"
                refs = list(launched or [])
            else:
                name = _emulator_link(reader["emulator"], "../")
            groups[bool(reader.get("runs_system"))].append(
                f"{name} ({', '.join(refs)})" if refs else f"{name} (by {reader['proof']})")
            if not reader.get("runs_system"):
                # A launcher record is this platform's own code: kept whole.
                bare.append(f"{name} ({', '.join(refs)})"
                            if reader["emulator"] == "launcher" and refs else name)
        if not groups[True]:
            return "Read by " + ", ".join(groups[False])
        text = "Read by " + ", ".join(groups[True])
        # Cores of other systems that share the name: named, not cited, as
        # their lines describe another machine's file.
        if bare:
            text += ", also named by " + ", ".join(bare)
        return text
    examined = evidence.get("cores_examined") or []
    # A core the site gives no page (a test core) is named, not linked.
    with_page = _profiles_with_page(str(siteinputs.current().emulators))
    cores = ("cores examined: " + ", ".join(
        _emulator_link(c, "../") if c in with_page else c for c in examined)
             if examined else "no core examined")
    if evidence.get("unsettled"):
        return f"No reader found, not settled: {evidence['unsettled']} ({cores})"
    return f"No reader found ({cores})"


def _profiles_by_core_name() -> dict[str, list[str]]:
    """Core name as a platform writes it -> the profiles with a page for it.

    MinUI writes `mednafen_vb`, the profile and its page are `beetle_vb`.
    """
    return _core_names_in(str(siteinputs.current().emulators))


@functools.lru_cache(maxsize=None)
def _profiles_with_page(emulators_dir: str) -> frozenset[str]:
    """The profiles the site writes a page for: no alias, no test core."""
    profiles = _profiles_in(emulators_dir, skip_aliases=True)
    return frozenset(
        k for k, v in profiles.items() if v.get("type") != "alias" and v.get("role") != "test"
    )


@functools.lru_cache(maxsize=None)
def _core_names_in(emulators_dir: str) -> dict[str, list[str]]:
    profiles = _profiles_in(emulators_dir, skip_aliases=True)
    with_page = _profiles_with_page(emulators_dir)
    return {
        core: sorted(k for k in keys if k in with_page)
        for core, keys in upstream_profile_index(profiles).items()
    }


def _core_name_links(cores: list[str]) -> list[str]:
    """A link per core to its profile page, the bare name where none exists."""
    index = _profiles_by_core_name()
    links = []
    for core in cores:
        keys = [core] if core in index.get(core, []) else index.get(core, [])
        if keys:
            links.extend(_emulator_link(k, "../") for k in keys)
        else:
            links.append(f"`{core}`")
    return links


def _core_folders_section(name: str, config: dict) -> list[str]:
    """Each folder the frontend hands a core, and the files the pack puts in it.

    For a platform that names no file of its own (MinUI and its forks): the
    folders come from its launch scripts, the files from its install manifest.
    """
    folders = config.get("core_system_dirs") or {}
    manifest = _REPO_ROOT / "install" / f"{name}.json"
    files = json.loads(manifest.read_text())["files"] if manifest.is_file() else []
    lines = [
        "### Core folders",
        "",
        "Each folder below is the one the frontend gives that core. The pack "
        "puts the files the core reads there.",
        "",
        "| Folder | Cores | Files |",
        "|--------|-------|-------|",
    ]
    for folder, info in sorted(folders.items()):
        held = sorted(
            f["dest"][len(folder) + 1:] for f in files
            if f.get("dest", "").startswith(folder + "/")
        )
        cores = ", ".join(_core_name_links(info.get("cores", [])))
        shown = ", ".join(f"`{n}`" for n in held) if held else "none needed"
        lines.append(f"| `{folder}/` | {cores} | {shown} |")
    lines.append("")
    return lines


def _check_sentence(display: str, mode: str, config: dict, no_list: bool) -> str:
    """What the frontend itself checks, from the mode its code uses."""
    if no_list:
        return (f"{display} has no BIOS list, so it checks nothing itself. Each "
                "emulator looks for its own files when a game starts.")
    if config.get("hash_rule") == "size_and_any_hash":
        return f"{display} also checks each file's size and contents."
    if digest_algorithm(mode):
        return f"{display} also checks each file's contents."
    return f"{display} checks names only. `--check` also checks contents."


def _folder_rows(rows: tuple[tuple[str, str], ...], indent: str = "") -> list[str]:
    return [
        f"{indent}| Where | BIOS folder |",
        f"{indent}|-------|-------------|",
        *(f"{indent}| {label} | {path} |" for label, path in rows),
    ]


# The second most asked question about BIOS files (14 % of the community
# sample): the file is there and the setup still reports it missing.
# `--check` lists every file whose hash is wrong by name (install.py, the
# "wrong hash" lines of check_lines).
MISSING_IN_PLACE = "Reported missing anyway? `--check` names a wrong file."

# Under every command of a setup page: the safety list is the one the home
# page shows in full, so the setup page links it.
SAFE_LINK = "[Is it safe?](../index.md#is-it-safe)"

def first_screen_words() -> list[str]:
    """What a beginner sees when the command runs, the screen's own words
    read from install.py: the one-liner opens the full screen, and the page
    showed a line menu (Enter, i, c, q) nobody saw, whose keys had changed
    since."""
    installer = _installer()
    # The screen it opens first: the setup found, or the list when none
    # is. Install comes on the next one, Choose systems beside it and named
    # above on the page.
    # Nothing found, the folder comes before Install: which-pack left it
    # out.
    return [f"It asks **{installer.TUI_FOUND_TITLE}** (or **{installer.TUI_CHOOSE_TITLE}** "
            f"and **{installer.TUI_FOLDER_TITLE}**), then offers **{installer.TUI_INSTALL_ROW}**."]


# The demo files the site serves (docs_assets/demo/, scripts/make_demo.py):
# the GIF is the README's, the tape and demo.json are inputs.
DEMO_ASSETS = tuple(f"{stem}.{ext}" for stem in ("install", "install-handheld")
                    for ext in ("webm", "mp4", "png"))


def install_demo(variant: str = "default", name: str = "") -> list[str]:
    """An installer demo (default, or handheld): a video that loads once it
    is on screen, its description for screen readers. *name* tells two
    demos of one page apart (the tab each sits in)."""
    facts = demo_facts(variant)
    text = html.escape(demo_description(facts), quote=True)
    own = f' variant="{variant}" name="{name}"' if name else ""
    return [f'<InstallDemo description="{text}" width="{facts["width"]}" '
            f'height="{facts["height"]}"{own} />', ""]


def check_pass_line() -> str:
    """The pass line of "How to check": the words `--check` prints only when
    no file is missing or wrong (install.py EVERYTHING_IN_PLACE), read from
    the installer. Typed here, it kept "All files up to date." after the
    installer said "Everything is in place."."""
    return f"Good result: `{_installer().EVERYTHING_IN_PLACE}`"

# Under "From your computer": a device with no network installs from the ZIP
# (`--from-pack`). The id is the one wiki/installer.md gives its section.
OFFLINE_LINE = ("No internet on the device? "
                "[Install from the ZIP](../wiki/installer.md#without-a-network-offline-install).")


def _network_share(name: str, guide: Guide) -> str:
    """The network folder a computer fills, for a setup that runs on its own
    device and has no ZIP: the command runs on the computer and writes
    there. Empty when the page cites no such folder."""
    if guide.run != ("device",) or _computer_first(name, guide):
        return ""
    for label, path in guide.folders:
        if label.startswith("From Windows") and path.startswith("`\\\\"):
            return path.strip("`").rstrip("\\")
    return ""


def _share_tabs(name: str, share: str) -> tuple[dict[str, str], dict[str, str]]:
    """The command per computer for a network folder (\\\\RECALBOX\\share\\bios),
    and how a Mac or a Linux desktop opens that folder first. Only Windows
    had a line: a Mac user fell back to SSH or to taking the card out.

    macOS mounts smb://recalbox/share at /Volumes/share. A Linux desktop
    mounts it where its file manager chooses, so that tab names the folder.
    """
    host, _, rest = share.lstrip("\\").partition("\\")
    volume, _, below = rest.partition("\\")
    url = f"smb://{host.lower()}/{volume}"
    tail = "/" + below.replace("\\", "/") if below else ""
    args = {
        "windows": f"--platform {name} --dest {share}",
        "macos": f"--platform {name} --dest /Volumes/{volume}{tail}",
        "linux": f"--platform {name} --dest /path/to/{volume}{tail}",
    }
    how = {
        "macos": (f"In Finder, Go > Connect to Server: `{url}`. Then paste the line in "
                  "**Terminal**."),
        "linux": (f"Open `{url}` in the file manager. Paste the line in a terminal, "
                  f"with the folder it opened for `/path/to/{volume}`."),
    }
    return args, how


def _offline_line(name: str) -> list[str]:
    """The offline line, on a setup whose ZIP a release publishes: the
    installer reads that ZIP with no network (`--from-pack`)."""
    pack = release_record.pack_for(name, release_record.load_advertised())
    return [OFFLINE_LINE, ""] if pack and pack.get("assets") else []


# The route of a setup with no ZIP when the device has no network: the
# command writes to any folder named after --dest (wiki/installer.md), so a
# computer fills the device's card. The FAQ answers it with an example.
CARD_ROUTE_FAQ = "wiki/faq.md#fill-an-sd-card-from-a-computer"


def _card_route(name: str, display: str, guide: Guide) -> list[str]:
    """The route with no network on the device, for a setup whose ZIP no
    release publishes: the command run on a computer, into the card. A
    setup with a ZIP has the offline line, a card setup's command already
    runs on the computer. The folder named after --dest is the one the
    command fills on the device (the registry's extract_to): AmberELEC's is
    `/storage/roms/`, which holds `bios/` and `neogeo/`. How a computer
    sees it is the reader's to name: no guide cites it."""
    if guide.on_card or _offline_line(name):
        return []
    extract_to = (load_platform_registry(str(siteinputs.current().platforms)).get(name) or {}).get("extract_to")
    leaf = (extract_to or "bios").rstrip("/").rsplit("/", 1)[-1].lstrip("~") or "bios"
    tabs = guide.card_run or ("windows", "macos", "linux")
    args = {key: f"--platform {name} --dest "
                 + (f"E:\\path\\to\\{leaf}" if key == "windows" else f"/path/to/{leaf}")
            for key in tabs}
    if guide.run != ("device",):
        lead = ("No network here? Run the command on a computer that has one, with a USB "
                f"drive's folder after `--dest`. Then copy it into {_folder_words(display, extract_to)}.")
        return [lead, "", *terminal_tabs(tabs, args, steps=False)]
    # A folder on the card's Linux partition: Windows and macOS show the
    # small boot partition alone, and no folder there fits --dest.
    put = ("Put the device's card in a computer." if "windows" in tabs
           else "Only a Linux computer opens the card.")
    lead = (f"No network? {put} After `--dest`, "
            f"name the folder the device calls `{extract_to}`.")
    return [lead, "", *terminal_tabs(tabs, args, steps=False),
            f"[More on SD cards](../{CARD_ROUTE_FAQ})", ""]


def _get_page_line(name: str, display: str) -> list[str]:
    """The setup's get/ page, under the command of a setup with no ZIP: the
    address a guide writer keeps. A setup with a ZIP links it by its button."""
    if has_release_pack(name):
        return []
    return [f"Link to share: [{get_page_title(name, display)}](../{get_page_link(name)})", ""]


def _setup_routes(name: str, display: str, page_link: bool = False) -> list[str]:
    """The ways to run the command for a setup no ZIP serves first, written
    once for its setup page and its get/ page: the network folder from a
    computer, the card from a computer when the device has no network, and
    the device's own terminal. *page_link* adds the get/ page, on the setup
    page only."""
    guide = GUIDES[name]
    share = _network_share(name, guide)
    card = _card_route(name, display, guide)
    shared = _get_page_line(name, display) if page_link else []
    if share or (card and guide.run == ("device",)):
        computer = ["## From a computer { #from-your-computer }", ""]
        if share:
            args, how = _share_tabs(name, share)
            # The setup page stays in its word budget: its Mac and Linux
            # lines are on the get/ page, the one the command is shared from.
            tabs = ("windows",) if page_link else ("windows", "macos", "linux")
            computer += [
                "Needs the device on the same network.",
                "",
                *terminal_tabs(tabs, args, how=how),
                *([f"[Mac or Linux](../{get_page_link(name)}#from-your-computer)", ""]
                  if page_link else []),
                SAFE_LINK,
                "",
            ]
        return [*computer, *card,
                *_guide_install(name, guide, "## On the device { #install }"), *shared]
    return [*_guide_install(name, guide, "## Install"), *shared, *card]


# Shown in the "On the device" tab of a guide that has no `terminal:` of its own.
DEVICE_TERMINAL_FALLBACK = "Or fill the folder from a computer, with the ZIP."


def _computer_first(name: str, guide: Guide) -> bool:
    """A system that runs only on its own device, with a ZIP to download: a
    beginner fills its folder from a computer more easily than from a
    terminal on the TV. Without a ZIP the command is the only route."""
    pack = release_record.pack_for(name, release_record.load_advertised())
    return guide.run == ("device",) and bool(pack and pack.get("assets"))


def _ships_neogeo(name: str) -> bool:
    """Whether the setup's files hold `neogeo.zip`, the archive a reader most
    often unzips by mistake: arcade BIOS sets are read zipped."""
    manifest = _REPO_ROOT / "install" / f"{name}.json"
    if not manifest.is_file():
        return False
    files = json.loads(manifest.read_text(encoding="utf-8")).get("files", [])
    return any(f.get("dest", "").rsplit("/", 1)[-1] == "neogeo.zip" for f in files)


def _guide_download(name: str, display: str, guide: Guide, extract_to: str | None,
                    heading: str) -> list[str]:
    """The pack: its buttons, its size, and where it is unzipped."""
    lines = [heading, ""]
    record = release_record.load_advertised()
    pack = release_record.pack_for(name, record)
    network = any(label.startswith("From ") for label, _path in guide.folders)
    if pack and pack.get("assets"):
        parts = len(pack["assets"])
        bullets = [
            f"{_fmt_size(pack['download_size'])} to download, "
            f"{_fmt_size(pack['extracted_size'])} once unzipped."
        ]
        if parts > 1:
            bullets.append("Both parts are needed." if parts == 2 else f"All {parts} parts are needed.")
        if _computer_first(name, guide) and network:
            target = "the network folder above"
        else:
            target = f"`{extract_to}`" if extract_to else "the BIOS folder"
        bullets.append(f"Unzip {'them all' if parts > 1 else 'it'} into {target}."
                       + (" Files like `neogeo.zip` stay zipped." if _ships_neogeo(name) else ""))
        if guide.download_hint and not _computer_first(name, guide):
            bullets.append(guide.download_hint)
        lines += [
            _pack_buttons(name, f"Download {display} Pack"),
            "",
            *(f"- {b}" for b in bullets),
            "",
        ]
    elif not has_release_pack(name):
        lines += [_pack_buttons(name, display=display), ""]
    elif record.get("tag"):
        made_from = setup_version(name)
        lines += [
            f"No {display} ZIP yet. The command installs the same files"
            + (f", made for {made_from}." if made_from else "."),
            "",
        ]
    else:
        lines += [_pack_buttons(name, f"Download {display} Pack"), ""]
    return [*lines, *only_some_consoles(name, "../")]


def only_some_consoles(name: str, prefix: str = "") -> list[str]:
    """The way to a smaller download, in the words Get the files uses."""
    return [
        f"Only some consoles? [Pick them]({prefix}which-pack.md?platform={name}"
        f"#only-some-consoles), or the command's **{_installer().TUI_SYSTEMS_ROW}**.",
        "",
    ]


def _guide_install(name: str, guide: Guide, heading: str) -> list[str]:
    """The command, in a tab per place it runs, and whether it is safe."""
    lines = [
        heading,
        "",
        "It finds the folder and checks each file.",
        "",
    ]
    if guide.on_card:
        lines += [
            "Put the SD card in a computer. On Windows, note its letter, like "
            "**E:**. Put the card's path after `--dest`.",
            "",
        ]
    device = guide.terminal or f"{TERMINALS['device'][1]} {DEVICE_TERMINAL_FALLBACK}"
    return [
        *lines,
        *terminal_tabs(guide.run, platform_args(name, guide), how={"device": device}),
        SAFE_LINK,
        "",
    ]


def devices_meta(devices: tuple[str, ...]) -> str:
    """The device names a reader types, as the `devices` search field of the
    page: an attribute on an empty element, commas out (the search engine
    splits its keys on commas), so no excerpt shows them."""
    names = " ".join(name.replace(",", " ") for name in devices)
    return f'<span data-pagefind-meta="devices:{html.escape(names, quote=True)}"></span>'


# Devices named in a row of the handheld guide. The rest stay in the
# page's search field and on the list the row links.
HANDHELD_ROW_DEVICES = 6


# Where a handheld row with no cited folder sends the reader: the setting
# that shows RetroArch's BIOS folder, the words of the RetroArch page.
RETROARCH_FOLDER_SETTING = ("In RetroArch, open **Settings > Directory > System/BIOS**. "
                            "It shows the folder.")
# After a folder on a part of the card only Linux reads.
LINUX_ONLY_HINT = ("Copy from a Linux computer, or check the folder in RetroArch's "
                   "**Settings > Directory > System/BIOS**.")


def _handheld_row(system: HandheldSystem) -> str:
    shown = ", ".join(system.devices[:HANDHELD_ROW_DEVICES])
    more = len(system.devices) - HANDHELD_ROW_DEVICES
    devices = (f"{shown}{f' and {more} more' if more > 0 else ''} "
               f"([list]({system.devices_source}))" if system.devices else "")
    if not system.folder:
        folder = RETROARCH_FOLDER_SETTING
    else:
        folder = f"{system.folder} ([source]({system.folder_source}))"
        if system.linux_only:
            folder += f". {LINUX_ONLY_HINT}"
    return f"| {system.name} | {devices} | {folder} |"


def generate_handheld_guide(guide: HandheldGuide) -> str:
    """The guide for the handheld systems that run a setup (ArkOS, muOS,
    Onion... run RetroArch): one row per system the installer detects, the
    folder seen on the card from a computer and the devices, each cited from
    the system's own pages, then that setup's ZIP and the command for a card.

    A handheld owner starts from the device name. The systems were named
    only in a closed note, with a path seen from inside the device."""
    uses = GUIDES[guide.uses]
    display = load_platform_config(guide.uses, str(siteinputs.current().platforms)).get("platform", guide.uses)
    args = {"windows": f"--platform {guide.uses} --dest E:\\BIOS",
            "macos": f"--platform {guide.uses} --dest /path/to/card/BIOS",
            "linux": f"--platform {guide.uses} --dest /path/to/card/BIOS"}
    return "\n".join([
        f"# {guide.title}",
        "",
        guide.summary,
        "",
        devices_meta(guide.devices),
        "",
        "[Download](#download)",
        "",
        "## Where the files go { #where-the-files-go }",
        "",
        "Put the SD card in a computer. Find the system below.",
        "",
        "| System | Devices | BIOS folder on the card |",
        "|--------|---------|-------------------------|",
        *(_handheld_row(system) for system in guide.systems),
        "",
        *_guide_download(guide.uses, display, uses, None, "## Download { #download }"),
        *_offline_line(guide.uses),
        "## Fill the card from a computer { #install }",
        "",
        "On Windows, note the card's letter, like **E:**. Put its BIOS folder after "
        "`--dest`, written as in the table.",
        "",
        *terminal_tabs(("windows", "macos", "linux"), args),
        SAFE_LINK,
        "",
        *_next_block([
            f"[{display}]({guide.uses}.md): every folder and every file",
            "[When a game does not start](../wiki/troubleshooting.md)",
        ]),
    ]) + "\n"


def _platform_guide(name: str, display: str, cov: dict, registry: dict, no_list: bool) -> list[str]:
    """The guide part of a platform page: folder, command, pack, check, next.

    A system that runs only on its own device puts the computer route
    (download, unzip into the network folder) before the command."""
    guide = GUIDES[name]
    entry = registry.get(name, {})
    extract_to = entry.get("extract_to")
    # An app's page opens on the command: one line to paste is the shortest
    # way to a working setup, and the folder table is what a manual copy needs.
    lines = ["## Where the files go", ""]
    if guide.lead:
        lines += [guide.lead, ""]
    lines += _folder_rows(guide.folders)
    if extract_to and has_release_pack(name):
        lines.append(f"| Unzip the pack into | `{extract_to}` |")
    lines.append("")
    for note in guide.notes:
        lines += [note, ""]
    lines += [line for note in extract_notes(str(siteinputs.current().platforms), released_only=True)
              if f"The {display} pack " in note
              for line in (note, "")]
    if guide.more_folders:
        detected = _detected_systems(registry, name) if guide.more_folders_detected else []
        lines += markup.details("note", guide.more_folders_title, [
            *_folder_rows(guide.more_folders),
            *(f"| {system} | `{folder}` |" for system, folder in detected),
            "",
            *([guide.more_folders_note, ""] if guide.more_folders_note else []),
        ])
    if guide.on_card:
        lines += ["<!-- image: minui-card -->", ""]
    if _computer_first(name, guide):
        # The ZIP copied over the network needs the folder table above it.
        lines += [
            *_guide_download(name, display, guide, extract_to,
                             "## From a computer { #download }"),
            *_offline_line(name),
            *_guide_install(name, guide, "## On the device { #install }"),
        ]
    else:
        where = lines
        lines = [
            *_setup_routes(name, display, page_link=True),
            *_guide_download(name, display, guide, extract_to, "## Download"),
            *_offline_line(name),
            *where,
        ]
    check_args = {key: f"{args} --check" for key, args in platform_args(name, guide).items()}
    lines += [
        "## How to check",
        "",
        "Add `--check` to the command. It changes nothing.",
        "",
        *terminal_tabs(guide.run, check_args, steps=False),
        check_pass_line(),
        "",
        _check_sentence(display, cov["mode"], cov["config"], no_list),
        "",
        MISSING_IN_PLACE,
        "",
        *([guide.finish, ""] if guide.finish else []),
        *_next_block([
            "[First install, step by step](../wiki/first-install.md)",
            "[When a game does not start](../wiki/troubleshooting.md)",
        ]),
    ]
    return lines


# A hash a platform's list writes, in words.
_HASH_WORDS = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "crc32": "CRC32"}


def generate_platform_page(
    name: str,
    cov: dict,
    registry: dict | None = None,
    emulator_files: dict | None = None,
    moved: dict[str, str] | None = None,
) -> str:
    """A guide first (folder, command, pack, check), then every file the
    platform's list and its emulators need, under a reference heading.

    ``moved`` collects the pages of systems whose list is too long for it.
    """
    from sitesources import list_source

    registry = registry or {}
    config = cov["config"]
    display = cov["platform"]
    mode = cov["mode"]
    pct = _pct(cov["present"], cov["total"])

    # The mark is drawn beside the title from the front matter: floated
    # beside the first line at 48 px it read as a broken image.
    logo_url = registry.get(name, {}).get("logo", "")
    logo_url = local_images().get(logo_url, logo_url)

    homepage = config.get("homepage", "")
    version = config.get("version", "")
    hash_type = config.get("hash_type", "")
    base_dest = config.get("base_destination", "")

    mode_badge = (
        "rb-badge-success" if reads_file_contents(mode) else "rb-badge-info"
    )

    lines = [
        *(["---", f"logo: {json.dumps(logo_url)}", "---", ""] if logo_url else []),
        f"# {display}",
        "",
    ]

    summary = GUIDES[name].summary if name in GUIDES else ""
    if summary:
        lines += [summary + (f" [{display} website]({homepage})." if homepage else ""), ""]

    no_list = not cov["total"] and registry.get(name, {}).get("native_list") == "none"
    if name in GUIDES:
        lines += _platform_guide(name, display, cov, registry, no_list)
    lines += [
        "## Reference: every file by system { #reference-every-file-by-system }",
        "",
        level_label("reference"),
        "",
        "For checking the work: counts, the list's source and each file's hashes.",
        "",
        *(line for note in (GUIDES[name].reference_notes if name in GUIDES else ())
          for line in (note, "")),
    ]
    if no_list:
        # MinUI and its forks hand each core a folder and name no file: a
        # 0/0 coverage band read as "this device is not supported".
        lines.extend(markup.aside("info", "No BIOS list of its own", [
            f"{display} names no BIOS file itself: it gives each emulator core "
            "its own folder and the core looks for its files there. The pack "
            "places every file the cores it runs need into those folders. The "
            "core files are listed further down this page.",
        ]))
    band = [] if no_list else [
            markup.block_open("div", 'class="rb-stats"'),
            "",
            *_stat(f"{cov['present']}/{cov['total']}", f"Coverage ({pct})"),
            *_stat(str(cov["verified"]), "Verified"),
            *_stat(str(cov["missing"]), "Missing"),
            *_stat(f'<span class="rb-badge {mode_badge}">{check_label(mode, config.get("hash_rule"))}</span>',
                   "Checked by"),
            "</div>",
            "",
        ]
    lines.extend([*band, markup.block_open("div", 'class="rb-meta-card"'), "",
                  "| Detail | Value |", "|---|---|"])
    # The hash the list writes, when it is not the one the platform checks:
    # RetroArch checks presence and its System.dat writes sha1.
    if hash_type and hash_type != mode:
        lines.append(f"| Hashes in the list | {_HASH_WORDS.get(hash_type, hash_type)} |")
    if version:
        lines.append(f"| Version | {version} |")
    # base_destination is only the root the platform's own list writes its
    # paths from: the pack strips it, so it is no folder to extract into.
    if base_dest:
        lines.append(f"| Paths in the platform's list start at | `{base_dest}/` |")
    if homepage:
        lines.append(f"| Homepage | [{homepage}]({homepage}) |")
    transcribed = str(config.get("source") or "")
    if transcribed:
        # The file every declaration on this page was read from: without it
        # a hash could not be traced to the revision that states it.
        listed = list_source(transcribed)
        moving = (listed.moving if listed else bool(
            re.search(r"/(?:master|main|db)(?:/|$)|refs/heads/", transcribed)))
        note = " (a branch: the revision read is not recorded)" if moving else ""
        # Named in words: the raw URL broke into 25 lines of 8 characters
        # on a phone.
        link = (f"[{_escape_tags(listed.label)}]({listed.browse()})" if listed
                else f"<{transcribed}>")
        lines.append(f"| Transcribed from | {link}{note} |")
    if name in _EXPORTED:
        lines.append(f"| Updated file | [Download it and see the changes](../exports.md#{name}) |")
    lines.append(f"| Data | {_platform_data_links(name)} |")
    contrib_list = registry.get(name, {}).get("contributed_by", [])
    if contrib_list:
        for cb in contrib_list:
            username = cb.get("username", "")
            contribution = cb.get("contribution", "")
            pr = cb.get("pr")
            pr_link = f" ([#{pr}]({REPO_URL}/pull/{pr}))" if pr else ""
            lines.append(
                f"| Contributed by | [@{username}](https://github.com/{username}):"
                f" {contribution}{pr_link} |"
            )
    lines.extend(["", "</div>"])
    if name not in GUIDES:
        detect = (registry.get(name, {}).get("install") or {}).get("detect") or []
        on_card = any(rule.get("method") == "card_marker" for rule in detect)
        lines.extend(["", *_platform_install_block(name, display, on_card)])
        lines.extend(["", _pack_buttons(name, f"Download {display} Pack", display=display)])
    lines.append("")

    # The declaration behind each detail, by system and name in declaration
    # order: keyed by name alone, the last of MiSTer's 23 boot.rom gave its
    # MD5 to every system's row.
    config_files: dict[tuple[str, str], list[dict]] = {}
    for sys_id, system in config.get("systems", {}).items():
        for fe in system.get("files", []):
            fname = fe.get("name", "")
            if fname:
                config_files.setdefault((sys_id, fname), []).append(fe)

    by_system: dict[str, list] = {}
    for d in cov["details"]:
        sys_id = d.get("system", "unknown")
        by_system.setdefault(sys_id, []).append(d)

    if no_list:
        lines.extend(_core_folders_section(name, config))
    if _own_list_only(config):
        lines.extend([f"**Cores:** {OWN_LIST_ONLY}", ""])

    # System summary table (quick navigation)
    lines.extend(
        [] if no_list and not by_system else [
            "### Systems overview",
            "",
            "| System | Files | Status | Emulators |",
            "|--------|-------|--------|-----------|",
        ]
    )
    by_system_declared = _declared_by_system(config_files)
    for sys_id, files in sorted(by_system.items()):
        ok_count = sum(1 for f in files if f["status"] == "ok")
        total = len(files)
        non_ok = total - ok_count
        if non_ok == 0:
            status = '<span class="rb-badge rb-badge-success">OK</span>'
        else:
            status = (
                f'<span class="rb-badge rb-badge-warning">'
                f'{non_ok} issue{"s" if non_ok > 1 else ""}</span>'
            )
        sys_emus = _system_emulators(sys_id, emulator_files, by_system_declared.get(sys_id))
        anchor = sys_id.replace(" ", "-")
        # Named and linked as the detail blocks below do: the column held
        # profile ids, none of 1,463 linked.
        emu_str = ", ".join(_emulator_named_link(e, "../") for e in sorted(sys_emus)[:3])
        if len(sys_emus) > 3:
            emu_str += f" [+{len(sys_emus) - 3}](#{anchor})"
        # The name a reader filters on, the id the list writes beside it.
        # The id and the count are no words a reader searches for: indexed,
        # every platform page answered a system id before its system's page.
        lines.append(
            f"| [{_escape_tags(system_name(sys_id))}](#{anchor}) "
            f"<small data-pagefind-ignore>{sys_id}</small> "
            f"| <span data-pagefind-ignore>{ok_count}/{total}</span> | {status} | {emu_str} |"
        )
    lines.append("")
    if by_system:
        lines.extend(markup.details("note", ROLE_LEGEND_TITLE, [ROLE_LEGEND]))

    lines.extend(
        _render_platform_systems(by_system, config_files, emulator_files,
                                 (name, display), moved, config)
    )

    lines.extend(["", _date_line()])
    return "\n".join(lines) + "\n"


# System pages


def generate_files_page() -> str:
    """Find a file by any of its hashes: files/?hash=<value>.

    site.js reads the one shard of api/v1/lookup/ the value names and lists
    every page that cites it. files/?sha1=<sha1> is the card's permanent
    address and opens the card directly.
    """
    return "\n".join([
        "---",
        "terms: check my dump, md5 check, verify bios file, check hash, "
        "is my bios correct, is my bios right",
        "---",
        "",
        "# Find or check a file",
        "",
        "Check a BIOS dump: paste its hash or choose the file.",
        "",
        "A hash is a fingerprint of a file's contents ([Glossary](../wiki/glossary.md)). "
        "Tools such as clrmamepro and RomVault print one, and so do emulator logs "
        "and the BIOS lists of setups.",
        "",
        "Paste it below, alone or in the line md5sum or certutil prints. The page "
        "shows the file in the collection that has it, the setups that list it and "
        "the emulators that check for it.",
        "",
        '<form class="rb-file-lookup" action="./" method="get">',
        '<label for="rb-hash">SHA1, MD5, CRC32 or SHA256</label> ',
        # No pattern: the line md5sum or certutil prints is taken whole, and
        # the page reads the hash out of it.
        '<input id="rb-hash" name="hash" size="66" autocomplete="off" spellcheck="false" '
        'required> ',
        '<button type="submit">Find</button>',
        "</form>",
        "",
        '<p id="rb-file-lookup-status" role="status"></p>',
        "",
        "To try it, paste `0555c6fae8906f3f09baf5988f00e55f88e9f30b`, the SHA1 of "
        "`scph5501.bin`, the PlayStation BIOS v3.0. "
        "To look a file up by its name, use the search at the top of the page.",
        "",
        "## Permanent links",
        "",
        "A file's card lives on its manufacturer's page, and a file refiled "
        "between manufacturers moves with it. `files/?sha1=<sha1>` is the address "
        "that does not move: it opens the card wherever it is now. The link icon "
        "beside each card's name is that address. A file that left the "
        "collection keeps it: the page says when, and opens the card of the "
        "file in its place.",
        "",
        "## The index behind it",
        "",
        "The lookup reads one file of [`api/v1/lookup/`](../data.md), named by the "
        "first two characters of the hash: one of 256, never the whole index. "
        "[`api/v1/file-locations.json`](../api/v1/file-locations.json) lists every "
        "card by SHA1 in one file.",
        "",
    ])


_REPO_ROOT = Path(__file__).resolve().parent.parent


def data_directory_members(install_dir: Path = _REPO_ROOT / "install") -> dict[str, dict[str, dict]]:
    """Each data directory's files with their sha1 and size, as the install
    manifests record them for the installer to check."""
    members: dict[str, dict[str, dict]] = {}
    for path in sorted(install_dir.glob("*.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        for tree in manifest.get("data_directories") or []:
            members.setdefault(str(tree.get("ref", "")), {}).update(tree.get("files") or {})
    return members


def data_directory_revisions(data_dir: Path = _REPO_ROOT / "data") -> dict[str, dict]:
    """The revision each data directory was fetched at, as refresh_data_dirs records it."""
    path = data_dir / ".versions.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


_GIT_COMMIT = re.compile(r"[0-9a-f]{40}")
_GITHUB_REPO = re.compile(r"https://github\.com/([^/]+/[^/]+)/")


def data_directory_origin(entry: dict, fetched: dict) -> list[str]:
    """Where a data directory is fetched from, and the commit the packs hold.

    The URL is written with the `{version}` refresh_data_dirs substitutes:
    printed raw it led to a 404. A zip source records the server's ETag,
    which names no revision anyone can fetch, so only a git commit is shown.
    """
    lines = []
    url = str(entry.get("source_url") or "")
    if url:
        url = url.replace("{version}", str(entry.get("version", "master")))
        lines.append(f"Fetched from <{url}>")
    sha = str(fetched.get("sha", "")).strip('"')
    if _GIT_COMMIT.fullmatch(sha):
        repo = _GITHUB_REPO.match(url)
        commit = f"[{_code(sha[:12])}](https://github.com/{repo.group(1)}/commit/{sha})" \
            if repo else _code(sha)
        branch = str(fetched.get("version", ""))
        lines.append(f"Revision: {commit}" + (
            f", the head of `{branch}` when fetched" if branch and branch != sha else ""))
    return lines


def page_data_directories(name: str, profiles: dict) -> list[dict]:
    """The data directories an emulator page lists.

    Its own, then those of the aliases that point at it: an alias has no
    page, and the 90 FreeIntv overlays its profile declares were linked to
    emulators/freeintv_ts_overlay/, a page that does not exist.
    """
    trees = [t for t in profiles[name].get("data_directories") or [] if isinstance(t, dict)]
    refs = {str(t.get("ref", "")) for t in trees}
    for alias in sorted(profiles):
        profile = profiles[alias]
        if profile.get("type") != "alias" or profile.get("alias_of") != name:
            continue
        for tree in profile.get("data_directories") or []:
            ref = str(tree.get("ref", ""))
            if isinstance(tree, dict) and ref not in refs:
                refs.add(ref)
                trees.append(tree)
    return trees


def _data_member_owners(profiles: dict) -> dict[str, str]:
    """The emulator page that lists each data directory, the first by name.

    Only a profile that has a page can own one.
    """
    owners: dict[str, str] = {}
    for name in sorted(profiles):
        if profiles[name].get("type") == "alias" or profiles[name].get("role") == "test":
            continue
        for tree in page_data_directories(name, profiles):
            owners.setdefault(str(tree.get("ref", "")), name)
    return owners


def file_location_items(
    db: dict, profiles: dict | None = None, members: dict | None = None
) -> list[dict]:
    """Each held file's card, keyed by its sha1.

    A card lives on its manufacturer's page, and a file refiled between
    manufacturers (mt32_control.rom, Commodore to Roland) moved its link
    with it. files/?sha1= reads this list and goes to the card wherever it
    is now: the address cited depends on the content only. The url is
    site-absolute (/retrobios/systems/...): written from the site root, it
    resolved against the document holding it to a page that does not exist.
    """
    items = []
    for sha1, entry in sorted(db.get("files", {}).items()):
        parts = entry.get("path", "").split("/")
        if len(parts) < 3 or parts[0] != "bios":
            continue
        page = card_page(entry.get("path", ""), sha1)
        items.append({"sha1": sha1, "url": _site_path(f"systems/{page}.md#sha1-{sha1[:12]}")})
    # A data directory's files are listed on the page of an emulator reading
    # the tree: 2,534 hashes the packs ship were found nowhere on the site.
    owners = _data_member_owners(profiles or {})
    known = {item["sha1"] for item in items}
    for ref, files in sorted((members or {}).items()):
        if ref not in owners:
            continue
        # A large tree is listed on pages of its own (data_tree_pages).
        page_of = {member: stem for stem, names in data_tree_pages(ref, files)
                   for member in names}
        for member, info in sorted(files.items()):
            sha1 = str(info.get("sha1", ""))
            if sha1 and sha1 not in known:
                known.add(sha1)
                page = page_of.get(member, owners[ref])
                items.append({"sha1": sha1,
                              "url": _site_path(f"emulators/{page}.md#sha1-{sha1[:12]}")})
    return sorted(items, key=lambda item: item["sha1"])


LOOKUP_PREFIX = 2  # hex characters naming a lookup shard: 256 files


def _lookup_system_name(sys_id: str) -> str | None:
    """The system's name as every page prints it, None for an id the site
    cannot name. The Find a file page reads it, and never builds one."""
    try:
        return system_name(sys_id)
    except KeyError:
        return None


def _console_system_names(profiles: dict, coverages: dict) -> dict[tuple[str, str], str]:
    """(manufacturer slug, console folder) -> the name of the system whose
    own section that folder is: a collection file is named after the console
    it is filed under. A folder no id owns, or that two names own, is left out.
    """
    from siterender import _own_section, system_ids

    found: dict[tuple[str, str], set[str]] = {}
    for sys_id in system_ids(profiles, [c["config"] for c in coverages.values()]):
        own = _own_section(sys_id)
        if own is not None:
            found.setdefault((_slug(own[0]), own[1]), set()).add(system_name(sys_id))
    return {key: next(iter(names)) for key, names in found.items() if len(names) == 1}


def _data_member_digests(
    members: dict, data_registry: dict | None = None, root: Path = _REPO_ROOT,
) -> dict[str, dict[str, str]]:
    """sha1 -> every hash the lookup takes, for each data directory member
    whose copy in the tree's local cache has the sha1 the manifest records.
    The manifests carry sha1 alone: the MD5 of Dolphin's ApprovedInis.json
    found nothing although the pack ships it."""
    from common import load_data_dir_registry  # noqa: PLC0415
    from hashing import compute_hashes  # noqa: PLC0415

    if data_registry is None:
        data_registry = load_data_dir_registry(str(siteinputs.current().platforms))
    found: dict[str, dict[str, str]] = {}
    for ref, tree in sorted(members.items()):
        cache = (data_registry.get(ref) or {}).get("local_cache")
        if not cache:
            continue
        for member, info in sorted(tree.items()):
            sha1 = str(info.get("sha1", ""))
            path = root / cache / member
            if not sha1 or sha1 in found or not path.is_file():
                continue
            digests = compute_hashes(path, frozenset(HASH_ALGORITHMS))
            if digests.get("sha1") == sha1:
                found[sha1] = {algo: digests[algo].lower() for algo in HASH_ALGORITHMS}
    return found


def retired_records(retired: dict[str, dict], files: dict, locations: list[dict]) -> list[dict]:
    """A record for each hash of a file that left the collection.

    Its address (files/?sha1=, #sha1-<12>) was published and answered that
    no file the site knows has the hash, inviting a contribution of a file
    the collection held. The record says when it left, and leads to the
    card of the file holding its place, followed to the one held today.
    """
    cards = {item["sha1"]: item["url"] for item in locations}
    records = []
    for sha1, record in sorted(retired.items()):
        if sha1 in files:
            continue
        successor, seen = record.get("successor"), {sha1}
        while successor and successor not in files and successor not in seen:
            seen.add(successor)
            successor = (retired.get(successor) or {}).get("successor")
        url = cards.get(successor) if successor in files else None
        extra = {"left": str(record["left"])}
        if url:
            extra["successor"] = successor
        else:
            # The page its card was on: the reader lands among its neighbours.
            url = _site_path(f"systems/{card_page(str(record.get('path', '')), sha1)}.md")
        for algorithm in HASH_ALGORITHMS:
            value = sha1 if algorithm == "sha1" else record.get(algorithm)
            for one in _hash_values(value):
                records.append({"value": one, "algorithm": algorithm, "layer": "retired",
                                "name": str(record.get("name", "")), "sha1": sha1,
                                "url": url, **extra})
    return records


def _archive_member_records(entry: dict, sha1: str, url: str,
                            root: Path = _REPO_ROOT) -> list[dict]:
    """The CRC32 of each member of a collection archive, read from its
    central directory.

    A pasted CRC of a ROM the collection holds only inside a set (logica2.u2
    in a500.zip, 8484f426) found nothing: 26,014 of 33,403 members were in
    no record. The record leads to the archive's card and names it.
    """
    path = root / str(entry.get("path", ""))
    if path.suffix.lower() != ".zip" or not path.is_file():
        return []
    try:
        with zipfile.ZipFile(path) as archive:
            members = [(info.filename, info.CRC) for info in archive.infolist()
                       if not info.is_dir()]
    except (OSError, zipfile.BadZipFile) as exc:
        print(f"  WARNING: {path}: members unreadable ({exc})", file=sys.stderr)
        return []
    return [{"value": f"{crc:08x}", "algorithm": "crc32", "layer": "archive-member",
             "name": member.rsplit("/", 1)[-1], "archive": str(entry.get("name", "")),
             "sha1": sha1, "url": url}
            for member, crc in members]


def file_lookup_records(
    db: dict,
    coverages: dict,
    profiles: dict,
    locations: list[dict],
    members: dict | None = None,
    consumers: FileConsumers | None = None,
    retired: dict | None = None,
    wanted: list[dict] | None = None,
) -> list[dict]:
    """Every hash the site knows, one record per value, for files/?hash=.

    The collection's own files lead to their card, a platform's declared
    value to the system section of its page, a profile's to the entry's
    card, a wanted dump (``wanted``, the provenance-wanted.csv rows) to
    its catalog on the provenance page. The site search indexed these values as text, 4 MB of the 21 MB
    it made every visitor download: the lookup reads one shard instead.
    """
    files = db.get("files", {})
    named = _console_system_names(profiles, coverages)
    member_names = {
        str(info.get("sha1", "")): member.rsplit("/", 1)[-1]
        for tree in (members or {}).values() for member, info in sorted(tree.items())
    }
    member_digests = _data_member_digests(members or {})
    records: list[dict] = []
    for item in locations:
        sha1 = item["sha1"]
        entry = files.get(sha1)
        if entry is None:
            # A data directory member: the manifests record its sha1, the
            # tree on disk the other three.
            digests = member_digests.get(sha1) or {"sha1": sha1}
            records.extend({"value": digests[algorithm], "algorithm": algorithm,
                            "layer": "data-directory", "name": member_names.get(sha1, ""),
                            "sha1": sha1, "url": item["url"]}
                           for algorithm in HASH_ALGORITHMS if algorithm in digests)
            continue
        parts = str(entry.get("path", "")).split("/")
        held_by = named.get((_slug(parts[1]), parts[2])) if len(parts) > 3 else None
        for algorithm in HASH_ALGORITHMS:
            for value in _hash_values(entry.get(algorithm)):
                records.append({
                    "value": value, "algorithm": algorithm, "layer": "collection",
                    "name": str(entry.get("name", "")), "sha1": sha1, "url": item["url"],
                    **({"system_name": held_by} if held_by else {}),
                })
        records += _archive_member_records(entry, sha1, item["url"])
    for key, coverage in sorted(coverages.items()):
        for system_id, system in sorted((coverage["config"].get("systems") or {}).items()):
            url = _site_path(f"platforms/{key}.md#{system_id.replace(' ', '-')}")
            system_label = _lookup_system_name(system_id)
            for entry in system.get("files") or []:
                # A hash of a ROM inside the archive (zipped_file) designates
                # no collection file by itself: the archive holding it is the one.
                archive = (consumers.sha1_of(entry)
                           if consumers is not None and entry.get("zipped_file") else None)
                for algorithm in HASH_ALGORITHMS:
                    for value in _hash_values(entry.get(algorithm)):
                        records.append({
                            "value": value, "algorithm": algorithm, "layer": "platform",
                            "owner": key, "name": str(entry.get("name", "")), "url": url,
                            **({"system_name": system_label} if system_label else {}),
                            **({"sha1": archive} if archive else {}),
                        })
    for key, profile in sorted(profiles.items()):
        if profile.get("type") == "alias" or profile.get("role") == "test":
            continue
        entries = profile.get("files") or []
        own_systems = [str(s) for s in profile.get("systems") or []]
        for entry, anchor in zip(entries, emulator_file_anchors(entries)):
            url = _site_path(f"emulators/{emulator_card_page(key, anchor)}.md#{anchor}")
            sys_id = str(entry.get("system") or "") or (
                own_systems[0] if len(own_systems) == 1 else "")
            entry_label = _lookup_system_name(sys_id) if sys_id else None
            members = [(str(entry.get("name", "")), entry)] + [
                (str(member["name"]), member) for member in entry.get("contents") or []
                if isinstance(member, dict) and member.get("name")
            ]
            for name, holder in members:
                for algorithm in HASH_ALGORITHMS:
                    for value in _hash_values(holder.get(algorithm)):
                        records.append({
                            "value": value, "algorithm": algorithm, "layer": "emulator",
                            "owner": key, "name": name, "url": url,
                            **({"system_name": entry_label} if entry_label else {}),
                        })
    records += retired_records(retired or {}, files, locations)
    records += wanted_records(wanted or [])
    records += _held_under_every_hash(records, files, db.get("indexes") or {})
    for record in records:
        if record["layer"] in ("platform", "emulator"):
            record.setdefault("declared", record["algorithm"])
    if consumers is not None:
        records += _read_by_name(records, files, consumers)
    unique = {json.dumps(r, sort_keys=True): r for r in records}
    return sorted(unique.values(), key=lambda r: (
        r["value"], r["layer"], r.get("owner", ""), r["name"], r["url"]))


def wanted_records(rows: list[dict]) -> list[dict]:
    """A record under each hash of a dump a catalog lists and the collection
    lacks, from the rows of provenance-wanted.csv. A pasted hash of a
    wanted dump (Redump's ps2-dvd-212k.bin) answered that nothing the site
    knows has it, and never said the dump is wanted."""
    records = []
    for row in rows:
        label = _PROVENANCE_LABELS.get(row["catalog"], row["catalog"])
        url = _site_path(f"provenance.md#{_slugify_anchor(label)}")
        for algorithm in ("sha1", "md5", "crc32"):
            value = str(row.get(algorithm) or "").lower()
            if value:
                records.append({"value": value, "algorithm": algorithm, "layer": "wanted",
                                "owner": label, "name": row["name"], "url": url})
    return records


def _read_by_name(records: list[dict], files: dict, consumers: FileConsumers) -> list[dict]:
    """The emulators the file's card names that no declared hash reached.

    The card counts every profile entry resolving to the file, by name
    included: scph5501.bin named 11 emulators on its card and 9 in the
    lookup, PCSX-ReARMed and PCSX1 reading it by name. Each is written under
    every hash of the file, `declared` saying no hash was.
    """
    reached = {(r["sha1"], r["owner"]) for r in records
               if r["layer"] == "emulator" and r.get("sha1")}
    added: list[dict] = []
    for sha1, emulators in sorted(consumers.emulators.items()):
        entry = files.get(sha1)
        if entry is None:
            continue
        for emulator in sorted(emulators):
            if (sha1, emulator) in reached:
                continue
            index = consumers.emulator_entries.get(sha1, {}).get(emulator)
            entries = consumers.emulator_files.get(emulator) or []
            if index is None or index >= len(entries):
                continue
            anchor = _emulator_card_anchor(emulator, entries, index)
            url = _site_path(f"emulators/{emulator_card_page(emulator, anchor)}.md#{anchor}")
            name = str(entries[index].get("name", ""))
            for algorithm in HASH_ALGORITHMS:
                for value in _hash_values(entry.get(algorithm)):
                    added.append({
                        "value": value, "algorithm": algorithm, "layer": "emulator",
                        "owner": emulator, "name": name, "url": url, "sha1": sha1,
                        "declared": "name",
                    })
    return added


def _collection_sha1(files: dict, indexes: dict, algorithm: str, value: str) -> str | None:
    """The collection file a declared value designates, None when none does."""
    if algorithm == "sha1":
        return value if value in files else None
    found = indexes.get(f"by_{algorithm}", {}).get(value)
    if isinstance(found, list):
        found = found[0] if len(found) == 1 else None
    return found if found in files else None


def _held_under_every_hash(records: list[dict], files: dict, indexes: dict) -> list[dict]:
    """A platform or emulator record whose value designates a collection
    file, written under the file's other hashes too.

    Batocera lists scph5501.bin by md5: pasted by its sha1, the file showed
    no setup at all. Each record now carries the file's sha1, and
    ``declared`` names the hash its owner wrote when the record is a copy.
    """
    copies: list[dict] = []
    for record in records:
        if record["layer"] not in ("platform", "emulator"):
            continue
        sha1 = record.get("sha1") or _collection_sha1(
            files, indexes, record["algorithm"], record["value"])
        if sha1 not in files:
            continue
        record["sha1"] = sha1
        for algorithm in HASH_ALGORITHMS:
            for value in _hash_values(files[sha1].get(algorithm)):
                if value != record["value"]:
                    copies.append({**record, "value": value, "algorithm": algorithm,
                                   "declared": record["algorithm"]})
    return copies


def write_lookup_shards(
    api: Path, records: list[dict], generated_at: str, commit: str = "",
) -> int:
    """One envelope per leading pair of hex characters, as the lookup asks.

    A value that is not hexadecimal (a typo in a profile) has no shard the
    lookup would read, and is left out. Returns the number of shards.
    """
    shards: dict[str, list[dict]] = {}
    for record in records:
        if re.fullmatch(r"[0-9a-f]{8,}", record["value"]):
            shards.setdefault(record["value"][:LOOKUP_PREFIX], []).append(record)
    folder = api / "lookup"
    folder.mkdir(parents=True, exist_ok=True)
    for prefix, items in sorted(shards.items()):
        write_if_changed(str(folder / f"{prefix}.json"), json.dumps({
            "schema_version": 1,
            "generated_at": generated_at,
            **({"commit": commit} if commit else {}),
            "kind": "file-lookup",
            "count": len(items),
            "items": items,
        }, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n")
    return len(shards)


def _console_display(manufacturer: str, console: str) -> str:
    """A console section's name as the reader looks for it: the heading
    system_name gives its id, or the folder alone under a program's top
    (Other, Arcade), where "Other mame" would name nothing."""
    from siterender import _PROGRAM_TOPS, _heading_name  # noqa: PLC0415

    return console if manufacturer in _PROGRAM_TOPS else _heading_name(manufacturer, console)


def generate_systems_index(manufacturers: dict) -> str:
    """Every console in one table, found by its own name.

    The index listed 74 manufacturers and no console: someone looking for
    PlayStation had to know it is filed under Sony, and Other hid 91
    sections. Manufacturer pages stay the containers.
    """
    for old, new in SYSTEM_PAGES_MOVED.items():
        sitestarlight.MOVED_PAGES.setdefault(old, new)
    total_mfr = len(manufacturers)
    total_consoles = sum(len(c) for c in manufacturers.values())
    # A copy filed under two folders appears on both pages, counted once here.
    total_files = len({
        f.get("sha1") for consoles in manufacturers.values()
        for files in consoles.values() for f in files
    })

    lines = [
        "# Systems",
        "",
        "Every BIOS file the collection holds, by console. Open a console to "
        "see each file, the emulators that read it and the setups that list it.",
        "",
        f"{_count(total_consoles, 'console')}, {_count(total_files, 'file')} in the "
        f"repository, from {_count(total_mfr, 'manufacturer')}.",
        "",
    ]

    # Other holds one folder per emulator: a7800 or altirra in the console
    # table named no console. Arcade boards are neither consoles nor
    # computers, and the crumb of their page says Arcade too.
    def kind(mfr: str) -> str:
        if mfr in GAME_DATA_TOPS:
            return "games"
        if mfr == "Arcade":
            return "arcade"
        return "programs" if mfr == "Other" else "consoles"

    for heading, group, first, note in (
        ("Consoles and computers", "consoles", "Console", ""),
        ("Arcade", "arcade", "Name",
         "Arcade boards, and the sets each arcade emulator family reads."),
        ("Emulator folders", "programs", "Folder",
         "Files kept under the emulator that reads them, not under a console."),
        ("Game engines and PC games", "games", "Name",
         "Game engines and PC games hold the files a game engine reads, such "
         "as the data of a game, rather than the BIOS of a machine."),
    ):
        rows = sorted(
            ((_folder_emulator(console)[0] if group == "programs"
              else _section_label(mfr, console) if mfr == "Arcade"
              or (mfr, console) in SECTION_LABELS
              else _console_display(mfr, console), mfr, console, len(files))
             for mfr, consoles in manufacturers.items() if kind(mfr) == group
             for console, files in consoles.items()),
            key=lambda row: (row[0].casefold(), row[1].casefold(), row[2]),
        )
        if not rows:
            continue
        lines += [f"## {heading}", ""]
        if note:
            lines += [note, ""]
        if group == "programs":
            # Each folder by the emulator's name, linked to its page: the
            # rows read a7800 and azaharplus beside console names, and
            # every maker cell said Other.
            lines += ["| Emulator | Files |", "|---------|------:|"]
            for name, mfr, console, count in rows:
                href = console_href(_slug(mfr), console).removeprefix("systems/")
                key = _folder_emulator(console)[1]
                cell = name.replace("|", "-")
                cell = f"[{cell}](../emulators/{key}.md)" if key else cell
                lines.append(f"| {cell} | [{_count(count, 'file')}]({href}) |")
            lines.append("")
            continue
        lines += [
            # The count before the maker: on a phone the last column is
            # the one scrolled off, and most names carry the maker already.
            f"| {first} | Files | Maker |",
            "|---------|------:|-------|",
        ]
        for name, mfr, console, count in rows:
            cell = name.replace("|", "-")
            href = console_href(_slug(mfr), console).removeprefix("systems/")
            lines.append(f"| [{cell}]({href}) | {count:,} | [{mfr}]({_slug(mfr)}.md) |")
        lines.append("")

    return "\n".join(lines) + "\n"


def _folder_emulator(folder: str) -> tuple[str, str]:
    """The display name and profile of the emulator a folder under Other is
    named after, by its profile key or its name, else the folder and "".
    """
    profiles = _profiles_on_disk()
    if folder in profiles and profiles[folder].get("type") != "alias" and profiles[folder].get("role") != "test":
        return str(profiles[folder].get("emulator") or folder), folder
    for key in sorted(profiles):
        profile = profiles[key]
        if profile.get("type") == "alias" or profile.get("role") == "test":
            continue
        names = {str(profile.get(field) or "").casefold() for field in ("emulator", "display_name")}
        if folder.casefold() in names:
            return str(profile.get("emulator") or key), key
    return folder, ""


_PROVENANCE_LABELS = {"redump": "Redump", "no-intro": "No-Intro", "tosec": "TOSEC"}

_PROVENANCE_HOMES = {
    "redump": "http://redump.org/",
    "no-intro": "https://no-intro.org/",
    "tosec": "https://www.tosecdev.org/",
}


def _prov_title(data: dict) -> str:
    """Tooltip text for a provenance badge."""
    parts = [data.get("dat", ""), data.get("description", "")]
    return ": ".join(p for p in parts if p).replace('"', "&quot;")


# TOSEC dump flags that say the dump is not a clean copy of the chip
# (TOSEC Naming Convention, "Dump info flags"); [a] alternate and [!]
# verified good are not among them.
_TOSEC_BAD_FLAGS = {
    "b": "bad dump", "o": "overdump", "h": "hacked", "cr": "cracked",
    "f": "fixed", "t": "trained", "p": "pirate",
}
_TOSEC_FLAG_RE = re.compile(r"\[(b|o|h|cr|f|t|p)\d*(?:\s[^\]]*)?\]")


def _dump_flags(source: str, data: dict) -> list[str]:
    """What a catalog's name says is wrong with the dump, as words."""
    if source != "tosec":
        return []
    name = str(data.get("name") or data.get("description") or "")
    seen: list[str] = []
    for flag in _TOSEC_FLAG_RE.findall(name):
        word = _TOSEC_BAD_FLAGS[flag]
        if word not in seen:
            seen.append(word)
    return seen


def _provenance_lines(provenance: dict, prefix: str) -> list[str]:
    """One visible line per catalog: its badge and the entry's own name.

    The name was only a title attribute, unreadable on a touch screen and
    absent from the search for 793 of 803 provenances, and a TOSEC entry
    flagged [b] or [o] wore the same green badge as a clean dump.
    """
    lines: list[str] = []
    for source, data in sorted(provenance.items()):
        label = _PROVENANCE_LABELS.get(source, source)
        flags = _dump_flags(source, data)
        kind = "rb-badge-warning" if flags else "rb-badge-success"
        badge = f'<span class="rb-badge {kind}">[{label}]({prefix}provenance.md#{source})</span>'
        name = str(data.get("name") or data.get("description") or "")
        line = f"- Catalogued: {badge} {_code(name)}" if name else f"- Catalogued: {badge}"
        if flags:
            line += f" ({', '.join(flags)}, as {label} records it)"
        lines.append(line)
    return lines


def load_derivable(path: str = "derivable.json") -> dict[str, dict]:
    """Missing sha1 -> how the collection produces it, as the pipeline found.

    Empty when the pipeline has not recorded it: the page then lists every
    missing dump, as it did before the record existed.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return {}


_ROMSET_SOURCES = {"mame": "MAME", "fbneo": "FBNeo"}


def _date_in_words(stamp: str) -> str:
    """`2026-08-07T...` as `<time datetime="2026-08-07">7 August 2026</time>`."""
    try:
        day = datetime.strptime(str(stamp)[:10], "%Y-%m-%d")
    except ValueError:
        return _escape_tags(str(stamp))
    return f'<time datetime="{day:%Y-%m-%d}">{day.day} {day:%B %Y}</time>'


def generate_provenance_page(
    db: dict, report: dict, derivable: dict[str, dict] | None = None,
    moved: dict[str, str] | None = None,
) -> str:
    """Page explaining the verified dump badges and listing catalog gaps.

    With ``moved``, each catalog's wanted list goes to a page of its own,
    keyed by stem: the three lists made a 694 KB page."""
    matched_files = count_catalog_matched(db)
    total_files = compute_composition(db)["systems"]["files"]
    # When each catalog was read: a 76-day-old snapshot showed no age.
    as_of = ", ".join(
        f"{_PROVENANCE_LABELS.get(source, source)} {_date_in_words(data['imported_at'])}"
        for source, data in report.items() if data.get("imported_at")
    )

    lines = [
        "# Dump provenance",
        "",
        *([f'<p class="rb-timestamp" data-pagefind-ignore>Catalogs as of: {as_of}.</p>', ""]
          if as_of else []),
        "Provenance says whether a file is, byte for byte, a dump that Redump, "
        "No-Intro or TOSEC catalogues. It says where a dump is known from, "
        "not whether an emulator accepts it: that is the emulator's code, read "
        "in its profile. Example: `scph5501.bin` is Redump's `ps-30a.bin`.",
        "",
        f"**{matched_files:,}** of {total_files:,} system files match an entry "
        "in a dump-preservation catalog. Those files carry a "
        '<span class="rb-badge rb-badge-success">catalog</span> badge and the '
        "catalog entry's own name on the [system pages](systems/index.md), "
        'orange (<span class="rb-badge rb-badge-warning">TOSEC</span>) where '
        "TOSEC flags the dump as bad, overdumped, hacked, cracked or fixed. "
        "Arcade ROM sets and engine data "
        "sit outside what those catalogs index, so they are excluded from the "
        "ratio rather than counted as failures.",
        "",
        "## What the badge means",
        "",
        "The badge says the file is byte-identical to a dump catalogued by "
        "No-Intro, Redump, or TOSEC. Matching is done on SHA1, falling back to "
        "MD5 plus size for older catalog entries that predate SHA1. Filenames "
        "are never used: the same dump is `fdsbios.nes` here, "
        "`[BIOS] Family Computer Disk System (Japan) (En) (Rev 1).bin` at "
        "No-Intro, and "
        "`Nintendo Famicom Disk System BIOS (198x)(Nintendo)(JP)(en).bin` at "
        "TOSEC.",
        "",
        "## What it does not mean",
        "",
        "A file without a badge is not inferior and works exactly the same. "
        "Emulator behaviour is decided by [verification]"
        "(wiki/verification-modes.md), which reads the emulator source code, "
        "not by catalog membership. Plenty of files this project ships are "
        "outside any catalog by nature: composites a core assembles for itself "
        "(the MiSTer X68000 `boot.rom` is `cgrom.dat` joined to `iplrom.dat`), "
        "modern console firmware updates, game data such as Diablo's `diabdat.mpq`, and "
        "arcade sets tracked by MAME driver source instead.",
        "",
        "When the two views disagree, this project follows the code, because "
        "that is what decides whether the emulator boots. The reasoning is in "
        "the [technical questions](wiki/technical-faq.md#are-these-files-verified-against-original-"
        "hardware-dumps).",
        "",
        "## Coverage",
        "",
        "| Catalog | In collection | Covered DATs | Snapshot |",
        "|---------|--------------|-------------|----------|",
    ]

    for source, data in report.items():
        label = _PROVENANCE_LABELS.get(source, source)
        home = _PROVENANCE_HOMES.get(source, "")
        in_scope = data["matched"] + len(data["missing"])
        pct = 100 * data["matched"] / in_scope if in_scope else 0
        name = f"[{label}]({home})" if home else label
        lines.append(
            f"| {name} | {data['matched']:,}/{in_scope:,} ({pct:.0f}%) | "
            f"{len(data['covered_dats'])} | {_date_in_words(data['imported_at'])} |"
        )

    lines.extend(
        [
            "",
            "Coverage counts only DATs the collection already reaches: a DAT "
            "counts as covered once at least one of its entries is held. "
            "No-Intro tags every non-game dump `[BIOS]`, including digital "
            "title distribution such as the Wii U and 3DS CDN catalogues, "
            "which this project does not ship.",
            "",
        ]
    )

    out_of_scope = {s: d["out_of_scope"] for s, d in report.items() if d["out_of_scope"]}
    if out_of_scope:
        detail = ", ".join(
            f"{_PROVENANCE_LABELS.get(s, s)} {c:,}" for s, c in sorted(out_of_scope.items())
        )
        lines.extend(
            [
                f"Entries in DATs the collection does not cover at all are "
                f"excluded from those numbers ({detail}).",
                "",
            ]
        )

    # A dump the collection already produces (the odd bytes of a Kickstart,
    # the halves of a character ROM) is no acquisition target: the page asked
    # the public for 79 of them.
    derivable = derivable or {}
    derived_entries: dict[str, dict] = {}
    derived_by_source: dict[str, int] = {}
    for source, data in report.items():
        kept = []
        for entry in data["missing"]:
            sha1 = (entry.get("sha1") or "").lower()
            if sha1 in derivable:
                derived_entries.setdefault(sha1, entry)
                derived_by_source[source] = derived_by_source.get(source, 0) + 1
            else:
                kept.append(entry)
        data["missing"] = kept
    total_missing = distinct_missing(report)
    # The three counts below added up to more than the total above it.
    listed = sum(len(data["missing"]) for data in report.values())
    overlap = (
        f" A dump two catalogs describe is listed under each, so the lists "
        f"hold {listed:,} rows."
        if listed != total_missing else ""
    )
    lines.extend(
        [
            "## Wanted: catalogued dumps this project does not have",
            "",
            f"The tables below list **{total_missing:,}** dumps a catalog "
            f"describes and the collection lacks.{overlap} Nothing here ships in any "
            "pack: it is an acquisition list, published with hashes so anyone "
            "can check a personal collection against it. A contribution "
            "matching one of these hashes is welcome: see "
            "[Contributing](contributing.md).",
            "",
            markup.button("Download the list (CSV)", "downloads/provenance-wanted.csv"),
            "",
        ]
    )

    for source, data in report.items():
        if not data["missing"]:
            continue
        label = _PROVENANCE_LABELS.get(source, source)
        by_dat: dict[str, list] = {}
        for entry in data["missing"]:
            for dat in entry.get("dats") or [entry.get("dat", "")]:
                by_dat.setdefault(dat, []).append(entry)
        lines.extend([f"### {label}", ""])
        if moved is not None:
            where = _list_pages(
                f"provenance-{_slugify_anchor(source)}", f"Wanted from {label}",
                f"Dumps {label} catalogues and the collection lacks. Part of "
                f"[Dump provenance](provenance.md#{_slugify_anchor(label)}).",
                [], [_wanted_list(source, label, data, by_dat, derived_by_source.get(source, 0))],
                moved, parent=("Dump provenance", "/provenance/"),
            )
            lines.extend([
                f"{_count(len(data['missing']), 'dump')} in {_count(len(by_dat), 'DAT')}: "
                f"listed on {where}.", "",
            ])
            continue
        for dat in sorted(by_dat):
            entries = by_dat[dat]
            table = ["| Name | Description | SHA1 |", "|------|-------------|------|"]
            for entry in sorted(entries, key=lambda e: e["name"]):
                sha1 = entry.get("sha1") or "-"
                # A pipe in catalog text would split the markdown table row
                name = entry["name"].replace("|", "-")
                desc = (entry.get("description") or "").replace("|", "-")
                # Where an emulator's romset already carries the dump.
                for hit in entry.get("romsets", []):
                    desc += (
                        f" Ships in {_ROMSET_SOURCES.get(hit['source'], hit['source'])} "
                        f"`{hit['archive']}` as `{hit['member']}`."
                    )
                table.append(f"| `{name}` | {desc} | `{sha1}` |")
            lines.extend(markup.details("note", f"{dat} ({len(entries)})", table))

    if derived_entries:
        lines.extend(
            [
                "## Derivable: dumps the collection already produces",
                "",
                f"**{len(derived_entries):,}** catalogued dumps are not held as "
                "files but come out of one that is: a byte or word split, a "
                "half, a swap, or two chips joined. They are not wanted.",
                "",
                "| Name | Comes from | How | SHA1 |",
                "|------|------------|-----|------|",
            ]
        )
        for sha1, entry in sorted(derived_entries.items(), key=lambda kv: kv[1]["name"]):
            how = derivable[sha1]
            sources = " + ".join(f"`{path}`" for path in how.get("from", []))
            name = entry["name"].replace("|", "-")
            lines.append(f"| `{name}` | {sources} | {how.get('transform', '')} | `{sha1}` |")
        lines.append("")

    lines.extend(["", _date_line()])
    return "\n".join(lines) + "\n"


def _wanted_list(source: str, label: str, data: dict, by_dat: dict[str, list],
                 derived: int) -> list[str]:
    """A catalog's wanted page: the counts, then every missing dump in one
    table folded under a filter box.

    The page was one closed block per DAT, 46 for TOSEC: a name was found
    by opening each in turn. The box filters the whole list by name, DAT,
    description or SHA1, and says how many rows it keeps.
    """
    missing = data["missing"]
    held = data["matched"]
    reached = held + len(missing) + derived
    dats = _count(len(data["covered_dats"]), "DAT")
    lines = [
        f"Held: **{held:,}** of {reached:,}, in the {dats} the collection reaches. "
        f"Wanted: **{len(missing):,}**, from {_count(len(by_dat), 'DAT')}.",
        "",
    ]
    if derived:
        verb = "is" if derived == 1 else "are"
        lines.extend([
            f"{derived:,} more {verb} [derivable]"
            "(provenance.md#derivable-dumps-the-collection-already-produces).", ""])
    if data.get("out_of_scope"):
        lines.extend([f"{data['out_of_scope']:,} more sit in DATs the collection does not reach.", ""])
    counts = ["| DAT | Wanted |", "|-----|--------|",
              *(f"| {dat.replace('|', '-')} | {len(entries):,} |"
                for dat, entries in sorted(by_dat.items()))]
    lines.extend(markup.details("note", f"Wanted by DAT ({len(by_dat):,})", counts))
    rows = []
    for entry in sorted(missing, key=lambda e: (e["name"], e.get("sha1") or "")):
        desc = markup.inline_html(entry.get("description") or "")
        for hit in entry.get("romsets", []):
            desc += markup.inline_html(
                f" Ships in {_ROMSET_SOURCES.get(hit['source'], hit['source'])} "
                f"`{hit['archive']}` as `{hit['member']}`.")
        in_dats = ", ".join(html.escape(d) for d in (entry.get("dats") or [entry.get("dat", "")]))
        sha1 = html.escape(entry.get("sha1") or "-")
        # The search reads the name alone. The DAT names are searched once, in
        # the count table above, and the site search holds no hashes. With the
        # descriptions indexed too, the TOSEC list matched "2" 556 times
        # (years, versions) and put the PlayStation page ahead of the
        # PlayStation 2 one for "playstation 2 bios". The name and the hash
        # sit in their cells as text: a catalog name is words, and in code
        # each word wore its own box on a narrow column.
        skip = markup.search_exclude()
        rows.append("<tr>"
                    f"<td>{html.escape(entry['name'], quote=False)}</td>"
                    f"<td {skip}>{in_dats}</td><td {skip}>{desc or '-'}</td>"
                    f'<td class="rb-hash" {skip}>{sha1}</td></tr>')
    heads = ["Name", "DAT", "Description", "SHA1"]
    lines.extend([
        siteentries.filter_box(f"rb-wanted-filter-{_slugify_anchor(source)}",
                               "dumps", heads, len(rows)),
        '<details class="rb-details rb-details-note">',
        f"<summary>All {_count(len(rows), 'wanted dump')}</summary>",
        '<table class="rb-wanted" data-rb-stack="true">',
        "<thead><tr>" + "".join(f'<th scope="col">{h}</th>' for h in heads) + "</tr></thead>",
        "<tbody>", *rows, "</tbody>", "</table>", "</details>", "",
    ])
    return lines


_RELEASE_ASSET_NAMES: dict[str, str] | None = None


def _download_name(path: str) -> str:
    """The name a browser saves a collection file under: the last segment
    of its download URL. Neither host sends a Content-Disposition, and the
    download attribute is ignored on another origin."""
    return urllib.parse.unquote(_fetch_url(path).rsplit("/", 1)[-1])


def _fetch_url(path: str) -> str:
    """Where a collection file downloads from: its raw URL, or the
    large-files release asset when .gitignore keeps it out of git."""
    global _RELEASE_ASSET_NAMES
    if _RELEASE_ASSET_NAMES is None:
        from largefiles import (  # noqa: PLC0415
            LARGE_FILES_RELEASE,
            asset_names,
            load_registered_paths,
            published_asset_name,
        )

        _RELEASE_ASSET_NAMES = {
            registered: f"{REPO_URL}/releases/download/{LARGE_FILES_RELEASE}/"
            + urllib.parse.quote(published_asset_name(name))
            for registered, name in asset_names(load_registered_paths()).items()
        }
    return _RELEASE_ASSET_NAMES.get(path) or (
        "https://raw.githubusercontent.com/Abdess/retrobios/main/"
        + urllib.parse.quote(path)
    )


_platform_names: dict[str, str] = {}


def _platform_display(name: str) -> str:
    """A setup's name as its platform file writes it: Batocera, not batocera."""
    display = _platform_names.get(name)
    if display is None:
        try:
            config = load_platform_config(name, str(siteinputs.current().platforms))
        except FileNotFoundError:
            config = {}
        display = _platform_names[name] = str(config.get("platform") or name)
    return display


# A setup, the link to its page, and where it puts the file.
Place = tuple[str, str, list[str]]


def _platform_places(sha1: str, consumers: FileConsumers) -> list[Place]:
    """Each platform declaring the file, linked to its system section, with
    the destination it gives the file."""
    systems_of = getattr(consumers, "platform_systems", {}).get(sha1, {})
    destinations_of = getattr(consumers, "platform_destinations", {}).get(sha1, {})
    places: list[Place] = []
    for platform in consumers.platforms.get(sha1, ()):
        section = sorted(systems_of.get(platform, ()))
        fragment = f"#{section[0].replace(' ', '-')}" if section else ""
        places.append((_platform_display(platform), f"../platforms/{platform}.md{fragment}",
                       sorted(destinations_of.get(platform, ()))))
    return sorted(places, key=lambda place: place[0].casefold())


def _platform_links(sha1: str, consumers: FileConsumers) -> list[str]:
    """Each platform declaring the file, as Markdown: its name, linked to
    its system section, then the destination it gives the file."""
    return [
        f"[{name}]({href})" + (": " + ", ".join(_code(d) for d in dests) if dests else "")
        for name, href, dests in _platform_places(sha1, consumers)
    ]


_card_anchors: dict[str, tuple[list, list[str]]] = {}


def _emulator_card_anchor(emulator: str, files: list, index: int) -> str:
    """The id of a profile entry's card on its emulator page."""
    cached = _card_anchors.get(emulator)
    if cached is None or cached[0] is not files:
        cached = _card_anchors[emulator] = (files, emulator_file_anchors(files))
    return cached[1][index] if 0 <= index < len(cached[1]) else ""


def _emulator_links(sha1: str, consumers: FileConsumers) -> list[str]:
    """Each emulator reading the file, linked to the entry that reads it.

    The platform links landed on their system section, and the emulator
    links on the page top: duckstation's scph5501.bin entry, with the line
    that accepts it, sat 260 lines down a page of 105 entries.
    """
    entries = getattr(consumers, "emulator_entries", {}).get(sha1, {})
    files_of = getattr(consumers, "emulator_files", {})
    links = []
    # By the name the emulator's page carries: 19,499 card links read
    # melonds_ds where its page says melonDS DS.
    named = sorted(((_emulator_display(e), e) for e in consumers.emulators.get(sha1, ())),
                   key=lambda pair: (pair[0].casefold(), pair[1]))
    for display, emulator in named:
        index = entries.get(emulator)
        anchor = (_emulator_card_anchor(emulator, files_of[emulator], index)
                  if index is not None and emulator in files_of else "")
        page = emulator_card_page(emulator, anchor) if anchor else emulator
        fragment = f"#{anchor}" if anchor else ""
        # The card's facts are raw HTML: "Game & Watch" is escaped, and a
        # bracket would end the link the facts are parsed from.
        text = html.escape(display, quote=False).replace("[", "&#91;").replace("]", "&#93;")
        links.append(f"[{text}](../emulators/{page}.md{fragment})")
    return links


def _installed_places(sha1: str, consumers: FileConsumers, declared: set[str]) -> list[Place]:
    """Each pack installing the file that its platform's list does not name,
    with the place the pack gives it."""
    places = [
        (_platform_display(platform), f"../platforms/{platform}.md", sorted(d for d in dests if d))
        for platform, dests in getattr(consumers, "installed", {}).get(sha1, {}).items()
        if platform not in declared
    ]
    return sorted(places, key=lambda place: place[0].casefold())


def _places_lines(places: list[Place]) -> list[str]:
    """Setups grouped by where they put the file, one line per place:
    "`scph5501.bin`: Batocera, EmuDeck". Each setup repeating the name
    took five lines where one says it. A setup that names no place (EmuDeck
    matches by MD5) is listed on a line of its own, last."""
    def plain(text: str) -> str:
        return html.escape(text, quote=False).replace("`", "&#96;")

    by_place: dict[tuple[str, ...], list[str]] = {}
    for name, href, dests in places:
        by_place.setdefault(tuple(dests), []).append(f"[{name}]({href})")
    ordered = sorted(by_place.items(), key=lambda item: (not item[0], -len(item[1]), item[0]))
    return [
        (" and ".join(f"<code>{plain(d)}</code>" for d in dests) + ": " if dests else "")
        + ", ".join(links)
        for dests, links in ordered
    ]


def _places_markdown(places: list[Place]) -> list[str]:
    """_places_lines in Markdown, for a card written as a list: the places
    as code spans, which the glossary and the line breaks treat as code."""
    by_place: dict[tuple[str, ...], list[str]] = {}
    for name, href, dests in places:
        by_place.setdefault(tuple(dests), []).append(f"[{name}]({href})")
    ordered = sorted(by_place.items(), key=lambda item: (not item[0], -len(item[1]), item[0]))
    return [(" and ".join(_code(d) for d in dests) + ": " if dests else "") + ", ".join(links)
            for dests, links in ordered]


def _inline_card_html(text: str) -> str:
    """A card value written in Markdown (code spans, links), as the HTML a
    fact list holds. HTML already in the value is kept."""
    out: list[str] = []
    for part in re.split(r"(`[^`]*`)", text):
        if len(part) > 1 and part.startswith("`") and part.endswith("`"):
            out.append(f"<code>{html.escape(part[1:-1], quote=False)}</code>")
        else:
            out.append(re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", r'<a href="\2">\1</a>', part))
    return "".join(out)


# A link icon, the way a heading anchor is drawn: the word "permalink" was
# read as part of every card title, by the search and by screen readers.
# Drawn once per page and used by each card: inline, its 400 bytes were
# 100 KB on the Sony page.
PERMALINK_SYMBOL = (
    '<svg aria-hidden="true" style="display:none"><symbol id="rb-link-icon" '
    'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/>'
    '<path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/></symbol></svg>'
)
_PERMALINK_ICON = ('<svg aria-hidden="true" width="16" height="16">'
                   '<use href="#rb-link-icon"/></svg>')


def _icon_symbol() -> list[str]:
    """The icon's drawing, for a page of cards. None in the yardstick."""
    return [PERMALINK_SYMBOL, ""] if markup.starlight() else []


RomsetMembers = tuple[tuple[str, str], ...]
# A release a recipe agrees with: its place among the imported releases of
# its source, and its name ("0.220", "1.0.0.03").
Release = tuple[int, str]


def _release_name(source: str, label: str, versions: dict) -> str:
    """"MAME mame0220" as "0.220", an FBNeo DAT title as its version."""
    match = re.fullmatch(r"MAME mame(\d)(\d+)", label) if source == "mame" else None
    return f"{match[1]}.{match[2]}" if match else str(versions.get(label) or label)


@functools.lru_cache(maxsize=1)
def _romset_snapshots() -> list[tuple[str, dict]]:
    return [(str(snapshot.get("source", path.stem)), snapshot)
            for path in sorted((_REPO_ROOT / "recipes").glob("*.json"))
            for snapshot in [json.loads(path.read_text(encoding="utf-8"))]]


@functools.lru_cache(maxsize=1)
def _romset_releases() -> dict[str, list[tuple[RomsetMembers, str, list[Release]]]]:
    """Archive name -> (members, source, the releases agreeing on them), from
    the MAME and FBNeo recipe snapshots under recipes/.

    A snapshot stores a recipe once for every version that agrees on it,
    so a match reads "this set's contents in those versions".
    """
    releases: dict[str, list[tuple[RomsetMembers, str, list[Release]]]] = {}
    for source, snapshot in _romset_snapshots():
        versions = snapshot.get("dats") or {}
        order = {label: index for index, label in enumerate(versions)}
        for entry in snapshot.get("entries") or []:
            members = tuple(sorted(
                (str(m["name"]), str(m.get("crc32") or "").lower())
                for m in entry.get("members") or [] if m.get("name") is not None
            ))
            if not entry.get("name") or not members or not all(crc for _n, crc in members):
                continue
            agreed = [(order.get(label, -1), _release_name(source, str(label), versions))
                      for label in entry.get("dats") or [entry.get("dat")]]
            releases.setdefault(str(entry["name"]), []).append((members, source, agreed))
    return releases


def _release_runs(releases: list[Release]) -> str:
    """Releases as runs of consecutive imports: "0.190 to 0.195, 0.220 to
    0.289". One FBNeo version shared by 15 DATs reads once."""
    runs: list[list[Release]] = []
    for release in sorted(set(releases)):
        if runs and release[1] == runs[-1][-1][1]:
            continue
        if runs and release[0] == runs[-1][-1][0] + 1:
            runs[-1].append(release)
        else:
            runs.append([release])
    return ", ".join(run[0][1] if len(run) == 1 else f"{run[0][1]} to {run[-1][1]}"
                     for run in runs)


def _source_order(source: str) -> tuple[bool, str]:
    return source != "mame", source


def _romset_line(f: dict) -> str:
    """Which MAME and FBNeo releases a collected archive's contents match.

    MAME and FBNeo check the members of an archive by CRC32, never its own
    bytes or its member names: a set works with a release when it holds
    every CRC32 the release's recipe lists, extra members or not. The
    main neogeo.zip, which every MAME from 0.177 to 0.289 loads, read "No
    match" when names had to agree and no member could be extra. Empty
    when no recipe names the archive or the file is not on disk.
    """
    recipes = _romset_releases().get(str(f.get("name", "")))
    path = _REPO_ROOT / str(f.get("path", ""))
    if not recipes or not path.is_file():
        return ""
    try:
        with zipfile.ZipFile(path) as archive:
            held = tuple(sorted((info.filename, f"{info.CRC:08x}")
                                for info in archive.infolist() if not info.is_dir()))
    except (OSError, zipfile.BadZipFile) as exc:
        print(f"  WARNING: {path}: {exc}", file=sys.stderr)
        return ""
    crcs = {crc for _name, crc in held}
    same: dict[str, list[Release]] = {}
    holds: dict[str, list[Release]] = {}
    # source -> (fewest CRC32s missing, the latest release missing that many)
    closest: dict[str, tuple[int, Release]] = {}
    for members, source, agreed in recipes:
        missing = len({crc for _name, crc in members} - crcs)
        if members == held:
            same.setdefault(source, []).extend(agreed)
        elif not missing:
            holds.setdefault(source, []).extend(agreed)
        elif agreed:
            latest = max(agreed)
            best = closest.get(source)
            if best is None or (missing, -latest[0]) < (best[0], -best[1][0]):
                closest[source] = (missing, latest)

    def runs(found: dict[str, list[Release]], skip: dict[str, list[Release]]) -> str:
        return " and ".join(
            f"{_ROMSET_SOURCES.get(source, source)} {_release_runs(kept)}"
            for source in sorted(found, key=_source_order)
            for kept in [[r for r in found[source] if r not in skip.get(source, [])]] if kept)

    said = []
    if same:
        said.append(f"Same contents as {runs(same, {})}")
    if holds and runs(holds, same):
        said.append(f"Holds every ROM of {runs(holds, same)}")
    if said:
        return ". ".join(said)
    if not closest:
        return f"No match in {_romset_coverage()}"
    return "No match: missing " + ", ".join(
        f"{_count(missing, 'ROM')} of {_ROMSET_SOURCES.get(source, source)} {release[1]}"
        for source, (missing, release) in sorted(closest.items(),
                                                 key=lambda item: _source_order(item[0])))


@functools.lru_cache(maxsize=1)
def _romset_coverage() -> str:
    """The releases the recipes cover: "MAME 0.190 to 0.289 or FBNeo 1.0.0.03"."""
    covered = {}
    for source, snapshot in _romset_snapshots():
        versions = snapshot.get("dats") or {}
        if versions:
            ends = [(index, _release_name(source, label, versions))
                    for index, label in enumerate(versions)]
            # The ends of the span, read as one run.
            span = [ends[0], (1, ends[-1][1])] if len(ends) > 1 else ends
            covered[source] = f"{_ROMSET_SOURCES.get(source, source)} {_release_runs(span)}"
    return " or ".join(covered[source] for source in sorted(covered, key=_source_order))


ROMSET_FAQ = "../wiki/technical-faq.md#which-mame-version-do-the-arcade-bios-sets-match"


def _system_file_card(
    f: dict, consumers: FileConsumers, anchored: set[str] | None = None,
    searchable: bool = True,
) -> list[str]:
    """One file of a system page: hashes, who reads it, its provenance.

    ``searchable`` false keeps even the name out of the site search: the
    asset trees of game engines hold thousands of 0.ogg and tile.png.
    """
    name = f["name"]
    sha1_full = f.get("sha1", "unknown")
    md5_full = f.get("md5", "unknown")
    # The size a card names is the file's own, exact: rounded, 44,348,015
    # and 44,356,548 bytes were one 42.3 MB.
    size = _card_size(int(f.get("size", 0)))
    # Who reads this file, not who reads a file of this name
    plats = sorted(consumers.platforms.get(sha1_full, ()))
    emus = sorted(consumers.emulators.get(sha1_full, ()))
    installed = _installed_places(sha1_full, consumers, set(plats))

    anchor = f"sha1-{sha1_full[:12]}" if sha1_full != "unknown" else ""
    # A copy filed under two consoles of one maker is listed twice on its
    # page: the first card holds the anchor, as an id names one element.
    if anchored is not None:
        if anchor in anchored:
            anchor = ""
        else:
            anchored.add(anchor)
    skip = markup.search_exclude()
    lines = [markup.block_open("div", 'class="rb-sys-file"'), ""]
    # The heading's own link is this page's, the icon is the file's own
    # address, resolved by content wherever its card moves.
    # The yardstick keeps the word, the size the page budget was set on.
    icon = _PERMALINK_ICON if markup.starlight() else "permalink"
    permalink = (
        f' <a class="rb-permalink" href="{markup.site_href(f"files/?sha1={sha1_full}")}" '
        f'aria-label="Permanent link to {html.escape(name)}" '
        f'title="Permanent link, by content" {skip}>{icon}</a>'
    ) if anchor else ""
    # A file nothing reads said so nowhere: 53 of 248 Sony cards had no
    # emulator, platform or pack line and looked unfinished.
    unread = (f' <span class="rb-badge rb-badge-muted" {skip}>No reader</span>'
              if not (emus or plats or installed) else "")
    # The download leads the card: as a "(download)" after the collection
    # path, fourth of the facts, a reader of the Apple II page found none.
    download = (
        f' <a class="rb-download" href="{html.escape(_fetch_url(f["path"]))}" '
        f'aria-label="Download {html.escape(name)}" {skip}>Download</a>'
    ) if f.get("path") and markup.starlight() else ""
    lines.append(_card_title(
        f'{_code(name)} <span class="rb-badge rb-badge-muted">{size}</span>{unread}{download}{permalink}',
        anchor, searchable,
    ))
    lines.append("")

    # Each fact: its label, its values, whether the search reads it. What a
    # setup does with the file comes first, the fingerprints last.
    facts: list[tuple[str, list[str], bool]] = []
    saved = _download_name(f["path"]) if f.get("path") else name
    if saved != name:
        # A .variants/ copy is stored as advision.zip.1c086064, and the
        # browser names the download after the URL: copied as it came, the
        # file a platform pins was not found under its name.
        facts.append(("Save as", [f"{_code(name)}, the download is named {_code(saved)}"], False))
    if plats:
        # Each link lands on the platform's system section, and says where
        # that platform puts the file. Out of the search: the card's title
        # weighs the most a word can, and the list made the excerpt of
        # every card a run of setup names and paths.
        facts.append(("On the setup's list",
                      _places_lines(_platform_places(sha1_full, consumers)), False))
    if installed:
        # The packs that carry the file for their cores: a RetroBat user
        # looking up scph5501.bin found every platform but RetroBat, whose
        # pack installs it for six cores.
        facts.append(("Packed for its emulators by", _places_lines(installed), False))
    if emus:
        facts.append(("Emulators", [", ".join(_emulator_links(sha1_full, consumers))], False))
    romset = _romset_line(f)
    if romset:
        # The version question every arcade player asks, answered from the
        # recipes: the cards named emulators and no release.
        facts.append(("Romset", [romset], False))
    if f.get("path"):
        # The card named a file, its hashes and provenance, but not where to
        # get it: a user missing scph5501.bin found the reference and no way
        # to the bytes.
        path = _code(f["path"])
        if not markup.starlight():
            path += f" ([download]({_fetch_url(f['path'])}))"
        facts.append(("Collection path", [path], False))
    catalogued = [line.split(": ", 1)[1]
                  for line in _provenance_lines(f.get("provenance") or {}, "../")]
    if catalogued:
        facts.append(("Catalogued", catalogued, False))
    # Every hash in full: the site search indexes text, not a title
    # attribute, so a pasted md5 or crc32 (what clrmamepro, RomVault or an
    # emulator log prints) found nothing behind a 12-character prefix.
    # files/?hash= finds them, and the index skips them.
    for label, value in (("SHA1", sha1_full), ("MD5", md5_full),
                         ("CRC32", f.get("crc32")), ("SHA256", f.get("sha256"))):
        if value and value != "unknown":
            # Starlight writes the value bare: its cell carries the hash
            # style and the copy button (_fact_list).
            shown = (html.escape(str(value)) if markup.starlight()
                     else f'<span class="rb-hash">{html.escape(str(value))}</span>')
            facts.append((label, [shown], False))

    if not markup.starlight():
        # The size yardstick pages are cut by: the list a card was when the
        # budget was set, so a fact grid moves no card to another page.
        lines.extend(search_excluded([f"- {label}: {', '.join(values)}"
                                      for label, values, _searched in facts]))
    else:
        lines.extend(_card_fact_groups(facts, sha1_full, searchable))
    lines.extend(["", "</div>", ""])
    return lines


# What a system card shows at a glance: who lists the file and who reads it.
# Its fingerprints and the rest open on demand, so a page of 250 cards reads
# as a list of files, not a wall of hashes.
_CARD_KEY_FACTS = ("Save as", "On the setup's list", "Packed for its emulators by", "Emulators")
_CARD_HASHES = ("SHA1", "MD5", "CRC32", "SHA256")
# The words a card's fold names its other facts by.
_CARD_MORE_WORDS = {"Romset": "romset", "Collection path": "collection path",
                    "Catalogued": "catalogues"}
# A hash shown short, in a card, a platform row or an emulator table: as long
# as the card's own address (sha1-<12 hex>), one length across the site.
SHORT_HASH = 12


def _listed_words(words: list[str]) -> str:
    """"a", "a and b", "a, b and c", first letter capital."""
    text = words[0] if len(words) == 1 else f"{', '.join(words[:-1])} and {words[-1]}"
    return text[:1].upper() + text[1:]


def _fact_list(facts: list[tuple[str, list[str], bool]], skip: str,
               copy: dict[str, str] | None = None) -> list[str]:
    """Facts as a grid, label then value, one value cell per label.

    A label in *copy* holds one hash: its cell takes the hash style, and
    the site script a copy button (site.ts). *copy* gives the cell's
    classes. One element, where a span in the cell was one more per hash.
    """
    if not facts:
        return []
    copy = copy or {}

    def cell(label: str, values: list[str]) -> str:
        if label in copy:
            return f'<dd class="{copy[label]}">{values[0]}</dd>'
        return "<dd>" + "<br>".join(_inline_card_html(v) for v in values) + "</dd>"

    return [f'<dl class="rb-facts"{skip}>',
            *(f"<dt>{label}</dt>{cell(label, values)}" for label, values, _searched in facts),
            "</dl>"]


def card_fold(summary: str, body: list[str], skip: bool = True) -> list[str]:
    """A fold of a file card: closed, its summary naming what it holds.

    Native details: no script needed, and the text inside stays in the page
    (and in the search, unless *skip*). No class: the card styles its folds,
    and a class was 21 bytes on each of 250 cards."""
    attribute = f" {markup.search_exclude()}" if skip else ""
    summary_line = f"<summary>{html.escape(summary, quote=False)}</summary>"
    # Each tag on a line of its own, or MDX reads the fold as a paragraph
    # left open. Markdown inside also takes a blank line around it.
    gap = [] if body and body[0].startswith("<") else [""]
    return [f"<details{attribute}>", summary_line, *gap, *body, *gap, "</details>"]


def _card_fact_groups(facts: list[tuple[str, list[str], bool]], sha1: str,
                      searchable: bool) -> list[str]:
    """A system card's facts under Starlight: the key ones open, a short
    SHA1 first, then the hashes and the rest in one closed fold.

    The search skips all of them, as it did when they were one list: on
    each row the attribute was 77 KB of the Sony page. Hashes are found by
    files/?hash=, which the search box offers for a pasted hash.
    """
    skip = f" {markup.search_exclude()}"
    key = [fact for fact in facts if fact[0] in _CARD_KEY_FACTS]
    hashes = [fact for fact in facts if fact[0] in _CARD_HASHES]
    more = [fact for fact in facts if fact not in key and fact not in hashes]
    searched = [fact for fact in facts if fact[2] and searchable]
    lines: list[str] = []
    if searched:
        # No fact is searched today. One that is keeps its label out: the
        # excerpt ran the two together, "On the setup's listAmberELEC".
        lines += ['<dl class="rb-facts">',
                  *(f"<dt{skip}>{label}</dt><dd>"
                    + "<br>".join(_inline_card_html(v) for v in values) + "</dd>"
                    for label, values, _searched in searched),
                  "</dl>"]
        key = [fact for fact in key if fact not in searched]
        more = [fact for fact in more if fact not in searched]
    glance = []
    if sha1 and sha1 != "unknown":
        # The first characters, enough to tell two dumps apart at a glance.
        # Its button copies the whole value, read from the fold below: the
        # value twice was 54 bytes more on each card.
        glance.append(("SHA1", [html.escape(sha1[:SHORT_HASH])], False))
    lines += _fact_list(glance + key, skip, {"SHA1": "rb-hash"})
    # One fold: two were four more elements on each of 250 cards.
    folded = hashes + more
    if folded:
        words = (["hashes"] if hashes else []) + [
            _CARD_MORE_WORDS.get(label, label.lower()) for label, _values, _searched in more]
        # On one line: nothing reads it as Markdown, and a page cut by size
        # holds its cards in the same bytes.
        lines += card_fold(_listed_words(words),
                           ["".join(_fact_list(folded, "", dict.fromkeys(_CARD_HASHES, "rb-hash")))])
    return lines


SEARCH_TABLE_BYTES = 3000


def tables_out_of_search(markdown: str, threshold: int = SEARCH_TABLE_BYTES) -> str:
    """Each table longer than ``threshold`` bytes, wrapped out of the search.

    A search result shows the start of a section: a 600-row table as one
    snippet helps nobody, and the gaps, provenance and cross-reference
    tables were 900 KB of the index. The headings above them stay.
    """
    lines = markdown.split("\n")
    out: list[str] = []
    index = 0
    while index < len(lines):
        match = re.match(r"( *)\|", lines[index])
        if not match:
            out.append(lines[index])
            index += 1
            continue
        indent = match.group(1)
        end = index
        while end < len(lines) and re.match(rf"{indent}\|", lines[end]):
            end += 1
        table = lines[index:end]
        if sum(len(line) for line in table) > threshold:
            out += ["", indent + markup.block_open("section", markup.search_exclude()), "",
                    *table, "", f"{indent}</section>", ""]
        else:
            out += table
        index = end
    return "\n".join(out)


def search_excluded(lines: list[str]) -> list[str]:
    """Lines the site search leaves out, as a block of their own.

    The browser downloads and indexes the whole search index before the
    first result: hashes, link lists and install commands repeated on 600
    pages made it 21 MB. Hashes are found by files/?hash=, names and prose
    stay searchable.

    A section, not a div: the search plugin compares elements by tag, so
    the first div closed inside an excluded div (a code block's) ended the
    exclusion and the rest of the block was indexed.
    """
    return ["", markup.block_open("section", markup.search_exclude()), "",
            *lines, "", "</section>", ""]


# Card lines the site search leaves out. They list where a file goes and
# who cites it, links to other pages that index the same names, and they
# were 6.6 of the 24.7 MB the browser downloads and indexes before the first
# result. The name, the hashes, the entry's path and the notes stay
# searchable.
SEARCH_SKIPPED = (
    "- SHA1:", "- MD5:", "- CRC32:", "- SHA256:", "- Adler32", "- Size:",
    "- Validation", "- Priority:", "- Contents (",
    "- Platforms:", "- Source:", "- Asked for by:",
    "- Collection path:", "- Collection copy:", "- Collection copies:",
    "- Installed by the platform's own package on:",
    "- Not in the platform's package", "- Never opened on these platforms",
)


def _search_skipped_apart(lines: list[str]) -> list[str]:
    """Card list lines, each run the search skips in a block of its own."""
    out: list[str] = []
    skipping = False
    for line in lines:
        skip = line.startswith(SEARCH_SKIPPED) or (skipping and line.startswith("    "))
        if skip and not skipping:
            out.extend(["", markup.block_open(
                "div", f'class="rb-search-skip" {markup.search_exclude()}'), ""])
        elif skipping and not skip:
            out.extend(["", "</div>", ""])
        skipping = skip
        out.append(line)
    if skipping:
        out.extend(["", "</div>", ""])
    return out


def _card_title(text: str, anchor: str, searchable: bool = True, weight: int = 10) -> str:
    """A file card's heading, so the site search lands on the card.

    The search splits a page at its headings: a card titled in bold sent a
    pasted md5 to the top of a page of a hundred cards. Level 3, under
    the console or the Files heading: a level 4 after a level 2 skipped
    one for screen readers on 551 pages. The table of contents of a page
    of cards stops above it (sitestarlight.py), and a card without an
    anchor keeps the id the toc gives it.
    """
    if markup.starlight():
        # Raw HTML: the card links to itself already, and a Markdown heading
        # would add the engine's anchor link and icon to every card.
        title = re.sub(r"`([^`]+)`", lambda m: f"<code>{html.escape(m[1], quote=False)}</code>", text)
        ident = f' id="{anchor}"' if anchor else ""
        # A system page's card is the file's own page in all but name: its
        # title weighs the most a word can, so a file name typed in the
        # search finds the card before a guide that cites it as an example.
        # An emulator's card says who reads the file, and weighs half.
        search = f' data-pagefind-weight="{weight}"' if searchable else f" {markup.search_exclude()}"
        return f'<h3{ident} class="rb-file-title"{search}>{title}</h3>'
    attributes = f"#{anchor} .rb-file-title" if anchor else ".rb-file-title"
    if not searchable:
        attributes += " data-search-exclude"
    return f"### {text} {{ {attributes} }}"


def system_install_choices(coverages: dict) -> dict[str, dict[str, list[tuple[str, str]]]]:
    """slug -> console -> the (platform, system id) pairs linked to it.

    Read through the same table as every system link, so a command sits in
    the section the platform's system links to. Only a system the
    platform's install manifest records is offered: --system refuses any
    other name.
    """
    from siterender import _page_by_norm  # noqa: PLC0415

    choices: dict[str, dict[str, list[tuple[str, str]]]] = {}
    for name, cov in sorted(coverages.items()):
        manifest = _REPO_ROOT / "install" / f"{name}.json"
        if not manifest.is_file():
            continue
        document = json.loads(manifest.read_text(encoding="utf-8"))
        recorded = {
            str(system)
            for entry in (document.get("files") or []) + (document.get("omitted_files") or [])
            for system in entry.get("systems") or []
        }
        for sys_id in sorted(set(cov["config"].get("systems") or {}) & recorded):
            page = _system_page_map.get(sys_id) or _page_by_norm(sys_id)
            if page:
                slug, console = page
                choices.setdefault(slug, {}).setdefault(console, []).append((name, sys_id))
    return choices


# A manufacturer page above this much Markdown becomes a summary with one
# page per console, and a console above it is cut into parts. Measured as
# MkDocs Markdown, a page renders to up to 1.8 times its size in HTML with
# its structured data: at 500 KB the Sony page was 849 KB, and every page
# stays under 600 KB from 300 KB. game-engines was one 10.5 MB page that
# took 21 s of main-thread work on a phone.
SYSTEM_PAGE_BUDGET = 300_000
# Manufacturers whose every console gets a page of its own, whatever its
# size. A section shares its page's search fields with its neighbours, and
# a digit is on too many pages to weigh: "playstation 3 bios" found the
# PlayStation page before the Sony page that held the PlayStation 3.
CONSOLE_PAGES = frozenset({"Sony"})
# What the sections kept on a manufacturer's summary may weigh once
# rendered, estimated from their Markdown. Fitted on the Nintendo, Sega and
# Commodore summaries: highlighted install commands grow about eleven times
# since each carries its setup's name, cards 1.7 times. The page budget is
# 600 KB of HTML, and the frame around the content (head, navigation,
# footer) is about 45 KB.
CARD_HTML_RATIO = 1.7
INSTALL_HTML_RATIO = 11
SYSTEM_SUMMARY_HTML = 500_000
# The ratio was fitted while each command named the raw.githubusercontent.com
# bootstrap, 66 characters (67 for PowerShell). A box is weighed with its
# address at that length, so the shorter site address moves no console off
# or onto a summary and no card changes address.
FITTED_ADDRESS_CHARS = {INSTALL_PS1: 67, INSTALL_SH: 66}


def _install_box_weight(lines: list[str]) -> int:
    weight = 0
    for line in lines:
        weight += len(line) + 1
        for address, fitted in FITTED_ADDRESS_CHARS.items():
            found = line.count(address)
            line = line.replace(address, "")
            weight += found * (fitted - len(address))
    return weight


# A system card: whether it is a variant, its lines, its sha1.
Card = tuple[bool, list[str], str]
_Item = TypeVar("_Item")


def _reading_entries(sha1: str, consumers: FileConsumers) -> list[dict]:
    """The profile entries that read a file, one per emulator."""
    files_of = getattr(consumers, "emulator_files", {})
    entries = []
    for emulator, index in getattr(consumers, "emulator_entries", {}).get(sha1, {}).items():
        files = files_of.get(emulator) or []
        if 0 <= index < len(files) and isinstance(files[index], dict):
            entries.append(files[index])
    return entries


_NO_PRIORITY = 1 << 30


def _card_rank(f: dict, consumers: FileConsumers, start: dict[str, int] | None = None) -> tuple:
    """Where a file's card sits in its console: the files the section's
    start line names first, in its order (``start``, sha1 -> place), then
    the files an emulator requires, then by the emulators' search order
    (smallest first), then a required file by how many emulators read it,
    then by how many setups list the file, then by name.

    By byte order the PlayStation section opened on LibPS.exe and
    PSX_DTLH2000.bin, capitals first, and scph5501.bin was 28th. Without
    the reader count the Neo Geo section opened on aes.zip, which geolith
    alone reads. Without the start line's order, "first below" named
    neogeo.zip over a section opening on sfix.sfix.
    """
    sha1 = str(f.get("sha1", ""))
    entries = _reading_entries(sha1, consumers)
    priorities = [e["priority"] for e in entries if isinstance(e.get("priority"), int)]
    required = any(e.get("required", True) for e in entries)
    return (
        (start or {}).get(sha1, _NO_PRIORITY),
        not required,
        min(priorities, default=_NO_PRIORITY),
        -len(entries) if required else 0,
        -len(consumers.platforms.get(sha1, ())),
        f["name"].casefold(), f["name"], f.get("path", ""),
    )


def _by_name(f: dict) -> tuple:
    return f["name"].casefold(), f["name"], f.get("path", "")


def _console_cards(
    manufacturer: str,
    files: list[dict],
    consumers: FileConsumers,
    anchored: set[str],
    by_name: bool = False,
    start: list[str] | None = None,
) -> list[Card]:
    """Each card of one console, primaries then variants, with whether it
    is a variant. ``start`` is the sha1s the start line names, whose cards
    come first in its order. ``by_name`` orders the rest by name alone,
    for a console cut into parts named by their first and last file: the
    PlayStation 2 opened on cheats_ni.zip, its BIOS far below."""
    searchable = manufacturer not in GAME_DATA_TOPS
    place = {sha1: index for index, sha1 in enumerate(start or [])}

    def order(f: dict) -> tuple:
        if by_name:
            return (place.get(str(f.get("sha1", "")), _NO_PRIORITY), *_by_name(f))
        return _card_rank(f, consumers, place)
    # Another revision of a MAME or FBNeo set is another release's set, its
    # Romset line saying which: it sits open beside the set of its name.
    # Twelve neogeo.zip were on five pages, the SNK ones closed under
    # Variants.
    romsets = _romset_releases()
    beside = [f for f in files if "/.variants/" in f["path"] and f["name"] in romsets]
    main_files = [f for f in files if "/.variants/" not in f["path"]]
    variant_files = [f for f in files if "/.variants/" in f["path"] and f not in beside]
    # Sets of one name side by side, the first ranked leading.
    ranked = sorted(main_files, key=order)
    by_set: dict[str, list[dict]] = {}
    for f in [*ranked, *sorted(beside, key=order)]:
        if f["name"] in romsets:
            by_set.setdefault(f["name"], []).append(f)
    ordered: list[dict] = []
    for f in ranked:
        if f["name"] not in romsets:
            ordered.append(f)
        elif by_set.get(f["name"]):
            ordered.extend(by_set.pop(f["name"]))
    ordered.extend(f for files in by_set.values() for f in files)
    cards = [(False, _system_file_card(f, consumers, anchored, searchable), str(f.get("sha1", "")))
             for f in ordered]
    cards += [(True, _system_file_card(v, consumers, anchored, searchable), str(v.get("sha1", "")))
              for v in sorted(variant_files, key=order)]
    return cards


# A "Start with" line names this many files at most: Game Engines'
# TheXTech requires 2,014.
START_WITH_NAMES = 6


def _region_order() -> dict[str, int]:
    """The regions a start line lists, the territories first. A file read
    for every region is a region-free stand-in for the BIOS of each one:
    the PlayStation section opened on psxonpsp660.bin, which one emulator
    requires among the BIOS it accepts, above the scph files most read."""
    from region import REGION_TREE, WORLD  # noqa: PLC0415

    ordered = []
    for parent, members in REGION_TREE.items():
        ordered += [parent, *sorted(members)]
    ordered.append(WORLD)
    return {region: index for index, region in enumerate(ordered)}


def _reading_pairs(sha1: str, consumers: FileConsumers) -> list[tuple[str, dict]]:
    """The profile entries that read a file, each with its emulator."""
    files_of = getattr(consumers, "emulator_files", {})
    pairs = []
    for emulator, index in sorted(getattr(consumers, "emulator_entries", {}).get(sha1, {}).items()):
        files = files_of.get(emulator) or []
        if 0 <= index < len(files) and isinstance(files[index], dict):
            pairs.append((emulator, files[index]))
    return pairs


def _entry_systems(emulator: str, entry: dict) -> list[str]:
    """The systems an entry is read for: its own `system:` or `systems:`
    (a MAME device set several systems load), else its profile's only one."""
    if entry.get("system") or entry.get("systems"):
        return entry_system_ids(entry, {})
    systems = (_profiles_on_disk().get(emulator) or {}).get("systems") or []
    return [str(systems[0])] if len(systems) == 1 else []


def _emulator_display(emulator: str) -> str:
    return str((_profiles_on_disk().get(emulator) or {}).get("emulator") or emulator)


# id(consumers) -> (consumers, section -> the entries whose system leads there).
_SECTION_ENTRIES: dict[int, tuple[object, dict[tuple[str, str], list]]] = {}


def _entries_by_section(consumers: FileConsumers) -> dict[tuple[str, str], list]:
    """Each console section with the (sha1, emulator, entry, system) whose
    system leads to it, read once per build."""
    from siterender import system_section  # noqa: PLC0415

    cached = _SECTION_ENTRIES.get(id(consumers))
    if cached is not None and cached[0] is consumers:
        return cached[1]
    sections: dict[str, tuple[str, str] | None] = {}
    index: dict[tuple[str, str], list] = {}
    for sha1 in sorted(getattr(consumers, "emulator_entries", {})):
        for emulator, entry in _reading_pairs(sha1, consumers):
            for sys_id in _entry_systems(emulator, entry):
                if sys_id not in sections:
                    sections[sys_id] = system_section(sys_id)
                place = sections[sys_id]
                if place is not None:
                    index.setdefault(place, []).append((sha1, emulator, entry, sys_id))
    _SECTION_ENTRIES.clear()
    _SECTION_ENTRIES[id(consumers)] = (consumers, index)
    return index


def _setup_name(f: dict, consumers: FileConsumers, pairs: list[tuple[str, dict]]) -> str:
    """The name most setups give a file, else most emulators: the collection
    keeps BizHawk's GBA_bios.rom where eight setups write gba_bios.bin."""
    counts: dict[str, int] = {}
    destinations = getattr(consumers, "platform_destinations", {}).get(str(f.get("sha1", "")), {})
    for dests in destinations.values():
        for base in {d.replace("\\", "/").rsplit("/", 1)[-1] for d in dests if d}:
            counts[base] = counts.get(base, 0) + 1
    if not counts:
        for _emulator, entry in pairs:
            if entry.get("name"):
                name = str(entry["name"])
                counts[name] = counts.get(name, 0) + 1
    if not counts:
        return f["name"]
    most = max(counts.values())
    top = sorted((n for n, c in counts.items() if c == most), key=lambda n: (n.casefold(), n))
    return f["name"] if f["name"] in top else top[0]


def _without_files(emulators: list[str]) -> str:
    """Who runs without the files: every emulator reading one, up to three
    by name, more counted, as their order would rank nothing."""
    names = sorted({_emulator_display(e) for e in emulators}, key=str.casefold)
    if len(names) > 3:
        return f": none of its {len(names)} emulators requires one"
    return " with " + (", ".join(names[:-1]) + f" or {names[-1]}" if len(names) > 1 else names[0])


def _visible(name: str) -> str:
    """The file name a start line shows, out of its code span and link."""
    match = re.match(r"\[?`([^`]*)`", name)
    return match[1] if match else name


def _add_name(names: list[str], name: str) -> None:
    """A name once per line: two copies of sfcbox.zip read as one file."""
    if all(_visible(n) != _visible(name) for n in names):
        names.append(name)


class _StartGroup:
    """What one system of a section asks for."""

    def __init__(self) -> None:
        self.by_region: dict[str, list[str]] = {}
        self.plain: list[str] = []
        # Files an emulator reads when present and replaces when absent.
        self.optional: list[str] = []
        self.emulators: list[str] = []
        # Each file an emulator requires, by its visible name, with the
        # emulators requiring it and the name as the line writes it.
        self.requires: dict[str, set[str]] = {}
        self.written: dict[str, str] = {}
        # Visible name -> the sha1 of the file it names.
        self.sha1s: dict[str, str] = {}
        # Emulators that replace a missing file with their own code.
        self.hle: set[str] = set()
        # Files an emulator reads when present and runs the same without.
        self.extra: list[str] = []
        # By line (a region, "" for every region): visible name -> the
        # emulators requiring that file for the line. Three Mega CD BIOS,
        # one per region, share the name cd_bios.rom.
        self.line_readers: dict[str, dict[str, set[str]]] = {}
        # (line, visible name, emulator) -> the name the emulator reads.
        self.read_as: dict[tuple[str, str, str], str] = {}
        # (line, visible name) -> the file name its card shows.
        self.card_names: dict[tuple[str, str], str] = {}
        # (line, visible name) of the files most of whose readers read
        # them beside another one they require.
        self.extras: set[tuple[str, str]] = set()

    def require(self, name: str, emulator: str) -> None:
        self.written.setdefault(_visible(name), name)
        self.requires.setdefault(_visible(name), set()).add(emulator)

    def read_for(self, line: str, name: str, emulator: str, read: str, card: str) -> None:
        """Record that ``emulator`` requires ``name`` for ``line``, under
        the name ``read``, its card titled ``card``."""
        visible = _visible(name)
        self.line_readers.setdefault(line, {}).setdefault(visible, set()).add(emulator)
        self.read_as.setdefault((line, visible, emulator), read)
        self.card_names.setdefault((line, visible), card)

    def absorb(self, other: _StartGroup) -> None:
        for region, names in other.by_region.items():
            for name in names:
                _add_name(self.by_region.setdefault(region, []), name)
        for mine, theirs in ((self.plain, other.plain), (self.optional, other.optional),
                             (self.extra, other.extra), (self.emulators, other.emulators)):
            for name in theirs:
                _add_name(mine, name)
        for visible, emulators in other.requires.items():
            self.written.setdefault(visible, other.written[visible])
            self.requires.setdefault(visible, set()).update(emulators)
        for visible, sha1 in other.sha1s.items():
            self.sha1s.setdefault(visible, sha1)
        self.hle.update(other.hle)
        for line, readers in other.line_readers.items():
            for visible, emulators in readers.items():
                self.line_readers.setdefault(line, {}).setdefault(visible, set()).update(emulators)
        for key, value in other.read_as.items():
            self.read_as.setdefault(key, value)
        for key, value in other.card_names.items():
            self.card_names.setdefault(key, value)
        self.extras |= other.extras

    def requirers(self) -> set[str]:
        return set().union(*self.requires.values()) if self.requires else set()

    def as_read(self, visible: str, emulators: set[str], line: str | None = None) -> str:
        """A file as an emulator reading it instead is told to fetch it:
        by its card's name, with the name it reads when that differs.
        The line read "ares reads neo-epo.sp1" above a card titled
        neo-epo.bin."""
        lines = [line] if line is not None else sorted(self.line_readers)
        for key in lines:
            card = self.card_names.get((key, visible))
            if card is None:
                continue
            reads = {self.read_as[(key, visible, e)] for e in emulators
                     if (key, visible, e) in self.read_as}
            written = self.written.get(visible, _code(card))
            # A linked name (a file under Arcade) keeps its link.
            shown = written if _visible(written) == card else _code(card)
            if len(reads) == 1 and next(iter(reads)) != card:
                return f"{shown} (as {_code(next(iter(reads)))})"
            return shown
        return self.written.get(visible, _code(visible))


def _start_groups(
    files: list[dict], consumers: FileConsumers, section: tuple[str, str] | None
) -> dict[str | None, _StartGroup]:
    """The files of a section an emulator reads, by the system they are
    read for. An entry is the section's when one of its systems leads
    here: the DS section named five DSi files, and the NES one FBNeo's
    YM2608 sample, read for a system with no section of its own. An entry
    that names no system, in a profile of several, reads the section's own
    console. A file the system requires but filed under
    Arcade, where sets serve every machine, is named too, linked to its
    card: the Neo Geo BIOS. One filed under another console is that
    console's, whatever system an emulator files it under (BizHawk reads
    the Mega CD BIOS for its Genesis), and one under Other is a single
    emulator's, its shaders and fonts. A file the emulator ships with is
    no file to fetch."""
    from siterender import _heading_name, _manufacturer_slug, system_name, system_section  # noqa: PLC0415

    here = (_manufacturer_slug(section[0]), section[1]) if section else None
    held = {str(f.get("sha1", "")) for f in files}
    primaries = [f for f in files if "/.variants/" not in f["path"]]
    kept: dict[str, list[tuple[str, dict, str | None]]] = {}
    for f in primaries:
        sha1 = str(f.get("sha1", ""))
        for emulator, entry in _reading_pairs(sha1, consumers):
            if comes_with_app(entry):
                continue
            system = None
            systems = _entry_systems(emulator, entry)
            if here is not None and systems:
                system = next((s for s in systems if system_section(s) == here), None)
                if system is None:
                    continue
            kept.setdefault(sha1, []).append((emulator, entry, system))
    candidates = list(primaries)
    known = (getattr(consumers, "_db", None) or {}).get("files", {})
    if here is not None:
        for sha1, emulator, entry, system in _entries_by_section(consumers).get(here, []):
            record = known.get(sha1)
            parts = str((record or {}).get("path", "")).split("/")
            if (sha1 in held or not record or comes_with_app(entry) or ".variants" in parts
                    or len(parts) < 3 or parts[1] != "Arcade"):
                continue
            if sha1 not in kept:
                candidates.append({**record, "elsewhere": True})
            kept.setdefault(sha1, []).append((emulator, entry, system))

    groups: dict[str | None, _StartGroup] = {}
    ranked = sorted(candidates, key=lambda f: _card_rank(f, consumers))
    rendered: dict[str, str] = {}
    for f in ranked:
        sha1 = str(f.get("sha1", ""))
        pairs = kept.get(sha1, [])
        name = _code(_setup_name(f, consumers, [(e, entry) for e, entry, _s in pairs]))
        if f.get("elsewhere"):
            name = f"[{name}]({markup.site_href(f'files/?sha1={sha1}')})"
        rendered[sha1] = name
    # A member read inside its archive is the archive's to name: FinalBurn
    # Neo reads sfix.sfix inside neogeo.zip, and the line had it read
    # sfix.sfix instead of neogeo.zip.
    archives = {_visible(name): (name, sha1) for sha1, name in reversed(rendered.items())}
    by_name = (getattr(consumers, "_db", None) or {}).get("indexes", {}).get("by_name", {})

    def archive_named(archive: str) -> tuple[str, str]:
        """The archive as the line names it, linked to its card when the
        collection holds one, with that card's sha1."""
        if archive in archives:
            return archives[archive]
        found = by_name.get(archive) or []
        found = [found] if isinstance(found, str) else sorted(found)
        found.sort(key=lambda s: "/.variants/" in str(known.get(s, {}).get("path", "")))
        if not found:
            return _code(archive), ""
        return f"[{_code(archive)}]({markup.site_href(f'files/?sha1={found[0]}')})", ""

    def reading(f: dict) -> Iterator[tuple[str, dict, str | None, str, str]]:
        """Each read of a file: the emulator, its entry, the system, the
        name the line writes and the sha1 of the card it names."""
        sha1 = str(f.get("sha1", ""))
        for emulator, entry, system in kept.get(sha1, []):
            name, named = rendered[sha1], sha1
            if entry.get("archive"):
                name, named = archive_named(str(entry["archive"]))
            yield emulator, entry, system, name, named

    # A file as many of whose readers require another file and read this
    # one only when present is an extra, not a start file: NAOMI opened on
    # hod2bios.zip, which 13 of the 19 emulators listing it read beside
    # naomi.zip for the House of the Dead 2 alone.
    requiring: dict[str, set[str]] = {}
    optional: dict[str, set[str]] = {}
    for f in ranked:
        for emulator, entry, _system, name, named in reading(f):
            if entry.get("hle_fallback"):
                continue
            side = requiring if entry.get("required", True) else optional
            side.setdefault(named or _visible(name), set()).add(emulator)
    needs_other = {emulator: {key for key, emulators in requiring.items() if emulator in emulators}
                   for emulators in requiring.values() for emulator in emulators}
    weak = {key for key, emulators in requiring.items()
            if len(emulators) <= len({e for e in optional.get(key, ())
                                      if needs_other.get(e, set()) - {key}})}

    for f in ranked:
        for emulator, entry, system, name, named in reading(f):
            try:
                key = system_name(system) if system else None
            except KeyError:
                key = None
            group = groups.setdefault(key, _StartGroup())
            if named:
                group.sha1s.setdefault(_visible(name), named)
            if emulator not in group.emulators:
                group.emulators.append(emulator)
            if entry.get("hle_fallback"):
                _add_name(group.optional, name)
                group.hle.add(emulator)
                continue
            if not entry.get("required", True):
                _add_name(group.extra, name)
                continue
            group.require(name, emulator)
            read = str(entry.get("archive") or entry.get("name") or _visible(name))
            card = str(entry["archive"]) if entry.get("archive") else str(f["name"])
            regions = sorted({str(r) for r in entry.get("region") or []})
            for region in regions or [""]:
                _add_name(group.by_region.setdefault(region, []) if region else group.plain, name)
                group.read_for(region, name, emulator, read, card)
                if (named or _visible(name)) in weak:
                    group.extras.add((region, _visible(name)))
    named = [key for key in groups if key is not None]
    if None in groups and named:
        # An entry that names no system reads the section's own console.
        heading = _heading_name(*section) if section else None
        groups[heading if heading in groups else named[0]].absorb(groups.pop(None))
    return groups


def _start_with(
    files: list[dict], consumers: FileConsumers, first_below: bool = True,
    section: tuple[str, str] | None = None,
) -> list[str]:
    """The line a console section opens on: the files an emulator requires,
    by the region the emulator picks each for, and by system when the
    section holds several.

    ``section`` is the (manufacturer, console) the files are under: an
    entry read for another console's system is left to that console.
    Read from the profiles' system, required, hle_fallback and region
    fields, never typed per system. A system most of whose emulators run
    without its files says so, and names the few that require one. A
    section where no emulator reads a file gets no line.
    """
    return _start(files, consumers, first_below, section)[0]


def _start_order(
    files: list[dict], consumers: FileConsumers, section: tuple[str, str] | None = None,
) -> list[str]:
    """The sha1s of the files a section's start line names, in its order:
    the cards come in that order, so "first below" is true."""
    return _start(files, consumers, True, section)[1]


def _start(
    files: list[dict], consumers: FileConsumers, first_below: bool,
    section: tuple[str, str] | None,
) -> tuple[list[str], list[str]]:
    """The start line and the sha1s it names, in order."""
    groups = _start_groups(files, consumers, section)
    sha1s: dict[str, str] = {}
    for group in groups.values():
        for visible, sha1 in group.sha1s.items():
            sha1s.setdefault(visible, sha1)
    held = {str(f.get("sha1", "")) for f in files}
    lines = _lead_file(groups)
    if not lines:
        lines = _group_lines(groups, first_below, held, sha1s,
                             _section_label(*section) if section and section != OTHER_ARCADE else "")
    order: list[str] = []
    for line in lines:
        for visible in re.findall(r"`([^`]*)`", line):
            sha1 = sha1s.get(visible)
            if sha1 and sha1 not in order:
                order.append(sha1)
    return [_link_held_names(line, sha1s, held) for line in lines], order


def _link_held_names(line: str, sha1s: dict[str, str], held: set[str]) -> str:
    """Each file the start line names leads to its card, where it downloads:
    the Apple II line named eight files and none was a way to get one."""
    def link(match: re.Match) -> str:
        sha1 = sha1s.get(match[1], "")
        return f"[{match[0]}](#sha1-{sha1[:12]})" if sha1 in held else match[0]
    # A name inside a link already (a "Keep it zipped" archive) stays as
    # is, and so does the name a file is read under, "(as `d2fdc.zip`)".
    return re.sub(r"(?<!\[)(?<!\(as )`([^`]*)`(?!\]\()", link, line)


def _group_lines(
    groups: dict[str | None, _StartGroup], first_below: bool, held: set[str],
    sha1s: dict[str, str], console: str = "",
) -> list[str]:
    """One block per system, as the section opens on them. ``console`` names
    the section in a line that picks a BIOS by region."""
    keys = sorted(groups, key=lambda k: str(k).casefold())
    blocks: dict[str | None, list[tuple[str, str]]] = {}
    for key in keys:
        block = _group_start(groups[key], first_below and not blocks)
        if block and first_below and not blocks:
            # "First below" holds only when the first file named is a card
            # of this page: the Neo Geo BIOS is filed under Arcade.
            first = re.search(r"`([^`]*)`", block[0][1])
            if first and sha1s.get(first[1]) not in held:
                block = _group_start(groups[key], False)
        if block:
            blocks[key] = block
    if not blocks:
        return []
    if len(blocks) == 1:
        return _start_lines(next(iter(blocks.values())), console)
    if all(lead == "*" for block in blocks.values() for lead, _text in block):
        # No machine of the section needs a file: the SNES said "Start with"
        # over two lines that each said no file is needed.
        lines = ["**No file needed** on any of these machines:", ""]
        lines += [f"- **{key}**: {text.lstrip(': ')}"
                  for key, block in blocks.items() for _lead, text in block]
        return [*lines, ""]
    lines = ["**Start with** the files of the machine:", ""]
    for key, block in blocks.items():
        for lead, text in block:
            if lead == "*":
                lines.append(f"- **{key}**: no file needed{text}")
                continue
            if lead == "+":
                # What the others read instead ends the machine's line.
                end = "" if lines[-1].endswith(".") else "."
                lines[-1] = f"{lines[-1]}{end} {text}"
                continue
            lines.append(f"- **{key}, {lead}**: {text}" if lead else f"- **{key}**: {text}")
    return [*lines, ""]


def _display_names(emulators: set[str] | list[str]) -> list[str]:
    return sorted({_emulator_display(e) for e in emulators}, key=str.casefold)


def _names_counted(names: list[str], most: int = 3, noun: str = "") -> str:
    """Names as "a, b and c", the ones past ``most`` counted: "a, b, c and
    12 more". One past ``most`` is named, not counted as "1 more"."""
    if len(names) > most + 1:
        more = f"{len(names) - most} more" + (f" {noun}" if noun else "")
        return f"{', '.join(names[:most])} and {more}"
    return _said_as_list(names)


def _lead_file(groups: dict[str | None, _StartGroup]) -> list[str]:
    """A section of several systems where most emulators require one file:
    that file first, and the emulators that read another instead. The Neo
    Geo section listed three machines, and neogeo.zip, which 26 emulators
    read, came after a file ares alone reads."""
    if len(groups) < 2:
        return []
    emulators: set[str] = set()
    requires: dict[str, set[str]] = {}
    written: dict[str, str] = {}
    holder: dict[str, _StartGroup] = {}
    for group in groups.values():
        emulators.update(group.emulators)
        for visible, readers in group.requires.items():
            requires.setdefault(visible, set()).update(readers)
            written.setdefault(visible, group.written[visible])
            holder.setdefault(visible, group)
    if not requires:
        return []
    top = max(requires, key=lambda v: len(requires[v]))
    readers = requires[top]
    if 2 * len(readers) <= len(emulators):
        return []
    zipped = " Keep it zipped." if top.casefold().endswith(".zip") else ""
    names = _display_names(readers)
    said = (_names_counted(names, 2, "emulators") if len(names) > 2
            else _said_as_list(names))
    lines = [f"**Start with** {written[top]}.{zipped} {said} read{'s' if len(names) == 1 else ''} it.",
             ""]
    # The emulators that require other files and not this one, by the
    # files they require, each by its card's name.
    others: dict[tuple[str, ...], set[str]] = {}
    for emulator in emulators - readers:
        theirs = tuple(holder[v].as_read(v, {emulator}) for v in requires
                       if emulator in requires[v])
        if theirs:
            others.setdefault(theirs, set()).add(emulator)
    sentences = []
    for files, who in sorted(others.items(), key=lambda item: (-len(item[1]), item[0])):
        names = _display_names(who)
        verb = "reads" if len(names) == 1 else "read"
        sentences.append(f"{_names_counted(names)} {verb} {_said_as_list(list(files))} instead.")
    if sentences:
        lines += [" ".join(sentences), ""]
    return lines


def _group_start(group: _StartGroup, first_below: bool) -> list[tuple[str, str]]:
    """One system's start as (lead, text) pairs. The lead is the regions a
    line is for, "" the files every region needs, "*" the line of a system
    that runs without any file.

    A file is a start file when the emulators requiring it outweigh those
    that run without it. The Game Boy opened on dmg_boot.bin, which Emux
    GB alone of 13 requires, under a home page that says the Game Boy
    needs no BIOS."""
    from region import _PARENT  # noqa: PLC0415

    def listed(names: list[str], below: bool = first_below) -> str:
        if len(names) <= START_WITH_NAMES:
            return ", ".join(names)
        # The first three by rank, the rest counted: "the 9 files" named
        # none, and the Neo Geo BIOS everyone reads is filed under Arcade.
        return f"{', '.join(names[:3])} and {_count(len(names) - 3, 'more file')}" + (
            ", first below" if below else "")

    requirers = group.requirers()
    hle = group.hle - requirers
    running = set(group.emulators) - requirers
    # One that replaces the file with its own code runs, with less
    # accuracy, and counts half: most PlayStation cores have such a
    # fallback, and a reader still starts with the BIOS.
    if requirers and 2 * len(requirers) <= 2 * len(running - hle) + len(hle):
        free = _display_names(running)
        needing = _display_names(requirers)
        names = list(group.written.values())
        verb = "requires" if len(needing) == 1 else "require"
        if all(len(readers) == len(requirers) for readers in group.requires.values()):
            return [("*", f" with {_names_counted(free)}. Only {_names_counted(needing)} {verb} "
                          f"{listed(names, False)}.")]
        # Each requires some of the files: "bsnes, FinalBurn Neo and 3
        # more require 22 files" read as 22 files for a bsnes user.
        these = f"these {len(names)} files" if len(names) > START_WITH_NAMES else "these files"
        return [("*", f" with {_names_counted(free)}. Only {_names_counted(needing)} {verb} "
                      f"some of {these}: {listed(names, False)}.")]

    def instead_of(line: str, names: list[str], answered: set[str]) -> str:
        """What the emulators no other name answers read instead, one
        sentence per set of files: "FinalBurn Neo reads fdsbios.zip instead"."""
        readers = group.line_readers.get(line, {})
        others: dict[tuple[str, ...], set[str]] = {}
        for emulator in sorted(set().union(*(readers.get(_visible(n), set()) for n in names))
                               - answered):
            theirs = tuple(group.as_read(_visible(n), {emulator}, line) for n in names
                           if emulator in readers.get(_visible(n), set()))
            others.setdefault(theirs, set()).add(emulator)
        sentences = []
        for files, who in sorted(others.items(), key=lambda item: (-len(item[1]), item[0])):
            shown = _display_names(who)
            verb = "reads" if len(shown) == 1 else "read"
            sentences.append(f"{_names_counted(shown)} {verb} {_said_as_list(list(files))} instead.")
        return " ".join(sentences)

    def split(line: str, names: list[str]) -> tuple[list[str], str, set[str]]:
        """A line's names as the files to start with, the sentence naming
        what other emulators read instead, and every emulator the line
        answers. Names no emulator requires beside another are other names
        for one slot: "fdsbios.zip, disksys.rom" read as two files to get."""
        readers = group.line_readers.get(line, {})
        sets = {n: readers.get(_visible(n), set()) for n in names}
        lead = max(names, key=lambda n: len(sets[n]))
        main = [n for n in names if n == lead or sets[n] <= sets[lead]]
        rest = [n for n in names if n not in main]
        # A file the lead's readers require beside it is a start file too,
        # unless most of its readers take it as an extra.
        main = [n for n in main if n == lead or (line, _visible(n)) not in group.extras]
        return main, instead_of(line, rest, set(sets[lead])), set().union(*sets.values())

    order = _region_order()
    # A territory its region answers the same way adds nothing: Brazil
    # under Latin America.
    by_region = {r: names for r, names in group.by_region.items()
                 if group.by_region.get(_PARENT.get(r, "")) != names}
    # Regions that need the same files share a line.
    regional: dict[tuple[str, ...], str] = {}
    answered: set[str] = set()
    shown: set[str] = set()
    for region in sorted(by_region, key=lambda r: (order.get(r, len(order)), r)):
        main, sentence, readers = split(region, by_region[region])
        answered |= readers
        shown |= {_visible(n) for n in by_region[region]}
        text = f"{listed(main)}. {sentence}" if sentence else listed(main)
        same = next((rs for rs, held in regional.items() if held == text), None)
        if same is None:
            regional[(region,)] = text
        else:
            regional[(*same, region)] = regional.pop(same)

    out = [(", ".join(_region_words(r) for r in regions), regional[regions])
           for regions in sorted(regional, key=lambda rs: (order.get(rs[0], len(order)), rs))]
    # A name a region line gives already is no "also", and one only
    # emulators no region line answers reads is an "instead": armsx1 reads
    # scph1001.bin where the others pick a BIOS by region.
    plain = [n for n in group.plain if _visible(n) not in shown]
    if plain and out:
        readers = group.line_readers.get("", {})
        also = [n for n in plain if readers.get(_visible(n), set()) & answered]
        if also:
            out.append(("", listed(also)))
        sentence = instead_of("", [n for n in plain if n not in also], answered)
        if sentence:
            out.append(("+", sentence))
    elif plain:
        main, sentence, _readers = split("", plain)
        out.append(("", listed(main)))
        if sentence:
            out.append(("+", sentence))
    if not out and group.optional:
        out.append(("*", f"{_without_files(group.emulators)}. "
                         f"For full accuracy: {listed(group.optional)}."))
    elif not out and group.extra:
        # The Mega Drive's emulators read the TMSS BIOS when it is there:
        # the section said nothing under a home page saying none is needed.
        out.append(("*", f"{_without_files(group.emulators)}. "
                         f"Optional: {listed(group.extra, False)}."))
    return out


def _start_lines(block: list[tuple[str, str]], console: str = "") -> list[str]:
    """One system's start, as the lines its section opens on. A BIOS picked
    by region is named with its console: "playstation bios" found the
    PlayStation 2 page first, its file names holding "BIOS" and the
    PlayStation page's text never saying "PlayStation BIOS"."""
    lead, text = block[0]
    if lead == "*":
        return [f"**No file needed**{text}", ""]
    # What the emulators no line answers read instead, after the lines.
    instead = " ".join(text for lead, text in block if lead == "+")
    block = [(lead, text) for lead, text in block if lead != "+"]
    if len(block) == 1 and block[0][0] == "":
        named, _sep, _where = block[0][1].partition(", first below")
        below = " They come first below." if _sep else ""
        return [" ".join(filter(None, [f"**Start with**: {named}.{below}", instead])), ""]
    bios = f"the {console} BIOS" if console else "the BIOS"
    lines = [f"**Start with** {bios} for the region of the games:", ""]
    for lead, text in block:
        lines.append(f"- **{lead or 'Some emulators also require'}**: {text}")
    if instead:
        lines += ["", instead]
    return [*lines, ""]


def _cards_markdown(cards: list[Card]) -> list[str]:
    """Primaries, then the variants in a closed block."""
    lines = [line for variant, card, _sha1 in cards if not variant for line in card]
    variants = [card for variant, card, _sha1 in cards if variant]
    if variants:
        # A variant gets the same card as a primary: the revision a
        # platform pins is the one a reader comes to find, and showed as
        # a name and a truncated MD5, nothing said who pins it.
        lines.extend(markup.details(
            "note", f"Variants ({len(variants)})", [line for card in variants for line in card]))
    return lines


def _parts(cards: list[_Item], budget: int,
           sizes: list[int] | None = None) -> list[list[_Item]]:
    """Cards in runs of at most ``budget`` bytes of Markdown, in order.
    ``sizes`` gives each card's weight when it is not its own Markdown,
    and is required for items other than cards."""
    parts: list[list[_Item]] = [[]]
    size = 0
    for index, card in enumerate(cards):
        weight = sizes[index] if sizes else sum(len(line) + 1 for line in card[1])
        if parts[-1] and size + weight > budget:
            parts.append([])
            size = 0
        parts[-1].append(card)
        size += weight
    return parts


def _console_heading(manufacturer: str, console: str, label: str = "") -> str:
    """A console's heading, its name alone. An icon on 79 of 544 headings
    read as missing art on the rest, set the text at two positions on one
    page and faded out on one theme or the other. ``label`` is the text
    when it differs from the folder, the id staying the folder's."""
    return f"## {label or console} {{ #{console_anchor(manufacturer, console)} }}"


def _romset_note(consoles: dict[str, list]) -> list[str]:
    """The line a page of MAME or FBNeo sets carries: an arcade player
    looking for the version found the answer only under Reference."""
    releases = _romset_releases()
    if not any(str(f.get("name", "")) in releases for files in consoles.values() for f in files):
        return []
    return ["MAME and FBNeo sets must match the emulator's version. "
            f"[Which version each core reads]({ROMSET_FAQ}).", ""]


_NEXT_FROM_SYSTEMS = [
    "[Get the files](../which-pack.md), for the setup in use",
    "[When a game does not start](../wiki/troubleshooting.md)",
    "[Every emulator](../emulators/index.md), and the files each one reads",
]

# The arcade boards the system pages give a section, by the console key
# their section goes by (the board's name) -> the board's system id. Set by
# arcade_board_sections() before the first system page is written.
_BOARD_CONSOLES: dict[str, str] = {}
# The Arcade folder of files no board claims: the folder is named after
# its maker, which said nothing about what it holds.
OTHER_ARCADE = ("Arcade", "Arcade")
OTHER_ARCADE_LABEL = "Other arcade files"
# (manufacturer, console) -> the boards whose sets left that folder's
# section for the boards' own pages. The section names them.
_BOARDS_FROM: dict[tuple[str, str], set[str]] = {}
# System pages published under an address no page holds since, and where
# their files went: the Atom and the MZ were boards, ScummVM's and SDLPAL's
# files were on two pages, the Dreamcast lost its NAOMI sets. An address
# redirects only while no page takes it back (sitestarlight.redirects).
SYSTEM_PAGES_MOVED = {
    "systems/arcade-acorn-atom.md": "systems/acorn.md",
    "systems/arcade-sharp-mz-2000.md": "systems/sharp.md",
    "systems/arcade-sharp-mz-2500.md": "systems/sharp.md",
    "systems/arcade-miuchiz.md": "systems/arcade.md",
    "systems/arcade-yamaha-ym2608.md": "systems/arcade.md",
    # Oric is filed under its maker since 2026-10-23, and a reader still
    # followed the old address to the 404 page.
    "systems/oric.md": "systems/tangerine.md#oric",
    "systems/other-scummvm.md": "systems/scummvm.md",
    "systems/other-sdlpal.md": "systems/sdlpal.md",
    "systems/sega-dreamcast.md": "systems/sega.md",
}


def arcade_board_sections(
    manufacturers: dict[str, dict[str, list]],
    installs: dict[str, dict[str, list[tuple[str, str]]]],
) -> tuple[dict[str, dict[str, list]], dict[str, dict[str, list[tuple[str, str]]]]]:
    """The Arcade page grouped by board, and each board's install commands.

    The Arcade sections were the folders of bios/Arcade/: NAOMI, PGM and
    ZN-1 had no section, and their names stayed plain on 568 emulator
    pages. Each archive goes to the board siterender.arcade_board() reads
    from the profiles, never from its folder, and a folder named after a
    board (Namco System 246) joins it, whatever maker's folder holds the
    copy. A set a reviewed machine owns (siterender.archive_machine) goes
    to that machine's section. Files neither claims stay in their
    folders. Each board is recorded (siterender.record_board_section) before
    any page links one, and a system's install commands follow its link to
    the board's section. Call after reset_console_pages()."""
    from siterender import (  # noqa: PLC0415
        arcade_board,
        arcade_boards,
        archive_machine,
        record_board_section,
        record_card_move,
        system_section,
    )

    _BOARD_CONSOLES.clear()
    _BOARDS_FROM.clear()
    arcade = manufacturers.get("Arcade")
    if not arcade:
        return manufacturers, installs
    names = arcade_boards()
    by_name = {name.casefold(): board for board, name in names.items()}
    boards: dict[str, list] = {}
    folders: dict[str, list] = {}
    seen: dict[str, set[str]] = {}
    # The sets a reviewed machine owns go to its section: neogeo.zip sat on
    # five Arcade pages, the Atom's and the MZ-2000's sets on board pages.
    machines: dict[tuple[str, str], list] = {}

    def file_on_board(board: str, f: dict) -> None:
        # One card per content: a copy under Arcade and one under MAME
        # are the same file.
        if str(f.get("sha1", "")) in seen.setdefault(board, set()):
            return
        seen[board].add(str(f.get("sha1", "")))
        boards.setdefault(board, []).append(f)

    for console in sorted(arcade):
        joined = by_name.get(console.casefold())
        for f in arcade[console]:
            sha1 = str(f.get("sha1", ""))
            board = joined or arcade_board(sha1)
            machine = None if board else archive_machine(sha1)
            if board is not None:
                file_on_board(board, f)
            elif machine is not None:
                machines.setdefault(machine, []).append(f)
                record_card_move("Arcade", console, sha1, *machine)
            else:
                folders.setdefault(console, []).append(f)
    # A board's set filed under a machine's folder is on the board's page
    # too, whatever the folder: naomi.zip under the Dreamcast was the copy
    # five setups list, and the NAOMI page did not name it.
    makers: dict[str, dict[str, list]] = {}
    for mfr, consoles in manufacturers.items():
        if mfr == "Arcade":
            continue
        for console, files in consoles.items():
            kept = []
            for f in files:
                sha1 = str(f.get("sha1", ""))
                board = arcade_board(sha1)
                machine = None if board else archive_machine(sha1)
                if board is not None:
                    file_on_board(board, f)
                    _BOARDS_FROM.setdefault((mfr, console), set()).add(board)
                elif machine is not None and machine != (mfr, console):
                    # The Atom's own set sat with the BBC Micro.
                    machines.setdefault(machine, []).append(f)
                    record_card_move(mfr, console, sha1, *machine)
                else:
                    kept.append(f)
            if len(kept) != len(files):
                makers.setdefault(mfr, dict(consoles))[console] = kept
    for (mfr, console), files in sorted(machines.items()):
        consoles = makers.setdefault(mfr, dict(manufacturers.get(mfr, {})))
        held = {str(f.get("sha1", "")) for f in consoles.get(console, [])}
        consoles[console] = [*consoles.get(console, []),
                             *(f for f in files if str(f.get("sha1", "")) not in held)]
    for board in sorted(boards):
        record_board_section(board)
        _BOARD_CONSOLES[names[board]] = board
    regrouped = {**folders, **{names[board]: files for board, files in boards.items()}}
    makers = {mfr: {console: files for console, files in consoles.items() if files}
              for mfr, consoles in makers.items()}

    moved: dict[str, dict[str, list[tuple[str, str]]]] = {}
    for slug, consoles in installs.items():
        for console, pairs in consoles.items():
            for platform, sys_id in pairs:
                section = system_section(sys_id)
                if section and section[0] == "arcade" and section[1] in _BOARD_CONSOLES:
                    slug_to, console_to = section
                else:
                    slug_to, console_to = slug, console
                moved.setdefault(slug_to, {}).setdefault(console_to, []).append((platform, sys_id))
    return {**manufacturers, **makers, "Arcade": regrouped}, moved


def _boards_line(manufacturer: str, console: str) -> list[str]:
    """The line of a section whose board sets went to the boards' pages:
    the Dreamcast folder holds NAOMI's and Atomiswave's."""
    from siterender import arcade_boards  # noqa: PLC0415

    boards = _BOARDS_FROM.get((manufacturer, console))
    if not boards:
        return []
    names = arcade_boards()
    links = [f"[{names[board]}]({console_href('arcade', names[board]).removeprefix('systems/')})"
             for board in sorted(boards, key=lambda b: names[b].casefold())]
    return [f"**Arcade board BIOS** on the boards' own pages: {', '.join(links)}.", ""]


def _section_label(manufacturer: str, console: str) -> str:
    """The heading a section shows."""
    if (manufacturer, console) == OTHER_ARCADE:
        return OTHER_ARCADE_LABEL
    return SECTION_LABELS.get((manufacturer, console), console)


def _part_name(manufacturer: str, console: str) -> str:
    """What a part's title calls the files: "Arcade files a to b"."""
    if (manufacturer, console) == OTHER_ARCADE:
        return "Arcade"
    return SECTION_LABELS.get((manufacturer, console), console)


def _system_front_matter(
    parent: tuple[str, str] | None = None,
    prev: tuple[str, str] | None = None,
    following: tuple[str, str] | None = None,
    weight: float | None = None,
    consoles: list[str] | None = None,
) -> list[str]:
    """The front matter of a system page: the page it belongs to, the
    parts before and after it (label, site path), its search weight and
    the consoles it holds, which the search reads as a field."""
    lines = _parent_front_matter(parent)
    for key, link in (("prev", prev), ("next", following)):
        if link:
            lines += [f"{key}:", f"  label: {json.dumps(link[0])}", f"  link: {json.dumps(link[1])}"]
    if weight is not None:
        lines.append(f"searchWeight: {weight}")
    if consoles:
        lines += ["consoles:", *(f"  - {json.dumps(name)}" for name in consoles)]
    return ["---", *lines, "---", ""] if lines else []


def _part_weight() -> float:
    """The search weight of a part page: its cards keep their own weight."""
    return SEARCH_WEIGHT.get("part", DEMOTED_WEIGHT)


@functools.lru_cache(maxsize=None)
def _manifest_systems(platform: str) -> frozenset[str]:
    """The system ids a platform's install manifest records: --system
    refuses any other."""
    manifest = _REPO_ROOT / "install" / f"{platform}.json"
    if not manifest.is_file():
        return frozenset()
    document = json.loads(manifest.read_text(encoding="utf-8"))
    return frozenset(
        str(system)
        for entry in (document.get("files") or []) + (document.get("omitted_files") or [])
        for system in entry.get("systems") or []
    )


def _install_pairs(
    declared: list[tuple[str, str]], lead: str | None, consumers: FileConsumers,
) -> list[tuple[str, str]]:
    """A section's install commands: the setups whose system leads here,
    then each setup that files the section's first file under a system of
    its own (RetroArch files neogeo.zip under arcade), with that id."""
    pairs = list(declared)
    have = {platform for platform, _system in pairs}
    for platform, systems in sorted(getattr(consumers, "platform_systems", {})
                                    .get(lead or "", {}).items()):
        if platform in have:
            continue
        recorded = [s for s in sorted(systems) if s in _manifest_systems(platform)]
        if recorded:
            pairs.append((platform, recorded[0]))
            have.add(platform)
    return sorted(pairs, key=lambda pair: (_platform_display(pair[0]).casefold(), pair[1]))


def system_pages(
    manufacturer: str,
    consoles: dict[str, list],
    consumers: FileConsumers,
    installs: dict[str, list[tuple[str, str]]] | None = None,
    budget: int = SYSTEM_PAGE_BUDGET,
) -> dict[str, tuple[str, dict[str, list]]]:
    """A manufacturer's pages by stem under systems/: one page, or a summary
    and a page per console when the whole would pass ``budget``. Each page
    comes with the files whose cards it holds, by console.

    Every console keeps its heading on the summary, so a link to
    systems/<maker>/#<console> still lands, and site.js sends a card
    anchor the page no longer holds to the card's new place. The pages
    each card and console went to are recorded for every other link
    (siterender.record_console_pages). An arcade board has a page of its
    own, systems/arcade-<board slug>/, under a heading of that id.
    """
    from siterender import board_slug  # noqa: PLC0415

    slug = _slug(manufacturer)
    installs = installs or {}
    boards = {console: _BOARD_CONSOLES[console] for console in consoles
              if manufacturer == "Arcade" and console in _BOARD_CONSOLES}
    json_next = (f"[Every hash of these files, as JSON](../api/v1/systems/"
                 f"{urllib.parse.quote(slug)}.json)")
    # Boards first on the Arcade page, then the folders of sets for many
    # machines. Such a folder starts nowhere: its line named konamigv.zip,
    # sys573.zip and 97 more, files of boards with lines of their own.
    ordered = sorted(consoles, key=lambda c: (bool(boards) and c not in boards, c))

    def start_of(console: str, first_below: bool = True) -> list[str]:
        if boards and console not in boards:
            return []
        return [*_start_with(consoles[console], consumers, first_below, (manufacturer, console)),
                *_boards_line(manufacturer, console)]

    starts = {console: [] if boards and console not in boards
              else _start_order(consoles[console], consumers, (manufacturer, console))
              for console in consoles}

    def cards_of(console: str, anchors: set[str], by_name: bool = False) -> list[Card]:
        return _console_cards(manufacturer, consoles[console], consumers, anchors,
                              by_name, starts[console])

    def install_block(console: str) -> list[str]:
        lead = starts[console][0] if starts[console] else None
        return _console_install_block(
            _section_label(manufacturer, console),
            _install_pairs(installs.get(console, []), lead, consumers))

    def all_sections() -> dict[str, list[Card]]:
        anchors: set[str] = set()
        return {console: cards_of(console, anchors) for console in ordered}

    # One line, then the legend closed: four paragraphs said the same on
    # every maker's page before its first console.
    intro = f"Every BIOS file for {manufacturer} machines, one card per file."
    legend = search_excluded(markup.details("note", "How to read a card", [
        "A card gives the file's fingerprints, the emulators that read it, the setups "
        "that list it and where to download it. A file can have several versions, one "
        "per region or revision: the main one comes first, the others under "
        "\"Variants\". To install the files of one console, open its \"Install\" box.",
        "",
        "**On the setup's list** names the setups whose own BIOS list has the file, by "
        "the name each gives it. **Packed for its emulators by** names the setups whose "
        "pack adds it because one of their emulators reads it.",
    ]))
    # The consoles a page answers for, a search field: machines only. An
    # emulator's folder under Other put that page first for "dolphin", and
    # a console with a page of its own is that page's to answer for.
    machines = [console for console in ordered
                if manufacturer not in ("Other", *GAME_DATA_TOPS)
                and (manufacturer != "Arcade" or console in boards)]

    def consoles_front(kept: set[str] | None = None) -> list[str]:
        return _system_front_matter(consoles=[
            _section_label(manufacturer, c) for c in machines if kept is None or c in kept])

    front = consoles_front()

    def whole_page(sections: dict[str, list[Card]]) -> str:
        lines = [
            *front, f"# {manufacturer}", "", intro, "", *legend, *_romset_note(consoles),
            *_icon_symbol(),
        ]
        for console, cards in sections.items():
            lines.append(_console_heading(manufacturer, console,
                                          _section_label(manufacturer, console)))
            lines.append("")
            lines.extend(start_of(console))
            lines.extend(install_block(console))
            lines.extend(_cards_markdown(cards))
            lines.append("")
        lines.extend(_next_block([*_NEXT_FROM_SYSTEMS, json_next]))
        lines.extend(["", _date_line()])
        return "\n".join(lines) + "\n"

    def card_weight(card: list[str]) -> int:
        return sum(len(line) + 1 for line in card)

    # Sizes are those of the MkDocs Markdown the budget was set on, so the
    # pages split where they always have and no card changes address.
    with markup.using("mkdocs"):
        measured = all_sections()
        measured_text = whole_page(measured)
    weights = {
        console: sum(card_weight(card) for _variant, card, _sha1 in cards)
        for console, cards in measured.items()
    }
    # An install box is a few lines of Markdown and about nine times that
    # once highlighted: ten of them were 295 KB of the 583 KB Nintendo
    # page, which the card weights never counted. A page is also cut when
    # its estimate as it renders passes the summary's.
    with markup.using("mkdocs"):
        boxes = {console: _install_box_weight(install_block(console)) for console in consoles}
    rendered = {console: CARD_HTML_RATIO * weights[console] + INSTALL_HTML_RATIO * boxes[console]
                for console in weights}
    if (not boards and manufacturer not in CONSOLE_PAGES and len(measured_text) <= budget
            and sum(rendered.values()) <= SYSTEM_SUMMARY_HTML):
        text = whole_page(all_sections()) if markup.starlight() else measured_text
        return {slug: (text, consoles)}

    # Every board has a page of its own. Then the heaviest sections move
    # to pages of their own until what stays on the manufacturer's page is
    # half the budget: a section of one file keeps its place, and a reader
    # does not open 91 pages to browse Other.
    moved: set[str] = set(boards) | (set(consoles) if manufacturer in CONSOLE_PAGES else set())
    for console in sorted(weights, key=lambda c: (-weights[c], c)):
        if sum(w for c, w in weights.items() if c not in moved) <= budget // 2:
            break
        moved.add(console)
    # Then until what stays holds its estimate as it renders.
    for console in sorted(rendered, key=lambda c: (-rendered[c], c)):
        if sum(w for c, w in rendered.items() if c not in moved) <= SYSTEM_SUMMARY_HTML:
            break
        moved.add(console)

    pages: dict[str, tuple[str, dict[str, list]]] = {}
    summary = [
        *consoles_front(set(consoles) - moved), f"# {manufacturer}", "", intro, "", *legend,
        *_romset_note(consoles),
        *_icon_symbol(),
    ]
    summary_anchors: set[str] = set()
    parent = (manufacturer, f"/systems/{slug}/")
    for console in ordered:
        label = _section_label(manufacturer, console)
        summary.append(_console_heading(manufacturer, console, label))
        summary.append("")
        if console not in moved:
            summary.extend(start_of(console))
            summary.extend(install_block(console))
            summary.extend(_cards_markdown(cards_of(console, summary_anchors)))
            summary.append("")
            continue
        # Cards are rendered again for their own page: the anchors a page
        # holds are its own.
        def cut(by_name: bool) -> list[list[Card]]:
            cards = cards_of(console, set(), by_name)
            with markup.using("mkdocs"):
                sizes = [card_weight(card) for _variant, card, _sha1 in cards_of(
                    console, set(), by_name)]
            parts = _parts(cards, budget, sizes)
            if len(parts) < 2:
                return parts
            # Even parts: cut at budget, the PlayStation 2 was 137 cards
            # and 4. The same number of parts, each near the mean.
            share = -(-sum(sizes) // len(parts))
            even = _parts(cards, share, sizes)
            while len(even) > len(parts):
                share += max(1, share // 50)
                even = _parts(cards, share, sizes)
            return even

        # One page keeps the required files first. Parts are named by their
        # first and last file, so a console cut in parts goes by name, the
        # files the start line names first.
        parts = cut(False)
        if len(parts) > 1:
            parts = cut(True)
        board = boards.get(console)
        base = (f"arcade-{board_slug(board)}" if board
                else f"{slug}-{_slugify_anchor(console) or 'files'}")
        stems = [base if index == 0 else f"{base}-{index + 1}" for index in range(len(parts))]
        clash = set(stems) & set(pages)
        if clash:
            raise RuntimeError(f"two system sections take one page: {sorted(clash)}")
        record_console_pages(slug, console, stems, [
            [sha1 for _variant, _card, sha1 in part] for part in parts
        ])
        lead = set(starts[console])
        # A part by the files it holds: "Arcade: Arcade, part 3 of 5" said
        # nothing a search result could use. A folder under Other goes by
        # its emulator's name: "mame files" named the folder.
        named = _folder_emulator(console)[0] if manufacturer == "Other" else None
        titles = ([f"{manufacturer}: {named or label}"] if len(stems) == 1 else [
            "{} files {} to {}".format(named or _part_name(manufacturer, console),
                                       *_part_ends(part, lead))
            for part in parts])
        count = _count(len(consoles[console]), "file")
        summary.extend(start_of(console, False))
        if len(stems) == 1:
            own = "its" if len(consoles[console]) == 1 else "their"
            summary.append(f"{count}, on [{own} own page]({stems[0]}.md).")
        else:
            summary.append(f"{count}, on {len(stems)} pages by file name:")
            summary.append("")
            for index, (stem, part) in enumerate(zip(stems, parts)):
                summary.append(f"- [Part {index + 1}]({stem}.md): {_part_range(part, lead)}")
        summary.append("")
        for index, (stem, part) in enumerate(zip(stems, parts)):
            neighbours = [(titles[i], f"/systems/{stems[i]}/")
                          for i in (index - 1, index + 1) if 0 <= i < len(stems)]
            lines = [
                *_system_front_matter(
                    parent,
                    prev=neighbours[0] if index > 0 else None,
                    following=neighbours[-1] if index + 1 < len(stems) else None,
                    weight=_part_weight() if len(stems) > 1 else None,
                    consoles=[label] if index == 0 and console in machines else None),
                # The crumbs end on the maker's page: no line says it again.
                f"# {titles[index]}", "", *_icon_symbol(),
            ]
            if len(stems) > 1:
                others = ", ".join(
                    f"[part {i + 1}]({other}.md)" for i, other in enumerate(stems) if i != index)
                lines.extend([f"This part holds {_part_range(part, lead)}. The others: {others}.",
                              ""])
            # A board's page is its one section: its title names it, and a
            # heading of the same name said it a third time. Its cards come
            # under "Files", as every page of one console's.
            if index == 0:
                lines.extend(start_of(console, len(stems) == 1))
            lines.extend(legend)
            lines.extend(_romset_note({console: consoles[console]}))
            lines.extend(install_block(console))
            lines.extend(["## Files", ""])
            lines.extend(_cards_markdown(part))
            lines.append("")
            lines.extend(_next_block([f"[{manufacturer}]({slug}.md), every section"]
                                     + _NEXT_FROM_SYSTEMS + [json_next]))
            lines.extend(["", _date_line()])
            held = {sha1 for _variant, _card, sha1 in part}
            pages[stem] = ("\n".join(lines) + "\n", {console: [
                f for f in consoles[console] if str(f.get("sha1", "")) in held]})
    summary.extend(_next_block([*_NEXT_FROM_SYSTEMS, json_next]))
    summary.extend(["", _date_line()])
    kept = {console: files for console, files in consoles.items() if console not in moved}
    return {slug: ("\n".join(summary) + "\n", kept), **pages}


def _part_ends(part: list[Card], lead: set[str] | frozenset[str] = frozenset()) -> tuple[str, str]:
    """The first and last file names of a part, as the cards show them.
    The files a start line puts first are left out when the part holds
    others: the range is the run by name that follows them."""
    named = [card for card in part if card[2] not in lead] or part
    names = []
    for _variant, card, _sha1 in named:
        # An HTML heading on the site, a Markdown one in the size yardstick.
        match = re.search(r"`([^`]*)`|<code>(.*?)</code>", card[2])
        names.append(match[1] if match[1] is not None else html.unescape(match[2]))
    return names[0], names[-1]


def _part_range(part: list[Card], lead: set[str] | frozenset[str] = frozenset()) -> str:
    """The first and last file names of a part, with its count."""
    first, last = _part_ends(part, lead)
    if len(part) == 1:
        return f"`{first}`"
    return f"{_count(len(part), 'file')}, `{first}` to `{last}`"


def generate_system_page(
    manufacturer: str,
    consoles: dict[str, list],
    consumers: FileConsumers,
    installs: dict[str, list[tuple[str, str]]] | None = None,
) -> str:
    """One manufacturer's page, a section per console.

    ``installs`` gives, per console, the (platform, system id) pairs whose
    install command the section offers. A page over the budget is the
    summary system_pages writes, its consoles on pages of their own.
    """
    return system_pages(manufacturer, consoles, consumers, installs)[_slug(manufacturer)][0]


# Emulator pages


def _named_system_link(sys_id: str, prefix: str = "") -> str:
    """A system by its display name, linked where _system_link links it.

    The emulator pages printed the id ("sony-playstation") where every
    other page says "Sony PlayStation". The id stays in the address only.
    """
    from siterender import system_section  # noqa: PLC0415

    name = system_name(sys_id).replace("[", r"\[").replace("]", r"\]")
    section = system_section(sys_id)
    if not section:
        return name
    slug, console = section
    return f"[{name}]({console_href(slug, console, prefix)})"


def _distinct_spellings(names: list) -> list[str]:
    """Names as a reader tells them apart: one per spelling, ignoring case.

    DuckStation's cores list `Duckstation` for EmuELEC, whose launch name is
    spelled so, and the page read "duckstation, Duckstation". The profile
    keeps both, the core lookup being case-sensitive.
    """
    seen: dict[str, str] = {}
    for name in map(str, names):
        seen.setdefault(name.casefold(), name)
    return list(seen.values())


# Region slugs whose words are not the slug title-cased, beyond region.LABELS.
_REGION_WORDS = {"world": "every region"}


def _region_words(value: object, most: int = 0) -> str:
    """A region: value in words. ``most`` caps the regions named, the rest
    counted: one Saturn BIOS serves seven."""
    raw = value if isinstance(value, list) else [value] if value else []
    from region import label  # noqa: PLC0415

    words = [_REGION_WORDS.get(str(r)) or label(str(r)) for r in raw]
    if most and len(words) > most:
        words = words[:most] + [f"{len(words) - most} more"]
    return _said_as_list(words)


_CATEGORY_WORDS = {"bios": "BIOS", "game_data": "game data", "bios_zip": "BIOS ZIP"}


INITIAL_DIGITS = "0 to 9"


def emulator_initial(display: str) -> str:
    """The letter an emulator is filed under, in the navigation and on the
    index alike. A name that does not open on a letter goes under "0 to 9"."""
    initial = display[:1].upper()
    return initial if "A" <= initial <= "Z" else INITIAL_DIGITS


def generate_emulators_index(profiles: dict) -> str:
    unique = {
        k: v for k, v in profiles.items()
        if v.get("type") != "alias" and v.get("role") != "test"
    }
    aliases = {k: v for k, v in profiles.items() if v.get("type") == "alias"}

    by_class: dict[str, list[tuple[str, dict]]] = {}
    for name in sorted(unique.keys()):
        p = unique[name]
        cls = p.get("core_classification", "other")
        by_class.setdefault(cls, []).append((name, p))

    total_files = sum(len(p.get("files", [])) for p in unique.values())

    lines = [
        "# Emulators",
        "",
        "Each page is one emulator: the files it reads, whether it starts games "
        "without them, and the line of its source code that says so. The "
        "kind says how a core relates to the emulator it comes from, which "
        "tells how far its own files can differ.",
        "",
        f"**{len(unique):,}** emulator profiles, **{total_files:,}** files total, **{len(aliases):,}** aliases.",
        "",
        "| Kind | Count | Description |",
        "|------|-------|-------------|",
    ]

    cls_desc = {
        "official_port": "The same authors keep the app and the RetroArch core",
        "community_fork": "Ported to RetroArch by someone else",
        "pure_libretro": "Built for RetroArch, no app of its own",
        "game_engine": "Game engine reimplementation",
        "enhanced_fork": "Fork with added features",
        "frozen_snapshot": "Frozen at an old version",
        "embedded_hle": "Needs no BIOS file: the emulator carries its own",
        "launcher": "Launches an external emulator",
        "other": "Unclassified",
    }

    cls_order = [
        "official_port",
        "community_fork",
        "pure_libretro",
        "game_engine",
        "enhanced_fork",
        "frozen_snapshot",
        "embedded_hle",
        "launcher",
        "other",
    ]

    for cls in cls_order:
        entries = by_class.get(cls, [])
        if not entries:
            continue
        label = CLS_LABELS.get(cls, cls)
        desc = cls_desc.get(cls, "")
        lines.append(f"| {label} | {len(entries)} | {desc} |")
    lines.append("")

    # One section per initial, the groups the navigation draws: its letter
    # links land on the section of the same name.
    by_initial: dict[str, list[tuple[str, dict]]] = {}
    for name, p in unique.items():
        by_initial.setdefault(emulator_initial(str(p.get("emulator", name))), []).append((name, p))
    for initial in sorted(by_initial, key=lambda g: (g != INITIAL_DIGITS, g)):
        lines.extend([
            f"## {initial}",
            "",
            "| Emulator | Kind | Systems | Files |",
            "|--------|------|---------|-------|",
        ])
        entries = sorted(by_initial[initial], key=lambda e: str(e[1].get("emulator", e[0])).casefold())
        for name, p in entries:
            emu_name = p.get("emulator", name)
            cls = p.get("core_classification", "other")
            systems = list(dict.fromkeys(
                _named_system_link(s, "../") for s in p.get("systems") or []))
            files = p.get("files", [])
            sys_str = ", ".join(systems[:3])
            if len(systems) > 3:
                sys_str += f" and {len(systems) - 3} more"
            file_count = len(files)
            file_str = f"{file_count:,}" if file_count else "-"
            lines.append(f"| [{emu_name}]({name}.md) | {CLS_LABEL_ONE.get(cls, cls)} | {sys_str} | {file_str} |")
        lines.append("")

    if aliases:
        lines.extend(["## Aliases", ""])
        lines.append("| Core | Points to |")
        lines.append("|------|-----------|")
        for name in sorted(aliases.keys()):
            parent = aliases[name].get(
                "alias_of", aliases[name].get("bios_identical_to", "unknown")
            )
            lines.append(f"| {name} | [{parent}]({parent}.md) |")
        lines.append("")

    return "\n".join(lines) + "\n"


def _snippet_noun(names: Iterable[str], firmware: int, fetched: int) -> str:
    """What an emulator's files are called in its snippet. A Switch
    emulator reads keys, and "eden keys" is what readers search for. Ship
    of Harkinian reads game ROMs, which are no BIOS."""
    names = list(names)
    keys = sum("key" in name.casefold() for name in names)
    if keys >= 2 and any("firmware" in name.casefold() for name in names):
        return "keys and firmware"
    if names and keys * 2 > len(names):
        return "keys"
    return "BIOS" if firmware * 2 >= fetched else "files"


def comes_with_app(f: dict) -> bool:
    """The emulator installs the file in the build the entry describes.

    The rule verify and the pack read (``installed_with_emulator``). An entry
    narrowed by ``mode`` is that build's alone: the other build reads its
    own entry, or nothing.
    """
    from validation import installed_with_emulator  # noqa: PLC0415

    return installed_with_emulator(f)


def _file_badges(f: dict, in_repo: bool, for_system: str = "") -> list[str]:
    """The status chips shown beside a file name.

    Fourteen independent optional fields, each contributing at most one
    chip. Kept apart from the rest of the row so the field-by-field
    rendering stays readable. ``for_system`` names the system a required
    file serves, on a profile that runs more than one.
    """
    required = f.get("required", False)
    hle = f.get("hle_fallback", False)
    mode = f.get("mode", "")
    category = f.get("category", "")
    region = f.get("region", "")
    storage = f.get("storage", "")
    embedded = f.get("embedded", False)
    has_builtin = f.get("has_builtin", False)
    archive = f.get("archive", "")
    ftype = f.get("type", "")
    badges = []
    shipped = comes_with_app(f)
    if shipped:
        # NetherSX2's three interface fonts sat beside the BIOS as
        # "required" and "missing": the app ships them, nobody fetches them.
        # Narrowed to one build, the build is named.
        build = f.get("mode") if f.get("mode") in ("standalone", "libretro") else ""
        label = f"installed with the {build} emulator" if build else "comes with the app"
        badges.append(f'<span class="rb-badge rb-badge-info">{label}</span>')
    elif required:
        needed = f"required for {html.escape(for_system)}" if for_system else "required"
        badges.append(
            f'<span class="rb-badge rb-badge-danger">{needed}</span>'
        )
    else:
        badges.append(
            '<span class="rb-badge rb-badge-muted">optional</span>'
        )
    # Whether the collection holds a file the app ships says nothing to
    # the reader: no status chip.
    if shipped:
        status = ""
    elif in_repo:
        status = '<span class="rb-badge rb-badge-success">in repo</span>'
    elif f.get("unsourceable"):
        status = '<span class="rb-badge rb-badge-muted">unsourceable</span>'
    else:
        status = '<span class="rb-badge rb-badge-warning">missing</span>'
    if status:
        badges.append(status)
    if hle:
        badges.append(
            '<span class="rb-badge rb-badge-info">HLE fallback</span>'
        )
    if mode and not (shipped and mode in ("standalone", "libretro")):
        badges.append(
            f'<span class="rb-badge rb-badge-muted">{mode}</span>'
        )
    if category and category != "bios":
        badges.append(
            f'<span class="rb-badge rb-badge-info">{_CATEGORY_WORDS.get(category, category)}</span>'
        )
    if region:
        # Labelled: "optional in repo japan" read as one run-on phrase.
        badges.append(
            f'<span class="rb-badge rb-badge-muted">Region: {_region_words(region)}</span>'
        )
    if storage and storage != "embedded":
        badges.append(
            f'<span class="rb-badge rb-badge-muted">{storage}</span>'
        )
    if embedded:
        badges.append(
            '<span class="rb-badge rb-badge-muted">embedded</span>'
        )
    if has_builtin:
        badges.append(
            '<span class="rb-badge rb-badge-info">built-in fallback</span>'
        )
    if archive:
        badges.append(
            f'<span class="rb-badge rb-badge-muted rb-badge-archive">in {archive}</span>'
        )
    if ftype and ftype != "bios":
        badges.append(
            f'<span class="rb-badge rb-badge-muted">{ftype}</span>'
        )

    return badges


def _first_hash_value(entry: dict) -> str:
    """The first declared hash of an entry, lowercase, for a stable anchor."""
    for field in ("sha1", "md5", "crc32", "sha256"):
        value = entry.get(field)
        value = value[0] if isinstance(value, list) and value else value
        if value:
            return str(value).lower().split(",")[0].strip().removeprefix("0x")
    return ""


_LOAD_FROM = {
    "system_dir": "the system (BIOS) directory",
    "save_dir": "the save directory, not the BIOS directory",
    "content_dir": "the folder of the loaded content, not the BIOS directory",
    "working_directory": "the working directory, not the BIOS directory",
    "data_dir": "the emulator's data directory, not the BIOS directory",
    "hdd_image": "inside the emulated hard disk image, not the BIOS directory",
    "internal_storage": "the app's internal storage, not the BIOS directory",
}


def _by_build(value: object, words: Callable[[str], str]) -> str:
    """A field keyed by build, said per build, or a plain value said once."""
    if isinstance(value, dict):
        return ", ".join(f"{words(str(v))} ({mode} build)" for mode, v in value.items() if v)
    return words(str(value)) if value else ""


def _load_from_text(value: object) -> str:
    """Where the code reads a file, in words.

    The card showed the Path alone: Dolphin's libretro core reads
    gba_bios.bin from its save directory, and a reader put it under system/.
    """
    if value in (None, "", "system_dir"):
        return ""
    return _by_build(value, lambda v: _LOAD_FROM.get(v, _code(v)))


def _found_by_text(value: object) -> str:
    """How the code finds a file: by the name it opens, or by content."""
    words = {
        "name": "file name (the code opens this name)",
        "content": "content (the code scans the folder and identifies the file "
                   "by its hash, any file name works)",
    }
    return _by_build(value, lambda v: words.get(v, _code(v)))


def _on_mismatch_lines(value: object) -> list[str]:
    """What the code does when a declared check fails, where it is not reject."""
    said = {"warn": "warns and runs with the file", "reject": "rejects the file"}
    if value == "warn":
        return [f"On a failed check: {said['warn']}"]
    if isinstance(value, dict):
        return [f"On a failed {check} check: {said.get(str(how), _code(str(how)))}"
                for check, how in value.items()]
    return []


def emulator_setups(coverages: dict, profiles: dict) -> dict[str, list[str]]:
    """Each emulator with the platforms that run it, by display name."""
    setups: dict[str, list[str]] = {}
    for platform, cov in coverages.items():
        for emulator in resolve_platform_cores(cov["config"], profiles):
            setups.setdefault(emulator, []).append(platform)
    return {
        emulator: sorted(names, key=lambda p: _platform_display(p).casefold())
        for emulator, names in setups.items()
    }


def _validation_names(validation: object) -> set[str]:
    """The checks a `validation:` names, a list or one list per build."""
    if isinstance(validation, dict):
        return {str(v) for checks in validation.values() for v in checks or []}
    return {str(v) for v in validation or []}


def _card_size(size: int) -> str:
    """A file's size, exact: in whole MB or KB when it is one, else in B."""
    for unit, scale in (("MB", 1024 * 1024), ("KB", 1024)):
        if size >= scale and size % scale == 0:
            return f"{size // scale:,} {unit}"
    return f"{size:,} B"


def _exact_size(size: int) -> str:
    """A rounded size with its bytes, where the bytes are not the same figure."""
    return _fmt_size(size) if size < 1024 else f"{_fmt_size(size)} ({size:,} bytes)"


def _build_file_links(pin_build: list[dict]) -> list[str]:
    """Each platform build file that holds the revision, linked at the
    commit it was read at when the source record holds it. The prose of
    pin_frozen named the file as plain text."""
    from sitesources import _browse_repo, _source_permalink, tree_holds  # noqa: PLC0415

    links = []
    for build in pin_build:
        repo = _browse_repo(str(build["repo"]))
        path = str(build["path"])
        revision = str(build["revision"])
        text = f"{_escape_tags(_platform_display(str(build['platform'])))} {_code(path)}"
        # Linked where the record saw the file at that commit, as every
        # source link is: a tag can move, and is never recorded.
        if repo is not None and tree_holds(repo, revision, path):
            text = f"[{text}]({_source_permalink(repo, revision, path, None, None)})"
        links.append(f"{text} at {_code(str(build['revision']))} sets {_code(str(build['variable']))}")
    return links


def _build_rows(profile: dict) -> list[str]:
    """Meta card rows for who ships the build, how its files are found, why
    its revision is held and where its releases are announced."""
    rows = []
    built_by = profile.get("built_by") or []
    if built_by:
        names = ", ".join(f"[{p}](../platforms/{p}.md)" for p in map(str, built_by))
        rows.append(f"| Built by | {names}, under its core name. The libretro "
                    "buildbot does not publish this build. |")
    found = _found_by_text(profile.get("found_by"))
    if found:
        rows.append(f"| Files found by | {found} |")
    # Each pin says why it is held: a bare upstream revision read as a
    # profile left behind HEAD (mupen64plus, aps3e).
    for field, label in (("pin_frozen", "Revision held"),
                         ("upstream_frozen", "Upstream revision held")):
        frozen = profile.get(field)
        if frozen:
            held = _escape_tags(' '.join(str(frozen).split())).replace('|', r'\|')
            rows.append(f"| {label} | {held} |")
    builds = _build_file_links(profile.get("pin_build") or [])
    if builds:
        rows.append(f"| Build file | {'<br>'.join(builds)} |")
    announced = profile.get("version_source")
    if isinstance(announced, dict) and announced.get("url"):
        url = str(announced["url"])
        row = f"| Releases announced at | [{url}]({url})"
        if announced.get("no_genuine_copy"):
            row += (f" (version {_escape_tags(str(announced['no_genuine_copy']))} "
                    "announced there, found only as rebuilt copies)")
        rows.append(row + " |")
    return rows


def _entry_label(f: dict, profile: dict) -> str:
    """The name a file card goes by, its title without the badges."""
    fname = f.get("name", "")
    if f is any_name_bios(profile):
        # Found by content: the name is an example, any image of the system works.
        system = system_name((profile.get("systems") or [""])[0])
        return (f"a {system} BIOS (example: {_code(fname)})" if _named_example(str(fname))
                else f"a {system} BIOS, any file name")
    return _code(fname)


def _render_emulator_file(
    f: dict,
    profile: dict,
    consumers: FileConsumers | None,
    files: list,
    _file_available: Callable[[dict], bool],
    anchor: str = "",
    owner: str = "",
    alias: str = "",
    data_href: str = "#data-folder",
    badges_apart: bool = False,
) -> list[str]:
    """Render one row of an emulator profile's file table.

    `anchor` is the card's id on the page, so one file can be cited by URL,
    and `alias` a second id it answers to. `data_href` links the data
    folder an app reads the entry under, from the page the card lands on.
    `badges_apart`: the title holds the name alone, for a table whose
    Status column shows the badges (siteentries.py).

    Split out of generate_emulator_page, where it was a 228-line loop body
    carrying most of that function's branching: thirty-odd optional fields,
    each with its own badge, hash line or note.
    """
    lines: list[str] = []
    fname = f.get("name", "")
    in_repo = _file_available(f)
    source_ref = f.get("source_ref", "")
    aliases = f.get("aliases", [])
    validation = f.get("validation", [])
    size = f.get("size")
    fnote = f.get("note", f.get("notes", ""))
    fmd5 = f.get("md5", "")
    fsha1 = f.get("sha1", "")
    fcrc32 = f.get("crc32", "")
    fsha256 = f.get("sha256", "")
    fadler32 = f.get("known_hash_adler32", "")
    fmin = f.get("min_size")
    fmax = f.get("max_size")
    desc = f.get("description", "")
    fpath = f.get("path", "")
    fsystem = f.get("system", "")
    priority = f.get("priority")
    fast_boot = f.get("fast_boot")
    contents = f.get("contents", [])
    config_key = f.get("config_key", "")
    dest = f.get("dest", f.get("destination", ""))
    fpattern = f.get("pattern", "")
    region_check = f.get("region_check")
    size_note = f.get("size_note", "")
    size_range = f.get("size_range", "")

    # melonDS reads DS and DSi files: "required" alone sat on the DSi NAND
    # above the DS files, for an emulator most people run for DS games.
    for_system = (system_name(str(fsystem))
                  if fsystem and len(profile.get("systems") or []) > 1 else "")
    badges = _file_badges(f, in_repo, for_system)
    badge_str = " ".join(badges)
    lines.append(markup.block_open("div", 'class="rb-file-entry"'))
    lines.append("")
    marker = f'<span id="{alias}"></span>' if alias else ""
    label = _entry_label(f, profile)
    title = f"{marker}{label}" if badges_apart else f"{marker}{label} {badge_str}"
    lines.append(_card_title(title, anchor, weight=5))
    lines.append("")
    if desc:
        lines.extend([data_root_words(_escape_tags(str(desc)), data_href), ""])
    body_start = len(lines)

    details = []
    # Where the app reads it under its data folder, said beside the path:
    # Ryujinx's card read "Path: system/prod.keys" with no root.
    place = standalone_place(owner, profile, f) if owner else ""
    under = f", in [the data folder]({data_href})"
    standalone_path = f.get("standalone_path", "")
    if (fpath and fpath != fname) or (place and place == fpath):
        details.append(f"Path: `{fpath}`" + (under if place and place == fpath else ""))
    if standalone_path and standalone_path != fpath:
        # The standalone build reads it elsewhere: MesenCE's dsp1.rom goes
        # under Firmware/, and a page naming only the core's path sent its
        # users to the wrong folder.
        details.append(f"Standalone path: `{standalone_path}`"
                       + (under if place == standalone_path else ""))
    read_from = _load_from_text(f.get("load_from"))
    if read_from:
        details.append(f"Read from: {read_from}")
    found = _found_by_text(f.get("found_by"))
    if found:
        details.append(f"Found by: {found}")
    if fsystem:
        details.append(f"System: {_named_system_link(fsystem, '../')}")
    # Where the code compares the size, the exact bytes: raze tells three
    # DUKE3D.GRP apart by size, all three shown as 42.3 MB.
    sized = _exact_size if "size" in _validation_names(validation) else _fmt_size
    if size:
        if isinstance(size, list):
            size_str = " / ".join(sized(s) for s in size)
        else:
            size_str = sized(size)
        if fmin or fmax:
            bounds = []
            if fmin:
                bounds.append(f"min {sized(fmin)}")
            if fmax:
                bounds.append(f"max {sized(fmax)}")
            size_str += f" ({', '.join(bounds)})"
        details.append(f"Size: {size_str}")
    elif fmin or fmax:
        bounds = []
        if fmin:
            bounds.append(f"min {sized(fmin)}")
        if fmax:
            bounds.append(f"max {sized(fmax)}")
        details.append(f"Size: {', '.join(bounds)}")
    # Starlight folds the hashes and gives each a copy button.
    copyable = markup.starlight()
    if fsha1:
        details.append(f"SHA1: {_hash_spans(fsha1, copyable)}")
    if fmd5:
        details.append(f"MD5: {_hash_spans(fmd5, copyable)}")
    if fcrc32:
        crcs = fcrc32 if isinstance(fcrc32, list) else [fcrc32]
        details.append("CRC32: " + ", ".join(
            markup.hash_value(crc, True) if copyable else f"`{crc}`" for crc in crcs))
    if fsha256:
        details.append(f"SHA256: {_hash_spans(fsha256, copyable)}")
    if fadler32:
        # Printed as the downloads spell a hash, one per code span: the list
        # repr read `['0x66f334fe', ...]`. Dolphin hashes its DSP ROMs over
        # byte-swapped 16-bit words, so the raw Adler-32 the downloads carry
        # for the same file differs, and the card says which one it lists.
        values = fadler32 if isinstance(fadler32, list) else [fadler32]
        shown = ", ".join(_code(str(v).lower().removeprefix("0x")) for v in values)
        if f.get("adler32_byteswap"):
            details.append(
                f"Adler32 over the file's 16-bit words byte-swapped: {shown} "
                "(the Adler-32 in the downloads is the file's own and differs)"
            )
        else:
            details.append(f"Adler32: {shown}")
    if aliases:
        details.append(f"Aliases: {', '.join(f'`{a}`' for a in aliases)}")
    if priority is not None:
        details.append(f"Priority: {priority}")
    if fast_boot is not None:
        details.append(f"Fast boot: {'yes' if fast_boot else 'no'}")
    if validation:
        if isinstance(validation, list):
            details.append(f"Validation: {', '.join(validation)}")
        elif isinstance(validation, dict):
            for scope, checks in validation.items():
                details.append(f"Validation ({scope}): {', '.join(checks)}")
    details.extend(_on_mismatch_lines(f.get("on_mismatch")))
    if f.get("installed_on"):
        details.append("Installed by the platform's own package on: "
                       + ", ".join(sorted(f["installed_on"])))
    if f.get("not_bundled_on"):
        details.append("Not in the platform's package, so the pack brings it, on: "
                       + ", ".join(sorted(f["not_bundled_on"])))
    if f.get("unread_on"):
        details.append("Never opened on these platforms, whose launcher names other files: "
                       + ", ".join(sorted(f["unread_on"])))
    if source_ref:
        asker = requested_by(profile, source_ref)
        if asker:
            # A profile reading a libretro core and the original emulator
            # cited both trees alike: readers could not tell which code asks
            # for the file.
            details.append(f"Asked for by: {asker}")
        details.append(
            f"Source: {_source_ref_markdown(profile, source_ref)}"
        )
    if consumers and f.get("type") == "directory":
        details.extend(_directory_copies(f, consumers))
    if consumers:
        sha1 = consumers.sha1_of(
            *entry_target(f, profile.get("files") or []), owner=owner)
        held = consumers.path_of(sha1) if sha1 and in_repo else ""
        parts = held.split("/")
        if len(parts) >= 3 and parts[0] == "bios" and f.get("archive"):
            details.append(_held_copy_line((held, f["name"]), consumers))
        elif len(parts) >= 3 and parts[0] == "bios":
            # Which copy answers this entry, linked to its collection card
            # (provenance, every hash, download): an entry declaring no hash
            # said "in repo" without naming the file.
            page = card_page(held, sha1)
            details.append(
                f"Collection copy: [{_code(held)}]"
                f"(../systems/{urllib.parse.quote(page)}.md#sha1-{sha1[:12]})"
            )
        elif in_repo and not any(d.startswith("Collection copies:") for d in details):
            copy = held_copy(f)
            if copy:
                details.append(_held_copy_line(copy, consumers))
        plat_links = _platform_links(sha1, consumers) if sha1 else []
        if plat_links and markup.starlight():
            # Grouped by where the setups put the file, as the system card
            # says it: twelve setups repeating scph5502.bin took twelve
            # names and twelve paths where a few say it. One sentence a
            # place: a list or a line break was one more element a place.
            places = _places_markdown(_platform_places(sha1, consumers))
            details.append("Platforms: " + ". ".join(places))
        elif plat_links:
            details.append(f"Platforms: {', '.join(plat_links)}")

    if dest and dest != fname and dest != fpath:
        details.append(f"Destination: `{dest}`")
    if config_key:
        details.append(f"Config key: `{config_key}`")
    if fpattern:
        details.append(f"Pattern: `{fpattern}`")
    if region_check is not None:
        details.append(f"Region check: {'yes' if region_check else 'no'}")
    if size_note:
        details.append(f"Size note: {size_note}")
    if size_range:
        details.append(f"Size range: {size_range}")

    if markup.starlight():
        lines.extend(_emulator_card_folds(f, details, fnote, profile, in_repo, contents,
                                          data_href))
        lines.extend(["", "</div>", ""])
        return lines
    if details:
        for d in details:
            lines.append(f"- {d}")
    if fnote:
        lines.append(f"- {data_root_words(_escape_tags(link_prose_citations(profile, str(fnote))), data_href)}")
    if not in_repo and f.get("unsourceable"):
        lines.append(f"- {_unsourceable_line(f)}")
    lines.extend(_contents_lines(contents))
    lines[body_start:] = _search_skipped_apart(lines[body_start:])
    lines.append("")
    lines.append("</div>")
    lines.append("")
    return lines


def _contents_lines(contents: list) -> list[str]:
    """Every member with the hashes the emulator checks: MAME and FBNeo
    verify the members, never the archive, so a member's crc32 is the
    value a reader compares a set against."""
    if not contents:
        return []
    lines = [f"- Contents ({len(contents)} members):"]
    for c in contents:
        if isinstance(c, dict):
            parts = []
            if c.get("description"):
                parts.append(_escape_tags(str(c["description"])))
            if c.get("size"):
                parts.append(_fmt_size(c["size"]))
            if c.get("crc32"):
                parts.append(f"CRC32 `{c['crc32']}`")
            if c.get("sha1"):
                parts.append(f"SHA1 `{c['sha1']}`")
            extra = f": {', '.join(parts)}" if parts else ""
            lines.append(f"    - `{c.get('name', '')}`{extra}")
        else:
            lines.append(f"    - {c}")
    return lines


# What an emulator card shows at a glance: where the file goes, how big it
# is, which setups list it and which copy answers it. Fingerprints and the
# reading details open on demand.
_ENTRY_KEY_FACTS = ("Path:", "Standalone path:", "Read from:", "Found by:", "System:",
                    "Size:", "Aliases:", "Collection copy:", "Collection copies:",
                    "Platforms", "Destination:")
_ENTRY_HASHES = ("SHA1:", "MD5:", "CRC32:", "SHA256:", "Adler32")
# The words the fold of an emulator card names its facts by.
_ENTRY_MORE_WORDS = (
    ("Priority", "priority"), ("Fast boot", "fast boot"), ("Validation", "validation"),
    ("On a failed", "failed check"), ("Installed by the platform's own package", "packages"),
    ("Not in the platform's package", "packages"), ("Never opened", "unread setups"),
    ("Asked for by", "source"), ("Source", "source"), ("Config key", "config key"),
    ("Pattern", "pattern"), ("Region check", "region check"), ("Size note", "size note"),
    ("Size range", "size range"),
)


def _more_words(lines: list[str]) -> list[str]:
    """The words a fold names its facts by, once each, in their order."""
    words: list[str] = []
    for line in lines:
        text = re.sub(r"<[^>]+>", "", line.removeprefix("- "))
        word = next((w for prefix, w in _ENTRY_MORE_WORDS if text.startswith(prefix)),
                    text.split(":", 1)[0].lower())
        if word not in words:
            words.append(word)
    return words


def _short_hash_line(f: dict) -> str:
    """The entry's strongest declared hash, cut to SHORT_HASH characters,
    with a copy button for the whole value. "" when it declares none."""
    from hashing import parse_hash_list  # noqa: PLC0415

    for field, label in (("sha1", "SHA1"), ("md5", "MD5"), ("sha256", "SHA256"), ("crc32", "CRC32")):
        values = parse_hash_list(f.get(field) or "")
        if values:
            value = str(values[0])
            more = f" and {len(values) - 1} more" if len(values) > 1 else ""
            return (f'{label}: <span class="rb-hash" data-copy="{html.escape(value)}">'
                    f"{html.escape(value[:SHORT_HASH])}</span>{more}")
    return ""


def _emulator_card_folds(
    f: dict, details: list[str], fnote: object, profile: dict, in_repo: bool,
    contents: list, data_href: str,
) -> list[str]:
    """An emulator card's body under Starlight: the key facts and the notes
    open, the hashes and the rest in one closed fold.

    Lines the search reads and lines it skips are kept in two runs: mixed,
    each change of side was one more list and one more block, five lists
    on a card of a dozen lines.
    """
    def skipped(line: str) -> bool:
        return f"- {line}".startswith(SEARCH_SKIPPED)

    key = [d for d in details if d.startswith(_ENTRY_KEY_FACTS)]
    hashes = [d for d in details if d.startswith(_ENTRY_HASHES)]
    more = [d for d in details if d not in key and d not in hashes]
    short = _short_hash_line(f)
    shut_open = [d for d in key if skipped(d)]
    sized = next((i for i, d in enumerate(shut_open) if d.startswith("Size:")), None)
    if short and sized is not None:
        # On the size's line: what tells this dump from another, one list
        # item fewer on each card.
        shut_open[sized] += ", " + short.replace(": ", " ", 1)
    elif short:
        shut_open.insert(0, short)
    # What the search reads first, the notes included, then what it skips:
    # one list each.
    open_lines = [d for d in key if not skipped(d)]
    if fnote:
        open_lines.append(data_root_words(
            _escape_tags(link_prose_citations(profile, str(fnote))), data_href))
    if not in_repo and f.get("unsourceable"):
        open_lines.append(_unsourceable_line(f))
    lines = [f"- {d}" for d in open_lines]
    shut_fold = [f"- {d}" for d in hashes + [m for m in more if skipped(m)]]
    read_fold = [f"- {m}" for m in more if not skipped(m)]
    # The members of an archive, a list of their own under the fold's
    # summary, which counts them: a "Contents" item holding them was two
    # more elements and 44 bytes on each of 200 MAME cards.
    members = [f"* {line.removeprefix('    - ')}" for line in _contents_lines(contents)[1:]]
    fold: list[str] = []
    if shut_fold or read_fold or members:
        words = (["hashes"] if hashes else []) + _more_words(
            [line for line in shut_fold + read_fold if not line.startswith(
                tuple(f"- {h}" for h in _ENTRY_HASHES))])
        words = words if len(words) <= 3 else [*words[:3], "more"]
        if members:
            words.append(_count(len(members), "member"))
        hidden_part = [*shut_fold, "", *members] if members else shut_fold
        body = (hidden_part if not read_fold else [
            "", markup.block_open("div", f'class="rb-search-skip" {markup.search_exclude()}'),
            "", *hidden_part, "", "</div>", "", *read_fold])
        fold = card_fold(_listed_words(words), body, skip=False)
    # A fold the search skips whole sits in the skipped block before it, with
    # no attribute of its own: on a page of 200 MAME cards the attribute, the
    # class and a block each were 12 KB.
    hidden = bool(fold) and not read_fold
    shut = [f"- {d}" for d in shut_open] + (["", *fold] if hidden else [])
    if shut:
        lines += ["", markup.block_open("div", f'class="rb-search-skip" {markup.search_exclude()}'),
                  "", *shut, "", "</div>", ""]
    if fold and not hidden:
        lines += ["", *fold, ""]
    return lines


def _held_copy_line(copy: tuple[str, str], consumers: FileConsumers) -> str:
    """Where a copy the database does not index sits: a ZIP member under
    bios/, or a file or tree of a data directory the packs fetch."""
    path, member = copy
    parts = path.rstrip("/").split("/")
    if member:
        archive = _code(path)
        zsha1 = consumers.sha1_at(path)
        if zsha1 and len(parts) >= 3 and parts[0] == "bios":
            page = urllib.parse.quote(card_page(path, zsha1))
            archive = f"[{archive}](../systems/{page}.md#sha1-{zsha1[:12]})"
        return f"Collection copy: member {_code(member)} of {archive}"
    if parts[0] == "data" and len(parts) >= 2:
        ref, inside = parts[1], "/".join(parts[2:])
        if path.endswith("/"):
            where = _code(inside + "/") if inside else "the tree"
            return f"Collection copy: {where} in the {_code(ref)} data directory"
        info = (_DATA_MEMBERS.get(ref) or {}).get(inside) or {}
        shown = _code(inside)
        if info.get("sha1"):
            shown = (f'<a href="../../files/?sha1={info["sha1"]}">'
                     f"<code>{html.escape(inside)}</code></a>")
        return f"Collection copy: {shown} in the {_code(ref)} data directory"
    tree = f"{REPO_URL}/tree/main/{urllib.parse.quote(path.rstrip('/'))}"
    return f"Collection copy: [{_code(path)}]({tree})"


def _directory_copies(entry: dict, consumers: FileConsumers) -> list[str]:
    """What the collection holds under a directory entry, and where.

    The card said "in repo" and linked none of the files: alephone's
    Plugins/ holds 393 of them, each with its own card on a system page.
    """
    members = consumers.directory_members(entry)
    held = sorted({consumers.path_of(sha1) for sha1 in members.values()} - {""})
    if not held:
        return []
    folder = os.path.commonpath(held) if len(held) > 1 else os.path.dirname(held[0])
    parts = folder.split("/")
    where = _code(folder + "/")
    if len(parts) >= 3 and parts[0] == "bios":
        where = f"[{where}]({console_href(_slug(parts[1]), parts[2], '../')})"
    tree = f"{REPO_URL}/tree/main/{urllib.parse.quote(folder)}"
    return [f"Collection copies: {_count(len(members), 'file')} under {where} "
            f"([browse]({tree}))"]


_MAME_RELEASE = re.compile(r"^0\.\d")


def emulator_romset(profile: dict) -> str:
    """The romset an arcade emulator's sets must match, "MAME 0.78", or "".

    ``mame_version`` where the profile has one (MAME4droid 2024 is app
    1.38.1 on MAME 0.289), else the version of a MAME build or of a
    FinalBurn core, whose sets follow its own release.
    """
    if profile.get("type") in ("alias", "launcher") or profile.get("role") == "test":
        return ""
    emulator = str(profile.get("emulator", ""))
    version = str(profile.get("core_version") or "")
    if profile.get("mame_version"):
        return f"MAME {profile['mame_version']}"
    # HBMAME's sets are its own homebrew sets, whatever MAME it is based on.
    if "MAME" in emulator and "HBMAME" not in emulator and _MAME_RELEASE.match(version):
        return f"MAME {version}"
    if emulator.startswith("FinalBurn Neo") and version:
        return f"FinalBurn Neo {version}"
    if (emulator.startswith("FB Alpha") or "FBA" in emulator) and version:
        return f"FB Alpha {version}"
    return ""


def _version_said(value: object, basis: dict, profile: dict, mode: str = "") -> str:
    """One build's version and where the profile reads it, linked to the
    file or the tag where the source allows."""
    kind = basis.get("kind")
    if kind == "none":
        return "none stated in the source"
    if value is None:
        if kind == "unverified":
            return f"unknown: {_UNVERIFIED.get(str(basis.get('why')), 'unread')}"
        return "none published"
    value = str(value)
    url = version_basis_url(profile, basis, mode) if kind in ("file", "tag") else ""

    def shown(text: object) -> str:
        return f"[{_code(str(text))}]({url})" if url else _code(str(text))

    if kind == "file":
        return f"{value}, stated in {shown(basis.get('path'))}"
    if kind == "tag":
        distance = int(basis.get("distance") or 0)
        if not distance:
            return f"{value}, the tag at this revision"
        return f"{value}, {distance} commit{'s' if distance != 1 else ''} after tag {shown(basis.get('tag'))}"
    if kind == "package":
        return f"{value}, read from {basis.get('artifact')}"
    if kind == "unverified":
        return f"{value}, not confirmed: {_UNVERIFIED.get(str(basis.get('why')), 'unread')}"
    return value


# Why a profile's version could not be read, said to a reader.
_UNVERIFIED = {
    "no_pin": "no revision recorded",
    "host_unsupported": "its host cannot be read",
    "host_gone": "its source is gone",
    "host_unreachable": "its host did not answer",
    "pin_off_branch": "its recorded revision is not the build described",
    "no_artifact": "no build recorded as read",
    "no_source": "no source declared",
}


def version_markdown(profile: dict) -> str:
    """The Version cell: core_version and where version_basis reads it.

    A null version said "none published" whether the code states none or
    nobody looked. Keyed by build mode like source, each build is named,
    where the page printed the dict's Python repr.
    """
    if "core_version" not in profile and not profile.get("version_basis"):
        return "unknown"
    value = profile.get("core_version")
    basis = profile.get("version_basis") if isinstance(profile.get("version_basis"), dict) else {}
    if isinstance(value, dict) or (basis and "kind" not in basis):
        values = value if isinstance(value, dict) else {}
        modes = list(dict.fromkeys([*values, *basis]))
        return ", ".join(
            f"{_version_said(values.get(mode), basis.get(mode) or {}, profile, mode)} ({mode})"
            for mode in modes
        )
    return _version_said(value, basis, profile)


ROMSET_FAQ_PAGE = Path(WIKI_SRC_DIR) / "technical-faq.md"
_ROMSET_BLOCK = re.compile(
    r"(<!-- generated: romsets -->\n)(.*?)(<!-- /generated: romsets -->)", re.S)


def _retroarch_label(profile: dict) -> str:
    """"Arcade (MAME 2003)" gives "MAME 2003", "Arcade (FinalBurn Neo)
    (Neo-Geo)" gives "FinalBurn Neo (Neo-Geo)"."""
    inner = str(profile.get("display_name") or profile.get("emulator") or "").split("(", 1)[-1]
    return inner.replace(")", "", 1).strip()


def romset_table(profiles: dict) -> list[str]:
    """The FAQ's arcade table: each MAME and FinalBurn libretro core and the
    romset its profile reads at its pin.

    Written by hand, it told readers to collect MAME 0.160 sets for a core
    whose src/version.c states 0.159, and FinalBurn Neo 1.0.0.2 for a source
    at 1.0.0.03. A core whose name gives its version (Recalbox's MAME 0.258)
    needs no row.
    """
    rows: dict[str, list[str]] = {}
    for key, profile in sorted(profiles.items()):
        if not re.match(r"(mame|fbneo|fbalpha)", key) or \
                "libretro" not in str(profile.get("type", "")):
            continue
        romset = emulator_romset(profile)
        label = _retroarch_label(profile)
        if not romset or romset.split(" ", 1)[1].lstrip("v") in label:
            continue
        rows.setdefault(romset, []).append(label)

    def order(romset: str) -> tuple:
        family = 0 if romset.startswith("MAME") else 1 if romset.startswith("FB Alpha") else 2
        numbers = tuple(int(n) for n in re.findall(r"\d+", romset.split(" (", 1)[0]))
        return family, numbers

    lines = ["| Emulator, as RetroArch names it | Sets from |", "|---|---|"]
    for romset in sorted(rows, key=order):
        lines.append(f"| {', '.join(sorted(rows[romset]))} | {romset} |")
    return lines


def with_romset_table(page: str, profiles: dict) -> str:
    """The FAQ page with its romset table read from the profiles."""
    table = "\n".join(romset_table(profiles)) + "\n"
    if not _ROMSET_BLOCK.search(page):
        raise ValueError(f"{ROMSET_FAQ_PAGE}: no romsets block to write the table in")
    return _ROMSET_BLOCK.sub(lambda m: f"{m.group(1)}{table}{m.group(3)}", page, count=1)


ARCHIVE_RECIPES_PAGE = Path(WIKI_SRC_DIR) / "archive-recipes.md"
_ARCHIVE_BLOCK = re.compile(
    r"(<!-- generated: archive-recipes -->\n)(.*?)(<!-- /generated: archive-recipes -->)", re.S)


def archive_recipe_lines(counts: dict[str, int]) -> list[str]:
    """What an exact and a canonical rebuild are, each with its count."""
    total = f"{counts['total']:,}"
    return [
        f"- **Exact**: the same bytes as the archive in the collection."
        f" {counts['exact']:,} of {total} archives.",
        f"- **Canonical**: the same files inside, packed another way."
        f" {counts['canonical']:,} of {total} archives.",
    ]


def with_archive_counts(page: str, counts: dict[str, int]) -> str:
    """The archive recipes page with its counts read from recipes/archives.json."""
    block = "\n".join(archive_recipe_lines(counts)) + "\n"
    if not _ARCHIVE_BLOCK.search(page):
        raise ValueError(f"{ARCHIVE_RECIPES_PAGE}: no archive-recipes block to write the counts in")
    return _ARCHIVE_BLOCK.sub(lambda m: f"{m.group(1)}{block}{m.group(3)}", page, count=1)


def _render_metadata_rows(profile: dict) -> list[str]:
    """Scalar profile fields, one table row each.

    Anything structured belongs in a collapsible block below, not in a
    row: a dict rendered into a table cell is unreadable.
    """
    lines: list[str] = []
    romset = emulator_romset(profile)
    if romset:
        lines.append(f"| Romset | [{romset}]({ROMSET_FAQ}) |")
    for field, label in [
        ("core", "Core ID"),
        ("core_name", "Core name"),
        ("bios_size", "BIOS size"),
        ("bios_directory", "BIOS directory"),
        ("bios_detection", "BIOS detection"),
        ("bios_selection", "BIOS selection"),
        ("firmware_file", "Firmware file"),
        ("firmware_source", "Firmware source"),
        ("firmware_install", "Firmware install"),
        ("firmware_detection", "Firmware detection"),
        ("resources_directory", "Resources directory"),
        ("rom_path", "ROM path"),
        ("game_count", "Game count"),
        ("verification", "Checks the file by"),
        ("analysis_date", "Analysis date"),
        ("analysis_commit", "Analysis commit"),
    ]:
        val = profile.get(field)
        if val is None or val == "" or isinstance(val, (dict, list)):
            continue
        if field == "bios_directory" and profile.get("type") == "standalone" \
                and not str(val).startswith(("/", "~", "$")) and ":" not in str(val):
            # A bare `bios/` read as a place on the device: it is a folder
            # inside the app's own data folder, which the notes describe.
            lines.append(f"| {label} | {_code(val)}, inside the app's own data folder |")
        elif field == "bios_size" and isinstance(val, int):
            lines.append(f"| {label} | {_fmt_size(val)} ({val:,} bytes) |")
        elif isinstance(val, str) and val.startswith("http"):
            lines.append(f"| {label} | [{val}]({val}) |")
        else:
            lines.append(f"| {label} | {val} |")
    roots = profile.get("data_root")
    if isinstance(roots, dict):
        # The folder per system, for the reader who checks the profile.
        for key in ("windows", "macos", "linux", "android", "ios"):
            root = roots.get(key)
            if isinstance(root, dict) and root.get("path"):
                lines.append(f"| Data folder ({_OS_LABELS[key]}) | "
                             f"{_under_root(str(root['path']), '')} |")
    if profile.get("source_ref"):
        lines.append(
            f"| Source ref | {_source_ref_markdown(profile, profile['source_ref'])} |"
        )
    return lines


def install_commands(args: str = "", indent: str = "",
                     oses: tuple[str, ...] | None = None) -> list[str]:
    """The same install for each place a user runs it: one generator for the
    download page and the platform, system and emulator pages, so none of
    them loses the Android or Windows form.

    ``oses`` names the terminals (keys of TERMINALS) the command runs in,
    written as the synced OS tabs: MAME4droid runs on Android only, and its
    page offered a PowerShell command. None keeps the three blocks.
    """
    if oses is not None:
        return terminal_tabs(oses, dict.fromkeys(oses, args), indent)
    lines = []
    for label, shell in (
        ("Linux, macOS, Steam Deck:", "sh"),
        ("Windows (PowerShell):", "powershell"),
        ("Android (Termux, the command installs Python and asks for storage access):", "sh"),
    ):
        lines += [f"{indent}{label}", "", *fence(shell, install_command(shell, args), indent), ""]
    return lines


@functools.cache
def _installer() -> object:
    """install.py, read as a module: the names `--emulator` accepts are its
    own (`emulator_names`)."""
    import importlib.util  # noqa: PLC0415

    spec = importlib.util.spec_from_file_location("install", _REPO_ROOT / "install.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@functools.cache
def _published_emulator_names() -> dict[str, dict[str, str]]:
    """Per published manifest, every name `--emulator` accepts there and the
    profile it stands for, as `install.py --list-emulators` prints them."""
    installer = _installer()
    names: dict[str, dict[str, str]] = {}
    for path in sorted((_REPO_ROOT / "install").glob("*.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        names[path.stem] = installer.emulator_names(
            manifest, manifest.get("files") or [], manifest.get("omitted_files") or [])
    return names


# Where a setup's command runs, in the order the tabs show them.
_COMMAND_TERMINALS = ("windows", "macos", "linux", "steamdeck", "android", "device")

# The terminals an app's data_root key covers: the Deck runs the Linux build.
_DATA_ROOT_TERMINALS = {
    "windows": ("windows",), "macos": ("macos",), "linux": ("linux", "steamdeck"),
    "android": ("android",), "ios": (),
}


def emulator_install_route(name: str, profile: dict) -> tuple[str, list[str], tuple[str, ...]]:
    """The name `--emulator` takes for this profile, the setups the command
    fills, and the terminals it runs in, or ("", [], ()) when none works.

    A name works where a published manifest maps it to this profile: 215
    pages printed a command every manifest refused. A setup counts when the
    installer finds it without `--dest`. A standalone app is reached only
    through a setup that launches it as an app (its standalone_cores), on
    the systems both run on: RetroArch's list names AetherSX2, and the
    command filled RetroArch's system folder, which the app never reads.
    """
    if profile.get("type") in ("alias", "launcher") or profile.get("role") == "test":
        return "", [], ()
    if not [f for f in profile.get("files") or [] if isinstance(f, dict) and not comes_with_app(f)]:
        return "", [], ()
    standalone = profile.get("type") == "standalone"
    accepted: dict[str, set[str]] = {}
    for platform, names in _published_emulator_names().items():
        if platform not in GUIDES:
            continue
        if standalone and not runs_standalone(name, profile, _standalone_cores(platform)):
            continue
        if any("--dest" in args for args in platform_args(platform, GUIDES[platform]).values()):
            continue
        own = {n for n, target in names.items() if target == name}
        if own:
            accepted[platform] = own
    if not accepted:
        return "", [], ()
    # The profile's own name where a setup takes it, else the alias most
    # setups take: the one command must work on every setup it names.
    candidates = set().union(*accepted.values())
    command = min(candidates, key=lambda n: (
        -sum(n in own for own in accepted.values()), n != name, n))
    order = list(GUIDES)
    setups = sorted((p for p, own in accepted.items() if command in own), key=order.index)
    terminals = {key for setup in setups for key in GUIDES[setup].run}
    if isinstance(profile.get("data_root"), dict):
        # Only the systems the program is built for (Cemu has no Android
        # build). A device setup runs it itself: its terminal stays.
        terminals &= {"device", *(t for key in profile["data_root"]
                                   for t in _DATA_ROOT_TERMINALS.get(key, ()))}
    oses = tuple(key for key in _COMMAND_TERMINALS if key in terminals)
    if not oses:
        return "", [], ()
    return command, setups, oses


def _standalone_cores(platform: str) -> frozenset[str]:
    """The emulators a setup launches as apps, by its platform file."""
    return _standalone_cores_in(str(siteinputs.current().platforms), platform)


@functools.cache
def _standalone_cores_in(platforms_dir: str, platform: str) -> frozenset[str]:
    config = load_platform_config(platform, platforms_dir)
    return frozenset(str(c) for c in config.get("standalone_cores") or [])


def _said_or(names: list[str]) -> str:
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + f" or {names[-1]}"


def _install_block(name: str, profile: dict) -> list[str]:
    """One command that installs this emulator's files where it reads them.

    The installer finds the setup and its BIOS folder, then keeps what this
    emulator reads there: its own files and the setup's files of the
    systems it runs. Written only where a published manifest takes the
    name, in the terminals of the setups that run it. `--emulator` turns off
    the pass that fills a lone app's folders (install.py, `narrowing` in
    main), so an app on its own is named with the setup that serves it.
    """
    command, setups, oses = emulator_install_route(name, profile)
    if not command:
        return []
    emu = str(profile.get("emulator") or name)
    shown = [_platform_display(setup) for setup in setups]
    if profile.get("type") == "standalone":
        lead = (f"With {_said_or(shown)}: the installer finds {_said_or(shown)} and its "
                f"BIOS folder, then downloads only the files {emu} reads there and checks "
                "each one.")
    else:
        lead = ("The installer finds the setup and its BIOS folder, then downloads "
                "only the files this emulator reads there and checks each one.")
        if profile.get("type") == "standalone + libretro":
            # The command fills a setup, never the app's own folder.
            where = (_said_or(shown) if len(shown) <= 3
                     else f"{shown[0]}, {shown[1]} or another setup")
            lead = f"For {emu} inside {where}. {lead}"
    return search_excluded(markup.details("tip", "Install this emulator's files", [
        lead,
        "",
        *install_commands(f"--emulator {command}", oses=oses),
    ]))


# Entries whose folder the app opens is not data_root joined to their
# standalone_path (or path): the pack builder still places them by that
# field, so the joined path names a place the app never reads. Their page
# gives the data folder alone. A row names the profile, the entries (a name,
# a path prefix ending in "/", or "*" for every file) and, when the rule
# holds on some systems only, the data_root keys it covers.
FOLDER_ONLY: tuple[tuple[str, tuple[str, ...], tuple[str, ...], str], ...] = (
    ("amiberry", ("*",), (),
     "the app reads every ROM, Kickstarts included, under ROMs/ of its folder"),
    ("fsuae", ("fsuae/Kickstarts/",), (),
     "the app reads Kickstarts from ROMs/Kickstart/ of its folder"),
    ("citra", ("Citra/sysdata/",), (),
     "the app reads its keys and shared fonts from sysdata/ of its folder"),
    ("ymir", ("*",), (),
     "the app reads its IPL, cartridge and CD-block ROMs from roms/ipl/, roms/cart/ and roms/cdb/"),
    ("mame", ("*",), (),
     "the app reads every set under roms/ of its working directory"),
    ("eka2l1", ("data/",), ("ios",),
     "on iOS the data folder is the data-storage folder itself, so data/ would be one level too deep"),
    ("aethersx2", ("resources/", "eeprom.dat", "flash.dat"), (),
     "resources sit beside the program, and eeprom.dat and flash.dat in the working directory"),
    ("cemu", ("resources/sharedFonts/",), (),
     "the shared fonts are read from the program's data path"),
    ("cxbx-reloaded", ("hlsl/",), (),
     "the shaders are read from beside the program"),
    ("ppsspp-1.5.4", ("ppsspp-1.5.4/assets/",), (),
     "the assets tree is read from beside the program"),
    ("yaps2", ("resources/",), (),
     "resources are read from beside the program"),
    ("hatari", ("tos.img", "tos.sym"), (),
     "the TOS image is read from the install data directory"),
    ("armsx2", ("proverb.zip",), ("android",),
     "the Android app keeps the arcade boot programs in its internal storage"),
    ("armsx2", ("eeprom.dat", "flash.dat"), (),
     "eeprom.dat and flash.dat are read from the working directory"),
    ("kenji-nx", ("drivers/",), (),
     "a driver archive is unpacked under drivers/, a layout not confirmed in the source"),
)


def folder_only_matches(pattern: str, entry: dict) -> bool:
    """Whether a FOLDER_ONLY pattern names this entry."""
    if pattern == "*":
        return True
    if pattern.endswith("/"):
        return any(str(entry.get(key) or "").startswith(pattern)
                   for key in ("path", "standalone_path"))
    return entry.get("name") == pattern


def _folder_only(name: str, entry: dict) -> set[str]:
    """The data_root keys on which this entry's joined path is not the app's
    folder: every key ({"*"}), some, or none."""
    keys: set[str] = set()
    for profile, patterns, only, _reason in FOLDER_ONLY:
        if profile == name and any(folder_only_matches(p, entry) for p in patterns):
            keys |= set(only) or {"*"}
    return keys


def standalone_place(name: str, profile: dict, entry: dict, key: str = "") -> str:
    """Where under the data folder the app reads this entry, or "".

    Only what the app opens there: a lone app's ``standalone_path`` or
    ``path``, a dual profile's ``standalone_path`` or the ``path`` of an
    entry its standalone build alone reads. Nothing for an entry found by
    name, one the app ships, one the libretro core alone reads, or one
    FOLDER_ONLY lists (on ``key``, or on any key when ``key`` is empty).
    """
    if not isinstance(entry, dict) or not profile.get("data_root"):
        return ""
    mode = entry.get("mode")
    if mode == "libretro" or comes_with_app(entry):
        return ""
    excluded = _folder_only(name, entry)
    if "*" in excluded or (key in excluded if key else excluded):
        return ""
    if profile.get("type") == "standalone" or mode == "standalone":
        return str(entry.get("standalone_path") or entry.get("path") or "")
    return str(entry.get("standalone_path") or "")


_OS_LABELS = {"windows": "Windows", "macos": "macOS", "linux": "Linux",
              "android": "Android", "ios": "iOS"}


def _under_root(root: str, folder: str) -> str:
    """``root`` with ``folder`` below it, as code: each alternative of
    "$XDG_CONFIG_HOME/x, else ~/.config/x", and a root written in words
    ("the folder picked in the setup wizard") kept as words."""
    folder = folder.strip("/")
    shown = []
    for alternative in root.split(", else "):
        alternative = alternative.strip()
        if " " in alternative and "/" not in alternative and not alternative.startswith("<"):
            shown.append(f"{_code(folder + '/')} in {_escape_tags(alternative)}"
                         if folder else _escape_tags(alternative))
            continue
        joined = alternative.rstrip("/") + (f"/{folder}" if folder else "") + "/"
        shown.append(_code(joined))
    return ", else ".join(shown)


def _data_root_folder(name: str, profile: dict, key: str, entries: list[dict]) -> str:
    """The one folder under the root that every entry the app reads sits
    in, or "": VICE places 3 of its 322 files in DRIVES/, and naming that
    folder would send the other 319 there."""
    folders = set()
    for f in entries:
        mode = f.get("mode")
        if mode == "libretro" or comes_with_app(f):
            continue
        place = standalone_place(name, profile, f, key)
        if not place:
            return ""
        folders.add(place.rpartition("/")[0])
    return folders.pop() if len(folders) == 1 else ""


def data_folder_block(name: str, profile: dict, entries: list[dict] | None = None) -> list[str]:
    """The app's data folder, one tab per system it runs on, each with the
    code that names it and its note: 61 profiles cite it and no page showed
    it. ``entries`` are the files the folder is for: when they all sit in
    one folder below the root, the tab names that folder."""
    roots = profile.get("data_root") or {}
    if not isinstance(roots, dict) or not roots:
        return []
    if entries is None:
        entries = [f for f in profile.get("files") or [] if isinstance(f, dict)]
    items = []
    for key in ("windows", "macos", "linux", "android", "ios"):
        root = roots.get(key)
        if not isinstance(root, dict) or not root.get("path"):
            continue
        path = str(root["path"])
        line = _under_root(path, _data_root_folder(name, profile, key, entries))
        if key == "android" and path.startswith("Android/data/"):
            line += ", on the internal storage."
        body = [line]
        note = " ".join(str(root.get("note") or "").split()).rstrip(".")
        if note:
            # "the folder" reads as a sentence, "portable.ini" keeps its case.
            first = note.split(" ", 1)[0]
            if first.isalpha() and first.islower():
                note = note[:1].upper() + note[1:]
            body += ["", _escape_tags(note) + "."]
        body += ["", f"Source: {_source_ref_markdown(profile, str(root['source_ref']))}"]
        items.append((_OS_LABELS[key], body))
    if len(items) == 1:
        label, body = items[0]
        return [f"On {label}: {body[0]}", *body[1:], ""]
    return markup.tabs(items)


def data_root_words(text: str, href: str = "#data-folder") -> str:
    """Prose that names the field data_root, linked to the folder it holds:
    ten pages told readers "given in data_root"."""
    return re.sub(r"\bdata_root\b", f"[the data folder]({href})", text)


def _platform_install_block(name: str, display: str, on_card: bool = False) -> list[str]:
    """The platform's pack, installed file by file: what the ZIP holds, with
    resume, verification and only what is missing.

    ``on_card``: the files go on the frontend's SD card, installed from the
    computer it is mounted on, whose root is named.
    """
    if on_card:
        return markup.details("tip", "Install with one command", [
            f"With the {display} SD card mounted, the installer downloads the files "
            "of the pack that are missing or differ from it into `Bios/<TAG>/` on "
            "the card, checks each one, and resumes where it stopped. `--dest` "
            "names the card's root.",
            "",
            "Linux, macOS:",
            "",
            *fence("sh", install_command("sh", f"--platform {name} --dest /path/to/card")),
            "",
            "Windows (PowerShell, E: being the card):",
            "",
            *fence("powershell", install_command("powershell", f"--platform {name} --dest E:\\")),
        ], opened=True)
    return markup.details("tip", "Install with one command", [
        f"The installer downloads the files of the {display} pack that are "
        "missing or differ from it, checks each one, and resumes where it "
        "stopped. Add `--system` with the ids of the systems overview below "
        "to install fewer systems.",
        "",
        *install_commands(f"--platform {name}"),
    ], opened=True)


def _ps_quote(value: str) -> str:
    """A PowerShell argument: bare when plain, single-quoted otherwise."""
    return value if re.fullmatch(r"[\w.+-]+", value) else "'" + value.replace("'", "''") + "'"


# The OS tabs of a system's install box: labels the site's other command
# tabs use, so the reader's choice carries from page to page.
INSTALL_PICKER_OSES = ("windows", "macos", "linux", "steamdeck")


def _install_args(platform: str, system: str, shell: str) -> str:
    quoted = _ps_quote(system) if shell == "powershell" else shlex.quote(system)
    return f"--platform {platform} --system {quoted}"


def _default_setup(declared: list[tuple[str, str]]) -> tuple[str, str]:
    """The setup an install box shows before the reader picks one.

    The first in alphabetical order was AmberELEC on 17 system pages, a
    handheld system under a Windows tab. The box shows the setup whose
    command runs under the most of its tabs (the guide's `run`), then on the
    most systems overall, then one the release publishes a ZIP for.
    """
    def reach(pair: tuple[str, str]) -> tuple[int, int, bool]:
        runs = GUIDES[pair[0]].run if pair[0] in GUIDES else ()
        return (len(set(runs) & set(INSTALL_PICKER_OSES)), len(runs), has_release_pack(pair[0]))

    return max(declared, key=reach)


def _install_picker(declared: list[tuple[str, str]]) -> list[str]:
    """One command, for the setup the reader picks, under the OS tabs.

    Every setup's command for a console was written out, twice: 12 long
    lines for the PSP, about 360 page elements once highlighted. The
    picker shows one and the script (site.ts) rewrites it for the setup
    chosen, remembered from page to page. Without the script the picker
    stays hidden and the plain list of every command shows, open.
    """
    def attribute(text: str) -> str:
        # Quotes kept as written: a system id quoted for the shell ('Neo Geo').
        return html.escape(text, quote=False).replace('"', "&quot;")

    names = Counter(platform for platform, _system in declared)
    lead = _default_setup(declared)
    options = "".join(
        f'<option value="{attribute(platform)}"'
        + (" selected" if (platform, system) == lead else "")
        + f' data-sh="{attribute(_install_args(platform, system, "sh"))}" '
        f'data-ps="{attribute(_install_args(platform, system, "powershell"))}">'
        + html.escape(_platform_display(platform) + (f" ({system})" if names[platform] > 1 else ""),
                      quote=False)
        + "</option>"
        for platform, system in declared)
    args = {key: _install_args(*lead, TERMINALS[key][2]) for key in INSTALL_PICKER_OSES}
    return [
        "Each platform names the system its own way.",
        "",
        '<div class="rb-install" data-rb-install="" hidden>',
        "",
        f'<label class="rb-install-setup">Setup <select>{options}</select></label>',
        "",
        *terminal_tabs(INSTALL_PICKER_OSES, args, steps=False),
        "",
        "</div>",
        "",
        # Each command as inline code, no highlighting: the list is the
        # fallback and the reference, and highlighted it was most of the
        # box's elements.
        '<details class="rb-install-all" open>',
        "<summary>Every setup's command</summary>",
        "",
        *_command_list("Terminal (Linux, macOS, Steam Deck):", declared, "sh"),
        *_command_list("PowerShell (Windows):", declared, "powershell"),
        "</details>",
    ]


def _command_list(label: str, declared: list[tuple[str, str]], shell: str) -> list[str]:
    """Every setup's command for one shell, a line each, with a copy button.

    Inline HTML code, so no break element is added at each slash. A break
    point follows the URL's scheme: the Markdown around the code made the
    bare URL a link inside the command, and a scheme with nothing after it
    is no link. The break adds no character to a copy."""
    def command(platform: str, system: str) -> str:
        text = html.escape(install_command(shell, _install_args(platform, system, shell)), quote=False)
        return text.replace("://", "://<wbr>")

    # One HTML line: the glossary leaves HTML alone, and it marked a word
    # inside a command.
    names = Counter(platform for platform, _system in declared)
    items = "".join(
        f"<li>{html.escape(_platform_display(platform), quote=False)}"
        + (f" ({html.escape(system, quote=False)})" if names[platform] > 1 else "")
        + f': <code data-copy="">{command(platform, system)}</code></li>'
        for platform, system in declared)
    return [label, "", f"<ul>{items}</ul>", ""]


def _console_install_block(console: str, declared: list[tuple[str, str]]) -> list[str]:
    """Each platform's command for one console, by the system id it gives it,
    for a terminal and for PowerShell, each under its setup's name: RetroBat
    had two lines and nothing said which was for the Neo Geo."""
    if not declared:
        return []
    sh = [line for platform, system in declared for line in (
        f"# {_platform_display(platform)}",
        install_command("sh", f"--platform {platform} --system {shlex.quote(system)}"))]
    ps = [line for platform, system in declared for line in (
        f"# {_platform_display(platform)}",
        install_command("powershell", f"--platform {platform} --system {_ps_quote(system)}"))]
    # The name last: "Install the Atari System 1 files" read as a count. A
    # label naming files already reads "Install these files": "Install
    # the files of Other arcade files".
    summary = ("Install these files" if console.casefold().endswith(" files")
               else f"Install the files of {console}")
    if markup.starlight() and len(declared) > 1:
        return search_excluded(markup.details("tip", summary, _install_picker(declared)))
    return search_excluded(markup.details("tip", summary, [
        "Each platform names the system its own way.",
        "",
        "Linux, macOS, Steam Deck:",
        "",
        *fence("sh", "\n".join(sh)),
        "",
        "Windows (PowerShell):",
        "",
        *fence("powershell", "\n".join(ps)),
    ]))


def _render_platform_details(profile: dict) -> list[str]:
    """The per-platform block, one level of nesting deep."""
    lines: list[str] = []
    platform_details = profile.get("platform_details")
    if platform_details and isinstance(platform_details, dict):
        body: list[str] = []
        for pk, pv in platform_details.items():
            if isinstance(pv, dict):
                body.extend([f"- **{pk}:**", ""])
                for sk, sv in pv.items():
                    body.append(f"    - {sk}: {_detail_value(profile, sk, sv)}")
                body.append("")
            else:
                body.append(f"- **{pk}:** {_detail_value(profile, pk, pv)}")
        lines.extend(markup.details("info", "Platform details", body, opened=True))

    return lines


def _detail_value(profile: dict, key: object, value: object) -> str:
    """A platform detail, its citations linked at the profile's pin."""
    if key == "source_ref" and isinstance(value, (str, dict)):
        return _source_ref_markdown(profile, value)
    if isinstance(value, str):
        return _escape_tags(link_prose_citations(profile, value))
    return _plain_value(value)


def _plain_value(value: object) -> str:
    """A scalar or a list of scalars as a reader writes it, not as Python does."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if value is None:
        # A YAML null states that there is none, but Python's `None` read as a gap.
        return "none"
    if isinstance(value, (list, tuple)):
        return ", ".join(_plain_value(item) for item in value)
    return _escape_tags(str(value))


def _structured_field_text(profile: dict) -> Callable[[object, object], str]:
    """Scalars of a structured block, citations linked at the profile's pin.

    The file entries and platform details linked their source_ref, and the
    analysis and firmware blocks printed 186 of them as plain code.
    """
    def text(key: object, value: object) -> str:
        if key == "source_ref" and isinstance(value, str):
            return _source_ref_markdown(profile, value)
        if isinstance(value, str):
            return link_prose_citations(profile, _field_text(key, value))
        return _field_text(key, value)

    return text


def _render_structured_blocks(profile: dict) -> list[str]:
    """Every remaining structured field, as a collapsible section."""
    lines: list[str] = []
    _structured_blocks = [
        ("analysis", "Source analysis"),
        ("memory_layout", "Memory layout"),
        ("regions", "Regions"),
        ("nvm_layout", "NVM layout"),
        ("model_kickstart_map", "Model kickstart map"),
        ("builtin_boot_roms", "Built-in boot ROMs"),
        ("common_bios_filenames", "Common BIOS filenames"),
        ("valid_bios_crc32", "Valid BIOS CRC32"),
        ("dev_flash", "dev_flash"),
        ("dev_flash2", "dev_flash2"),
        ("dev_flash3", "dev_flash3"),
        ("firmware_modules", "Firmware modules"),
        ("firmware_titles", "Firmware titles"),
        ("fallback_fonts", "Fallback fonts"),
        ("io_devices", "I/O devices"),
        ("partitions", "Partitions"),
        ("mlc_structure", "MLC structure"),
        ("machine_directories", "Machine directories"),
        ("machine_properties", "Machine properties"),
        ("whdload_kickstarts", "WHDLoad kickstarts"),
        ("bios_identical_to", "BIOS identical to"),
        ("pack_structure", "Pack structure"),
        ("firmware_version", "Firmware version"),
    ]
    for field, label in _structured_blocks:
        val = profile.get(field)
        if val is None:
            continue
        body: list[str] = []
        _render_yaml_value(body, val, indent=0,
                           field_text=_structured_field_text(profile))
        # Closed: raw profile data, below the files (Cemu's firmware
        # titles opened the page above them).
        block = markup.details(
            "abstract", label, [_escape_tags(line) for line in body])
        # A block listing hashes is the lookup's, as a card's hash lines are:
        # izapple2's ROM table put "md5" 59 times in the search, above the
        # page that explains MD5 checks.
        if any(re.search(r"\b[0-9a-f]{32,64}\b", line) for line in body):
            block = search_excluded(block)
        lines.extend(block)

    return lines


def _hash_spans(value: str | list, copy: bool = False) -> str:
    """Each hash a profile accepts, in full, each with a copy button when
    *copy*.

    Cut to 12 characters with the rest in a title attribute, 208 hashes
    that only a profile declares were out of reach of the site search: it
    indexes text, and a pasted sha1 matched nothing.
    """
    from hashing import parse_hash_list  # noqa: PLC0415

    return ", ".join(
        markup.hash_value(v, copy) for v in parse_hash_list(value)
    )


def _availability_check(
    db: dict, data_names: set[str] | None, owner: str = "",
) -> Callable[[dict], bool]:
    """A predicate answering whether the collection holds a file.

    It answers the way cross_reference does. A page that called a file
    missing while the gap report called it held would describe a
    different collection on two pages of the same site.
    """
    from cross_reference import entry_source

    by_name = db.get("indexes", {}).get("by_name", {})
    by_name_lower = {k.lower(): k for k in by_name}
    by_path_suffix = db.get("indexes", {}).get("by_path_suffix", {})

    index = {
        "by_name": by_name,
        "by_name_lower": by_name_lower,
        "by_path_suffix": by_path_suffix,
        "by_md5": db.get("indexes", {}).get("by_md5", {}),
        "by_sha256": db.get("indexes", {}).get("by_sha256", {}),
        "by_crc32": db.get("indexes", {}).get("by_crc32", {}),
        "db_files": db.get("files", {}),
        "data_names": data_names,
    }

    def _file_available(f: dict) -> bool:
        """Check if a file is available using the same resolution as cross_reference."""
        # cross_reference sets these aside before resolving: the file found
        # under the name belongs to another game or release.
        if not f.get("name") or f.get("unsourceable"):
            return False
        return entry_source({**f, "source_profile": owner} if owner else f, index) is not None

    return _file_available


def _emulator_slots(files: list[dict]) -> list[list[dict]]:
    """The entries of each slot, as verify --emulator and the gaps page
    count them, leaving out the slots the app ships."""
    from cross_reference import slot_key

    slots: dict[tuple, list[dict]] = {}
    for f in files:
        slots.setdefault(slot_key(f), []).append(f)
    return [group for group in slots.values() if not all(comes_with_app(f) for f in group)]


def _set_names(value: object) -> list[str]:
    """The sets an entry belongs to: group takes a name, a list or a map."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, dict)):
        return [str(name) for name in value]
    return []


def _requirements(files: list[dict], groups: dict | None) -> list[list[dict]]:
    """Each thing the emulator needs: the members of a required set, any one
    of which fills it (DuckStation's ps-bios, 105 images), or a required
    file of its own. load_emulator_profiles marks every member of a
    required set required, so counted per file DuckStation read "105
    required" for one BIOS."""
    required_sets = {name for name, spec in (groups or {}).items()
                     if isinstance(spec, dict) and spec.get("required")}
    sets: dict[str, list[dict]] = {}
    alone: list[list[dict]] = []
    for f in files:
        if f.get("required") is not True or comes_with_app(f):
            continue
        names = [name for name in _set_names(f.get("group")) if name in required_sets]
        if names:
            for name in names:
                sets.setdefault(name, []).append(f)
        else:
            alone.append([f])
    return [*sets.values(), *alone]


def _regional_set(requirements: list[list[dict]]) -> list[dict]:
    """The one requirement, a set whose members the code picks by the game's
    region, or [] when there is no such single choice."""
    if len(requirements) != 1 or len(requirements[0]) < 2:
        return []
    members = requirements[0]
    if not all(f.get("region") for f in members):
        return []
    return members if len({_region_words(f["region"]) for f in members}) >= 2 else []


def _emulator_file_summary(files: list[dict], groups: dict | None = None) -> list[str]:
    """What the emulator reads, above its file table, and its categories.

    Counted by slot, as verify --emulator and the gaps page count: raze
    lists every GRP its code accepts under one name, and holding one fills
    the slot. Counted per entry, the page announced 46 missing where 12
    slots are empty. The files the app ships are counted apart: NetherSX2
    said "4 required" for one BIOS and three fonts in its package. A
    required set counts once (`groups`).
    """
    slots = _emulator_slots(files)
    shipped = sum(1 for f in files if comes_with_app(f))
    requirements = _requirements(files, groups)
    in_sets = {id(f) for members in requirements for f in members}
    req_slots = sum(1 for group in slots if any(id(f) in in_sets for f in group))
    req_count = len(requirements)
    optional = len(slots) - req_slots
    hle_count = sum(1 for group in slots if any(f.get("hle_fallback") for f in group))

    # Sentences, one number format: the line read "1,563 files | 164
    # required, 1399 optional | 1563 in repo".
    total = f"**{_count(len(slots), 'file')}**"
    if sum(len(group) for group in slots) != len(slots):
        total += f" ({sum(len(group) for group in slots):,} accepted versions)"
    line = f"{total}: {req_count:,} required, {optional:,} optional."
    if any(len(members) > 1 for members in requirements):
        line += " Any one file of a required set fills it."
    regional = _regional_set(requirements) or (
        [f for members in requirements for f in members]
        if _regional_choice([f for members in requirements for f in members]) else [])
    if regional:
        # DuckStation takes the BIOS of the game's region: "3 required"
        # read as "get all three".
        line = f"{total}. One of {len(regional):,} is required, for the games' region."
        if optional:
            line += f" {optional:,} {'is' if optional == 1 else 'are'} optional."
    if hle_count:
        line += f" {hle_count:,} {'has' if hle_count == 1 else 'have'} an HLE fallback."
    if shipped:
        line += f" {_count(shipped, 'more file')} {'comes' if shipped == 1 else 'come'} with the app."
    lines = [line, ""]

    categories = [f.get("category", "bios") for f in files]
    if "game_data" in categories or "bios_zip" in categories:
        cats = [
            f"{categories.count(key):,} {label}"
            for key, label in (
                ("bios", "BIOS"), ("bios_zip", "BIOS ZIPs"), ("game_data", "game data")
            )
            if categories.count(key)
        ]
        lines.extend([f"By kind: {_said_as_list(cats)}.", ""])
    return lines


def _emulator_held_line(files: list[dict], available: Callable[[dict], bool]) -> list[str]:
    """What this collection holds of them, one quiet line under the table:
    a reader comes for what the emulator needs, the project's counts after."""
    slots = _emulator_slots(files)
    if not slots:
        return []
    in_repo = sum(1 for group in slots if any(available(f) for f in group))
    unsourceable = sum(
        1 for group in slots
        if not any(available(f) for f in group) and all(f.get("unsourceable") for f in group)
    )
    held = [f"{in_repo:,} in repo", f"{len(slots) - in_repo - unsourceable:,} missing"]
    if unsourceable:
        held.append(f"{unsourceable:,} unsourceable")
    return [f"<p><small>In this collection: {_said_as_list(held)}.</small></p>", ""]


def _said_as_list(items: list[str]) -> str:
    """"a, b and c"."""
    return ", ".join(items[:-1]) + f" and {items[-1]}" if len(items) > 1 else "".join(items)


# Data directory members and revisions, read once per build.
_DATA_MEMBERS: dict[str, dict[str, dict]] = {}
_DATA_REVISIONS: dict[str, dict] = {}
# Emulator -> the platforms that run it, as resolve_platform_cores answers.
_EMULATOR_SETUPS: dict[str, list[str]] = {}
# The measurement index items of each emulator, for the proof lines of its page.
_MEASUREMENT_ITEMS: dict[str, list[dict]] = {}
# The emulator pages that list each data directory, by ref.
_DATA_READERS: dict[str, list[tuple[str, str]]] = {}

# A data directory listing more files than this goes to pages of its own,
# this many files each: Dolphin's Sys tree put 2,164 rows and 16,900
# elements on the Dolphin page, read on a phone.
DATA_TREE_ROWS = 400
DATA_TREE_ROWS_PER_PAGE = 1_000


def data_tree_pages(ref: str, members: dict[str, dict]) -> list[tuple[str, list[str]]]:
    """The pages under emulators/ listing a large data directory, with the
    members each holds in name order, or none when the tree is listed on
    the pages of the emulators reading it."""
    if len(members) <= DATA_TREE_ROWS:
        return []
    names = sorted(members)
    stem = f"data-{_slugify_anchor(ref)}"
    return [(stem + (f"-{n}" if n > 1 else ""), names[start:start + DATA_TREE_ROWS_PER_PAGE])
            for n, start in enumerate(range(0, len(names), DATA_TREE_ROWS_PER_PAGE), 1)]


def _data_member_table(members: dict[str, dict], names: list[str], anchors: set[str]) -> list[str]:
    """A data directory's files with their size and sha1, each sha1 an
    anchor the first time the page lists it (``anchors``, the page's ids)."""
    table = ["| File | Size | SHA1 |", "|------|-----:|------|"]
    for member in names:
        info = members[member]
        sha1 = str(info.get("sha1", ""))
        # One id per page: two members can hold the same bytes (every empty
        # file), and Dolphin's trees share Sys.
        anchor = f"sha1-{sha1[:12]}"
        span = "" if anchor in anchors else f'<span id="{anchor}"></span>'
        anchors.add(anchor)
        table.append(f"| {span}{_code(member)} | {_fmt_size(int(info.get('size', 0)))} | {_code(sha1)} |")
    return table


def _data_tree_page(ref: str, entry: dict, pages: list[tuple[str, list[str]]],
                    index: int) -> str:
    """One page of a large data directory's file list."""
    stem, names = pages[index]
    members = _DATA_MEMBERS.get(ref) or {}
    part = f" (part {index + 1} of {len(pages)})" if len(pages) > 1 else ""
    read_by = _said_as_list([f"[{_escape_tags(display)}]({key}.md#data-directories)"
                             for key, display in _DATA_READERS.get(ref, [])])
    # A file list out of the search: "dolphin" found three parts of the
    # dolphin-sys tree, on their title, before the Dolphin page.
    front: dict = {"level": "reference", "search": "exclude"}
    # The reader the tree is named after (dolphin for dolphin-sys), else
    # the first by name.
    readers = _DATA_READERS.get(ref) or []
    owner = max(readers, default=None,
                key=lambda reader: len(reader[0]) if ref.startswith(f"{reader[0]}-") else 0)
    if owner:
        head = _part_front_matter(
            (owner[1], f"{owner[0]}.md"),
            [(f"The {ref} data directory, part {n}", f"{other}.md")
             for n, (other, _names) in enumerate(pages, 1)], index, front)
    else:
        head = ["---", yaml.safe_dump(front, sort_keys=False, allow_unicode=True).rstrip("\n"),
                "---", ""]
    lines = [
        *head,
        f"# The {ref} data directory{part}", "",
        f"{entry.get('description') or 'A data directory'}: "
        f"{_count(len(members), 'file')}, as the packs ship them."
        + (f" Read by {read_by}." if read_by else ""), "",
    ]
    if len(pages) > 1:
        lines.extend([", ".join(f"[part {i}]({other}.md)" if other != stem else f"part {i}"
                                for i, (other, _names) in enumerate(pages, 1)), ""])
    lines.extend(search_excluded(_data_member_table(members, names, set())))
    lines.extend(["", _date_line()])
    return "\n".join(lines) + "\n"


# An emulator page lists at most this many file cards: MAME's 1,564 made a
# 3 MB page. Past it, the cards go to pages of their own and the emulator's
# page keeps a table of every entry, each row holding the card's old
# anchor. A count, not a size: system cards link to these cards and are
# written before them. At 400 a part of MAME's cards was 805 KB of HTML.
EMULATOR_CARDS_PER_PAGE = 220
# The most cards a part of a split page holds. Each card is a table row
# since siteentries.py, about five elements and 60 bytes more: at 220 a
# part, MAME's first was 612 KB and 9,777 elements.
EMULATOR_CARDS_PER_PART = 180
# The words a part's rows may show, every card closed. A count of cards
# held while the rows did not grow: once 888 of MAME's entries named
# their system, each row said "for <system>" and the first part showed
# 1,931 words for 1,180 before. The frame of a part (headings, filter
# boxes, the links to the other parts, the footer) shows 100 to 170 more,
# and tests/test_site_entry_tables.py holds a part under 1,693: about a
# tenth is left as margin.
EMULATOR_PART_WORDS = 1_350


# The headings an emulator's cards go under, in page order: what it needs
# first. DuckStation's three required BIOS were cards 12 to 14 under one
# heading, and MAME opened on 25 floppy sound samples.
CARD_SECTIONS = (("required", "Required"), ("optional", "Optional"), ("game_data", "Game data"),
                 ("with_app", "Comes with the app"))
_SECTION_RANK = {key: rank for rank, (key, _title) in enumerate(CARD_SECTIONS)}


def _card_section(f: dict) -> str:
    if comes_with_app(f):
        return "with_app"
    if f.get("category") == "game_data":
        return "game_data"
    return "required" if f.get("required") else "optional"


def _display_order(files: list) -> list[int]:
    """Entry indexes in page order: required, optional, then game data,
    each in profile order."""
    return sorted(range(len(files)), key=lambda i: _SECTION_RANK[_card_section(files[i])])


def _html_words(fragment: str) -> int:
    """The words a browser shows for an HTML fragment, each tag a break."""
    return len(html.unescape(re.sub(r"<[^>]*>", " ", fragment)).split())


def _entry_row_words(files: list[dict], profile: dict,
                     available: Callable[[dict], bool]) -> list[int]:
    """The words each entry's row shows with its card closed: its title
    and its cells, an empty cell written "-" in a column another row of
    its section fills. A part's table drops a column its own rows leave
    empty: counted over the whole section, a row never shows more."""
    cells = [_entry_cells(f, profile, available) for f in files]
    filled: dict[str, set[int]] = {}
    for f, row in zip(files, cells):
        filled.setdefault(_card_section(f), set()).update(
            column for column, cell in enumerate(row) if cell)
    return [_html_words(_entry_label(f, profile)) + sum(
                _html_words(cell) or column in filled[_card_section(f)]
                for column, cell in enumerate(row))
            for f, row in zip(files, cells)]


def emulator_parts(name: str, files: list, profile: dict | None = None,
                   available: Callable[[dict], bool] | None = None,
                   ) -> list[tuple[str, list[int]]]:
    """The pages an emulator's cards go to, with the entries each holds,
    or none when they fit on the emulator's page. In page order, at most
    EMULATOR_PART_WORDS shown and EMULATOR_CARDS_PER_PART entries a part,
    the parts balanced by words. ``available`` is the page's own test of
    a held file, the status a row shows: without it every row is weighed
    "in repo", the longest status."""
    if len(files) <= EMULATOR_CARDS_PER_PAGE:
        return []
    profile = profile if profile is not None else {"files": files}
    order = _display_order(files)
    words = _entry_row_words(files, profile, available or (lambda _f: True))
    sizes = [words[i] for i in order]
    ceiling = max(EMULATOR_PART_WORDS, max(sizes))
    count = max(len(_parts(order, ceiling, sizes)), -(-len(files) // EMULATOR_CARDS_PER_PART))
    while True:
        # The fewest words a part can hold for the parts to be ``count``:
        # cut at the ceiling, the last part took what the others left.
        share = min(-(-sum(sizes) // count), ceiling)
        runs = _parts(order, share, sizes)
        while len(runs) > count:
            share = min(share + max(1, share // 50), ceiling)
            runs = _parts(order, share, sizes)
        if max(len(run) for run in runs) <= EMULATOR_CARDS_PER_PART:
            return [(f"{name}-files-{index}", run) for index, run in enumerate(runs, 1)]
        count += 1


# From this many entries an emulator page lists them as one table, each
# row opening to its card (siteentries.py). Below it the page is one
# screen of open cards. A summary table above folded cards listed every
# file twice: PCSX-ReARMed's seven, once in the table and once in a closed
# "7 files" block. A split emulator's card pages always use the table.
EMULATOR_TABLE_MIN = 6
ENTRY_HEADS = ["File", "Contents", "Status", "Hash"]
# The end of the badge _file_badges writes for an entry of each section.
_SECTION_BADGE = {"required": ">required</span>", "optional": ">optional</span>",
                  "with_app": ">comes with the app</span>"}


def _entry_rows(files: list[dict], cards: list[list[str]], profile: dict,
                available: Callable[[dict], bool]) -> list[siteentries.Row]:
    """Each entry as a table row: its card's title and body, the number of
    members an archive holds, its badges and its hash."""
    rows = []
    for f, card in zip(files, cards):
        title, body = siteentries.card_title_and_body(card)
        rows.append(siteentries.Row(title, body, _entry_cells(f, profile, available)))
    return rows


def _entry_cells(f: dict, profile: dict, available: Callable[[dict], bool]) -> list[str]:
    """An entry's cells beside its title: the members an archive holds,
    its badges and its hash."""
    many = len(profile.get("systems") or []) > 1
    for_system = system_name(str(f["system"])) if f.get("system") and many else ""
    contents = f.get("contents") or []
    badges = _file_badges(f, available(f), for_system)
    # The first badge says whether the entry is needed: under Required,
    # Optional or Comes with the app it repeats the section heading.
    # One element and two words fewer on each of MAME's 1,563 rows.
    if badges and badges[0].endswith(_SECTION_BADGE.get(_card_section(f), "\0")):
        badges = badges[1:]
    return [f"{len(contents):,}" if contents else "", " ".join(badges), _hash_short(f)]


def _entries_table(files: list[dict], group: list[int], rows: list[siteentries.Row]) -> list[str]:
    """The rows of ``group``, one section's entries, as one table."""
    key = _card_section(files[group[0]])
    heading = dict(CARD_SECTIONS)[key]
    return siteentries.entry_table([rows[i] for i in group], ENTRY_HEADS,
                                   f"rb-entry-filter-{key.replace('_', '-')}", heading,
                                   # The badges hide themselves from the search
                                   # but for the archive's name ("in pgm.zip"),
                                   # how a ZIP name finds the cores reading it.
                                   searched=frozenset({"Status"}))


def _sectioned(files: list, indexes: list[int],
               render: Callable[[list[int]], list[str]]) -> list[str]:
    """Each section's heading, then ``render`` of its entries among ``indexes``."""
    lines: list[str] = []
    for key, title in CARD_SECTIONS:
        group = [i for i in indexes if _card_section(files[i]) == key]
        if group:
            lines.extend([f"## {title}", "", *render(group)])
    return lines


def _hash_short(f: dict) -> str:
    """The shortest way to tell two dumps apart in a table: the first 12
    characters of an md5, crc32 or sha1, the whole value in its title."""
    for field in ("md5", "crc32", "sha1"):
        value = f.get(field)
        value = value[0] if isinstance(value, list) and value else value
        if value:
            full = html.escape(str(value).lower().split(",")[0].strip().removeprefix("0x"))
            # Kept on one line: the label above the value doubled each row.
            return f'{field.upper()}\u00a0<code title="{full}">{full[:12]}</code>'
    return ""


def _summary_table(files: list[dict], indexes: list[int], cell: Callable[[int, str], str],
                   multi_system: bool = False) -> list[str]:
    """The table of an emulator's entries, one row each, ``cell`` writing
    the linked name of entry i from its shown path.

    A column every row leaves empty is not written: AetherSX2's Region
    column held "-" on every row and pushed Required off a phone screen.
    Nor is Required when every row gives the same answer, which the
    section heading or the count above already says: in MAME's index it
    turned 1,564 rows into label and value pairs on a phone.
    """
    rows = []
    for i in indexes:
        f = files[i]
        needed = "with the app" if comes_with_app(f) else "yes" if f.get("required") else "no"
        if needed == "yes" and multi_system and f.get("system"):
            needed = f"for {system_name(str(f['system']))}"
        rows.append((cell(i, str(f.get("path") or f.get("name", ""))),
                     _region_words(f.get("region"), 3), needed, _hash_short(f)))
    keep = [0] + [column for column in (1, 3) if any(row[column] for row in rows)]
    if len({row[2] for row in rows}) > 1:
        keep.append(2)
    keep.sort()
    heads = ("File", "Region", "Required", "Hash")
    return [
        "| " + " | ".join(heads[c] for c in keep) + " |",
        "|" + "|".join("------" for _c in keep) + "|",
        *("| " + " | ".join(row[c] or "-" for c in keep) + " |" for row in rows),
    ]


def plan_emulator_pages(profiles: dict,
                        available: Callable[[dict], bool] | None = None) -> None:
    """Record which page holds each emulator card, before any page links one.
    ``available`` is the test the pages use for a held file."""
    stems = set()
    for name, profile in sorted(profiles.items()):
        if profile.get("type") == "alias" or profile.get("role") == "test":
            continue
        files = profile.get("files") or []
        anchors = emulator_file_anchors(files)
        for stem, entries in emulator_parts(name, files, profile, available):
            stems.add(stem)
            record_emulator_cards(name, stem, [anchors[i] for i in entries])
    clash = stems & set(profiles)
    if clash:
        raise RuntimeError(f"an emulator's card page takes a profile's address: {sorted(clash)}")


def generate_emulator_page(
    name: str,
    profile: dict,
    db: dict,
    consumers: FileConsumers | None = None,
    data_names: set[str] | None = None,
    data_registry: dict | None = None,
    data_dirs: list[dict] | None = None,
) -> str:
    """One emulator's page. ``data_dirs`` defaults to the profile's own."""
    return emulator_pages(
        name, profile, db, consumers, data_names, data_registry, data_dirs)[name]


def any_name_bios(profile: dict) -> dict | None:
    """The one BIOS an emulator needs under any name, or None.

    A profile found by content (`found_by: content`, `bios_mode: agnostic`)
    for one system, with one required file of no declared region: the
    code identifies the image by what it holds, so the entry's name is an
    example. AetherSX2's page showed `bios/ps2-0230a-20080220.bin` as the
    file to get, while its notes say no name and no hash is matched.
    """
    if profile.get("found_by") != "content" and profile.get("bios_mode") != "agnostic":
        return None
    if len(profile.get("systems") or []) != 1:
        return None
    required = [f for f in profile.get("files") or []
                if isinstance(f, dict) and f.get("required") is True and not comes_with_app(f)]
    if len(required) != 1 or required[0].get("region") or required[0].get("category") not in (None, "bios"):
        return None
    return required[0]


def _collection_card_href(entry: dict, consumers: FileConsumers | None, owner: str) -> str:
    """The collection card of the copy that answers an emulator entry, or ""."""
    if consumers is None:
        return ""
    sha1 = consumers.sha1_of(entry, entry.get("path") or "", owner=owner)
    held = consumers.path_of(sha1) if sha1 else ""
    if not held.startswith("bios/"):
        return ""
    return f"../systems/{urllib.parse.quote(card_page(held, sha1))}.md#sha1-{sha1[:12]}"


def _named_example(name: str) -> bool:
    """A real file name, not a placeholder such as `<bios>.bin`."""
    return bool(name) and "<" not in name


def _any_name_folder(profile: dict, entry: dict) -> str:
    """Where the one BIOS goes, as the profile states it, or ""."""
    folder = str(profile.get("bios_directory") or "")
    if not folder:
        path = str(entry.get("path") or "")
        folder = path.rsplit("/", 1)[0] + "/" if "/" in path else ""
    if not folder:
        return ""
    if profile.get("type") == "standalone":
        # A bare `bios/` is a folder inside the app's own data folder.
        own = ("[the app's data folder](#data-folder)" if profile.get("data_root")
               else "the app's own data folder")
        return f"the {_code(folder.strip('/'))} folder inside {own}"
    return f"{_code(folder)}, inside the BIOS folder"


def _any_name_steps(emu_name: str, profile: dict, entry: dict, href: str,
                    name: str = "") -> str:
    """The intro of an emulator that takes one BIOS of any name: get one,
    put it in its folder, any name works.

    An app whose profile names its data folder gets that folder, one tab
    per system it runs on: AetherSX2's step said "inside the app's own
    data folder" while the profile cites Android/data/xyz.aethersx2.android.
    """
    system = system_name((profile.get("systems") or [""])[0])
    example = str(entry.get("name") or "")
    if _named_example(example) and href:
        get = f"Download [{_code(example)}]({href})."
    else:
        get = f"Get one from the {_named_system_link(profile['systems'][0], '../')} files."
    steps = [get]
    folders: list[str] = []
    if profile.get("type") == "standalone" and standalone_place(name, profile, entry):
        steps.append("Put it in this folder:")
        folders = ['<div id="data-folder" class="rb-anchor"></div>', "",
                   *data_folder_block(name, profile, [entry])]
    else:
        folder = _any_name_folder(profile, entry)
        if folder:
            steps.append(f"Put it in {folder}.")
        folders = _data_folder_intro(name, profile)
    reader = "The app" if profile.get("type") == "standalone" else "The emulator"
    return "\n".join([
        f"{emu_name} needs one {system} BIOS file, any region.",
        "",
        *(f"{number}. {step}" for number, step in enumerate(steps, 1)),
        "",
        *folders,
        *([""] if folders and folders[-1] else []),
        f"Any file name works. {reader} reads what the file holds.",
    ])


def _data_folder_intro(name: str, profile: dict) -> list[str]:
    """Where the app keeps its files, under the intro of a profile that
    names its data folder and takes more than one BIOS of any name."""
    if not profile.get("data_root"):
        return []
    files = [f for f in profile.get("files") or [] if isinstance(f, dict)]
    placed = [f for f in files if standalone_place(name, profile, f)]
    subject = ("The app" if profile.get("type") == "standalone"
               else "Run on its own, the app")
    lead = (f"{subject} reads its files from this folder:" if placed
            else f"{subject} keeps its data in this folder:")
    return ['<div id="data-folder" class="rb-anchor"></div>', "", lead, "",
            *data_folder_block(name, profile, files)]


def _emulator_intro(emu_name: str, profile: dict, href: str = "", name: str = "") -> str:
    """What the emulator needs, in plain words, from fields every profile has.

    The page opened on a twelve-row table: "Type", "Version", "Checked by".
    DuckStation needs one PlayStation BIOS of any name, and the reader had
    to infer it from the "Files found by" row. ``href`` links the
    collection's copy of the one BIOS an emulator takes under any name,
    and ``name`` is the profile's key.
    """
    entry = any_name_bios(profile)
    if entry is not None:
        return _any_name_steps(emu_name, profile, entry, href, name)
    names: list[str] = []
    for sys_id in profile.get("systems") or []:
        label = system_name(sys_id)
        if label not in names:
            names.append(label)
    # What the app installs itself is no file for the reader to get.
    files = [f for f in profile.get("files") or [] if isinstance(f, dict) and not comes_with_app(f)]
    requirements = _requirements(files, profile.get("groups"))
    required = [f for members in requirements for f in members]
    sentences = []
    if names:
        shown = names if len(names) <= 4 else names[:3] + [f"{len(names) - 3} more systems"]
        sentences.append(f"{emu_name} emulates {_said_as_list(shown)}.")
    regional = _regional_set(requirements)
    by_region = "" if regional else _regional_choice(required)
    others = len(files) - len(required)
    if regional:
        # DuckStation needs one BIOS of the game's region and accepts 105
        # images: every member of its ps-bios set is marked required, and
        # the page said "105 of them required".
        sentences.append(
            f"It needs one BIOS for the game's region, among the {len(regional):,} it accepts.")
        if others:
            sentences.append(
                f"The {_count(others, 'other file')} {'is' if others == 1 else 'are'} optional.")
    elif by_region:
        # Three required BIOS of three regions: the page said "3 of them
        # required" and read as "get all of these".
        sentences.append(f"It picks the BIOS for the game's region: {by_region}.")
        if others:
            sentences.append(
                f"The {_count(others, 'other file')} {'is' if others == 1 else 'are'} optional.")
    elif files:
        sentences.append(
            f"It reads {_count(len(files), 'file')}, {len(requirements):,} of them required: "
            "without a required file it does not start games."
            if requirements else
            f"It reads {_count(len(files), 'file')}, none of them required: it starts "
            "games without them."
        )
        if any(len(members) > 1 for members in requirements):
            sentences.append("Any one file of a required set fills it.")
    if required and len(names) > 1:
        sentences.append("A required file is needed only by the machines that use it.")
        if profile.get("found_by") == "content":
            sentences.append("It recognises a file by its contents, so any file name works.")
        if any(f.get("source_ref") for f in files):
            sentences.append("Each file below cites the line of source code that reads it.")
    folder = _data_folder_intro(name, profile) if name else []
    return "\n".join([" ".join(sentences), "", *folder]).strip("\n")


def _regional_choice(required: list[dict], most: int = 6) -> str:
    """The required files as one choice by region, or "" when they are not one.

    Only when every required entry carries a region: and they name at least
    two: region: is the territory the code selects the file for, so the
    reader needs the one of the game's region.
    """
    if not required or len(required) > most or not all(f.get("region") for f in required):
        return ""
    if len({_region_words(f["region"]) for f in required}) < 2:
        return ""
    choices = [f"{f.get('name', '')} ({_region_words(f['region'], 3)})" for f in required]
    return ", ".join(choices[:-1]) + f" or {choices[-1]}"


def emulator_pages(
    name: str,
    profile: dict,
    db: dict,
    consumers: FileConsumers | None = None,
    data_names: set[str] | None = None,
    data_registry: dict | None = None,
    data_dirs: list[dict] | None = None,
) -> dict[str, str]:
    """An emulator's page by stem under emulators/, and the pages its cards
    went to when there are more than EMULATOR_CARDS_PER_PAGE."""
    if profile.get("type") == "alias":
        parent = profile.get("alias_of", profile.get("bios_identical_to", "unknown"))
        return {name: (
            f"# {name}\n\n"
            f"This core uses the same firmware as **{parent}**.\n\n"
            f"See [{parent}]({parent}.md) for details.\n"
        )}

    emu_name = profile.get("emulator", name)
    emu_type = profile.get("type", "unknown")
    classification = profile.get("core_classification", "")
    source_raw = profile.get("source", "")
    source = str(source_raw) if not isinstance(source_raw, dict) else ""
    # A key set to null says there is none (the project is its own upstream,
    # it publishes no version), and an absent key says nobody wrote it down. The
    # page printed `None` for the first, which read as the second.
    upstream_raw = profile.get("upstream", "")
    upstream_none = "upstream" in profile and upstream_raw is None
    upstream = str(upstream_raw) if isinstance(upstream_raw, str) else ""
    version = version_markdown(profile)
    profiled = profile.get("profiled_date", "unknown")
    systems = profile.get("systems", [])
    cores = profile.get("cores", [name])
    files = profile.get("files", [])
    notes_raw = profile.get("notes", profile.get("note", ""))
    notes = (
        str(notes_raw).strip() if notes_raw and not isinstance(notes_raw, dict) else ""
    )
    exclusion = profile.get("exclusion_note", "")
    if data_dirs is None:
        data_dirs = profile.get("data_directories", [])

    part_pages: dict[str, str] = {}
    one_bios = any_name_bios(profile)
    intro = _emulator_intro(emu_name, profile, _collection_card_href(
        one_bios, consumers, name) if one_bios else "", name)
    romset = emulator_romset(profile)
    lines = [
        f"# {emu_name}",
        "",
        *([intro, ""] if intro else []),
    ]
    if romset:
        # The commonest arcade failure is a set from another MAME version,
        # and its answer sat on a Reference page no arcade page linked.
        # FinalBurn profiles list the members of their archives, not the
        # archives, and MAME 2003-Plus none at all: the line went missing
        # on both.
        lines.extend([f"Its BIOS and game sets must come from the {romset} romset. "
                      f"[Which version each core reads]({ROMSET_FAQ}).", ""])
    card_start = len(lines)
    lines += [
        markup.block_open("div", 'class="rb-meta-card"'),
        "",
        "| Detail | Value |",
        "|---|---|",
        f"| Type | {emu_type} |",
    ]
    if classification:
        cls_display = CLS_LABEL_ONE.get(classification, classification)
        lines.append(f"| Classification | {cls_display} |")
    if isinstance(source_raw, dict):
        parts = []
        for k, v in source_raw.items():
            if isinstance(v, str) and v.startswith("http"):
                parts.append(f"[{k}]({v})")
            else:
                parts.append(f"{k}: {v}")
        lines.append(f"| Source | {', '.join(parts)} |")
    elif source:
        if source.startswith("http"):
            lines.append(f"| Source | [{source}]({source}) |")
        else:
            lines.append(f"| Source | {source} |")
    if isinstance(upstream_raw, dict):
        parts = []
        for k, v in upstream_raw.items():
            if isinstance(v, str) and v.startswith("http"):
                parts.append(f"[{k}]({v})")
            else:
                parts.append(f"{k}: {v}")
        lines.append(f"| Upstream | {', '.join(parts)} |")
    elif upstream_none:
        lines.append("| Upstream | none: the source is the project itself |")
    elif upstream and upstream != source:
        if upstream.startswith("http"):
            lines.append(f"| Upstream | [{upstream}]({upstream}) |")
        else:
            lines.append(f"| Upstream | {upstream} |")
    gone = profile.get("upstream_gone")
    if gone:
        # The links above answer 451 or reach a domain someone else now
        # owns: said beside them, with the date the profile observed it.
        lines.append(f"| Source status | gone: {_escape_tags(str(gone))} |")
    mirror = profile.get("source_mirror")
    if mirror:
        lines.append(f"| Mirror | [{mirror}]({mirror}) |" if str(mirror).startswith("http")
                     else f"| Mirror | {mirror} |")
    lines.append(f"| Version | {version} |")
    revision = revision_markdown(profile)
    if revision:
        lines.append(f"| Revision | {revision} |")
    lines.extend(_build_rows(profile))
    setups = _EMULATOR_SETUPS.get(name)
    if setups:
        # The file cards name the setups whose own list holds a file: the
        # ones that run the emulator and pack its files were said nowhere.
        # Said once here: a line on each card put MAME's parts and four
        # other pages over their element budget. Out of the search: setup
        # names on 530 pages ranked the data page first for "batocera folder".
        lines.append(f"| Run by | <span {markup.search_exclude()}>" + ", ".join(
            f"[{_platform_display(p)}](../platforms/{p}.md)" for p in setups) + "</span> |")
    lines.append(f"| Profiled | {profiled} |")
    # The YAML is the reusable document this site renders, and the JSON is the
    # same profile for a program.
    lines.append(
        f"| Profile | [YAML]({REPO_URL}/blob/main/emulators/{name}.yml), "
        f"[JSON](../api/v1/emulators/{name}.json) |"
    )
    if cores:
        lines.append(f"| Cores | {', '.join(_distinct_spellings(cores))} |")
    if systems:
        sys_links = list(dict.fromkeys(_named_system_link(s, "../") for s in systems))
        lines.append(f"| Systems | {', '.join(sys_links)} |")
    author = profile.get("author", "")
    if author:
        lines.append(f"| Author | {author} |")
    based_on = profile.get("based_on", "")
    if based_on:
        lines.append(f"| Based on | {based_on} |")
    lines.extend(_render_metadata_rows(profile))
    lines.append("")
    lines.append("</div>")
    lines.append("")
    # Reference for the few who check a revision: stacked on a phone, the
    # card took two screens above the files.
    lines[card_start:] = markup.details("note", "About this profile", lines[card_start:])

    lines.extend(_install_block(name, profile))

    lines.extend(_render_platform_details(profile))

    if notes:
        body = _admonition_body(data_root_words(link_prose_citations(profile, notes))
                                ).replace("\n    ", "\n")
        lines.extend(markup.details("note", "Technical notes", body.split("\n")))

    if not files:
        lines.append("No BIOS or firmware files required.")
        if exclusion:
            lines.append("")
            lines.extend(markup.aside("info", "Why no files", [_escape_tags(str(exclusion))])[:-1])
    else:
        _file_available = _availability_check(db, data_names, name)

        lines.extend(["## Files", ""])
        lines.extend(_emulator_file_summary(files, profile.get("groups")))
        held = _emulator_held_line(files, _file_available)

        anchors = emulator_file_anchors(files)
        aliases = emulator_file_aliases(files, anchors)
        parts = emulator_parts(name, files, profile, _file_available)
        data_href = f"{name}.md#data-folder" if parts else "#data-folder"
        table_form = markup.starlight() and (bool(parts) or len(files) >= EMULATOR_TABLE_MIN)
        cards = [
            _render_emulator_file(f, profile, consumers, files, _file_available, anchor, name,
                                  alias, data_href, badges_apart=table_form)
            for f, anchor, alias in zip(files, anchors, aliases)
        ]
        rows = (_entry_rows(files, cards, profile, _file_available) if table_form else [])
        if not parts and table_form:
            lines.extend(held)
            lines.extend(_sectioned(files, _display_order(files),
                                    lambda group: _entries_table(files, group, rows)))
        elif not parts:
            lines.extend(held)
            lines.extend(_sectioned(files, _display_order(files),
                                    lambda group: [line for i in group for line in cards[i]]))
        else:
            lines.extend(_card_index(emu_name, files, anchors, aliases, parts,
                                     len(systems or []) > 1))
            lines.extend(held)
            for number, (stem, entries) in enumerate(parts, 1):
                part_pages[stem] = _emulator_part_page(
                    name, emu_name, number, parts, [cards[i] for i in entries],
                    [files[i] for i in entries],
                    [rows[i] for i in entries] if table_form else None)

    lines.extend(sitemeasurements.proof_section(_MEASUREMENT_ITEMS.get(name, [])))

    blocks = _render_structured_blocks(profile)
    if blocks:
        lines.extend(["## Profile data", "", *blocks])

    if data_dirs:
        # The member tables are a file list with hashes: out of the search,
        # dolphin, primehack and ishiiruka each put 210 KB of it there.
        lines.extend([
            "## Data directories",
            "",
        ])
        trees_start = len(lines)
        member_anchors: set[str] = set()
        # Each tree with what it holds, where it comes from, which build reads
        # it and the code that does: these trees put thousands of files in
        # the packs, and the page said only `dolphin-sys` > `Sys`.
        for dd in data_dirs:
            ref = dd.get("ref", "")
            dest = dd.get("destination", "")
            entry = (data_registry or {}).get(ref, {})
            # An empty destination wrote "``", which opened a code span
            # running to the next one and hid a link from the MDX pass.
            line = f"- `{ref}` > `{dest}`" if dest else f"- `{ref}`"
            if entry.get("description"):
                line += f": {entry['description']}"
            lines.append(line)
            lines.extend(f"    - {line}" for line in data_directory_origin(
                entry, _DATA_REVISIONS.get(ref) or {}))
            if dd.get("mode"):
                lines.append(f"    - Read by the {dd['mode']} build only")
            if dd.get("bundled"):
                lines.append("    - Installed with the emulator, so packs leave it out")
            if dd.get("source_ref"):
                lines.append(f"    - Source: {_source_ref_markdown(profile, dd['source_ref'])}")
            members = _DATA_MEMBERS.get(ref) or {}
            tree_pages = data_tree_pages(ref, members)
            if tree_pages:
                where = (f"[a page of their own]({tree_pages[0][0]}.md)" if len(tree_pages) == 1
                         else "pages of their own: " + ", ".join(
                             f"[part {i}]({stem}.md)" for i, (stem, _names) in enumerate(tree_pages, 1)))
                lines.append(f"    - {_count(len(members), 'file')}, listed on {where}")
                for index, (stem, _names) in enumerate(tree_pages):
                    part_pages[stem] = _data_tree_page(ref, entry, tree_pages, index)
            elif members:
                table = _data_member_table(members, sorted(members), member_anchors)
                lines.append("")
                lines.extend(markup.details(
                    "info", f"{_count(len(members), 'file')}, as the packs ship them",
                    table, indent="    "))
        lines.append("")
        # The member tables are the lookup's.
        lines[trees_start:] = search_excluded(lines[trees_start:])

    lines.extend(_next_block([
        "[Get the files](../which-pack.md), for the setup in use",
        "[Every system](../systems/index.md), and the files each one needs",
        "[When a game does not start](../wiki/troubleshooting.md)",
    ]))
    lines.extend(["", _date_line()])
    return {name: "\n".join(lines) + "\n", **part_pages}


def _card_index(
    emu_name: str, files: list[dict], anchors: list[str], aliases: list[str],
    parts: list[tuple[str, range]], multi_system: bool = False,
) -> list[str]:
    """Every entry of a split emulator page, one row each, linked to its card.

    Each row holds the ids the card had on this page, so a link cited
    before the split lands on the row, and site.js follows it to the card.
    """
    page_of = {index: stem for stem, entries in parts for index in entries}

    def cell(i: int, shown: str) -> str:
        # The id sits on the link itself, one element fewer per row: MAME's
        # 1,564 rows put 13,300 elements on its page.
        href = markup.site_href(f"emulators/{page_of[i]}/#{anchors[i]}")
        alias = f'<span id="{aliases[i]}"></span>' if aliases[i] else ""
        return (f'{alias}<a id="{anchors[i]}" href="{href}">'
                f"<code>{html.escape(shown, quote=False)}</code></a>")

    def table(group: list[int]) -> list[str]:
        return [
            markup.block_open("section", f'class="rb-card-index" {markup.search_exclude()}'),
            "", *_summary_table(files, group, cell, multi_system), "", "</section>", "",
        ]

    return [
        f"{emu_name} reads more files than one page holds: each entry below "
        f"links to its card, on {_count(len(parts), 'page')}: "
        + ", ".join(f"[{number}]({stem}.md)" for number, (stem, _e) in enumerate(parts, 1))
        + ".",
        "",
        *_sectioned(files, _display_order(files), table),
    ]


def _part_front_matter(parent: tuple[str, str], siblings: list[tuple[str, str]],
                       index: int, front: dict | None = None) -> list[str]:
    """The front matter of part ``index`` of ``siblings`` ((label, link)
    each): the page it belongs to, its neighbours and the part weight.

    MAME's eight card pages had no parent, so the crumbs skipped MAME, and
    `prev: false`, so part 5 reached part 6 only through a sentence.
    The first part's previous page is the parent, the last part has no next.
    """
    data = dict(front or {})
    data["parent"] = {"label": parent[0], "link": parent[1]}
    before = siblings[index - 1] if index > 0 else parent
    data["prev"] = {"label": before[0], "link": before[1]}
    data["next"] = ({"label": siblings[index + 1][0], "link": siblings[index + 1][1]}
                    if index + 1 < len(siblings) else False)
    data["searchWeight"] = SEARCH_WEIGHT.get("part", DEMOTED_WEIGHT)
    return ["---", yaml.safe_dump(data, sort_keys=False, allow_unicode=True).rstrip("\n"),
            "---", ""]


def _emulator_part_page(
    name: str, emu_name: str, number: int, parts: list[tuple[str, range]],
    cards: list[list[str]], files: list[dict], rows: list[siteentries.Row] | None = None,
) -> str:
    """One page of a split emulator's cards: with ``rows``, one table row
    each, the card under its name."""
    if rows is not None:
        def render(group: list[int]) -> list[str]:
            return _entries_table(files, group, rows)
    else:
        def render(group: list[int]) -> list[str]:
            return [line for i in group for line in cards[i]]
    first = str(files[0].get("path") or files[0].get("name", ""))
    last = str(files[-1].get("path") or files[-1].get("name", ""))
    others = ", ".join(
        f"[{n}]({stem}.md)" for n, (stem, _e) in enumerate(parts, 1) if n != number)
    lines = [
        *_part_front_matter((emu_name, f"{name}.md"),
                            [(f"{emu_name} files, part {n}", f"{stem}.md")
                             for n, (stem, _e) in enumerate(parts, 1)], number - 1),
        f"# {emu_name} files, part {number} of {len(parts)}",
        "",
        # The crumbs end on the emulator, read from parent:.
        f"This part holds {_count(len(files), 'entry', 'entries')}, "
        f"{_code(first)} to {_code(last)}. The other parts: {others}.",
        "",
        *_sectioned(files, list(range(len(files))), render),
    ]
    lines.extend(_next_block([f"[{emu_name}]({name}.md), the profile and every entry"]))
    lines.extend(["", _date_line()])
    return "\n".join(lines) + "\n"


# Contributing page


_ACCEPTED_RE = re.compile(r"\b(sha1|sha256|md5|crc32) mismatch: got \S+, accepted \[([^\]]*)\]")


def _held_accepted(discrepancy: str, db: dict | None) -> str:
    """Where the collection keeps a dump the emulator accepts, if it does.

    The table printed the hash the emulator wants and stopped there, while
    the collection held that exact dump for every one of the ten rows.
    """
    match = _ACCEPTED_RE.search(discrepancy or "")
    if not match or not db:
        return ""
    algo, accepted = match.group(1), match.group(2)
    indexes = db.get("indexes", {})
    for value in re.split(r"[\s,]+", accepted.lower()):
        if algo == "sha1":
            sha1 = value if value in db.get("files", {}) else None
        else:
            sha1 = indexes.get(f"by_{algo}", {}).get(value)
        path = db.get("files", {}).get(sha1 or "", {}).get("path")
        if path:
            return path
    return ""


_PROBLEM_HASHES = ("sha1", "md5", "sha256", "crc32")


def _declared_hashes(config: dict, detail: dict) -> dict[str, list[str]]:
    """The hashes the platform declares for a reported file, by algorithm.

    The untested table said "declared hash contradicted by the local file"
    and named neither: the reader could not look for the dump RetroDECK asks
    for, nor report the difference.
    """
    from hashing import parse_hash_list  # noqa: PLC0415

    system = (config.get("systems") or {}).get(detail.get("system", "")) or {}
    for entry in system.get("files") or []:
        if isinstance(entry, dict) and entry.get("name") == detail.get("name"):
            return {
                algo: parse_hash_list(entry.get(algo))
                for algo in _PROBLEM_HASHES if parse_hash_list(entry.get(algo))
            }
    return {}


def _declared_destination(config: dict, detail: dict) -> str:
    """Where the platform's list puts a reported file, its name when the
    entry names no folder."""
    system = (config.get("systems") or {}).get(detail.get("system", "")) or {}
    for entry in system.get("files") or []:
        if isinstance(entry, dict) and entry.get("name") == detail.get("name"):
            return str(entry.get("destination") or detail.get("name", ""))
    return str(detail.get("name", ""))


def short_hash(value: str) -> str:
    """A hash in a table cell: its first 12 characters, the whole value in
    the title. Full MD5 and SHA1 values pushed the gaps tables past the
    column on every screen."""
    value = str(value)
    if len(value) <= 12:
        return _code(value)
    return f'<code title="{html.escape(value)}">{html.escape(value[:12])}</code>'


def _hash_cell(hashes: dict[str, list[str]]) -> str:
    return "<br>".join(
        f"{algo} " + ", ".join(short_hash(v) for v in values) for algo, values in hashes.items()
    )


def _unsourceable_line(f: dict) -> str:
    """Why the collection holds no copy of a file a profile marks
    `unsourceable:`, linked to the list of them. The flag only keeps a
    same-named file from being served in its place: the file is still
    wanted, and "Not collectable" sent readers away from KANJI2.ROM, which
    MAME's fm7740sx.zip carries."""
    return (f"Not collected yet: {_escape_tags(str(f['unsourceable']))} "
            "([files not collected yet](../gaps.md#not-collected-yet))")


def _catalogued_needs(report: dict | None) -> dict[tuple[str, str], list[str]]:
    """(profile, file name casefolded) -> where a dump catalog or an
    imported romset lists that file, from a provenance report built with
    the profiles' needs."""
    out: dict[tuple[str, str], list[str]] = {}
    for source, data in sorted((report or {}).items()):
        label = _PROVENANCE_LABELS.get(source, source)
        for entry in data.get("missing", []):
            where = [f"{label} `{_escape_tags(str(entry.get('name', '')))}`"]
            where += [f"{_escape_tags(str(hit['source']))} `{_escape_tags(str(hit['archive']))}`"
                      for hit in entry.get("romsets", [])]
            for need in entry.get("needed_by", []):
                held = out.setdefault((need["emulator"], str(need["name"]).casefold()), [])
                held += [w for w in where if w not in held]
    return out


def _reason_cell(text: str) -> str:
    """A reason in a gaps table, in the class that keeps its column readable."""
    return f'<span class="rb-reason">{text}</span>' if text else "-"


def _copy_cell(path: str, algos: list[str], db: dict | None) -> str:
    """The file a path holds, with its hashes in the algorithms declared."""
    if not path:
        return "-"
    record = next(
        (rec | {"sha1": sha1} for sha1, rec in (db or {}).get("files", {}).items()
         if rec.get("path") == path),
        {},
    )
    hashes = {algo: [str(record[algo]).lower()] for algo in algos if record.get(algo)}
    shown = f"[{_code(path)}]({_fetch_url(path)})"
    return f"{shown}<br>{_hash_cell(hashes)}" if hashes else shown


def _render_problem_files(
    platform_problems: list, settled: list | None = None, db: dict | None = None,
    missing_total: int | None = None,
) -> list[str]:
    """Files a platform declares that its own check then rejects.

    Split out of generate_gap_analysis, which reached complexity 56. This
    section is the one that stands alone: it reads platform_problems and
    nothing else, where the sections around it share gap_report and the
    resolved core list.
    """
    lines: list[str] = []
    # ---- Section 2: Problem files ----

    missing_files: dict[str, dict] = {}
    untested_files: dict[str, dict] = {}
    mismatch_files: dict[str, dict] = {}

    for p in platform_problems:
        fname = p["name"]
        if p["status"] == "missing":
            entry = missing_files.setdefault(fname, {
                "name": fname, "required": p["required"],
                "platforms": [], "reason": p["reason"], "categories": set(),
                "where": {},
            })
            entry["platforms"].append(p["platform"])
            # The platform's entry for the file, and the folder it expects.
            entry["where"].setdefault(
                (p["platform"], p.get("platform_key", ""), p.get("system", "")), set(),
            ).add(p.get("destination") or fname)
            entry["categories"].add(p.get("category", "bios"))
            if p["required"]:
                entry["required"] = True
        elif p["status"] == "untested":
            # Keyed by what is declared and what is held: two platforms
            # asking two dumps under one name are two rows.
            declared = p.get("declared") or {}
            key = f"{fname}\0{sorted(declared.items())}\0{p.get('path', '')}"
            entry = untested_files.setdefault(key, {
                "name": fname, "required": p["required"],
                "platforms": [], "reason": p["reason"],
                "declared": declared, "path": p.get("path", ""),
            })
            entry["platforms"].append(p["platform"])
        if p.get("discrepancy"):
            entry = mismatch_files.setdefault(fname, {
                "name": fname, "platforms": [],
                "discrepancy": p["discrepancy"],
            })
            entry["platforms"].append(p["platform"])

    total_problems = len(missing_files) + len(untested_files) + len(mismatch_files)
    # One row per name: the page opened on "48 are missing", counted by
    # destination, above a heading that said "10 files". Both are said.
    names = _count(len(missing_files), "name")
    missing_said = (f"{missing_total:,} missing under {names}"
                    if missing_total is not None else f"{len(missing_files)} missing")

    if total_problems > 0:
        lines.extend([
            "## Problem files",
            "",
            f"{missing_said}, {len(untested_files)} untested, "
            f"{len(mismatch_files)} discrepancy.",
            "",
        ])

        if missing_files:
            lines.extend([
                f'### Missing <span class="rb-badge rb-badge-danger">'
                f"{_count(len(missing_files), 'name')}</span>",
                "",
                "Required is the platform's own flag. Category says what the "
                "platform's emulators do with the file: `bios` is firmware they "
                "load, `game_data` comes from a copy of the game, `unread` is "
                "opened by none of them. Only a missing `bios` entry stops a "
                "console from starting. A name a list declares in several "
                "folders is one row. Each platform links to its entry, which "
                "names the cores examined, and is followed by where its list "
                "puts the file.",
                "",
                "| File | Category | Required | Platforms |",
                "|------|----------|----------|-----------|",
            ])
            for fname in sorted(missing_files):
                f = missing_files[fname]
                req = "yes" if f["required"] else "no"
                plats = "; ".join(
                    (f"[{display}](platforms/{key}.md#{system.replace(' ', '-')})"
                     if key and system else display)
                    + " " + ", ".join(_code(dest) for dest in sorted(dests))
                    for (display, key, system), dests in sorted(f["where"].items())
                )
                cats = f["categories"]
                category = "bios" if "bios" in cats else ", ".join(sorted(cats))
                lines.append(f"| `{fname}` | {category} | {req} | {plats} |")
            lines.append("")

        if untested_files:
            lines.extend([
                f'### Untested <span class="rb-badge rb-badge-warning">'
                f"{_count(len(untested_files), 'file')}</span>",
                "",
                "Present, but not the expected hash. Declared is what the platform "
                "asks for, the collection copy is what the path holds.",
                "",
                "| File | Platforms | Reason | Declared | Collection copy |",
                "|------|----------|--------|----------|-----------------|",
            ])
            for key in sorted(untested_files):
                f = untested_files[key]
                plats = ", ".join(sorted(set(f["platforms"])))
                declared = f["declared"]
                lines.append(
                    f"| {_code(f['name'])} | {plats} | {_reason_cell(f['reason'])} "
                    f"| {_hash_cell(declared) or '-'} "
                    f"| {_copy_cell(f['path'], list(declared) or ['md5'], db)} |"
                )
            lines.append("")

        if mismatch_files:
            lines.extend([
                f'### Discrepancy <span class="rb-badge rb-badge-warning">'
                f"{_count(len(mismatch_files), 'file')}</span>",
                "",
                "The platform's own check passes, but the emulator's size or "
                "hash check fails. Each row names the check that fails.",
                "",
                "| File | Platforms | Discrepancy | Accepted dump in the collection |",
                "|------|----------|-------------|-------------------|",
            ])
            for fname in sorted(mismatch_files):
                f = mismatch_files[fname]
                plats = ", ".join(sorted(set(f["platforms"])))
                held = _held_accepted(f["discrepancy"], db)
                cell = f"[{_code(held)}]({_fetch_url(held)})" if held else "-"
                lines.append(f"| `{fname}` | {plats} | {_reason_cell(f['discrepancy'])} | {cell} |")
            lines.append("")

    if settled:
        lines.extend([
            "### Other revisions of a held destination",
            "",
            "A platform can declare one path twice with different hashes. The "
            "path holds the file one declaration accepts, so it is counted once, "
            "as held. The other declaration cannot be met at the same time.",
            "",
            "| File | Platform | Status | Path held for system |",
            "|------|----------|--------|--------------|",
        ])
        for p in sorted(settled, key=lambda row: (row["name"], row["platform"])):
            lines.append(
                f"| {_code(p['name'])} | {_escape_tags(p['platform'])} | {p['status']} "
                f"| {_code(p['held_by'])} |"
            )
        lines.append("")

    return lines


def _platform_lists_sentence(
    total: int, verified: int, untested: int, missing: int,
    not_firmware: dict[str, int] | None = None,
) -> str:
    """The platforms' own lists in one sentence, every count said.

    Four tiles opened the page: "Verified (100%)" for 5,437 of 5,438 and
    "Missing 0", above a table of red cells, on the page about what is
    missing. The gaps are in the files the emulators load, and the sentence
    says so. The missing count then read as missing firmware, while every
    entry behind it was game data or a file no emulator opens: the split by
    category is said with it.
    """
    def _is(count: int) -> str:
        return "is" if count == 1 else "are"

    not_firmware = {k: v for k, v in (not_firmware or {}).items() if v}
    parts = [f"{verified:,} {_is(verified)} held and pass the platform's own check"]
    if untested:
        parts.append(f"{untested:,} {_is(untested)} held but not verified "
                     "(listed under Untested below)")
    parts.append(f"{missing:,} {_is(missing)} missing")
    listed = ", ".join(parts[:-1]) + f" and {parts[-1]}"
    split = ""
    if missing and not_firmware:
        labels = {"game_data": "game data",
                  "unread": "opened by none of the platform's emulators"}
        firmware = missing - sum(not_firmware.values())
        others = [
            f"{count:,} {'is' if count == 1 else 'are'} {labels.get(category, category)}"
            for category, count in sorted(not_firmware.items())
        ]
        others_text = others[0] if len(others) == 1 else ", ".join(others[:-1]) + f" and {others[-1]}"
        head = (f"None of the missing is firmware: {others_text}" if not firmware
                else f"Of the missing, {firmware:,} {'is' if firmware == 1 else 'are'} "
                     f"firmware, {others_text}")
        split = f" {head}. Only missing firmware stops a console from starting."
    return (
        f"Of the {total:,} files on the platforms' own BIOS lists, {listed}.{split} "
        "The files the emulators load beyond those lists are counted per "
        "platform in the table below."
    )


def _missing_required_firmware(cov: dict) -> int:
    """Entries of a platform's list that are missing, required and firmware.

    Only those stop a console from starting. Game data and files no core
    opens are counted apart, and red on every short row carried no signal.
    """
    return len({
        (d.get("system", ""), d.get("name", "")) for d in cov.get("details") or []
        if d.get("status") == "missing" and d.get("required", True)
        and d.get("category", "bios") == "bios" and not d.get("settled_by")
    })


def _ratio_cell(done: int, total: int, alarm: int = 0) -> str:
    """A held-over-needed cell: the numbers, a bar, and a badge only when
    required firmware is missing."""
    if not total:
        return "-"
    share = done / total * 100
    cell = (f'<span class="rb-bar" style="--v:{share:.1f}%" aria-hidden="true"><span></span></span>'
            f"{done:,}/{total:,}")
    if alarm:
        cell += f' <span class="rb-badge rb-badge-danger">{alarm:,} required missing</span>'
    return cell


# GitHub's upload page for a folder of bios/: a browser upload by someone
# without write access lands on a fork and opens a pull request.
UPLOAD_URL = f"{REPO_URL}/upload/main/bios"
# Rows of Files to source on one page: 601 on one page made a phone page
# 274,509 px long.
FILES_TO_SOURCE_PART = 100


def _upload_folder(profile: dict) -> str:
    """The bios/ folder a file the emulator loads is uploaded into: the
    console folder of its first system that has one, else none."""
    from siterender import _own_section

    for sys_id in profile.get("systems") or []:
        own = _own_section(str(sys_id))
        if own is not None:
            return "/".join(own)
    return ""


def reading_platforms(emu_name: str, profile: dict, name: str,
                      configs: dict[str, dict]) -> set[str]:
    """Of the platforms running an emulator (name -> config), those whose
    build of it reads the entry: BlastEm's cdbios.bin is read by the
    standalone build only, and RetroBat hands that build other names."""
    from common import platform_layouts, standalone_set  # noqa: PLC0415
    from validation import filter_files_by_mode, unread_on  # noqa: PLC0415

    return {
        platform for platform, config in configs.items()
        if any(f.get("name") == name and not unread_on(f, platform)
               for view, standalone in platform_layouts(emu_name, profile, standalone_set(config))
               for f in filter_files_by_mode(view.get("files") or [], standalone))
    }


def generate_gap_analysis(
    profiles: dict,
    coverages: dict,
    db: dict,
    data_names: set[str] | None = None,
    registry: dict | None = None,
    gap_report: dict | None = None,
    moved: dict[str, str] | None = None,
    catalogued: dict | None = None,
) -> str:
    """Generate a unified gap analysis page.

    ``catalogued`` is a provenance report built with the profiles' needs:
    a file the collection does not hold yet names the catalog or romset
    that lists it.

    With ``moved``, the list of files to source goes to pages of its own,
    keyed by stem: on the page it made 662 KB of HTML.

    Combines verification results (from coverages/verify.py) with source
    provenance (from cross_reference) into a single truth dashboard.

    Sections:
    1. Verification status, aggregated across all platforms
    2. Problem files: missing, untested, hash mismatch
    3. Core complement: emulator files not declared by any platform
    """

    from common import resolve_platform_cores

    # ---- Section 1: aggregate verify results across all platforms ----

    total_verified = 0
    total_untested = 0
    total_missing_verify = 0
    total_files_verify = 0
    not_firmware_totals: dict[str, int] = {}

    platform_problems: list[dict] = []
    settled_problems: list[dict] = []
    for pname, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        total_verified += cov["verified"]
        total_untested += cov["untested"]
        total_missing_verify += cov["missing"]
        total_files_verify += cov["total"]
        for category, count in (cov.get("missing_not_firmware") or {}).items():
            not_firmware_totals[category] = not_firmware_totals.get(category, 0) + count

        for d in cov["details"]:
            if d.get("settled_by") and d["status"] != "ok":
                # Its path holds another declaration's file: the headline,
                # counted by destination, rightly leaves it out, and listing
                # it under the same word made the page contradict itself.
                settled_problems.append({
                    "platform": cov["platform"], "name": d["name"],
                    "status": d["status"], "held_by": d["settled_by"],
                })
                continue
            if d["status"] != "ok" or d.get("discrepancy"):
                platform_problems.append({
                    "platform": cov["platform"],
                    "platform_key": pname,
                    "name": d["name"],
                    "status": d["status"],
                    "required": d.get("required", True),
                    "category": d.get("category", "bios"),
                    "reason": d.get("reason", ""),
                    "discrepancy": d.get("discrepancy", ""),
                    "system": d.get("system", ""),
                    "declared": _declared_hashes(cov.get("config") or {}, d),
                    "destination": _declared_destination(cov.get("config") or {}, d),
                    "path": d.get("path") or "",
                })

    lines = [
        "# What the packs do not hold",
        "",
        "What each pack still cannot give, and why. Most gaps are not "
        "firmware: a platform's list can also name game files, such as "
        "Diablo's `diabdat.mpq`, which comes from an owned copy of the game, or files "
        "no emulator of that platform opens. Those are counted apart. A missing "
        "firmware file means a console that does not start, and each one is "
        "named below with the platforms that list it.",
        "",
        "Each file here is a request: for a file under \"Files to source\", "
        "[adding it](contributing.md) fills the gap for "
        "every platform at once.",
        "",
        " ".join([
            markup.button("Download gaps CSV", "downloads/gaps.csv"),
            markup.button("Open gaps API", "api/v1/gaps.json"),
            markup.button("All data exports", "data.md"),
        ]),
        "",
        _platform_lists_sentence(
            total_files_verify, total_verified, total_untested, total_missing_verify,
            not_firmware_totals,
        ),
        "",
    ]

    # ---- Verification per platform ----

    lines.extend([
        "## What each pack contains",
        "",
        "| Platform | On its BIOS list (destinations) | Files its emulators load | Checked by |",
        "|----------|-----------------:|-------------------------:|------------|",
    ])

    for pname, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        display = cov["platform"]
        core_total = (
            cov["core_present"] + cov["core_missing"] + cov["core_unsourceable"]
        )
        lines.append(
            f"| [{display}](platforms/{pname}.md) "
            f"| {_ratio_cell(cov['present'], cov['total'], _missing_required_firmware(cov))} "
            f"| {_ratio_cell(cov['core_present'], core_total)} "
            f"| {check_label(cov['mode'], cov['config'].get('hash_rule'))} |"
        )
    lines.extend([
        "",
        "Each fraction is what the pack has over what is needed, counting "
        "required and optional files alike since both ship. The first column "
        "is the BIOS list the platform publishes, counted by destination: a "
        "path the list declares twice is one file to place. A red badge marks "
        "a list that is short of required firmware. The second counts files its "
        "emulators load that this list never mentions, found by reading their "
        "source code, and it is often several times larger. What is short "
        "is named in the sections below. That second "
        "number is a floor, not a ceiling: an emulator that accepts any file "
        "handed to it names none in its code, so nothing there can be counted. "
        "Checked by is the test the platform runs on its own, replicated here "
        "from its source code "
        "([how each one works](wiki/verification-modes.md)).",
        "",
        "## How much of each list the emulator code confirms { #corroboration-against-emulator-source }",
        "",
        "| Platform | On its BIOS list | Documented in a profile | Content the code checks |",
        "|----------|-----------------:|------------------------:|------------------------:|",
    ])

    for pname, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        gt = cov["ground_truth"]
        if not gt.get("applicable", True):
            prof_cell = gt_cell = "-"
        elif gt["total"]:
            prof_pct = f"{gt.get('with_profile', 0) / gt['total'] * 100:.0f}%"
            prof_cell = f"{gt.get('with_profile', 0):,} ({prof_pct})"
            gt_pct = f"{gt['with_validation'] / gt['total'] * 100:.0f}%"
            gt_cell = f"{gt['with_validation']:,} ({gt_pct})"
        else:
            prof_cell = gt_cell = "0"
        lines.append(
            f"| [{cov['platform']}](platforms/{pname}.md) "
            f"| {gt['total']:,} | {prof_cell} | {gt_cell} |"
        )

    lines.extend([
        "",
        "Both columns count the files on the platform's own BIOS list, the "
        "same number as the first column of the table above. Documented in a "
        "profile means an emulator profile, written from source, describes the "
        "file. Content the code checks is stricter: the emulator verifies a "
        "size or hash for it, and this tool repeats that check. The gap "
        "between the two is "
        "not a defect, it is what the emulator code does: many emulators load "
        "a file without ever checking its content, and no amount of profiling "
        "can invent a check the code does not perform. A dash means no "
        "profiled emulator applies to the platform, whose own source is then "
        "the only authority.",
        "",
        _content_check_ceiling(profiles),
        "",
    ])

    # ---- Section 1b: platform lists vs emulator source ----

    from truth import diff_platform_truth, generate_platform_truth

    div_rows = []
    for pname, cov in sorted(coverages.items(), key=lambda x: x[1]["platform"]):
        truth_data = generate_platform_truth(
            pname, cov["config"], (registry or {}).get(pname, {}), profiles, db
        )
        s = diff_platform_truth(truth_data, native_layer(cov["config"]))["summary"]
        if s["systems_compared"] == 0:
            div_rows.append(
                f"| [{cov['platform']}](platforms/{pname}.md) | - | - | - | - |"
            )
        else:
            div_rows.append(
                f"| [{cov['platform']}](platforms/{pname}.md) "
                f"| {s['total_missing']} "
                f"| {s['total_extra_phantom'] + s['total_extra_unprofiled']} "
                f"| {s['total_hash_mismatch']} "
                f"| {s['total_required_mismatch']} |"
            )

    lines.extend([
        "## Platform lists vs emulator source",
        "",
        "Platform file lists are scraped as-is from each upstream project. "
        "Emulator profiles are read from source code. The two do not always "
        "agree, and this table counts the differences. Packs follow the "
        "platform contract, and these numbers show where that contract diverges "
        "from what the code loads.",
        "",
        "| Platform | Missing from list | Not read by profiles | Hash conflict | Required status |",
        "|----------|------------------:|--------:|--------------:|----------------:|",
        *div_rows,
        "",
        "- **Missing from list**: a profiled emulator loads the file, the platform list does not mention it",
        "- **Not read by profiles**: on the platform list, loaded by no emulator profiled so far (a profile may still be incomplete)",
        "- **Hash conflict**: the platform list and the emulator source expect different hashes",
        "- **Required status**: required/optional differs between list and code",
        "",
        "A dash means no profiled emulator overlaps the platform's systems, "
        "so there is nothing to compare: the platform's own source is the "
        "only authority for its files.",
        "",
        "The same comparison feeds the [updated platform files](exports.md): "
        "each platform's own file, patched with these differences and kept "
        "in its native format (System.dat, es_bios.xml, batocera-systems, ...).",
        "",
    ])

    lines.extend(_render_problem_files(platform_problems, settled_problems, db,
                                       total_missing_verify))

    # ---- Section 3: Core complement (cross-reference provenance) ----

    unique_profiles = {
        k: v
        for k, v in profiles.items()
        if v.get("type") != "alias" and v.get("role") != "test"
    }
    relevant_set: set[str] = set()
    for _name, cov in coverages.items():
        matched = resolve_platform_cores(cov["config"], unique_profiles)
        relevant_set.update(matched)
    if gap_report is None:
        gap_report = build_emulator_gap_report(profiles, coverages, db, data_names)
    report_all = gap_report

    src_totals: dict[str, int] = {
        "bios": 0, "data": 0, "large_file": 0, "bundled": 0, "missing": 0,
    }
    total_undeclared = 0
    emulator_gaps = []

    for emu_name, data in sorted(report_all.items()):
        if data["gaps"] == 0:
            continue
        total_undeclared += data["gaps"]
        for key, count in _gap_sources(data).items():
            src_totals[key] += count
        emulator_gaps.append((emu_name, data))


    if total_undeclared > 0:
        total_available = (
            src_totals["bios"] + src_totals["data"] + src_totals["large_file"]
        )
        pct_available = (
            f"{total_available / total_undeclared * 100:.0f}%"
            if total_undeclared
            else "0%"
        )

        lines.extend([
            "## Files emulators load that no platform lists { #core-complement }",
            "",
            f"Files loaded by emulators but not declared by any platform. "
            f"{total_undeclared:,} files across {_count(len(emulator_gaps), 'emulator')}, "
            f"{total_available:,} available ({pct_available}), "
            f"{src_totals['bundled']:,} installed with their emulator, "
            f"{src_totals['missing']:,} to source.",
            "",
            "This counts every profiled emulator, including those no platform "
            "ships yet, so it reaches past what the first table above counts: "
            "it covers only the emulators each platform actually ships. "
            "Whatever is not in the collection is an acquisition target, named "
            "per emulator below.",
            "",
            "### Where the files come from",
            "",
            "| Source | Count | Description |",
            "|--------|------:|-------------|",
            f"| bios/ | {src_totals['bios']} | In repository (database.json) |",
            f"| data/ | {src_totals['data']} | Data directories (buildbot, GitHub) |",
            f"| release | {src_totals['large_file']} "
            "| GitHub release assets (large files) |",
            f"| bundled | {src_totals['bundled']} "
            "| Installed with the emulator's own package, not collected |",
            f"| missing | {src_totals['missing']} | Not available, needs sourcing |",
            "",
            "### Per emulator",
            "",
            "| Emulator | Undeclared | bios | data | release | Bundled | Missing |",
            "|----------|----------:|-----:|-----:|--------:|--------:|--------:|",
        ])

        for emu_name, data in sorted(emulator_gaps, key=lambda x: -x[1]["gaps"]):
            display = data["emulator"]
            sources = _gap_sources(data)
            m = sources["missing"]
            missing_str = (
                f'<span class="rb-badge rb-badge-danger">{m}</span>'
                if m > 0
                else '<span class="rb-badge rb-badge-success">0</span>'
            )
            lines.append(
                f"| [{display}](emulators/{emu_name}.md) "
                f"| {data['gaps']} "
                f"| {sources['bios']} "
                f"| {sources['data']} "
                f"| {sources['large_file']} "
                f"| {sources['bundled']} "
                f"| {missing_str} |"
            )
        lines.append("")

        # List truly missing files with platform impact
        emu_to_platforms: dict[str, set[str]] = {}
        unique_profiles = {
            k: v
            for k, v in profiles.items()
            if v.get("type") != "alias" and v.get("role") != "test"
        }
        for pname in coverages:
            config = coverages[pname]["config"]
            matched = resolve_platform_cores(config, unique_profiles)
            for emu_name in matched:
                emu_to_platforms.setdefault(emu_name, set()).add(pname)


        # One row per file to find: a name two emulators share is one file
        # only when both declare the same hash. Keyed by name alone, Fallout
        # 2's master.dat vanished behind Fallout 1's, and the three Sonic
        # decompilations' Data.rsdk showed as one.
        src_missing_details: list[dict] = []
        by_identity: dict[tuple[str, str], dict] = {}
        entries = 0
        bundled_rows: set[tuple[str, str]] = set()
        for emu_name, data in emulator_gaps:
            for g in data["gap_details"]:
                if g["source"] != "missing":
                    continue
                if g.get("bundled"):
                    # It arrives with the emulator's own package, which is
                    # why the collection documents it and does not hold it:
                    # asking readers to source it sent them after a file
                    # every install already has.
                    bundled_rows.add((data["emulator"], g["name"]))
                    continue
                entries += 1
                key = (g["name"], g.get("identity") or f"emulator:{emu_name}")
                row = by_identity.get(key)
                if row is None:
                    row = by_identity[key] = {
                        "name": g["name"],
                        "path": g.get("path") or g["name"],
                        "identity": g.get("identity", ""),
                        "emulators": [data["emulator"]],
                        "emu_keys": [emu_name],
                        "required": g["required"],
                        "source_ref": g["source_ref"],
                    }
                    src_missing_details.append(row)
                elif emu_name not in row["emu_keys"]:
                    row["emulators"].append(data["emulator"])
                    row["emu_keys"].append(emu_name)
                    row["required"] = row["required"] or g["required"]

        if src_missing_details:
            req_src = [m for m in src_missing_details if m["required"]]
            counted = (
                f"{_count(len(src_missing_details), 'file')}, {len(req_src)} required."
                + (
                    f" They come from {_count(entries, 'entry', 'entries')}: a file "
                    "declared with the same hash at several places is listed once."
                    if entries != len(src_missing_details) else ""
                )
            )
            head = [
                "| File | Destination | Expected | Emulator | Required | Affects platforms | Source ref |",
                "|------|-------------|----------|----------|----------|------------------|-----------|",
            ]
            rows: list[str] = []
            for m in sorted(
                src_missing_details,
                key=lambda x: (not x["required"], x["name"]),
            ):
                plats = sorted(set().union(
                    *(reading_platforms(key, profiles[key], m["name"], {
                        p: coverages[p]["config"] for p in emu_to_platforms.get(key, set())
                    }) for key in m["emu_keys"])
                ))
                plat_badges = (
                    " ".join(
                        f'<span class="rb-badge rb-badge-info">{p}</span>'
                        for p in plats
                    )
                    if plats
                    else "-"
                )
                req = "yes" if m["required"] else "no"
                algorithm, _, value = m["identity"].partition(":")
                expected = f"{algorithm} {short_hash(value)}" if value else "-"
                destination = _code(m["path"]) if m["path"] != m["name"] else "-"
                emulators = ", ".join(
                    f"[{_escape_tags(display)}](emulators/{key}.md)"
                    for display, key in zip(m["emulators"], m["emu_keys"])
                )
                folder = _upload_folder(profiles[m["emu_keys"][0]])
                upload = f"{UPLOAD_URL}/{urllib.parse.quote(folder)}" if folder else UPLOAD_URL
                rows.append(
                    f"| `{m['name']}` [Have it? Upload]({upload}) | {destination} | {expected} "
                    f"| {emulators} | {req} | {plat_badges} | "
                    f"{_source_ref_markdown(profiles[m['emu_keys'][0]], m['source_ref'])} |"
                )
            lines.extend(["### Files to source", "", counted, ""])
            if moved is None:
                lines.extend([*head, *rows, ""])
            else:
                where = _list_pages(
                    "gaps-files-to-source", "Files to source",
                    f"{counted} Each is a file an emulator loads that no platform lists and "
                    "the collection does not hold. Part of "
                    "[What the packs do not hold](gaps.md#files-to-source).",
                    head, [rows[i:i + FILES_TO_SOURCE_PART] for i in range(
                        0, len(rows), FILES_TO_SOURCE_PART)], moved, budget=1,
                    parent=("What the packs do not hold", "/gaps/"),
                )
                lines.extend([f"Listed on {where}.", ""])
        if bundled_rows:
            emulators = sorted({emulator for emulator, _name in bundled_rows})
            lines.extend([
                f"{len(bundled_rows)} further files arrive with their emulator's own "
                f"package ({_escape_tags(', '.join(emulators))}): documented in the profile, not "
                "collected, and not listed here.",
                "",
            ])

    # ---- Section 4: files the collection does not hold yet (unsourceable) ----

    all_unsourceable: list[dict] = []
    for emu_name, data in sorted(report_all.items()):
        for u in data.get("unsourceable", []):
            all_unsourceable.append({
                "name": u["name"],
                "emulator": data["emulator"],
                "emu_key": emu_name,
                "reason": u["reason"],
                "source_ref": u.get("source_ref", ""),
            })

    if all_unsourceable:
        listed = _catalogued_needs(catalogued)
        # The old heading's address still leads here.
        lines.extend([
            '<span id="acknowledged-gaps"></span>',
            "",
            "## Not collected yet",
            "",
            f"{len(all_unsourceable)} files the collection does not hold. A file "
            "with the same name is never served in their place. Each is still "
            "wanted, and the last column names a catalog or romset that lists it.",
            "",
            "| File | Emulator | Reason | Source ref | Listed in |",
            "|------|----------|--------|-----------|-----------|",
        ])
        for u in sorted(all_unsourceable, key=lambda x: x["name"]):
            where = listed.get((u["emu_key"], str(u["name"]).casefold()), [])
            lines.append(
                f"| `{u['name']}` | {u['emulator']} | {_reason_cell(u['reason'])} "
                f"| {_source_ref_markdown(profiles[u['emu_key']], u['source_ref'])} "
                f"| {', '.join(where) or '-'} |"
            )
        lines.append("")

    lines.extend(["", _date_line()])
    return "\n".join(lines) + "\n"


def _core_scope_note(config: dict, profiles: dict) -> str:
    """" (all libretro)" when the platform resolves every libretro core.

    Read from what resolve_platform_cores returns, not from the shape of
    ``cores:``: RetroPie and RetroDECK name ``retroarch`` in a list, which
    pulls in every libretro core as ``all_libretro`` does, and the label
    showed for RetroArch and Lakka only.
    """
    every_libretro = resolve_platform_cores({"cores": "all_libretro"}, profiles)
    resolved = resolve_platform_cores(config, profiles)
    if not every_libretro or not every_libretro <= resolved:
        return ""
    others = len(resolved - every_libretro)
    if not others:
        return " (all libretro)"
    return f" (all libretro, plus {_count(others, 'other core')})"


def _gap_sources(data: dict) -> dict[str, int]:
    """Where each undeclared file of one emulator comes from.

    A file the emulator's own package installs is not one to find. The
    report's gap_missing counts it, and the gaps page announced 1,356 files
    to source where 609 are, with a red badge on emulators that have none.
    """
    counts = {"bios": 0, "data": 0, "large_file": 0, "bundled": 0, "missing": 0}
    for gap in data.get("gap_details") or []:
        source = gap.get("source", "")
        if source == "missing" and gap.get("bundled"):
            source = "bundled"
        if source in counts:
            counts[source] += 1
    return counts


def _xref_upstream(profile: dict) -> str:
    """The project a core comes from: its upstream, else its own source."""
    raw = profile.get("upstream") or profile.get("source", "")
    return raw if isinstance(raw, str) else ""


_FORGES = frozenset({
    "github.com", "gitlab.com", "codeberg.org", "bitbucket.org", "git.eden-emu.dev",
    "git.ryujinx.app",
})


def upstream_project(url: str) -> tuple[str, str]:
    """(project key, revision or path inside it) for an upstream URL.

    MAME was twelve rows: mamedev/mame and one row per release tree
    (mamedev/mame/tree/mame0289 and the rest). On a forge the project is
    owner/repo, a GitLab project every group before `/-/`, and the rest is
    a revision. Elsewhere the address without its scheme, `www.` and
    trailing slash is the project. A note written after the address
    (`... (sys/src/games/nes/)`) is a path inside it.
    """
    url, _, note = url.strip().partition(" ")
    note = note.strip().strip("()")
    if not url.startswith(("http://", "https://")):
        return " ".join(filter(None, (url, note))), ""
    parsed = urllib.parse.urlsplit(url)
    host = parsed.netloc.lower().removeprefix("www.")
    parts = [p for p in parsed.path.split("/") if p]
    if host == "gitlab.com" and len(parts) >= 2:
        cut = parts.index("-") if "-" in parts else len(parts)
        rest = parts[cut + 1:]
        if rest[:1] in (["tree"], ["blob"]):
            rest = rest[1:]
        return f"{host}/{'/'.join(parts[:cut])}", "/".join(filter(None, ("/".join(rest), note)))
    if host in _FORGES and len(parts) >= 2:
        repo = parts[1].removesuffix(".git")
        rest = parts[2:]
        if rest[:1] in (["tree"], ["blob"], ["src"]):
            rest = rest[1:]
        return f"{host}/{parts[0]}/{repo}", "/".join(filter(None, ("/".join(rest), note)))
    return "/".join([host, *parts]), note


def _upstream_label(key: str) -> str:
    """owner/repo on GitHub, host/owner/repo on another forge, and a
    Software Heritage revision by its short id."""
    swh = re.fullmatch(r"archive\.softwareheritage\.org/browse/revision/([0-9a-f]{12})[0-9a-f]*", key)
    if swh:
        return f"Software Heritage revision {swh[1]}"
    return key.removeprefix("github.com/")


def _breakable(label: str) -> str:
    """A project address that may wrap after each slash: unbroken, the
    longest pushed three of five columns off a 1,440 px screen."""
    return "/<wbr>".join(_escape_tags(part) for part in label.split("/"))


def _xref_platform_rows(config: dict, unique: dict) -> tuple[int, list[str]]:
    """The cores a platform pulls in, as table rows, with their count."""
    # The cores the builder and verify resolve: a hand copy here dropped
    # the libretro set a list naming retroarch pulls in, and the system
    # fallback EmuDeck relies on.
    matched = sorted(key for key in resolve_platform_cores(config, unique) if key in unique)
    rows = []
    for emu_name in matched:
        p = unique[emu_name]
        cls_raw = p.get("core_classification", "-")
        systems = p.get("systems", []) or []
        sys_str = ", ".join(_escape_tags(system_name(s)) for s in systems[:3])
        if len(systems) > 3:
            sys_str += f" +{len(systems) - 3}"
        files = p.get("files", []) or []
        libretro_only = sum(1 for f in files if f.get("mode") == "libretro")
        standalone_only = sum(1 for f in files if f.get("mode") == "standalone")
        file_str = str(len(files))
        parts = [f"{n} {label}" for n, label in ((libretro_only, "libretro-only"),
                                                  (standalone_only, "standalone-only")) if n]
        if parts:
            file_str += f" ({', '.join(parts)})"
        upstream = _xref_upstream(p)
        key, _rest = upstream_project(upstream)
        upstream_display = (f"[{_breakable(_upstream_label(key))}]({upstream.split()[0]})"
                            if upstream.startswith("http") else (_escape_tags(upstream) or "-"))
        rows.append(
            f"| [{_escape_tags(p.get('emulator', emu_name))}](emulators/{emu_name}.md) "
            f"| {CLS_LABEL_ONE.get(cls_raw, cls_raw)} | {sys_str or '-'} | {file_str} "
            f"| {upstream_display} |"
        )
    return len(matched), rows


# What a platform that declares no core (cores: []) is told, on its page
# and in the cross-reference.
OWN_LIST_ONLY = "None. Its own list is the whole truth: no core profile adds a file."


def _own_list_only(config: dict) -> bool:
    """The platform declares `cores: []`: its own list decides alone."""
    return isinstance(config.get("cores"), list) and not config["cores"]


def _render_xref_by_platform(
    coverages: dict, unique: dict, moved: dict[str, str] | None = None,
) -> list[str]:
    """Which cores each platform pulls in: counts here, a page per platform.

    One page held every platform's table, 30,551 nodes: the overview keeps
    the counts and each platform's table moves to ``moved`` by stem.
    """
    lines = [
        "## By platform",
        "",
        "| Platform | Cores | Core list |",
        "|----------|------:|-----------|",
    ]
    for pname in sorted(coverages, key=lambda x: coverages[x]["platform"]):
        cov = coverages[pname]
        display = cov["platform"]
        config = cov["config"]
        count, rows = _xref_platform_rows(config, unique)
        stem = f"cross-reference-{pname}"
        if _own_list_only(config):
            # cores: [] (MiSTer, BizHawk): no profile describes what they
            # read, and a page of cores would be an empty table.
            lines.append(f"| [{_escape_tags(display)}](platforms/{pname}.md) | 0 "
                         f"| {OWN_LIST_ONLY} |")
            continue
        lines.append(
            f"| [{_escape_tags(display)}](platforms/{pname}.md) | {count}"
            f"{_core_scope_note(config, unique)} | [Cores on {_escape_tags(display)}]({stem}.md) |"
        )
        if moved is not None:
            moved[stem] = "\n".join([
                "---", "level: reference",
                *_parent_front_matter(("Cores by platform", "/cross-reference/")), "---", "",
                f"# Cores on {display}",
                "",
                f"{_count(count, 'core')}{_core_scope_note(config, unique)} that "
                f"{display} runs, the systems each emulates and the project it comes "
                f"from. Part of [Cores by platform](cross-reference.md). The files "
                f"are listed on the [{display} page](platforms/{pname}.md).",
                "",
                "| Core | Classification | Systems | Files | Upstream |",
                "|------|---------------|---------|-------|----------|",
                *rows,
                "",
            ]) + "\n"
    lines.append("")
    return lines


def _render_xref_by_upstream(
    coverages: dict, unique: dict
) -> list[str]:
    """The same relation read the other way: one row per upstream project."""
    lines: list[str] = [
        "## By upstream emulator",
        "",
        "One row per project: the releases and folders of one repository are "
        "listed in the Revisions column. Platforms counts the platforms that run "
        "at least one of its cores.",
        "",
        "| Cores | Upstream | Revisions | Classification | Platforms |",
        "|-------|----------|-----------|----------------|----------:|",
    ]

    by_upstream: dict[str, list[tuple[str, str, str]]] = {}
    for emu_name, p in sorted(unique.items()):
        # A null upstream is the project's own source: grouping it under
        # the string "None" put eight unrelated engines in one row.
        up_str = _xref_upstream(p)
        if up_str:
            key, rest = upstream_project(up_str)
            by_upstream.setdefault(key, []).append((emu_name, up_str, rest))

    platform_membership: dict[str, set[str]] = {}
    for pname, cov in coverages.items():
        for key in resolve_platform_cores(cov["config"], unique):
            platform_membership.setdefault(key, set()).add(cov["platform"])

    for key in sorted(by_upstream, key=lambda k: _upstream_label(k).casefold()):
        members = by_upstream[key]
        cores = sorted(c for c, _url, _rest in members)
        classifications = sorted({
            CLS_LABEL_ONE.get(unique[c].get("core_classification", "-"),
                           unique[c].get("core_classification", "-"))
            for c in cores
        })
        plats = sorted(set().union(*(platform_membership.get(c, set()) for c in cores)))
        revisions = sorted({rest for _c, _url, rest in members if rest})
        urls = sorted({url.split()[0] for _c, url, _rest in members})
        # The project's own address: the bare one when a core cites it.
        home = next((u for u in urls if not upstream_project(u)[1]), urls[0])
        upstream_cell = (f"[{_breakable(_upstream_label(key))}]({home})" if home.startswith("http")
                         else _escape_tags(key))
        lines.append(
            "| " + ", ".join(f"[{c}](emulators/{c}.md)" for c in cores)
            + f" | {upstream_cell} | {', '.join(_breakable(r) for r in revisions) or '-'} "
            f"| {', '.join(classifications)} | {len(plats)} |"
        )
    return lines


def generate_cross_reference(
    coverages: dict,
    profiles: dict,
    moved: dict[str, str] | None = None,
) -> str:
    """Cross-reference: counts per platform, then cores by upstream project.

    ``moved`` collects one page per platform with its core table.
    """
    unique = {
        k: v for k, v in profiles.items() if v.get("type") != "alias" and v.get("role") != "test"
    }

    total_cores = len(unique)
    total_upstreams = len({
        upstream_project(_xref_upstream(p))[0] for p in unique.values() if _xref_upstream(p)
    })
    # "623 cores across 18 platforms" counted every profile: 91 of them
    # no platform runs.
    run_cores = len({
        key for cov in coverages.values()
        for key in resolve_platform_cores(cov["config"], unique)
    })

    lines = [
        "# Cores by platform",
        "",
        "Every core each platform runs, the systems it emulates, and the project "
        "it comes from. A core built for RetroArch is often a port of another "
        "emulator, and the two can differ in the files they read and the checks "
        "they make, so each core names its upstream project. "
        f"{total_cores} cores are profiled, {run_cores} of them run by the "
        f"{len(coverages)} platforms, and they come from {total_upstreams} "
        "upstream projects.",
        "",
        "The files a platform's emulators load and its own list does not name are "
        "counted on [What the packs do not hold](gaps.md).",
        "",
        " ".join([
            markup.button("Download cross-reference CSV", "downloads/cross-reference.csv"),
            markup.button("Open emulator API", "api/v1/emulators.json"),
            markup.button("All data exports", "data.md"),
        ]),
        "",
    ]

    lines.extend(_render_xref_by_platform(coverages, unique, moved))
    lines.extend(_render_xref_by_upstream(coverages, unique))

    lines.extend(["", _date_line()])
    return "\n".join(lines) + "\n"


def generate_contributing() -> str:
    return contributing_text(
        lambda page: f"{page}.md", "# Contributing", "on this site"
    ) + "\n" + "\n".join(_next_block([
        "[Profiling an emulator](wiki/profiling.md), the first task most "
        "contributions start from",
    ]))


# The end of a reference page: back to the index, or on to contributing.
def generate_not_found() -> str:
    """The page a stale link lands on. Pages have moved before (file cards
    refiled between manufacturers), so it offers the search, the two pages
    a visitor most often wants, and the list a moved page belongs to."""
    return "\n".join([
        "---",
        "search: exclude",
        "---",
        "",
        "# Page not found",
        "",
        '<p class="rb-lead">This address has no page. It may have moved since the link was written.</p>',
        "",
        '<p><button type="button" class="rb-notfound-search" data-rb-open-search>Search the site</button></p>',
        "",
        "- [Start here](index.md): what BIOS files are and how to install them",
        "- [Get the files](which-pack.md): the pack or the command for each device",
        "- Browse [platforms](platforms/index.md), [systems](systems/index.md) "
        "or [emulators](emulators/index.md)",
        "",
        '<div id="rb-notfound-hint" hidden></div>',
        "",
    ])


def reference_next() -> str:
    return "\n" + "\n".join(_next_block([
        "[Reference index](wiki/index.md), every reference page in one list",
        "For contributors: [How to contribute](contributing.md)",
    ]))


# Wiki pages
# index, architecture, tools, profiling are maintained as wiki/ sources
# and copied verbatim by main(). Only data-model is generated dynamically.


def generate_wiki_data_model(db: dict, profiles: dict) -> str:
    """Generate data model documentation from actual database structure."""
    files_count = len(db.get("files", {}))
    by_md5 = len(db.get("indexes", {}).get("by_md5", {}))
    by_name = len(db.get("indexes", {}).get("by_name", {}))
    by_crc32 = len(db.get("indexes", {}).get("by_crc32", {}))
    by_path = len(db.get("indexes", {}).get("by_path_suffix", {}))
    by_sha256 = len(db.get("indexes", {}).get("by_sha256", {}))

    # A real entry with real values: the PlayStation BIOS v3.0 (A).
    sample_key = "0555c6fae8906f3f09baf5988f00e55f88e9f30b"
    files = db.get("files", {})
    sample = files.get(sample_key) or next(iter(files.values()), {})
    lines = [
        "# Data model",
        "",
        "Three kinds of file hold everything this project knows. `database.json` "
        "lists every file the collection holds, keyed by its SHA1. A platform YAML "
        "copies the BIOS list a setup publishes. An emulator profile records what "
        "one emulator opens, read from its code. The sections below show the "
        "fields of each, with a real entry, to read the data or build on it.",
        "",
        "Example: `scph5501.bin` is one entry of `database.json` (key "
        "`0555c6fa...`), one entry of `platforms/batocera.yml` (its MD5) and one "
        "entry of `emulators/duckstation.yml` (its MD5, region and priority).",
        "",
        "## database.json",
        "",
        f"Primary key: SHA1. **{files_count}** file entries.",
        "",
        f"The entry of `{sample.get('name', '')}`:",
        "",
        "```json",
        *json.dumps(sample, indent=2, ensure_ascii=False).splitlines(),
        "```",
        "",
        "`provenance` maps each catalog that lists the file to the DAT and entry "
        "it was matched against. It is present only when the file matches a "
        "snapshot under `provenance/`. The join runs by SHA1 first, then by "
        "MD5 + size. See [dump provenance](../provenance.md).",
        "",
        "### Indexes",
        "",
        "| Index | Entries | Purpose |",
        "|-------|---------|---------|",
        f"| `by_md5` | {by_md5} | MD5 to SHA1 lookup (Batocera, Recalbox verification) |",
        f"| `by_name` | {by_name} | filename to SHA1 list (name-based resolution) |",
        f"| `by_crc32` | {by_crc32} | CRC32 to SHA1 lookup |",
        f"| `by_path_suffix` | {by_path} | relative path to SHA1 (regional variant disambiguation) |",
        f"| `by_sha256` | {by_sha256} | SHA256 to SHA1 lookup (emulator profile validation) |",
        "",
        "### File resolution order",
        "",
        "`resolve_local_file` finds the file an entry describes by its hashes "
        "first, then by its path, then by its name, and a filename or "
        "destination never overrides a declared hash. The steps and their "
        "return codes are written once, in "
        "[the file resolution chain](verification-modes.md#file-resolution-chain).",
        "",
        "## Platform YAML",
        "",
        "Scraped from upstream sources. Structure:",
        "",
        "```yaml",
        "platform: Batocera",
        "verification_mode: md5        # how the platform checks files",
        "hash_type: md5                # hash type in file entries",
        "base_destination: bios        # root directory for BIOS files",
        "systems:",
        "  system-id:",
        "    files:",
        "      - name: filename",
        "        destination: path/in/bios/dir",
        "        md5: expected_hash",
        "        sha1: expected_hash",
        "        required: true",
        "```",
        "",
        "Supports inheritance (`inherits: retroarch`) and shared groups",
        "(`includes: [group_name]` referencing `_shared.yml`).",
        "",
        "`base_destination` is the prefix the pack applies to every entry. It is",
        "empty when the upstream destinations already carry their own root, which",
        "is why the RetroDECK pack ships `bios/` and `roms/` at its top level.",
        "Core files then go under `core_destination` when the platform states one",
        "(`bios` for AmberELEC and EmuELEC, whose lists also name `neogeo/` and",
        "`ports/`), else under the root nearly every destination shares.",
        "",
        "## Emulator YAML",
        "",
        f"**{len(profiles)}** profile files, **{len(unique_emulator_profiles(profiles))}** "
        "distinct emulators once aliases are folded in. Source-verified from "
        "emulator code.",
        "",
        "See the [profiling guide](profiling.md) for the full field reference.",
        "",
        "## Static API and bulk exports",
        "",
        "The website publishes versioned JSON, CSV and SQLite metadata generated "
        "from these same structures. Start with the [Data and API](../data.md) "
        "catalog. Each downloadable artifact carries a SHA256 in "
        "`api/v1/catalog.json`.",
        "",
    ]
    return "\n".join(lines) + "\n"


# Build cross-reference indexes


def _build_file_consumers(db: dict, coverages: dict, profiles: dict) -> FileConsumers:
    """Which platforms and emulators read each collected file."""
    consumers = FileConsumers(db, build_zip_contents_index(db))
    consumers.add_platforms({name: cov["config"] for name, cov in coverages.items()})
    consumers.add_emulators(profiles)
    consumers.add_manifests(Path(__file__).resolve().parent.parent / "install")
    return consumers


def _build_emulator_file_index(profiles: dict) -> dict[str, dict]:
    """Map emulator_name -> {systems, norm}, for the platform pages.

    norm holds the systems as _norm_system_id reads them: a platform files
    the Mega Drive as sega-mega-drive and genesis_plus_gx as sega-megadrive,
    and an exact match left the RetroArch page with no emulator for it.
    """
    from common import _norm_system_id

    return {
        name: {
            "systems": set(profile.get("systems", [])),
            "norm": {_norm_system_id(str(s)) for s in profile.get("systems", [])},
            # Archive members are read inside their archive, never by name.
            "names": {
                str(entry["name"]).lower()
                for entry in profile.get("files") or []
                if isinstance(entry, dict) and entry.get("name")
                and not entry.get("archive")
            },
        }
        for name, profile in profiles.items()
        if profile.get("type") != "alias"
    }


def _declared_by_system(config_files: dict) -> dict[str, list[dict]]:
    """The platform's own entries of each system, hashes included."""
    by_system: dict[str, list[dict]] = {}
    for (sys_id, _name), entries in config_files.items():
        by_system.setdefault(sys_id, []).extend(entries)
    return by_system


def _system_emulators(
    sys_id: str, emulator_files: dict | None, files: list[dict] | None = None
) -> list[str]:
    """The emulators a platform runs for one of its systems.

    A platform can group machines no profile names as one system: RetroArch
    files NAOMI and Atomiswave as sega-dreamcast-arcade, the Enterprise 64
    and 128 as enterprise-64-128. When no system id matches, the emulators
    are the ones that read a file the system lists, by its name. A member of
    an archive does not count: fbneo's boot.bin is read inside bubsys.zip,
    and RomM's Dreamcast boot.bin is not that file.
    """
    from common import _norm_system_id

    norm = _norm_system_id(sys_id)
    by_id = [name for name, data in (emulator_files or {}).items()
             if sys_id in data["systems"] or norm in data["norm"]]
    if by_id or not files:
        return by_id
    names = {str(f.get("name", "")).lower() for f in files} - {""}
    return [name for name, data in (emulator_files or {}).items()
            if names & data.get("names", set())]


# Navigation


_OS_NAMES = {"windows": "Windows", "darwin": "macOS", "linux": "Linux"}


def _runs_on(entry: dict, guide: Guide) -> str:
    """Where a setup runs, read from the systems the installer detects it on."""
    if guide.on_card:
        return "SD card, filled from a computer"
    if "server" in guide.run:
        return "A server"
    if "device" in guide.run:
        return "Its own system"
    systems = {rule.get("os") for rule in (entry.get("install") or {}).get("detect") or []}
    names = [label for key, label in _OS_NAMES.items() if key in systems]
    if "steamdeck" in guide.run:
        names.append("Steam Deck")
    if "android" in guide.run:
        names.append("Android")
    return ", ".join(names)


def _folder_cell(name: str, guide: Guide, prefix: str = "") -> str:
    """The BIOS folder in a table cell, or a link where it depends on the system."""
    if len(guide.folders) > 3:
        return f"Depends on the system: [listed on its page]({prefix}platforms/{name}.md#where-the-files-go)"
    return "<br>".join(f"{label}: {path}" for label, path in guide.folders)


def _pack_cell(name: str, record: dict, prefix: str = "") -> str:
    """The pack's parts and size, or the command where the release has none."""
    if not has_release_pack(name):
        return f"No ZIP. [{NO_PACK}]({prefix}platforms/{name}.md#install)."
    pack = release_record.pack_for(name, record)
    if record.get("tag") and not (pack and pack.get("assets")):
        return f"No ZIP yet. [{NO_PACK}]({prefix}platforms/{name}.md#install)."
    # One small button to the setup's get/ page, which lists every part, and
    # the size after it.
    link = download_links(name, record, "ZIP", page=get_page_link(name, prefix),
                          button=lambda text, url: markup.button(text, url))
    size = pack.get("download_size") if pack else None
    return f"{link} ({_fmt_size(size)})" if size else link


def _group_keys(registry: dict, group: str, display: dict[str, str]) -> list[str]:
    return sorted(
        (k for k in registry if registry[k].get("device_group") == group),
        key=lambda k: display[k].casefold(),
    )


def _own_root_folders(registry: dict) -> dict[str, str]:
    """Platforms whose pack holds its own top folder, with where it unzips.

    The same rule as extract_notes: a list written from an empty base
    destination carries its root in every path."""
    folders = {}
    for key, entry in registry.items():
        config = load_platform_config(key, str(siteinputs.current().platforms))
        if config.get("base_destination") == "" and entry.get("extract_to"):
            folders[key] = entry["extract_to"]
    return folders


def _folder_row(key: str, display: dict[str, str], registry: dict, record: dict,
                own_root: dict[str, str]) -> str:
    """One setup's row: where it runs, its BIOS folder and its ZIP. A setup
    whose ZIP holds its own top folder says where to unzip it, and the
    BIOS folder itself when it has no ZIP to unzip."""
    guide = GUIDES[key]
    pack = release_record.pack_for(key, record)
    zipped = bool(pack and pack.get("assets"))
    folder = (f"Unzip into `{own_root[key]}`" if key in own_root and zipped
              else _folder_cell(key, guide))
    return (f"| [{display[key]}](platforms/{key}.md) | "
            f"{guide.runs_on or _runs_on(registry[key], guide)} | {folder} | "
            f"{_pack_cell(key, record)} |")


def _folder_tables(registry: dict, record: dict, display: dict[str, str]) -> list[str]:
    """Every setup's folder and ZIP, one table per device group, the groups
    of one setup together under "Other setups" as on the tiles. A row for
    each setup that runs another (LaunchBox, Android) under its group."""
    own_root = _own_root_folders(registry)
    header = ["| Setup | Runs on | BIOS folder | ZIP |", "|-------|---------|-------------|-----|"]
    lines: list[str] = []
    alone: list[str] = []
    for group, (label, _description) in DEVICE_GROUPS.items():
        members = _group_keys(registry, group, display)
        if len(members) == 1 and not ALSO_RUNS.get(group):
            alone += members
            continue
        if not members:
            continue
        lines += [f'<span id="{GROUP_ANCHORS[group]}"></span>**{label}**', "", *header]
        lines += [_folder_row(key, display, registry, record, own_root) for key in members]
        lines += [
            f"| {setup} | {runs_on} | {folder}, same as "
            f"[{display[uses]}](platforms/{uses}.md) | {_pack_cell(uses, record)} |"
            for setup, _summary, uses, runs_on, folder in ALSO_RUNS.get(group, ())
        ]
        lines.append("")
    if alone:
        anchors = "".join(f'<span id="{GROUP_ANCHORS[registry[key]["device_group"]]}"></span>'
                          for key in alone)
        lines += [f"{anchors}**Other setups**", "", *header,
                  *(_folder_row(key, display, registry, record, own_root) for key in alone), ""]
    return lines


# iPhone and iPad: no terminal, so each app is filled its own way. Every
# step is the app's own: RetroArch's iOS guide (Files app, On My iPhone >
# RetroArch) and platform_darwin.m (system under Documents/RetroArch), the
# DS BIOS rows of Delta's Settings.storyboard, Provenance's import guide.
IOS_SOURCES = {
    "retroarch_docs": "https://github.com/libretro/docs/blob/"
                      "cfa4c1a17e586c01d3a48e9eda12b6c989f8954f/docs/guides/install-ios.md?plain=1#L94",
    "retroarch_code": "https://github.com/libretro/RetroArch/blob/"
                      "5333a7c5a59e268470834a96f86047d3cb6139a9/frontend/drivers/platform_darwin.m#L438-L459",
    "delta": "https://github.com/rileytestut/Delta/blob/"
             "c1d3d068e019e6493eed45654569db3cc5beb86a/Delta/Base.lproj/Settings.storyboard#L2448-L2500",
    "provenance": "https://wiki.provenance-emu.com/using-provenance/importing-roms",
}
IOS_DEVICES = ("iPhone", "iPad", "iOS", "Delta", "Provenance")
# The same names as which-pack's search terms, the section's meta field
# alone leaving "ios" unanswered.
IOS_TERMS = tuple(name.lower() for name in IOS_DEVICES)


def ios_section() -> list[str]:
    """The section the iPhone and iPad tile opens: the consoles picked on a
    computer, then each app's own way in."""
    return [
        "## iPhone and iPad { #iphone-and-ipad }",
        "",
        devices_meta(IOS_DEVICES),
        "",
        "[Pick the consoles](which-pack.md?platform=retroarch#only-some-consoles) "
        "on a computer. Copy them to the app.",
        "",
        "- **RetroArch**: Files app, **On My iPhone > RetroArch**, then "
        f"`RetroArch/system/` ([docs]({IOS_SOURCES['retroarch_docs']}), "
        f"[code]({IOS_SOURCES['retroarch_code']})).",
        "- **Delta**, for DS games: import `bios7.bin`, `bios9.bin` and `firmware.bin` "
        f"in **Settings**, under **Nintendo DS** ([code]({IOS_SOURCES['delta']})).",
        "- **Provenance**: share the file, then **Copy to Provenance** "
        f"([docs]({IOS_SOURCES['provenance']})).",
        "",
    ]


def generate_which_pack() -> str:
    """The device picker: every registered platform as a tile under the
    device it runs on, the ZIP advice with every folder and ZIP in one closed
    table, the console picker, and the command for a setup not listed.

    The tiles are the choice. Open tables under them listed every setup a
    second time and made the page 11,800 px tall on a phone."""
    registry = load_platform_registry(str(siteinputs.current().platforms))
    record = release_record.load_advertised()
    display = {key: load_platform_config(key, str(siteinputs.current().platforms)).get("platform", key)
               for key in registry}
    all_tabs = ("windows", "macos", "linux", "steamdeck", "android")
    # The quick install box also runs on a game system: its tab shows the
    # handheld recording (sitesteps).
    box_tabs = (*all_tabs, "device")
    box_steps, box_demos = sitesteps.install_box(box_tabs)
    # Python is on most Linux and macOS machines: the package runs the same
    # installer there without the bootstrap.
    for tab in ("macos", "linux"):
        box_demos[tab] = [*box_demos[tab],
                          f"With Python 3.8 or newer, `{PACKAGE_COMMAND}` does the same.", ""]
    lines = [
        "---",
        f"terms: {', '.join(IOS_TERMS)}",
        "---",
        "",
        "# Get the files",
        "",
        "Pick the setup. Its page gives the folder and the command.",
        "",
        "## Pick the setup { #pick-your-setup }",
        "",
        *setup_picker(registry, display),
        "## Folders and ZIP files { #manual-download }",
        "",
        "- A big ZIP comes in parts, like `Pack.part1of2.zip`. Download every part.",
        "- Unzip them into the BIOS folder. Put the files straight in it, "
        "not in a new folder.",
        "- Leave the ZIPs inside, like `neogeo.zip`, as they are.",
        "- A few ZIPs hold their own top folder. Their setup's page says where "
        "to unzip them.",
        "",
        *markup.details("note", "Every folder and ZIP in one table",
                        _folder_tables(registry, record, display)),
    ]
    pending = any(has_release_pack(key) and not (pack and pack.get("assets"))
                  for key, pack in ((key, release_record.pack_for(key, record)) for key in registry))
    if record.get("tag") and pending:
        lines += ["Setups added after the last release have no ZIP until the next one.", ""]
    lines += ["No ZIP on a row: the command serves that setup. ZIPs are made for the "
              f"setups most people download. [Why?]({NO_ZIP_FAQ})", ""]
    lines += [
        f"The ZIPs come from the [latest release]({RELEASE_URL}). The command may "
        "install newer files.",
        "",
        "## Only some consoles?",
        "",
        "Pick them here, and get the files and the command. Or use the command's "
        f"**{_installer().TUI_SYSTEMS_ROW}**.",
        "",
        "<FilePicker />",
        "",
        *ios_section(),
        "## Not in the list? One command finds it { #quick-install }",
        "",
        "A **terminal** is a window for typing commands.",
        "",
        *terminal_tabs(box_tabs, {}, under_steps=box_steps, under_command=box_demos),
        "On Batocera, Recalbox and other game systems, run it on the device. "
        "The setup's page shows how.",
        "",
        *first_screen_words(),
        "",
        *trust_box(""),
        "**Check the folder later.** Add `--check`. It changes nothing.",
        "",
        *terminal_tabs(all_tabs, dict.fromkeys(TERMINALS, "--check"), steps=False),
        *markup.details("note", "Fill an SD card from a computer", [
            "Name the setup and the BIOS folder on the card. For RetroArch on a "
            "Nintendo Switch:",
            "",
            "Linux, macOS:",
            "",
            *fence("sh", install_command(
                "sh", "--platform retroarch --dest /path/to/sdcard/retroarch/cores/system")),
            "",
            "Windows (PowerShell, E: being the card):",
            "",
            *fence("powershell", install_command(
                "powershell", "--platform retroarch --dest E:\\retroarch\\cores\\system")),
        ]),
        *markup.details("note", "Copy the BIOS files from an old card", [
            "Plug the old card in and add `--from` with its folder. The BIOS files "
            "found there are copied, and the rest downloaded. The old card is only read.",
            "",
            "Linux, macOS:",
            "",
            *fence("sh", install_command("sh", "--from /media/me/OLDCARD")),
            "",
            "Windows (PowerShell, E: being the old card):",
            "",
            *fence("powershell", install_command("powershell", "--from E:\\")),
        ]),
        "Details: [All installer options](wiki/installer.md).",
        "",
        *_next_block([
            "[First install, step by step](wiki/first-install.md)",
            "[When a game does not start](wiki/troubleshooting.md)",
        ]),
    ]
    return "\n".join(lines) + "\n"


def nav_emulators(profiles: dict) -> dict[str, dict]:
    """The emulators listed in the navigation, by key.

    A profile that emulates no system and reads no file (the libretro sample
    and test cores, games with nothing to load) answers no question about
    BIOS files. Its page stays, reachable from the overview table and the
    search, and the navigation is left to the cores people look up.
    """
    return {
        key: profile for key, profile in unique_emulator_profiles(profiles).items()
        if profile.get("systems") or profile.get("files")
    }


def _emulator_nav(profiles: dict) -> list:
    """Emulators by initial (A, B, C), one level deep. A name that does not
    open on a letter goes under "0 to 9". The route middleware draws every
    initial but the open one as a single link, so a page carries the links
    of one initial only."""
    groups: dict[str, list[tuple[str, str]]] = {}
    for key, profile in nav_emulators(profiles).items():
        display = str(profile.get("emulator", key))
        groups.setdefault(emulator_initial(display), []).append((display, f"emulators/{key}.md"))
    nav: list = ["emulators/index.md"]
    for label in sorted(groups, key=lambda g: (g != INITIAL_DIGITS, g)):
        items = sorted(groups[label], key=lambda e: e[0].casefold())
        nav.append({label: [{display: path} for display, path in items]})
    return nav


def _system_nav(manufacturers: dict) -> list:
    """Manufacturer pages, the machines apart from the arcade boards and the
    game and engine trees: an arcade page's crumb read "Consoles and
    computers"."""
    machines, arcade, games = [], [], []
    for mfr in sorted(manufacturers, key=str.casefold):
        entry = {mfr: f"systems/{_slug(mfr)}.md"}
        if mfr in GAME_DATA_TOPS:
            games.append(entry)
        else:
            (arcade if mfr == "Arcade" else machines).append(entry)
    nav: list = ["systems/index.md", {"Consoles and computers": machines}]
    if arcade:
        nav.append({"Arcade": arcade})
    if games:
        nav.append({"Game engines and PC games": games})
    return nav


def _platform_nav(coverages: dict, registry: dict) -> list:
    """Platforms by the kind of device they run on, as on the device picker."""
    nav: list = ["platforms/index.md"]
    for group, (label, _description) in DEVICE_GROUPS.items():
        members = [
            {coverages[name]["platform"]: f"platforms/{name}.md"}
            for name in sorted(coverages, key=lambda n: coverages[n]["platform"].casefold())
            if registry.get(name, {}).get("device_group") == group
        ]
        # The handheld guide sits with the group whose tile leads to it.
        members += [{HANDHELD_GUIDE.title: HANDHELD_GUIDE.path}
                    for tile in GROUP_TILES.get(group, ())
                    if HANDHELD_GUIDE and tile.link == HANDHELD_GUIDE.path]
        if members:
            nav.append({label: members})
    return nav


# The tabs in reading order, by the level their pages declare.
TABS = {
    "start": "Start here",
    "setup": "Setups",
    "explore": "Explore",
    "reference": "Reference",
    "contribute": "Contribute",
}


class NavError(ValueError):
    """A wiki page does not say where it goes in the navigation."""


def _h1(markdown: str) -> str:
    match = re.search(r"^# (.+?)(?:\s*\{[^}]*\})?\s*$", markdown, re.M)
    return match.group(1).strip() if match else ""


NavPlace = tuple[int, object, str]


def wiki_nav(wiki_dir: Path | None = None) -> dict[str, list[NavPlace]]:
    """Wiki pages by tab, each at the place its front matter gives.

    A page states `level:` (its tab), `order:` (its place in the tab, the
    smallest first) and, when the navigation names it otherwise than its
    first heading, `nav_title:`. `group:` files it under a labelled group
    of its tab. `nav: false` keeps a page out on purpose. A page that says
    neither raises, naming what to add.
    """
    wiki_dir = Path(wiki_dir) if wiki_dir else _REPO_ROOT / WIKI_SRC_DIR
    tabs: dict[str, list[NavPlace]] = {level: [] for level in TABS}
    for page in sorted(wiki_dir.glob("*.md")):
        where = f"{WIKI_SRC_DIR}/{page.name}"
        text = page.read_text(encoding="utf-8")
        meta = _front_matter(text)
        level = meta.get("level")
        if level not in TABS:
            raise NavError(
                f"{where}: front matter needs `level:`, one of {', '.join(TABS)}, "
                f"to place the page in a tab (found {level!r})"
            )
        if meta.get("nav") is False:
            continue
        order = meta.get("order")
        if not isinstance(order, int) or isinstance(order, bool):
            raise NavError(
                f"{where}: front matter needs `order:`, a whole number giving its "
                f"place in the {TABS[level]} tab, smallest first (found {order!r}), "
                "or `nav: false` to keep it out of the navigation"
            )
        path = f"{WIKI_SRC_DIR}/{page.name}"
        if page.name == "index.md":
            tabs[level].append((order, path, ""))
            continue
        title = meta.get("nav_title") or _h1(text)
        if not title:
            raise NavError(f"{where}: no `# ` heading and no `nav_title:` to name it")
        group = meta.get("group") or ""
        if not isinstance(group, str):
            raise NavError(f"{where}: `group:` names a group of the {TABS[level]} tab (found {group!r})")
        tabs[level].append((order, {str(title): path}, group))
    return tabs


def _overview_anchors(nav: list, docs: Path) -> dict[str, set[str]]:
    """The heading ids of each overview page the navigation names, where a
    group of the sidebar finds its own section."""
    def overviews(value: object) -> Iterator[str]:
        if isinstance(value, str):
            yield value
        elif isinstance(value, list):
            for entry in value:
                yield from overviews(entry)
        elif isinstance(value, dict):
            for child in value.values():
                if isinstance(child, list):
                    yield from overviews(child)

    anchors: dict[str, set[str]] = {}
    for rel in overviews(nav):
        stem = rel.rsplit(".", 1)[0]
        page = next((docs / f"{stem}{suffix}" for suffix in (".md", ".mdx")
                     if (docs / f"{stem}{suffix}").is_file()), None)
        if page:
            anchors[rel] = sitestarlight.heading_ids(page.read_text(encoding="utf-8"))
    return anchors


def _nav_target(entry: object) -> str:
    return entry if isinstance(entry, str) else str(next(iter(entry.values())))


def generate_nav(
    coverages: dict,
    manufacturers: dict,
    profiles: dict,
    registry: dict | None = None,
    wiki_dir: Path | None = None,
) -> list:
    """The navigation, five tabs in reading order.

    Start here is for someone who knows nothing yet, Setups for someone
    who knows their device, Explore for one system or emulator, Reference for
    checking the work, Contribute for adding to it. Each tab opens on its
    index page.

    The generated pages hold the places below. A wiki page takes its own
    place from its front matter (wiki_nav), so a new page needs no edit here.
    A group of a tab sits at the place of its first page, its pages in their
    own order.
    """
    generated: dict[str, list[tuple]] = {
        "start": [(0, "index.md"), (20, {"Get the files": "which-pack.md"})],
        "setup": [(10 * i, item)
                  for i, item in enumerate(_platform_nav(coverages, registry or {}))],
        "explore": [
            (0, "explore.md"),
            (10, {"Systems": _system_nav(manufacturers)}),
            (20, {"Emulators": _emulator_nav(profiles)}),
        ],
        "reference": [
            # Find a file first: the one tool a reader comes to with a file in hand.
            (5, {"Find or check a file": "files/index.md"}, "Checking files"),
            (20, {"What the packs do not hold": "gaps.md"}, "Checking files"),
            (30, {"Cores by platform": "cross-reference.md"}, "Checking files"),
            (40, {"Dump provenance": "provenance.md"}, "Checking files"),
            (60, {"Data and API": "data.md"}, "Data"),
            (64, {"Data model": "wiki/data-model.md"}, "Data"),
            (68, {"Updated platform files": "exports.md"}, "Data"),
            (69, {"Measurements": sitemeasurements.EXPLORER_PAGE}, "Data"),
        ],
        "contribute": [(0, "contributing.md")],
    }
    wiki = wiki_nav(wiki_dir)
    nav = []
    for level, label in TABS.items():
        places = [(place[0], place[1], place[2] if len(place) > 2 else "")
                  for place in generated[level]]
        entries = sorted(places + wiki[level], key=lambda item: item[0])
        for (first, a, _), (second, b, _) in zip(entries, entries[1:]):
            if first == second:
                raise NavError(
                    f"{label} tab: {_nav_target(a)} and {_nav_target(b)} both take "
                    f"order {first}; give one of them a free number"
                )
        items: list = []
        groups: dict[str, list] = {}
        for _order, entry, group in entries:
            if not group:
                items.append(entry)
            elif group in groups:
                groups[group].append(entry)
            else:
                groups[group] = [entry]
                items.append({group: groups[group]})
        nav.append({label: items})
    return nav


# Main


def main() -> None:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Generate the documentation site from project data"
    )
    parser.add_argument(
        "--db", default="database.json",
        help="database file to read (default: %(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default="platforms",
        help="platform YAML directory (default: %(default)s)",
    )
    parser.add_argument(
        "--emulators-dir", default="emulators",
        help="emulator profile directory (default: %(default)s)",
    )
    parser.add_argument(
        "--site-dir", default=STARLIGHT_DIR,
        help="the Astro Starlight project the site is written into (default: %(default)s)",
    )
    parser.add_argument(
        "--docs-dir", default=None,
        help="directory the pages are written to (default: the project's "
             "content collection, src/content/docs)",
    )
    args = parser.parse_args()
    if args.docs_dir is None:
        args.docs_dir = str(Path(args.site_dir) / STARLIGHT_CONTENT)
    # Before any write: the public assets and the bootstraps went out first,
    # and a mistyped folder stopped the run only after them.
    require_directory(args.emulators_dir, "--emulators-dir")
    require_directory(args.platforms_dir, "--platforms-dir")
    try:
        # Two runs over one docs/ delete each other's pages and scratch
        # files in the sweep, so the second is refused instead.
        import contextlib

        from common import load_data_dir_registry, repository_output_lock
        from refresh_data_dirs import hold_data_dirs

        # The coverage pages resolve against data/, held while they are read.
        # Whatever --docs-dir says, website/src/data and wiki/ are written.
        with artifact_lock(args.docs_dir), \
                repository_output_lock(str(PUBLISHED_PARTS_FILE)), \
                contextlib.ExitStack() as held:
            hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))
            _generate(args)
    except ArtifactLockBusy as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


def _generate(args: argparse.Namespace) -> None:

    # Every page reads these, never the repository's own files.
    siteinputs.use(siteinputs.SiteInputs(
        db=Path(args.db).resolve(),
        emulators=Path(args.emulators_dir).resolve(),
        platforms=Path(args.platforms_dir).resolve(),
    ))
    db = load_database(args.db)
    docs = Path(args.docs_dir)
    # Files the site serves as they are (data, downloads, images), in the
    # project's public folder.
    public = Path(args.site_dir) / "public"

    for d in GENERATED_DIRS:
        (public / d if d in PUBLIC_DIRS else docs / d).mkdir(parents=True, exist_ok=True)

    # No robots.txt: a crawler reads it only at the host root (RFC 9309), and
    # this project site lives under /retrobios/. Every page's head points at
    # the sitemap instead (Starlight's head links it).
    (public / "robots.txt").unlink(missing_ok=True)
    # The one-line commands' bootstraps, at the site's root.
    sitebootstrap.write_bootstraps(public, _REPO_ROOT)

    images_dest = public / "assets" / "images"
    images_dest.mkdir(parents=True, exist_ok=True)
    # Logos, system icons and sharing cards are served from the site itself
    # (docs_assets/*/sources.json records where each came from).
    # brand: the mark, favicons and touch icon (scripts/make_site_icons.py).
    folders = [("logos", "logos"), ("system-icons", "system-icons"), ("og", "og"),
               ("brand", "brand")]
    for folder, dest in folders:
        source = Path("docs_assets") / folder
        if source.is_dir():
            shutil.copytree(source, public / "assets" / dest, dirs_exist_ok=True)
    demo_dest = public / "assets" / "demo"
    demo_dest.mkdir(parents=True, exist_ok=True)
    for name in DEMO_ASSETS:
        shutil.copy2(Path("docs_assets") / "demo" / name, demo_dest / name)
    assets_src = Path(".github") / "assets"
    for name, dest_name in [("logo.png", "logo.png"), ("favicon.png", "favicon.png")]:
        src = assets_src / name
        if src.exists():
            shutil.copy2(src, images_dest / dest_name)

    registry_path = Path(args.platforms_dir) / "_registry.yml"
    registry = {}
    if registry_path.exists():
        with open(registry_path) as f:
            registry = (yaml_load(f) or {}).get("platforms", {})

    platform_names = list_registered_platforms(
        args.platforms_dir
    )

    from common import load_data_dir_registry
    from cross_reference import _build_supplemental_index

    data_registry = load_data_dir_registry(args.platforms_dir)
    suppl_names = _build_supplemental_index()

    print("Computing platform coverage...")
    coverages = platform_coverages(
        sorted(platform_names), args.platforms_dir, db, data_registry,
        emulators_dir=args.emulators_dir, db_path=args.db,
        report=lambda _name, cov: print(
            f"  {cov['platform']}: {cov['present']}/{cov['total']} ({_pct(cov['present'], cov['total'])})"
        ),
    )

    print("Loading emulator profiles...")
    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    unique_count = sum(1 for p in profiles.values() if p.get("type") != "alias")
    print(
        f"  {len(profiles)} profiles ({unique_count} unique, {len(profiles) - unique_count} aliases)"
    )

    consumers = _build_file_consumers(db, coverages, profiles)
    emulator_files = _build_emulator_file_index(profiles)

    print("Generating home page...")
    write_if_changed(
        str(docs / "index.md"), generate_home(
            db, coverages, profiles, registry, args.platforms_dir
        )
    )

    write_if_changed(str(docs / "explore.md"), generate_explore_index(db, coverages, profiles))

    stats = compute_stats(db, coverages, profiles)
    stats["composition"] = compute_composition(db)
    write_if_changed(str(public / "stats.json"), generate_stats(stats))
    # llms.txt and the ARD manifest an agent reads first, from the registry.
    siteagents.write(public, sorted(((name, cov["platform"]) for name, cov in coverages.items()),
                                    key=lambda row: row[1].casefold()), write_if_changed)

    # Computed once: the gap analysis page and the published gaps export must
    # report the same files.
    gap_report = build_emulator_gap_report(profiles, coverages, db, suppl_names)

    # The test each emulator page builds for itself: the parts a page is
    # cut into weigh the status its rows show.
    file_held = _availability_check(db, suppl_names)
    # The plan names systems: the sections must be this run's data first.
    manufacturers = _group_by_manufacturer(db)
    set_console_sections(manufacturers, program_names(profiles))
    plan_emulator_pages(profiles, file_held)
    # Build system_id -> manufacturer page map (needed by all generators)
    print("Building system cross-reference map...")
    set_system_page_map(
        _system_pages_from_data(manufacturers, coverages, db, profiles)
    )
    print(f"  {len(_system_page_map)} system IDs mapped to pages")
    from siterender import link_coverage, system_ids  # noqa: PLC0415

    print("Generating system pages...")

    prime_system_icons({
        _icon_name(mfr, console)
        for mfr, consoles in manufacturers.items()
        for console in consoles
    })

    # The arcade boards are recorded before any page links one, the
    # system pages first among them.
    reset_console_pages()
    sections, console_installs = arcade_board_sections(
        manufacturers, system_install_choices(coverages))
    linked, total = link_coverage(
        system_ids(profiles, [cov["config"] for cov in coverages.values()]))
    print(f"  {linked} of {total} system ids linked")

    write_if_changed(
        str(docs / "systems" / "index.md"), generate_systems_index(sections)
    )
    (docs / "files").mkdir(parents=True, exist_ok=True)
    write_if_changed(str(docs / "files" / "index.md"), generate_files_page())
    for mfr, consoles in sections.items():
        slug = mfr.lower().replace(" ", "-")
        pages = system_pages(mfr, consoles, consumers, console_installs.get(slug))
        for stem, (page, held) in pages.items():
            PAGE_DATA[f"systems/{stem}.md"] = system_structured_data(stem, held)
            if stem != slug:
                PART_PAGES.add(f"systems/{stem}.md")
            write_if_changed(str(docs / "systems" / f"{stem}.md"), page)
        write_single_item(
            public / "api" / "v1" / "systems" / f"{slug}.json", "systems",
            # The published data keeps the collection's folders.
            system_export_item(slug, mfr, manufacturers[mfr]),
            str(db.get("generated_at") or _timestamp()), _source_commit(),
        )
    clash = split_system_stems() & {_slug(m) for m in manufacturers}
    if clash:
        raise RuntimeError(f"a console page takes a manufacturer's address: {sorted(clash)}")

    print("Compiling the measurements...")
    measured = sitemeasurements.build(
        public, emulators_dir=Path(args.emulators_dir), repo=REPO_URL,
        system_names={sys_id: system_name(sys_id) for sys_id in sorted(set(_system_page_map))},
    )
    for path in measured.paths:
        _record(path)
    _MEASUREMENT_ITEMS.clear()
    _MEASUREMENT_ITEMS.update(sitemeasurements.by_emulator(measured.index))
    print(f"  {measured.index['records']} records, {measured.index['count']} tests")
    write_if_changed(str(docs / sitemeasurements.EXPLORER_PAGE),
                     sitemeasurements.generate_explorer_page(measured.index) + reference_next())

    print("Generating static API and bulk data exports...")
    exports = generate_data_exports(
        public, db, coverages, profiles, stats, gap_report, consumers
    )
    write_release_advertised(Path(args.site_dir) / "src" / "generated")
    write_if_changed(str(docs / "data.md"),
                     generate_data_page(exports, public / sitemeasurements.SQLITE_PATH)
                     + reference_next())
    PAGE_DATA["data.md"] = dataset_structured_data(exports, db)

    export_reports = load_export_reports()
    _EXPORTED.update(report["platform"] for report in export_reports)

    print("Generating platform pages...")
    write_if_changed(
        str(docs / "platforms" / "index.md"),
        generate_platform_index(coverages, registry),
    )
    if HANDHELD_GUIDE:
        write_if_changed(str(docs / HANDHELD_GUIDE.path), generate_handheld_guide(HANDHELD_GUIDE))
    published_parts = _published_parts()
    for name, cov in coverages.items():
        # The emulators this platform runs, not every one of the system.
        runs = resolve_platform_cores(cov["config"], profiles)
        moved: dict[str, str] = {}
        write_if_changed(
            str(docs / "platforms" / f"{name}.md"),
            generate_platform_page(name, cov, registry, {
                emu: data for emu, data in emulator_files.items() if emu in runs
            }, moved),
        )
        for stem, page in moved.items():
            if stem in coverages:
                raise RuntimeError(f"a system page takes the platform {stem}'s address")
            PART_PAGES.add(f"platforms/{stem}.md")
            anchor = re.search(rf"\]\({re.escape(name)}\.md#([^)\s]+)\)", page)
            if anchor:
                published_parts[f"platforms/{stem}.md"] = f"platforms/{name}.md#{anchor[1]}"
            # One console of one setup's list, a reference: "playstation
            # bios" found five setups' lists before the console's page.
            # Weighed down, they still won on their title, which the page
            # weight does not reach, and their file list is already kept out
            # of the index: the title alone, found again on the setup's page
            # and the console's, is all the search held of them.
            SEARCH_DEMOTED.add(f"platforms/{stem}.md")
            front = _front_matter(page)
            if front:
                page = page[page.find("\n---\n", 4) + 5:].lstrip("\n")
            front.update(level="reference", search="exclude",
                         parent={"label": cov["platform"], "link": f"{name}.md"})
            page = "---\n" + yaml.safe_dump(front, sort_keys=False, allow_unicode=True) \
                + "---\n\n" + page
            write_if_changed(str(docs / "platforms" / f"{stem}.md"), page)
        PAGE_DATA[f"platforms/{name}.md"] = platform_structured_data(name, cov)

    print("Generating emulator pages...")
    _EMULATOR_SETUPS.update(emulator_setups(coverages, profiles))
    _DATA_MEMBERS.update(data_directory_members())
    _DATA_REVISIONS.update(data_directory_revisions())
    for key in sorted(profiles):
        if profiles[key].get("type") == "alias" or profiles[key].get("role") == "test":
            continue
        display = str(profiles[key].get("emulator", key))
        for tree in page_data_directories(key, profiles):
            readers = _DATA_READERS.setdefault(str(tree.get("ref", "")), [])
            if (key, display) not in readers:
                readers.append((key, display))
    for ref, members in _DATA_MEMBERS.items():
        for stem, _names in data_tree_pages(ref, members):
            PART_PAGES.add(f"emulators/{stem}.md")
    write_if_changed(
        str(docs / "emulators" / "index.md"), generate_emulators_index(profiles)
    )
    public_profiles = {
        name: profile
        for name, profile in profiles.items()
        if profile.get("type") != "alias" and profile.get("role") != "test"
    }
    (public / "api" / "v1" / "emulators").mkdir(parents=True, exist_ok=True)
    for name, profile in public_profiles.items():
        # The profile itself, one small document per core: reusing one
        # meant downloading emulators.json (5.9 MB) and filtering it.
        # The envelope and item of emulators.json, one item long: the
        # profile validates against the published schema, which an "id"
        # beside its fields broke on all 530, and schema_version is there.
        # The commit too, as every other envelope: 625 files lacked it.
        write_single_item(
            public / "api" / "v1" / "emulators" / f"{name}.json", "emulators",
            {"id": name, "profile": profile},
            str(db.get("generated_at") or _timestamp()), _source_commit(),
        )
        pages = emulator_pages(
            name, profile, db, consumers, suppl_names, data_registry,
            data_dirs=page_data_directories(name, profiles),
        )
        record_emulator_page(name, profile)
        # A frozen copy answers after the emulator: a frozen_snapshot, and a
        # profile pinned to the revision one platform builds (pin_frozen).
        # Reicast and Flycast 2021 LE answered "dc bios missing" before Flycast.
        if (profile.get("type") in ("launcher", "alias")
                or profile.get("core_classification") in ("launcher", "alias", "frozen_snapshot")
                or profile.get("pin_frozen")):
            SEARCH_DEMOTED.add(f"emulators/{name}.md")
        files = profile.get("files") or []
        for stem, entries in emulator_parts(name, files, profile, file_held):
            PAGE_DATA[f"emulators/{stem}.md"] = emulator_structured_data(
                {**profile, "files": [files[i] for i in entries]})
            PART_PAGES.add(f"emulators/{stem}.md")
        for stem, page in pages.items():
            write_if_changed(str(docs / "emulators" / f"{stem}.md"), page)

    print("Generating cross-reference page...")
    xref_pages: dict[str, str] = {}
    write_if_changed(
        str(docs / "cross-reference.md"),
        tables_out_of_search(generate_cross_reference(coverages, profiles, xref_pages))
        + reference_next(),
    )
    for stem, page in xref_pages.items():
        write_if_changed(str(docs / f"{stem}.md"), tables_out_of_search(page))
    for pname, cov in coverages.items():
        if _own_list_only(cov["config"]):
            # The empty table it had is gone: its address leads to the
            # platform's page, which says its own list decides alone.
            sitestarlight.MOVED_PAGES.setdefault(
                f"cross-reference-{pname}.md", f"platforms/{pname}.md")

    provenance_report = build_report(
        db, load_provenance_snapshots(), needs=profile_needs(profiles, db))

    print("Generating gap analysis page...")
    gap_pages: dict[str, str] = {}
    write_if_changed(
        str(docs / "gaps.md"),
        tables_out_of_search(generate_gap_analysis(
            profiles, coverages, db, suppl_names, registry, gap_report, gap_pages,
            catalogued=provenance_report,
        )) + reference_next(),
    )
    for stem, page in gap_pages.items():
        write_if_changed(str(docs / f"{stem}.md"), tables_out_of_search(page))

    print("Generating updated platform files page...")
    write_if_changed(
        str(docs / "exports.md"),
        generate_exports_page(
            export_reports,
            {name: cov["platform"] for name, cov in coverages.items()},
        ) + reference_next(),
    )

    print("Generating dump provenance page...")
    provenance_pages: dict[str, str] = {}
    write_if_changed(
        str(docs / "provenance.md"),
        tables_out_of_search(
            generate_provenance_page(db, provenance_report, load_derivable(), provenance_pages)
        ) + reference_next(),
    )
    for stem, page in provenance_pages.items():
        write_if_changed(str(docs / f"{stem}.md"), tables_out_of_search(page))

    # Wiki pages: copy manually maintained sources + generate dynamic ones
    print("Generating wiki pages...")
    wiki_dest = docs / "wiki"
    wiki_dest.mkdir(parents=True, exist_ok=True)
    wiki_src = Path(WIKI_SRC_DIR)
    # The romset table is the profiles' versions, never typed: the source
    # page is rewritten before it is copied, as the README is.
    faq = _REPO_ROOT / ROMSET_FAQ_PAGE
    if faq.is_file():
        write_if_changed(str(faq), with_romset_table(faq.read_text(encoding="utf-8"), profiles))
    recipes_page = _REPO_ROOT / ARCHIVE_RECIPES_PAGE
    if recipes_page.is_file():
        write_if_changed(str(recipes_page), with_archive_counts(
            recipes_page.read_text(encoding="utf-8"), archive_build.rebuild_counts()))
    if wiki_src.is_dir():
        for src_file in wiki_src.glob("*.md"):
            shutil.copy2(src_file, wiki_dest / src_file.name)
            _record(wiki_dest / src_file.name)
    method_page = docs / sitemeasurements.METHOD_PAGE
    if method_page.is_file():
        write_if_changed(str(method_page), sitemeasurements.with_hosts(
            method_page.read_text(encoding="utf-8"), measured.index))
    table_page = docs / SETUP_TABLE_PAGE
    if table_page.is_file():
        write_if_changed(str(table_page), with_setup_table(
            table_page.read_text(encoding="utf-8"), coverages))
    # data-model.md is generated (contains live DB stats)
    write_if_changed(
        str(wiki_dest / "data-model.md"), generate_wiki_data_model(db, profiles)
    )

    print("Generating which-pack page...")
    write_if_changed(str(docs / "which-pack.md"), generate_which_pack())

    # One permanent download address per registered platform: the README's
    # table links each of them.
    print("Generating download pages...")
    get_dir = docs / release_record.GET_DIR
    get_dir.mkdir(parents=True, exist_ok=True)
    for name in platform_names:
        write_if_changed(str(get_dir / f"{name}.md"), generate_get_page(name))
    write_if_changed(str(get_dir / "index.md"), generate_get_index())

    print("Generating contributing page...")
    write_if_changed(str(docs / "contributing.md"), generate_contributing())

    # Swept before the decoration, which rewrites every page it finds: a
    # page no generator produced any more (a console moved back onto its
    # manufacturer's page) was decorated, recorded, and kept for ever.
    write_if_changed(str(docs / "404.md"), generate_not_found())
    stale = _sweep_generated(docs, [d for d in GENERATED_DIRS if d not in PUBLIC_DIRS])
    stale += _sweep_generated(public, list(PUBLIC_DIRS))
    stale += _sweep_top_pages(docs)

    print("Adding page metadata and structured data...")
    lastmod = decorate_markdown_pages(docs)

    nav = generate_nav(coverages, manufacturers, profiles, registry,
                              Path(WIKI_SRC_DIR))
    print("Writing the navigation and the picker's data...")
    site = Path(args.site_dir)
    present = {
        path.relative_to(docs).with_suffix(".md").as_posix()
        for path in docs.rglob("*.md*") if path.suffix in (".md", ".mdx")
    } - {"404.md"}
    published_parts = record_parts(docs, present, published_parts)
    write_if_changed(str(PUBLISHED_PARTS_FILE), json.dumps(published_parts, indent=1) + "\n")
    generated = site / "src" / "generated"
    generated.mkdir(parents=True, exist_ok=True)
    write_if_changed(str(generated / "sidebar.json"),
                     json.dumps(sitestarlight.sidebar(nav, present, _overview_anchors(nav, docs)),
                                indent=1) + "\n")
    write_if_changed(str(generated / "redirects.json"),
                     json.dumps(sitestarlight.redirects(profiles, present, published_parts), indent=1,
                                sort_keys=True) + "\n")
    write_if_changed(str(generated / "lastmod.json"),
                     json.dumps(dict(sorted(lastmod.items())), indent=1) + "\n")
    system_ids = set(_system_page_map) | {
        sys_id for cov in coverages.values() for sys_id in cov["config"].get("systems", {})
    }
    titles = {sys_id: system_name(sys_id) for sys_id in sorted(system_ids)}
    sitestarlight.picker_data(_REPO_ROOT / "install", public / "data" / "picker", titles)
    total_pages = len(present)
    print(f"\nGenerated {total_pages} pages in {args.docs_dir}/")
    if stale:
        print(f"Removed {stale} page(s) nothing produced this run")


from sitediagrams import local_images, prepare_page, unresolved_images  # noqa: E402,F401
from sitewrite import (  # noqa: E402,F401
    _produced,
    _record,
    _undecorated,
    write_if_changed,
    write_decorated,
    _sweep_generated,
    _sweep_top_pages,
)
from sitesources import (  # noqa: E402,F401
    link_prose_citations,
    requested_by,
    revision_markdown,
    _repo_pins,
    _forge_sources,
    _source_permalink,
    _source_ref_markdown,
    version_basis_url,
)
from siterender import (  # noqa: E402,F401
    _by_mode,
    _count,
    _field_text,
    _render_yaml_value,
    _slugify_anchor,
    _system_page_map,
    _system_link,
    set_system_page_map,
    set_console_sections,
    program_names,
    system_name,
    card_page,
    console_href,
    console_anchor,
    record_console_pages,
    record_emulator_cards,
    emulator_card_page,
    reset_console_pages,
    split_system_stems,
    _platform_link,
    _emulator_link,
    _fmt_size,
    _pct,
    _admonition_body,
    _code,
    _escape_tags,
    _icon_name,
    _icon_url,
    system_icon_markdown,
    prime_system_icons,
    _icon_available,
    SYSTEM_ICON_BASE,
    ICON_DIR,
)

if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
